//! Where this machine actually is, as seen from this machine and from outside.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

pub const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.nextcloud.com:3478",
    "stun.sipnet.net:3478",
];

// Plain http only, so no TLS stack has to ride along.
pub const IP_ECHO_SERVERS: &[&str] = &[
    "http://icanhazip.com",
    "http://ifconfig.me/ip",
    "http://api.ipify.org",
];

/// The source address the kernel would use for outbound traffic. Nothing is
/// transmitted: a connected UDP socket only performs a route lookup.
pub fn local_ip() -> Result<IpAddr, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
    sock.connect("8.8.8.8:80")
        .map_err(|e| format!("route lookup: {e}"))?;
    let addr = sock.local_addr().map_err(|e| format!("local addr: {e}"))?;
    Ok(addr.ip())
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Discovers the public address with a wall-clock budget.
///
/// Every probe runs concurrently and the first usable answer wins, so a
/// network that filters UDP (three or four dead STUN servers) does not cost
/// four timeouts in a row before the http echo is even tried.
pub fn public_ip_budget(budget: Duration, verbose: bool) -> Result<IpAddr, String> {
    use std::sync::mpsc;
    use std::time::Instant;

    let (tx, rx) = mpsc::channel::<IpAddr>();

    for server in STUN_SERVERS {
        let tx = tx.clone();
        let server = *server;
        std::thread::spawn(move || {
            if let Ok(ip) = crate::stun::external_ip(server, Duration::from_secs(2)) {
                if !is_private(ip) {
                    let _ = tx.send(ip);
                }
            }
        });
    }

    for url in IP_ECHO_SERVERS {
        let tx = tx.clone();
        let url = *url;
        std::thread::spawn(move || {
            if let Ok(ip) = http_echo_ip(url) {
                if !is_private(ip) {
                    let _ = tx.send(ip);
                }
            }
        });
    }

    drop(tx);

    let deadline = Instant::now() + budget;
    let mut remaining_probes = STUN_SERVERS.len() + IP_ECHO_SERVERS.len();

    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let slice = (deadline - now).min(Duration::from_millis(250));

        match rx.recv_timeout(slice) {
            Ok(ip) => {
                if verbose {
                    eprintln!("ax: public address {ip}");
                }
                return Ok(ip);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if verbose {
                    remaining_probes = remaining_probes.saturating_sub(0);
                    let _ = remaining_probes;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    Err("no public address answered".into())
}

/// Background discovery still needs an answer, but a slow network should not
/// hold up the command for long.
pub fn public_ip() -> Result<IpAddr, String> {
    public_ip_budget(Duration::from_secs(5), false)
}

fn http_echo_ip(url: &str) -> Result<IpAddr, String> {
    let u = crate::http::parse(url)?;
    let mut stream = TcpStream::connect((u.host.as_str(), u.port))
        .map_err(|e| format!("connect {}: {e}", u.host))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ax\r\nConnection: close\r\n\r\n",
        u.path, u.host
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;

    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed reply".to_string())?;
    let text = String::from_utf8_lossy(&raw[sep + 4..]);
    let line = text.lines().next().unwrap_or("").trim();

    line.parse::<IpAddr>()
        .map_err(|_| format!("{} answered with {line:?}, not an address", u.host))
}

fn tune(stream: TcpStream) -> TcpStream {
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
    let _ = stream.set_nodelay(true);
    stream
}

/// Dials a list of candidate addresses, first one that answers wins.
///
/// Every candidate gets a slice of the budget rather than the whole thing: a
/// LAN address that is not there should not eat the timeout that the public
/// address needs.
pub fn dial_any(addrs: &[SocketAddr], timeout: Duration, verbose: bool) -> Result<TcpStream, String> {
    if addrs.is_empty() {
        return Err("no address to dial".into());
    }

    let mut seen = Vec::new();
    for (index, addr) in addrs.iter().enumerate() {
        if seen.contains(addr) {
            continue;
        }
        seen.push(*addr);

        let share = timeout
            .checked_div((addrs.len() - index) as u32)
            .unwrap_or(timeout)
            .max(Duration::from_millis(500))
            .min(timeout);

        if verbose {
            eprintln!("ax: dialing {addr} (up to {}s)", share.as_secs_f32());
        }

        match TcpStream::connect_timeout(addr, share) {
            Ok(stream) => {
                if verbose {
                    eprintln!("ax: connected to {addr}");
                }
                return Ok(tune(stream));
            }
            Err(e) => {
                if verbose {
                    eprintln!("ax: {addr} failed: {e}");
                }
            }
        }
    }

    let tried = seen
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "could not reach the host at {tried} within {}s — \n\
         \x20 check that startssh is still running and the port is reachable\n\
         \x20 if both machines share a network, the LAN address is tried first\n\
         \x20 behind CGNAT no forward exists: rerun there with -host <public ip>\n\
         \x20 after forwarding the port yourself",
        timeout.as_secs()
    ))
}
