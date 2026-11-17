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

/// STUN first because it is stateless and fast, plain http echo as the fallback
/// for networks that swallow UDP.
pub fn public_ip() -> Result<IpAddr, String> {
    let mut first_err: Option<String> = None;

    for server in STUN_SERVERS {
        match crate::stun::external_ip(server, Duration::from_secs(3)) {
            Ok(ip) if !is_private(ip) => return Ok(ip),
            Ok(_) => {}
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }

    for url in IP_ECHO_SERVERS {
        match http_echo_ip(url) {
            Ok(ip) if !is_private(ip) => return Ok(ip),
            Ok(_) => {}
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }

    Err(first_err.unwrap_or_else(|| "no public address discovered".into()))
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

pub fn dial(addr: SocketAddr, timeout: Duration) -> Result<TcpStream, String> {
    let stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect {addr}: {e}"))?;
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
    let _ = stream.set_nodelay(true);
    Ok(stream)
}
