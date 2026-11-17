//! startssh / connectssh: a single TCP stream relayed over the encrypted tunnel.
//! ssh does its own multiplexing inside that stream, so one relay is enough.

use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;

use crate::cli::Args;
use crate::code::{Code, KIND_SSH, SECRET_LEN};
use crate::expose;
use crate::netinfo;
use crate::rand;
use crate::splice::splice;
use crate::tunnel;

pub fn start(raw: &[String]) -> Result<(), String> {
    let args = Args::parse(raw);
    let bind = args.string("bind", "0.0.0.0");
    let port = args.int("port", 0)?;
    let ssh_port = args.int("ssh-port", 22)?;
    let target = args.string("target", "127.0.0.1");
    let no_map = args.flag("no-map");

    let pinned_host = match args.get("host") {
        Some(text) => Some(parse_ip(text)?),
        None => None,
    };
    let pinned_port = match args.get("pub-port") {
        Some(_) => Some(to_port(args.int("pub-port", 0)?)?),
        None => None,
    };

    if !(0..=65535).contains(&port) {
        return Err(format!("-port {port} is out of range"));
    }
    if !(1..=65535).contains(&ssh_port) {
        return Err(format!("-ssh-port {ssh_port} is out of range"));
    }

    let listener = TcpListener::bind((bind.as_str(), port as u16))
        .map_err(|e| format!("listen on {bind}:{port}: {e}"))?;
    let internal = listener
        .local_addr()
        .map_err(|e| format!("local addr: {e}"))?
        .port();

    let endpoint = expose::expose_tcp(internal, pinned_host, pinned_port, no_map, "ax ssh")?;

    let secret: [u8; SECRET_LEN] = rand::bytes()?;
    let code = match endpoint.alt {
        Some(lan) => Code::with_alt(KIND_SSH, endpoint.ip, lan, endpoint.port, secret)?,
        None => Code::new(KIND_SSH, endpoint.ip, endpoint.port, secret)?,
    };

    let upstream = format!("{target}:{ssh_port}");

    eprintln!(
        "ax: forwarding {} -> {upstream}",
        SocketAddr::new(endpoint.ip, endpoint.port)
    );
    if let Some(lan) = endpoint.alt {
        eprintln!("ax: same-network callers can use {lan} directly");
    }
    println!("{}", code.encode());
    eprintln!(
        "\non the other machine:\n  ax connectssh {}\n",
        code.encode()
    );

    for incoming in listener.incoming() {
        let sock = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("ax: accept: {e}");
                continue;
            }
        };

        let upstream = upstream.clone();
        std::thread::spawn(move || handle_client(sock, secret, &upstream));
    }

    Ok(())
}

fn handle_client(sock: TcpStream, secret: [u8; SECRET_LEN], upstream: &str) {
    let peer = sock
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());

    let tunnel = match tunnel::server(sock, &secret) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ax: {peer} rejected: {e}");
            return;
        }
    };

    let up = match TcpStream::connect(upstream) {
        Ok(up) => up,
        Err(e) => {
            eprintln!("ax: {peer} upstream {upstream}: {e}");
            return;
        }
    };

    eprintln!("ax: {peer} connected");
    splice(tunnel, up);
    eprintln!("ax: {peer} closed");
}

pub fn connect(raw: &[String]) -> Result<(), String> {
    let args = Args::parse(raw);
    let ssh_bin = args.string("ssh", "ssh");
    let timeout = args.int("timeout", 15)?;

    if args.positional.is_empty() {
        return Err("usage: ax connectssh <code> [user]".into());
    }

    let code = Code::parse(KIND_SSH, &args.positional[0])?;
    let user = args
        .positional
        .get(1)
        .cloned()
        .or_else(|| std::env::var("AX_SSH_USER").ok())
        .unwrap_or_default();

    let verbose = args.flag("v") || args.flag("verbose");
    let sock = netinfo::dial_any(&code.addrs(), Duration::from_secs(timeout as u64), verbose)?;
    let tunnel = tunnel::client(sock, &code.secret)?;

    let local = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("local bind: {e}"))?;
    let local_port = local
        .local_addr()
        .map_err(|e| format!("local addr: {e}"))?
        .port();

    std::thread::spawn(move || {
        if let Ok((conn, _)) = local.accept() {
            splice(tunnel, conn);
        }
    });

    let dest = if user.is_empty() {
        "127.0.0.1".to_string()
    } else {
        format!("{user}@127.0.0.1")
    };

    eprintln!("ax: tunnel on 127.0.0.1:{local_port}, launching {ssh_bin}");

    let status = Command::new(&ssh_bin)
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-p")
        .arg(local_port.to_string())
        .arg(&dest)
        .status()
        .map_err(|e| format!("run {ssh_bin}: {e}"))?;

    if !status.success() {
        return Err(format!("{ssh_bin} exited with {status}"));
    }
    Ok(())
}

fn parse_ip(text: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Ok(ip);
    }

    use std::net::ToSocketAddrs;
    let mut addrs = (text, 0u16)
        .to_socket_addrs()
        .map_err(|e| format!("-host {text}: {e}"))?;
    addrs
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| format!("-host {text} did not resolve to an address"))
}

fn to_port(value: i64) -> Result<u16, String> {
    if !(1..=65535).contains(&value) {
        return Err(format!("port {value} is out of range"));
    }
    Ok(value as u16)
}
