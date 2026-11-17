//! A pairing relay for hosts that cannot accept inbound connections.
//!
//! The relay only joins two sockets: the caller and the host each dial out to
//! it, identify themselves with a room derived from the code secret, and are
//! spliced together. The ordinary ax handshake then runs over that joined
//! stream, so the relay moves ciphertext it cannot read, alter, or fake.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::code::SECRET_LEN;
use crate::crypto::hmac_sha256;
use crate::splice::splice;

const MAGIC: &[u8; 4] = b"AXR1";
const ROOM_LEN: usize = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_WAITING_PER_ROOM: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Host,
    Client,
}

impl Role {
    fn tag(self) -> u8 {
        match self {
            Role::Host => 1,
            Role::Client => 2,
        }
    }

    fn from_tag(tag: u8) -> Option<Role> {
        match tag {
            1 => Some(Role::Host),
            2 => Some(Role::Client),
            _ => None,
        }
    }
}

/// Room name for a code secret. A caller without the secret cannot join the
/// room, and the relay never learns the secret itself — only this digest.
pub fn room(secret: &[u8; SECRET_LEN]) -> [u8; ROOM_LEN] {
    let mac = hmac_sha256(secret, b"ax relay room v1");
    let mut out = [0u8; ROOM_LEN];
    out.copy_from_slice(&mac[..ROOM_LEN]);
    out
}

type Rooms = HashMap<[u8; ROOM_LEN], Vec<(u8, TcpStream)>>;

fn rooms() -> &'static Mutex<Rooms> {
    static ROOMS: OnceLock<Mutex<Rooms>> = OnceLock::new();
    ROOMS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `host:port`, `ip:port`, or `[v6]:port`.
pub fn resolve(text: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| format!("-relay {text}: wants host:port"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("-relay {text}: {port:?} is not a port"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');

    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("-relay {text}: {e}"))?
        .next()
        .ok_or_else(|| format!("-relay {text}: no address"))
}

pub fn serve(bind: &str, port: u16) -> Result<(), String> {
    let listener = TcpListener::bind((bind, port))
        .map_err(|e| format!("relay listen on {bind}:{port}: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("local addr: {e}"))?;

    eprintln!("ax: relay listening on {local}");
    eprintln!(
        "ax: run the host side with:  ax startssh -relay {}",
        reachable(local)
    );
    eprintln!("ax: the host prints a code; the caller runs: ax connectssh <code>");
    eprintln!("ax: the relay pairs the sockets and never sees the session keys");

    for incoming in listener.incoming() {
        let sock = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("ax: relay accept: {e}");
                continue;
            }
        };
        std::thread::spawn(move || {
            if let Err(e) = pair(sock) {
                eprintln!("ax: relay: {e}");
            }
        });
    }

    Ok(())
}

/// Best-guess address to print for the operator, who usually wants the LAN one
/// when running on the same box they are testing from.
fn reachable(local: SocketAddr) -> String {
    if local.ip().is_unspecified() {
        if let Ok(ip) = crate::netinfo::local_ip() {
            return SocketAddr::new(ip, local.port()).to_string();
        }
    }
    local.to_string()
}

fn pair(mut sock: TcpStream) -> Result<(), String> {
    let _ = sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT));

    let mut head = [0u8; 4 + 1 + ROOM_LEN];
    sock.read_exact(&mut head)
        .map_err(|e| format!("read handshake: {e}"))?;

    if &head[..4] != MAGIC {
        return Err("peer is not an ax relay client".into());
    }

    let role = Role::from_tag(head[4]).ok_or_else(|| format!("unknown role {}", head[4]))?;
    let mut room = [0u8; ROOM_LEN];
    room.copy_from_slice(&head[5..]);

    let _ = sock.set_read_timeout(None);
    let _ = sock.set_write_timeout(None);
    let _ = sock.set_nodelay(true);

    let mate = {
        let mut map = rooms().lock().map_err(|_| "relay state poisoned")?;
        let slot = map.entry(room).or_default();

        match slot.iter().position(|(tag, _)| *tag != role.tag()) {
            Some(index) => {
                let (_, other) = slot.remove(index);
                if slot.is_empty() {
                    map.remove(&room);
                }
                Some(other)
            }
            None => None,
        }
    };

    if let Some(other) = mate {
        if role == Role::Host {
            splice(sock, other);
        } else {
            splice(other, sock);
        }
        return Ok(());
    }

    // Held in the map until the other side arrives; this thread ends.
    let mut map = rooms().lock().map_err(|_| "relay state poisoned")?;
    let slot = map.entry(room).or_default();
    if slot.len() >= MAX_WAITING_PER_ROOM {
        return Err("too many peers waiting in that room".into());
    }
    slot.push((role.tag(), sock));

    Ok(())
}

/// Dials the relay and announces which side of the room this is.
pub fn client(
    relay: SocketAddr,
    secret: &[u8; SECRET_LEN],
    role: Role,
) -> Result<TcpStream, String> {
    let mut sock = TcpStream::connect_timeout(&relay, Duration::from_secs(10))
        .map_err(|e| format!("connect {relay}: {e}"))?;
    let _ = sock.set_nodelay(true);
    let _ = sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT));

    let mut head = [0u8; 4 + 1 + ROOM_LEN];
    head[..4].copy_from_slice(MAGIC);
    head[4] = role.tag();
    head[5..].copy_from_slice(&room(secret));

    sock.write_all(&head)
        .map_err(|e| format!("relay handshake: {e}"))?;
    sock.flush().map_err(|e| format!("relay handshake: {e}"))?;

    let _ = sock.set_write_timeout(None);
    Ok(sock)
}
