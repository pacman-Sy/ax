//! Minimal STUN binding request: ask a server what source address it saw.
//! Only the mapping is learned; nothing is relayed through the server later.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

const MAGIC: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const ATTR_MAPPED: u16 = 0x0001;
const ATTR_XOR_MAPPED: u16 = 0x0020;

pub fn external_ip(server: &str, timeout: Duration) -> Result<IpAddr, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("stun bind: {e}"))?;
    sock.connect(server)
        .map_err(|e| format!("stun connect {server}: {e}"))?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| format!("stun timeout: {e}"))?;
    sock.set_write_timeout(Some(timeout))
        .map_err(|e| format!("stun timeout: {e}"))?;

    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    req[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    for byte in req[8..20].iter_mut() {
        *byte = random_byte();
    }

    sock.send(&req).map_err(|e| format!("stun send: {e}"))?;

    let mut buf = [0u8; 1500];
    let n = sock.recv(&mut buf).map_err(|e| format!("stun recv: {e}"))?;
    if n < 20 {
        return Err("stun: short reply".into());
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != BINDING_RESPONSE {
        return Err("stun: not a binding response".into());
    }
    if u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) != MAGIC {
        return Err("stun: bad magic cookie".into());
    }

    let cookie = [buf[4], buf[5], buf[6], buf[7]];
    let declared = 20 + u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = declared.min(n);

    let mut off = 20;
    while off + 4 <= end {
        let attr = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        let val_start = off + 4;
        if val_start + len > end {
            break;
        }
        let val = &buf[val_start..val_start + len];

        match attr {
            ATTR_XOR_MAPPED if len >= 8 && val[1] == 0x01 => {
                let ip = Ipv4Addr::new(
                    val[4] ^ cookie[0],
                    val[5] ^ cookie[1],
                    val[6] ^ cookie[2],
                    val[7] ^ cookie[3],
                );
                return Ok(IpAddr::V4(ip));
            }
            ATTR_MAPPED if len >= 8 && val[1] == 0x01 => {
                return Ok(IpAddr::V4(Ipv4Addr::new(val[4], val[5], val[6], val[7])));
            }
            _ => {}
        }

        off = val_start + len;
    }

    Err("stun: no mapped address in reply".into())
}

fn random_byte() -> u8 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    // RandomState is seeded from the OS per instance; it is not a CSPRNG, but
    // this is only a transaction id for a UDP round trip.
    let mut h = RandomState::new().build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    h.write_u32(std::process::id());
    h.finish() as u8
}
