//! The code: address, port, purpose and shared secret in one typeable string.
//! Everything the far side needs is in here, so no third party sits in the path
//! once the code has been handed over.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const KIND_SSH: u8 = b's';
pub const KIND_UPLOAD: u8 = b'u';
pub const SECRET_LEN: usize = 16;

const VER4: u8 = 4;
const VER6: u8 = 6;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Clone)]
pub struct Code {
    pub kind: u8,
    pub ip: IpAddr,
    pub port: u16,
    pub secret: [u8; SECRET_LEN],
}

impl Code {
    pub fn new(kind: u8, ip: IpAddr, port: u16, secret: [u8; SECRET_LEN]) -> Result<Code, String> {
        if port == 0 {
            return Err("port 0 cannot go in a code".into());
        }
        Ok(Code {
            kind,
            ip,
            port,
            secret,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }

    /// Grouped in fours so it survives being read off a screen or read aloud.
    pub fn encode(&self) -> String {
        let mut payload: Vec<u8> = Vec::with_capacity(2 + 16 + 2 + SECRET_LEN);

        match self.ip {
            IpAddr::V4(v4) => {
                payload.push(VER4);
                payload.push(self.kind);
                payload.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                payload.push(VER6);
                payload.push(self.kind);
                payload.extend_from_slice(&v6.octets());
            }
        }

        payload.extend_from_slice(&self.port.to_be_bytes());
        payload.extend_from_slice(&self.secret);

        let raw = b32_encode(&payload);
        let mut out = String::with_capacity(raw.len() + raw.len() / 4);
        for (i, ch) in raw.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(ch);
        }
        out
    }

    /// Accepts any casing, with dashes, spaces, or neither.
    pub fn parse(want: u8, input: &str) -> Result<Code, String> {
        let clean: String = input
            .chars()
            .map(|c| c.to_ascii_uppercase())
            .filter(|c| c.is_ascii_uppercase() || ('2'..='7').contains(c))
            .collect();

        let raw = b32_decode(&clean).ok_or_else(|| "code is not valid base32".to_string())?;
        if raw.len() < 2 {
            return Err("code is too short".into());
        }

        let (ip, off) = match raw[0] {
            VER4 => {
                if raw.len() != 2 + 4 + 2 + SECRET_LEN {
                    return Err("code has the wrong length for ipv4".into());
                }
                let ip = IpAddr::V4(Ipv4Addr::new(raw[2], raw[3], raw[4], raw[5]));
                (ip, 6)
            }
            VER6 => {
                if raw.len() != 2 + 16 + 2 + SECRET_LEN {
                    return Err("code has the wrong length for ipv6".into());
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&raw[2..18]);
                (IpAddr::V6(Ipv6Addr::from(octets)), 18)
            }
            _ => return Err("code carries an unknown version".into()),
        };

        let kind = raw[1];
        if kind != want {
            return Err(format!(
                "that is a {} code, this command wants a {} code",
                kind_name(kind),
                kind_name(want)
            ));
        }

        let port = u16::from_be_bytes([raw[off], raw[off + 1]]);
        if port == 0 {
            return Err("code carries port zero".into());
        }

        let mut secret = [0u8; SECRET_LEN];
        secret.copy_from_slice(&raw[off + 2..off + 2 + SECRET_LEN]);

        Ok(Code {
            kind,
            ip,
            port,
            secret,
        })
    }
}

pub fn kind_name(kind: u8) -> &'static str {
    match kind {
        KIND_SSH => "ssh",
        KIND_UPLOAD => "upload",
        _ => "unknown",
    }
}

fn b32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 2);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        buf = (buf << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn b32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for ch in text.bytes() {
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'2'..=b'7' => ch - b'2' + 26,
            _ => return None,
        } as u32;

        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> [u8; SECRET_LEN] {
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    }

    #[test]
    fn round_trips_ipv4() {
        let code = Code::new(
            KIND_SSH,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)),
            55123,
            secret(),
        )
        .unwrap();

        let text = code.encode();
        let back = Code::parse(KIND_SSH, &text).unwrap();

        assert_eq!(back.ip, code.ip);
        assert_eq!(back.port, 55123);
        assert_eq!(back.secret, secret());
    }

    #[test]
    fn round_trips_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let code = Code::new(KIND_UPLOAD, ip, 8080, secret()).unwrap();

        let back = Code::parse(KIND_UPLOAD, &code.encode()).unwrap();
        assert_eq!(back.ip, ip);
        assert_eq!(back.port, 8080);
    }

    #[test]
    fn accepts_sloppy_input() {
        let code = Code::new(
            KIND_UPLOAD,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            443,
            secret(),
        )
        .unwrap();
        let text = code.encode();

        let lowered = text.to_lowercase().replace('-', " ");
        let back = Code::parse(KIND_UPLOAD, &lowered).unwrap();
        assert_eq!(back.ip, code.ip);
        assert_eq!(back.port, 443);
    }

    #[test]
    fn rejects_wrong_kind() {
        let code = Code::new(
            KIND_SSH,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            443,
            secret(),
        )
        .unwrap();
        assert!(Code::parse(KIND_UPLOAD, &code.encode()).is_err());
    }
}
