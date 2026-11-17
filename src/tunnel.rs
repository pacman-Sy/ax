//! Session tunnel: X25519 key agreement, HKDF key schedule, ChaCha20 for
//! confidentiality and HMAC-SHA256 per frame for integrity.
//!
//! The code secret is the salt for the key schedule and the key for mutual
//! authentication, so a relay or observer in the path cannot read the stream,
//! alter it, or impersonate either end without holding the code.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::chacha::ChaCha20;
use crate::code::SECRET_LEN;
use crate::crypto::{constant_time_eq, hkdf_expand, hmac_sha256, wipe};
use crate::x25519;

const PROTO: &[u8] = b"ax-tunnel-v1";
const INFO: &[u8] = b"ax v1 tunnel keys";
const MAX_FRAME: usize = 16 * 1024;
const TAG_LEN: usize = 32;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub struct TunnelReader {
    pub(crate) sock: TcpStream,
    enc: [u8; 32],
    mac: [u8; 32],
    counter: u64,
    buf: Vec<u8>,
    pos: usize,
}

pub struct TunnelWriter {
    sock: TcpStream,
    enc: [u8; 32],
    mac: [u8; 32],
    counter: u64,
}

pub struct Tunnel {
    pub rx: TunnelReader,
    pub tx: TunnelWriter,
}

pub fn client(sock: TcpStream, secret: &[u8; SECRET_LEN]) -> Result<Tunnel, String> {
    perform(sock, secret, true)
}

pub fn server(sock: TcpStream, secret: &[u8; SECRET_LEN]) -> Result<Tunnel, String> {
    perform(sock, secret, false)
}

fn perform(sock: TcpStream, secret: &[u8; SECRET_LEN], is_client: bool) -> Result<Tunnel, String> {
    let _ = sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    let mut sock = sock;

    let io_err = |e: io::Error| format!("handshake: {e}");

    let (mut secret_scalar, public) = x25519::keypair()?;
    let mut peer_public = [0u8; 32];

    if is_client {
        sock.write_all(&public).map_err(io_err)?;
        sock.read_exact(&mut peer_public).map_err(io_err)?;
    } else {
        sock.read_exact(&mut peer_public).map_err(io_err)?;
        sock.write_all(&public).map_err(io_err)?;
    }

    let mut shared = x25519::x25519(secret_scalar, peer_public);
    if shared == [0u8; 32] {
        return Err("handshake: peer offered a low-order public key".into());
    }

    let mut transcript = Vec::with_capacity(PROTO.len() + 64);
    transcript.extend_from_slice(PROTO);
    if is_client {
        transcript.extend_from_slice(&public);
        transcript.extend_from_slice(&peer_public);
    } else {
        transcript.extend_from_slice(&peer_public);
        transcript.extend_from_slice(&public);
    }

    // Salt the schedule with the code secret: knowing the code is what makes
    // the derived keys the right ones.
    let prk = hmac_sha256(secret, &shared);
    let okm = hkdf_expand(&prk, INFO, 128)?;

    let c2s_enc = key_at(&okm, 0);
    let s2c_enc = key_at(&okm, 1);
    let c2s_mac = key_at(&okm, 2);
    let s2c_mac = key_at(&okm, 3);

    let auth_key = hmac_sha256(&okm[96..128], PROTO);
    let client_tag = tag_for(&auth_key, &transcript, b"client");
    let server_tag = tag_for(&auth_key, &transcript, b"server");

    let mut peer_tag = [0u8; 32];
    if is_client {
        sock.write_all(&client_tag).map_err(io_err)?;
        sock.read_exact(&mut peer_tag).map_err(io_err)?;
        if !constant_time_eq(&peer_tag, &server_tag) {
            return Err("handshake: the far side does not hold this code".into());
        }
    } else {
        sock.read_exact(&mut peer_tag).map_err(io_err)?;
        if !constant_time_eq(&peer_tag, &client_tag) {
            return Err("handshake: caller does not hold this code".into());
        }
        sock.write_all(&server_tag).map_err(io_err)?;
    }

    let _ = sock.set_read_timeout(None);
    let _ = sock.set_write_timeout(None);

    let reader_sock = sock.try_clone().map_err(|e| format!("split socket: {e}"))?;

    let (rx_enc, rx_mac, tx_enc, tx_mac) = if is_client {
        (s2c_enc, s2c_mac, c2s_enc, c2s_mac)
    } else {
        (c2s_enc, c2s_mac, s2c_enc, s2c_mac)
    };

    wipe(&mut shared);
    wipe(&mut secret_scalar);

    Ok(Tunnel {
        rx: TunnelReader {
            sock: reader_sock,
            enc: rx_enc,
            mac: rx_mac,
            counter: 0,
            buf: Vec::new(),
            pos: 0,
        },
        tx: TunnelWriter {
            sock,
            enc: tx_enc,
            mac: tx_mac,
            counter: 0,
        },
    })
}

fn key_at(okm: &[u8], index: usize) -> [u8; 32] {
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[index * 32..index * 32 + 32]);
    key
}

fn tag_for(key: &[u8; 32], transcript: &[u8], side: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(transcript.len() + side.len());
    input.extend_from_slice(transcript);
    input.extend_from_slice(side);
    hmac_sha256(key, &input)
}

fn nonce_for(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

impl TunnelReader {
    fn next_frame(&mut self) -> io::Result<()> {
        let mut len_bytes = [0u8; 4];
        self.sock.read_exact(&mut len_bytes)?;

        let len = u32::from_be_bytes(len_bytes) as usize;
        if len == 0 || len > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame length out of range",
            ));
        }

        let mut sealed = vec![0u8; len + TAG_LEN];
        self.sock.read_exact(&mut sealed)?;
        let (payload, tag) = sealed.split_at(len);

        let mut mac_input = Vec::with_capacity(4 + len);
        mac_input.extend_from_slice(&len_bytes);
        mac_input.extend_from_slice(payload);

        let want = hmac_sha256(&self.mac, &mac_input);
        if !constant_time_eq(tag, &want) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame failed authentication",
            ));
        }

        let mut plain = payload.to_vec();
        let mut cipher = ChaCha20::new(&self.enc, &nonce_for(self.counter));
        cipher.xor(&mut plain);

        self.counter = self.counter.wrapping_add(1);
        self.buf = plain;
        self.pos = 0;
        Ok(())
    }
}

impl Read for TunnelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos >= self.buf.len() {
            match self.next_frame() {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            }
        }

        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Read for Tunnel {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.rx.read(out)
    }
}

impl Write for TunnelWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }

        let n = data.len().min(MAX_FRAME);
        let mut sealed = data[..n].to_vec();

        let mut cipher = ChaCha20::new(&self.enc, &nonce_for(self.counter));
        cipher.xor(&mut sealed);

        let len_bytes = (n as u32).to_be_bytes();
        let mut mac_input = Vec::with_capacity(4 + n);
        mac_input.extend_from_slice(&len_bytes);
        mac_input.extend_from_slice(&sealed);
        let tag = hmac_sha256(&self.mac, &mac_input);

        self.sock.write_all(&len_bytes)?;
        self.sock.write_all(&sealed)?;
        self.sock.write_all(&tag)?;

        self.counter = self.counter.wrapping_add(1);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

impl Write for Tunnel {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.tx.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tx.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn handshake_pair(secret: [u8; SECRET_LEN]) -> (Tunnel, Tunnel) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            server(sock, &secret).unwrap()
        });

        let client_sock = TcpStream::connect(addr).unwrap();
        let client = client(client_sock, &secret).unwrap();
        let server = server.join().unwrap();
        (client, server)
    }

    #[test]
    fn round_trips_in_both_directions() {
        let (mut c, mut s) = handshake_pair([7u8; SECRET_LEN]);

        c.write_all(b"hello from client").unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello from client");

        s.write_all(b"hello back, over a longer frame than one read")
            .unwrap();
        let mut buf2 = [0u8; 128];
        let n2 = s_rx(&mut c, &mut buf2);
        assert!(buf2[..n2].starts_with(b"hello back"));
    }

    fn s_rx(c: &mut Tunnel, buf: &mut [u8]) -> usize {
        let mut got = 0;
        while got < 10 {
            match c.read(&mut buf[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => break,
            }
        }
        got
    }

    #[test]
    fn rejects_a_peer_without_the_code() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            server(sock, &[1u8; SECRET_LEN]).is_err()
        });

        let sock = TcpStream::connect(addr).unwrap();
        let client_result = client(sock, &[2u8; SECRET_LEN]);

        assert!(client_result.is_err());
        assert!(server.join().unwrap());
    }
}
