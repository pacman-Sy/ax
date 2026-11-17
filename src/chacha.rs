//! ChaCha20 keystream (RFC 8439) with a 96-bit nonce. Stream cipher only; the
//! integrity tag is HMAC-SHA256 in tunnel.rs, so encrypt-then-MAC stays simple.

pub struct ChaCha20 {
    state: [u32; 16],
    block: [u8; 64],
    pos: usize,
    counter: u32,
}

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> ChaCha20 {
        let mut state = [0u32; 16];

        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        for i in 0..8 {
            state[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }

        ChaCha20 {
            state,
            block: [0u8; 64],
            pos: 64,
            counter: 0,
        }
    }

    fn refill(&mut self) {
        let mut working = self.state;
        working[12] = self.counter;

        for _ in 0..10 {
            quarter(&mut working, 0, 4, 8, 12);
            quarter(&mut working, 1, 5, 9, 13);
            quarter(&mut working, 2, 6, 10, 14);
            quarter(&mut working, 3, 7, 11, 15);
            quarter(&mut working, 0, 5, 10, 15);
            quarter(&mut working, 1, 6, 11, 12);
            quarter(&mut working, 2, 7, 8, 13);
            quarter(&mut working, 3, 4, 9, 14);
        }

        for i in 0..16 {
            working[i] = working[i].wrapping_add(self.state[i]);
            let bytes = working[i].to_le_bytes();
            self.block[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }

        self.counter = self.counter.wrapping_add(1);
        self.pos = 0;
    }

    pub fn xor(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.pos == 64 {
                self.refill();
            }
            *byte ^= self.block[self.pos];
            self.pos += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keystream(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let mut c = ChaCha20::new(key, nonce);
        c.xor(&mut buf);
        buf
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Keystream for key = 00..1f and nonce bytes (i * 7 + 1), 128 bytes.
    /// Generated with `openssl enc -chacha20 -K <key> -iv 00000000<nonce>` over
    /// 128 zero bytes and then frozen here, so the test needs no network or
    /// external tool.
    #[test]
    fn matches_openssl_vector() {
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let mut nonce = [0u8; 12];
        for i in 0..12 {
            nonce[i] = (i as u8).wrapping_mul(7).wrapping_add(1);
        }

        let ks = keystream(&key, &nonce, 128);
        assert_eq!(
            hex(&ks),
            concat!(
                "18d4720511f610a2d1d62bbdd2c853291a75b5f0add067d71108e0efae132090",
                "7cb488d3fab0ffd00f934f14cbd2cb68311e23b707391b8a85fae3b308ba1131",
                "f544395032eb5bce7254fef632db7ce6f5e33ffc20371b851cc119cc9bbead18",
                "2bd435d1e72a43aa5a64b30597574bf863d427ea1e44b6cdff03ccc73978704d",
            )
        );
    }

    #[test]
    fn keystream_is_a_stream() {
        let key = [9u8; 32];
        let nonce = [3u8; 12];

        let mut buf = vec![0u8; 200];
        let mut first = ChaCha20::new(&key, &nonce);
        first.xor(&mut buf);
        let original = buf.clone();

        let mut second = ChaCha20::new(&key, &nonce);
        second.xor(&mut buf);
        assert_eq!(buf, vec![0u8; 200]);

        let mut third = ChaCha20::new(&key, &nonce);
        third.xor(&mut buf);
        assert_eq!(buf, original);
    }
}
