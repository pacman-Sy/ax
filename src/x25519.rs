//! X25519 (RFC 7748), radix 2^51 limbs. Used once per session to agree on
//! fresh keys, so a stolen code does not decrypt traffic recorded earlier.

type Fe = [u64; 5];

const MASK: u64 = (1u64 << 51) - 1;

const ONE: Fe = [1, 0, 0, 0, 0];
const ZERO: Fe = [0, 0, 0, 0, 0];

// p = 2^255 - 19
const P: Fe = [
    0x7ffffffffffed,
    0x7ffffffffffff,
    0x7ffffffffffff,
    0x7ffffffffffff,
    0x7ffffffffffff,
];

// 2p, used to bias subtraction so limbs never underflow.
const TWO_P: Fe = [
    0x000FFFFFFFFFFFDA,
    0x000FFFFFFFFFFFFE,
    0x000FFFFFFFFFFFFE,
    0x000FFFFFFFFFFFFE,
    0x000FFFFFFFFFFFFE,
];

fn carry(r: &mut Fe) {
    for _ in 0..3 {
        r[1] += r[0] >> 51;
        r[0] &= MASK;
        r[2] += r[1] >> 51;
        r[1] &= MASK;
        r[3] += r[2] >> 51;
        r[2] &= MASK;
        r[4] += r[3] >> 51;
        r[3] &= MASK;
        r[0] += 19 * (r[4] >> 51);
        r[4] &= MASK;
    }
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 5];
    for i in 0..5 {
        r[i] = a[i] + b[i];
    }
    carry(&mut r);
    r
}

fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 5];
    for i in 0..5 {
        r[i] = a[i] + TWO_P[i] - b[i];
    }
    carry(&mut r);
    r
}

fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let a0 = a[0] as u128;
    let a1 = a[1] as u128;
    let a2 = a[2] as u128;
    let a3 = a[3] as u128;
    let a4 = a[4] as u128;

    let b0 = b[0] as u128;
    let b1 = b[1] as u128;
    let b2 = b[2] as u128;
    let b3 = b[3] as u128;
    let b4 = b[4] as u128;

    let b1_19 = b1 * 19;
    let b2_19 = b2 * 19;
    let b3_19 = b3 * 19;
    let b4_19 = b4 * 19;

    let c0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
    let c1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
    let c2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
    let c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
    let c4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

    let mut r = [0u64; 5];
    let mut t = c0;
    r[0] = (t as u64) & MASK;
    t >>= 51;
    t += c1;
    r[1] = (t as u64) & MASK;
    t >>= 51;
    t += c2;
    r[2] = (t as u64) & MASK;
    t >>= 51;
    t += c3;
    r[3] = (t as u64) & MASK;
    t >>= 51;
    t += c4;
    r[4] = (t as u64) & MASK;
    t >>= 51;
    r[0] += (t as u64) * 19;

    carry(&mut r);
    r
}

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

fn fe_mul_small(a: &Fe, k: u64) -> Fe {
    let mut r = [0u64; 5];
    let mut acc: u128 = 0;
    for i in 0..5 {
        let v = (a[i] as u128) * (k as u128) + acc;
        r[i] = (v as u64) & MASK;
        acc = v >> 51;
    }
    r[0] += (acc as u64) * 19;
    carry(&mut r);
    r
}

fn fe_from_bytes(b: &[u8; 32]) -> Fe {
    let load = |i: usize| -> u64 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[i..i + 8]);
        u64::from_le_bytes(w)
    };

    [
        load(0) & MASK,
        (load(6) >> 3) & MASK,
        (load(12) >> 6) & MASK,
        (load(19) >> 1) & MASK,
        (load(24) >> 12) & MASK,
    ]
}

fn fe_to_bytes(f: &Fe) -> [u8; 32] {
    let mut t = *f;
    carry(&mut t);
    carry(&mut t);

    // Conditional subtract of p so the encoding is canonical.
    let mut borrow: i128 = 0;
    let mut d = [0u64; 5];
    for i in 0..5 {
        let v = t[i] as i128 - P[i] as i128 - borrow;
        if v < 0 {
            d[i] = (v + (1i128 << 51)) as u64;
            borrow = 1;
        } else {
            d[i] = v as u64;
            borrow = 0;
        }
    }
    if borrow == 0 {
        t = d;
    }

    let mut out = [0u8; 32];
    for i in 0..5 {
        let bit = i * 51;
        let byte = bit / 8;
        let shift = bit % 8;
        let mut chunk = (t[i] as u128) << shift;
        for j in 0..8 {
            if byte + j < 32 {
                out[byte + j] |= (chunk & 0xff) as u8;
            }
            chunk >>= 8;
        }
    }
    out
}

fn fe_invert(a: &Fe) -> Fe {
    // a^(p-2), 2^255 - 21 = 0x7fff...ffeb
    let mut exp = [0xffu8; 32];
    exp[0] = 0xeb;
    exp[31] = 0x7f;

    let mut result = ONE;
    for byte in exp.iter().rev() {
        for bit in (0..8).rev() {
            result = fe_sq(&result);
            if (byte >> bit) & 1 == 1 {
                result = fe_mul(&result, a);
            }
        }
    }
    result
}

fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

pub fn x25519(secret: [u8; 32], point: [u8; 32]) -> [u8; 32] {
    let mut k = secret;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = fe_from_bytes(&point);
    let mut x2 = ONE;
    let mut z2 = ZERO;
    let mut x3 = x1;
    let mut z3 = ONE;
    let mut swap: u64 = 0;

    for t in (0..255).rev() {
        let bit = ((k[t >> 3] >> (t & 7)) & 1) as u64;
        swap ^= bit;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = bit;

        let a = fe_add(&x2, &z2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);

        x3 = fe_sq(&fe_add(&da, &cb));
        z3 = fe_mul(&x1, &fe_sq(&fe_sub(&da, &cb)));

        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&e, &fe_add(&aa, &fe_mul_small(&e, 121665)));
    }

    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);

    let out = fe_mul(&x2, &fe_invert(&z2));
    fe_to_bytes(&out)
}

pub fn keypair() -> Result<([u8; 32], [u8; 32]), String> {
    let secret: [u8; 32] = crate::rand::bytes()?;
    let mut base = [0u8; 32];
    base[0] = 9;
    let public = x25519(secret, base);
    Ok((secret, public))
}

#[cfg(test)]
/// RFC 7748 base point: the little-endian encoding of u = 9.
const BASE_POINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "expected 32 bytes of hex");
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn rfc7748_section_5_2() {
        let alice_secret =
            hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public = x25519(alice_secret, BASE_POINT);
        assert_eq!(
            alice_public,
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );

        let bob_secret = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public = x25519(bob_secret, BASE_POINT);
        assert_eq!(
            bob_public,
            hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );

        let shared_a = x25519(alice_secret, bob_public);
        let shared_b = x25519(bob_secret, alice_public);
        assert_eq!(shared_a, shared_b);
        assert_eq!(
            shared_a,
            hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    /// RFC 7748 section 5.2 also pins the scalar-multiply-by-base case for
    /// k = 2^254 + 2^253 + ... (the "1 iterated" vector), which catches ladder
    /// errors the key-agreement vectors alone can miss.
    #[test]
    fn rfc7748_iterated_scalar() {
        let k = hex32("0900000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(
            x25519(k, BASE_POINT),
            hex32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
        );
    }

    /// Clamping is mandatory: the low three bits are cleared and bit 254 is
    /// set, so two scalars that differ only there must agree.
    #[test]
    fn clamps_the_scalar() {
        let mut a = [0x77u8; 32];
        a[0] &= 0xf8;
        a[31] &= 0x7f;
        a[31] |= 0x40;

        let mut b = a;
        b[0] |= 0x07;
        assert_eq!(x25519(a, BASE_POINT), x25519(b, BASE_POINT));
    }

    #[test]
    fn keypair_agrees() {
        let (a_priv, a_pub) = keypair().unwrap();
        let (b_priv, b_pub) = keypair().unwrap();
        assert_eq!(x25519(a_priv, b_pub), x25519(b_priv, a_pub));
    }
}
