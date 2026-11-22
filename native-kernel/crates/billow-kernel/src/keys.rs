//! Key derivation shared by the protocol outbounds.
//!
//! - Shadowsocks AEAD 2017 (SIP004): `EVP_BytesToKey` master key plus the
//!   HKDF-SHA1 info strings the whole ecosystem uses.
//! - Trojan: SHA-224 hex of the password (56-byte ASCII, as in trojan-go and
//!   Mihomo's `transport/trojan`).
//! - VMess-style UUID parsing for VLESS: 16 hex digits or a dashed UUID.

use sha2::{Digest, Sha224};

/// `EVP_BytesToKey(password, md5, salt, 1)` with the OpenSSL 1.x semantics
/// (one MD5 round, so the key is repeated when it is longer than 16 bytes).
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    // D_1 = MD5(password); D_i = MD5(D_{i-1}||password). This is what both
    // Mihomo's `Kdf` (transport/shadowsocks/core: it writes `prev` then the
    // password into every round) and OpenSSL's EVP_BytesToKey compute; the
    // specific vector below was printed by Go before being pinned.
    let mut prev: Vec<u8> = Vec::new();
    let mut out = Vec::with_capacity(key_len);
    while out.len() < key_len {
        let mut input = Vec::with_capacity(prev.len() + password.len());
        input.extend_from_slice(&prev);
        input.extend_from_slice(password);
        prev = md5(&input).to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

/// HKDF-SHA1 with an explicit salt (Shadowsocks: salt = the connection salt).
pub fn hkdf_sha1_with_salt(salt: &[u8], key: &[u8], len: usize) -> Vec<u8> {
    // `Some(salt)` also extracts on an empty salt instead of the RFC's
    // zero-filled one; the salt here is the connection salt.
    let hk = hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), key);
    let mut out = vec![0u8; len];
    hk.expand(INFO_SS_SUBKEY, &mut out)
        .expect("HKDF output length is bounded");
    out
}

/// HKDF-SHA1 with an empty salt (Shadowsocks: `salt` is the KDF salt, see
/// [`hkdf_sha1_with_salt`]).
pub fn hkdf_sha1(info: &[u8], key: &[u8], len: usize) -> Vec<u8> {
    let hk = hkdf::Hkdf::<sha1::Sha1>::new(None, key);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)
        .expect("HKDF output length is bounded");
    out
}

pub const INFO_SS_SUBKEY: &[u8] = b"ss-subkey";
pub const INFO_AEAD_2022: &[u8] = b"ss-aead-key";

/// Trojan password key: `sha224(password)` rendered as lowercase hex (56 bytes).
/// Mihomo and trojan-go reject passwords longer than 56 bytes; the encoded key
/// is truncated to 56 bytes.
pub fn trojan_password_key(password: &str) -> Vec<u8> {
    let hash = Sha224::digest(password.as_bytes());
    let mut hex = String::with_capacity(56);
    for byte in hash {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex.into_bytes()
}

/// Parse a VLESS user id as 16 raw bytes (dashed UUID or 32 hex digits).
pub fn parse_uuid(raw: &str) -> Result<[u8; 16], String> {
    let hex: String = raw.chars().filter(|c| *c != '-').collect();
    let dashed_ok = raw.len() == 36
        && raw.as_bytes()[8] == b'-'
        && raw.as_bytes()[13] == b'-'
        && raw.as_bytes()[18] == b'-'
        && raw.as_bytes()[23] == b'-';
    if !(hex.len() == 32 && (raw.len() == 32 || dashed_ok)) {
        return Err(format!(
            "'{raw}' is not a UUID (want xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx or 32 hex digits)"
        ));
    }
    let mut out = [0u8; 16];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).expect("hex is ASCII");
        out[index] =
            u8::from_str_radix(pair, 16).map_err(|_| format!("'{raw}' has non-hex digits"))?;
    }
    Ok(out)
}

/// A string that prints as `<redacted>` in logs; the wrapped secret is reachable
/// only through [`Secret::expose`].
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

// Small MD5 so the workspace does not need another dependency. It backs
// `EVP_BytesToKey` (SIP004), the VMess user-id derivation and the VMess
// chacha20-poly1305 key schedule.
pub(crate) fn md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    // MD5's T table: floor(2^32 * |sin(i)|) for i = 1..=64 (RFC 1321).
    #[rustfmt::skip]
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];
    let mut message = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;
    for chunk in message.chunks(64) {
        let mut m = [0u32; 16];
        for (word, bytes) in m.iter_mut().zip(chunk.chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().expect("4 bytes"));
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..].copy_from_slice(&d0.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn sudoku_seed_canonicalises_key_material_like_the_pinned_helper() {
        // Printed by `tool/kernel-compat/peers/sudoku-vectors -op keypair`
        // (the pinned `sudoku.GenKeyPair` / `ClientAEADSeed`).
        let private =
            "b8b31447340b4075285104902992bee510a56b81d87db697e52fd3184d9f440cae6e44c1c6d9bf4d20a5ed01089f5ec3e3b09a1137fa357a3847cbd7aa6f5e0d";
        let public = "32b3e97af0b5d5a31a3b9adc1872ea4944ffe259ec3982d37c535511fdb5f5e2";
        assert_eq!(sudoku_seed(private).unwrap(), public);
        assert_eq!(sudoku_seed(public).unwrap(), public);
        // A non-hex PSK is used verbatim, and so is a hex string that is not
        // key material (the pinned helper keeps the text in both cases).
        assert_eq!(sudoku_seed("plain-psk").unwrap(), "plain-psk");
        assert_eq!(sudoku_seed("00").unwrap(), "00");
        assert_eq!(sudoku_seed("zz").unwrap(), "zz");
        assert_eq!(sudoku_seed("  padded-key  ").unwrap(), "padded-key");
    }

    use super::*;

    #[test]
    fn md5_matches_the_reference_digest() {
        let hex: String = md5(b"abc").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "900150983cd24fb0d6963f7d28e17f72");
        let empty: String = md5(b"").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(empty, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn evp_bytes_to_key_multi_block_matches_the_reference() {
        // 32-byte key requires two MD5 blocks: D_2 = MD5(D_1||password), the
        // rule Mihomo's `Kdf` follows. Values pinned from an independent
        // hashlib computation (password "ss-password" + 32 bytes of 0x07).
        let mut material = b"ss-password".to_vec();
        material.extend(std::iter::repeat(7u8).take(32));
        let first: String = md5(&material).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(first, "d3a9726d17e726d7dca31fa292f8be55");
        let second: String = md5(&[md5(&material).as_slice(), &material].concat())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(second, "59759f9f187d0842f0f95f32eefc822a");
        assert_eq!(
            evp_bytes_to_key(&material, 32),
            vec![
                0xd3, 0xa9, 0x72, 0x6d, 0x17, 0xe7, 0x26, 0xd7, 0xdc, 0xa3, 0x1f, 0xa2, 0x92, 0xf8,
                0xbe, 0x55, 0x59, 0x75, 0x9f, 0x9f, 0x18, 0x7d, 0x08, 0x42, 0xf0, 0xf9, 0x5f, 0x32,
                0xee, 0xfc, 0x82, 0x2a
            ]
        );
    }

    #[test]
    fn shadowsocks_2017_derivation() {
        // OpenSSL EVP_BytesToKey (MD5, one round) for the supported key sizes;
        // the password argument is the AEAD password with the salt appended.
        // Values recomputed with Python hashlib before being pinned.
        assert_eq!(
            evp_bytes_to_key(b"foobar", 16),
            vec![
                0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91, 0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12,
                0xc6, 0x3f
            ]
        );
        assert_eq!(
            evp_bytes_to_key(b"test", 16),
            vec![
                0x09, 0x8f, 0x6b, 0xcd, 0x46, 0x21, 0xd3, 0x73, 0xca, 0xde, 0x4e, 0x83, 0x26, 0x27,
                0xb4, 0xf6
            ]
        );
        // The subkey is HKDF-SHA1(psk, salt, "ss-subkey"); the Go reference
        // below is the authoritative check.
        assert_eq!(
            hkdf_sha1_with_salt(
                b"0123456789abcdef0123456789abcdef",
                &evp_bytes_to_key(b"pw", 32),
                32
            )
            .len(),
            32
        );
    }

    #[test]
    fn derivation_matches_go_metacubex_shadowaead() {
        // Reference values printed by Go (crypto/md5 + golang.org/x/crypto/hkdf,
        // the libraries Mihomo's `transport/shadowsocks` uses): `Kdf("pw", 32)`
        // then `HKDF-SHA1(psk, salt "0123...ef", "ss-subkey")` must give this
        // subkey (32-byte AES-256-GCM key).
        assert_eq!(
            evp_bytes_to_key(b"pw", 32),
            vec![
                0x8f, 0xe4, 0xc1, 0x14, 0x51, 0x28, 0x1c, 0x09, 0x4a, 0x65, 0x78, 0xe6, 0xdd, 0xbf,
                0x5e, 0xed, 0xf2, 0x0d, 0x7d, 0xd7, 0x0d, 0xa9, 0x01, 0xc0, 0xc4, 0x47, 0x22, 0x1c,
                0x81, 0x86, 0x48, 0x26
            ]
        );
        assert_eq!(
            hkdf_sha1_with_salt(
                b"0123456789abcdef0123456789abcdef",
                &evp_bytes_to_key(b"pw", 32),
                32
            ),
            vec![
                0x9a, 0x55, 0x2e, 0xd0, 0x76, 0x4f, 0x72, 0x9d, 0xb6, 0x1f, 0x18, 0xb8, 0xb2, 0x11,
                0xdf, 0x9f, 0x09, 0x03, 0x6d, 0xf7, 0x5d, 0xa5, 0xb9, 0x40, 0xd6, 0xe7, 0x7f, 0xd2,
                0x69, 0xc0, 0xbc, 0xd9
            ]
        );
    }

    #[test]
    fn trojan_key_is_sha224_hex() {
        let key = trojan_password_key("password");
        assert_eq!(key.len(), 56);
        assert_eq!(
            String::from_utf8(key).unwrap(),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn uuids_parse_both_spellings() {
        let dashed = parse_uuid("9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68").unwrap();
        let plain = parse_uuid("9d0cb9d0964f4ef6897d6c6b3ccf9e68").unwrap();
        assert_eq!(dashed, plain);
        assert!(parse_uuid("xyz").is_err());
    }
}

/// Sudoku's canonical AEAD seed (`ClientAEADSeed`/`ServerAEADSeed` of the
/// pinned source): a hex key is interpreted as key material and replaced by
/// the compressed public point it carries or derives, anything else is used
/// verbatim. Both sides must agree on this string because the table and the
/// KIP/HKDF keys are derived from it.
pub fn sudoku_seed(key: &str) -> Result<String, String> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    let key = key.trim();
    if key.is_empty() {
        return Ok(String::new());
    }
    let bytes = match decode_hex(key) {
        Some(bytes) => bytes,
        None => return Ok(key.to_string()),
    };
    let encode = |point: &curve25519_dalek::edwards::EdwardsPoint| hex_encode(&point.compress().to_bytes());
    if bytes.len() == 32 {
        // A compressed point and a scalar share the length; the pinned helper
        // keeps a valid point verbatim and only then treats the bytes as a
        // private scalar.
        if let Some(point) = CompressedEdwardsY(
            bytes.as_slice().try_into().map_err(|_| "32 bytes")?,
        )
        .decompress()
        {
            return Ok(encode(&point));
        }
    }
    let scalar = |slice: &[u8]| -> Option<Scalar> {
        let array: [u8; 32] = slice.try_into().ok()?;
        Option::<Scalar>::from(Scalar::from_canonical_bytes(array))
    };
    let public = match bytes.len() {
        32 => scalar(&bytes).map(|x| curve25519_dalek::edwards::EdwardsPoint::mul_base(&x)),
        64 => {
            let (r, k) = bytes.split_at(32);
            match (scalar(r), scalar(k)) {
                (Some(r), Some(k)) => Some(curve25519_dalek::edwards::EdwardsPoint::mul_base(
                    &(r + k),
                )),
                _ => None,
            }
        }
        _ => None,
    };
    match public {
        Some(point) => Ok(encode(&point)),
        None => Ok(key.to_string()),
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
