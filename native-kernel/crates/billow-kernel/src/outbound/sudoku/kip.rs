//! The Sudoku KIP control plane (`transport/sudoku/kip.go`).
//!
//! Messages are `"kip" | type | u16 length | payload` on the record stream.
//! The handshake is a client hello (timestamp, user hash, nonce, X25519 public
//! key, feature bits and an optional table hint) answered by a server hello
//! that echoes the nonce and carries the server's public key; both sides then
//! rekey the record layer with HKDF over the shared secret. The first message
//! after the handshake selects the session kind: `OpenTCP` carries the target.

use std::io;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub const TYPE_CLIENT_HELLO: u8 = 0x01;
pub const TYPE_SERVER_HELLO: u8 = 0x02;
pub const TYPE_OPEN_TCP: u8 = 0x10;
pub const TYPE_START_MUX: u8 = 0x11;
pub const TYPE_START_UOT: u8 = 0x12;
pub const TYPE_KEEP_ALIVE: u8 = 0x14;

pub const FEATURE_OPEN_TCP: u32 = 1 << 0;
pub const FEATURE_MUX: u32 = 1 << 1;
pub const FEATURE_UOT: u32 = 1 << 2;
pub const FEATURE_KEEP_ALIVE: u32 = 1 << 4;
pub const FEATURE_ALL: u32 = FEATURE_OPEN_TCP | FEATURE_MUX | FEATURE_UOT | FEATURE_KEEP_ALIVE;

const MAGIC: &[u8; 3] = b"kip";
const HEADER: usize = 6; // magic(3) + type(1) + u16 length
const MAX_PAYLOAD: usize = 64 * 1024;
pub const NONCE_LEN: usize = 16;
pub const PUBLIC_KEY_LEN: usize = 32;

/// `kipUserHashFromKey`: the first 8 bytes of SHA-256 over the raw key bytes
/// (hex-decoded when the key is hex, as the pinned helper does).
pub fn user_hash(key: &str) -> [u8; 8] {
    let key = key.trim();
    let mut out = [0u8; 8];
    if key.is_empty() {
        return out;
    }
    let digest = match decode_hex(key) {
        Some(bytes) if !bytes.is_empty() => Sha256::digest(&bytes),
        _ => Sha256::digest(key.as_bytes()),
    };
    out.copy_from_slice(&digest[..8]);
    out
}

pub fn encode_message(kind: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sudoku: KIP payload too large",
        ));
    }
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// A KIP message parsed from the plaintext stream; `total` is the number of
/// bytes it occupied.
pub struct Message {
    pub kind: u8,
    pub payload: Vec<u8>,
    pub total: usize,
}

/// Parse one message from `buffer`; `None` when more bytes are needed.
pub fn parse_message(buffer: &[u8]) -> io::Result<Option<Message>> {
    if buffer.len() < HEADER {
        return Ok(None);
    }
    if &buffer[..3] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sudoku: bad KIP magic",
        ));
    }
    let kind = buffer[3];
    let len = u16::from_be_bytes([buffer[4], buffer[5]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sudoku: KIP payload too large",
        ));
    }
    if buffer.len() < HEADER + len {
        return Ok(None);
    }
    Ok(Some(Message {
        kind,
        payload: buffer[HEADER..HEADER + len].to_vec(),
        total: HEADER + len,
    }))
}

pub struct ClientHello {
    pub timestamp: u64,
    pub user_hash: [u8; 8],
    pub nonce: [u8; NONCE_LEN],
    pub client_pub: [u8; PUBLIC_KEY_LEN],
    pub features: u32,
    pub table_hint: Option<u32>,
}

impl ClientHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(68);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.user_hash);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.client_pub);
        out.extend_from_slice(&self.features.to_be_bytes());
        if let Some(hint) = self.table_hint {
            out.extend_from_slice(&hint.to_be_bytes());
        }
        out
    }
}

pub struct ServerHello {
    pub nonce: [u8; NONCE_LEN],
    pub server_pub: [u8; PUBLIC_KEY_LEN],
    pub selected_features: u32,
}

pub fn decode_server_hello(payload: &[u8]) -> io::Result<ServerHello> {
    if payload.len() != NONCE_LEN + PUBLIC_KEY_LEN + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sudoku: server hello has the wrong length",
        ));
    }
    let mut hello = ServerHello {
        nonce: [0u8; NONCE_LEN],
        server_pub: [0u8; PUBLIC_KEY_LEN],
        selected_features: 0,
    };
    hello.nonce.copy_from_slice(&payload[..NONCE_LEN]);
    hello
        .server_pub
        .copy_from_slice(&payload[NONCE_LEN..NONCE_LEN + PUBLIC_KEY_LEN]);
    let offset = NONCE_LEN + PUBLIC_KEY_LEN;
    hello.selected_features = u32::from_be_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ]);
    Ok(hello)
}

fn expand(prk: &[u8], info: &[u8]) -> io::Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sudoku: invalid HKDF PRK"))?;
    let mut out = [0u8; 32];
    hkdf.expand(info, &mut out)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sudoku: HKDF expand failed"))?;
    Ok(out)
}

/// `derivePSKDirectionalBases`: HKDF-Expand over `SHA256(psk)` before the
/// handshake.
pub fn psk_directional_bases(seed: &str) -> io::Result<([u8; 32], [u8; 32])> {
    let sum = Sha256::digest(seed.as_bytes());
    let okm_c2s = expand(&sum, b"sudoku-psk-c2s")?;
    let okm_s2c = expand(&sum, b"sudoku-psk-s2c")?;
    Ok((okm_c2s, okm_s2c))
}

/// `deriveSessionDirectionalBases`: HKDF-Extract(salt = SHA256(psk), ikm =
/// shared secret || client nonce), then Expand per direction.
pub fn session_directional_bases(
    seed: &str,
    shared: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> io::Result<([u8; 32], [u8; 32])> {
    let salt = Sha256::digest(seed.as_bytes());
    let mut ikm = Vec::with_capacity(shared.len() + NONCE_LEN);
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(nonce);
    // `Hkdf::new` performs the extract step (salt, ikm) that Go's
    // `hkdf.Extract` does; `expand` then uses that PRK.
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hkdf.expand(b"sudoku-session-c2s", &mut c2s)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sudoku: HKDF expand failed"))?;
    hkdf.expand(b"sudoku-session-s2c", &mut s2c)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sudoku: HKDF expand failed"))?;
    Ok((c2s, s2c))
}

/// A fresh X25519 key pair.
pub fn ephemeral_key() -> (StaticSecret, [u8; PUBLIC_KEY_LEN]) {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret).to_bytes();
    (secret, public)
}

pub fn shared_secret(secret: &StaticSecret, peer: &[u8; PUBLIC_KEY_LEN]) -> [u8; 32] {
    secret.diffie_hellman(&PublicKey::from(*peer)).to_bytes()
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_and_wait_for_completion() {
        let wire = encode_message(TYPE_OPEN_TCP, b"address").unwrap();
        assert_eq!(wire.len(), 6 + 7);
        assert!(parse_message(&wire[..4]).unwrap().is_none());
        let message = parse_message(&wire).unwrap().unwrap();
        assert_eq!(message.kind, TYPE_OPEN_TCP);
        assert_eq!(message.payload, b"address");
        assert_eq!(message.total, wire.len());
    }

    #[test]
    fn a_bad_magic_is_rejected() {
        let mut wire = encode_message(TYPE_CLIENT_HELLO, &[]).unwrap();
        wire[0] = b'x';
        assert!(parse_message(&wire).is_err());
    }

    #[test]
    fn the_user_hash_prefers_the_hex_key_bytes() {
        // sha256(0x01 0x02 ...) is not the hash of the ascii digits.
        let hex_key = "0102030405060708090a0b0c0d0e0f10";
        let from_bytes = Sha256::digest(decode_hex(hex_key).unwrap());
        let from_text = Sha256::digest(hex_key.as_bytes());
        assert_eq!(user_hash(hex_key).to_vec(), from_bytes[..8].to_vec());
        assert_ne!(user_hash(hex_key).to_vec(), from_text[..8].to_vec());
        assert_eq!(
            user_hash("plain-psk").to_vec(),
            Sha256::digest(b"plain-psk")[..8].to_vec()
        );
    }

    #[test]
    fn both_sides_derive_the_same_session_keys() {
        let (client_secret, client_pub) = ephemeral_key();
        let (server_secret, server_pub) = ephemeral_key();
        let client_shared = shared_secret(&client_secret, &server_pub);
        let server_shared = shared_secret(&server_secret, &client_pub);
        assert_eq!(client_shared, server_shared);
        let nonce = [7u8; NONCE_LEN];
        let (c2s, s2c) = session_directional_bases("key", &client_shared, &nonce).unwrap();
        let (c2s2, s2c2) = session_directional_bases("key", &server_shared, &nonce).unwrap();
        assert_eq!((c2s, s2c), (c2s2, s2c2));
    }
}
