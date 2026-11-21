//! ZeroTier VL1/VL2 protocol adapter (T19).
//!
//! Implemented from ZeroTier's public wire protocol and verified against a
//! controlled peer built from the locked `github.com/metacubex/zerotier-go`
//! module (MPL-2.0, test-only). No Go source is copied or linked:
//!
//! * identity: the 40-bit address proof of work over the combined X25519 +
//!   Ed25519 public key (2 MiB Salsa20/20 memory-hard hash), the
//!   `address:0:public[:private]` text form and the binary identity form;
//! * planet/moon world parsing (roots, endpoints, update key);
//! * VL1 packet framing (IV/destination/source/flags/authenticator/verb),
//!   Salsa20/12 + Poly1305 armor and the protocol-13 extended HELLO armor;
//! * HELLO/OK, WHOIS and ECHO verbs, and the VL2 Ethernet frame payload;
//! * a UDP client that completes the HELLO handshake with a peer.
//!
//! The pinned adapter also owns a userspace IP stack, a TUN device and the
//! network-controller membership exchange. Those are T6/T7 (device/TUN) and
//! T5 (network configuration) responsibilities, so [`crate::outbound::mod`]
//! refuses a `dial()` through this outbound with that gap named while the
//! protocol layer below is available to the device layer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use aes::Aes256;
use ctr::Ctr128BE;
use ed25519_dalek::{SigningKey, VerifyingKey};
use poly1305::universal_hash::KeyInit as _;
use poly1305::{Poly1305, Tag};
use rand::RngCore;
use salsa20::{Salsa12, Salsa20};
use sha2::{Digest, Sha512};
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};

/// ZeroTier's current wire protocol version.
pub const PROTOCOL_VERSION: u8 = 13;
/// Oldest peer protocol accepted in a HELLO.
pub const PROTOCOL_VERSION_MIN: u8 = 4;
pub const ADDRESS_SIZE: usize = 5;
pub const PUBLIC_KEY_SIZE: usize = 64;
pub const PRIVATE_KEY_SIZE: usize = 64;
pub const SYMMETRIC_KEY_SIZE: usize = 48;
pub const SIGNATURE_SIZE: usize = 96;

pub const PACKET_IV_OFFSET: usize = 0;
pub const PACKET_DEST_OFFSET: usize = 8;
pub const PACKET_SOURCE_OFFSET: usize = 13;
pub const PACKET_FLAGS_OFFSET: usize = 18;
pub const PACKET_MAC_OFFSET: usize = 19;
pub const PACKET_VERB_OFFSET: usize = 27;
pub const PACKET_PAYLOAD_OFFSET: usize = 28;
pub const PACKET_MIN_SIZE: usize = PACKET_PAYLOAD_OFFSET;

const EXTENDED_ARMOR_KEY_SIZE: usize = 32;
const FLAG_EXTENDED_ARMOR: u8 = 0x80;

/// The floating point of the VL1 verb space used by this adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Verb {
    Nop = 0x00,
    Hello = 0x01,
    Error = 0x02,
    Ok = 0x03,
    Whois = 0x04,
    Rendezvous = 0x05,
    Frame = 0x06,
    ExtFrame = 0x07,
    Echo = 0x08,
    MulticastLike = 0x09,
    NetworkCredentials = 0x0a,
    NetworkConfigRequest = 0x0b,
    NetworkConfig = 0x0c,
    MulticastGather = 0x0d,
    MulticastFrame = 0x0e,
    Ack = 0x12,
    UserMessage = 0x14,
}

impl Verb {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x00 => Verb::Nop,
            0x01 => Verb::Hello,
            0x02 => Verb::Error,
            0x03 => Verb::Ok,
            0x04 => Verb::Whois,
            0x05 => Verb::Rendezvous,
            0x06 => Verb::Frame,
            0x07 => Verb::ExtFrame,
            0x08 => Verb::Echo,
            0x09 => Verb::MulticastLike,
            0x0a => Verb::NetworkCredentials,
            0x0b => Verb::NetworkConfigRequest,
            0x0c => Verb::NetworkConfig,
            0x0d => Verb::MulticastGather,
            0x0e => Verb::MulticastFrame,
            0x12 => Verb::Ack,
            0x14 => Verb::UserMessage,
            _ => return None,
        })
    }
}

/// ZeroTier packet armor suite (`cipher` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Poly1305None,
    Poly1305Salsa2012,
    TrustedPath,
    AesGmacSiv,
}

impl Cipher {
    fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Cipher::Poly1305None,
            1 => Cipher::Poly1305Salsa2012,
            2 => Cipher::TrustedPath,
            _ => Cipher::AesGmacSiv,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ZerotierError {
    #[error("invalid ZeroTier identity: {0}")]
    InvalidIdentity(&'static str),
    #[error("invalid ZeroTier world: {0}")]
    InvalidWorld(&'static str),
    #[error("invalid ZeroTier packet: {0}")]
    InvalidPacket(&'static str),
    #[error("ZeroTier authentication failed")]
    Authentication,
    #[error("ZeroTier identity has no private key")]
    PrivateKeyMissing,
    #[error("ZeroTier network ID is invalid")]
    InvalidNetwork,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out waiting for the ZeroTier peer")]
    Timeout,
}

fn push_be_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn push_be_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn read_be_u16(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2)
        .map(|slice| u16::from_be_bytes([slice[0], slice[1]]))
}
fn read_be_u64(data: &[u8], at: usize) -> Option<u64> {
    let slice = data.get(at..at + 8)?;
    Some(u64::from_be_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

/// A ZeroTier node identity: a 40-bit address and the X25519/Ed25519 key pair.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    address: u64,
    public: [u8; PUBLIC_KEY_SIZE],
    private: Option<[u8; PRIVATE_KEY_SIZE]>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", self.address_string())
    }
}

impl Identity {
    /// Generate a secret identity satisfying ZeroTier's address proof of work.
    pub fn generate() -> Self {
        let mut ed_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ed_seed);
        let signing = SigningKey::from_bytes(&ed_seed);
        let mut private = [0u8; PRIVATE_KEY_SIZE];
        private[32..].copy_from_slice(&ed_seed);
        rand::thread_rng().fill_bytes(&mut private[..32]);
        loop {
            let secret = StaticSecret::from(<[u8; 32]>::try_from(&private[..32]).unwrap());
            let public_dh = PublicKey::from(&secret);
            let mut public = [0u8; PUBLIC_KEY_SIZE];
            public[..32].copy_from_slice(public_dh.as_bytes());
            public[32..].copy_from_slice(signing.verifying_key().as_bytes());
            let digest = identity_memory_hard_hash(&public);
            let address = address_from_digest(&digest);
            if digest[0] < 17 && !is_reserved_address(address) {
                return Identity {
                    address,
                    public,
                    private: Some(private),
                };
            }
            increment_identity_private(&mut private);
        }
    }

    pub fn parse(text: &str) -> Result<Self, ZerotierError> {
        let parts: Vec<&str> = text.trim().split(':').collect();
        if parts.len() != 3 && parts.len() != 4 {
            return Err(ZerotierError::InvalidIdentity("expected address:0:public[:private]"));
        }
        let address = parse_address(parts[0])?;
        if parts[1] != "0" {
            return Err(ZerotierError::InvalidIdentity("identity type must be 0"));
        }
        let public_bytes = hex::decode(parts[2])
            .map_err(|_| ZerotierError::InvalidIdentity("public key is not hex"))?;
        if public_bytes.len() != PUBLIC_KEY_SIZE {
            return Err(ZerotierError::InvalidIdentity("public key must be 64 bytes"));
        }
        let mut public = [0u8; PUBLIC_KEY_SIZE];
        public.copy_from_slice(&public_bytes);
        let private = if parts.len() == 4 {
            let private_bytes = hex::decode(parts[3])
                .map_err(|_| ZerotierError::InvalidIdentity("private key is not hex"))?;
            if private_bytes.len() != PRIVATE_KEY_SIZE {
                return Err(ZerotierError::InvalidIdentity("private key must be 64 bytes"));
            }
            let mut private = [0u8; PRIVATE_KEY_SIZE];
            private.copy_from_slice(&private_bytes);
            Some(private)
        } else {
            None
        };
        let identity = Identity {
            address,
            public,
            private,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn parse_binary(data: &[u8]) -> Result<(Self, usize), ZerotierError> {
        if data.len() < ADDRESS_SIZE + 1 + PUBLIC_KEY_SIZE + 1 {
            return Err(ZerotierError::InvalidIdentity("truncated binary identity"));
        }
        if data[ADDRESS_SIZE] != 0 {
            return Err(ZerotierError::InvalidIdentity("identity type must be 0"));
        }
        let address = address_from_bytes(&data[..ADDRESS_SIZE])
            .ok_or(ZerotierError::InvalidIdentity("bad address"))?;
        let mut public = [0u8; PUBLIC_KEY_SIZE];
        public.copy_from_slice(&data[ADDRESS_SIZE + 1..ADDRESS_SIZE + 1 + PUBLIC_KEY_SIZE]);
        let mut pos = ADDRESS_SIZE + 1 + PUBLIC_KEY_SIZE;
        let private_len = data[pos] as usize;
        pos += 1;
        let private = if private_len == 0 {
            None
        } else {
            if private_len != PRIVATE_KEY_SIZE || data.len() < pos + private_len {
                return Err(ZerotierError::InvalidIdentity("bad binary private key"));
            }
            let mut private = [0u8; PRIVATE_KEY_SIZE];
            private.copy_from_slice(&data[pos..pos + private_len]);
            pos += private_len;
            Some(private)
        };
        let identity = Identity {
            address,
            public,
            private,
        };
        identity.validate()?;
        Ok((identity, pos))
    }

    pub fn address(&self) -> u64 {
        self.address
    }
    pub fn address_string(&self) -> String {
        format!("{:010x}", self.address)
    }
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.public
    }
    pub fn has_private(&self) -> bool {
        self.private.is_some()
    }
    pub fn public_string(&self) -> String {
        format!("{}:0:{}", self.address_string(), hex::encode(self.public))
    }
    pub fn secret_string(&self) -> Option<String> {
        self.private
            .map(|private| format!("{}:0:{}:{}", self.address_string(), hex::encode(self.public), hex::encode(private)))
    }

    pub fn append_binary(&self, out: &mut Vec<u8>, include_private: bool) {
        out.extend_from_slice(&self.address.to_be_bytes()[3..]);
        out.push(0);
        out.extend_from_slice(&self.public);
        match (include_private, self.private) {
            (true, Some(private)) => {
                out.push(PRIVATE_KEY_SIZE as u8);
                out.extend_from_slice(&private);
            }
            _ => out.push(0),
        }
    }

    /// Validate the address proof of work and, when present, the private keys.
    pub fn validate(&self) -> Result<(), ZerotierError> {
        if is_reserved_address(self.address) {
            return Err(ZerotierError::InvalidIdentity("reserved address"));
        }
        let digest = identity_memory_hard_hash(&self.public);
        if digest[0] >= 17 || address_from_digest(&digest) != self.address {
            return Err(ZerotierError::InvalidIdentity("address proof of work does not match"));
        }
        if let Some(private) = self.private {
            let secret = StaticSecret::from(<[u8; 32]>::try_from(&private[..32]).unwrap());
            if PublicKey::from(&secret).as_bytes() != &self.public[..32] {
                return Err(ZerotierError::InvalidIdentity("X25519 private key does not match"));
            }
            let seed: [u8; 32] = private[32..].try_into().unwrap();
            let signing = SigningKey::from_bytes(&seed);
            if signing.verifying_key().as_bytes() != &self.public[32..] {
                return Err(ZerotierError::InvalidIdentity("Ed25519 private key does not match"));
            }
        }
        Ok(())
    }

    /// ZeroTier's 48-byte X25519 agreement secret.
    pub fn agree(&self, peer: &Identity) -> Result<[u8; SYMMETRIC_KEY_SIZE], ZerotierError> {
        let private = self.private.ok_or(ZerotierError::PrivateKeyMissing)?;
        let secret = StaticSecret::from(<[u8; 32]>::try_from(&private[..32]).unwrap());
        let peer_public = PublicKey::from(<[u8; 32]>::try_from(&peer.public[..32]).unwrap());
        let shared = secret.diffie_hellman(&peer_public);
        let digest = Sha512::digest(shared.as_bytes());
        let mut key = [0u8; SYMMETRIC_KEY_SIZE];
        key.copy_from_slice(&digest[..SYMMETRIC_KEY_SIZE]);
        Ok(key)
    }

    /// Sign a message with the Ed25519 half of the identity.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_SIZE], ZerotierError> {
        use ed25519_dalek::Signer;
        let private = self.private.ok_or(ZerotierError::PrivateKeyMissing)?;
        let seed: [u8; 32] = private[32..].try_into().unwrap();
        let signing = SigningKey::from_bytes(&seed);
        let digest = Sha512::digest(message);
        let signature = signing.sign(&digest[..32]);
        let mut out = [0u8; SIGNATURE_SIZE];
        out[..64].copy_from_slice(&signature.to_bytes());
        out[64..].copy_from_slice(&digest[..32]);
        Ok(out)
    }

    /// Verify a ZeroTier signature (Ed25519 over SHA-512(message)[..32]).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        use ed25519_dalek::Verifier;
        if signature.len() != SIGNATURE_SIZE {
            return false;
        }
        let digest = Sha512::digest(message);
        if signature[64..] != digest[..32] {
            return false;
        }
        let Ok(key_bytes) = <[u8; 32]>::try_from(&self.public[32..]) else {
            return false;
        };
        let Ok(verifying) = VerifyingKey::from_bytes(&key_bytes) else {
            return false;
        };
        let Ok(sig_bytes) = <[u8; 64]>::try_from(&signature[..64]) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying.verify(&digest[..32], &signature).is_ok()
    }
}

fn parse_address(text: &str) -> Result<u64, ZerotierError> {
    if text.len() != 10 {
        return Err(ZerotierError::InvalidIdentity("address must be 10 hex digits"));
    }
    let bytes = hex::decode(text).map_err(|_| ZerotierError::InvalidIdentity("address is not hex"))?;
    let address = address_from_bytes(&bytes).ok_or(ZerotierError::InvalidIdentity("bad address"))?;
    if is_reserved_address(address) {
        return Err(ZerotierError::InvalidIdentity("reserved address"));
    }
    Ok(address)
}

fn address_from_bytes(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != ADDRESS_SIZE {
        return None;
    }
    let mut value = 0u64;
    for byte in bytes {
        value = (value << 8) | *byte as u64;
    }
    Some(value)
}

fn address_from_digest(digest: &[u8; 64]) -> u64 {
    let mut value = 0u64;
    for byte in &digest[59..64] {
        value = (value << 8) | *byte as u64;
    }
    value
}

fn is_reserved_address(address: u64) -> bool {
    address == 0 || (address >> 32) as u8 == 0xff
}

fn increment_identity_private(private: &mut [u8; PRIVATE_KEY_SIZE]) {
    let second = u64::from_le_bytes(private[8..16].try_into().unwrap()) + 1;
    let third = u64::from_le_bytes(private[16..24].try_into().unwrap()) - 1;
    private[8..16].copy_from_slice(&second.to_le_bytes());
    private[16..24].copy_from_slice(&third.to_le_bytes());
}

/// Apply one Salsa20/20 block stream at `block_counter` (0-based).
fn salsa20_block(key: &[u8; 32], nonce: &[u8; 8], block_counter: u64, data: &mut [u8]) {
    let mut cipher = Salsa20::new(key.into(), nonce.into());
    cipher.seek(block_counter * 64);
    cipher.apply_keystream(data);
}

/// ZeroTier's 2 MiB memory-hard address hash (Salsa20/20).
fn identity_memory_hard_hash(public: &[u8; PUBLIC_KEY_SIZE]) -> [u8; 64] {
    let mut digest: [u8; 64] = Sha512::digest(public).into();
    let mut genmem = vec![0u8; 2 * 1024 * 1024];
    let key = <[u8; 32]>::try_from(&digest[..32]).unwrap();
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&digest[32..40]);

    salsa20_block(&key, &nonce, 0, &mut genmem[..64]);
    let mut block = 1u64;
    let mut offset = 64;
    while offset < genmem.len() {
        let previous = genmem[offset - 64..offset].to_vec();
        genmem[offset..offset + 64].copy_from_slice(&previous);
        salsa20_block(&key, &nonce, block, &mut genmem[offset..offset + 64]);
        block += 1;
        offset += 64;
    }

    let mut stream_counter = block;
    let mut i = 0;
    while i < genmem.len() {
        let idx1 = (u64::from_be_bytes(genmem[i..i + 8].try_into().unwrap()) & 7) as usize * 8;
        i += 8;
        let idx2 = (u64::from_be_bytes(genmem[i..i + 8].try_into().unwrap())
            % (genmem.len() as u64 / 8)) as usize
            * 8;
        i += 8;
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(&genmem[idx2..idx2 + 8]);
        genmem[idx2..idx2 + 8].copy_from_slice(&digest[idx1..idx1 + 8]);
        digest[idx1..idx1 + 8].copy_from_slice(&tmp);
        salsa20_block(&key, &nonce, stream_counter, &mut digest);
        stream_counter += 1;
    }
    digest
}

/// A signed planet or moon root-server topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct World {
    pub world_type: u8,
    pub id: u64,
    pub timestamp: u64,
    pub updates_must_be_signed_by: [u8; PUBLIC_KEY_SIZE],
    pub signature: [u8; SIGNATURE_SIZE],
    pub roots: Vec<WorldRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldRoot {
    pub identity: Identity,
    pub endpoints: Vec<SocketAddr>,
}

impl World {
    /// Parse a complete planet (type 1) and reject trailing bytes.
    pub fn parse_planet(data: &[u8]) -> Result<Self, ZerotierError> {
        let (world, consumed) = World::parse(data)?;
        if consumed != data.len() || world.world_type != 1 {
            return Err(ZerotierError::InvalidWorld("not a complete planet"));
        }
        if world.roots.is_empty() {
            return Err(ZerotierError::InvalidWorld("planet has no roots"));
        }
        Ok(world)
    }

    pub fn parse(data: &[u8]) -> Result<(Self, usize), ZerotierError> {
        let fixed = 1 + 8 + 8 + PUBLIC_KEY_SIZE + SIGNATURE_SIZE + 1;
        if data.len() < fixed {
            return Err(ZerotierError::InvalidWorld("truncated world"));
        }
        let world_type = data[0];
        if world_type != 0 && world_type != 1 && world_type != 127 {
            return Err(ZerotierError::InvalidWorld("unknown world type"));
        }
        let id = read_be_u64(data, 1).unwrap();
        let timestamp = read_be_u64(data, 9).unwrap();
        let mut updates = [0u8; PUBLIC_KEY_SIZE];
        updates.copy_from_slice(&data[17..17 + PUBLIC_KEY_SIZE]);
        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&data[17 + PUBLIC_KEY_SIZE..17 + PUBLIC_KEY_SIZE + SIGNATURE_SIZE]);
        let mut pos = 17 + PUBLIC_KEY_SIZE + SIGNATURE_SIZE;
        let root_count = data[pos] as usize;
        pos += 1;
        if root_count > 4 {
            return Err(ZerotierError::InvalidWorld("too many roots"));
        }
        let mut roots = Vec::with_capacity(root_count);
        for _ in 0..root_count {
            let (identity, consumed) = Identity::parse_binary(&data[pos..])?;
            pos += consumed;
            if pos >= data.len() {
                return Err(ZerotierError::InvalidWorld("truncated root endpoints"));
            }
            let endpoint_count = data[pos] as usize;
            pos += 1;
            if endpoint_count > 32 {
                return Err(ZerotierError::InvalidWorld("too many root endpoints"));
            }
            let mut endpoints = Vec::with_capacity(endpoint_count);
            for _ in 0..endpoint_count {
                let (endpoint, consumed) = parse_inet_address(&data[pos..])
                    .ok_or(ZerotierError::InvalidWorld("bad root endpoint"))?;
                pos += consumed;
                endpoints.push(endpoint);
            }
            roots.push(WorldRoot { identity, endpoints });
        }
        if world_type == 127 {
            if data.len() < pos + 2 {
                return Err(ZerotierError::InvalidWorld("truncated moon dictionary"));
            }
            let dictionary_len = read_be_u16(data, pos).unwrap() as usize;
            pos += 2;
            if data.len() < pos + dictionary_len {
                return Err(ZerotierError::InvalidWorld("truncated moon dictionary"));
            }
            pos += dictionary_len;
        }
        Ok((
            World {
                world_type,
                id,
                timestamp,
                updates_must_be_signed_by: updates,
                signature,
                roots,
            },
            pos,
        ))
    }
}

fn parse_inet_address(data: &[u8]) -> Option<(SocketAddr, usize)> {
    match *data.first()? {
        0 => None,
        4 => {
            if data.len() < 7 {
                return None;
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Some((SocketAddr::new(IpAddr::V4(ip), port), 7))
        }
        6 => {
            if data.len() < 19 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Some((SocketAddr::new(IpAddr::V6(ip), port), 19))
        }
        _ => None,
    }
}

fn append_inet_address(out: &mut Vec<u8>, address: Option<SocketAddr>) {
    match address {
        None => out.push(0),
        Some(SocketAddr::V4(addr)) => {
            out.push(4);
            out.extend_from_slice(&addr.ip().octets());
            push_be_u16(out, addr.port());
        }
        Some(SocketAddr::V6(addr)) => {
            out.push(6);
            out.extend_from_slice(&addr.ip().octets());
            push_be_u16(out, addr.port());
        }
    }
}

/// One VL1 packet (header, authenticator and verb payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    data: Vec<u8>,
}

impl Packet {
    pub fn new(destination: u64, source: u64, verb: Verb) -> Self {
        let mut data = vec![0u8; PACKET_MIN_SIZE];
        rand::thread_rng().fill_bytes(&mut data[PACKET_IV_OFFSET..PACKET_DEST_OFFSET]);
        data[PACKET_DEST_OFFSET..PACKET_SOURCE_OFFSET]
            .copy_from_slice(&destination.to_be_bytes()[3..]);
        data[PACKET_SOURCE_OFFSET..PACKET_FLAGS_OFFSET]
            .copy_from_slice(&source.to_be_bytes()[3..]);
        data[PACKET_VERB_OFFSET] = verb as u8;
        Packet { data }
    }

    pub fn parse(data: &[u8]) -> Result<Self, ZerotierError> {
        if data.len() < PACKET_MIN_SIZE || data.len() > 7 * 1432 {
            return Err(ZerotierError::InvalidPacket("size"));
        }
        Ok(Packet {
            data: data.to_vec(),
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
    pub fn destination(&self) -> u64 {
        address_from_bytes(&self.data[PACKET_DEST_OFFSET..PACKET_SOURCE_OFFSET]).unwrap_or(0)
    }
    pub fn source(&self) -> u64 {
        address_from_bytes(&self.data[PACKET_SOURCE_OFFSET..PACKET_FLAGS_OFFSET]).unwrap_or(0)
    }
    pub fn packet_id(&self) -> u64 {
        read_be_u64(&self.data, PACKET_IV_OFFSET).unwrap_or(0)
    }
    pub fn verb(&self) -> Option<Verb> {
        Verb::from_u8(self.data[PACKET_VERB_OFFSET] & 0x1f)
    }
    pub fn cipher(&self) -> Cipher {
        Cipher::from_bits((self.data[PACKET_FLAGS_OFFSET] & 0x38) >> 3)
    }
    pub fn payload(&self) -> &[u8] {
        &self.data[PACKET_PAYLOAD_OFFSET..]
    }
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data[PACKET_PAYLOAD_OFFSET..]
    }
    pub fn append(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }
    pub fn append_u16(&mut self, value: u16) {
        push_be_u16(&mut self.data, value);
    }
    pub fn append_u64(&mut self, value: u64) {
        push_be_u64(&mut self.data, value);
    }
    pub fn set_extended_armor(&mut self) {
        self.data[PACKET_FLAGS_OFFSET] |= FLAG_EXTENDED_ARMOR;
    }
    pub fn extended_armor(&self) -> bool {
        self.data[PACKET_FLAGS_OFFSET] & FLAG_EXTENDED_ARMOR != 0
    }

    fn mangle_key(&self, key: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&key[..32]);
        for i in 0..18 {
            out[i] ^= self.data[i];
        }
        out[18] ^= self.data[PACKET_FLAGS_OFFSET] & 0xf8;
        out[19] ^= self.data.len() as u8;
        out[20] ^= (self.data.len() >> 8) as u8;
        out
    }

    fn armor_stream(&self, key: &[u8]) -> Vec<u8> {
        let mangled = self.mangle_key(key);
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&self.data[PACKET_IV_OFFSET..PACKET_DEST_OFFSET]);
        let mut stream = vec![0u8; 64 + self.data.len() - PACKET_VERB_OFFSET];
        let mut cipher = Salsa12::new((&mangled).into(), (&nonce).into());
        cipher.apply_keystream(&mut stream);
        stream
    }

    /// Apply ZeroTier's legacy Salsa20/12 + Poly1305 armor.
    pub fn armor(&mut self, key: &[u8], encrypt: bool) -> Result<(), ZerotierError> {
        if key.len() < 32 {
            return Err(ZerotierError::InvalidPacket("armor key"));
        }
        let cipher_bits = if encrypt { 1 } else { 0 };
        self.data[PACKET_FLAGS_OFFSET] =
            (self.data[PACKET_FLAGS_OFFSET] & !0x38) | (cipher_bits << 3);
        let stream = self.armor_stream(key);
        if encrypt {
            for (i, byte) in self.data[PACKET_VERB_OFFSET..].iter_mut().enumerate() {
                *byte ^= stream[64 + i];
            }
        }
        let mut mac_key = [0u8; 32];
        mac_key.copy_from_slice(&stream[..32]);
        let tag = poly1305_tag(&mac_key, &self.data[PACKET_VERB_OFFSET..]);
        self.data[PACKET_MAC_OFFSET..PACKET_VERB_OFFSET].copy_from_slice(&tag[..8]);
        Ok(())
    }

    /// Verify (and decrypt when required) the legacy armor.
    pub fn dearmor(&mut self, key: &[u8]) -> Result<(), ZerotierError> {
        if key.len() < 32 {
            return Err(ZerotierError::InvalidPacket("armor key"));
        }
        let cipher = self.cipher();
        if cipher == Cipher::TrustedPath || cipher == Cipher::AesGmacSiv {
            return Err(ZerotierError::InvalidPacket("unsupported armor suite"));
        }
        let stream = self.armor_stream(key);
        let mut mac_key = [0u8; 32];
        mac_key.copy_from_slice(&stream[..32]);
        let expected = poly1305_tag(&mac_key, &self.data[PACKET_VERB_OFFSET..]);
        if self.data[PACKET_MAC_OFFSET..PACKET_VERB_OFFSET] != expected[..8] {
            return Err(ZerotierError::Authentication);
        }
        if cipher == Cipher::Poly1305Salsa2012 {
            for (i, byte) in self.data[PACKET_VERB_OFFSET..].iter_mut().enumerate() {
                *byte ^= stream[64 + i];
            }
        }
        Ok(())
    }

    /// Apply protocol-13 extended armor to a cleartext HELLO.
    pub fn armor_extended(&mut self, key: &[u8], peer: &Identity) -> Result<(), ZerotierError> {
        self.set_extended_armor();
        self.armor(key, false)?;
        let mut ephemeral_private = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ephemeral_private);
        let secret = StaticSecret::from(ephemeral_private);
        let ephemeral_public = PublicKey::from(&secret);
        let peer_public = PublicKey::from(<[u8; 32]>::try_from(&peer.public[..32]).unwrap());
        let shared = secret.diffie_hellman(&peer_public);
        let digest = Sha512::digest(shared.as_bytes());
        let aes_key: [u8; 32] = digest[..32].try_into().unwrap();
        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(&self.data[..12]);
        let mut cipher = Ctr128BE::<Aes256>::new((&aes_key).into(), (&iv).into());
        cipher.apply_keystream(&mut self.data[PACKET_MAC_OFFSET..]);
        self.data.extend_from_slice(ephemeral_public.as_bytes());
        Ok(())
    }

    /// Verify protocol-13 extended armor and remove the ephemeral key.
    pub fn dearmor_extended(&mut self, key: &[u8], identity: &Identity) -> Result<(), ZerotierError> {
        if !self.extended_armor() || self.cipher() != Cipher::Poly1305None {
            return Err(ZerotierError::InvalidPacket("not extended armor"));
        }
        if self.data.len() < PACKET_MIN_SIZE + EXTENDED_ARMOR_KEY_SIZE {
            return Err(ZerotierError::InvalidPacket("extended armor length"));
        }
        let at = self.data.len() - EXTENDED_ARMOR_KEY_SIZE;
        let ephemeral_public: [u8; 32] = self.data[at..].try_into().unwrap();
        let private = identity.private.ok_or(ZerotierError::PrivateKeyMissing)?;
        let secret = StaticSecret::from(<[u8; 32]>::try_from(&private[..32]).unwrap());
        let shared = secret.diffie_hellman(&PublicKey::from(ephemeral_public));
        let digest = Sha512::digest(shared.as_bytes());
        let aes_key: [u8; 32] = digest[..32].try_into().unwrap();
        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(&self.data[..12]);
        let mut cipher = Ctr128BE::<Aes256>::new((&aes_key).into(), (&iv).into());
        cipher.apply_keystream(&mut self.data[PACKET_MAC_OFFSET..at]);
        self.data.truncate(at);
        self.dearmor(key)
    }

    /// Apply the secondary HELLO field protection stream.
    pub fn crypt_field(&mut self, key: &[u8], start: usize, length: usize) -> Result<(), ZerotierError> {
        if key.len() < 32 || start + length > self.data.len() {
            return Err(ZerotierError::InvalidPacket("crypt field"));
        }
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&self.data[PACKET_IV_OFFSET..PACKET_DEST_OFFSET]);
        nonce[7] &= 0xf8;
        let mut cipher = Salsa12::new((&key[..32]).try_into().unwrap(), (&nonce).into());
        cipher.apply_keystream(&mut self.data[start..start + length]);
        Ok(())
    }
}

fn poly1305_tag(key: &[u8; 32], data: &[u8]) -> Tag {
    let mac = Poly1305::new(key.into());
    mac.compute_unpadded(data)
}

/// A VL2 Ethernet frame carried by `VerbFrame`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vl2Frame {
    pub network_id: u64,
    pub ether_type: u16,
    pub payload: Vec<u8>,
}

impl Vl2Frame {
    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.payload.len());
        push_be_u64(&mut out, self.network_id);
        push_be_u16(&mut out, self.ether_type);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn parse(payload: &[u8]) -> Result<Self, ZerotierError> {
        if payload.len() < 10 {
            return Err(ZerotierError::InvalidPacket("VL2 frame payload"));
        }
        Ok(Vl2Frame {
            network_id: read_be_u64(payload, 0).unwrap(),
            ether_type: read_be_u16(payload, 8).unwrap(),
            payload: payload[10..].to_vec(),
        })
    }
}

/// Information learned from a peer's HELLO/OK exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHello {
    pub address: u64,
    pub identity: Identity,
    pub protocol_version: u8,
    pub major: u8,
    pub minor: u8,
    pub revision: u16,
    pub external_address: Option<SocketAddr>,
    pub planet_id: u64,
    pub planet_timestamp: u64,
    pub worlds: Vec<u8>,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Build a HELLO packet and return it with the peer's shared key.
pub fn build_hello(
    local: &Identity,
    peer: &Identity,
    local_address: Option<SocketAddr>,
    planet: (u64, u64),
    encrypted_hello: bool,
) -> Result<(Packet, [u8; SYMMETRIC_KEY_SIZE]), ZerotierError> {
    let key = local.agree(peer)?;
    let mut packet = Packet::new(peer.address, local.address, Verb::Hello);
    packet.append(&[PROTOCOL_VERSION, 0, 0]);
    packet.append_u16(0);
    packet.append_u64(now_millis());
    local.append_binary(&mut packet.data, false);
    append_inet_address(&mut packet.data, local_address);
    packet.append_u64(planet.0);
    packet.append_u64(planet.1);
    let crypted_at = packet.data.len();
    packet.append_u16(0);
    packet.crypt_field(&key, crypted_at, packet.data.len() - crypted_at)?;
    if encrypted_hello {
        packet.armor_extended(&key, peer)?;
    } else {
        // A HELLO is authenticated but not encrypted (`Armor(key, false)`).
        packet.armor(&key, false)?;
    }
    Ok((packet, key))
}

/// Parse a HELLO or OK body into a [`PeerHello`].
pub fn parse_peer_hello(packet: &Packet) -> Result<PeerHello, ZerotierError> {
    let payload = packet.payload();
    let identity_offset = 1 + 1 + 1 + 2 + 8;
    if payload.len() < identity_offset + ADDRESS_SIZE + 1 + PUBLIC_KEY_SIZE + 1 {
        return Err(ZerotierError::InvalidPacket("short HELLO"));
    }
    let (identity, identity_len) = Identity::parse_binary(&payload[identity_offset..])?;
    if identity.address() != packet.source() {
        return Err(ZerotierError::Authentication);
    }
    let mut pos = identity_offset + identity_len;
    let mut external_address = None;
    if pos < payload.len() {
        if let Some((address, consumed)) = parse_inet_address(&payload[pos..]) {
            external_address = Some(address);
            pos += consumed;
        } else if payload[pos] == 0 {
            pos += 1;
        }
    }
    let mut planet_id = 0;
    let mut planet_timestamp = 0;
    if payload.len() - pos >= 16 {
        planet_id = read_be_u64(payload, pos).unwrap();
        planet_timestamp = read_be_u64(payload, pos + 8).unwrap();
        pos += 16;
    }
    Ok(PeerHello {
        address: identity.address(),
        identity,
        protocol_version: payload[0],
        major: payload[1],
        minor: payload[2],
        revision: read_be_u16(payload, 3).unwrap(),
        external_address,
        planet_id,
        planet_timestamp,
        worlds: payload[pos..].to_vec(),
    })
}

/// Parse an OK reply for a HELLO request. The OK body does not repeat the
/// peer identity, so the caller supplies the identity it addressed.
pub fn parse_ok(packet: &Packet, peer: &Identity) -> Result<PeerHello, ZerotierError> {
    let payload = packet.payload();
    // in_reply_to verb (1) + request packet id (8) + timestamp (8) +
    // protocol/major/minor/rev (5) + external endpoint + worlds length.
    if payload.len() < 22 {
        return Err(ZerotierError::InvalidPacket("short OK"));
    }
    let mut pos = 22;
    let mut external_address = None;
    if pos < payload.len() {
        if let Some((address, consumed)) = parse_inet_address(&payload[pos..]) {
            external_address = Some(address);
            pos += consumed;
        } else if payload[pos] == 0 {
            pos += 1;
        }
    }
    let worlds = if payload.len() >= pos + 2 {
        let length = read_be_u16(payload, pos).unwrap() as usize;
        pos += 2;
        if payload.len() < pos + length {
            return Err(ZerotierError::InvalidPacket("short OK worlds"));
        }
        payload[pos..pos + length].to_vec()
    } else {
        Vec::new()
    };
    Ok(PeerHello {
        address: peer.address(),
        identity: peer.clone(),
        protocol_version: payload[17],
        major: payload[18],
        minor: payload[19],
        revision: read_be_u16(payload, 20).unwrap(),
        external_address,
        planet_id: 0,
        planet_timestamp: 0,
        worlds,
    })
}

/// Build an OK reply for a HELLO request (used by controlled tests and by the
/// device layer when it answers a peer).
pub fn build_ok(
    local: &Identity,
    request: &Packet,
    key: &[u8],
    external_address: Option<SocketAddr>,
    worlds: &[u8],
) -> Result<Packet, ZerotierError> {
    if request.verb() != Some(Verb::Hello) {
        return Err(ZerotierError::InvalidPacket("OK request is not HELLO"));
    }
    let hello = parse_peer_hello(request)?;
    let mut packet = Packet::new(hello.address, local.address(), Verb::Ok);
    packet.append(&[Verb::Hello as u8]);
    packet.append_u64(request.packet_id());
    packet.append_u64(now_millis());
    packet.append(&[PROTOCOL_VERSION, 0, 0]);
    packet.append_u16(0);
    append_inet_address(&mut packet.data, external_address);
    packet.append_u16(worlds.len() as u16);
    packet.append(worlds);
    packet.armor(key, true)?;
    Ok(packet)
}

/// Complete a HELLO handshake over a UDP socket.
pub async fn handshake(
    socket: &UdpSocket,
    local: &Identity,
    peer: &Identity,
    peer_address: SocketAddr,
    planet: (u64, u64),
    encrypted_hello: bool,
    timeout: Duration,
) -> Result<PeerHello, ZerotierError> {
    let (packet, key) = build_hello(local, peer, socket.local_addr().ok(), planet, encrypted_hello)?;
    let request_id = packet.packet_id();
    socket.send_to(packet.bytes(), peer_address).await?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buffer = vec![0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(ZerotierError::Timeout);
        }
        let (size, from) = match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await {
            Ok(result) => result?,
            Err(_) => return Err(ZerotierError::Timeout),
        };
        if from != peer_address {
            continue;
        }
        let Ok(mut response) = Packet::parse(&buffer[..size]) else {
            continue;
        };
        if response.destination() != local.address() || response.source() != peer.address() {
            continue;
        }
        if encrypted_hello && response.extended_armor() {
            response.dearmor_extended(&key, local)?;
        } else {
            response.dearmor(&key)?;
        }
        if response.verb() != Some(Verb::Ok) {
            continue;
        }
        let hello = parse_ok(&response, peer)?;
        let payload = response.payload();
        if payload.len() < 9 || payload[0] != Verb::Hello as u8 {
            continue;
        }
        if read_be_u64(payload, 1) != Some(request_id) {
            continue;
        }
        return Ok(hello);
    }
}

/// Parse and validate a 64-bit ZeroTier network ID.
pub fn parse_network_id(text: &str) -> Result<u64, ZerotierError> {
    if text.len() != 16 {
        return Err(ZerotierError::InvalidNetwork);
    }
    let bytes = hex::decode(text).map_err(|_| ZerotierError::InvalidNetwork)?;
    let mut value = 0u64;
    for byte in bytes {
        value = (value << 8) | byte as u64;
    }
    if value == 0 {
        return Err(ZerotierError::InvalidNetwork);
    }
    if value >> 56 != 0xff && is_reserved_address(value >> 24) {
        return Err(ZerotierError::InvalidNetwork);
    }
    Ok(value)
}

/// Whether a datagram is a cleartext HELLO (the only packet a new node can
/// send before it knows the peer's key).
pub fn is_unencrypted_hello(packet: &Packet) -> bool {
    packet.verb() == Some(Verb::Hello)
        && packet.cipher() == Cipher::Poly1305None
        && !packet.extended_armor()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_A: &str = "64bb654c16:0:1621a4a2d540cdf6d3b63947a29b9aaed1c86842b12da93e468fa723944c3c4357e8ac7436ccb931a0c230df4da2a8575237262a9564d543cd725b4f48de76c2:cfedde328eca0973d0ddaf3f47f78fc43f9c332b2019cecbecc7e483652d03eda60ec8322f1589580807a3ca79163bd673892eb433b54945c697dfef79e2adc7";
    const SECRET_B: &str = "a32dce5ea1:0:159562c11bd37e4c9317a63252a686b68387d842988011e2af9ac12ffe1bb02c84ab4e6cb7568a4f1b9a4502582014b133bc8d0db6a02b11311d3e571dd87e15:0d8239f206afb6a37b9b3482d10c74221d23c42c9db8985a3f6858c483b149d4230af59cb7d61298c820aa7e72999c97285454b063783b7d32b9afc2cb0d425c";

    fn identity_a() -> Identity {
        Identity::parse(SECRET_A).expect("fixed identity A")
    }

    fn identity_b() -> Identity {
        Identity::parse(SECRET_B).expect("fixed identity B")
    }

    #[test]
    fn identity_text_roundtrip_and_signature() {
        let identity = identity_a();
        identity.validate().expect("fixed identity validates");
        assert!(identity.has_private());
        let secret = identity.secret_string().expect("secret form");
        let parsed = Identity::parse(&secret).expect("secret parses");
        assert_eq!(parsed.address(), identity.address());
        assert_eq!(parsed.public_key(), identity.public_key());
        let public = identity.public_string();
        let parsed_public = Identity::parse(&public).expect("public parses");
        assert!(!parsed_public.has_private());
        assert!(parsed_public.verify(b"zero tier", &identity.sign(b"zero tier").unwrap()));
        assert!(!parsed_public.verify(b"other", &identity.sign(b"zero tier").unwrap()));
    }

    #[test]
    #[ignore]
    fn identity_generation_satisfies_pow() {
        // The full proof-of-work loop is a slow, non-hermetic default test;
        // the controlled peer test exercises a generated identity instead.
        let identity = Identity::generate();
        identity.validate().expect("generated identity validates");
    }

    #[test]
    fn identity_proof_of_work_is_enforced() {
        let identity = identity_a();
        let mut public = *identity.public_key();
        public[0] ^= 1;
        let broken = Identity {
            address: identity.address(),
            public,
            private: None,
        };
        assert!(matches!(
            broken.validate(),
            Err(ZerotierError::InvalidIdentity(_))
        ));
        assert!(Identity::parse("0000000000:0:00").is_err());
    }

    #[test]
    fn packet_armor_roundtrips_and_rejects_tampering() {
        let local = identity_a();
        let peer = identity_b();
        let key = local.agree(&peer).unwrap();
        let mut packet = Packet::new(peer.address(), local.address(), Verb::Echo);
        packet.append(b"hello");
        packet.armor(&key, true).unwrap();
        let wire = packet.bytes().to_vec();
        let mut parsed = Packet::parse(&wire).unwrap();
        parsed.dearmor(&key).unwrap();
        assert_eq!(parsed.verb(), Some(Verb::Echo));
        assert_eq!(parsed.payload(), b"hello");
        let mut tampered = wire;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let mut parsed = Packet::parse(&tampered).unwrap();
        assert!(matches!(
            parsed.dearmor(&key),
            Err(ZerotierError::Authentication)
        ));
    }

    #[test]
    fn hello_has_the_pinned_payload_shape() {
        let local = identity_a();
        let peer = identity_b();
        let (packet, key) = build_hello(
            &local,
            &peer,
            Some("10.0.0.1:9993".parse().unwrap()),
            (1, 2),
            false,
        )
        .unwrap();
        let mut parsed = Packet::parse(packet.bytes()).unwrap();
        parsed.dearmor(&key).unwrap();
        let hello = parse_peer_hello(&parsed).unwrap();
        assert_eq!(hello.address, local.address());
        assert_eq!(hello.protocol_version, PROTOCOL_VERSION);
        assert_eq!(hello.planet_id, 1);
        assert_eq!(hello.planet_timestamp, 2);
        assert_eq!(
            hello.external_address,
            Some("10.0.0.1:9993".parse().unwrap())
        );
        let mut ok = build_ok(&peer, &parsed, &key, None, &[]).unwrap();
        ok.dearmor(&key).unwrap();
        let reply = parse_ok(&ok, &peer).unwrap();
        assert_eq!(reply.address, peer.address());
        assert_eq!(reply.protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn network_ids_and_vl2_frames() {
        assert!(parse_network_id("8056c2e21c000001").is_ok());
        assert!(parse_network_id("zzzzzzzzzzzzzzzz").is_err());
        assert!(parse_network_id("0000000000000000").is_err());
        let frame = Vl2Frame {
            network_id: 0x8056c2e21c000001,
            ether_type: 0x0800,
            payload: vec![0x45, 0, 0, 20],
        };
        assert_eq!(Vl2Frame::parse(&frame.payload()).unwrap(), frame);
        assert!(Vl2Frame::parse(&[0u8; 9]).is_err());
    }

    #[test]
    fn world_parser_reads_roots_and_rejects_truncation() {
        let root = identity_a();
        let mut data = vec![1u8];
        data.extend_from_slice(&149604618u64.to_be_bytes());
        data.extend_from_slice(&7u64.to_be_bytes());
        data.extend_from_slice(&root.public[..]);
        data.extend_from_slice(&[0u8; SIGNATURE_SIZE]);
        data.push(1);
        root.append_binary(&mut data, false);
        data.push(1);
        data.extend_from_slice(&[4, 127, 0, 0, 1, 0x26, 0xe7]);
        let world = World::parse_planet(&data).unwrap();
        assert_eq!(world.id, 149604618);
        assert_eq!(world.roots.len(), 1);
        assert_eq!(world.roots[0].endpoints[0], "127.0.0.1:9959".parse().unwrap());
        assert!(World::parse_planet(&data[..data.len() - 1]).is_err());
    }
}
