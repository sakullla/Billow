// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Derived from the locked EasyTier source (github.com/EasyTier/EasyTier,
// LGPL-3.0-or-later), specifically:
//   easytier-core/src/config/mod.rs            (network_secret_digest)
//   easytier-core/src/packet/mod.rs            (PeerManagerHeader, TCPTunnelHeader,
//                                               PacketType, DefaultEndian = little)
//   easytier-core/src/peers/conn/peer_conn.rs  (HandshakeRequest, cleartext path,
//                                               Noise XX msg1/2/3, secret proof)
//   easytier-core/src/peers/conn/peer_conn_ping.rs (Ping/Pong payload)
//   easytier-core/src/peers/conn/peer_session.rs + tunnel/secure_datagram.rs
//                                               (root/traffic keys, epoch/seq)
//   easytier-core/src/tunnel/encrypt/{aes_gcm,chacha20}.rs (AEAD tail)
// The Go module cache pins `github.com/easytier/easytier/easytier-go`
// v0.0.0-20261111015056-2abb1676b475 whose embedded core reports commit
// 5f1eaa7c9f9d3e89e9b75a6d87531a436fae40c4. That revision is not in the
// public history; the translation used the public EasyTier main revision
// 45a6b6f1769f95590a396f4962e58d654b6e0380 (fetched 2026-11-22) and was
// verified against the pinned wasm core.
//
// This file is a Rust translation distributed under LGPL-3.0-or-later. The
// workspace is distributed under GPL-3.0-only (the sudoku translation), so a
// binary containing this module must satisfy both sets of obligations. See
// native-kernel/THIRD_PARTY_NOTICES.md and
// native-kernel/third_party/EasyTier-LGPL-3.0.txt.
//
// Scope: network_secret_digest, the peer-manager/TCP frame, cleartext
// HandshakeRequest/PingPong, the Noise XX handshake and the
// secure-datagram/AES-GCM/ChaCha20 data path. The userspace IP stack/TUN and
// OSPF/route exchange remain T6/T7.

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::net::SocketAddr;
use std::time::Duration;

use aes_gcm::aead::{Aead, AeadInPlace, KeyInit as _, Payload as AeadPayload};
use aes_gcm::{Aes128Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChachaKey, Nonce as ChachaNonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

fn decode_base64_32(value: &str) -> Option<[u8; 32]> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    fn sextet(byte: u8) -> Option<u8> {
        TABLE.iter().position(|b| *b == byte).map(|i| i as u8)
    }
    let trimmed = value.trim();
    if trimmed.len() != 44 || !trimmed.ends_with('=') {
        return None;
    }
    let mut out = Vec::with_capacity(32);
    for chunk in trimmed.as_bytes().chunks(4) {
        let mut values = [0u8; 4];
        for (i, byte) in chunk.iter().enumerate() {
            values[i] = if *byte == b'=' { 0 } else { sextet(*byte)? };
        }
        let triple = ((values[0] as u32) << 18)
            | ((values[1] as u32) << 12)
            | ((values[2] as u32) << 6)
            | values[3] as u32;
        out.push((triple >> 16) as u8);
        if chunk[2] != b'=' {
            out.push((triple >> 8) as u8);
        }
        if chunk[3] != b'=' {
            out.push(triple as u8);
        }
    }
    out.try_into().ok()
}

pub fn parse_private_key(value: &str) -> Result<[u8; 32], EasytierError> {
    decode_base64_32(value).ok_or(EasytierError::InvalidKey)
}

pub fn parse_public_key(value: &str) -> Result<[u8; 32], EasytierError> {
    decode_base64_32(value).ok_or(EasytierError::InvalidKey)
}

pub fn derive_public_key(private: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

pub fn generate_private_key() -> [u8; 32] {
    StaticSecret::random_from_rng(rand::rngs::OsRng).to_bytes()
}

/// EasyTier network secret digest (`NetworkSecretDigest`), 32 bytes.
pub type NetworkSecretDigest = [u8; 32];

pub const MAGIC_COOKIE: u32 = 0xd1e1a5e1;
pub const PROTOCOL_VERSION: u32 = 1;
pub const PEER_MANAGER_HEADER_SIZE: usize = 16;
pub const TCP_TUNNEL_HEADER_SIZE: usize = 4;

/// EasyTier's digest: two `DefaultHasher` writes, then four big-endian
/// shards where each shard is fed back into the same hasher. Reproduced
/// exactly from `config/mod.rs::generate_digest_from_str`; this is why the
/// earlier SHA-256 placeholder did not interop with the pinned core.
pub fn network_secret_digest(network_name: &str, network_secret: &str) -> NetworkSecretDigest {
    let mut hasher = DefaultHasher::new();
    hasher.write(network_name.as_bytes());
    hasher.write(network_secret.as_bytes());
    let mut digest = [0u8; 32];
    for i in 0..4 {
        digest[i * 8..(i + 1) * 8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&digest[..(i + 1) * 8]);
    }
    digest
}

/// `PeerManagerHeader` packet types (`packet/mod.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Data = 1,
    HandShake = 2,
    RoutePacket = 3,
    Ping = 4,
    Pong = 5,
    TaRpc = 6,
    Route = 7,
    RpcReq = 8,
    RpcResp = 9,
    ForeignNetworkPacket = 10,
    KcpSrc = 11,
    KcpDst = 12,
    NoiseHandshakeMsg1 = 13,
    NoiseHandshakeMsg2 = 14,
    NoiseHandshakeMsg3 = 15,
    QuicSrc = 16,
    QuicDst = 17,
    DataWithKcpSrcModified = 18,
    DataWithQuicSrcModified = 19,
    RelayHandshake = 20,
    RelayHandshakeAck = 21,
}

impl PacketType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => PacketType::Data,
            2 => PacketType::HandShake,
            3 => PacketType::RoutePacket,
            4 => PacketType::Ping,
            5 => PacketType::Pong,
            6 => PacketType::TaRpc,
            7 => PacketType::Route,
            8 => PacketType::RpcReq,
            9 => PacketType::RpcResp,
            10 => PacketType::ForeignNetworkPacket,
            11 => PacketType::KcpSrc,
            12 => PacketType::KcpDst,
            13 => PacketType::NoiseHandshakeMsg1,
            14 => PacketType::NoiseHandshakeMsg2,
            15 => PacketType::NoiseHandshakeMsg3,
            16 => PacketType::QuicSrc,
            17 => PacketType::QuicDst,
            18 => PacketType::DataWithKcpSrcModified,
            19 => PacketType::DataWithQuicSrcModified,
            20 => PacketType::RelayHandshake,
            21 => PacketType::RelayHandshakeAck,
            _ => return None,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EasytierError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out waiting for the EasyTier peer")]
    Timeout,
    #[error("invalid EasyTier frame: {0}")]
    Frame(&'static str),
    #[error("unexpected EasyTier packet type {0}")]
    PacketType(u8),
    #[error("EasyTier handshake magic mismatch")]
    Magic,
    #[error("EasyTier network name mismatch")]
    NetworkName,
    #[error("EasyTier network secret digest mismatch")]
    SecretDigest,
    #[error("EasyTier peer id conflict")]
    PeerId,
    #[error("EasyTier protobuf decode error")]
    Protobuf,
    #[error("EasyTier secure-datagram/Noise operation failed")]
    SecureDatagramUnsupported,
    #[error("EasyTier Noise handshake failed: {0}")]
    Noise(&'static str),
    #[error("invalid EasyTier key material")]
    InvalidKey,
}

/// One `TCPTunnelHeader` + `PeerManagerHeader` + payload record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub from_peer_id: u32,
    pub to_peer_id: u32,
    pub packet_type: u8,
    pub flags: u8,
    pub forward_counter: u8,
    pub payload: Vec<u8>,
    /// The peer-manager header `len` field. Encryption keeps the plaintext
    /// length here while the payload grows by the AEAD tail.
    pub declared_len: Option<u32>,
}

impl Frame {
    /// Serialize exactly as the locked `ZCPacket`/`TcpTunnel` path does:
    /// 4-byte little-endian total record length, then a packed little-endian
    /// PeerManagerHeader (from, to, type, flags, forward_counter, reserved,
    /// payload length), then the payload.
    pub fn encode(&self) -> Vec<u8> {
        let record_len = PEER_MANAGER_HEADER_SIZE + self.payload.len();
        let mut out = Vec::with_capacity(TCP_TUNNEL_HEADER_SIZE + record_len);
        out.extend_from_slice(&(record_len as u32).to_le_bytes());
        out.extend_from_slice(&self.from_peer_id.to_le_bytes());
        out.extend_from_slice(&self.to_peer_id.to_le_bytes());
        out.push(self.packet_type);
        out.push(self.flags);
        out.push(self.forward_counter);
        out.push(0);
        let declared = self.declared_len.unwrap_or(self.payload.len() as u32);
        out.extend_from_slice(&declared.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, EasytierError> {
        if data.len() < TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE {
            return Err(EasytierError::Frame("short header"));
        }
        let record_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        if record_len < PEER_MANAGER_HEADER_SIZE
            || TCP_TUNNEL_HEADER_SIZE + record_len > data.len()
        {
            return Err(EasytierError::Frame("bad total length"));
        }
        let hdr = &data[4..4 + PEER_MANAGER_HEADER_SIZE];
        let from_peer_id = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let to_peer_id = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        let packet_type = hdr[8];
        let flags = hdr[9];
        let forward_counter = hdr[10];
        let payload_len = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as usize;
        if PEER_MANAGER_HEADER_SIZE + payload_len > record_len {
            return Err(EasytierError::Frame("bad payload length"));
        }
        let start = 4 + PEER_MANAGER_HEADER_SIZE;
        Ok(Frame {
            from_peer_id,
            to_peer_id,
            packet_type,
            flags,
            forward_counter,
            payload: data[start..start + payload_len].to_vec(),
            declared_len: Some(payload_len as u32),
        })
    }
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_varint(data: &[u8], at: &mut usize) -> Result<u64, EasytierError> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = *data.get(*at).ok_or(EasytierError::Protobuf)?;
        *at += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err(EasytierError::Protobuf);
        }
    }
}

fn put_field_varint(out: &mut Vec<u8>, field: u32, value: u64) {
    put_varint(out, ((field as u64) << 3) | 0);
    put_varint(out, value);
}

fn put_field_bytes(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    put_varint(out, ((field as u64) << 3) | 2);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn skip_field(data: &[u8], at: &mut usize, wire: u8) -> Result<(), EasytierError> {
    match wire {
        0 => {
            read_varint(data, at)?;
        }
        1 => *at += 8,
        2 => {
            let len = read_varint(data, at)? as usize;
            *at += len;
        }
        5 => *at += 4,
        _ => return Err(EasytierError::Protobuf),
    }
    if *at > data.len() {
        return Err(EasytierError::Protobuf);
    }
    Ok(())
}

/// `peer_rpc.HandshakeRequest` as used by the cleartext path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeRequest {
    pub magic: u32,
    pub my_peer_id: u32,
    pub version: u32,
    pub features: Vec<String>,
    pub network_name: String,
    pub network_secret_digest: Vec<u8>,
}

impl HandshakeRequest {
    pub fn new(network_name: &str, network_secret: &str, my_peer_id: u32) -> Self {
        HandshakeRequest {
            magic: MAGIC_COOKIE,
            my_peer_id,
            version: PROTOCOL_VERSION,
            features: vec!["liveness-echo-v1".to_string()],
            network_name: network_name.to_string(),
            network_secret_digest: network_secret_digest(network_name, network_secret).to_vec(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_field_varint(&mut out, 1, self.magic as u64);
        put_field_varint(&mut out, 2, self.my_peer_id as u64);
        put_field_varint(&mut out, 3, self.version as u64);
        for feature in &self.features {
            put_field_bytes(&mut out, 4, feature.as_bytes());
        }
        put_field_bytes(&mut out, 5, self.network_name.as_bytes());
        put_field_bytes(&mut out, 6, &self.network_secret_digest);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, EasytierError> {
        let mut at = 0;
        let mut request = HandshakeRequest {
            magic: 0,
            my_peer_id: 0,
            version: 0,
            features: Vec::new(),
            network_name: String::new(),
            network_secret_digest: Vec::new(),
        };
        while at < data.len() {
            let tag = read_varint(data, &mut at)?;
            let field = (tag >> 3) as u32;
            let wire = (tag & 7) as u8;
            match (field, wire) {
                (1, 0) => request.magic = read_varint(data, &mut at)? as u32,
                (2, 0) => request.my_peer_id = read_varint(data, &mut at)? as u32,
                (3, 0) => request.version = read_varint(data, &mut at)? as u32,
                (4, 2) | (5, 2) | (6, 2) => {
                    let len = read_varint(data, &mut at)? as usize;
                    let bytes = data
                        .get(at..at + len)
                        .ok_or(EasytierError::Protobuf)?
                        .to_vec();
                    at += len;
                    match field {
                        4 => request
                            .features
                            .push(String::from_utf8(bytes).map_err(|_| EasytierError::Protobuf)?),
                        5 => {
                            request.network_name =
                                String::from_utf8(bytes).map_err(|_| EasytierError::Protobuf)?
                        }
                        _ => request.network_secret_digest = bytes,
                    }
                }
                _ => skip_field(data, &mut at, wire)?,
            }
        }
        Ok(request)
    }
}

/// The `PeerManagerHeader` body used by the cleartext data/route packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerManagerHeader {
    pub from_peer_id: u32,
    pub to_peer_id: u32,
    pub packet_type: u8,
    pub flags: u8,
    pub forward_counter: u8,
    pub payload_len: u32,
}

impl PeerManagerHeader {
    pub fn decode(data: &[u8]) -> Result<Self, EasytierError> {
        if data.len() < PEER_MANAGER_HEADER_SIZE {
            return Err(EasytierError::Frame("short peer manager header"));
        }
        Ok(PeerManagerHeader {
            from_peer_id: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            to_peer_id: u32::from_le_bytes(data[4..8].try_into().unwrap()),
            packet_type: data[8],
            flags: data[9],
            forward_counter: data[10],
            payload_len: u32::from_le_bytes(data[12..16].try_into().unwrap()),
        })
    }
}

/// A connected EasyTier cleartext host/discovery session.
#[derive(Debug)]
pub struct EasytierSession {
    stream: TcpStream,
    pub local_peer_id: u32,
    pub remote_peer_id: u32,
    pub network_name: String,
    pub remote_features: Vec<String>,
    secure: Option<SecureSession>,
    pub local_static_public: Option<[u8; 32]>,
}

impl EasytierSession {
    /// Send the cleartext HandshakeRequest and verify the peer's reply.
    pub async fn connect(
        address: SocketAddr,
        network_name: &str,
        network_secret: &str,
        timeout: Duration,
    ) -> Result<Self, EasytierError> {
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(address))
            .await
            .map_err(|_| EasytierError::Timeout)??;
        let local_peer_id = loop {
            let id = rand::random::<u32>();
            if id != 0 {
                break id;
            }
        };
        let request = HandshakeRequest::new(network_name, network_secret, local_peer_id);
        let frame = Frame {
            from_peer_id: local_peer_id,
            to_peer_id: 0,
            packet_type: PacketType::HandShake as u8,
            flags: 0,
            forward_counter: 1,
            payload: request.encode(),
            declared_len: None,
        };
        stream.write_all(&frame.encode()).await?;
        let reply = read_frame(&mut stream, timeout).await?;
        if reply.packet_type != PacketType::HandShake as u8 {
            return Err(EasytierError::PacketType(reply.packet_type));
        }
        let parsed = HandshakeRequest::decode(&reply.payload)?;
        if parsed.magic != MAGIC_COOKIE {
            return Err(EasytierError::Magic);
        }
        if parsed.network_name != network_name {
            return Err(EasytierError::NetworkName);
        }
        if parsed.network_secret_digest.len() != 32
            || parsed.network_secret_digest != request.network_secret_digest
        {
            return Err(EasytierError::SecretDigest);
        }
        if parsed.my_peer_id == local_peer_id {
            return Err(EasytierError::PeerId);
        }
        Ok(EasytierSession {
            stream,
            local_peer_id,
            remote_peer_id: parsed.my_peer_id,
            network_name: network_name.to_string(),
            remote_features: parsed.features,
            secure: None,
            local_static_public: None,
        })
    }

    /// Noise XX client handshake and secure-datagram session setup.
    pub async fn connect_secure(
        address: SocketAddr,
        network_name: &str,
        network_secret: &str,
        options: EasytierSecureOptions,
        timeout: Duration,
    ) -> Result<Self, EasytierError> {
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(address))
            .await
            .map_err(|_| EasytierError::Timeout)??;
        let local_peer_id = loop {
            let id = rand::random::<u32>();
            if id != 0 {
                break id;
            }
        };
        let a_conn_id = Uuid::new_v4();
        let mut noise = NoiseInitiator::new(options.private_key);
        let msg1 = encode_noise_msg1(
            network_name,
            a_conn_id,
            &options.algorithm,
            &["liveness-echo-v1".to_string()],
        );
        let wire = noise.write_msg1(&msg1)?;
        let handshake_hash_after_msg1 = noise.handshake_hash();
        let frame = Frame {
            from_peer_id: local_peer_id,
            to_peer_id: 0,
            packet_type: PacketType::NoiseHandshakeMsg1 as u8,
            flags: 0,
            forward_counter: 1,
            payload: wire,
            declared_len: None,
        };
        stream.write_all(&frame.encode()).await?;
        let reply = read_frame(&mut stream, timeout).await?;
        if reply.packet_type != PacketType::NoiseHandshakeMsg2 as u8 {
            return Err(EasytierError::PacketType(reply.packet_type));
        }
        let remote_peer_id = if reply.from_peer_id != 0 {
            reply.from_peer_id
        } else {
            return Err(EasytierError::PeerId);
        };
        let plaintext = noise.read_msg2(&reply.payload)?;
        let msg2 = decode_noise_msg2(&plaintext)?;
        if msg2.b_network_name != network_name || msg2.role_hint != 1 {
            return Err(EasytierError::NetworkName);
        }
        if msg2.a_conn_id_echo != Some(a_conn_id) {
            return Err(EasytierError::PeerId);
        }
        let root_key = msg2.root_key_32.ok_or(EasytierError::SecureDatagramUnsupported)?;
        if msg2.action == 1 {
            return Err(EasytierError::SecureDatagramUnsupported);
        }
        let handshake_hash_for_proof = noise.handshake_hash();
        let proof = if network_secret.is_empty() {
            None
        } else {
            let mut data = SECRET_PROOF_PREFIX.to_vec();
            data.extend_from_slice(&handshake_hash_for_proof);
            Some(hmac_sha256(network_secret.as_bytes(), &data))
        };
        let digest = network_secret_digest(network_name, network_secret);
        let msg3 = encode_noise_msg3(a_conn_id, msg2.b_conn_id, proof, digest);
        let wire = noise.write_msg3(&msg3)?;
        let frame = Frame {
            from_peer_id: local_peer_id,
            to_peer_id: remote_peer_id,
            packet_type: PacketType::NoiseHandshakeMsg3 as u8,
            flags: 0,
            forward_counter: 1,
            payload: wire,
            declared_len: None,
        };
        stream.write_all(&frame.encode()).await?;
        // The server's msg2 proof uses the handshake hash after msg1.
        if let Some(proof) = msg2.secret_proof_32.as_deref() {
            let mut data = SECRET_PROOF_PREFIX.to_vec();
            data.extend_from_slice(&handshake_hash_after_msg1);
            let expected = hmac_sha256(network_secret.as_bytes(), &data);
            if proof != expected {
                return Err(EasytierError::SecretDigest);
            }
        } else if !network_secret.is_empty() {
            return Err(EasytierError::SecretDigest);
        }
        let secure = options.encrypt_data.then(|| {
            SecureSession::new(
                root_key,
                msg2.b_session_generation,
                msg2.initial_epoch,
                options.algorithm.clone(),
                local_peer_id,
                remote_peer_id,
            )
        });
        Ok(EasytierSession {
            stream,
            local_peer_id,
            remote_peer_id,
            network_name: network_name.to_string(),
            remote_features: msg2.features,
            secure,
            local_static_public: Some(PublicKey::from(&StaticSecret::from(options.private_key)).to_bytes()),
        })
    }

    /// Send a Ping (type 4) with a little-endian u32 sequence and wait for
    /// the peer's Pong (type 5).
    pub async fn ping(&mut self, sequence: u32, timeout: Duration) -> Result<(), EasytierError> {
        let frame = Frame {
            from_peer_id: self.local_peer_id,
            to_peer_id: self.remote_peer_id,
            packet_type: PacketType::Ping as u8,
            flags: 0,
            forward_counter: 1,
            payload: sequence.to_le_bytes().to_vec(),
            declared_len: None,
        };
        tokio::time::timeout(timeout, self.stream.write_all(&frame.encode()))
            .await
            .map_err(|_| EasytierError::Timeout)??;
        loop {
            let reply = read_frame(&mut self.stream, timeout).await?;
            if reply.packet_type == PacketType::Pong as u8
                && reply.payload == sequence.to_le_bytes()
            {
                return Ok(());
            }
        }
    }

    /// Send a data packet. When a secure session is active the payload is
    /// AES-GCM/ChaCha20 encrypted and the peer-manager encrypted flag/tail are
    /// applied exactly as `secure_datagram.rs` does.
    pub async fn send_data(
        &mut self,
        packet_type: u8,
        payload: &[u8],
    ) -> Result<(), EasytierError> {
        let declared_len = payload.len() as u32;
        let (payload, flags) = if let Some(secure) = self.secure.as_mut() {
            (secure.encrypt_payload(payload)?, 1u8)
        } else {
            (payload.to_vec(), 0u8)
        };
        let frame = Frame {
            from_peer_id: self.local_peer_id,
            to_peer_id: self.remote_peer_id,
            packet_type,
            flags,
            forward_counter: 1,
            payload,
            declared_len: Some(declared_len),
        };
        self.stream.write_all(&frame.encode()).await?;
        Ok(())
    }

    /// Decrypt one received data packet payload when the peer marked it
    /// encrypted. Ping/Pong/Noise frames are never encrypted by the source.
    pub fn decrypt_received(&mut self, frame: &Frame) -> Result<Vec<u8>, EasytierError> {
        if frame.flags & 1 == 0 {
            return Ok(frame.payload.clone());
        }
        let secure = self
            .secure
            .as_mut()
            .ok_or(EasytierError::SecureDatagramUnsupported)?;
        secure.decrypt_payload(&frame.payload)
    }
}

/// Read one `TCPTunnelHeader`-framed record.
pub async fn read_frame(stream: &mut TcpStream, timeout: Duration) -> Result<Frame, EasytierError> {
    let mut header = [0u8; TCP_TUNNEL_HEADER_SIZE];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| EasytierError::Timeout)??;
    let record_len = u32::from_le_bytes(header) as usize;
    if !(PEER_MANAGER_HEADER_SIZE..=1 << 20).contains(&record_len) {
        return Err(EasytierError::Frame("length out of range"));
    }
    let mut record = vec![0u8; record_len];
    tokio::time::timeout(timeout, stream.read_exact(&mut record))
        .await
        .map_err(|_| EasytierError::Timeout)??;
    let mut full = Vec::with_capacity(TCP_TUNNEL_HEADER_SIZE + record_len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&record);
    Frame::decode(&full)
}


const NOISE_PROTOCOL: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const NOISE_PROLOGUE: &[u8] = b"easytier-peerconn-noise";
const SECRET_PROOF_PREFIX: &[u8] = b"easytier secret proof";

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&out);
    hash
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while out.len() < length {
        let mut input = Vec::with_capacity(previous.len() + info.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(info);
        input.push(counter);
        let block = hmac_sha256(prk, &input);
        out.extend_from_slice(&block);
        previous = block.to_vec();
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    out
}

struct NoiseState {
    h: [u8; 32],
    ck: [u8; 32],
    key: Option<[u8; 32]>,
    nonce: u64,
}

impl NoiseState {
    fn new() -> Self {
        let mut h = [0u8; 32];
        let name = NOISE_PROTOCOL.as_bytes();
        if name.len() <= 32 {
            h[..name.len()].copy_from_slice(name);
        } else {
            h = sha256(name);
        }
        let mut state = NoiseState {
            h,
            ck: h,
            key: None,
            nonce: 0,
        };
        state.mix_hash(NOISE_PROLOGUE);
        state
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h.copy_from_slice(&hasher.finalize());
    }

    fn mix_key(&mut self, dh: &[u8; 32]) {
        let prk = hmac_sha256(&self.ck, dh);
        let okm = hkdf_expand(&prk, &[], 64);
        self.ck.copy_from_slice(&okm[..32]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm[32..]);
        self.key = Some(key);
        self.nonce = 0;
    }

    fn aead_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.nonce.to_le_bytes());
        nonce
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, EasytierError> {
        let ciphertext = if let Some(key) = self.key {
            let cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(&key));
            let nonce = self.aead_nonce();
            self.nonce = self.nonce.wrapping_add(1);
            cipher
                .encrypt(
                    ChachaNonce::from_slice(&nonce),
                    AeadPayload {
                        msg: plaintext,
                        aad: &self.h,
                    },
                )
                .map_err(|_| EasytierError::SecureDatagramUnsupported)?
        } else {
            plaintext.to_vec()
        };
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    fn decrypt_and_hash_tagged(&mut self, ciphertext: &[u8], tag: &'static str) -> Result<Vec<u8>, EasytierError> {
        let plaintext = if let Some(key) = self.key {
            let cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(&key));
            let nonce = self.aead_nonce();
            self.nonce = self.nonce.wrapping_add(1);
            cipher
                .decrypt(
                    ChachaNonce::from_slice(&nonce),
                    AeadPayload {
                        msg: ciphertext,
                        aad: &self.h,
                    },
                )
                .map_err(|_| EasytierError::Noise(tag))?
        } else {
            ciphertext.to_vec()
        };
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }
}

/// Noise XX initiator handshake, matching `snow` in the locked source.
struct NoiseInitiator {
    state: NoiseState,
    local_static: StaticSecret,
    local_public: PublicKey,
    ephemeral: Option<StaticSecret>,
    remote_ephemeral: Option<PublicKey>,
    remote_static: Option<PublicKey>,
}

impl NoiseInitiator {
    fn new(local_private: [u8; 32]) -> Self {
        let local_static = StaticSecret::from(local_private);
        let local_public = PublicKey::from(&local_static);
        NoiseInitiator {
            state: NoiseState::new(),
            local_static,
            local_public,
            ephemeral: None,
            remote_ephemeral: None,
            remote_static: None,
        }
    }

    fn write_msg1(&mut self, payload: &[u8]) -> Result<Vec<u8>, EasytierError> {
        let ephemeral = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral);
        self.state.mix_hash(ephemeral_public.as_bytes());
        self.ephemeral = Some(ephemeral);
        let mut out = ephemeral_public.as_bytes().to_vec();
        out.extend_from_slice(&self.state.encrypt_and_hash(payload)?);
        Ok(out)
    }

    fn read_msg2(&mut self, message: &[u8]) -> Result<Vec<u8>, EasytierError> {
        if message.len() < 32 + 48 {
            return Err(EasytierError::SecureDatagramUnsupported);
        }
        let remote_ephemeral = PublicKey::from(<[u8; 32]>::try_from(&message[..32]).unwrap());
        self.state.mix_hash(remote_ephemeral.as_bytes());
        let ephemeral = self
            .ephemeral
            .as_ref()
            .ok_or(EasytierError::SecureDatagramUnsupported)?;
        let shared = ephemeral.diffie_hellman(&remote_ephemeral);
        self.state.mix_key(shared.as_bytes());
        let static_plain = self.state.decrypt_and_hash_tagged(&message[32..80], "static")?;
        if static_plain.len() != 32 {
            return Err(EasytierError::SecretDigest);
        }
        self.remote_static =
            Some(PublicKey::from(<[u8; 32]>::try_from(static_plain.as_slice()).unwrap()));
        let remote_static = self
            .remote_static
            .as_ref()
            .ok_or(EasytierError::Noise("static"))?;
        let shared = ephemeral.diffie_hellman(remote_static);
        self.state.mix_key(shared.as_bytes());
        let payload = self.state.decrypt_and_hash_tagged(&message[80..], "payload")?;
        self.remote_ephemeral = Some(remote_ephemeral);
        Ok(payload)
    }

    fn write_msg3(&mut self, payload: &[u8]) -> Result<Vec<u8>, EasytierError> {
        let remote_ephemeral = self
            .remote_ephemeral
            .ok_or(EasytierError::SecureDatagramUnsupported)?;
        let mut out = self
            .state
            .encrypt_and_hash(self.local_public.as_bytes())?;
        let shared = self.local_static.diffie_hellman(&remote_ephemeral);
        self.state.mix_key(shared.as_bytes());
        out.extend_from_slice(&self.state.encrypt_and_hash(payload)?);
        Ok(out)
    }

    fn handshake_hash(&self) -> [u8; 32] {
        self.state.h
    }

}

fn encode_uuid(uuid: Uuid) -> Vec<u8> {
    let (high, low) = uuid.as_u64_pair();
    let mut out = Vec::new();
    put_field_varint(&mut out, 1, (high >> 32) as u64);
    put_field_varint(&mut out, 2, (high & 0xffff_ffff) as u64);
    put_field_varint(&mut out, 3, (low >> 32) as u64);
    put_field_varint(&mut out, 4, (low & 0xffff_ffff) as u64);
    out
}

fn decode_uuid(data: &[u8]) -> Result<Uuid, EasytierError> {
    let mut at = 0;
    let mut parts = [0u32; 4];
    while at < data.len() {
        let tag = read_varint(data, &mut at)?;
        let field = (tag >> 3) as usize;
        let wire = (tag & 7) as u8;
        if wire == 0 && (1..=4).contains(&field) {
            parts[field - 1] = read_varint(data, &mut at)? as u32;
        } else {
            skip_field(data, &mut at, wire)?;
        }
    }
    Ok(Uuid::from_u64_pair(
        (u64::from(parts[0]) << 32) | u64::from(parts[1]),
        (u64::from(parts[2]) << 32) | u64::from(parts[3]),
    ))
}

fn encode_noise_msg1(
    network_name: &str,
    conn_id: Uuid,
    algorithm: &str,
    features: &[String],
) -> Vec<u8> {
    let mut out = Vec::new();
    put_field_varint(&mut out, 1, PROTOCOL_VERSION as u64);
    put_field_bytes(&mut out, 2, network_name.as_bytes());
    put_field_bytes(&mut out, 4, &encode_uuid(conn_id));
    put_field_bytes(&mut out, 5, algorithm.as_bytes());
    for feature in features {
        put_field_bytes(&mut out, 6, feature.as_bytes());
    }
    out
}

#[derive(Debug, Clone)]
struct NoiseMsg2 {
    b_network_name: String,
    role_hint: u32,
    action: u32,
    b_session_generation: u32,
    root_key_32: Option<[u8; 32]>,
    initial_epoch: u32,
    b_conn_id: Option<Uuid>,
    a_conn_id_echo: Option<Uuid>,
    secret_proof_32: Option<Vec<u8>>,
    server_encryption_algorithm: String,
    features: Vec<String>,
}

fn decode_noise_msg2(data: &[u8]) -> Result<NoiseMsg2, EasytierError> {
    let mut at = 0;
    let mut msg = NoiseMsg2 {
        b_network_name: String::new(),
        role_hint: 0,
        action: 0,
        b_session_generation: 0,
        root_key_32: None,
        initial_epoch: 0,
        b_conn_id: None,
        a_conn_id_echo: None,
        secret_proof_32: None,
        server_encryption_algorithm: String::new(),
        features: Vec::new(),
    };
    while at < data.len() {
        let tag = read_varint(data, &mut at)?;
        let field = (tag >> 3) as u32;
        let wire = (tag & 7) as u8;
        match (field, wire) {
            (1, 2) | (5, 2) | (7, 2) | (8, 2) | (9, 2) | (10, 2) | (11, 2) => {
                let len = read_varint(data, &mut at)? as usize;
                let bytes = data
                    .get(at..at + len)
                    .ok_or(EasytierError::Protobuf)?
                    .to_vec();
                at += len;
                match field {
                    1 => msg.b_network_name = String::from_utf8(bytes).map_err(|_| EasytierError::Protobuf)?,
                    5 => {
                        let key: [u8; 32] = bytes.try_into().map_err(|_| EasytierError::Protobuf)?;
                        msg.root_key_32 = Some(key);
                    }
                    7 => msg.b_conn_id = Some(decode_uuid(&bytes)?),
                    8 => msg.a_conn_id_echo = Some(decode_uuid(&bytes)?),
                    9 => msg.secret_proof_32 = Some(bytes),
                    10 => msg.server_encryption_algorithm = String::from_utf8(bytes).map_err(|_| EasytierError::Protobuf)?,
                    _ => msg.features.push(String::from_utf8(bytes).map_err(|_| EasytierError::Protobuf)?),
                }
            }
            (2, 0) | (3, 0) | (4, 0) | (6, 0) => {
                let value = read_varint(data, &mut at)? as u32;
                match field {
                    2 => msg.role_hint = value,
                    3 => msg.action = value,
                    4 => msg.b_session_generation = value,
                    _ => msg.initial_epoch = value,
                }
            }
            _ => skip_field(data, &mut at, wire)?,
        }
    }
    Ok(msg)
}

fn encode_noise_msg3(
    a_conn_id: Uuid,
    b_conn_id: Option<Uuid>,
    proof: Option<[u8; 32]>,
    digest: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    put_field_bytes(&mut out, 1, &encode_uuid(a_conn_id));
    if let Some(b_conn_id) = b_conn_id {
        put_field_bytes(&mut out, 2, &encode_uuid(b_conn_id));
    }
    if let Some(proof) = proof {
        put_field_bytes(&mut out, 3, &proof);
    }
    put_field_bytes(&mut out, 4, &digest);
    out
}

#[derive(Debug)]
struct SecureSession {
    root_key: [u8; 32],
    _generation: u32,
    send_epoch: u32,
    send_seq: u64,
    recv_epoch: u32,
    recv_max_seq: u64,
    algorithm: String,
    send_dir: usize,
    recv_dir: usize,
}

impl SecureSession {
    fn new(
        root_key: [u8; 32],
        generation: u32,
        initial_epoch: u32,
        algorithm: String,
        local_peer_id: u32,
        remote_peer_id: u32,
    ) -> Self {
        let send_dir = usize::from(local_peer_id >= remote_peer_id);
        SecureSession {
            root_key,
            _generation: generation,
            send_epoch: initial_epoch,
            send_seq: 0,
            recv_epoch: initial_epoch,
            recv_max_seq: 0,
            algorithm,
            send_dir,
            recv_dir: 1 - send_dir,
        }
    }

    fn traffic_key(&self, epoch: u32, dir: usize) -> [u8; 32] {
        let prk = hmac_sha256(&[0u8; 32], &self.root_key);
        let mut info = Vec::with_capacity(9 + 4 + 1);
        info.extend_from_slice(b"et-traffic");
        info.extend_from_slice(&epoch.to_be_bytes());
        info.push(dir as u8);
        let okm = hkdf_expand(&prk, &info, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm[..32]);
        key
    }

    fn encrypt_payload(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, EasytierError> {
        let epoch = self.send_epoch;
        let seq = self.send_seq;
        self.send_seq += 1;
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&epoch.to_be_bytes());
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        let key = self.traffic_key(epoch, self.send_dir);
        let mut payload = plaintext.to_vec();
        let tag = if self.algorithm == "chacha20" {
            let cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(&key));
            cipher
                .encrypt_in_place_detached(ChachaNonce::from_slice(&nonce), &[], &mut payload)
                .map_err(|_| EasytierError::SecureDatagramUnsupported)?
        } else {
            let cipher = Aes128Gcm::new_from_slice(&key[..16])
                .map_err(|_| EasytierError::SecureDatagramUnsupported)?;
            cipher
                .encrypt_in_place_detached(AesNonce::from_slice(&nonce), &[], &mut payload)
                .map_err(|_| EasytierError::SecureDatagramUnsupported)?
        };
        payload.extend_from_slice(&tag);
        payload.extend_from_slice(&nonce);
        Ok(payload)
    }

    fn decrypt_payload(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, EasytierError> {
        if ciphertext.len() < 28 {
            return Err(EasytierError::SecureDatagramUnsupported);
        }
        let body_len = ciphertext.len() - 28;
        let nonce: [u8; 12] = ciphertext[body_len + 16..].try_into().unwrap();
        let tag: [u8; 16] = ciphertext[body_len..body_len + 16].try_into().unwrap();
        let epoch = u32::from_be_bytes(nonce[..4].try_into().unwrap());
        let seq = u64::from_be_bytes(nonce[4..].try_into().unwrap());
        if epoch < self.recv_epoch || (epoch == self.recv_epoch && seq <= self.recv_max_seq) {
            return Err(EasytierError::SecretDigest);
        }
        let key = self.traffic_key(epoch, self.recv_dir);
        let mut payload = ciphertext[..body_len].to_vec();
        if self.algorithm == "chacha20" {
            let cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(&key));
            cipher
                .decrypt_in_place_detached(
                    ChachaNonce::from_slice(&nonce),
                    &[],
                    &mut payload,
                    chacha20poly1305::Tag::from_slice(&tag),
                )
                .map_err(|_| EasytierError::SecretDigest)?;
        } else {
            let cipher = Aes128Gcm::new_from_slice(&key[..16])
                .map_err(|_| EasytierError::SecureDatagramUnsupported)?;
            cipher
                .decrypt_in_place_detached(
                    AesNonce::from_slice(&nonce),
                    &[],
                    &mut payload,
                    aes_gcm::Tag::from_slice(&tag),
                )
                .map_err(|_| EasytierError::SecretDigest)?;
        }
        self.recv_epoch = epoch;
        self.recv_max_seq = seq;
        Ok(payload)
    }
}

/// Options for the Noise XX/secure-datagram path.
pub struct EasytierSecureOptions {
    pub private_key: [u8; 32],
    pub algorithm: String,
    pub encrypt_data: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_matches_the_locked_easytier_vectors() {
        assert_eq!(
            hex::encode(network_secret_digest("capprobe", "test")),
            "5e7befbd5bcab40df260b8b9f03230e014a13608a8dfd2a477d0c360a02ffc08"
        );
        assert_eq!(
            hex::encode(network_secret_digest("capprobe2", "test")),
            "0304950fd1e219b26a7996b818ab1d15dfe4ecb2b234a22dead4d537b6dce4d2"
        );
    }

    #[test]
    fn frame_uses_little_endian_peer_ids_and_lengths() {
        let frame = Frame {
            from_peer_id: 0x11223344,
            to_peer_id: 0x55667788,
            packet_type: PacketType::HandShake as u8,
            flags: 0,
            forward_counter: 1,
            payload: b"body".to_vec(),
            declared_len: Some(4),
        };
        let wire = frame.encode();
        assert_eq!(&wire[..4], &(PEER_MANAGER_HEADER_SIZE as u32 + 4).to_le_bytes());
        assert_eq!(&wire[4..8], &[0x44, 0x33, 0x22, 0x11]);
        assert_eq!(&wire[8..12], &[0x88, 0x77, 0x66, 0x55]);
        assert_eq!(Frame::decode(&wire).unwrap(), frame);
    }

    #[test]
    fn handshake_roundtrips_and_ignores_unknown_fields() {
        let request = HandshakeRequest::new("billow", "secret", 7);
        let encoded = request.encode();
        assert_eq!(HandshakeRequest::decode(&encoded).unwrap(), request);
        let mut extended = encoded;
        extended.extend_from_slice(&[0x78, 0x01]); // field 15 varint 1
        assert_eq!(HandshakeRequest::decode(&extended).unwrap(), request);
    }
}
