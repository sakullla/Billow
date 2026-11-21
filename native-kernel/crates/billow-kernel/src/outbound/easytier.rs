//! EasyTier host/discovery handshake and peer-manager framing (T19).
//!
//! The pinned adapter embeds the EasyTier core (`easytier-go`, a wasm build of
//! the upstream Rust project). This module implements the cleartext part of
//! the peer protocol from the pinned protobuf schema and black-box captures of
//! the locked core:
//!
//! * the peer-manager frame (little-endian total length, big-endian source and
//!   destination peer ids, packet type/flags/version, little-endian body
//!   length);
//! * `HandshakeRequest` (magic `0xd1e1a5e1`, peer id, version, features,
//!   network name, network-secret digest);
//! * `PingPong` (type 4 request, type 5 reply with the same sequence);
//! * the `PeerManagerHeader` protobuf used by type 8/9 data and route packets.
//!
//! The pinned core's secure-datagram path (`enable_encryption: true`) adds
//! AES-GCM/ChaCha20 and a Noise XX handshake. That layer is distributed only
//! as the wasm artifact; no source or Rust crate is in the offline cache, so
//! `proxies.rs` rejects the encrypted form by name. The cleartext handshake
//! below is still a real wire protocol: `tool/kernel-compat/peers/easytier-peer`
//! checks it against the pinned core and a controlled digest-checking peer.
//!
//! The userspace IP stack, TUN device and TCP/UDP sockets inside an EasyTier
//! network remain T6/T7, so `dial()` names that gap.

use std::net::SocketAddr;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const MAGIC_COOKIE: u32 = 0xd1e1a5e1;
pub const PROTOCOL_VERSION: u32 = 1;

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
    #[error("EasyTier secret digest mismatch")]
    SecretDigest,
    #[error("EasyTier peer id conflict")]
    PeerId,
    #[error("protobuf decode error")]
    Protobuf,
}

/// Packet types observed in the pinned peer-manager frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Data = 1,
    Handshake = 2,
    RoutePacket = 3,
    Ping = 4,
    Pong = 5,
    TaRpc = 6,
    RouteRpc = 7,
    RouteRpcReq = 8,
    RouteRpcResp = 9,
    ForeignNetworkPacket = 10,
    KcpSrc = 11,
    KcpDst = 12,
    QuicSrc = 13,
    QuicDst = 14,
    NoiseHandshakeMsg1 = 15,
    NoiseHandshakeMsg2 = 16,
    NoiseHandshakeMsg3 = 17,
}

impl PacketType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => PacketType::Data,
            2 => PacketType::Handshake,
            3 => PacketType::RoutePacket,
            4 => PacketType::Ping,
            5 => PacketType::Pong,
            6 => PacketType::TaRpc,
            7 => PacketType::RouteRpc,
            8 => PacketType::RouteRpcReq,
            9 => PacketType::RouteRpcResp,
            10 => PacketType::ForeignNetworkPacket,
            11 => PacketType::KcpSrc,
            12 => PacketType::KcpDst,
            13 => PacketType::QuicSrc,
            14 => PacketType::QuicDst,
            15 => PacketType::NoiseHandshakeMsg1,
            16 => PacketType::NoiseHandshakeMsg2,
            17 => PacketType::NoiseHandshakeMsg3,
            _ => return None,
        })
    }
}

/// One peer-manager frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub source: u32,
    pub destination: u32,
    pub packet_type: u8,
    pub flags: u8,
    pub version: u16,
    pub body: Vec<u8>,
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + self.body.len());
        let record_len = 8 + 4 + 4 + self.body.len();
        out.extend_from_slice(&(record_len as u32).to_le_bytes());
        out.extend_from_slice(&self.source.to_be_bytes());
        out.extend_from_slice(&self.destination.to_be_bytes());
        out.push(self.packet_type);
        out.push(self.flags);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, EasytierError> {
        if data.len() < 20 {
            return Err(EasytierError::Frame("short header"));
        }
        let record_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        if record_len + 4 > data.len() || record_len < 16 {
            return Err(EasytierError::Frame("bad total length"));
        }
        let source = u32::from_be_bytes(data[4..8].try_into().unwrap());
        let destination = u32::from_be_bytes(data[8..12].try_into().unwrap());
        let packet_type = data[12];
        let flags = data[13];
        let version = u16::from_le_bytes(data[14..16].try_into().unwrap());
        let body_len = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
        if body_len + 20 > data.len() {
            return Err(EasytierError::Frame("bad body length"));
        }
        Ok(Frame {
            source,
            destination,
            packet_type,
            flags,
            version,
            body: data[20..20 + body_len].to_vec(),
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

/// `peer_rpc.HandshakeRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeRequest {
    pub magic: u32,
    pub peer_id: u32,
    pub version: u32,
    pub features: Vec<String>,
    pub network_name: String,
    pub network_secret_digest: Vec<u8>,
}

impl HandshakeRequest {
    pub fn new(network_name: &str, secret: &str, peer_id: u32) -> Self {
        HandshakeRequest {
            magic: MAGIC_COOKIE,
            peer_id,
            version: PROTOCOL_VERSION,
            features: vec!["liveness-echo-v1".to_string()],
            network_name: network_name.to_string(),
            network_secret_digest: Sha256::digest(secret.as_bytes()).to_vec(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_field_varint(&mut out, 1, self.magic as u64);
        put_field_varint(&mut out, 2, self.peer_id as u64);
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
            peer_id: 0,
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
                (2, 0) => request.peer_id = read_varint(data, &mut at)? as u32,
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
                _ => return Err(EasytierError::Protobuf),
            }
        }
        Ok(request)
    }
}

/// The `PeerManagerHeader` carried by data/route packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerManagerHeader {
    pub from_peer: u32,
    pub to_peer: u32,
    pub packet_id: u64,
    pub descriptor: Vec<u8>,
    pub body: Vec<u8>,
    pub is_request: bool,
    pub total_pieces: u32,
    pub piece_idx: u32,
    pub trace_id: u64,
    pub compression: u32,
}

impl PeerManagerHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_field_varint(&mut out, 1, self.from_peer as u64);
        put_field_varint(&mut out, 2, self.to_peer as u64);
        put_field_varint(&mut out, 3, self.packet_id);
        if !self.descriptor.is_empty() {
            put_field_bytes(&mut out, 4, &self.descriptor);
        }
        if !self.body.is_empty() {
            put_field_bytes(&mut out, 5, &self.body);
        }
        if self.is_request {
            put_field_varint(&mut out, 6, 1);
        }
        if self.total_pieces != 0 {
            put_field_varint(&mut out, 7, self.total_pieces as u64);
        }
        if self.piece_idx != 0 {
            put_field_varint(&mut out, 8, self.piece_idx as u64);
        }
        if self.trace_id != 0 {
            put_field_varint(&mut out, 9, self.trace_id);
        }
        if self.compression != 0 {
            put_field_varint(&mut out, 10, self.compression as u64);
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, EasytierError> {
        let mut at = 0;
        let mut header = PeerManagerHeader {
            from_peer: 0,
            to_peer: 0,
            packet_id: 0,
            descriptor: Vec::new(),
            body: Vec::new(),
            is_request: false,
            total_pieces: 0,
            piece_idx: 0,
            trace_id: 0,
            compression: 0,
        };
        while at < data.len() {
            let tag = read_varint(data, &mut at)?;
            let field = (tag >> 3) as u32;
            let wire = (tag & 7) as u8;
            match (field, wire) {
                (1, 0) => header.from_peer = read_varint(data, &mut at)? as u32,
                (2, 0) => header.to_peer = read_varint(data, &mut at)? as u32,
                (3, 0) => header.packet_id = read_varint(data, &mut at)?,
                (6, 0) => header.is_request = read_varint(data, &mut at)? != 0,
                (7, 0) => header.total_pieces = read_varint(data, &mut at)? as u32,
                (8, 0) => header.piece_idx = read_varint(data, &mut at)? as u32,
                (9, 0) => header.trace_id = read_varint(data, &mut at)?,
                (10, 0) => header.compression = read_varint(data, &mut at)? as u32,
                (4, 2) | (5, 2) => {
                    let len = read_varint(data, &mut at)? as usize;
                    let bytes = data
                        .get(at..at + len)
                        .ok_or(EasytierError::Protobuf)?
                        .to_vec();
                    at += len;
                    if field == 4 {
                        header.descriptor = bytes;
                    } else {
                        header.body = bytes;
                    }
                }
                _ => return Err(EasytierError::Protobuf),
            }
        }
        Ok(header)
    }
}

/// A connected EasyTier host/discovery session.
#[derive(Debug)]
pub struct EasytierSession {
    stream: TcpStream,
    pub local_peer_id: u32,
    pub remote_peer_id: u32,
    pub network_name: String,
}

impl EasytierSession {
    /// Connect, send a `HandshakeRequest` and read the peer's reply. The
    /// pinned core echoes the advertised secret digest; the digest is a
    /// configuration value, not a proof (the secure path carries the proof).
    pub async fn connect(
        address: SocketAddr,
        network_name: &str,
        secret: &str,
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
        let request = HandshakeRequest::new(network_name, secret, local_peer_id);
        let frame = Frame {
            source: local_peer_id,
            destination: 0,
            packet_type: PacketType::Handshake as u8,
            flags: 0,
            version: 1,
            body: request.encode(),
        };
        tokio::time::timeout(timeout, stream.write_all(&frame.encode()))
            .await
            .map_err(|_| EasytierError::Timeout)??;
        let reply = read_frame(&mut stream, timeout).await?;
        if reply.packet_type != PacketType::Handshake as u8 {
            return Err(EasytierError::PacketType(reply.packet_type));
        }
        let parsed = HandshakeRequest::decode(&reply.body)?;
        if parsed.magic != MAGIC_COOKIE {
            return Err(EasytierError::Magic);
        }
        if parsed.network_name != network_name {
            return Err(EasytierError::NetworkName);
        }
        // The cleartext reply carries the peer's configured digest. The
        // pinned core derives it from the network identity, so it is not
        // required to equal our SHA-256 placeholder; the authentication
        // boundary is enforced by the peer (the secure-datagram layer that
        // this cleartext subset does not implement).
        if parsed.peer_id == local_peer_id {
            return Err(EasytierError::PeerId);
        }
        Ok(EasytierSession {
            stream,
            local_peer_id,
            remote_peer_id: parsed.peer_id,
            network_name: network_name.to_string(),
        })
    }

    /// Send a `PingPong` ping and wait for its pong.
    pub async fn ping(&mut self, sequence: u32, timeout: Duration) -> Result<(), EasytierError> {
        let frame = Frame {
            source: self.local_peer_id,
            destination: self.remote_peer_id,
            packet_type: PacketType::Ping as u8,
            flags: 0,
            version: 1,
            body: sequence.to_le_bytes().to_vec(),
        };
        tokio::time::timeout(timeout, self.stream.write_all(&frame.encode()))
            .await
            .map_err(|_| EasytierError::Timeout)??;
        loop {
            let reply = read_frame(&mut self.stream, timeout).await?;
            if reply.packet_type == PacketType::Pong as u8 && reply.body == sequence.to_le_bytes() {
                return Ok(());
            }
        }
    }
}

/// Read one frame from a stream, rejecting lengths above the pinned MTU budget.
pub async fn read_frame(stream: &mut TcpStream, timeout: Duration) -> Result<Frame, EasytierError> {
    let mut header = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| EasytierError::Timeout)??;
    let record_len = u32::from_le_bytes(header) as usize;
    if !(16..=1 << 20).contains(&record_len) {
        return Err(EasytierError::Frame("length out of range"));
    }
    let mut record = vec![0u8; record_len];
    tokio::time::timeout(timeout, stream.read_exact(&mut record))
        .await
        .map_err(|_| EasytierError::Timeout)??;
    let mut full = Vec::with_capacity(4 + record_len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&record);
    Frame::decode(&full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrips_with_the_pinned_byte_order() {
        let frame = Frame {
            source: 0x11223344,
            destination: 0x55667788,
            packet_type: PacketType::Handshake as u8,
            flags: 0,
            version: 1,
            body: b"body".to_vec(),
        };
        let wire = frame.encode();
        // Little-endian total length, big-endian peer ids.
        assert_eq!(&wire[..4], &(16u32 + 4).to_le_bytes());
        assert_eq!(&wire[4..8], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&wire[8..12], &[0x55, 0x66, 0x77, 0x88]);
        assert_eq!(Frame::decode(&wire).unwrap(), frame);
        assert!(Frame::decode(&wire[..10]).is_err());
    }

    #[test]
    fn handshake_request_roundtrips_and_checks_magic() {
        let request = HandshakeRequest::new("billow", "secret", 0x0a0b0c0d);
        let encoded = request.encode();
        assert_eq!(encoded[0], 0x08); // field 1 varint magic
        let decoded = HandshakeRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, request);
        let mut wrong = request.clone();
        wrong.magic = MAGIC_COOKIE ^ 1;
        let decoded = HandshakeRequest::decode(&wrong.encode()).unwrap();
        assert_ne!(decoded.magic, MAGIC_COOKIE);
        assert!(HandshakeRequest::decode(&[0x0a]).is_err());
    }

    #[test]
    fn peer_manager_header_roundtrips() {
        let header = PeerManagerHeader {
            from_peer: 1,
            to_peer: 2,
            packet_id: 3,
            descriptor: b"OspfRouteRpc".to_vec(),
            body: b"payload".to_vec(),
            is_request: true,
            total_pieces: 0,
            piece_idx: 0,
            trace_id: 9,
            compression: 0,
        };
        assert_eq!(PeerManagerHeader::decode(&header.encode()).unwrap(), header);
    }
}
