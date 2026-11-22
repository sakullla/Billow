// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Derived from the locked EasyTier source (github.com/EasyTier/EasyTier,
// LGPL-3.0-or-later), specifically:
//   easytier-core/src/config/mod.rs            (network_secret_digest)
//   easytier-core/src/packet/mod.rs            (PeerManagerHeader, TCPTunnelHeader,
//                                               PacketType, DefaultEndian = little)
//   easytier-core/src/peers/conn/peer_conn.rs  (HandshakeRequest, cleartext path)
//   easytier-core/src/peers/conn/peer_conn_ping.rs (Ping/Pong payload)
// The Go module cache pins `github.com/easytier/easytier/easytier-go`
// v0.0.0-20261111015056-2abb1676b475 whose embedded core reports
// commit 5f1eaa7c9f9d3e89e9b75a6d87531a436fae40c4; the public upstream main
// tree is the translation reference. This file is a Rust expression and is
// distributed under LGPL-3.0-or-later, not the MIT license of the rest of the
// kernel. See native-kernel/THIRD_PARTY_NOTICES.md.
//
// Scope: the cleartext host/discovery frame, network secret digest,
// HandshakeRequest, PeerManagerHeader and PingPong. The secure-datagram /
// Noise XX layer and the userspace IP stack/TUN are not implemented here;
// `enable-encryption: true` and the related keys are rejected at load.

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
    #[error("EasyTier secure-datagram/Noise layer is not implemented")]
    SecureDatagramUnsupported,
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
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
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
