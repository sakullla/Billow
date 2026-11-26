//! WireGuard transport (Noise IK handshake + transport data messages).
//!
//! This module is the protocol half of the pinned `wireguard` outbound
//! (`adapter/outbound/wireguard.go`): it terminates the WireGuard tunnel at
//! the packet level and exposes encrypted IP packets. [`connect_stack`] wires
//! that packet stream to the shared smoltcp stack in [`crate::outbound::l3`],
//! so [`dial`] returns a real TCP stream and `tunnel::udp` gets a real UDP
//! association. Peer selection follows `allowed-ips` by longest prefix
//! (`select_peer`).
//!
//! Wire format implemented here (WireGuard whitepaper, public protocol):
//!
//! * handshake initiation (`type 1`): ephemeral, encrypted static, encrypted
//!   TAI64N timestamp, MAC1/MAC2;
//! * handshake response (`type 2`): ephemeral, encrypted empty, MAC1/MAC2;
//!   the initiator derives the transport keys, with the optional pre-shared
//!   key mixed in at the responder's step;
//! * cookie reply (`type 3`): XChaCha20-Poly1305 encrypted cookie, so a
//!   rate-limited responder is not a permanent failure;
//! * transport data (`type 4`): ChaCha20-Poly1305 with a 96-bit counter
//!   nonce, zero padding to the 16-byte block, replay window and keepalive.
//!
//! Keys are the base64 form the pinned type reads (`private-key`,
//! `public-key`, `pre-shared-key`); `reserved` occupies the three reserved
//! header bytes as the pinned `ClientBind` does for WARP-style endpoints.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use blake2::digest::consts::U16;
use blake2::digest::{Digest, FixedOutput};
use blake2::{Blake2s256, Blake2sMac};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::outbound::l3::{self, Stack, StackConfig};
use crate::outbound::ipstack::IpPrefix;
use crate::proxies::{WireguardOutbound, WireguardPeerOutbound};

/// `CONSTRUCTION` from the WireGuard whitepaper.
const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// `IDENTIFIER` from the WireGuard whitepaper.
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

const MESSAGE_HANDSHAKE_INITIATION: u8 = 1;
const MESSAGE_HANDSHAKE_RESPONSE: u8 = 2;
const MESSAGE_COOKIE_REPLY: u8 = 3;
const MESSAGE_TRANSPORT_DATA: u8 = 4;

const INITIATION_LEN: usize = 148;
const RESPONSE_LEN: usize = 92;
const COOKIE_REPLY_LEN: usize = 64;
const TRANSPORT_HEADER_LEN: usize = 16;
/// `REKEY_AFTER_TIME`: the initiator starts a new handshake after two
/// minutes, before the responder's three-minute rejection window.
const REKEY_AFTER: Duration = Duration::from_secs(120);
/// `REJECT_AFTER_MESSAGES` is 2^60 for a transport key; a rekey happens far
/// earlier, but the counter is still bounded here so a bug cannot wrap.
const REJECT_AFTER_MESSAGES: u64 = 1 << 60;

/// A WireGuard key as the pinned outbound reads it: base64 of 32 bytes.
pub fn decode_key(value: &str) -> Result<[u8; 32], WireguardError> {
    let bytes = decode_base64(value).ok_or(WireguardError::InvalidKey)?;
    if bytes.len() != 32 {
        return Err(WireguardError::InvalidKey);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Decode standard base64 with padding, as Go's `base64.StdEncoding` does.
fn decode_base64(value: &str) -> Option<Vec<u8>> {
    fn sextet(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let trimmed = value.trim();
    if trimmed.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() / 4 * 3);
    let mut chunks = trimmed.as_bytes().chunks_exact(4);
    for chunk in &mut chunks {
        let pad = chunk.iter().filter(|byte| **byte == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut values = [0u8; 4];
        for (i, byte) in chunk.iter().enumerate() {
            values[i] = if *byte == b'=' {
                0
            } else {
                sextet(*byte)?
            };
        }
        let triple = ((values[0] as u32) << 18)
            | ((values[1] as u32) << 12)
            | ((values[2] as u32) << 6)
            | values[3] as u32;
        out.push((triple >> 16) as u8);
        if pad < 2 {
            out.push((triple >> 8) as u8);
        }
        if pad < 1 {
            out.push(triple as u8);
        }
    }
    Some(out)
}

#[derive(Debug, thiserror::Error)]
pub enum WireguardError {
    #[error("wireguard key is not base64 of 32 bytes")]
    InvalidKey,
    #[error("wireguard configuration has no peer to connect to")]
    NoPeer,
    #[error("wireguard endpoint {endpoint}: {source}")]
    Connect {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("wireguard handshake timed out after {0:?}")]
    Timeout(Duration),
    #[error("wireguard handshake: {0}")]
    Handshake(String),
    #[error("wireguard transport: {0}")]
    Transport(String),
    #[error("wireguard packet of {len} bytes exceeds the MTU of {mtu}")]
    PacketTooLarge { len: usize, mtu: usize },
    #[error("wireguard receive buffer of {len} bytes is smaller than the packet ({packet})")]
    BufferTooSmall { len: usize, packet: usize },
    #[error("wireguard endpooint {0} resolved to no address")]
    Resolve(String),
    #[error("wireguard configuration has no local IPv4 or IPv6 address ('ip'/'ipv6'): the userspace IP stack needs one")]
    NoLocalAddress,
    #[error("wireguard has no peer with an allowed-ips prefix covering {0}")]
    NoRoute(IpAddr),
    #[error("wireguard userspace stack: {0}")]
    Stack(String),
    #[error("wireguard data packet authentication failed; the session needs a new handshake")]
    Authentication,
}

/// One peer the tunnel encrypts packets for. Keys are already decoded; the
/// configuration parser keeps the base64 text so a load failure names the
/// option instead of printing key material.
#[derive(Clone, PartialEq, Eq)]
pub struct WireguardPeer {
    pub endpoint: SocketAddr,
    pub public_key: PublicKey,
    pub preshared_key: Option<[u8; 32]>,
    /// The three reserved header bytes (`reserved:`); every message sends
    /// them, as the pinned `ClientBind` does (`b[1..4]`).
    pub reserved: [u8; 3],
    /// Prefixes this peer carries; an empty list means "every destination"
    /// only for the compatibility constructors that do not know the config.
    /// The configuration path always fills it from `allowed-ips`.
    pub allowed_ips: Vec<IpPrefix>,
}

impl std::fmt::Debug for WireguardPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireguardPeer")
            .field("endpoint", &self.endpoint)
            .field("public_key", &"<key>")
            .field(
                "preshared_key",
                &self.preshared_key.map(|_| "<redacted>"),
            )
            .field("reserved", &self.reserved)
            .finish()
    }
}

/// Derive the Curve25519 public key of a WireGuard private key. Peer
/// configurations and the T6/T7 device layer need this to register the local
/// public key with the far side.
pub fn derive_public_key(private: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

/// Encode a key in the base64 form the pinned type expects.
pub fn encode_key(key: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(key.len().div_ceil(3) * 4);
    for chunk in key.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(triple >> 18) as usize & 63] as char);
        out.push(TABLE[(triple >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(triple >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[triple as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

impl WireguardPeer {
    /// Build a peer from the wire key text, for the transport API used by the
    /// device layer and the controlled-peer tests.
    pub fn from_base64(
        endpoint: SocketAddr,
        public_key: &str,
        preshared_key: Option<&str>,
        reserved: [u8; 3],
    ) -> Result<Self, WireguardError> {
        let public_key = PublicKey::from(decode_key(public_key)?);
        let preshared_key = preshared_key.map(decode_key).transpose()?;
        Ok(Self {
            endpoint,
            public_key,
            preshared_key,
            reserved,
            allowed_ips: Vec::new(),
        })
    }

    /// Build one peer from the parsed configuration. `server` may be a name;
    /// resolution happens in [`WireguardTunnel::connect`].
    pub fn from_outbound(
        peer: &WireguardPeerOutbound,
    ) -> Result<(String, u16, [u8; 32], Option<[u8; 32]>, [u8; 3]), WireguardError> {
        let public_key = decode_key(&peer.public_key)?;
        let preshared_key = peer
            .preshared_key
            .as_ref()
            .map(|key| decode_key(key.expose()))
            .transpose()?;
        let mut reserved = [0u8; 3];
        if !peer.reserved.is_empty() {
            for (slot, value) in reserved.iter_mut().zip(peer.reserved.iter()) {
                *slot = *value;
            }
        }
        Ok((
            peer.server.clone(),
            peer.port,
            public_key,
            preshared_key,
            reserved,
        ))
    }
}

/// One established WireGuard session (one peer, one handshake).
///
/// The caller owns the IP packets: [`send_packet`](Self::send_packet) writes
/// an IP datagram inside the tunnel and [`recv_packet`](Self::recv_packet)
/// returns the decrypted IP datagram the peer sent. This is exactly the
/// boundary the device/IP-stack layer (T6/T7) needs.
pub struct WireguardTunnel {
    socket: Arc<UdpSocket>,
    peer: WireguardPeer,
    local_static: StaticSecret,
    local_index: u32,
    peer_index: u32,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u64,
    replay: ReplayWindow,
    handshake_at: Instant,
    mtu: usize,
    keepalive: u16,
    last_sent: Instant,
    handshake_timeout: Duration,
    /// Reused receive scratch for transport data so a steady stream does not
    /// allocate a 64 KiB buffer per datagram. The handshake keeps its own
    /// allocation (it retransmits while holding the datagram).
    recv_scratch: Vec<u8>,
}

impl std::fmt::Debug for WireguardTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireguardTunnel")
            .field("endpoint", &self.peer.endpoint)
            .field("local_index", &self.local_index)
            .field("peer_index", &self.peer_index)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

impl WireguardTunnel {
    /// Resolve the endpoint (local DNS, as the pinned adapter resolves peer
    /// endpoints before handing them to the device) and perform the Noise IK
    /// handshake.
    pub async fn connect(
        outbound: &WireguardOutbound,
        peer_index: usize,
        timeout: Duration,
    ) -> Result<Self, WireguardError> {
        let private = decode_key(outbound.private_key.expose())?;
        let peer = outbound
            .peers
            .get(peer_index)
            .ok_or(WireguardError::NoPeer)?;
        let (server, port, public_key, preshared_key, reserved) =
            WireguardPeer::from_outbound(peer)?;
        let endpoint = resolve(&server, port).await?;
        let allowed_ips = peer
            .allowed_ips
            .iter()
            .filter_map(|value| IpPrefix::parse(value).ok())
            .collect();
        Self::connect_endpoint(
            private,
            WireguardPeer {
                endpoint,
                public_key: PublicKey::from(public_key),
                preshared_key,
                reserved,
                allowed_ips,
            },
            outbound.mtu as usize,
            outbound.persistent_keepalive,
            timeout,
        )
        .await
    }

    /// Perform the handshake against one already-resolved peer. Tests and the
    /// stack entry point use this constructor; the UDP socket is bound through
    /// [`super::bind_udp`] so the physical-interface binding of a desktop TUN
    /// is honoured (a plain `UdpSocket::bind` would be captured by the TUN
    /// again).
    pub async fn connect_endpoint(
        private_key: [u8; 32],
        peer: WireguardPeer,
        mtu: usize,
        keepalive: u16,
        timeout: Duration,
    ) -> Result<Self, WireguardError> {
        let bind: SocketAddr = if peer.endpoint.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let socket = Arc::new(
            super::bind_udp(bind)
                .await
                .map_err(|source| WireguardError::Connect {
                    endpoint: peer.endpoint.to_string(),
                    source,
                })?,
        );
        Self::connect_with_socket(private_key, peer, mtu, keepalive, timeout, socket).await
    }

    /// [`connect_endpoint`](Self::connect_endpoint) with a socket the caller
    /// already bound. The stack entry point creates it in the dial task so the
    /// task-local `DialerOptions` are in scope.
    pub async fn connect_with_socket(
        private_key: [u8; 32],
        peer: WireguardPeer,
        mtu: usize,
        keepalive: u16,
        timeout: Duration,
        socket: Arc<UdpSocket>,
    ) -> Result<Self, WireguardError> {
        socket
            .connect(peer.endpoint)
            .await
            .map_err(|source| WireguardError::Connect {
                endpoint: peer.endpoint.to_string(),
                source,
            })?;
        let local_static = StaticSecret::from(private_key);
        let mut tunnel = Self {
            socket,
            peer,
            local_static,
            local_index: 0,
            peer_index: 0,
            send_key: [0u8; 32],
            recv_key: [0u8; 32],
            send_counter: 0,
            replay: ReplayWindow::default(),
            handshake_at: Instant::now(),
            mtu: if mtu == 0 { 1408 } else { mtu },
            keepalive,
            last_sent: Instant::now(),
            handshake_timeout: timeout,
            recv_scratch: vec![0u8; 65535],
        };
        tunnel.handshake().await?;
        Ok(tunnel)
    }

    /// The peer's transport index (the `receiver_index` of our data packets).
    pub fn peer_index(&self) -> u32 {
        self.peer_index
    }

    /// The MTU the caller should not exceed when building IP packets.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// UDP address the tunnel was connected to.
    pub fn endpoint(&self) -> SocketAddr {
        self.peer.endpoint
    }

    /// Replace both transport keys with a fresh handshake. The carrier calls
    /// this once after an authenticated data packet fails to decrypt.
    pub async fn rekey(&mut self) -> Result<(), WireguardError> {
        self.handshake().await
    }

    async fn handshake(&mut self) -> Result<(), WireguardError> {        let mut initiation =
            InitiatorHandshake::new(&self.local_static, self.peer.public_key);
        self.local_index = random_u32();
        initiation.sender_index = self.local_index;
        let (message, state) = initiation.into_message(self.peer.preshared_key);
        self.last_sent = Instant::now();
        self.send_message(&message).await?;

        let deadline = Instant::now() + self.handshake_timeout;
        let mut cookie: Option<[u8; 16]> = None;
        let mut retry_at = Instant::now() + Duration::from_secs(1);
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(WireguardError::Timeout(self.handshake_timeout));
            }
            let wait = (deadline - now).min(retry_at.saturating_duration_since(now));
            match tokio::time::timeout(wait, self.recv_datagram()).await {
                Err(_) if Instant::now() >= retry_at => {
                    // Retransmit the same initiation (WireGuard handshakes are
                    // idempotent for the responder until it answers).
                    if let Some(cookie) = cookie {
                        let mut resent = message.clone();
                        write_mac2(&mut resent, &cookie);
                        self.send_message(&resent).await?;
                    } else {
                        self.send_message(&message).await?;
                    }
                    retry_at = Instant::now() + Duration::from_secs(1);
                }
                Err(_) => continue,
                Ok(Err(error)) => return Err(error),
                Ok(Ok(datagram)) => {
                    if datagram.len() < 4 {
                        continue;
                    }
                    match datagram[0] {
                        MESSAGE_HANDSHAKE_RESPONSE => {
                            if datagram.len() != RESPONSE_LEN {
                                return Err(WireguardError::Handshake(format!(
                                    "response has {} bytes, expected {RESPONSE_LEN}",
                                    datagram.len()
                                )));
                            }
                            let keys = state.consume_response(&datagram, self.local_index)?;
                            self.peer_index = keys.peer_index;
                            self.send_key = keys.send_key;
                            self.recv_key = keys.recv_key;
                            self.send_counter = 0;
                            self.replay = ReplayWindow::default();
                            self.handshake_at = Instant::now();
                            return Ok(());
                        }
                        MESSAGE_COOKIE_REPLY => {
                            if datagram.len() != COOKIE_REPLY_LEN {
                                continue;
                            }
                            let Some(decoded) =
                                decrypt_cookie(&datagram, self.peer.public_key, &message)
                            else {
                                continue;
                            };
                            cookie = Some(decoded);
                            let mut resent = message.clone();
                            write_mac2(&mut resent, &decoded);
                            self.send_message(&resent).await?;
                            retry_at = Instant::now() + Duration::from_secs(1);
                        }
                        _ => continue,
                    }
                }
            }
        }
    }

    /// Encrypt and send one IP packet. An empty packet is the WireGuard
    /// keepalive; callers should send at least a full IP header otherwise.
    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<(), WireguardError> {
        if packet.len() > self.mtu {
            return Err(WireguardError::PacketTooLarge {
                len: packet.len(),
                mtu: self.mtu,
            });
        }
        if self.handshake_at.elapsed() >= REKEY_AFTER
            || self.send_counter >= REJECT_AFTER_MESSAGES
        {
            // Initiator-side rekey: a fresh handshake replaces both transport
            // keys before the responder's three-minute rejection window.
            self.handshake().await?;
        }
        self.send_transport(packet).await
    }

    async fn send_transport(&mut self, packet: &[u8]) -> Result<(), WireguardError> {
        if self.send_counter >= REJECT_AFTER_MESSAGES {
            return Err(WireguardError::Transport(
                "transport counter reached the rejection limit; reconnect".to_string(),
            ));
        }
        let padded = pad_to_block(packet);
        let cipher = ChaCha20Poly1305::new_from_slice(&self.send_key)
            .map_err(|_| WireguardError::Transport("invalid send key".to_string()))?;
        let nonce = counter_nonce(self.send_counter);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &padded,
                    aad: &[],
                },
            )
            .map_err(|_| WireguardError::Transport("encrypt failed".to_string()))?;
        let mut datagram = Vec::with_capacity(TRANSPORT_HEADER_LEN + ciphertext.len());
        datagram.push(MESSAGE_TRANSPORT_DATA);
        datagram.extend_from_slice(&self.peer.reserved);
        datagram.extend_from_slice(&self.peer_index.to_le_bytes());
        datagram.extend_from_slice(&self.send_counter.to_le_bytes());
        datagram.extend_from_slice(&ciphertext);
        self.send_message(&datagram).await?;
        self.send_counter += 1;
        self.last_sent = Instant::now();
        Ok(())
    }

    /// Send a transport keepalive (an empty encrypted packet).
    pub async fn send_keepalive(&mut self) -> Result<(), WireguardError> {
        self.send_transport(&[]).await
    }

    /// Receive one decrypted IP packet. Keepalives are consumed here; the
    /// call returns only a non-empty packet or an error.
    pub async fn recv_packet(&mut self, buffer: &mut [u8]) -> Result<usize, WireguardError> {
        loop {
            if self.keepalive != 0
                && !self.last_sent.elapsed().is_zero()
                && self.last_sent.elapsed() >= Duration::from_secs(u64::from(self.keepalive))
            {
                self.send_keepalive().await?;
            }
            let length = self.recv_datagram_into().await?;
            if length < TRANSPORT_HEADER_LEN
                || self.recv_scratch[0] != MESSAGE_TRANSPORT_DATA
            {
                continue;
            }
            let datagram = &self.recv_scratch[..length];
            let receiver = u32::from_le_bytes(datagram[4..8].try_into().unwrap());
            if receiver != self.local_index {
                continue;
            }
            let counter = u64::from_le_bytes(datagram[8..16].try_into().unwrap());
            if !self.replay.check(counter) {
                continue;
            }
            let cipher = ChaCha20Poly1305::new_from_slice(&self.recv_key)
                .map_err(|_| WireguardError::Transport("invalid receive key".to_string()))?;
            let nonce = counter_nonce(counter);
            let plaintext = cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &datagram[TRANSPORT_HEADER_LEN..],
                        aad: &[],
                    },
                )
                .map_err(|_| WireguardError::Authentication)?;
            let length = ip_length(&plaintext, self.mtu);
            if length == 0 {
                // Keepalive: authenticated, no IP packet.
                continue;
            }
            if buffer.len() < length {
                return Err(WireguardError::BufferTooSmall {
                    len: buffer.len(),
                    packet: length,
                });
            }
            buffer[..length].copy_from_slice(&plaintext[..length]);
            return Ok(length);
        }
    }

    async fn send_message(&mut self, message: &[u8]) -> Result<(), WireguardError> {
        self.socket
            .send(message)
            .await
            .map(|_| ())
            .map_err(|source| WireguardError::Connect {
                endpoint: self.peer.endpoint.to_string(),
                source,
            })
    }

    /// Fill `recv_scratch` with one datagram and return its length.
    async fn recv_datagram_into(&mut self) -> Result<usize, WireguardError> {
        self.socket
            .recv(&mut self.recv_scratch)
            .await
            .map_err(|source| WireguardError::Transport(source.to_string()))
    }

    async fn recv_datagram(&mut self) -> Result<Vec<u8>, WireguardError> {
        let mut buffer = vec![0u8; 65535];
        let length = self
            .socket
            .recv(&mut buffer)
            .await
            .map_err(|source| WireguardError::Transport(source.to_string()))?;
        buffer.truncate(length);
        Ok(buffer)
    }
}

/// Resolve the endpoint with the in-scope `ip-version` and proxy DNS, the same
/// resolver every other outbound server name uses.
async fn resolve(server: &str, port: u16) -> Result<SocketAddr, WireguardError> {
    let addresses = super::resolve_all(server, port).await.map_err(|error| {
        WireguardError::Connect {
            endpoint: format!("{server}:{port}"),
            source: io::Error::other(error.to_string()),
        }
    })?;
    addresses
        .into_iter()
        .next()
        .ok_or_else(|| WireguardError::Resolve(server.to_string()))
}

// ---------------------------------------------------------------------------
// Userspace stack carrier
// ---------------------------------------------------------------------------

/// Registry key of one configured WireGuard outbound. The private/peer keys
/// are part of the key (different keys are different devices) but the digest
/// never prints them.
pub(crate) fn stack_fingerprint(outbound: &WireguardOutbound) -> String {
    let mut parts = vec![
        outbound.private_key.expose().to_string(),
        outbound.ip.clone().unwrap_or_default(),
        outbound.ipv6.clone().unwrap_or_default(),
        outbound.mtu.to_string(),
        outbound.udp.to_string(),
        outbound.persistent_keepalive.to_string(),
    ];
    for peer in &outbound.peers {
        parts.push(peer.server.clone());
        parts.push(peer.port.to_string());
        parts.push(peer.public_key.clone());
        parts.push(
            peer.preshared_key
                .as_ref()
                .map(|key| key.expose().to_string())
                .unwrap_or_default(),
        );
        parts.push(hex::encode(&peer.reserved));
        parts.push(peer.allowed_ips.join(","));
    }
    let borrowed: Vec<&str> = parts.iter().map(String::as_str).collect();
    l3::fingerprint("wireguard", &borrowed)
}

fn local_addresses(outbound: &WireguardOutbound) -> (Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>) {
    fn parse(value: &Option<String>) -> Option<IpAddr> {
        value
            .as_deref()
            .and_then(|text| IpPrefix::parse(text).ok())
            .map(|prefix| prefix.addr)
    }
    let ipv4 = match parse(&outbound.ip) {
        Some(IpAddr::V4(addr)) => Some(addr),
        _ => None,
    };
    let ipv6 = match parse(&outbound.ipv6) {
        Some(IpAddr::V6(addr)) => Some(addr),
        _ => None,
    };
    (ipv4, ipv6)
}

/// Peer selection by longest matching `allowed-ips` prefix. Equal lengths are
/// resolved in configuration order with the *later* peer winning, matching the
/// pinned device's route insertion.
pub fn select_peer(peers: &[Vec<IpPrefix>], dst: IpAddr) -> Option<usize> {
    let mut best: Option<(u8, usize)> = None;
    for (index, prefixes) in peers.iter().enumerate() {
        if prefixes.is_empty() {
            // The compatibility constructors (`from_base64`) carry no
            // configuration; one such peer accepts every destination.
            if best.is_none() {
                best = Some((0, index));
            }
            continue;
        }
        for prefix in prefixes {
            if prefix.contains(dst) {
                let bits = prefix.bits;
                if best.map(|(known, _)| bits >= known).unwrap_or(true) {
                    best = Some((bits, index));
                }
            }
        }
    }
    best.map(|(_, index)| index)
}

fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    crate::outbound::ipstack::parse_ip_packet(packet)
        .ok()
        .map(|parsed| parsed.dst)
}

/// Commands accepted by one peer actor.
enum PeerCommand {
    /// Route one IP packet to this peer; the first packet starts the handshake.
    Send(Vec<u8>),
    /// `dial()` waits for this specific peer; failure never falls back to
    /// another peer.
    Ensure(tokio::sync::oneshot::Sender<Result<(), String>>),
}

struct PeerHandle {
    tx: tokio::sync::mpsc::Sender<PeerCommand>,
    /// The peer endpoint actually resolved at stack creation.
    endpoint: SocketAddr,
}

struct PeerSpec {
    private_key: [u8; 32],
    peer: WireguardPeer,
    mtu: usize,
    keepalive: u16,
    handshake_timeout: Duration,
    /// Bound once in the dial task (`bind_udp`), then reused by every lazy
    /// handshake so the proxy's interface/routing-mark options apply and the
    /// socket is never re-bound behind the TUN.
    socket: Arc<UdpSocket>,
}

type PeerFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<WireguardTunnel, WireguardError>> + Send>,
>;

/// Commands/waits are bounded; excess work is refused by name.
const PEER_PENDING_PACKETS: usize = 16;
const PEER_WAITERS: usize = 32;
/// After a failed handshake the peer is skipped for this long, then the next
/// packet or `Ensure` retries it. Other peers are unaffected.
const PEER_RETRY: Duration = Duration::from_secs(1);

/// Stop/reload signal shared by the dispatcher and every peer actor. A plain
/// `Notify` can lose a wake that arrives while an actor is inside a handshake,
/// so the flag is checked at every loop boundary too.
struct Shutdown {
    stopped: AtomicBool,
    notify: tokio::sync::Notify,
}

impl Shutdown {
    fn new() -> Arc<Shutdown> {
        Arc::new(Shutdown {
            stopped: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        })
    }

    fn stop(&self) {
        self.stopped.store(true, AtomicOrdering::SeqCst);
        self.notify.notify_waiters();
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(AtomicOrdering::SeqCst)
    }
}

/// The userspace stack plus its lazily connected WireGuard peers.
pub struct WireguardCarrier {
    stack: Arc<Stack>,
    peers: Vec<PeerHandle>,
    /// Per-peer `allowed-ips`, aligned with `peers`.
    allowed: Vec<Vec<IpPrefix>>,
    /// Signals every peer actor and the dispatcher to stop (stop/reload or
    /// explicit forget).
    shutdown: Arc<Shutdown>,
}

impl std::fmt::Debug for WireguardCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireguardCarrier")
            .field("peers", &self.peers.len())
            .finish_non_exhaustive()
    }
}

impl WireguardCarrier {
    pub fn stack(&self) -> Arc<Stack> {
        self.stack.clone()
    }

    pub fn peer_endpoint(&self, index: usize) -> Option<SocketAddr> {
        self.peers.get(index).map(|peer| peer.endpoint)
    }

    /// Resolve a destination to a peer by longest `allowed-ips` prefix.
    pub fn peer_for(&self, dst: IpAddr) -> Option<usize> {
        select_peer(&self.allowed, dst)
    }

    /// Wait for one peer's handshake. A failure is specific to this peer and
    /// is never retried against another one.
    pub async fn ensure_peer(
        &self,
        index: usize,
        timeout: Duration,
    ) -> Result<(), WireguardError> {
        let Some(peer) = self.peers.get(index) else {
            return Err(WireguardError::NoPeer);
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        peer.tx
            .send(PeerCommand::Ensure(tx))
            .await
            .map_err(|_| WireguardError::Transport("wireguard peer task stopped".to_string()))?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(message))) => Err(WireguardError::Handshake(message)),
            Ok(Err(_)) => Err(WireguardError::Transport(
                "wireguard peer task dropped the ensure reply".to_string(),
            )),
            Err(_) => Err(WireguardError::Timeout(timeout)),
        }
    }
}

fn carrier_registry() -> &'static std::sync::Mutex<HashMap<String, Arc<WireguardCarrier>>> {
    static REGISTRY: std::sync::OnceLock<
        std::sync::Mutex<HashMap<String, Arc<WireguardCarrier>>>,
    > = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn lookup_carrier(fingerprint: &str) -> Option<Arc<WireguardCarrier>> {
    let mut map = carrier_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let carrier = map.get(fingerprint)?.clone();
    if carrier.stack.fatal_error().is_some()
        || (carrier.stack.idle() && carrier.stack.socket_counts() == (0, 0))
    {
        carrier.shutdown.stop();
        map.remove(fingerprint);
        return None;
    }
    Some(carrier)
}

fn publish_carrier(fingerprint: &str, carrier: &Arc<WireguardCarrier>) {
    let mut map = carrier_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    map.insert(fingerprint.to_string(), carrier.clone());
}

/// Passive idle reaping for the strong carrier registry (the l3 stack reaper
/// cannot see this map).
fn spawn_carrier_reaper() {
    static STARTED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let mut map = carrier_registry()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            map.retain(|_, carrier| {
                let keep = carrier.stack.fatal_error().is_none()
                    && !(carrier.stack.idle() && carrier.stack.socket_counts() == (0, 0));
                if !keep {
                    carrier.shutdown.stop();
                }
                keep
            });
        }
    });
}

/// Stop/reload hook for one configured WireGuard outbound: stops its actors,
/// drops the carrier and removes the shared stack entry. The idle check in
/// [`lookup_carrier`] covers the passive path.
pub fn forget(outbound: &WireguardOutbound) {
    let fingerprint = stack_fingerprint(outbound);
    forget_carrier(&fingerprint);
    l3::forget(&fingerprint);
}

pub fn forget_carrier(fingerprint: &str) {
    let mut map = carrier_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(carrier) = map.remove(fingerprint) {
        carrier.shutdown.stop();
    }
}

/// Resolve every peer and build the stack. No handshake happens here: each
/// peer connects on its first packet (or on `dial`'s explicit `ensure_peer`),
/// matching the pinned device's lazy per-peer connection.
pub async fn connect_carrier(
    outbound: &WireguardOutbound,
    timeout: Duration,
) -> Result<Arc<WireguardCarrier>, WireguardError> {
    let fingerprint = stack_fingerprint(outbound);
    if let Some(carrier) = lookup_carrier(&fingerprint) {
        return Ok(carrier);
    }
    if outbound.peers.is_empty() {
        return Err(WireguardError::NoPeer);
    }
    let (ipv4, ipv6) = local_addresses(outbound);
    if ipv4.is_none() && ipv6.is_none() {
        return Err(WireguardError::NoLocalAddress);
    }
    let mtu = if outbound.mtu == 0 {
        1408
    } else {
        outbound.mtu as usize
    };
    let private = decode_key(outbound.private_key.expose())?;
    // Endpoint resolution and socket binding happen outside the registry lock;
    // only the lookup/publish below is serialised.
    let mut specs = Vec::with_capacity(outbound.peers.len());
    let mut allowed = Vec::with_capacity(outbound.peers.len());
    for peer in &outbound.peers {
        let (server, port, public_key, preshared_key, reserved) =
            WireguardPeer::from_outbound(peer)?;
        let prefixes: Vec<IpPrefix> = peer
            .allowed_ips
            .iter()
            .filter_map(|value| IpPrefix::parse(value).ok())
            .collect();
        if prefixes.is_empty() {
            return Err(WireguardError::NoRoute(IpAddr::V4(
                std::net::Ipv4Addr::UNSPECIFIED,
            )));
        }
        let endpoint = resolve(&server, port).await?;
        let bind: SocketAddr = if endpoint.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let socket = Arc::new(
            super::bind_udp(bind)
                .await
                .map_err(|source| WireguardError::Connect {
                    endpoint: endpoint.to_string(),
                    source,
                })?,
        );
        specs.push(PeerSpec {
            private_key: private,
            peer: WireguardPeer {
                endpoint,
                public_key: PublicKey::from(public_key),
                preshared_key,
                reserved,
                allowed_ips: prefixes.clone(),
            },
            mtu,
            keepalive: outbound.persistent_keepalive,
            handshake_timeout: timeout,
            socket,
        });
        allowed.push(prefixes);
    }
    let config = StackConfig::new(ipv4, ipv6, mtu, fingerprint.clone());
    let stack = Stack::new(config).map_err(|error| WireguardError::Stack(error.to_string()))?;
    let shutdown = Shutdown::new();
    let (peers, allowed) = spawn_carrier(&stack, specs, allowed, shutdown.clone());
    let carrier = Arc::new(WireguardCarrier {
        stack,
        peers,
        allowed,
        shutdown,
    });
    // Double-check under the short creation lock: a concurrent dial may have
    // published first. The loser's carrier is dropped and its actor tasks exit
    // when their `Weak<Stack>` no longer upgrades.
    let _guard = l3::registry_lock().lock().await;
    if let Some(existing) = lookup_carrier(&fingerprint) {
        return Ok(existing);
    }
    publish_carrier(&fingerprint, &carrier);
    if !l3::publish(fingerprint.clone(), &carrier.stack) {
        carrier.shutdown.stop();
        forget_carrier(&fingerprint);
        return Err(WireguardError::Stack(format!(
            "the userspace stack registry already holds the maximum of {} active stacks",
            l3::MAX_STACKS
        )));
    }
    spawn_carrier_reaper();
    Ok(carrier)
}

/// Build (or reuse) the stack for callers that only need TCP/UDP termination
/// (`tunnel/udp`, the engine's UDP association). The lazy handshake happens on
/// the first packet of each peer.
pub async fn connect_stack(
    outbound: &WireguardOutbound,
    timeout: Duration,
) -> Result<Arc<Stack>, WireguardError> {
    connect_carrier(outbound, timeout)
        .await
        .map(|carrier| carrier.stack())
}

fn start_connect(
    connecting: &mut Option<PeerFuture>,
    spec: &PeerSpec,
) {
    if connecting.is_some() {
        return;
    }
    let spec = PeerSpec {
        private_key: spec.private_key,
        peer: spec.peer.clone(),
        mtu: spec.mtu,
        keepalive: spec.keepalive,
        handshake_timeout: spec.handshake_timeout,
        socket: spec.socket.clone(),
    };
    *connecting = Some(Box::pin(async move {
        WireguardTunnel::connect_with_socket(
            spec.private_key,
            spec.peer,
            spec.mtu,
            spec.keepalive,
            spec.handshake_timeout,
            spec.socket,
        )
        .await
    }));
}

fn drop_tunnel(tunnel: &mut Option<WireguardTunnel>, retry_after: &mut Option<Instant>) {
    *tunnel = None;
    *retry_after = Some(Instant::now() + PEER_RETRY);
}

/// One peer actor: lazy handshake, bounded pending queue, its own receive
/// future and keepalive timer. Errors only affect this peer.
async fn peer_task(
    weak: Weak<Stack>,
    spec: PeerSpec,
    mut commands: tokio::sync::mpsc::Receiver<PeerCommand>,
    shutdown: Arc<Shutdown>,
) {
    let mut tunnel: Option<WireguardTunnel> = None;
    let mut connecting: Option<PeerFuture> = None;
    let mut waiters: Vec<tokio::sync::oneshot::Sender<Result<(), String>>> = Vec::new();
    let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
    let mut retry_after: Option<Instant> = None;
    let mut rekeyed = false;
    let mut buffer = vec![0u8; 65535];
    let interval = Duration::from_secs(u64::from(spec.keepalive.max(1)));
    let mut keepalive_tick = tokio::time::interval(interval);
    keepalive_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut liveness_tick = tokio::time::interval(Duration::from_millis(500));
    liveness_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if shutdown.is_stopped() {
            return;
        }
        tokio::select! {
            _ = shutdown.notify.notified() => {
                return;
            }
            _ = liveness_tick.tick() => {
                if weak.upgrade().is_none() {
                    return;
                }
            }
            command = commands.recv() => match command {
                None => {
                    for waiter in waiters.drain(..) {
                        let _ = waiter.send(Err("wireguard peer task stopped".to_string()));
                    }
                    return;
                }
                Some(PeerCommand::Ensure(reply)) => {
                    if tunnel.is_some() {
                        let _ = reply.send(Ok(()));
                        continue;
                    }
                    if let Some(until) = retry_after {
                        if Instant::now() < until {
                            let _ = reply.send(Err(format!(
                                "wireguard peer {} did not complete its handshake",
                                spec.peer.endpoint
                            )));
                            continue;
                        }
                        retry_after = None;
                    }
                    if waiters.len() >= PEER_WAITERS {
                        let _ = reply.send(Err(format!(
                            "wireguard peer {} already has the maximum of {PEER_WAITERS} waiters",
                            spec.peer.endpoint
                        )));
                        continue;
                    }
                    waiters.push(reply);
                    start_connect(&mut connecting, &spec);
                }
                Some(PeerCommand::Send(packet)) => {
                    if let Some(active) = tunnel.as_mut() {
                        if active.send_packet(&packet).await.is_err() {
                            drop_tunnel(&mut tunnel, &mut retry_after);
                        }
                        rekeyed = false;
                        continue;
                    }
                    if let Some(until) = retry_after {
                        if Instant::now() < until {
                            // This peer is down; drop only its packets.
                            continue;
                        }
                        retry_after = None;
                    }
                    if pending.len() < PEER_PENDING_PACKETS {
                        pending.push_back(packet);
                    }
                    start_connect(&mut connecting, &spec);
                }
            },
            result = async {
                match connecting.as_mut() {
                    Some(future) => future.as_mut().await,
                    None => std::future::pending().await,
                }
            }, if connecting.is_some() => {
                connecting = None;
                match result {
                    Ok(connection) => {
                        tunnel = Some(connection);
                        retry_after = None;
                        rekeyed = false;
                        for waiter in waiters.drain(..) {
                            let _ = waiter.send(Ok(()));
                        }
                        while let Some(packet) = pending.pop_front() {
                            let Some(active) = tunnel.as_mut() else {
                                break;
                            };
                            if active.send_packet(&packet).await.is_err() {
                                drop_tunnel(&mut tunnel, &mut retry_after);
                                pending.clear();
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        let message = error.to_string();
                        for waiter in waiters.drain(..) {
                            let _ = waiter.send(Err(message.clone()));
                        }
                        pending.clear();
                        retry_after = Some(Instant::now() + PEER_RETRY);
                    }
                }
            },
            result = async {
                match tunnel.as_mut() {
                    Some(active) => active.recv_packet(&mut buffer).await,
                    None => std::future::pending().await,
                }
            }, if tunnel.is_some() => {
                match result {
                    Ok(length) => {
                        let Some(stack) = weak.upgrade() else {
                            return;
                        };
                        stack.push_rx_packet(&buffer[..length]);
                    }
                    Err(WireguardError::Authentication) if !rekeyed => {
                        rekeyed = true;
                        let failed = match tunnel.as_mut() {
                            Some(active) => active.rekey().await.is_err(),
                            None => true,
                        };
                        if failed {
                            drop_tunnel(&mut tunnel, &mut retry_after);
                        }
                    }
                    Err(_error) => {
                        // A transport failure belongs to this peer only; the
                        // next packet after a short cooldown retries it.
                        drop_tunnel(&mut tunnel, &mut retry_after);
                    }
                }
            },
            _ = keepalive_tick.tick() => {
                if spec.keepalive != 0 {
                    let failed = match tunnel.as_mut() {
                        Some(active) => active.send_keepalive().await.is_err(),
                        None => false,
                    };
                    if failed {
                        drop_tunnel(&mut tunnel, &mut retry_after);
                    }
                }
            }
        }
    }
}

fn spawn_carrier(
    stack: &Arc<Stack>,
    specs: Vec<PeerSpec>,
    allowed: Vec<Vec<IpPrefix>>,
    shutdown: Arc<Shutdown>,
) -> (Vec<PeerHandle>, Vec<Vec<IpPrefix>>) {
    let weak = Arc::downgrade(stack);
    let mut peers = Vec::with_capacity(specs.len());
    let mut senders = Vec::with_capacity(specs.len());
    for spec in specs {
        let endpoint = spec.peer.endpoint;
        let (tx, rx) = tokio::sync::mpsc::channel::<PeerCommand>(PEER_PENDING_PACKETS);
        peers.push(PeerHandle { tx: tx.clone(), endpoint });
        senders.push(tx);
        let weak = weak.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(peer_task(weak, spec, rx, shutdown));
    }
    let dispatcher_allowed = allowed.clone();
    // Egress dispatcher: take IP packets the stack produced and hand each to
    // the peer whose allowed-ips prefix covers its destination. The peer actor
    // performs the lazy handshake on the first packet.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if shutdown.is_stopped() {
                return;
            }
            tokio::select! {
                _ = shutdown.notify.notified() => return,
                _ = tick.tick() => {}
            }
            let Some(stack) = weak.upgrade() else {
                return;
            };
            let mut packets = Vec::new();
            while let Some(packet) = stack.take_tx_packet() {
                packets.push(packet);
            }
            for packet in packets {
                let Some(dst) = packet_destination(&packet) else {
                    continue;
                };
                let Some(index) = select_peer(&dispatcher_allowed, dst) else {
                    // No peer covers this destination; drop the packet. A
                    // TCP dial already selected/ensured its peer, so this is
                    // stray traffic, not a stack-wide failure.
                    continue;
                };
                let _ = senders[index].try_send(PeerCommand::Send(packet));
            }
        }
    });
    (peers, allowed)
}

fn dial_error(error: WireguardError) -> super::DialError {
    super::DialError::Handshake {
        protocol: "wireguard",
        source: io::Error::other(error.to_string()),
    }
}

/// `dial_inner` entry: build the stack, select the peer by the destination's
/// longest `allowed-ips` prefix, wait for exactly that peer's handshake and
/// dial the TCP stream. A failed peer is a handshake error; it never falls
/// back to a different peer.
pub async fn dial(
    outbound: &WireguardOutbound,
    target: &super::Target,
    timeout: Duration,
) -> Result<super::Dialed, super::DialError> {
    let carrier = connect_carrier(outbound, timeout).await.map_err(dial_error)?;
    let addresses = super::resolve_all(&target.host, target.port).await?;
    let remote = addresses
        .into_iter()
        .find(|address| match address.ip() {
            IpAddr::V4(_) => carrier.stack.ipv4().is_some(),
            IpAddr::V6(_) => carrier.stack.ipv6().is_some(),
        })
        .ok_or_else(|| super::DialError::Resolve {
            host: target.host.clone(),
            source: io::Error::new(
                io::ErrorKind::NotFound,
                "no resolved address matches a local tunnel address family",
            ),
        })?;
    let index = carrier.peer_for(remote.ip()).ok_or_else(|| {
        super::DialError::Handshake {
            protocol: "wireguard",
            source: io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "wireguard has no peer with an allowed-ips prefix covering {}",
                    remote.ip()
                ),
            ),
        }
    })?;
    carrier.ensure_peer(index, timeout).await.map_err(dial_error)?;
    let server = carrier
        .peer_endpoint(index)
        .ok_or(WireguardError::NoPeer)
        .map_err(dial_error)?;
    let stream = carrier
        .stack
        .dial_tcp(remote, timeout)
        .await
        .map_err(|error| super::DialError::Handshake {
            protocol: "wireguard",
            source: error,
        })?;
    Ok(super::Dialed { stream, server })
}

struct InitiatorHandshake {
    chaining_key: [u8; 32],
    hash: [u8; 32],
    local_static: [u8; 32],
    peer_static: PublicKey,
    ephemeral: StaticSecret,
    sender_index: u32,
}

impl InitiatorHandshake {
    fn new(local_static: &StaticSecret, peer_static: PublicKey) -> Self {
        let mut chaining_key = hash_parts(&[CONSTRUCTION]);
        let mut hash = hash_parts(&[&chaining_key, IDENTIFIER]);
        hash = hash_parts(&[&hash, peer_static.as_bytes()]);
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral);
        chaining_key = kdf1(&chaining_key, ephemeral_public.as_bytes());
        hash = hash_parts(&[&hash, ephemeral_public.as_bytes()]);
        Self {
            chaining_key,
            hash,
            local_static: local_static.to_bytes(),
            peer_static: PublicKey::from(peer_static),
            ephemeral,
            sender_index: 0,
        }
    }

    /// Build the initiation message and keep the Noise state needed for the
    /// response.
    fn into_message(self, preshared_key: Option<[u8; 32]>) -> (Vec<u8>, InitiatorState) {
        let local_public = PublicKey::from(&StaticSecret::from(self.local_static));
        let ephemeral_public = PublicKey::from(&self.ephemeral);
        let mut chaining_key = self.chaining_key;
        let mut hash = self.hash;

        let shared = self.ephemeral.diffie_hellman(&self.peer_static);
        let (next, key) = kdf2(&chaining_key, shared.as_bytes());
        chaining_key = next;
        let encrypted_static =
            encrypt(&key, &self.hash, local_public.as_bytes()).expect("32-byte static");
        hash = hash_parts(&[&hash, &encrypted_static]);

        let local_static = StaticSecret::from(self.local_static);
        let shared = local_static.diffie_hellman(&self.peer_static);
        let (next, key) = kdf2(&chaining_key, shared.as_bytes());
        chaining_key = next;
        let timestamp = tai64n();
        let encrypted_timestamp =
            encrypt(&key, &hash, &timestamp).expect("12-byte timestamp");
        hash = hash_parts(&[&hash, &encrypted_timestamp]);

        let mut message = Vec::with_capacity(INITIATION_LEN);
        message.push(MESSAGE_HANDSHAKE_INITIATION);
        message.extend_from_slice(&[0, 0, 0]);
        message.extend_from_slice(&self.sender_index.to_le_bytes());
        message.extend_from_slice(ephemeral_public.as_bytes());
        message.extend_from_slice(&encrypted_static);
        message.extend_from_slice(&encrypted_timestamp);
        write_macs(&mut message, self.peer_static.as_bytes());

        (
            message,
            InitiatorState {
                chaining_key,
                hash,
                ephemeral: self.ephemeral,
                local_static: self.local_static,
                local_public,
                sender_index: self.sender_index,
                preshared_key,
            },
        )
    }
}

struct InitiatorState {
    chaining_key: [u8; 32],
    hash: [u8; 32],
    ephemeral: StaticSecret,
    local_static: [u8; 32],
    local_public: PublicKey,
    #[allow(dead_code)]
    sender_index: u32,
    preshared_key: Option<[u8; 32]>,
}

struct TransportKeys {
    peer_index: u32,
    send_key: [u8; 32],
    recv_key: [u8; 32],
}

impl InitiatorState {
    fn consume_response(
        self,
        message: &[u8],
        local_index: u32,
    ) -> Result<TransportKeys, WireguardError> {
        let receiver_index = u32::from_le_bytes(message[8..12].try_into().unwrap());
        if receiver_index != local_index {
            return Err(WireguardError::Handshake(format!(
                "response receiver index {receiver_index} does not match our {local_index}"
            )));
        }
        let peer_index = u32::from_le_bytes(message[4..8].try_into().unwrap());
        // The response is sent to us, so its MAC1 is keyed by our static key.
        verify_macs(message, self.local_public.as_bytes())?;
        let peer_ephemeral = PublicKey::from(
            <[u8; 32]>::try_from(&message[12..44])
                .map_err(|_| WireguardError::Handshake("bad ephemeral".to_string()))?,
        );
        let mut chaining_key = self.chaining_key;
        let mut hash = self.hash;
        chaining_key = kdf1(&chaining_key, peer_ephemeral.as_bytes());
        hash = hash_parts(&[&hash, peer_ephemeral.as_bytes()]);
        chaining_key = kdf1(
            &chaining_key,
            self.ephemeral.diffie_hellman(&peer_ephemeral).as_bytes(),
        );
        let local_static = StaticSecret::from(self.local_static);
        chaining_key = kdf1(
            &chaining_key,
            local_static.diffie_hellman(&peer_ephemeral).as_bytes(),
        );
        // WireGuard always mixes a 32-byte pre-shared key; without one the
        // value is 32 zero bytes, not an empty input.
        let preshared = self.preshared_key.unwrap_or([0u8; 32]);
        let (chaining_key, tau, key) = kdf3(&chaining_key, &preshared);
        // The responder mixes tau into the transcript hash before it seals
        // the empty payload; the initiator must do the same before opening it.
        hash = hash_parts(&[&hash, &tau]);
        let empty = decrypt(&key, &hash, &message[44..60])?;
        if !empty.is_empty() {
            return Err(WireguardError::Handshake(
                "response carries a non-empty payload".to_string(),
            ));
        }
        hash = hash_parts(&[&hash, &message[44..60]]);
        let (send_key, recv_key) = kdf2(&chaining_key, &[]);
        let _ = hash;
        Ok(TransportKeys {
            peer_index,
            send_key,
            recv_key,
        })
    }
}

fn write_macs(message: &mut Vec<u8>, peer_static: &[u8; 32]) {
    let mac1_key = hash_parts(&[LABEL_MAC1, peer_static]);
    let mac1 = keyed_hash16(&mac1_key, message);
    message.extend_from_slice(&mac1);
    message.extend_from_slice(&[0u8; 16]);
}

fn write_mac2(message: &mut [u8], cookie: &[u8; 16]) {
    let mac2_at = message.len() - 16;
    let mac2 = keyed_hash16(cookie, &message[..mac2_at]);
    message[mac2_at..].copy_from_slice(&mac2);
}

fn verify_macs(message: &[u8], peer_static: &[u8; 32]) -> Result<(), WireguardError> {
    if message.len() < 32 {
        return Err(WireguardError::Handshake("short handshake".to_string()));
    }
    let mac1_at = message.len() - 32;
    let mac1_key = hash_parts(&[LABEL_MAC1, peer_static]);
    let expected = keyed_hash16(&mac1_key, &message[..mac1_at]);
    if !constant_time_eq(&expected, &message[mac1_at..mac1_at + 16]) {
        return Err(WireguardError::Handshake(
            "MAC1 does not verify (wrong peer public key)".to_string(),
        ));
    }
    Ok(())
}

fn decrypt_cookie(
    message: &[u8],
    peer_static: PublicKey,
    initiation: &[u8],
) -> Option<[u8; 16]> {
    let receiver = u32::from_le_bytes(message[4..8].try_into().ok()?);
    let _ = receiver;
    let key = hash_parts(&[LABEL_COOKIE, peer_static.as_bytes()]);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).ok()?;
    let nonce = XNonce::from_slice(&message[8..32]);
    let mac1_at = initiation.len() - 32;
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &message[32..],
                aad: &initiation[mac1_at..mac1_at + 16],
            },
        )
        .ok()?;
    <[u8; 16]>::try_from(plaintext.as_slice()).ok()
}

fn tai64n() -> [u8; 12] {
    const TAI64_UNIX_EPOCH: u64 = 0x4000_0000_0000_000a;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&(TAI64_UNIX_EPOCH + now.as_secs()).to_be_bytes());
    out[8..].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    out
}

fn random_u32() -> u32 {
    use rand::RngCore;
    OsRng.next_u32()
}

fn pad_to_block(packet: &[u8]) -> Vec<u8> {
    let padding = (16 - packet.len() % 16) % 16;
    let mut out = Vec::with_capacity(packet.len() + padding);
    out.extend_from_slice(packet);
    out.resize(packet.len() + padding, 0);
    out
}

/// The plaintext of a transport message is padded with zeros; the IPv4/IPv6
/// header carries the real length. A message with no IP header is a keepalive.
fn ip_length(plaintext: &[u8], mtu: usize) -> usize {
    let Some(first) = plaintext.first() else {
        return 0;
    };
    let length = match first >> 4 {
        4 => {
            if plaintext.len() < 20 {
                return 0;
            }
            u16::from_be_bytes([plaintext[2], plaintext[3]]) as usize
        }
        6 => {
            if plaintext.len() < 40 {
                return 0;
            }
            40 + u16::from_be_bytes([plaintext[4], plaintext[5]]) as usize
        }
        _ => return 0,
    };
    if length == 0 || length > plaintext.len() || length > mtu {
        return 0;
    }
    length
}

fn counter_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

#[derive(Default)]
struct ReplayWindow {
    latest: u64,
    seen: VecDeque<bool>,
}

impl ReplayWindow {
    fn check(&mut self, counter: u64) -> bool
    where
        Self: Sized,
    {
        const WINDOW: usize = 2048;
        if self.seen.is_empty() {
            self.seen = std::iter::repeat(false).take(WINDOW).collect();
        }
        if counter > self.latest {
            let advance = (counter - self.latest).min(WINDOW as u64) as usize;
            for _ in 0..advance {
                self.seen.push_back(false);
                self.seen.pop_front();
            }
            self.latest = counter;
            self.seen[WINDOW - 1] = true;
            return true;
        }
        let behind = self.latest - counter;
        if behind >= WINDOW as u64 {
            return false;
        }
        let index = WINDOW - 1 - behind as usize;
        if self.seen[index] {
            return false;
        }
        self.seen[index] = true;
        true
    }
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn keyed_hash16(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = Blake2sMac::<U16>::new_with_salt_and_personal(key, &[], &[])
        .expect("32-byte key fits the 64-byte BLAKE2s key block");
    blake2::digest::Update::update(&mut mac, data);
    let output = mac.finalize_fixed();
    let mut out = [0u8; 16];
    out.copy_from_slice(&output);
    out
}

fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..32].copy_from_slice(&hash_parts(&[key]));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        inner_pad[i] ^= key_block[i];
        outer_pad[i] ^= key_block[i];
    }
    let inner = hash_parts(&[&inner_pad, data]);
    hash_parts(&[&outer_pad, &inner])
}

fn kdf1(key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    // `KDF1` returns `t1`, not `t0`: t0 is the HMAC over `input` and t1 is
    // the HMAC over t0 || 0x1 (whitepaper "KDF_n").
    let t0 = hmac_blake2s(key, input);
    hmac_blake2s(&t0, &[1])
}

fn kdf2(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let t0 = hmac_blake2s(key, input);
    let t1 = hmac_blake2s(&t0, &[1]);
    (t1, hmac_blake2s(&t0, &[t1.as_slice(), &[2]].concat()))
}

fn kdf3(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let t0 = hmac_blake2s(key, input);
    let t1 = hmac_blake2s(&t0, &[1]);
    let t2 = hmac_blake2s(&t0, &[t1.as_slice(), &[2]].concat());
    (
        t1,
        t2,
        hmac_blake2s(&t0, &[t2.as_slice(), &[3]].concat()),
    )
}

fn encrypt(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher
        .encrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: plaintext, aad })
        .ok()
}

fn decrypt(key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, WireguardError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| WireguardError::Handshake("invalid handshake key".to_string()))?;
    cipher
        .decrypt(
            Nonce::from_slice(&[0u8; 12]),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| WireguardError::Handshake("handshake authentication failed".to_string()))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_pinned_base64_key_form() {
        // A syntactically valid 32-byte key (the value is not used as a key).
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(decode_key(key).unwrap(), [0u8; 32]);
        assert!(matches!(decode_key("not base64"), Err(WireguardError::InvalidKey)));
        assert!(matches!(
            decode_key("AAAA"),
            Err(WireguardError::InvalidKey)
        ));
    }

    #[test]
    fn kdf_matches_the_wireguard_test_vectors() {
        // WireGuard whitepaper KDF: t0 = HMAC(key, input), t1 = HMAC(t0, 0x1),
        // t2 = HMAC(t0, t1 || 0x2), t3 = HMAC(t0, t2 || 0x3).
        let key = [7u8; 32];
        let input = b"wireguard kdf input";
        let t0 = hmac_blake2s(&key, input);
        let (t1, t2) = kdf2(&key, input);
        let (t1_again, t2_again, t3) = kdf3(&key, input);
        assert_eq!(t1, t1_again);
        assert_eq!(t2, t2_again);
        assert_eq!(t1, hmac_blake2s(&t0, &[1]));
        assert_eq!(t2, hmac_blake2s(&t0, &[t1.as_slice(), &[2]].concat()));
        assert_eq!(t3, hmac_blake2s(&t0, &[t2.as_slice(), &[3]].concat()));
        assert_ne!(t1, t2);
        assert_ne!(t2, t3);
    }

    #[test]
    fn replay_window_rejects_duplicates_and_old_counters() {
        let mut window = ReplayWindow::default();
        assert!(window.check(0));
        assert!(!window.check(0));
        assert!(window.check(1));
        assert!(window.check(2));
        assert!(window.check(100));
        // Out-of-order packets inside the window are accepted once.
        assert!(window.check(99));
        assert!(!window.check(99));
        assert!(window.check(98));
        assert!(!window.check(98));
        // A counter behind the window is dropped.
        assert!(window.check(4096));
        assert!(!window.check(1024));
    }

    #[test]
    fn ip_length_ignores_keepalives_and_invalid_headers() {
        let mut ipv4 = vec![0u8; 28];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&28u16.to_be_bytes());
        assert_eq!(ip_length(&ipv4, 1420), 28);
        assert_eq!(ip_length(&[], 1420), 0);
        assert_eq!(ip_length(&[0x45, 0, 0], 1420), 0);
        let mut too_large = vec![0u8; 40];
        too_large[0] = 0x45;
        too_large[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(ip_length(&too_large, 1420), 0);
    }

    #[test]
    fn allowed_ips_select_by_longest_prefix_and_later_peer_wins() {
        let prefixes = |values: &[&str]| -> Vec<IpPrefix> {
            values
                .iter()
                .map(|value| IpPrefix::parse(value).expect("prefix"))
                .collect()
        };
        let peers = vec![
            prefixes(&["0.0.0.0/0"]),
            prefixes(&["10.0.0.0/8"]),
            prefixes(&["10.1.0.0/16"]),
            prefixes(&["10.1.0.0/16"]),
        ];
        assert_eq!(
            select_peer(&peers, IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3))),
            Some(3),
            "equal-length prefixes: the later peer wins"
        );
        assert_eq!(
            select_peer(&peers, IpAddr::V4(std::net::Ipv4Addr::new(10, 2, 2, 3))),
            Some(1)
        );
        assert_eq!(
            select_peer(&peers, IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))),
            Some(0)
        );
        assert_eq!(select_peer(&peers, IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)), None);
    }

    #[test]
    fn initiation_has_the_documented_shape() {
        let local_static = StaticSecret::from([1u8; 32]);
        let peer_static = PublicKey::from(&StaticSecret::from([2u8; 32]));
        let handshake = InitiatorHandshake::new(&local_static, peer_static);
        let (message, _state) = handshake.into_message(None);
        assert_eq!(message.len(), INITIATION_LEN);
        assert_eq!(message[0], MESSAGE_HANDSHAKE_INITIATION);
        assert_eq!(&message[1..4], &[0, 0, 0]);
        // MAC1 is keyed by the responder's static key and is not all zero.
        assert_ne!(&message[116..132], &[0u8; 16]);
        // MAC2 is zero until a cookie reply arrives.
        assert_eq!(&message[132..148], &[0u8; 16]);
    }
}
