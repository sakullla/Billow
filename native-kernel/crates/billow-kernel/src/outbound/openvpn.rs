//! OpenVPN control channel and AEAD data channel.
//!
//! This is the protocol half of the pinned `openvpn` outbound
//! (`adapter/outbound/openvpn.go` wrapping `transport/openvpn`):
//!
//! * UDP or TCP transport framing;
//! * control-channel hard reset, session IDs and the reliable message/ACK
//!   layer;
//! * a TLS 1.3/1.2 client over that control channel, verifying the server
//!   certificate chain against the configured inline CA (hostname is not
//!   checked, as the pinned client does) and authenticating itself with the
//!   configured inline certificate when present;
//! * the key-method-2 exchange (client pre-master/random1/random2 over TLS,
//!   server random1/random2 back) and the OpenVPN PRF key derivation;
//! * `PUSH_REQUEST`/`PUSH_REPLY` and the AEAD data channel
//!   (AES-128/256-GCM and CHACHA20-POLY1305) with P_DATA_V2 peer IDs and the
//!   OpenVPN keepalive payload.
//!
//! The data channel writes/reads IP packets; [`connect_stack`] wires them to
//! the shared smoltcp stack in [`crate::outbound::l3`], whose local address
//! comes from `PUSH_REPLY` (`ifconfig`/`ifconfig-ipv6`). [`dial`] therefore
//! returns a real TCP stream. `tls-auth`/`tls-crypt`, CBC data ciphers and
//! compression are rejected at configuration load (see `proxies.rs`).
//!
//! The protocol facts were taken from the public OpenVPN wire protocol and
//! checked as a black box against OpenVPN 2.7.9 (`tool/kernel-compat/peers/`
//! records the exact command); no OpenVPN source is vendored or linked.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha1::Sha1;

use crate::proxies::OpenVpnOutbound;

const OPCODE_HARD_RESET_CLIENT_V2: u8 = 7;
const OPCODE_HARD_RESET_SERVER_V2: u8 = 8;
const OPCODE_HARD_RESET_CLIENT_V3: u8 = 10;
const OPCODE_CONTROL_V1: u8 = 4;
const OPCODE_ACK_V1: u8 = 5;
const OPCODE_DATA_V1: u8 = 6;
const OPCODE_DATA_V2: u8 = 9;
const KEY_ID_MASK: u8 = 0x07;
const OPCODE_SHIFT: u8 = 3;
const SESSION_ID_SIZE: usize = 8;
const DATA_TAG_SIZE: usize = 16;
const DATA_IV_SIZE: usize = 12;
const PEER_ID_UNSET: u32 = 0x00ff_ffff;
const MAX_CONTROL_PAYLOAD: usize = 1000;
const RELIABLE_WINDOW: u32 = 64;
const RETRANSMIT: Duration = Duration::from_millis(500);
/// One blocking link read. `recv_data` loops over it until its own caller
/// timeout, so a 10 ms data-path poll actually blocks at most 50 ms on a
/// silent link; tests and evidence use this value.
const LINK_READ_TIMEOUT: Duration = Duration::from_millis(50);

/// OpenVPN's data-channel keepalive payload (`PING_STRING`).
pub const PING_PAYLOAD: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];

#[derive(Debug, thiserror::Error)]
pub enum OpenVpnError {
    #[error("openvpn connect {0}: {1}")]
    Connect(String, #[source] io::Error),
    #[error("openvpn control channel: {0}")]
    Control(String),
    #[error("openvpn handshake timed out after {0:?}")]
    Timeout(Duration),
    #[error("openvpn TLS: {0}")]
    Tls(String),
    #[error("openvpn certificate: {0}")]
    Certificate(String),
    #[error("openvpn key-method 2: {0}")]
    KeyExchange(String),
    #[error("openvpn push reply: {0}")]
    Push(String),
    #[error("openvpn data channel: {0}")]
    Data(String),
    #[error("openvpn replay: {0}")]
    Replay(String),
    #[error("openvpn unsupported configuration: {0}")]
    Unsupported(String),
    #[error("openvpn PUSH_REPLY carries no ifconfig/ifconfig-ipv6: the userspace IP stack has no local address")]
    NoIfconfig,
    #[error("openvpn userspace stack: {0}")]
    Stack(String),
}

/// The parsed `PUSH_REPLY` fields the data channel needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushReply {
    pub cipher: Option<String>,
    pub data_ciphers: Vec<String>,
    pub peer_id: Option<u32>,
    pub ifconfig: Option<String>,
    /// Local addresses the server assigned (`ifconfig` + `ifconfig-ipv6`),
    /// already converted to prefixes: a dotted netmask gives its length, a
    /// peer address in topology-p2p position gives a host prefix.
    pub prefixes: Vec<(std::net::IpAddr, u8)>,
    /// `route`/`route-ipv6` prefixes.
    pub routes: Vec<(std::net::IpAddr, u8)>,
    /// `dns` servers pushed by the server.
    pub dns: Vec<std::net::IpAddr>,
    pub redirect_gateway: bool,
    pub block_outside_dns: bool,
    pub block_ipv6: bool,
    pub push_continuation: bool,
    /// An `auth-token` record was seen. The token is not retained (it is
    /// session credential material) and is not used by this client yet.
    pub auth_token_seen: bool,
    /// `ping` interval pushed by the server (seconds).
    pub ping: Option<u16>,
    /// `ping-restart` timeout pushed by the server (seconds).
    pub ping_restart: Option<u16>,
    pub raw: String,
}

/// One decrypted data-channel packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataPacket {
    /// OpenVPN keepalive (`PING_STRING`); proves the data keys work.
    Keepalive,
    Data(Vec<u8>),
}

/// One OpenVPN session: control channel, TLS stream and data channel.
pub struct OpenVpnTunnel {
    control: Control,
    tls: ClientConnection,
    cipher: String,
    peer_id: u32,
    key_id: u8,
    send_key: Vec<u8>,
    recv_key: Vec<u8>,
    send_iv: [u8; DATA_IV_SIZE],
    recv_iv: [u8; DATA_IV_SIZE],
    send_id: u32,
    recv_highest: u32,
    recv_seen: bool,
    recv_window: u64,
    push: PushReply,
}

impl std::fmt::Debug for OpenVpnTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVpnTunnel")
            .field("cipher", &self.cipher)
            .field("peer_id", &self.peer_id)
            .field("push", &self.push)
            .finish_non_exhaustive()
    }
}

impl OpenVpnTunnel {
    /// Connect and complete the control channel, TLS authentication, key
    /// exchange and PUSH_REPLY. The returned tunnel can send/receive data
    /// packets; no IP stack is involved.
    pub fn connect(option: &OpenVpnOutbound, timeout: Duration) -> Result<Self, OpenVpnError> {
        let address = resolve(&option.server, option.port)?;
        Self::connect_at(option, address, timeout)
    }

    /// Connect to an already-resolved server address. The data-path entry
    /// resolves in the async dial task (honouring `ip-version`/DNS) and hands
    /// the address to the blocking data-channel thread.
    pub fn connect_at(
        option: &OpenVpnOutbound,
        address: SocketAddr,
        timeout: Duration,
    ) -> Result<Self, OpenVpnError> {
        if option.tls_auth.is_some() || option.tls_crypt.is_some() || option.tls_crypt_v2.is_some()
        {
            return Err(OpenVpnError::Unsupported(
                "tls-auth/tls-crypt control protection".to_string(),
            ));
        }
        let deadline = Instant::now() + timeout;
        let link = Link::connect_address(option, address, timeout)?;
        let local_session = random_session();
        let mut control = Control::new(link, local_session);
        control.handshake(deadline)?;
        debug_stage("control channel reset");

        let tls_config = tls_config(option)?;
        let server_name = ServerName::try_from(option.server.clone())
            .map_err(|_| OpenVpnError::Tls(format!("invalid server name '{}'", option.server)))?;
        let mut tls = ClientConnection::new(Arc::new(tls_config), server_name)
            .map_err(|error| OpenVpnError::Tls(error.to_string()))?;

        // Rustls handshake over the reliable control channel.
        loop {
            control.flush_tls(&mut tls)?;
            if !tls.is_handshaking() {
                control.flush_tls(&mut tls)?;
                break;
            }
            if Instant::now() >= deadline {
                return Err(OpenVpnError::Timeout(timeout));
            }
            control.pump(&mut tls, Duration::from_millis(50))?;
        }
        debug_stage("tls handshake");

        // Key-method 2: the client sends its key source over TLS, the server
        // answers with its own random values.
        let client = ClientKeySource::generate(option)?;
        control.write_app(&mut tls, &client.record())?;
        debug_stage("key method 2 request");
        let mut server_bytes = Vec::new();
        let server = loop {
            if Instant::now() >= deadline {
                return Err(OpenVpnError::Timeout(timeout));
            }
            let chunk = control.read_app(&mut tls, Duration::from_millis(100))?;
            if chunk.is_empty() {
                continue;
            }
            server_bytes.extend_from_slice(&chunk);
            if let Some((parsed, _)) = ServerKeySource::parse(&server_bytes) {
                break parsed;
            }
        };
        debug_stage("key method 2 response");

        // PUSH_REQUEST / PUSH_REPLY. A multi-segment reply ends with
        // `push-continuation N`; the pinned client asks again and concatenates
        // the next records.
        control.write_app(&mut tls, b"PUSH_REQUEST\0")?;
        let mut push_bytes = Vec::new();
        let mut reply = read_push_record(
            &mut control,
            &mut tls,
            deadline,
            timeout,
            &mut push_bytes,
        )?;
        let mut segments = 0;
        while reply.push_continuation {
            segments += 1;
            if segments > 8 {
                return Err(OpenVpnError::Unsupported(
                    "multi-segment PUSH_REPLY exceeds 8 segments".to_string(),
                ));
            }
            control.write_app(&mut tls, b"PUSH_REQUEST\0")?;
            let next = read_push_record(
                &mut control,
                &mut tls,
                deadline,
                timeout,
                &mut push_bytes,
            )?;
            merge_push_reply(&mut reply, next);
        }

        debug_stage("push reply");
        let cipher = negotiate_cipher(option, &reply)?;
        let key_len = cipher_key_len(&cipher)?;
        let key_material = derive_keys(
            &client,
            &server,
            &control.local_session,
            &control.remote_session,
            &option.auth,
            key_len,
        )?;
        let (send_key, send_hmac, recv_key, recv_hmac) = key_material;
        let mut send_iv = [0u8; DATA_IV_SIZE];
        let mut recv_iv = [0u8; DATA_IV_SIZE];
        send_iv[4..].copy_from_slice(&send_hmac[..DATA_IV_SIZE - 4]);
        recv_iv[4..].copy_from_slice(&recv_hmac[..DATA_IV_SIZE - 4]);
        let peer_id = reply.peer_id.unwrap_or(PEER_ID_UNSET);

        Ok(Self {
            control,
            tls,
            cipher,
            peer_id,
            key_id: 0,
            send_key,
            recv_key,
            send_iv,
            recv_iv,
            // OpenVPN reserves packet-id 0 ("no id"); the first data packet
            // is id 1, as the real server's replay check expects.
            send_id: 1,
            recv_highest: 0,
            recv_seen: false,
            recv_window: 0,
            push: reply,
        })
    }

    /// The negotiated `PUSH_REPLY`.
    pub fn push_reply(&self) -> &PushReply {
        &self.push
    }

    /// The negotiated data cipher.
    pub fn cipher(&self) -> &str {
        &self.cipher
    }

    /// Send one data-channel keepalive and wait for one keepalive from the
    /// server. This is the data-channel proof used by the controlled test.
    pub fn exchange_keepalive(&mut self, timeout: Duration) -> Result<(), OpenVpnError> {
        self.send_keepalive()?;
        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout {
                return Err(OpenVpnError::Timeout(timeout));
            }
            match self.recv_data(Duration::from_millis(100))? {
                Some(DataPacket::Keepalive) => return Ok(()),
                Some(DataPacket::Data(_)) => continue,
                None => continue,
            }
        }
    }

    /// Encrypt and send one IP packet through the data channel.
    pub fn send_data(&mut self, packet: &[u8]) -> Result<(), OpenVpnError> {
        let encrypted = self.encrypt_payload(packet)?;
        self.control
            .link
            .send(&encrypted)
            .map_err(|error| OpenVpnError::Data(error.to_string()))
    }

    /// Send the data-channel keepalive (`PING_STRING`). The pinned client
    /// answers the server's `--ping` records so a `--ping-restart` timer does
    /// not tear the session down while the stack is idle.
    pub fn send_keepalive(&mut self) -> Result<(), OpenVpnError> {
        let packet = self.encrypt_payload(&PING_PAYLOAD)?;
        self.control
            .link
            .send(&packet)
            .map_err(|error| OpenVpnError::Data(error.to_string()))
    }

    /// Receive one data packet (or keepalive). Control packets that arrive
    /// meanwhile are acknowledged and fed to the TLS stream.
    pub fn recv_data(&mut self, timeout: Duration) -> Result<Option<DataPacket>, OpenVpnError> {
        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout {
                return Ok(None);
            }
            let packet = match self.control.link.recv(LINK_READ_TIMEOUT) {
                Ok(packet) => packet,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
                Err(error) => return Err(OpenVpnError::Control(error.to_string())),
            };
            if packet.is_empty() {
                continue;
            }
            let opcode = packet[0] >> OPCODE_SHIFT;
            if opcode == OPCODE_ACK_V1
                || opcode == OPCODE_CONTROL_V1
                || opcode == OPCODE_HARD_RESET_SERVER_V2
            {
                if let Some(payloads) = self.control.handle(&packet)? {
                    for payload in payloads {
                        self.feed_tls(&payload);
                    }
                }
                continue;
            }
            if opcode != OPCODE_DATA_V1 && opcode != OPCODE_DATA_V2 {
                continue;
            }
            let plaintext = match self.decrypt_payload(&packet) {
                Ok(plaintext) => plaintext,
                // The pinned client drops a replayed/out-of-window packet and
                // keeps the session instead of tearing it down.
                Err(OpenVpnError::Replay(_)) => continue,
                Err(error) => return Err(error),
            };
            if plaintext == PING_PAYLOAD {
                return Ok(Some(DataPacket::Keepalive));
            }
            if plaintext.is_empty() {
                continue;
            }
            return Ok(Some(DataPacket::Data(plaintext)));
        }
    }

    fn encrypt_payload(&mut self, payload: &[u8]) -> Result<Vec<u8>, OpenVpnError> {
        let header = data_header(self.peer_id, self.key_id);
        let id = self.send_id;
        self.send_id = self
            .send_id
            .checked_add(1)
            .ok_or_else(|| OpenVpnError::Data("packet id exhausted".to_string()))?;
        let id_bytes = id.to_be_bytes();
        let aad = aead_additional_data(&header, &id_bytes);
        let nonce = data_nonce(self.send_iv, id);
        let mut sealed = aead_encrypt(&self.cipher, &self.send_key, &nonce, &aad, payload)
            .map_err(|error| OpenVpnError::Data(error.to_string()))?;
        let tag_at = sealed.len() - DATA_TAG_SIZE;
        let tag = sealed.split_off(tag_at);
        let mut out = Vec::with_capacity(header.len() + 4 + DATA_TAG_SIZE + sealed.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&id_bytes);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    fn decrypt_payload(&mut self, packet: &[u8]) -> Result<Vec<u8>, OpenVpnError> {
        let header_len = header_len(packet);
        if packet.len() < header_len + 4 + DATA_TAG_SIZE {
            return Err(OpenVpnError::Data("data packet too short".to_string()));
        }
        let header = &packet[..header_len];
        let id = u32::from_be_bytes(packet[header_len..header_len + 4].try_into().unwrap());
        let tag = &packet[header_len + 4..header_len + 4 + DATA_TAG_SIZE];
        let ciphertext = &packet[header_len + 4 + DATA_TAG_SIZE..];
        let mut combined = Vec::with_capacity(ciphertext.len() + DATA_TAG_SIZE);
        combined.extend_from_slice(ciphertext);
        combined.extend_from_slice(tag);
        let aad = aead_additional_data(header, &id.to_be_bytes());
        let nonce = data_nonce(self.recv_iv, id);
        let plaintext = aead_decrypt(&self.cipher, &self.recv_key, &nonce, &aad, &combined)
            .map_err(|_| OpenVpnError::Data("data packet authentication failed".to_string()))?;
        if !self.accept_packet_id(id) {
            return Err(OpenVpnError::Replay(format!(
                "replayed or out-of-window data packet id {id}"
            )));
        }
        Ok(plaintext)
    }

    fn accept_packet_id(&mut self, id: u32) -> bool {
        if !self.recv_seen {
            self.recv_seen = true;
            self.recv_highest = id;
            self.recv_window = 1;
            return true;
        }
        if id > self.recv_highest {
            let shift = id - self.recv_highest;
            self.recv_window = if shift >= 64 {
                1
            } else {
                (self.recv_window << shift) | 1
            };
            self.recv_highest = id;
            return true;
        }
        let behind = self.recv_highest - id;
        if behind >= 64 {
            return false;
        }
        let mask = 1u64 << behind;
        if self.recv_window & mask != 0 {
            return false;
        }
        self.recv_window |= mask;
        true
    }

    fn feed_tls(&mut self, payload: &[u8]) {
        let mut cursor = payload;
        if self.tls.read_tls(&mut cursor).is_ok() {
            let _ = self.tls.process_new_packets();
        }
    }
}

// ---------------------------------------------------------------------------
// Control channel
// ---------------------------------------------------------------------------

enum Link {
    Udp(UdpSocket),
    Tcp {
        stream: TcpStream,
        /// Complete frames plus any bytes of a frame whose read timed out.
        /// Keeping the partial bytes is what prevents a half frame from
        /// desynchronising the next length prefix.
        frames: FrameBuffer,
    },
}

/// Length-prefixed TCP frame reassembly that survives read timeouts.
struct FrameBuffer {
    bytes: Vec<u8>,
}

impl FrameBuffer {
    fn new() -> FrameBuffer {
        FrameBuffer { bytes: Vec::new() }
    }

    fn push(&mut self, data: &[u8]) {
        self.bytes.extend_from_slice(data);
    }

    fn next_frame(&mut self) -> Option<Vec<u8>> {
        if self.bytes.len() < 2 {
            return None;
        }
        let length = u16::from_be_bytes([self.bytes[0], self.bytes[1]]) as usize;
        if self.bytes.len() < 2 + length {
            return None;
        }
        let frame = self.bytes[2..2 + length].to_vec();
        self.bytes.drain(..2 + length);
        Some(frame)
    }
}

impl Link {
    fn connect_address(
        option: &OpenVpnOutbound,
        address: SocketAddr,
        timeout: Duration,
    ) -> Result<Self, OpenVpnError> {
        if option.proto == "tcp" {
            let stream = crate::outbound::tcp_stream_std_blocking(address, timeout)
                .map_err(|error| OpenVpnError::Connect(address.to_string(), error))?;
            stream
                .set_read_timeout(Some(timeout))
                .map_err(|error| OpenVpnError::Connect(address.to_string(), error))?;
            Ok(Link::Tcp {
                stream,
                frames: FrameBuffer::new(),
            })
        } else {
            let bind: SocketAddr = if address.is_ipv4() {
                SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0u16; 8], 0))
            };
            // Bound through the process-wide physical interface so a desktop
            // TUN does not capture the control channel again.
            let socket = crate::outbound::udp_socket_std_blocking(
                bind,
                &crate::proxies::DialerOptions::default(),
            )
            .map_err(|error| OpenVpnError::Connect(address.to_string(), error))?;
            socket
                .connect(address)
                .map_err(|error| OpenVpnError::Connect(address.to_string(), error))?;
            socket
                .set_read_timeout(Some(timeout))
                .map_err(|error| OpenVpnError::Connect(address.to_string(), error))?;
            Ok(Link::Udp(socket))
        }
    }

    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        match self {
            Link::Udp(socket) => socket.send(packet).map(|_| ()),
            Link::Tcp { stream, .. } => {
                let len = u16::try_from(packet.len())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
                stream.write_all(&len.to_be_bytes())?;
                stream.write_all(packet)
            }
        }
    }

    fn recv(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        match self {
            Link::Udp(socket) => {
                socket.set_read_timeout(Some(timeout))?;
                let mut buffer = vec![0u8; 65535];
                let length = socket.recv(&mut buffer)?;
                buffer.truncate(length);
                Ok(buffer)
            }
            Link::Tcp { stream, frames } => {
                let mut chunk = [0u8; 4096];
                loop {
                    if let Some(frame) = frames.next_frame() {
                        return Ok(frame);
                    }
                    stream.set_read_timeout(Some(timeout))?;
                    match stream.read(&mut chunk) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "openvpn TCP link closed mid-frame",
                            ))
                        }
                        Ok(read) => frames.push(&chunk[..read]),
                        // A partial frame stays in the buffer; the next call
                        // continues from the exact byte offset.
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            return Err(error)
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }
}

fn resolve(server: &str, port: u16) -> Result<SocketAddr, OpenVpnError> {
    use std::net::ToSocketAddrs;
    if let Ok(ip) = server.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    (server, port)
        .to_socket_addrs()
        .map_err(|error| OpenVpnError::Connect(format!("{server}:{port}"), error))?
        .next()
        .ok_or_else(|| {
            OpenVpnError::Connect(
                format!("{server}:{port}"),
                io::Error::new(io::ErrorKind::NotFound, "resolved to no address"),
            )
        })
}

// ---------------------------------------------------------------------------
// Userspace stack carrier
// ---------------------------------------------------------------------------

/// Registry key of one configured OpenVPN outbound. Certificate/key material
/// is part of the key and is never printed (only the digest).
pub(crate) fn stack_fingerprint(option: &OpenVpnOutbound) -> String {
    let mut parts = vec![
        option.server.clone(),
        option.port.to_string(),
        option.proto.clone(),
        option.cipher.clone(),
        option.data_ciphers.join(":"),
        option.data_cipher_fallback.clone().unwrap_or_default(),
        option.auth.clone(),
        option.ca.expose().to_string(),
        option.cert.as_ref().map(|value| value.expose().to_string()).unwrap_or_default(),
        option.key.as_ref().map(|value| value.expose().to_string()).unwrap_or_default(),
        option.username.as_ref().map(|value| value.expose().to_string()).unwrap_or_default(),
        option.password.as_ref().map(|value| value.expose().to_string()).unwrap_or_default(),
        option.mtu.to_string(),
        option.ping.to_string(),
        option.ping_restart.to_string(),
        option.tran_window.to_string(),
        option.handshake_timeout.to_string(),
        option.dev.clone(),
    ];
    for (key, value) in &option.peer_info {
        parts.push(format!("{key}={value}"));
    }
    let borrowed: Vec<&str> = parts.iter().map(String::as_str).collect();
    crate::outbound::l3::fingerprint("openvpn", &borrowed)
}

fn local_addresses(push: &PushReply) -> (Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>) {
    let mut ipv4 = None;
    let mut ipv6 = None;
    for (addr, _bits) in &push.prefixes {
        match addr {
            std::net::IpAddr::V4(addr) if ipv4.is_none() => ipv4 = Some(*addr),
            std::net::IpAddr::V6(addr) if ipv6.is_none() => ipv6 = Some(*addr),
            _ => {}
        }
    }
    (ipv4, ipv6)
}

struct OpenVpnInit {
    ipv4: Option<std::net::Ipv4Addr>,
    ipv6: Option<std::net::Ipv6Addr>,
}

/// Resolve the server in the async dial task, connect the blocking control and
/// data channel on a dedicated OS thread, then build/reuse the shared stack.
pub async fn connect_stack(
    option: &OpenVpnOutbound,
    timeout: Duration,
) -> Result<Arc<crate::outbound::l3::Stack>, OpenVpnError> {
    use crate::outbound::l3;

    let fingerprint = stack_fingerprint(option);
    if let Some(stack) = l3::lookup(&fingerprint) {
        return Ok(stack);
    }
    // Network resolution, the blocking data-path thread, and the one-shot
    // handoff all happen outside the registry lock; only the final
    // lookup/publish pair is serialised.
    let addresses = crate::outbound::resolve_all(&option.server, option.port)
        .await
        .map_err(|error| {
            OpenVpnError::Connect(
                format!("{}:{}", option.server, option.port),
                std::io::Error::other(error.to_string()),
            )
        })?;
    let address = addresses.into_iter().next().ok_or_else(|| {
        OpenVpnError::Connect(
            format!("{}:{}", option.server, option.port),
            std::io::Error::new(std::io::ErrorKind::NotFound, "resolved to no address"),
        )
    })?;
    let mtu = if option.mtu == 0 { 1500 } else { option.mtu as usize };
    let option_for_thread = option.clone();
    let ping = option.ping;
    let ping_restart = option.ping_restart;
    let (init_tx, init_rx) = tokio::sync::oneshot::channel::<Result<OpenVpnInit, OpenVpnError>>();
    let (stack_tx, stack_rx) =
        std::sync::mpsc::channel::<Arc<crate::outbound::l3::Stack>>();
    std::thread::Builder::new()
        .name("openvpn-datapath".to_string())
        .spawn(move || {
            let tunnel = match OpenVpnTunnel::connect_at(&option_for_thread, address, timeout) {
                Ok(tunnel) => tunnel,
                Err(error) => {
                    let _ = init_tx.send(Err(error));
                    return;
                }
            };
            let (ipv4, ipv6) = local_addresses(tunnel.push_reply());
            if ipv4.is_none() && ipv6.is_none() {
                let _ = init_tx.send(Err(OpenVpnError::NoIfconfig));
                return;
            }
            if init_tx.send(Ok(OpenVpnInit { ipv4, ipv6 })).is_err() {
                return;
            }
            // The async side builds the stack (it needs the same local
            // addresses) and hands it back; if it dies the thread exits.
            if let Ok(stack) = stack_rx.recv_timeout(Duration::from_secs(10)) {
                let push = tunnel.push_reply();
                let ping = push.ping.unwrap_or(ping);
                let ping_restart = push.ping_restart.unwrap_or(ping_restart);
                run_datapath(tunnel, stack, ping, ping_restart);
            }
        })
        .map_err(|error| OpenVpnError::Connect(address.to_string(), error))?;

    let init = match tokio::time::timeout(timeout + Duration::from_secs(1), init_rx).await {
        Ok(Ok(Ok(init))) => init,
        Ok(Ok(Err(error))) => return Err(error),
        Ok(Err(_)) => {
            return Err(OpenVpnError::Control(
                "openvpn data-path thread exited before reporting the push reply".to_string(),
            ))
        }
        Err(_) => return Err(OpenVpnError::Timeout(timeout)),
    };
    let config = l3::StackConfig::new(init.ipv4, init.ipv6, mtu, fingerprint.clone());
    let stack = l3::Stack::new(config).map_err(|error| OpenVpnError::Stack(error.to_string()))?;
    let published = {
        let _guard = l3::registry_lock().lock().await;
        // Double-check: a concurrent dial may have published first. Dropping
        // `stack_tx` on return disconnects the receiver, so the loser's
        // data-path thread stops immediately (its tunnel is dropped).
        if let Some(existing) = l3::lookup(&fingerprint) {
            return Ok(existing);
        }
        l3::publish(fingerprint.clone(), &stack)
    };
    if !published {
        return Err(OpenVpnError::Stack(format!(
            "the userspace stack registry already holds the maximum of {} active stacks",
            l3::MAX_STACKS
        )));
    }
    // The thread handoff is outside the registry lock; the thread is blocked on
    // this channel, so a failed send means it already exited.
    if stack_tx.send(stack.clone()).is_err() {
        l3::forget(&fingerprint);
        return Err(OpenVpnError::Control(
            "openvpn data-path thread is gone".to_string(),
        ));
    }
    Ok(stack)
}

/// What the data-path loop must do when it looks at its timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeepaliveAction {
    None,
    SendPing,
    Restart,
}

/// `ping` keeps the client's keepalive flowing; `ping-restart` tears the
/// session down when nothing arrived from the server for that long. Both are
/// the pushed values when the server sends them (`PUSH_REPLY`), otherwise the
/// configured ones.
fn keepalive_action(
    now: Instant,
    last_inbound: Instant,
    last_sent: Instant,
    ping: u16,
    ping_restart: u16,
) -> KeepaliveAction {
    if ping_restart != 0
        && now.duration_since(last_inbound) >= Duration::from_secs(u64::from(ping_restart))
    {
        return KeepaliveAction::Restart;
    }
    if ping != 0 && now.duration_since(last_sent) >= Duration::from_secs(u64::from(ping)) {
        return KeepaliveAction::SendPing;
    }
    KeepaliveAction::None
}

fn run_datapath(
    mut tunnel: OpenVpnTunnel,
    stack: Arc<crate::outbound::l3::Stack>,
    ping: u16,
    ping_restart: u16,
) {
    let weak = Arc::downgrade(&stack);
    let mut last_inbound = Instant::now();
    let mut last_sent = Instant::now();
    loop {
        let Some(stack) = weak.upgrade() else {
            return;
        };
        let now = Instant::now();
        match keepalive_action(now, last_inbound, last_sent, ping, ping_restart) {
            KeepaliveAction::Restart => {
                stack.fail(format!(
                    "openvpn ping-restart: no inbound data for {ping_restart}s"
                ));
                return;
            }
            KeepaliveAction::SendPing => {
                if let Err(error) = tunnel.send_keepalive() {
                    stack.fail(format!("openvpn keepalive send: {error}"));
                    return;
                }
                stack.touch();
                last_sent = Instant::now();
            }
            KeepaliveAction::None => {}
        }
        while let Some(packet) = stack.take_tx_packet() {
            if let Err(error) = tunnel.send_data(&packet) {
                stack.fail(format!("openvpn data send: {error}"));
                return;
            }
            stack.touch();
            last_sent = Instant::now();
        }
        match tunnel.recv_data(Duration::from_millis(10)) {
            Ok(Some(DataPacket::Data(packet))) => {
                last_inbound = Instant::now();
                stack.push_rx_packet(&packet);
            }
            Ok(Some(DataPacket::Keepalive)) => {
                last_inbound = Instant::now();
                if let Err(error) = tunnel.send_keepalive() {
                    stack.fail(format!("openvpn keepalive send: {error}"));
                    return;
                }
                stack.touch();
                last_sent = Instant::now();
            }
            Ok(None) => {}
            Err(error) => {
                stack.fail(format!("openvpn data receive: {error}"));
                return;
            }
        }
    }
}

/// Explicit teardown API for one configured OpenVPN outbound: removes the
/// shared stack entry; the data-path thread sees the last strong reference go
/// away and exits. This is not wired into engine reload/close yet (the idle
/// reaper is the automatic path).
pub fn forget(option: &OpenVpnOutbound) {
    crate::outbound::l3::forget(&stack_fingerprint(option));
}

fn dial_error(error: OpenVpnError) -> crate::outbound::DialError {
    crate::outbound::DialError::Handshake {
        protocol: "openvpn",
        source: std::io::Error::other(error.to_string()),
    }
}

/// `dial_inner` entry: build the stack, resolve the destination through the
/// session resolver, and return one TCP stream terminated by smoltcp.
pub(crate) async fn dial(
    option: &OpenVpnOutbound,
    target: &crate::outbound::Target,
    timeout: Duration,
) -> Result<crate::outbound::Dialed, crate::outbound::DialError> {
    let stack = connect_stack(option, timeout).await.map_err(dial_error)?;
    let addresses = crate::outbound::resolve_all(&target.host, target.port).await?;
    let remote = addresses
        .into_iter()
        .find(|address| match address.ip() {
            std::net::IpAddr::V4(_) => stack.ipv4().is_some(),
            std::net::IpAddr::V6(_) => stack.ipv6().is_some(),
        })
        .ok_or_else(|| crate::outbound::DialError::Resolve {
            host: target.host.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no resolved address matches a local tunnel address family",
            ),
        })?;
    let stream = stack.dial_tcp(remote, timeout).await.map_err(|error| {
        crate::outbound::DialError::Handshake {
            protocol: "openvpn",
            source: error,
        }
    })?;
    Ok(crate::outbound::Dialed {
        stream,
        server: option
            .server
            .parse::<std::net::IpAddr>()
            .map(|ip| SocketAddr::new(ip, option.port))
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], option.port))),
    })
}

struct Control {
    link: Link,
    local_session: [u8; SESSION_ID_SIZE],
    remote_session: [u8; SESSION_ID_SIZE],
    next_send: u32,
    unacked: BTreeMap<u32, (Instant, Vec<u8>)>,
    next_recv: u32,
    pending: BTreeMap<u32, Vec<u8>>,
    key_id: u8,
}

impl Control {
    fn new(link: Link, local_session: [u8; SESSION_ID_SIZE]) -> Self {
        Self {
            link,
            local_session,
            remote_session: [0u8; SESSION_ID_SIZE],
            next_send: 1,
            unacked: BTreeMap::new(),
            next_recv: 1,
            pending: BTreeMap::new(),
            key_id: 0,
        }
    }

    fn handshake(&mut self, deadline: Instant) -> Result<(), OpenVpnError> {
        let reset = encode_control(
            OPCODE_HARD_RESET_CLIENT_V2,
            self.key_id,
            self.local_session,
            &[],
            None,
            Some(0),
            &[],
        );
        let mut last = Instant::now() - RETRANSMIT;
        loop {
            if last.elapsed() >= RETRANSMIT {
                self.link
                    .send(&reset)
                    .map_err(|error| OpenVpnError::Control(error.to_string()))?;
                last = Instant::now();
            }
            if Instant::now() >= deadline {
                return Err(OpenVpnError::Timeout(deadline.saturating_duration_since(Instant::now())));
            }
            let packet = match self.link.recv(Duration::from_millis(100)) {
                Ok(packet) => packet,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    continue
                }
                Err(error) => return Err(OpenVpnError::Control(error.to_string())),
            };
            let Some(parsed) = parse_control(&packet) else {
                continue;
            };
            if parsed.opcode == OPCODE_HARD_RESET_SERVER_V2 && parsed.message_id == Some(0) {
                self.remote_session = parsed.session;
                self.ack(&[0])?;
                return Ok(());
            }
            if parsed.opcode == OPCODE_ACK_V1 {
                // An ack for the reset is expected once the server accepted it.
                if parsed.acks.contains(&0) {
                    // Keep waiting for the server reset; it normally arrives first.
                }
            }
        }
    }

    fn flush_tls(&mut self, tls: &mut ClientConnection) -> Result<(), OpenVpnError> {
        while tls.wants_write() {
            let mut buffer = Vec::new();
            tls.write_tls(&mut buffer)
                .map_err(|error| OpenVpnError::Tls(error.to_string()))?;
            if buffer.is_empty() {
                break;
            }
            for chunk in buffer.chunks(MAX_CONTROL_PAYLOAD) {
                self.send_control(chunk)?;
            }
        }
        self.retransmit()
    }

    fn pump(&mut self, tls: &mut ClientConnection, wait: Duration) -> Result<(), OpenVpnError> {
        self.retransmit()?;
        let start = Instant::now();
        while start.elapsed() < wait {
            let packet = match self.link.recv(Duration::from_millis(25)) {
                Ok(packet) => packet,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    continue
                }
                Err(error) => return Err(OpenVpnError::Control(error.to_string())),
            };
            if let Some(payloads) = self.handle(&packet)? {
                for payload in payloads {
                    self.feed_tls(tls, &payload)?;
                }
                if !tls.is_handshaking() {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn feed_tls(&self, tls: &mut ClientConnection, payload: &[u8]) -> Result<(), OpenVpnError> {
        let mut cursor = payload;
        tls.read_tls(&mut cursor)
            .map_err(|error| OpenVpnError::Tls(error.to_string()))?;
        tls.process_new_packets()
            .map_err(|error| OpenVpnError::Tls(error.to_string()))?;
        Ok(())
    }

    fn write_app(&mut self, tls: &mut ClientConnection, data: &[u8]) -> Result<(), OpenVpnError> {
        tls.writer()
            .write_all(data)
            .map_err(|error| OpenVpnError::Tls(error.to_string()))?;
        self.flush_tls(tls)
    }

    fn read_app(
        &mut self,
        tls: &mut ClientConnection,
        wait: Duration,
    ) -> Result<Vec<u8>, OpenVpnError> {
        let mut buffer = [0u8; 4096];
        let start = Instant::now();
        loop {
            match tls.reader().read(&mut buffer) {
                Ok(0) => return Err(OpenVpnError::Tls("TLS stream closed".to_string())),
                Ok(length) => return Ok(buffer[..length].to_vec()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if start.elapsed() >= wait {
                        return Ok(Vec::new());
                    }
                    self.pump(tls, Duration::from_millis(25))?;
                }
                Err(error) => return Err(OpenVpnError::Tls(error.to_string())),
            }
        }
    }

    fn send_control(&mut self, payload: &[u8]) -> Result<(), OpenVpnError> {
        let message_id = self.next_send;
        self.next_send = self
            .next_send
            .checked_add(1)
            .ok_or_else(|| OpenVpnError::Control("message id exhausted".to_string()))?;
        let packet = encode_control(
            OPCODE_CONTROL_V1,
            self.key_id,
            self.local_session,
            &[],
            None,
            Some(message_id),
            payload,
        );
        self.link
            .send(&packet)
            .map_err(|error| OpenVpnError::Control(error.to_string()))?;
        self.unacked.insert(message_id, (Instant::now(), packet));
        Ok(())
    }

    fn retransmit(&mut self) -> Result<(), OpenVpnError> {
        let now = Instant::now();
        let mut stale = Vec::new();
        for (id, (sent, _)) in &self.unacked {
            if now.duration_since(*sent) >= RETRANSMIT {
                stale.push(*id);
            }
        }
        for id in stale {
            if let Some((sent, packet)) = self.unacked.get_mut(&id) {
                self.link
                    .send(packet)
                    .map_err(|error| OpenVpnError::Control(error.to_string()))?;
                *sent = now;
            }
        }
        Ok(())
    }

    fn ack(&mut self, ids: &[u32]) -> Result<(), OpenVpnError> {
        if ids.is_empty() {
            return Ok(());
        }
        let packet = encode_control(
            OPCODE_ACK_V1,
            self.key_id,
            self.local_session,
            ids,
            Some(self.remote_session),
            None,
            &[],
        );
        self.link
            .send(&packet)
            .map_err(|error| OpenVpnError::Control(error.to_string()))
    }

    /// Handle one control packet; returns the in-order payloads that are now
    /// deliverable.
    fn handle(&mut self, packet: &[u8]) -> Result<Option<Vec<Vec<u8>>>, OpenVpnError> {
        let Some(parsed) = parse_control(packet) else {
            return Ok(None);
        };
        if !parsed.acks.is_empty() {
            for id in &parsed.acks {
                self.unacked.remove(id);
            }
        }
        // `parsed.remote_session` is this side's session id as seen by the
        // server; it must not replace the server session id we learn from the
        // hard-reset response, which is what our own acks must carry.
        let _ = parsed.remote_session;
        if parsed.opcode == OPCODE_ACK_V1 {
            return Ok(None);
        }
        let Some(message_id) = parsed.message_id else {
            return Ok(None);
        };
        self.ack(&[message_id])?;
        if message_id < self.next_recv {
            return Ok(None);
        }
        if message_id - self.next_recv >= RELIABLE_WINDOW {
            return Ok(None);
        }
        if message_id != self.next_recv {
            self.pending.entry(message_id).or_insert(parsed.payload);
            return Ok(None);
        }
        let mut deliverable = vec![parsed.payload];
        self.next_recv += 1;
        while let Some(payload) = self.pending.remove(&self.next_recv) {
            deliverable.push(payload);
            self.next_recv += 1;
        }
        Ok(Some(deliverable))
    }
}

#[derive(Debug)]
struct ParsedControl {
    opcode: u8,
    acks: Vec<u32>,
    remote_session: Option<[u8; SESSION_ID_SIZE]>,
    message_id: Option<u32>,
    payload: Vec<u8>,
    session: [u8; SESSION_ID_SIZE],
}

fn encode_control(
    opcode: u8,
    key_id: u8,
    session: [u8; SESSION_ID_SIZE],
    acks: &[u32],
    remote_session: Option<[u8; SESSION_ID_SIZE]>,
    message_id: Option<u32>,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + payload.len());
    out.push((opcode << OPCODE_SHIFT) | (key_id & KEY_ID_MASK));
    out.extend_from_slice(&session);
    out.push(acks.len() as u8);
    for ack in acks {
        out.extend_from_slice(&ack.to_be_bytes());
    }
    if !acks.is_empty() {
        if let Some(remote) = remote_session {
            out.extend_from_slice(&remote);
        }
    }
    if let Some(message_id) = message_id {
        out.extend_from_slice(&message_id.to_be_bytes());
        out.extend_from_slice(payload);
    }
    out
}

fn parse_control(packet: &[u8]) -> Option<ParsedControl> {
    if packet.len() < 1 + SESSION_ID_SIZE {
        return None;
    }
    let opcode = packet[0] >> OPCODE_SHIFT;
    let session = <[u8; SESSION_ID_SIZE]>::try_from(&packet[1..1 + SESSION_ID_SIZE]).ok()?;
    let mut offset = 1 + SESSION_ID_SIZE;
    let ack_count = *packet.get(offset)? as usize;
    offset += 1;
    if offset + ack_count * 4 > packet.len() {
        return None;
    }
    let mut acks = Vec::with_capacity(ack_count);
    for _ in 0..ack_count {
        acks.push(u32::from_be_bytes(
            packet[offset..offset + 4].try_into().ok()?,
        ));
        offset += 4;
    }
    let mut remote_session = None;
    if ack_count > 0 {
        if offset + SESSION_ID_SIZE > packet.len() {
            return None;
        }
        remote_session = Some(
            <[u8; SESSION_ID_SIZE]>::try_from(&packet[offset..offset + SESSION_ID_SIZE]).ok()?,
        );
        offset += SESSION_ID_SIZE;
    }
    let has_message_id = opcode != OPCODE_ACK_V1 && opcode <= OPCODE_HARD_RESET_CLIENT_V3;
    let message_id = if has_message_id {
        if offset + 4 > packet.len() {
            return None;
        }
        let id = u32::from_be_bytes(packet[offset..offset + 4].try_into().ok()?);
        offset += 4;
        Some(id)
    } else {
        None
    };
    Some(ParsedControl {
        opcode,
        acks,
        remote_session,
        message_id,
        payload: packet[offset..].to_vec(),
        session,
    })
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

fn tls_config(option: &OpenVpnOutbound) -> Result<ClientConfig, OpenVpnError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    let mut reader = option.ca.expose().as_bytes();
    for certificate in rustls_pemfile::certs(&mut reader) {
        let certificate = certificate.map_err(|error| OpenVpnError::Certificate(error.to_string()))?;
        roots
            .add(certificate)
            .map_err(|error| OpenVpnError::Certificate(error.to_string()))?;
    }
    if roots.is_empty() {
        return Err(OpenVpnError::Certificate(
            "the inline 'ca' contains no certificate".to_string(),
        ));
    }
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots.clone()),
        provider.clone(),
    )
    .build()
    .map_err(|error| OpenVpnError::Certificate(error.to_string()))?;
    let verifier = Arc::new(ChainOnlyVerifier { inner });

    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| OpenVpnError::Tls(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let config = match (&option.cert, &option.key) {
        (Some(cert), Some(key)) => {
            let mut cert_reader = cert.expose().as_bytes();
            let certs = rustls_pemfile::certs(&mut cert_reader)
                .collect::<Result<Vec<CertificateDer<'static>>, _>>()
                .map_err(|error| OpenVpnError::Certificate(error.to_string()))?;
            if certs.is_empty() {
                return Err(OpenVpnError::Certificate(
                    "the inline 'cert' contains no certificate".to_string(),
                ));
            }
            let mut key_reader = key.expose().as_bytes();
            let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
                .map_err(|error| OpenVpnError::Certificate(error.to_string()))?
                .ok_or_else(|| {
                    OpenVpnError::Certificate("the inline 'key' contains no private key".to_string())
                })?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|error| OpenVpnError::Certificate(error.to_string()))?
        }
        _ => builder.with_no_client_auth(),
    };
    Ok(config)
}

/// The pinned client verifies the certificate chain against `ca` but not the
/// hostname (`InsecureSkipVerify` plus an explicit chain check). This
/// verifier delegates to the webpki verifier and accepts only the
/// `NotValidForName` failure, which is exactly "chain good, name unchecked".
#[derive(Debug)]
struct ChainOnlyVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

impl ServerCertVerifier for ChainOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            )) => Ok(ServerCertVerified::assertion()),
            Err(error) => Err(error),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ---------------------------------------------------------------------------
// Key-method 2 and PUSH_REPLY
// ---------------------------------------------------------------------------

struct ClientKeySource {
    premaster: [u8; 48],
    random1: [u8; 32],
    random2: [u8; 32],
    options: String,
    username: String,
    password: String,
    peer_info: String,
}

impl ClientKeySource {
    fn generate(option: &OpenVpnOutbound) -> Result<Self, OpenVpnError> {
        let mut premaster = [0u8; 48];
        let mut random1 = [0u8; 32];
        let mut random2 = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut premaster);
        rand::rngs::OsRng.fill_bytes(&mut random1);
        rand::rngs::OsRng.fill_bytes(&mut random2);
        Ok(Self {
            premaster,
            random1,
            random2,
            options: install_options(option),
            username: option
                .username
                .as_ref()
                .map(|value| value.expose().to_string())
                .unwrap_or_default(),
            password: option
                .password
                .as_ref()
                .map(|value| value.expose().to_string())
                .unwrap_or_default(),
            peer_info: peer_info(option),
        })
    }

    fn record(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_be_bytes());
        out.push(2);
        out.extend_from_slice(&self.premaster);
        out.extend_from_slice(&self.random1);
        out.extend_from_slice(&self.random2);
        push_string(&mut out, &self.options);
        push_string(&mut out, &self.username);
        push_string(&mut out, &self.password);
        push_string(&mut out, &self.peer_info);
        out
    }
}

fn install_options(option: &OpenVpnOutbound) -> String {
    let primary = option.primary_cipher();
    let keysize = if matches!(primary, "AES-256-GCM" | "AES-256-CBC" | "CHACHA20-POLY1305") {
        "256"
    } else {
        "128"
    };
    let proto = if option.proto == "tcp" {
        "TCPv4_CLIENT"
    } else {
        "UDPv4"
    };
    format!(
        "V4,dev-type tun,link-mtu 1550,tun-mtu 1500,proto {proto},cipher {primary},auth {},keysize {keysize},key-method 2,tls-client",
        option.auth
    )
}

fn peer_info(option: &OpenVpnOutbound) -> String {
    let ciphers = if option.data_ciphers.is_empty() {
        option.cipher.clone()
    } else {
        option.data_ciphers.join(":")
    };
    let mut info = format!("IV_VER=sakullla-openvpn\nIV_PROTO=22\nIV_CIPHERS={ciphers}\n");
    for (key, value) in &option.peer_info {
        if matches!(key.as_str(), "IV_VER" | "IV_PROTO" | "IV_CIPHERS" | "IV_LZO") {
            continue;
        }
        info.push_str(&format!("{key}={value}\n"));
    }
    info
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    if value.is_empty() {
        out.extend_from_slice(&0u16.to_be_bytes());
        return;
    }
    let length = value.len() + 1;
    out.extend_from_slice(&(length as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    out.push(0);
}


struct ServerKeySource {
    random1: [u8; 32],
    random2: [u8; 32],
}

impl ServerKeySource {
    fn parse(buffer: &[u8]) -> Option<(Self, usize)> {
        if buffer.len() < 5 + 64 {
            return None;
        }
        if u32::from_be_bytes(buffer[..4].try_into().ok()?) != 0 {
            return None;
        }
        if buffer[4] & 0x0f != 2 {
            return None;
        }
        let mut offset = 5;
        let random1 = <[u8; 32]>::try_from(&buffer[offset..offset + 32]).ok()?;
        offset += 32;
        let random2 = <[u8; 32]>::try_from(&buffer[offset..offset + 32]).ok()?;
        offset += 32;
        // options + username + password + peer-info strings
        for _ in 0..4 {
            if offset + 2 > buffer.len() {
                return None;
            }
            let length = u16::from_be_bytes([buffer[offset], buffer[offset + 1]]) as usize;
            if offset + 2 + length > buffer.len() {
                return None;
            }
            offset += 2 + length;
        }
        Some((Self { random1, random2 }, offset))
    }
}

fn parse_push_reply(text: &str) -> Result<PushReply, OpenVpnError> {
    let mut reply = PushReply {
        raw: text.to_string(),
        ..PushReply::default()
    };
    for field in text.split(',') {
        let field = field.trim();
        if let Some(value) = field.strip_prefix("PUSH_REPLY") {
            // `PUSH_REPLY` may itself carry a first option in the same record.
            let value = value.trim_start_matches(' ');
            if !value.is_empty() {
                parse_push_field(value, &mut reply);
            }
        } else if let Some(value) = field.strip_prefix("cipher ") {
            reply.cipher = Some(value.trim().to_string());
        } else if let Some(value) = field.strip_prefix("data-ciphers ") {
            reply.data_ciphers = value
                .trim()
                .split(':')
                .map(|value| value.to_string())
                .collect();
        } else if let Some(value) = field.strip_prefix("peer-id ") {
            reply.peer_id = value.trim().parse().ok();
        } else if let Some(value) = field.strip_prefix("ifconfig ") {
            reply.ifconfig = Some(value.trim().to_string());
            parse_push_field(field, &mut reply);
        } else {
            parse_push_field(field, &mut reply);
        }
    }
    if reply.ifconfig.is_none() && !text.starts_with("PUSH_REPLY") {
        return Err(OpenVpnError::Push("not a PUSH_REPLY".to_string()));
    }
    Ok(reply)
}

/// Read one NUL-terminated record until a `PUSH_REPLY` record arrives.
/// Informational records are skipped (the pinned client does the same).
fn read_push_record(
    control: &mut Control,
    tls: &mut ClientConnection,
    deadline: Instant,
    timeout: Duration,
    push_bytes: &mut Vec<u8>,
) -> Result<PushReply, OpenVpnError> {
    loop {
        if Instant::now() >= deadline {
            return Err(OpenVpnError::Timeout(timeout));
        }
        let chunk = control.read_app(tls, Duration::from_millis(100))?;
        push_bytes.extend_from_slice(&chunk);
        let Some(end) = push_bytes.iter().position(|byte| *byte == 0) else {
            continue;
        };
        let text = String::from_utf8_lossy(&push_bytes[..end]).to_string();
        push_bytes.drain(..=end);
        if text.starts_with("AUTH_FAILED") {
            return Err(OpenVpnError::Push(text));
        }
        if text.starts_with("PUSH_REPLY") {
            return parse_push_reply(&text);
        }
        // A leading informational record: keep reading.
    }
}

/// Merge one continuation segment into the first `PUSH_REPLY`.
fn merge_push_reply(into: &mut PushReply, next: PushReply) {
    if next.cipher.is_some() {
        into.cipher = next.cipher;
    }
    if !next.data_ciphers.is_empty() {
        into.data_ciphers = next.data_ciphers;
    }
    if next.peer_id.is_some() {
        into.peer_id = next.peer_id;
    }
    if next.ifconfig.is_some() {
        into.ifconfig = next.ifconfig;
    }
    for prefix in next.prefixes {
        if !into.prefixes.contains(&prefix) {
            into.prefixes.push(prefix);
        }
    }
    for route in next.routes {
        if !into.routes.contains(&route) {
            into.routes.push(route);
        }
    }
    for dns in next.dns {
        if !into.dns.contains(&dns) {
            into.dns.push(dns);
        }
    }
    into.redirect_gateway |= next.redirect_gateway;
    into.block_outside_dns |= next.block_outside_dns;
    into.block_ipv6 |= next.block_ipv6;
    into.auth_token_seen |= next.auth_token_seen;
    into.ping = next.ping.or(into.ping);
    into.ping_restart = next.ping_restart.or(into.ping_restart);
    into.push_continuation = next.push_continuation;
    into.raw.push_str(&next.raw);
}

fn parse_push_field(field: &str, reply: &mut PushReply) {
    let mut parts = field.split_whitespace();
    match parts.next() {
        Some("ifconfig") => {
            let values: Vec<&str> = parts.collect();
            if let Some((addr, bits)) = ifconfig_prefix(&values) {
                reply.prefixes.push((addr, bits));
            }
        }
        Some("ifconfig-ipv6") => {
            let values: Vec<&str> = parts.collect();
            if let Some((addr, bits)) = ifconfig_prefix(&values) {
                reply.prefixes.push((addr, bits));
            }
        }
        Some("route") | Some("route-ipv6") => {
            let values: Vec<&str> = parts.collect();
            if let Some(prefix) = route_prefix(&values) {
                reply.routes.push(prefix);
            }
        }
        Some("dns") => {
            if let Some(value) = parts.next() {
                if let Ok(addr) = value.parse() {
                    reply.dns.push(addr);
                }
            }
        }
        Some("dhcp-option") => {
            // `dhcp-option DNS 10.8.0.1` is the common pushed DNS form.
            let kind = parts.next().unwrap_or_default();
            if kind.eq_ignore_ascii_case("DNS") {
                if let Some(value) = parts.next() {
                    if let Ok(addr) = value.parse() {
                        reply.dns.push(addr);
                    }
                }
            }
        }
        Some("redirect-gateway") => reply.redirect_gateway = true,
        Some("block-outside-dns") => reply.block_outside_dns = true,
        Some("block-ipv6") => reply.block_ipv6 = true,
        Some("push-continuation") => {
            reply.push_continuation = parts
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .map(|value| value != 0)
                .unwrap_or(true)
        }
        Some("auth-token") => reply.auth_token_seen = true,
        Some("ping") => reply.ping = parts.next().and_then(|value| value.parse().ok()),
        Some("ping-restart") => {
            reply.ping_restart = parts.next().and_then(|value| value.parse().ok())
        }
        _ => {}
    }
}

/// `ifconfig <local> <netmask-or-peer>` / `ifconfig-ipv6 <local/len> <peer>`.
/// The second IPv4 field is a netmask only when it is a contiguous mask;
/// otherwise it is the topology-p2p peer address and the local address is a
/// host prefix (`10.211.1.37 10.211.254.254` -> `/32`).
fn ifconfig_prefix(values: &[&str]) -> Option<(std::net::IpAddr, u8)> {
    let local = values.first()?.trim();
    if let Some((addr, bits)) = local.split_once('/') {
        let addr = addr.parse().ok()?;
        let bits = bits.parse().ok()?;
        return Some((addr, bits));
    }
    let addr: std::net::IpAddr = local.parse().ok()?;
    let bits = values
        .get(1)
        .and_then(|mask| mask.parse::<std::net::Ipv4Addr>().ok())
        .and_then(netmask_bits)
        .unwrap_or(if addr.is_ipv4() { 32 } else { 128 });
    Some((addr, bits))
}

fn route_prefix(values: &[&str]) -> Option<(std::net::IpAddr, u8)> {
    let network = values.first()?.trim();
    if let Some((addr, bits)) = network.split_once('/') {
        let addr = addr.parse().ok()?;
        let bits = bits.parse().ok()?;
        return Some((addr, bits));
    }
    let addr: std::net::IpAddr = network.parse().ok()?;
    let bits = if addr.is_ipv4() {
        values
            .get(1)
            .and_then(|mask| mask.parse::<std::net::Ipv4Addr>().ok())
            .and_then(netmask_bits)
            .unwrap_or(32)
    } else {
        128
    };
    Some((addr, bits))
}

/// Prefix length of a contiguous IPv4 netmask, or `None` when the bits have a
/// hole (a peer address is not a netmask).
fn netmask_bits(mask: std::net::Ipv4Addr) -> Option<u8> {
    let value = u32::from(mask);
    let inverted = !value;
    if inverted & inverted.wrapping_add(1) != 0 {
        return None;
    }
    Some(inverted.leading_zeros() as u8)
}

fn negotiate_cipher(option: &OpenVpnOutbound, push: &PushReply) -> Result<String, OpenVpnError> {
    let offered: Vec<String> = if option.data_ciphers.is_empty() {
        vec![option.cipher.clone()]
    } else {
        option.data_ciphers.clone()
    };
    let mut server: Vec<String> = Vec::new();
    if let Some(cipher) = &push.cipher {
        server.push(cipher.to_ascii_uppercase());
    }
    server.extend(push.data_ciphers.iter().map(|value| value.to_ascii_uppercase()));
    if server.is_empty() {
        return Ok(offered[0].clone());
    }
    for candidate in server {
        if offered.iter().any(|value| value == &candidate) {
            return Ok(candidate);
        }
    }
    if let Some(fallback) = &option.data_cipher_fallback {
        if offered.iter().any(|value| value == fallback) {
            return Ok(fallback.clone());
        }
    }
    Err(OpenVpnError::Push(format!(
        "no common data cipher (server: {:?}, client: {:?})",
        push.cipher, offered
    )))
}

fn cipher_key_len(cipher: &str) -> Result<usize, OpenVpnError> {
    match cipher {
        "AES-128-GCM" => Ok(16),
        "AES-192-GCM" => Err(OpenVpnError::Unsupported(
            "AES-192-GCM data cipher (use AES-128-GCM or AES-256-GCM)".to_string(),
        )),
        "AES-256-GCM" | "CHACHA20-POLY1305" => Ok(32),
        other => Err(OpenVpnError::Unsupported(format!(
            "data cipher '{other}'"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Data channel crypto
// ---------------------------------------------------------------------------

fn data_header(peer_id: u32, key_id: u8) -> Vec<u8> {
    if peer_id == PEER_ID_UNSET {
        vec![(OPCODE_DATA_V1 << OPCODE_SHIFT) | (key_id & KEY_ID_MASK)]
    } else {
        vec![
            (OPCODE_DATA_V2 << OPCODE_SHIFT) | (key_id & KEY_ID_MASK),
            (peer_id >> 16) as u8,
            (peer_id >> 8) as u8,
            peer_id as u8,
        ]
    }
}

fn header_len(packet: &[u8]) -> usize {
    if packet.is_empty() {
        return 0;
    }
    if packet[0] >> OPCODE_SHIFT == OPCODE_DATA_V2 {
        4
    } else {
        1
    }
}

fn aead_additional_data(header: &[u8], packet_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 4);
    if header.first().is_some_and(|byte| byte >> OPCODE_SHIFT == OPCODE_DATA_V2) {
        aad.extend_from_slice(header);
    }
    aad.extend_from_slice(packet_id);
    aad
}

fn data_nonce(implicit: [u8; DATA_IV_SIZE], packet_id: u32) -> [u8; DATA_IV_SIZE] {
    let mut nonce = implicit;
    let first = u32::from_be_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]) ^ packet_id;
    nonce[..4].copy_from_slice(&first.to_be_bytes());
    nonce
}

fn aead_encrypt(
    cipher: &str,
    key: &[u8],
    nonce: &[u8; DATA_IV_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    match cipher {
        "AES-128-GCM" => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
            cipher
                .encrypt(nonce.into(), Payload { msg: plaintext, aad })
                .map_err(|_| "encryption failed".to_string())
        }
        "AES-256-GCM" => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
            cipher
                .encrypt(nonce.into(), Payload { msg: plaintext, aad })
                .map_err(|_| "encryption failed".to_string())
        }
        "CHACHA20-POLY1305" => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|error| error.to_string())?;
            cipher
                .encrypt(nonce.into(), Payload { msg: plaintext, aad })
                .map_err(|_| "encryption failed".to_string())
        }
        other => Err(format!("unsupported data cipher '{other}'")),
    }
}

fn aead_decrypt(
    cipher: &str,
    key: &[u8],
    nonce: &[u8; DATA_IV_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    match cipher {
        "AES-128-GCM" => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
            cipher
                .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
                .map_err(|_| "authentication failed".to_string())
        }
        "AES-256-GCM" => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
            cipher
                .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
                .map_err(|_| "authentication failed".to_string())
        }
        "CHACHA20-POLY1305" => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|error| error.to_string())?;
            cipher
                .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
                .map_err(|_| "authentication failed".to_string())
        }
        other => Err(format!("unsupported data cipher '{other}'")),
    }
}

// ---------------------------------------------------------------------------
// PRF (OpenVPN key expansion) and key derivation
// ---------------------------------------------------------------------------

fn derive_keys(
    client: &ClientKeySource,
    server: &ServerKeySource,
    client_session: &[u8; SESSION_ID_SIZE],
    server_session: &[u8; SESSION_ID_SIZE],
    auth: &str,
    cipher_key_len: usize,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), OpenVpnError> {
    let mut master = vec![0u8; 48];
    openvpn_prf(
        &client.premaster,
        "OpenVPN master secret",
        &client.random1,
        &server.random1,
        &[],
        &[],
        &mut master,
    );
    let mut key_block = vec![0u8; 2 * (64 + 64)];
    openvpn_prf(
        &master,
        "OpenVPN key expansion",
        &client.random2,
        &server.random2,
        client_session,
        server_session,
        &mut key_block,
    );
    let client_to_server = &key_block[..128];
    let server_to_client = &key_block[128..];
    let send_cipher = client_to_server[..cipher_key_len].to_vec();
    let send_hmac = client_to_server[64..].to_vec();
    let recv_cipher = server_to_client[..cipher_key_len].to_vec();
    let recv_hmac = server_to_client[64..].to_vec();
    let _ = auth;
    Ok((send_cipher, send_hmac, recv_cipher, recv_hmac))
}

fn openvpn_prf(
    secret: &[u8],
    label: &str,
    client_seed: &[u8],
    server_seed: &[u8],
    client_session: &[u8],
    server_session: &[u8],
    out: &mut [u8],
) {
    let mut seed = Vec::new();
    seed.extend_from_slice(label.as_bytes());
    seed.extend_from_slice(client_seed);
    seed.extend_from_slice(server_seed);
    seed.extend_from_slice(client_session);
    seed.extend_from_slice(server_session);
    let split = secret.len().div_ceil(2);
    let s1 = &secret[..split];
    let s2 = &secret[secret.len() - split..];
    let md5 = phash_md5(s1, &seed, out.len());
    let sha1 = phash_sha1(s2, &seed, out.len());
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = md5[index] ^ sha1[index];
    }
}

fn phash_md5(secret: &[u8], seed: &[u8], size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    let mut a = hmac_md5(secret, seed);
    while out.len() < size {
        let mut input = Vec::with_capacity(a.len() + seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(seed);
        out.extend_from_slice(&hmac_md5(secret, &input));
        a = hmac_md5(secret, &a);
    }
    out.truncate(size);
    out
}

fn phash_sha1(secret: &[u8], seed: &[u8], size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    let mut a = hmac_sha1(secret, seed);
    while out.len() < size {
        let mut input = Vec::with_capacity(a.len() + seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(seed);
        out.extend_from_slice(&hmac_sha1(secret, &input));
        a = hmac_sha1(secret, &a);
    }
    out.truncate(size);
    out
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..16].copy_from_slice(&crate::keys::md5(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + data.len());
    let mut outer = Vec::with_capacity(BLOCK + 16);
    for byte in key_block {
        inner.push(byte ^ 0x36);
        outer.push(byte ^ 0x5c);
    }
    inner.extend_from_slice(data);
    let inner = crate::keys::md5(&inner);
    outer.extend_from_slice(&inner);
    crate::keys::md5(&outer)
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn debug_stage(stage: &str) {
    if std::env::var_os("BILLOW_OPENVPN_DEBUG").is_some() {
        eprintln!("openvpn debug: {stage}");
    }
}

fn random_session() -> [u8; SESSION_ID_SIZE] {
    let mut session = [0u8; SESSION_ID_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut session);
    session
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_packets_round_trip() {
        let session = *b"12345678";
        let packet = encode_control(
            OPCODE_CONTROL_V1,
            2,
            session,
            &[7, 9],
            Some(*b"abcdefgh"),
            Some(11),
            b"tls-bytes",
        );
        let parsed = parse_control(&packet).expect("parse");
        assert_eq!(parsed.opcode, OPCODE_CONTROL_V1);
        assert_eq!(parsed.acks, vec![7, 9]);
        assert_eq!(parsed.remote_session, Some(*b"abcdefgh"));
        assert_eq!(parsed.message_id, Some(11));
        assert_eq!(parsed.payload, b"tls-bytes");
        assert_eq!(parsed.session, session);

        let ack = encode_control(
            OPCODE_ACK_V1,
            0,
            session,
            &[3],
            Some(*b"abcdefgh"),
            None,
            &[],
        );
        let parsed = parse_control(&ack).expect("parse ack");
        assert_eq!(parsed.opcode, OPCODE_ACK_V1);
        assert_eq!(parsed.message_id, None);
    }

    #[test]
    fn prf_is_deterministic_and_sensitive_to_the_label() {
        let secret = [7u8; 48];
        let mut first = [0u8; 128];
        let mut again = [0u8; 128];
        let mut other = [0u8; 128];
        openvpn_prf(&secret, "OpenVPN master secret", &[1u8; 32], &[2u8; 32], &[], &[], &mut first);
        openvpn_prf(&secret, "OpenVPN master secret", &[1u8; 32], &[2u8; 32], &[], &[], &mut again);
        openvpn_prf(&secret, "OpenVPN key expansion", &[1u8; 32], &[2u8; 32], &[], &[], &mut other);
        assert_eq!(first, again);
        assert_ne!(first, other);
        assert_eq!(phash_md5(&secret[..24], b"seed", 128).len(), 128);
        assert_eq!(phash_sha1(&secret[24..], b"seed", 128).len(), 128);
    }

    #[test]
    fn push_reply_parses_cipher_peer_id_and_ifconfig() {
        let reply = parse_push_reply(
            "PUSH_REPLY,route 10.8.0.0 255.255.255.0,topology net30,ping 1,ifconfig 10.8.0.6 10.8.0.5,peer-id 3,cipher AES-256-GCM",
        )
        .expect("parse");
        assert_eq!(reply.peer_id, Some(3));
        assert_eq!(reply.cipher.as_deref(), Some("AES-256-GCM"));
        assert_eq!(reply.ifconfig.as_deref(), Some("10.8.0.6 10.8.0.5"));
        // The peer address in a p2p topology is not a netmask.
        assert_eq!(
            reply.prefixes,
            vec![(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 6)), 32)]
        );
        assert_eq!(
            reply.routes,
            vec![(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 0)),
                24
            )]
        );
    }

    #[test]
    fn push_reply_derives_prefixes_ipv6_dns_and_redirect() {
        let reply = parse_push_reply(
            "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,ifconfig-ipv6 fd00::2/64 fd00::1,route-ipv6 2000::/3,dns 10.8.0.1,redirect-gateway def1,block-outside-dns",
        )
        .expect("parse");
        assert_eq!(
            reply.prefixes,
            vec![
                (std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 2)), 24),
                (std::net::IpAddr::V6(std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)), 64),
            ]
        );
        assert_eq!(
            reply.routes,
            vec![(
                std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0)),
                3
            )]
        );
        assert_eq!(
            reply.dns,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 1))]
        );
        assert!(reply.redirect_gateway);
        assert!(reply.block_outside_dns);
    }

    #[test]
    fn push_reply_reads_the_pinned_timer_and_dhcp_records() {
        let reply = parse_push_reply(
            "PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DNS 10.8.0.2,block-ipv6,push-continuation,auth-token session-1,ping 10,ping-restart 60,ifconfig 10.8.0.2 255.255.255.0",
        )
        .expect("parse");
        assert_eq!(reply.dns.len(), 2);
        assert_eq!(
            reply.dns[0],
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 1))
        );
        assert!(reply.block_ipv6);
        assert!(reply.push_continuation);
        assert!(reply.auth_token_seen);
        assert_eq!(reply.ping, Some(10));
        assert_eq!(reply.ping_restart, Some(60));
    }

    #[test]
    fn multi_segment_push_reply_accumulates_options() {
        let mut first = parse_push_reply(
            "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,push-continuation 1",
        )
        .expect("first segment");
        assert!(first.push_continuation);
        let second = parse_push_reply(
            "PUSH_REPLY,route 10.9.0.0 255.255.255.0,dhcp-option DNS 10.8.0.1,ping 10,ping-restart 60,block-ipv6,push-continuation 0",
        )
        .expect("second segment");
        merge_push_reply(&mut first, second);
        assert!(!first.push_continuation);
        assert_eq!(
            first.prefixes,
            vec![(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 2)), 24)]
        );
        assert_eq!(first.routes.len(), 1);
        assert_eq!(first.dns.len(), 1);
        assert_eq!(first.ping, Some(10));
        assert_eq!(first.ping_restart, Some(60));
        assert!(first.block_ipv6);
        assert!(first.raw.contains("10.9.0.0"));
    }

    #[test]
    fn keepalive_timers_produce_ping_and_restart_actions() {
        let start = Instant::now();
        assert_eq!(
            keepalive_action(start, start, start, 10, 60),
            KeepaliveAction::None
        );
        assert_eq!(
            keepalive_action(
                start + Duration::from_secs(10),
                start + Duration::from_secs(1),
                start,
                10,
                60
            ),
            KeepaliveAction::SendPing
        );
        assert_eq!(
            keepalive_action(
                start + Duration::from_secs(60),
                start,
                start + Duration::from_secs(59),
                10,
                60
            ),
            KeepaliveAction::Restart,
            "ping-restart wins over an outgoing keepalive"
        );
        assert_eq!(
            keepalive_action(start + Duration::from_secs(600), start, start, 0, 0),
            KeepaliveAction::None,
            "zero disables both timers"
        );
    }

    #[test]
    fn tcp_frame_buffer_reassembles_across_partial_reads() {
        let mut frames = FrameBuffer::new();
        // Length prefix only, then half of the payload: no frame yet.
        frames.push(&[0, 5, 1]);
        assert_eq!(frames.next_frame(), None);
        frames.push(&[2]);
        assert_eq!(frames.next_frame(), None);
        frames.push(&[3, 4, 5, 0, 2, 9, 8]);
        assert_eq!(frames.next_frame(), Some(vec![1, 2, 3, 4, 5]));
        assert_eq!(frames.next_frame(), Some(vec![9, 8]));
        assert_eq!(frames.next_frame(), None);
        // A zero-length frame is valid and consumed atomically.
        frames.push(&[0, 0, 0, 1, 7]);
        assert_eq!(frames.next_frame(), Some(Vec::new()));
        assert_eq!(frames.next_frame(), Some(vec![7]));
    }

    #[test]
    fn replay_window_rejects_duplicates_and_old_ids() {
        let mut tunnel = TestWindow::default();
        assert!(tunnel.accept(0));
        assert!(!tunnel.accept(0));
        assert!(tunnel.accept(2));
        assert!(tunnel.accept(1));
        assert!(!tunnel.accept(1));
        assert!(tunnel.accept(1_000_000));
        assert!(!tunnel.accept(999_000));
    }

    #[derive(Default)]
    struct TestWindow {
        seen: bool,
        highest: u32,
        window: u64,
    }

    impl TestWindow {
        fn accept(&mut self, id: u32) -> bool {
            if !self.seen {
                self.seen = true;
                self.highest = id;
                self.window = 1;
                return true;
            }
            if id > self.highest {
                let shift = id - self.highest;
                self.window = if shift >= 64 {
                    1
                } else {
                    (self.window << shift) | 1
                };
                self.highest = id;
                return true;
            }
            let behind = self.highest - id;
            if behind >= 64 {
                return false;
            }
            let mask = 1u64 << behind;
            if self.window & mask != 0 {
                return false;
            }
            self.window |= mask;
            true
        }
    }
}
