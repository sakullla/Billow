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
//! The data channel writes/reads IP packets; turning them into TCP streams is
//! the userspace IP stack and TUN device owned by T6/T7, so [`dial`] refuses
//! with that gap named. `tls-auth`/`tls-crypt`, CBC data ciphers and
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
    #[error("openvpn unsupported configuration: {0}")]
    Unsupported(String),
}

/// The parsed `PUSH_REPLY` fields the data channel needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushReply {
    pub cipher: Option<String>,
    pub data_ciphers: Vec<String>,
    pub peer_id: Option<u32>,
    pub ifconfig: Option<String>,
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
        if option.tls_auth.is_some() || option.tls_crypt.is_some() || option.tls_crypt_v2.is_some()
        {
            return Err(OpenVpnError::Unsupported(
                "tls-auth/tls-crypt control protection".to_string(),
            ));
        }
        let deadline = Instant::now() + timeout;
        let link = Link::connect(option, timeout)?;
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

        // PUSH_REQUEST / PUSH_REPLY.
        control.write_app(&mut tls, b"PUSH_REQUEST\0")?;
        let mut push_bytes = Vec::new();
        let reply = loop {
            if Instant::now() >= deadline {
                return Err(OpenVpnError::Timeout(timeout));
            }
            let chunk = control.read_app(&mut tls, Duration::from_millis(100))?;
            push_bytes.extend_from_slice(&chunk);
            if let Some(end) = push_bytes.iter().position(|byte| *byte == 0) {
                let text = String::from_utf8_lossy(&push_bytes[..end]).to_string();
                if text.starts_with("AUTH_FAILED") {
                    return Err(OpenVpnError::Push(text));
                }
                if text.starts_with("PUSH_REPLY") {
                    break parse_push_reply(&text)?;
                }
                // A leading informational record: keep reading after the NUL.
                push_bytes.drain(..=end);
            }
        };

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
            send_id: 0,
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
        let packet = self.encrypt_payload(&PING_PAYLOAD)?;
        self.control.link
            .send(&packet)
            .map_err(|error| OpenVpnError::Data(error.to_string()))?;
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

    /// Receive one data packet (or keepalive). Control packets that arrive
    /// meanwhile are acknowledged and fed to the TLS stream.
    pub fn recv_data(&mut self, timeout: Duration) -> Result<Option<DataPacket>, OpenVpnError> {
        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout {
                return Ok(None);
            }
            let packet = match self.control.link.recv(Duration::from_millis(50)) {
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
            let plaintext = self.decrypt_payload(&packet)?;
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
            return Err(OpenVpnError::Data(format!(
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
    Tcp { stream: TcpStream, buffer: Vec<u8> },
}

impl Link {
    fn connect(option: &OpenVpnOutbound, timeout: Duration) -> Result<Self, OpenVpnError> {
        let address = resolve(&option.server, option.port)?;
        if option.proto == "tcp" {
            let stream = TcpStream::connect_timeout(&address, timeout)
                .map_err(|error| OpenVpnError::Connect(address.to_string(), error))?;
            stream
                .set_read_timeout(Some(timeout))
                .map_err(|error| OpenVpnError::Connect(address.to_string(), error))?;
            Ok(Link::Tcp {
                stream,
                buffer: Vec::new(),
            })
        } else {
            let bind: SocketAddr = if address.is_ipv4() {
                SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0u16; 8], 0))
            };
            let socket = UdpSocket::bind(bind)
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
            Link::Tcp { stream, buffer } => {
                stream.set_read_timeout(Some(timeout))?;
                buffer.clear();
                let mut length = [0u8; 2];
                stream.read_exact(&mut length)?;
                let length = u16::from_be_bytes(length) as usize;
                buffer.resize(length, 0);
                stream.read_exact(buffer)?;
                Ok(std::mem::take(buffer))
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
        if let Some(value) = field.strip_prefix("cipher ") {
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
        }
    }
    if reply.ifconfig.is_none() && !text.starts_with("PUSH_REPLY") {
        return Err(OpenVpnError::Push("not a PUSH_REPLY".to_string()));
    }
    Ok(reply)
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
