//! Tailscale control-plane and DERP protocol adapter (T19).
//!
//! Implemented from Tailscale's public 2021 control protocol and DERP wire
//! protocol, verified against controlled peers built from the locked
//! `github.com/metacubex/tailscale` module (BSD-3-Clause, test-only):
//!
//! * the control base transport: Noise IK (`Noise_IK_25519_ChaChaPoly_BLAKE2s`)
//!   with Tailscale's protocol-version prologue, the 101-byte initiation,
//!   51-byte response and the 4096-byte record framing;
//! * the HTTP/1.1 `POST /ts2021` upgrade carrying the initiation in
//!   `X-Tailscale-Handshake`, then an HTTP/2 request over the Noise stream;
//! * the DERP client handshake (`DERP🔑` server key frame, NaCl-boxed client
//!   info), frame codec, ping/pong and send/recv packet framing.
//!
//! The pinned adapter embeds `tsnet` and a userspace netstack. The netstack,
//! TUN device and the WireGuard data path's TCP/UDP sockets remain T6/T7, so
//! `dial()` names that gap while the control/DERP layers below are available.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use blake2::digest::{Digest, KeyInit as _};
use blake2::Blake2s256;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use http::Uri;
use poly1305::{Poly1305, Tag};
use rand::RngCore;
use salsa20::cipher::{KeyIvInit, StreamCipher};
use salsa20::{hsalsa, Key as SalsaKey, XNonce, XSalsa20};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

use super::tls::{client_config, ClientTls};
use crate::proxies::TlsSettings;

const PROTOCOL_NAME: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROTOCOL_PREFIX: &str = "Tailscale Control Protocol v";
const MAX_CONTROL_MESSAGE: usize = 4096;
const HEADER_LEN: usize = 3;
const INITIATION_LEN: usize = 101;
const RESPONSE_LEN: usize = 51;

#[derive(Debug, thiserror::Error)]
pub enum TailscaleError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out")]
    Timeout,
    #[error("HTTP upgrade rejected: {0}")]
    Upgrade(String),
    #[error("control handshake failed: {0}")]
    Handshake(&'static str),
    #[error("control authentication failed")]
    Authentication,
    #[error("control record exceeds 4096 bytes")]
    RecordTooLarge,
    #[error("HTTP/2 control request failed: {0}")]
    Http2(String),
    #[error("invalid control URL")]
    Url,
    #[error("DERP protocol error: {0}")]
    Derp(&'static str),
    #[error("DERP authentication failed")]
    DerpAuthentication,
}

fn hash(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Blake2s256::digest(data));
    out
}

fn mix_hash(state: &mut [u8; 32], data: &[u8]) {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, &state[..]);
    Digest::update(&mut hasher, data);
    state.copy_from_slice(&hasher.finalize());
}

fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    // Standard HMAC with BLAKE2s (64-byte block); the keyed BLAKE2s MAC is a
    // different construction and would not match the control protocol.
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Blake2s256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    for byte in &block {
        inner.push(byte ^ 0x36);
    }
    inner.extend_from_slice(data);
    let inner_hash = Blake2s256::digest(&inner);
    let mut outer = Vec::with_capacity(64 + 32);
    for byte in &block {
        outer.push(byte ^ 0x5c);
    }
    outer.extend_from_slice(&inner_hash);
    Blake2s256::digest(&outer).into()
}

/// HKDF-Expand (RFC 5869) for a 32-byte PRK and 32-byte outputs.
fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < length {
        let mut input = Vec::with_capacity(previous.len() + info.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(info);
        input.push(counter);
        let block = hmac_blake2s(prk, &input);
        out.extend_from_slice(&block);
        previous = block.to_vec();
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    out
}

fn mix_key(ck: &mut [u8; 32], shared: &[u8; 32]) -> [u8; 32] {
    // RFC 5869 with the chaining key as salt: HKDF-Extract(ck, shared) then
    // Expand to the next chaining key and one cipher key.
    let prk = hmac_blake2s(ck, shared);
    let okm = hkdf_expand(&prk, &[], 64);
    ck.copy_from_slice(&okm[..32]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[32..]);
    key
}

fn encrypt_and_hash(
    state: &mut [u8; 32],
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, TailscaleError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: state })
        .map_err(|_| TailscaleError::Handshake("encrypt"))?;
    mix_hash(state, &ciphertext);
    Ok(ciphertext)
}

fn decrypt_and_hash(
    state: &mut [u8; 32],
    key: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, TailscaleError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let plaintext = cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad: state })
        .map_err(|_| TailscaleError::Authentication)?;
    mix_hash(state, ciphertext);
    Ok(plaintext)
}

/// The 101-byte Noise IK initiation for the given protocol version.
pub fn initiation(
    machine_private: &[u8; 32],
    control_public: &[u8; 32],
    protocol_version: u16,
) -> Result<([u8; INITIATION_LEN], NoiseHandshake), TailscaleError> {
    let machine = StaticSecret::from(*machine_private);
    let machine_public = PublicKey::from(&machine);
    let control = PublicKey::from(*control_public);
    let ephemeral = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral);

    let mut state = hash(PROTOCOL_NAME.as_bytes());
    let mut ck = state;
    let prologue = format!("{PROTOCOL_PREFIX}{protocol_version}");
    mix_hash(&mut state, prologue.as_bytes());
    mix_hash(&mut state, control.as_bytes());
    mix_hash(&mut state, ephemeral_public.as_bytes());
    let shared = ephemeral.diffie_hellman(&control);
    let key = mix_key(&mut ck, shared.as_bytes());
    let encrypted_static = encrypt_and_hash(&mut state, &key, machine_public.as_bytes())?;
    let shared = machine.diffie_hellman(&control);
    let key = mix_key(&mut ck, shared.as_bytes());
    let empty = encrypt_and_hash(&mut state, &key, &[])?;

    let mut message = [0u8; INITIATION_LEN];
    message[..2].copy_from_slice(&protocol_version.to_be_bytes());
    message[2] = 1;
    message[3..5].copy_from_slice(&(96u16).to_be_bytes());
    message[5..37].copy_from_slice(ephemeral_public.as_bytes());
    message[37..37 + encrypted_static.len()].copy_from_slice(&encrypted_static);
    message[85..].copy_from_slice(&empty);
    Ok((
        message,
        NoiseHandshake {
            state,
            ck,
            machine_private: *machine_private,
            machine_ephemeral: ephemeral,
            control_public: *control_public,
            protocol_version,
        },
    ))
}

/// State retained between the initiation and the server response.
pub struct NoiseHandshake {
    state: [u8; 32],
    ck: [u8; 32],
    machine_private: [u8; 32],
    machine_ephemeral: StaticSecret,
    control_public: [u8; 32],
    protocol_version: u16,
}

impl NoiseHandshake {
    /// Consume the 51-byte response and split the transport keys.
    pub fn finish(mut self, response: &[u8; RESPONSE_LEN]) -> Result<NoiseTransport, TailscaleError> {
        if response[0] != 2 || u16::from_be_bytes([response[1], response[2]]) != 48 {
            return Err(TailscaleError::Handshake("response header"));
        }
        let server_ephemeral = PublicKey::from(<[u8; 32]>::try_from(&response[3..35]).unwrap());
        mix_hash(&mut self.state, server_ephemeral.as_bytes());
        let shared = self.machine_ephemeral.diffie_hellman(&server_ephemeral);
        let _ee_key = mix_key(&mut self.ck, shared.as_bytes());
        let machine = StaticSecret::from(self.machine_private);
        let shared = machine.diffie_hellman(&server_ephemeral);
        let key = mix_key(&mut self.ck, shared.as_bytes());
        decrypt_and_hash(&mut self.state, &key, &response[35..])?;
        let prk = hmac_blake2s(&self.ck, &[]);
        let okm = hkdf_expand(&prk, &[], 64);
        let mut tx = [0u8; 32];
        let mut rx = [0u8; 32];
        tx.copy_from_slice(&okm[..32]);
        rx.copy_from_slice(&okm[32..]);
        let _ = self.control_public;
        let _ = self.protocol_version;
        Ok(NoiseTransport { tx, rx })
    }
}

/// Transport keys after a completed control handshake.
pub struct NoiseTransport {
    tx: [u8; 32],
    rx: [u8; 32],
}

/// Encrypt a control record: `[type=4][len u16 BE][ciphertext]`.
pub fn encode_record(transport: &NoiseTransport, counter: &mut u64, plaintext: &[u8]) -> Result<Vec<u8>, TailscaleError> {
    if plaintext.len() + 16 > MAX_CONTROL_MESSAGE - HEADER_LEN {
        return Err(TailscaleError::RecordTooLarge);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&transport.tx));
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| TailscaleError::Handshake("record encrypt"))?;
    *counter += 1;
    let mut out = Vec::with_capacity(3 + ciphertext.len());
    out.push(4);
    out.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_record(transport: &NoiseTransport, counter: &mut u64, ciphertext: &[u8]) -> Result<Vec<u8>, TailscaleError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&transport.rx));
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| TailscaleError::Authentication)?;
    *counter += 1;
    Ok(plaintext)
}

/// An established Tailscale control connection.
pub struct TailscaleControl {
    stream: DuplexStream,
    pub host: String,
}

impl TailscaleControl {
    /// Open a control connection: dial, perform the HTTP/1.1 upgrade, complete
    /// Noise IK and expose the stream as plaintext HTTP/2 bytes.
    pub async fn connect(
        control_url: &str,
        machine_private: [u8; 32],
        control_public: [u8; 32],
        protocol_version: u16,
        timeout: Duration,
        tls: &ClientTls,
    ) -> Result<Self, TailscaleError> {
        let uri: Uri = control_url.parse().map_err(|_| TailscaleError::Url)?;
        let scheme = uri.scheme_str().unwrap_or("http");
        let host = uri.host().ok_or(TailscaleError::Url)?.to_string();
        let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
        let address = tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), port)))
            .await
            .map_err(|_| TailscaleError::Timeout)??;
        let stream: BoxStream = if scheme == "https" {
            let settings = TlsSettings {
                sni: Some(host.clone()),
                ..TlsSettings::default()
            };
            let config = client_config(&settings, tls)?;
            let connector = tokio_rustls::TlsConnector::from(config);
            let server_name = rustls_pki_types::ServerName::try_from(host.clone())
                .map_err(|_| TailscaleError::Url)?;
            let tls = connector
                .connect(server_name, address)
                .await
                .map_err(TailscaleError::Io)?;
            Box::new(tls)
        } else {
            Box::new(address)
        };

        let (message, handshake) = initiation(&machine_private, &control_public, protocol_version)?;
        let mut stream = BufReader::new(stream);
        let path = if uri.path().is_empty() || uri.path() == "/" { "/ts2021" } else { uri.path() };
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\nX-Tailscale-Handshake: {}\r\nContent-Length: 0\r\n\r\n",
            super::base64(&message)
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut status = String::new();
        tokio::time::timeout(timeout, read_line(&mut stream, &mut status))
            .await
            .map_err(|_| TailscaleError::Timeout)??;
        if !status.starts_with("HTTP/1.1 101") && !status.starts_with("HTTP/1.0 101") {
            return Err(TailscaleError::Upgrade(status.trim().to_string()));
        }
        let mut upgrade = false;
        loop {
            let mut line = String::new();
            tokio::time::timeout(timeout, read_line(&mut stream, &mut line))
                .await
                .map_err(|_| TailscaleError::Timeout)??;
            if line == "\r\n" || line.is_empty() {
                break;
            }
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("upgrade:") && lower.contains("tailscale-control-protocol") {
                upgrade = true;
            }
        }
        if !upgrade {
            return Err(TailscaleError::Upgrade("missing Upgrade header".to_string()));
        }
        let mut response = [0u8; RESPONSE_LEN];
        tokio::time::timeout(timeout, stream.read_exact(&mut response))
            .await
            .map_err(|_| TailscaleError::Timeout)??;
        let transport = handshake.finish(&response)?;
        let (plain_client, server_side) = tokio::io::duplex(64 * 1024);
        let (mut network_read, mut network_write) = tokio::io::split(stream);
        let (mut plain_read, mut plain_write) = tokio::io::split(server_side);
        let mut tx_counter = 0u64;
        let mut rx_counter = 0u64;
        let transport = Arc::new(transport);
        let writer_transport = transport.clone();
        tokio::spawn(async move {
            loop {
                let mut buffer = vec![0u8; 16 * 1024];
                let n = match plain_read.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                match encode_record(&writer_transport, &mut tx_counter, &buffer[..n]) {
                    Ok(record) => {
                        if network_write.write_all(&record).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = network_write.shutdown().await;
        });
        tokio::spawn(async move {
            loop {
                let mut header = [0u8; HEADER_LEN];
                if network_read.read_exact(&mut header).await.is_err() {
                    break;
                }
                if header[0] != 4 {
                    break;
                }
                let length = u16::from_be_bytes([header[1], header[2]]) as usize;
                if length > MAX_CONTROL_MESSAGE - HEADER_LEN {
                    break;
                }
                let mut ciphertext = vec![0u8; length];
                if network_read.read_exact(&mut ciphertext).await.is_err() {
                    break;
                }
                let Ok(plaintext) = decrypt_record(&transport, &mut rx_counter, &ciphertext) else {
                    break;
                };
                if plain_write.write_all(&plaintext).await.is_err() {
                    break;
                }
            }
            let _ = plain_write.shutdown().await;
        });
        Ok(TailscaleControl {
            stream: plain_client,
            host,
        })
    }

    /// POST a JSON body over the control stream's HTTP/2 connection.
    pub async fn post_json(
        self,
        path: &str,
        body: &str,
        timeout: Duration,
    ) -> Result<(u16, Vec<u8>), TailscaleError> {
        let (mut sender, connection) = h2::client::handshake(self.stream)
            .await
            .map_err(|e| TailscaleError::Http2(e.to_string()))?;
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        let uri = format!("https://{}{}", self.host, path)
            .parse::<Uri>()
            .map_err(|_| TailscaleError::Url)?;
        let request = http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(())
            .map_err(|_| TailscaleError::Url)?;
        let (response, mut send) = tokio::time::timeout(timeout, async {
            sender.send_request(request, false)
        })
        .await
        .map_err(|_| TailscaleError::Timeout)?
        .map_err(|e| TailscaleError::Http2(e.to_string()))?;
        send.send_data(bytes::Bytes::copy_from_slice(body.as_bytes()), true)
            .map_err(|e| TailscaleError::Http2(e.to_string()))?;
        let response = tokio::time::timeout(timeout, response)
            .await
            .map_err(|_| TailscaleError::Timeout)?
            .map_err(|e| TailscaleError::Http2(e.to_string()))?;
        let status = response.status().as_u16();
        let mut body_stream = response.into_body();
        let mut out = Vec::new();
        loop {
            match tokio::time::timeout(timeout, body_stream.data()).await {
                Ok(Some(Ok(chunk))) => {
                    out.extend_from_slice(&chunk);
                    if out.len() > 1 << 20 {
                        break;
                    }
                }
                Ok(Some(Err(e))) => return Err(TailscaleError::Http2(e.to_string())),
                Ok(None) | Err(_) => break,
            }
        }
        connection.abort();
        Ok((status, out))
    }
}

/// Small object-safe bound so HTTP and HTTPS streams share one type.
pub type BoxStream = Box<dyn super::Stream>;

async fn read_line(stream: &mut BufReader<BoxStream>, out: &mut String) -> io::Result<()> {
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        out.push(byte[0] as char);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(())
}

/// DERP frame types used by this adapter.
pub mod derp {
    pub const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";
    pub const FRAME_SERVER_KEY: u8 = 0x01;
    pub const FRAME_CLIENT_INFO: u8 = 0x02;
    pub const FRAME_SERVER_INFO: u8 = 0x03;
    pub const FRAME_SEND_PACKET: u8 = 0x04;
    pub const FRAME_RECV_PACKET: u8 = 0x05;
    pub const FRAME_KEEP_ALIVE: u8 = 0x06;
    pub const FRAME_PING: u8 = 0x12;
    pub const FRAME_PONG: u8 = 0x13;
    pub const PROTOCOL_VERSION: u32 = 2;
    pub const NONCE_LEN: usize = 24;
}

/// A DERP client after the server-key/client-info handshake.
pub struct DerpClient {
    read: tokio::io::ReadHalf<BoxStream>,
    write: tokio::io::WriteHalf<BoxStream>,
    pub server_public: [u8; 32],
    pub client_public: [u8; 32],
}

impl DerpClient {
    /// Connect to a plain TCP DERP endpoint and perform the client handshake.
    pub async fn connect(
        stream: BoxStream,
        client_private: [u8; 32],
        expected_server: Option<[u8; 32]>,
        timeout: Duration,
    ) -> Result<Self, TailscaleError> {
        let mut stream = BufReader::new(stream);
        let request = "GET /derp HTTP/1.1\r\nHost: derp\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut status = String::new();
        tokio::time::timeout(timeout, read_line(&mut stream, &mut status))
            .await
            .map_err(|_| TailscaleError::Timeout)??;
        if !status.starts_with("HTTP/1.1 101") {
            return Err(TailscaleError::Derp("upgrade rejected"));
        }
        loop {
            let mut line = String::new();
            tokio::time::timeout(timeout, read_line(&mut stream, &mut line))
                .await
                .map_err(|_| TailscaleError::Timeout)??;
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }
        let (kind, body) = read_derp_frame_reader(&mut stream, timeout).await?;
        if kind != derp::FRAME_SERVER_KEY || body.len() < 40 || &body[..8] != derp::MAGIC {
            return Err(TailscaleError::Derp("bad server key frame"));
        }
        let server_public: [u8; 32] = body[8..40].try_into().unwrap();
        if let Some(expected) = expected_server {
            if expected != server_public {
                return Err(TailscaleError::DerpAuthentication);
            }
        }
        let client_secret = StaticSecret::from(client_private);
        let client_public = PublicKey::from(&client_secret).to_bytes();
        let info = format!(
            "{{\"Version\":{},\"CanAckPings\":true,\"AppName\":\"billow-kernel\"}}",
            derp::PROTOCOL_VERSION
        );
        let sealed = box_seal(&client_private, &server_public, info.as_bytes());
        let mut body = Vec::with_capacity(32 + sealed.len());
        body.extend_from_slice(&client_public);
        body.extend_from_slice(&sealed);
        let mut header = vec![derp::FRAME_CLIENT_INFO];
        header.extend_from_slice(&(body.len() as u32).to_be_bytes());
        header.extend_from_slice(&body);
        stream.write_all(&header).await?;
        stream.flush().await?;
        let (read, write) = tokio::io::split(stream.into_inner());
        Ok(DerpClient {
            read,
            write,
            server_public,
            client_public,
        })
    }

    pub async fn ping(&mut self, data: [u8; 8], timeout: Duration) -> Result<[u8; 8], TailscaleError> {
        let mut frame = vec![derp::FRAME_PING];
        frame.extend_from_slice(&8u32.to_be_bytes());
        frame.extend_from_slice(&data);
        self.write.write_all(&frame).await?;
        self.write.flush().await?;
        loop {
            let (kind, body) = self.read_frame(timeout).await?;
            match kind {
                derp::FRAME_PONG if body.len() >= 8 => {
                    return Ok(body[..8].try_into().unwrap());
                }
                derp::FRAME_PING => {
                    let mut pong = vec![derp::FRAME_PONG];
                    pong.extend_from_slice(&(body.len() as u32).to_be_bytes());
                    pong.extend_from_slice(&body);
                    self.write.write_all(&pong).await?;
                }
                _ => {}
            }
        }
    }

    pub async fn send_packet(&mut self, destination: [u8; 32], packet: &[u8]) -> Result<(), TailscaleError> {
        let mut body = Vec::with_capacity(32 + packet.len());
        body.extend_from_slice(&destination);
        body.extend_from_slice(packet);
        let mut frame = vec![derp::FRAME_SEND_PACKET];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        self.write.write_all(&frame).await?;
        self.write.flush().await?;
        Ok(())
    }

    pub async fn read_frame(&mut self, timeout: Duration) -> Result<(u8, Vec<u8>), TailscaleError> {
        let mut header = [0u8; 5];
        tokio::time::timeout(timeout, self.read.read_exact(&mut header))
            .await
            .map_err(|_| TailscaleError::Timeout)??;
        let kind = header[0];
        let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if length > 1 << 20 {
            return Err(TailscaleError::Derp("frame too large"));
        }
        let mut body = vec![0u8; length];
        tokio::time::timeout(timeout, self.read.read_exact(&mut body))
            .await
            .map_err(|_| TailscaleError::Timeout)??;
        Ok((kind, body))
    }
}

async fn read_derp_frame_reader(
    stream: &mut BufReader<BoxStream>,
    timeout: Duration,
) -> Result<(u8, Vec<u8>), TailscaleError> {
    let mut header = [0u8; 5];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| TailscaleError::Timeout)??;
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if length > 1 << 20 {
        return Err(TailscaleError::Derp("frame too large"));
    }
    let mut body = vec![0u8; length];
    tokio::time::timeout(timeout, stream.read_exact(&mut body))
        .await
        .map_err(|_| TailscaleError::Timeout)??;
    Ok((header[0], body))
}

fn before_nm(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private);
    let peer = PublicKey::from(*public);
    let shared = secret.diffie_hellman(&peer);
    let key = SalsaKey::from(*shared.as_bytes());
    let zero = [0u8; 16];
    let subkey = hsalsa::<typenum::U10>(&key, (&zero).into());
    let mut out = [0u8; 32];
    out.copy_from_slice(&subkey);
    out
}

/// NaCl `crypto_box` (X25519 + HSalsa20 + XSalsa20-Poly1305), returning
/// `nonce || tag || ciphertext` as Tailscale's `SealTo` does.
pub fn box_seal(private: &[u8; 32], public: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let shared = before_nm(private, public);
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut stream = vec![0u8; 32 + message.len()];
    let mut cipher = XSalsa20::new(&SalsaKey::from(shared), &XNonce::from(nonce));
    cipher.apply_keystream(&mut stream);
    let poly_key = &stream[..32];
    let mut ciphertext = Vec::with_capacity(message.len());
    for (i, byte) in message.iter().enumerate() {
        ciphertext.push(byte ^ stream[32 + i]);
    }
    let tag = poly1305_tag(poly_key, &ciphertext);
    let mut out = Vec::with_capacity(24 + 16 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    out
}

/// NaCl `crypto_box_open` for `nonce || tag || ciphertext`.
pub fn box_open(private: &[u8; 32], public: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 24 + 16 {
        return None;
    }
    let shared = before_nm(private, public);
    let nonce: [u8; 24] = sealed[..24].try_into().ok()?;
    let tag: [u8; 16] = sealed[24..40].try_into().ok()?;
    let ciphertext = &sealed[40..];
    let mut stream = vec![0u8; 32 + ciphertext.len()];
    let mut cipher = XSalsa20::new(&SalsaKey::from(shared), &XNonce::from(nonce));
    cipher.apply_keystream(&mut stream);
    if poly1305_tag(&stream[..32], ciphertext) != tag {
        return None;
    }
    Some(
        ciphertext
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ stream[32 + i])
            .collect(),
    )
}

fn poly1305_tag(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mac = Poly1305::new(poly1305::Key::from_slice(key));
    let tag: Tag = mac.compute_unpadded(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    out
}

/// A helper for tests and the device layer: the DERP server key frame body.
pub fn derp_server_key_body(public: &[u8; 32], info: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(40 + info.len());
    body.extend_from_slice(derp::MAGIC);
    body.extend_from_slice(public);
    body.extend_from_slice(info.as_bytes());
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nacl_box_roundtrips_and_rejects_tampering() {
        let alice = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let alice_private = alice.to_bytes();
        let bob_private = bob.to_bytes();
        let alice_public = PublicKey::from(&alice).to_bytes();
        let bob_public = PublicKey::from(&bob).to_bytes();
        let sealed = box_seal(&alice_private, &bob_public, b"client-info");
        assert_eq!(
            box_open(&bob_private, &alice_public, &sealed).unwrap(),
            b"client-info"
        );
        let mut tampered = sealed;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(box_open(&bob_private, &alice_public, &tampered).is_none());
    }

    #[test]
    fn control_records_use_the_pinned_framing() {
        let transport = NoiseTransport {
            tx: [7u8; 32],
            rx: [7u8; 32],
        };
        let mut tx = 0u64;
        let record = encode_record(&transport, &mut tx, b"hello").unwrap();
        assert_eq!(record[0], 4);
        assert_eq!(u16::from_be_bytes([record[1], record[2]]) as usize, record.len() - 3);
        let mut rx = 0u64;
        assert_eq!(decrypt_record(&transport, &mut rx, &record[3..]).unwrap(), b"hello");
        let mut tampered = record;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decrypt_record(&transport, &mut rx, &tampered[3..]).is_err());
    }

    #[test]
    fn initiation_has_the_pinned_header() {
        let machine = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let control = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let (message, _) = initiation(
            &machine.to_bytes(),
            &PublicKey::from(&control).to_bytes(),
            39,
        )
        .unwrap();
        assert_eq!(&message[..2], &39u16.to_be_bytes());
        assert_eq!(message[2], 1);
        assert_eq!(u16::from_be_bytes([message[3], message[4]]), 96);
    }

    #[test]
    fn derp_server_key_body_starts_with_the_magic() {
        let body = derp_server_key_body(&[9u8; 32], "{}");
        assert_eq!(&body[..8], derp::MAGIC);
        assert_eq!(body.len(), 42);
        assert_eq!(body[8], 9);
    }
}
