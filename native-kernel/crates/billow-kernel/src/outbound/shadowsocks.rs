//! Shadowsocks AEAD 2017 (SIP004) TCP client stream and UDP packet codec.
//!
//! TCP, exactly as the pinned Mihomo's `transport/shadowsocks/shadowaead`
//! `Writer`/`Reader` lay it out: `salt || chunk || chunk ...`, where one chunk
//! is two sealed records under consecutive nonces -
//! `AEAD_seal(nonce, u16-BE length)` then `AEAD_seal(nonce + 1, payload)`,
//! AAD empty, nonce incremented little-endian (SIP004). The salt is `key_len`
//! bytes and the first payload chunk carries the target address, so the server
//! sees the destination before any tunneled bytes.
//! UDP: `salt || sealed(datagram)`; the datagram starts with the SOCKS5-style
//! target address, so a UDP association reuses [`SocksAddr`](super::SocksAddr).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes::Aes192;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use rand::RngCore;
use std::task::Poll as StdPoll;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::keys::{evp_bytes_to_key, hkdf_sha1_with_salt};
use crate::proxies::{ShadowsocksCipher, ShadowsocksOutbound, SsCipher};

const TAG_LEN: usize = 16;
const MAX_PAYLOAD: usize = 0x3FFF;

/// aes-gcm 0.10 only aliases the 128/256-bit AES-GCM types; shadowsocks'
/// aes-192-gcm is the same construction with a 24-byte key.
type Aes192Gcm = AesGcm<Aes192, U12>;

enum Aead {
    Aes128(Box<Aes128Gcm>),
    Aes192(Box<Aes192Gcm>),
    Aes256(Box<Aes256Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
    Xchacha(Box<XChaCha20Poly1305>),
}

impl Aead {
    fn new(cipher: SsCipher, key: &[u8]) -> Aead {
        match cipher {
            SsCipher::Aes128Gcm => Aead::Aes128(Box::new(
                Aes128Gcm::new_from_slice(key).expect("16-byte key"),
            )),
            SsCipher::Aes192Gcm => Aead::Aes192(Box::new(
                Aes192Gcm::new_from_slice(key).expect("24-byte key"),
            )),
            SsCipher::Aes256Gcm => Aead::Aes256(Box::new(
                Aes256Gcm::new_from_slice(key).expect("32-byte key"),
            )),
            SsCipher::Chacha20IetfPoly1305 => Aead::Chacha(Box::new(
                ChaCha20Poly1305::new_from_slice(key).expect("32-byte key"),
            )),
            SsCipher::Xchacha20IetfPoly1305 => Aead::Xchacha(Box::new(
                XChaCha20Poly1305::new_from_slice(key).expect("32-byte key"),
            )),
        }
    }

    /// Seal `buffer` in place under `nonce` with no associated data (Mihomo's
    /// writer seals `length || payload` as the plaintext of one record).
    fn seal(&self, nonce: &[u8], buffer: &mut Vec<u8>) -> Result<(), io::Error> {
        let aad: &[u8] = &[];
        let failed = || io::Error::other("shadowsocks seal failed");
        let tag = match self {
            Aead::Aes128(c) => c
                .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer)
                .map_err(|_| failed())?,
            Aead::Aes192(c) => c
                .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer)
                .map_err(|_| failed())?,
            Aead::Aes256(c) => c
                .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer)
                .map_err(|_| failed())?,
            Aead::Chacha(c) => c
                .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer)
                .map_err(|_| failed())?,
            Aead::Xchacha(c) => c
                .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer)
                .map_err(|_| failed())?,
        };
        buffer.extend_from_slice(&tag);
        Ok(())
    }

    fn open(&self, nonce: &[u8], buffer: &mut Vec<u8>) -> Result<(), io::Error> {
        let aad: &[u8] = &[];
        let malformed = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "shadowsocks authentication failed (wrong password, cipher or tampering)",
            )
        };
        if buffer.len() < TAG_LEN {
            return Err(malformed());
        }
        let split = buffer.len() - TAG_LEN;
        let tag = GenericArray::clone_from_slice(&buffer[split..]);
        buffer.truncate(split);
        match self {
            Aead::Aes128(c) => c
                .decrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer, &tag)
                .map_err(|_| malformed()),
            Aead::Aes192(c) => c
                .decrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer, &tag)
                .map_err(|_| malformed()),
            Aead::Aes256(c) => c
                .decrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer, &tag)
                .map_err(|_| malformed()),
            Aead::Chacha(c) => c
                .decrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer, &tag)
                .map_err(|_| malformed()),
            Aead::Xchacha(c) => c
                .decrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer, &tag)
                .map_err(|_| malformed()),
        }
    }
}

fn increment(nonce: &mut [u8]) {
    // SIP004 increments the nonce little-endian (Go shadowaead: `increment`).
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

/// Derive the per-connection AEAD from password and salt.
fn session_aead(cipher: SsCipher, password: &str, salt: &[u8]) -> Aead {
    // Mihomo `core.Kdf(password)` derives the pre-shared key at the cipher's
    // fixed key size, and `shadowaead.metaCipher.Encrypter/Decrypter` run
    // HKDF-SHA1 with the connection salt and info "ss-subkey" to get the
    // session subkey.
    let psk = evp_bytes_to_key(password.as_bytes(), cipher.psk_len());
    let subkey = hkdf_sha1_with_salt(salt, &psk, cipher.key_len());
    Aead::new(cipher, &subkey)
}

/// Seal one datagram payload (length prefix included in the AEAD layout).
fn seal_datagram(cipher: SsCipher, password: &str, plaintext: &[u8]) -> Vec<u8> {
    let salt = random_bytes(cipher.key_len());
    let aead = session_aead(cipher, password, &salt);
    let mut out = salt;
    let mut body = plaintext.to_vec();
    let nonce = vec![0u8; cipher.nonce_len()];
    aead.seal(&nonce, &mut body).expect("datagram seal");
    out.extend_from_slice(&body);
    out
}

fn open_datagram(cipher: SsCipher, password: &str, packet: &[u8]) -> io::Result<Vec<u8>> {
    let key_len = cipher.key_len();
    if packet.len() < key_len + TAG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shadowsocks datagram too short",
        ));
    }
    let aead = session_aead(cipher, password, &packet[..key_len]);
    let mut body = packet[key_len..].to_vec();
    let nonce = vec![0u8; cipher.nonce_len()];
    aead.open(&nonce, &mut body)?;
    Ok(body)
}

/// Length or address as the datagram prefix payload, used by the UDP tests.
pub fn datagram_plaintext(address_prefix: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = address_prefix.to_vec();
    out.extend_from_slice(payload);
    out
}

pub struct SsDatagram {
    pub cipher: SsCipher,
    pub password: String,
}

impl SsDatagram {
    pub fn encode(&self, plaintext: &[u8]) -> Vec<u8> {
        seal_datagram(self.cipher, &self.password, plaintext)
    }

    pub fn decode(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        open_datagram(self.cipher, &self.password, packet)
    }
}

/// Client-side AEAD stream over an established TCP connection to the server.
///
/// The server answers with its own salt; the read cipher is derived from that
/// salt on the first read, independently from the write cipher (SIP004).
pub struct SsStream<S> {
    inner: S,
    cipher: SsCipher,
    psk: Vec<u8>,
    write_aead: Aead,
    read_aead: Option<Aead>,
    /// The server's salt is read incrementally; a poll may end midway.
    read_salt: Vec<u8>,
    read_salt_filled: usize,
    write_nonce: Vec<u8>,
    read_nonce: Vec<u8>,
    /// Sealed bytes waiting to be written (address chunk first, then payload).
    write_buf: Vec<u8>,
    write_pos: usize,
    /// Caller-buffer length encoded at the end of `write_buf`; reported once
    /// the whole queue is written.
    pending_len: usize,
    read_pending: Vec<u8>,
    read_pos: usize,
}

impl<S> SsStream<S> {
    /// Seal one chunk: `AEAD(u16-BE length)` and `AEAD(payload)` under
    /// consecutive nonces, as Mihomo's `shadowaead.Writer.Write` writes it.
    fn seal_chunk(&mut self, payload: &[u8]) -> Vec<u8> {
        debug_assert!(payload.len() <= MAX_PAYLOAD);
        let mut out = Vec::with_capacity(2 + TAG_LEN + payload.len() + TAG_LEN);
        let mut length = (payload.len() as u16).to_be_bytes().to_vec();
        self.write_aead
            .seal(&self.write_nonce, &mut length)
            .expect("seal length record");
        increment(&mut self.write_nonce);
        out.extend_from_slice(&length);
        let mut body = payload.to_vec();
        self.write_aead
            .seal(&self.write_nonce, &mut body)
            .expect("seal payload record");
        increment(&mut self.write_nonce);
        out.extend_from_slice(&body);
        out
    }

    /// Queue the target address as the first chunk; it travels with the next
    /// write so a request reaches the server with its first payload.
    pub fn queue_address(&mut self, address: &[u8]) {
        let chunk = self.seal_chunk(address);
        self.write_buf.extend_from_slice(&chunk);
    }
}

/// Write every queued byte to the transport, reporting what is left.
fn flush_queue<S: AsyncWrite + Unpin>(
    inner: &mut S,
    queue: &[u8],
    pos: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while *pos < queue.len() {
        match Pin::new(&mut *inner).poll_write(cx, &queue[*pos..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "shadowsocks peer closed",
                )))
            }
            Poll::Ready(Ok(n)) => *pos += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let len = buf.len().min(MAX_PAYLOAD);
        // `poll_write` is polled again with the same buffer after returning
        // `Pending`; only then is the caller's chunk already sealed. A queued
        // address chunk is not part of the caller's buffer, so the caller's
        // chunk is appended behind it instead of replacing it.
        let resumed = this.pending_len == len && !this.write_buf.is_empty();
        if !resumed {
            let chunk = this.seal_chunk(&buf[..len]);
            this.write_buf.extend_from_slice(&chunk);
            this.pending_len = len;
        }
        match flush_queue(&mut this.inner, &this.write_buf, &mut this.write_pos, cx) {
            Poll::Ready(Ok(())) => {
                this.write_buf.clear();
                this.write_pos = 0;
                this.pending_len = 0;
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match flush_queue(&mut this.inner, &this.write_buf, &mut this.write_pos, cx) {
            Poll::Ready(Ok(())) => {
                this.write_buf.clear();
                this.write_pos = 0;
                this.pending_len = 0;
                Pin::new(&mut this.inner).poll_flush(cx)
            }
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut *self).poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.read_aead.is_none() {
            // The server's salt arrives before its first record; it may need
            // several polls, and progress is kept in the stream.
            while this.read_salt_filled < this.read_salt.len() {
                let mut view = ReadBuf::new(&mut this.read_salt[this.read_salt_filled..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut view) {
                    Poll::Ready(Ok(())) => {
                        let n = view.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "shadowsocks server closed before its salt",
                            )));
                        }
                        this.read_salt_filled += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let key_len = this.cipher.key_len();
            let subkey = crate::keys::hkdf_sha1_with_salt(&this.read_salt, &this.psk, key_len);
            this.read_aead = Some(Aead::new(this.cipher, &subkey));
        }
        loop {
            if this.read_pos < this.read_pending.len() {
                let n = buf.remaining().min(this.read_pending.len() - this.read_pos);
                buf.put_slice(&this.read_pending[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
                if this.read_pos == this.read_pending.len() {
                    this.read_pending.clear();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            // Record 1: the sealed 2-byte payload length.
            let mut sealed_len = vec![0u8; 2 + TAG_LEN];
            let filled = match read_exact_poll(Pin::new(&mut this.inner), cx, &mut sealed_len) {
                Poll::Ready(Ok(filled)) => filled,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if filled == 0 {
                return Poll::Ready(Ok(()));
            }
            if filled != sealed_len.len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "shadowsocks length record cut",
                )));
            }
            let read_aead = this.read_aead.as_ref().expect("derived above");
            if let Err(e) = read_aead.open(&this.read_nonce, &mut sealed_len) {
                return Poll::Ready(Err(e));
            }
            increment(&mut this.read_nonce);
            let declared = u16::from_be_bytes([sealed_len[0], sealed_len[1]]) as usize & MAX_PAYLOAD;
            if declared == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "shadowsocks zero-length chunk",
                )));
            }
            // Record 2: the sealed payload.
            let mut sealed = vec![0u8; declared + TAG_LEN];
            let filled = match read_exact_poll(Pin::new(&mut this.inner), cx, &mut sealed) {
                Poll::Ready(Ok(filled)) => filled,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if filled != sealed.len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("shadowsocks payload record cut after {filled}/{declared} bytes"),
                )));
            }
            let read_aead = this.read_aead.as_ref().expect("derived above");
            if let Err(e) = read_aead.open(&this.read_nonce, &mut sealed) {
                return Poll::Ready(Err(e));
            }
            increment(&mut this.read_nonce);
            inline(&mut this.read_pending, &sealed);
            this.read_pos = 0;
        }
    }
}

/// Replace `target` with `bytes`.
fn inline(target: &mut Vec<u8>, bytes: &[u8]) {
    target.clear();
    target.extend_from_slice(bytes);
}

/// Read exactly `buf.len()` bytes, reporting EOF as `Ok(0 consumed)`.
fn read_exact_poll<R: AsyncRead>(
    mut reader: Pin<&mut R>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
) -> StdPoll<io::Result<usize>> {
    let mut filled = 0;
    while filled < buf.len() {
        let mut view = ReadBuf::new(&mut buf[filled..]);
        match reader.as_mut().poll_read(cx, &mut view) {
            Poll::Ready(Ok(())) => {
                let n = view.filled().len();
                if n == 0 {
                    return StdPoll::Ready(if filled == 0 {
                        Ok(0)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "shadowsocks frame cut inside",
                        ))
                    });
                }
                filled += n;
            }
            Poll::Ready(Err(e)) => return StdPoll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    StdPoll::Ready(Ok(filled))
}

/// Dial the Shadowsocks server for `target`: sends the salt, queues the
/// address frame and returns the AEAD stream (the frame is flushed with the
/// first payload write, or by `flush`).
pub async fn dial(
    option: &ShadowsocksOutbound,
    target: &super::Target,
) -> Result<super::Dialed, super::DialError> {
    let tcp = super::connect_tcp(&option.server, option.port).await?;
    let server = tcp.peer_addr().map_err(|e| super::handshake("ss", e))?;
    let stream = connect_outbound(tcp, option, target)
        .await
        .map_err(|e| super::handshake("ss", e))?;
    Ok(super::Dialed { stream, server })
}

pub(super) async fn connect_outbound<S>(
    inner: S,
    option: &ShadowsocksOutbound,
    target: &super::Target,
) -> io::Result<super::BoxStream>
where
    S: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    match option.cipher {
        ShadowsocksCipher::Aead2017(cipher) => Ok(Box::new(
            connect(inner, cipher, option.password.expose(), &super::SocksAddr::encode(target)).await?,
        )),
        ShadowsocksCipher::Aead2022(cipher) => {
            let config = ss2022_config(option, cipher)?;
            Ok(Box::new(shadowsocks::ProxyClientStream::from_stream(
                ss2022_context().clone(),
                inner,
                &config,
                ss2022_address(target),
            )))
        }
    }
}

fn ss2022_config(
    option: &ShadowsocksOutbound,
    cipher: shadowsocks::crypto::CipherKind,
) -> io::Result<shadowsocks::ServerConfig> {
    shadowsocks::ServerConfig::new(
        (option.server.clone(), option.port),
        option.password.expose(),
        cipher,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid Shadowsocks 2022 key"))
}

fn ss2022_context() -> &'static shadowsocks::context::SharedContext {
    static CONTEXT: std::sync::OnceLock<shadowsocks::context::SharedContext> = std::sync::OnceLock::new();
    CONTEXT.get_or_init(|| {
        shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Local)
    })
}

fn ss2022_address(target: &super::Target) -> shadowsocks::relay::socks5::Address {
    use shadowsocks::relay::socks5::Address;
    match target.host.parse::<std::net::IpAddr>() {
        Ok(ip) => Address::SocketAddress(std::net::SocketAddr::new(ip, target.port)),
        Err(_) => Address::DomainNameAddress(target.host.clone(), target.port),
    }
}

pub(super) struct Ss2022Datagram {
    server: shadowsocks::ServerConfig,
    control: shadowsocks::relay::udprelay::options::UdpSocketControlData,
    replies: std::collections::HashMap<u64, ReplyWindow>,
}

struct ReplyWindow {
    latest: u64,
    seen: u128,
    last_seen: std::time::Instant,
}

impl Ss2022Datagram {
    pub(super) fn new(option: &ShadowsocksOutbound, cipher: shadowsocks::crypto::CipherKind) -> io::Result<Self> {
        let mut control = shadowsocks::relay::udprelay::options::UdpSocketControlData::default();
        control.client_session_id = rand::random();
        Ok(Self {
            server: ss2022_config(option, cipher)?,
            control,
            replies: Default::default(),
        })
    }

    pub(super) fn encode(&mut self, target: &super::Target, payload: &[u8]) -> io::Result<bytes::BytesMut> {
        let mut packet = bytes::BytesMut::new();
        if payload.is_empty() {
            // The upstream codec leaves padding in reserved capacity for an
            // empty datagram. Initialize that capacity before any padding is sealed.
            packet.resize(2048, 0);
            packet.clear();
        }
        self.control.packet_id = self.control.packet_id.checked_add(1)
            .ok_or_else(|| io::Error::other("Shadowsocks 2022 UDP session exhausted"))?;
        shadowsocks::relay::udprelay::crypto_io::encrypt_client_payload(
            ss2022_context(),
            self.server.method(),
            self.server.key(),
            &ss2022_address(target),
            &self.control,
            self.server.identity_keys(),
            payload,
            &mut packet,
        );
        Ok(packet)
    }

    pub(super) fn decode(&mut self, packet: &mut [u8]) -> Option<(super::Target, usize)> {
        use shadowsocks::relay::socks5::Address;

        let (length, address, control) = shadowsocks::relay::udprelay::crypto_io::decrypt_server_payload(
            ss2022_context(),
            self.server.method(),
            self.server.key(),
            packet,
        ).ok()?;
        let control = control?;
        if control.client_session_id != self.control.client_session_id {
            return None;
        }

        // Replies have timestamps checked by the wire codec. Keep the packet
        // window for their full replay lifetime, including future clock skew.
        let now = std::time::Instant::now();
        self.replies.retain(|_, window| now.duration_since(window.last_seen) < std::time::Duration::from_secs(60));
        if self.replies.len() >= 8 && !self.replies.contains_key(&control.server_session_id) {
            return None;
        }
        let window = self.replies.entry(control.server_session_id)
            .or_insert(ReplyWindow { latest: control.packet_id, seen: 0, last_seen: now });
        if control.packet_id > window.latest {
            let shift = control.packet_id - window.latest;
            window.seen = if shift >= 128 { 0 } else { window.seen << shift };
            window.latest = control.packet_id;
        }
        let bit = 1u128.checked_shl((window.latest - control.packet_id).try_into().ok()?)?;
        if window.seen & bit != 0 {
            return None;
        }
        window.seen |= bit;
        window.last_seen = now;
        let (host, port) = match address {
            Address::SocketAddress(addr) => (addr.ip().to_string(), addr.port()),
            Address::DomainNameAddress(host, port) => (host, port),
        };
        Some((super::Target { host, port }, length))
    }
}

/// Wrap an established TCP stream: sends the salt and queues the address frame.
pub async fn connect<S>(
    inner: S,
    cipher: SsCipher,
    password: &str,
    address: &[u8],
) -> io::Result<SsStream<S>>
where
    S: AsyncWrite + AsyncRead + Unpin,
{
    connect_inner(inner, cipher, password, Some(address)).await
}

/// Wrap an established stream as a bare AEAD layer (no SOCKS target frame):
/// the first payload is whatever the caller writes next. Mihomo's
/// `core.Cipher.StreamConn` is used this way by trojan's `ss-opts`, where the
/// trojan header follows the salt as the first AEAD chunk.
pub async fn connect_layer<S>(
    inner: S,
    cipher: SsCipher,
    password: &str,
) -> io::Result<SsStream<S>>
where
    S: AsyncWrite + AsyncRead + Unpin,
{
    connect_inner(inner, cipher, password, None).await
}

async fn connect_inner<S>(
    mut inner: S,
    cipher: SsCipher,
    password: &str,
    address: Option<&[u8]>,
) -> io::Result<SsStream<S>>
where
    S: AsyncWrite + AsyncRead + Unpin,
{
    let salt = random_bytes(cipher.key_len());
    inner.write_all(&salt).await?;
    let _ = flash(&mut inner).await;

    let psk = crate::keys::evp_bytes_to_key(password.as_bytes(), cipher.psk_len());
    let mut stream = SsStream {
        inner,
        cipher,
        write_aead: session_aead(cipher, password, &salt),
        psk,
        read_aead: None,
        read_salt: vec![0u8; cipher.key_len()],
        read_salt_filled: 0,
        write_nonce: vec![0u8; cipher.nonce_len()],
        read_nonce: vec![0u8; cipher.nonce_len()],
        write_buf: Vec::new(),
        write_pos: 0,
        pending_len: 0,
        read_pending: Vec::new(),
        read_pos: 0,
    };
    if let Some(address) = address {
        stream.queue_address(address);
    }
    Ok(stream)
}

/// Push queued bytes to the transport before the caller continues. For TLS
/// this writes the queued salt record now; for a plain socket it is a no-op
/// (the bytes already went out with `write_all`).
async fn flash<S: AsyncWrite + Unpin>(stream: &mut S) -> io::Result<()> {
    std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_flush(cx)).await
}

/// Read helper for the tests: consume one `AsyncRead` fully.
pub async fn read_to_end<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    reader.read_to_end(&mut out).await?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Server side of the bare AEAD layer: read the client salt, derive the
    /// read cipher, then open one chunk. Proves `connect_layer` emits no
    /// address frame: the first plaintext chunk is exactly what the caller
    /// wrote.
    #[tokio::test]
    async fn connect_layer_seals_the_first_payload_without_an_address_frame() {
        let (client, server) = tokio::io::duplex(4096);
        let password = "layer-pw";
        let cipher = SsCipher::Aes128Gcm;
        let expected = b"\x01\x02header-after-salt".to_vec();
        let server_task = tokio::spawn(async move {
            let mut server = server;
            let mut salt = vec![0u8; cipher.key_len()];
            server.read_exact(&mut salt).await.expect("salt");
            let aead = session_aead(cipher, password, &salt);
            let mut nonce = vec![0u8; cipher.nonce_len()];
            let mut sealed_len = vec![0u8; 2 + TAG_LEN];
            server.read_exact(&mut sealed_len).await.expect("length");
            aead.open(&nonce, &mut sealed_len).expect("open length");
            increment(&mut nonce);
            let declared = u16::from_be_bytes([sealed_len[0], sealed_len[1]]) as usize;
            let mut sealed = vec![0u8; declared + TAG_LEN];
            server.read_exact(&mut sealed).await.expect("payload");
            aead.open(&nonce, &mut sealed).expect("open payload");
            sealed
        });
        let mut stream = connect_layer(client, cipher, password)
            .await
            .expect("layer");
        stream.write_all(&expected).await.expect("write");
        stream.flush().await.expect("flush");
        assert_eq!(server_task.await.expect("server"), expected);
    }

    /// Every implemented cipher (including aes-192-gcm's 24-byte key and
    /// XChaCha20-Poly1305's 24-byte nonce) seals/opens the bare layer with the
    /// cipher's own key and nonce sizes, as `core.PickCipher` selects them.
    #[tokio::test]
    async fn connect_layer_roundtrips_every_implemented_cipher() {
        for cipher in [
            SsCipher::Aes128Gcm,
            SsCipher::Aes192Gcm,
            SsCipher::Aes256Gcm,
            SsCipher::Chacha20IetfPoly1305,
            SsCipher::Xchacha20IetfPoly1305,
        ] {
            let (client, server) = tokio::io::duplex(4096);
            let password = "layer-pw";
            let expected = b"header-after-salt".to_vec();
            let server_task = tokio::spawn(async move {
                let mut server = server;
                let mut salt = vec![0u8; cipher.key_len()];
                server.read_exact(&mut salt).await.expect("salt");
                let aead = session_aead(cipher, password, &salt);
                let mut nonce = vec![0u8; cipher.nonce_len()];
                let mut sealed_len = vec![0u8; 2 + TAG_LEN];
                server.read_exact(&mut sealed_len).await.expect("length");
                aead.open(&nonce, &mut sealed_len).expect("open length");
                increment(&mut nonce);
                let declared = u16::from_be_bytes([sealed_len[0], sealed_len[1]]) as usize;
                let mut sealed = vec![0u8; declared + TAG_LEN];
                server.read_exact(&mut sealed).await.expect("payload");
                aead.open(&nonce, &mut sealed).expect("open payload");
                sealed
            });
            let mut stream = connect_layer(client, cipher, password)
                .await
                .expect("layer");
            stream.write_all(&expected).await.expect("write");
            stream.flush().await.expect("flush");
            assert_eq!(server_task.await.expect("server"), expected, "{cipher:?}");
        }
    }

    /// The UDP datagram codec follows the same cipher selection; a wrong
    /// password must still fail authentication.
    #[tokio::test]
    async fn datagram_codec_roundtrips_every_implemented_cipher() {
        for cipher in [
            SsCipher::Aes128Gcm,
            SsCipher::Aes192Gcm,
            SsCipher::Aes256Gcm,
            SsCipher::Chacha20IetfPoly1305,
            SsCipher::Xchacha20IetfPoly1305,
        ] {
            let payload = b"datagram";
            let sealed = seal_datagram(cipher, "pw", payload);
            assert_eq!(
                sealed.len(),
                cipher.key_len() + payload.len() + TAG_LEN,
                "{cipher:?}"
            );
            assert_eq!(
                open_datagram(cipher, "pw", &sealed).expect("open"),
                payload,
                "{cipher:?}"
            );
            assert!(
                open_datagram(cipher, "other", &sealed).is_err(),
                "{cipher:?}"
            );
        }
    }
}
