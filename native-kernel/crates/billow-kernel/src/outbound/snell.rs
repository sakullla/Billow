//! Snell v1-v3 outbound (the pinned `transport/snell` wire format).
//!
//! A connection is an Argon2id-keyed AEAD record stream (`shadowaead` layout:
//! `salt(16) || (sealed u16 length, sealed payload) ...`, nonce starts at zero
//! and increments little-endian), optionally behind the simple-obfs HTTP
//! layer. The request header - `version 1`, command (`1` for v1/v3, `5` for
//! v2), empty client id, host length + host, port (BE) - is the first payload
//! of that stream. The server answers with one command byte: `0` tunnel, `2`
//! error (code, message length, message).
//!
//! v4-v6 replace the record layer and are rejected at load time, as are
//! `reuse` and `mode` (v6 traffic shaping).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead as _, KeyInit, Payload};
use aes_gcm::Aes128Gcm;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{connect_tcp, handshake, BoxStream, DialError, Dialed, Target};
use crate::proxies::{SnellObfs, SnellOutbound};

const VERSION: u8 = 1;
const COMMAND_CONNECT: u8 = 1;
const COMMAND_CONNECT_V2: u8 = 5;
const COMMAND_TUNNEL: u8 = 0;
const COMMAND_ERROR: u8 = 2;
const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
const MAX_PAYLOAD: usize = 0x3fff;
/// Upper bound of bytes queued while the peer is not reading.
const WRITE_QUEUE_LIMIT: usize = 1 << 20;

enum Aead {
    Aes(Box<Aes128Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

impl Aead {
    fn new(version: u8, key: &[u8]) -> Aead {
        // v1 is chacha20-poly1305, v2/v3 aes-128-gcm; the Argon2id output is
        // always 32 bytes and truncated to the cipher key size.
        if version == 1 {
            Aead::Chacha(Box::new(
                ChaCha20Poly1305::new_from_slice(&key[..32]).expect("32-byte key"),
            ))
        } else {
            Aead::Aes(Box::new(
                Aes128Gcm::new_from_slice(&key[..16]).expect("16-byte key"),
            ))
        }
    }

    fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad: &[],
        };
        let sealed = match self {
            Aead::Aes(cipher) => cipher.encrypt(nonce, payload),
            Aead::Chacha(cipher) => cipher.encrypt(nonce, payload),
        };
        sealed.map_err(|_| io::Error::other("snell seal failed"))
    }

    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad: &[],
        };
        let opened = match self {
            Aead::Aes(cipher) => cipher.decrypt(nonce, payload),
            Aead::Chacha(cipher) => cipher.decrypt(nonce, payload),
        };
        opened.map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "snell authentication failed (wrong psk or version)",
            )
        })
    }
}

/// `argon2.IDKey(psk, salt, 3, 8, 1, 32)`: the Snell-specific KDF.
pub fn snell_key(psk: &[u8], salt: &[u8]) -> [u8; 32] {
    let params = Params::new(8, 3, 1, Some(32)).expect("valid argon2 parameters");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(psk, salt, &mut out)
        .expect("argon2 output length is bounded");
    out
}

fn increment(nonce: &mut [u8; 12]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

/// The request header Snell sends as the first payload.
pub fn request_header(version: u8, target: &Target) -> Vec<u8> {
    let command = if version == 2 {
        COMMAND_CONNECT_V2
    } else {
        COMMAND_CONNECT
    };
    let mut out = Vec::with_capacity(6 + target.host.len());
    out.push(VERSION);
    out.push(command);
    out.push(0); // client id length
    out.push(target.host.len().min(255) as u8);
    out.extend_from_slice(&target.host.as_bytes()[..target.host.len().min(255)]);
    out.extend_from_slice(&target.port.to_be_bytes());
    out
}

enum ReadState {
    Salt { buf: Vec<u8>, filled: usize },
    Length { buf: [u8; 2 + TAG_LEN], filled: usize },
    Payload { size: usize, buf: Vec<u8>, filled: usize },
}

/// AEAD record stream over an established byte stream. The salt is written
/// once before the first record and read once before the first record.
pub struct SnellStream<S> {
    inner: S,
    version: u8,
    psk: Vec<u8>,
    write_aead: Option<Aead>,
    read_aead: Option<Aead>,
    write_nonce: [u8; 12],
    read_nonce: [u8; 12],
    read_state: ReadState,
    read_buf: Vec<u8>,
    read_pos: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
}

impl<S> SnellStream<S> {
    fn new(inner: S, version: u8, psk: Vec<u8>) -> SnellStream<S> {
        SnellStream {
            inner,
            version,
            psk,
            write_aead: None,
            read_aead: None,
            write_nonce: [0u8; 12],
            read_nonce: [0u8; 12],
            read_state: ReadState::Salt {
                buf: Vec::new(),
                filled: 0,
            },
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            write_pos: 0,
        }
    }

}

impl<S: AsyncWrite + Unpin> SnellStream<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "snell record write returned 0",
                    )))
                }
                Poll::Ready(Ok(written)) => self.write_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn queued(&self) -> usize {
        self.write_buf.len().saturating_sub(self.write_pos)
    }
}

fn poll_fill<S: AsyncRead + Unpin>(
    cx: &mut Context<'_>,
    inner: &mut S,
    buf: &mut [u8],
    filled: &mut usize,
) -> Poll<io::Result<()>> {
    while *filled < buf.len() {
        let mut read = ReadBuf::new(&mut buf[*filled..]);
        match Pin::new(&mut *inner).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                let read_len = read.filled().len();
                if read_len == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "snell peer closed the stream",
                    )));
                }
                *filled += read_len;
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

impl<S: AsyncRead + Unpin> AsyncRead for SnellStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.read_pos < self.read_buf.len() {
                let available = &self.read_buf[self.read_pos..];
                let take = available.len().min(buf.remaining());
                buf.put_slice(&available[..take]);
                self.read_pos += take;
                if self.read_pos == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            let mut state = std::mem::replace(
                &mut self.read_state,
                ReadState::Salt {
                    buf: Vec::new(),
                    filled: 0,
                },
            );
            match &mut state {
                ReadState::Salt { buf: salt, filled } => {
                    if salt.is_empty() {
                        *salt = vec![0u8; SALT_LEN];
                    }
                    let this = &mut *self;
                    match poll_fill(cx, &mut this.inner, salt, filled) {
                        Poll::Ready(Ok(())) => {
                            let key = snell_key(&this.psk, salt);
                            this.read_aead = Some(Aead::new(this.version, &key));
                            this.read_nonce = [0u8; 12];
                            this.read_state = ReadState::Length {
                                buf: [0u8; 2 + TAG_LEN],
                                filled: 0,
                            };
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {
                            self.read_state = state;
                            return Poll::Pending;
                        }
                    }
                }
                ReadState::Length { buf: record, filled } => {
                    let this = &mut *self;
                    match poll_fill(cx, &mut this.inner, record, filled) {
                        Poll::Ready(Ok(())) => {
                            let aead = this.read_aead.as_ref().expect("aead after salt");
                            let opened = aead.open(&this.read_nonce, record);
                            increment(&mut this.read_nonce);
                            match opened {
                                Ok(length) => {
                                    if length.len() != 2 {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "snell record length is not two bytes",
                                        )));
                                    }
                                    let size =
                                        u16::from_be_bytes([length[0], length[1]]) as usize;
                                    if size == 0 || size > MAX_PAYLOAD {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            format!("snell record of {size} bytes is out of range"),
                                        )));
                                    }
                                    this.read_state = ReadState::Payload {
                                        size,
                                        buf: vec![0u8; size + TAG_LEN],
                                        filled: 0,
                                    };
                                }
                                Err(error) => return Poll::Ready(Err(error)),
                            }
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {
                            self.read_state = state;
                            return Poll::Pending;
                        }
                    }
                }
                ReadState::Payload {
                    size,
                    buf: payload,
                    filled,
                } => {
                    let size = *size;
                    let this = &mut *self;
                    match poll_fill(cx, &mut this.inner, payload, filled) {
                        Poll::Ready(Ok(())) => {
                            let aead = this.read_aead.as_ref().expect("aead after salt");
                            let mut record = std::mem::take(payload);
                            let opened = aead.open(&this.read_nonce, &record);
                            increment(&mut this.read_nonce);
                            record.clear();
                            match opened {
                                Ok(plain) => {
                                    debug_assert_eq!(plain.len(), size);
                                    this.read_buf = plain;
                                    this.read_pos = 0;
                                    this.read_state = ReadState::Length {
                                        buf: [0u8; 2 + TAG_LEN],
                                        filled: 0,
                                    };
                                }
                                Err(error) => return Poll::Ready(Err(error)),
                            }
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {
                            self.read_state = state;
                            return Poll::Pending;
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SnellStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.queued() > WRITE_QUEUE_LIMIT {
            match self.drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.write_aead.is_none() {
            let mut salt = vec![0u8; SALT_LEN];
            rand::thread_rng().fill_bytes(&mut salt);
            let key = snell_key(&self.psk, &salt);
            self.write_aead = Some(Aead::new(self.version, &key));
            self.write_nonce = [0u8; 12];
            self.write_buf = salt;
            self.write_pos = 0;
        }

        let mut framed = Vec::with_capacity(buf.len() + 2 * buf.len().div_ceil(MAX_PAYLOAD) + 64);
        let mut nonce = self.write_nonce;
        {
            let aead = self.write_aead.as_ref().expect("aead after salt");
            for chunk in buf.chunks(MAX_PAYLOAD) {
                let mut length = Vec::with_capacity(2);
                length.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                let sealed_len = match aead.seal(&nonce, &length) {
                    Ok(sealed) => sealed,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                increment(&mut nonce);
                let sealed_payload = match aead.seal(&nonce, chunk) {
                    Ok(sealed) => sealed,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                increment(&mut nonce);
                framed.extend_from_slice(&sealed_len);
                framed.extend_from_slice(&sealed_payload);
            }
        }
        self.write_nonce = nonce;
        self.write_buf.extend_from_slice(&framed);
        match self.drain(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            // Pending is fine: the bytes are queued and the caller is not asked
            // to resend them.
            _ => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The simple-obfs HTTP layer: the first write becomes a GET request whose
/// body is that write, and the first read skips the server's HTTP response.
///
/// The request is queued as a whole, so a retried `poll_write` never sends it
/// twice; while the queue is draining, new bytes are appended behind it.
pub struct HttpObfs<S> {
    inner: S,
    host: String,
    port: u16,
    first_write: bool,
    first_read: bool,
    pending: Vec<u8>,
    pending_pos: usize,
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Partial HTTP response header, kept across `Pending` polls.
    header_buf: Vec<u8>,
}

impl<S> HttpObfs<S> {
    pub fn new(inner: S, obfs: &SnellObfs, port: u16) -> HttpObfs<S> {
        HttpObfs {
            inner,
            host: obfs.host.clone(),
            port,
            first_write: true,
            first_read: true,
            pending: Vec::new(),
            pending_pos: 0,
            read_buf: Vec::new(),
            read_pos: 0,
            header_buf: Vec::new(),
        }
    }

}

impl<S: AsyncWrite + Unpin> HttpObfs<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "snell obfs write returned 0",
                    )))
                }
                Poll::Ready(Ok(written)) => self.pending_pos += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HttpObfs<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_pos < self.read_buf.len() {
            let available = &self.read_buf[self.read_pos..];
            let take = available.len().min(buf.remaining());
            buf.put_slice(&available[..take]);
            self.read_pos += take;
            if self.read_pos == self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if !self.first_read {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        // Skip the server's HTTP response header; keep whatever body bytes
        // arrived in the same read. A partial header stays in `header_buf`
        // across `Pending` polls instead of being dropped.
        let mut scratch = [0u8; 1024];
        loop {
            let mut read = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) => {
                    let n = read.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell obfs peer closed before its HTTP response",
                        )));
                    }
                    self.header_buf.extend_from_slice(&scratch[..n]);
                    if let Some(end) = self.header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let body = self.header_buf[end + 4..].to_vec();
                        self.header_buf.clear();
                        self.first_read = false;
                        self.read_buf = body;
                        self.read_pos = 0;
                        if self.read_buf.is_empty() {
                            // The header arrived alone: read the first record
                            // body with the normal path instead of reporting a
                            // zero-length read (which would look like EOF).
                            return Pin::new(&mut self.inner).poll_read(cx, buf);
                        }
                        let available = &self.read_buf[self.read_pos..];
                        let take = available.len().min(buf.remaining());
                        buf.put_slice(&available[..take]);
                        self.read_pos += take;
                        return Poll::Ready(Ok(()));
                    }
                    if self.header_buf.len() > 16 * 1024 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snell obfs response header is too large",
                        )));
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HttpObfs<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.first_write {
            let mut key = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut key);
            let key = obfs_base64(&key);
            let host_header = if self.port == 80 {
                self.host.clone()
            } else {
                format!("{}:{}", self.host, self.port)
            };
            let head = format!(
                "GET http://{}/ HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.64.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nContent-Length: {}\r\n\r\n",
                self.host,
                host_header,
                key,
                buf.len()
            );
            self.pending = head.into_bytes();
            self.pending.extend_from_slice(buf);
            self.pending_pos = 0;
            self.first_write = false;
            return match self.drain(cx) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                _ => Poll::Ready(Ok(buf.len())),
            };
        }
        if !self.pending.is_empty() {
            match self.drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn obfs_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
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

/// Read the server's one-byte reply and the error body when it is an error.
async fn read_reply<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<()> {
    let mut command = [0u8; 1];
    stream.read_exact(&mut command).await?;
    match command[0] {
        COMMAND_TUNNEL => Ok(()),
        COMMAND_ERROR => {
            let mut code = [0u8; 1];
            stream.read_exact(&mut code).await?;
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut message = vec![0u8; length[0] as usize];
            stream.read_exact(&mut message).await?;
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "snell server reported code {}: {}",
                    code[0],
                    String::from_utf8_lossy(&message)
                ),
            ))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("snell server sent unknown command {other}"),
        )),
    }
}

pub async fn dial(option: &SnellOutbound, target: &Target) -> Result<Dialed, DialError> {
    let tcp = connect_tcp(&option.server, option.port).await?;
    let server = tcp.peer_addr().map_err(|e| handshake("snell", e))?;
    let psk = option.psk.expose().as_bytes().to_vec();

    let mut stream: BoxStream = match &option.obfs {
        Some(obfs) => Box::new(SnellStream::new(
            HttpObfs::new(tcp, obfs, option.port),
            option.version,
            psk,
        )),
        None => Box::new(SnellStream::new(tcp, option.version, psk)),
    };
    stream
        .write_all(&request_header(option.version, target))
        .await
        .map_err(|e| handshake("snell", e))?;
    stream.flush().await.map_err(|e| handshake("snell", e))?;
    // The reply is one byte on the same AEAD stream; reading it here turns a
    // rejected psk into a failed dial instead of a silent empty tunnel.
    read_reply(&mut stream)
        .await
        .map_err(|e| handshake("snell reply", e))?;
    Ok(Dialed { stream, server })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_header_layouts() {
        let target = Target {
            host: "example.com".into(),
            port: 443,
        };
        let v1 = request_header(1, &target);
        assert_eq!(&v1[..3], &[1, 1, 0]);
        assert_eq!(v1[3], 11);
        assert_eq!(&v1[4..15], b"example.com");
        assert_eq!(&v1[15..], &[1, 187]);

        let v2 = request_header(2, &target);
        assert_eq!(v2[1], COMMAND_CONNECT_V2);
        let v3 = request_header(3, &target);
        assert_eq!(v3[1], COMMAND_CONNECT);
    }

    #[test]
    fn snell_key_matches_the_argon2id_reference() {
        // Go: argon2.IDKey([]byte("secret"), []byte("0123456789abcdef"), 3, 8, 1, 32)
        let key = snell_key(b"secret", b"0123456789abcdef");
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "e8a571b1ab016daa75cb8593f17e4a056eec25739f11cd479c8f4bf16cb34909"
        );
    }

    #[test]
    fn nonce_increments_little_endian() {
        let mut nonce = [0u8; 12];
        increment(&mut nonce);
        assert_eq!(nonce[0], 1);
        nonce[0] = 0xff;
        increment(&mut nonce);
        assert_eq!(nonce[0], 0);
        assert_eq!(nonce[1], 1);
    }
}
