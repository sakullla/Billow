//! VMess outbound with the AEAD request header (`alterId: 0`).
//!
//! The layout is the pinned `transport/vmess` one, which is also what the
//! `listeners: type: vmess` server (sing-vmess) accepts:
//!
//! - request: `authID(16) || AEAD_seal(len(2), aad=authID)(18) || nonce(8) ||
//!   AEAD_seal(header, aad=authID)`, where every key/nonce is the nested
//!   HMAC-SHA256 `kdf(cmdKey, label, authID, nonce)` and `cmdKey` is
//!   `MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`;
//! - header body: version `1`, request IV (16), request key (16), response V,
//!   option `1` (chunk stream), `p<<4 | security`, reserved `0`, command `1`
//!   (TCP), port (BE), address type (`1` IPv4, `2` domain, `3` IPv6), address,
//!   `p` padding bytes and the FNV-1a-32 checksum of everything before it;
//! - body: `u16-BE length || AEAD_seal(payload)` records of at most
//!   `16384 - tag` bytes, with the AEAD nonce `count(BE) || iv[2..12]`;
//! - response: AEAD-sealed `u16` length then AEAD-sealed 4-byte header, with
//!   the body key/IV derived as `sha256(request key/IV)[..16]`.
//!
//! `cipher: none` keeps the AEAD header but sends plain `u16 || payload`
//! records, exactly as the pinned client does. UDP (command `2`) and the
//! legacy MD5 header (`alterId > 0`) are rejected at load time, not ignored.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes128Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::tls::ClientTls;
use super::{connect_tcp, handshake, tls, ws, BoxStream, DialError, Dialed, Target};
use crate::keys::md5;
use crate::proxies::{VmessCipher, VmessNetwork, VmessOutbound};

const VERSION: u8 = 1;
const OPTION_CHUNK_STREAM: u8 = 1;
const COMMAND_TCP: u8 = 1;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 2;
const ATYP_IPV6: u8 = 3;
const CHUNK_SIZE: usize = 1 << 14;
const MAX_RECORD: usize = 17 * 1024;
const TAG_LEN: usize = 16;

const KDF_SALT: &[u8] = b"VMess AEAD KDF";
const SALT_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
const SALT_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const SALT_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const SALT_RESP_KEY: &[u8] = b"AEAD Resp Header Key";
const SALT_RESP_IV: &[u8] = b"AEAD Resp Header IV";
const SALT_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const SALT_HEADER_IV: &[u8] = b"VMess Header AEAD Nonce";
const SALT_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const SALT_HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
/// `MD5(uuid || CMD_KEY_SALT)`; the fixed suffix is part of the VMess spec.
const CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// HMAC over an arbitrary hash function (the pinned KDF nests HMACs as hash
/// functions, not as one HMAC applied to another HMAC's output).
fn hmac_with<F: Fn(&[u8]) -> Vec<u8>>(hash: F, key: &[u8], data: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut key = if key.len() > BLOCK {
        hash(key)
    } else {
        key.to_vec()
    };
    key.resize(BLOCK, 0);
    let mut inner = Vec::with_capacity(BLOCK + data.len());
    let mut outer = Vec::with_capacity(BLOCK + 32);
    for byte in &key {
        inner.push(byte ^ 0x36);
        outer.push(byte ^ 0x5c);
    }
    inner.extend_from_slice(data);
    let inner_hash = hash(&inner);
    outer.extend_from_slice(&inner_hash);
    hash(&outer)
}

fn nested_hash(level_from_outer: usize, keys: &[&[u8]], data: &[u8]) -> Vec<u8> {
    if level_from_outer == keys.len() {
        return sha256(data);
    }
    // The outermost HMAC is keyed by the last path element, the innermost by
    // `"VMess AEAD KDF"`.
    let key = keys[keys.len() - 1 - level_from_outer];
    hmac_with(
        |inner| nested_hash(level_from_outer + 1, keys, inner),
        key,
        data,
    )
}

/// The pinned `transport/vmess.kdf`: the hash chain starts at SHA-256 and is
/// wrapped once per key (`"VMess AEAD KDF"` first, then every path element),
/// and the final HMAC is applied to `key`.
pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = Vec::with_capacity(path.len() + 1);
    keys.push(KDF_SALT);
    keys.extend_from_slice(path);
    let value = nested_hash(0, &keys, key);
    let mut out = [0u8; 32];
    out.copy_from_slice(&value);
    out
}

/// `MD5(uuid || "c48619fe-...")`: the per-user command key.
pub fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut material = uuid.to_vec();
    material.extend_from_slice(CMD_KEY_SALT);
    md5(&material)
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// `AES-128-ECB(cmdKey)` of `unix || random(4) || crc32(unix || random)`.
pub fn auth_id(cmd_key: &[u8; 16], unix: i64) -> [u8; 16] {
    let mut random = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut random);
    auth_id_with(cmd_key, unix, random)
}

/// [`auth_id`] with the four random bytes supplied (tests pin the value).
pub fn auth_id_with(cmd_key: &[u8; 16], unix: i64, random: [u8; 4]) -> [u8; 16] {
    let mut plain = Vec::with_capacity(12);
    plain.extend_from_slice(&(unix as u64).to_be_bytes());
    plain.extend_from_slice(&random);
    let crc = crc32_ieee(&plain);
    plain.extend_from_slice(&crc.to_be_bytes());
    let key = kdf(cmd_key, &[SALT_AUTH_ID]);
    let cipher = aes::Aes128::new_from_slice(&key[..16]).expect("16-byte AES key");
    let mut block = [0u8; 16];
    block.copy_from_slice(&plain);
    cipher.encrypt_block((&mut block).into());
    block
}

/// Seal the request header; the random nonce is part of the output.
pub fn seal_header(cmd_key: &[u8; 16], header: &[u8], unix: i64) -> Vec<u8> {
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut random = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut random);
    seal_header_with(cmd_key, header, unix, random, nonce)
}

/// [`seal_header`] with the auth-id random bytes and the connection nonce
/// supplied (tests pin the output).
pub fn seal_header_with(
    cmd_key: &[u8; 16],
    header: &[u8],
    unix: i64,
    random: [u8; 4],
    nonce: [u8; 8],
) -> Vec<u8> {
    let auth = auth_id_with(cmd_key, unix, random);

    let mut length = Vec::with_capacity(2);
    length.extend_from_slice(&(header.len() as u16).to_be_bytes());

    let len_key = kdf(cmd_key, &[SALT_HEADER_LEN_KEY, &auth, &nonce]);
    let len_iv = kdf(cmd_key, &[SALT_HEADER_LEN_IV, &auth, &nonce]);
    let sealed_len = seal_with(
        &len_key[..16],
        &len_iv[..12],
        &length,
        Some(auth.as_slice()),
    );

    let key = kdf(cmd_key, &[SALT_HEADER_KEY, &auth, &nonce]);
    let iv = kdf(cmd_key, &[SALT_HEADER_IV, &auth, &nonce]);
    let sealed_header = seal_with(
        &key[..16],
        &iv[..12],
        header,
        Some(auth.as_slice()),
    );

    let mut out = Vec::with_capacity(16 + sealed_len.len() + 8 + sealed_header.len());
    out.extend_from_slice(&auth);
    out.extend_from_slice(&sealed_len);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed_header);
    out
}

fn seal_with(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("16-byte AES key");
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad: aad.unwrap_or(&[]),
    };
    cipher.encrypt(nonce, payload).expect("AEAD seal")
}

fn open_with(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("16-byte AES key");
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad: aad.unwrap_or(&[]),
    };
    cipher.decrypt(nonce, payload).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess response header authentication failed (wrong uuid or tampered header)",
        )
    })
}

/// The unsealed request header body (before the AEAD wrapper).
pub fn request_body(
    req_iv: &[u8; 16],
    req_key: &[u8; 16],
    resp_v: u8,
    cipher: VmessCipher,
    target: &Target,
) -> Vec<u8> {
    let security = match cipher {
        VmessCipher::Aes128Gcm => 3u8,
        VmessCipher::Chacha20Poly1305 => 4u8,
        VmessCipher::None => 5u8,
    };
    let mut out = Vec::with_capacity(64 + target.host.len());
    out.push(VERSION);
    out.extend_from_slice(req_iv);
    out.extend_from_slice(req_key);
    out.push(resp_v);
    out.push(OPTION_CHUNK_STREAM);
    let mut padding = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut padding);
    let p = padding[0] & 0x0f;
    out.push((p << 4) | security);
    out.push(0);
    out.push(COMMAND_TCP);
    out.extend_from_slice(&target.port.to_be_bytes());
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        out.push(ATYP_DOMAIN);
        out.push(target.host.len().min(255) as u8);
        out.extend_from_slice(&target.host.as_bytes()[..target.host.len().min(255)]);
    }
    if p > 0 {
        out.extend_from_slice(&padding[1..1 + p as usize]);
    }
    let checksum = fnv1a32(&out);
    out.extend_from_slice(&checksum.to_be_bytes());
    out
}

/// Body cipher of one direction. `none` keeps the record framing without a tag.
enum BodyCipher {
    Aes(Box<Aes128Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
    None,
}

impl BodyCipher {
    fn new(cipher: VmessCipher, key: &[u8; 16]) -> BodyCipher {
        match cipher {
            VmessCipher::Aes128Gcm => {
                BodyCipher::Aes(Box::new(Aes128Gcm::new_from_slice(key).expect("16-byte key")))
            }
            VmessCipher::Chacha20Poly1305 => {
                // The pinned client expands the 16-byte VMess key to 32 bytes
                // with `md5(key) || md5(md5(key)[..16])`.
                let first = md5(key);
                let mut expanded = [0u8; 32];
                expanded[..16].copy_from_slice(&first);
                expanded[16..].copy_from_slice(&md5(&first[..16]));
                BodyCipher::Chacha(Box::new(
                    ChaCha20Poly1305::new_from_slice(&expanded).expect("32-byte key"),
                ))
            }
            VmessCipher::None => BodyCipher::None,
        }
    }

    fn overhead(&self) -> usize {
        match self {
            BodyCipher::None => 0,
            _ => TAG_LEN,
        }
    }

    fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad: &[],
        };
        let sealed = match self {
            BodyCipher::Aes(cipher) => cipher.encrypt(nonce, payload),
            BodyCipher::Chacha(cipher) => cipher.encrypt(nonce, payload),
            BodyCipher::None => return Ok(plaintext.to_vec()),
        };
        sealed.map_err(|_| io::Error::other("vmess body seal failed"))
    }

    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        if matches!(self, BodyCipher::None) {
            return Ok(ciphertext.to_vec());
        }
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad: &[],
        };
        let opened = match self {
            BodyCipher::Aes(cipher) => cipher.decrypt(nonce, payload),
            BodyCipher::Chacha(cipher) => cipher.decrypt(nonce, payload),
            BodyCipher::None => unreachable!(),
        };
        opened.map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "vmess body authentication failed (wrong cipher or tampered record)",
            )
        })
    }
}

fn chunk_nonce(count: u16, iv: &[u8; 16]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

enum ReadState {
    Header { size: [u8; 2], filled: usize },
    Body { buf: Vec<u8>, filled: usize },
}

/// VMess record layer over an established server stream.
pub struct VmessStream<S> {
    inner: S,
    read_cipher: BodyCipher,
    write_cipher: BodyCipher,
    read_iv: [u8; 16],
    write_iv: [u8; 16],
    read_count: u16,
    write_count: u16,
    read_state: ReadState,
    read_buf: Vec<u8>,
    read_pos: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
}

impl<S> VmessStream<S> {
    fn new(
        inner: S,
        cipher: VmessCipher,
        write_iv: [u8; 16],
        write_key: [u8; 16],
        read_iv: [u8; 16],
        read_key: [u8; 16],
    ) -> VmessStream<S> {
        VmessStream {
            inner,
            read_cipher: BodyCipher::new(cipher, &read_key),
            write_cipher: BodyCipher::new(cipher, &write_key),
            read_iv,
            write_iv,
            read_count: 0,
            write_count: 0,
            read_state: ReadState::Header {
                size: [0, 0],
                filled: 0,
            },
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            write_pos: 0,
        }
    }

}

impl<S: AsyncWrite + Unpin> VmessStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vmess record write returned 0",
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
                        "vmess peer closed the stream",
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

impl<S: AsyncRead + Unpin> AsyncRead for VmessStream<S> {
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
                ReadState::Header {
                    size: [0, 0],
                    filled: 0,
                },
            );
            match &mut state {
                ReadState::Header { size, filled } => {
                    let this = &mut *self;
                    match poll_fill(cx, &mut this.inner, size, filled) {
                        Poll::Ready(Ok(())) => {
                            let len = u16::from_be_bytes(*size) as usize;
                            if len > MAX_RECORD {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("vmess record of {len} bytes exceeds the maximum"),
                                )));
                            }
                            if len < this.read_cipher.overhead() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "vmess record shorter than its authentication tag",
                                )));
                            }
                            self.read_state = ReadState::Body {
                                buf: vec![0u8; len],
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
                ReadState::Body { buf: body, filled } => {
                    let this = &mut *self;
                    match poll_fill(cx, &mut this.inner, body, filled) {
                        Poll::Ready(Ok(())) => {
                            let nonce = chunk_nonce(this.read_count, &this.read_iv);
                            this.read_count = this.read_count.wrapping_add(1);
                            let mut sealed = std::mem::take(body);
                            let opened = this.read_cipher.open(&nonce, &sealed);
                            sealed.clear();
                            match opened {
                                Ok(plain) => {
                                    this.read_buf = plain;
                                    this.read_pos = 0;
                                    this.read_state = ReadState::Header {
                                        size: [0, 0],
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

impl<S: AsyncWrite + Unpin> AsyncWrite for VmessStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Poll::Ready(Err(error)) = self.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        // Bytes already queued are still ours; accepting more keeps the
        // relay simple and the queue is bounded by the caller's buffer.
        let overhead = self.write_cipher.overhead();
        let max_payload = CHUNK_SIZE - overhead;
        let mut framed = Vec::with_capacity(buf.len() + 2 * buf.len().div_ceil(max_payload) + 32);
        for chunk in buf.chunks(max_payload) {
            let nonce = chunk_nonce(self.write_count, &self.write_iv);
            self.write_count = self.write_count.wrapping_add(1);
            let sealed = match self.write_cipher.seal(&nonce, chunk) {
                Ok(sealed) => sealed,
                Err(error) => return Poll::Ready(Err(error)),
            };
            framed.extend_from_slice(&((sealed.len()) as u16).to_be_bytes());
            framed.extend_from_slice(&sealed);
        }
        if self.write_pos < self.write_buf.len() {
            // Keep the pending bytes first: append behind them.
            self.write_buf.extend_from_slice(&framed);
        } else {
            self.write_buf = framed;
            self.write_pos = 0;
        }
        match self.poll_drain(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            _ => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Read the server's response header (AEAD-sealed length then header).
async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    key: &[u8; 16],
    iv: &[u8; 16],
    resp_v: u8,
) -> io::Result<()> {
    let len_key = kdf(key, &[SALT_RESP_LEN_KEY]);
    let len_iv = kdf(iv, &[SALT_RESP_LEN_IV]);
    let mut sealed_len = [0u8; 18];
    stream.read_exact(&mut sealed_len).await?;
    let length = open_with(&len_key[..16], &len_iv[..12], &sealed_len, None)?;
    if length.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess response header length is not two bytes",
        ));
    }
    let size = u16::from_be_bytes([length[0], length[1]]) as usize;

    let payload_key = kdf(key, &[SALT_RESP_KEY]);
    let payload_iv = kdf(iv, &[SALT_RESP_IV]);
    let mut sealed = vec![0u8; size + TAG_LEN];
    stream.read_exact(&mut sealed).await?;
    let header = open_with(&payload_key[..16], &payload_iv[..12], &sealed, None)?;
    if header.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess response header shorter than four bytes",
        ));
    }
    if header[0] != resp_v {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess response header carries an unexpected response V",
        ));
    }
    if header[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vmess dynamic port in the response header is not supported",
        ));
    }
    Ok(())
}

pub async fn dial(
    option: &VmessOutbound,
    target: &Target,
    tls: &ClientTls,
) -> Result<Dialed, DialError> {
    let tcp = connect_tcp(&option.server, option.port).await?;
    let server = tcp.peer_addr().map_err(|e| handshake("vmess", e))?;
    let mut stream: BoxStream = match &option.network {
        VmessNetwork::Tcp => {
            if option.tls {
                Box::new(
                    tls::wrap(tcp, &option.server, &option.tls_settings, tls)
                        .await
                        .map_err(|e| handshake("vmess tls", e))?,
                )
            } else {
                Box::new(tcp)
            }
        }
        VmessNetwork::Ws(ws_settings) => {
            let stream: BoxStream = if option.tls {
                Box::new(
                    tls::wrap(tcp, &option.server, &option.tls_settings, tls)
                        .await
                        .map_err(|e| handshake("vmess tls", e))?,
                )
            } else {
                Box::new(tcp)
            };
            let host = option
                .tls_settings
                .sni
                .clone()
                .unwrap_or_else(|| option.server.clone());
            let tunnel = ws::connect(
                stream,
                &host,
                &ws_settings.path,
                &ws_settings.headers,
                ws_settings.v2ray_http_upgrade,
            )
            .await
            .map_err(|e| handshake("vmess ws", e))?;
            Box::new(tunnel)
        }
    };

    let mut random = [0u8; 33];
    rand::thread_rng().fill_bytes(&mut random);
    let mut req_iv = [0u8; 16];
    let mut req_key = [0u8; 16];
    req_iv.copy_from_slice(&random[..16]);
    req_key.copy_from_slice(&random[16..32]);
    let resp_v = random[32];

    let mut resp_key = [0u8; 16];
    let mut resp_iv = [0u8; 16];
    resp_key.copy_from_slice(&Sha256::digest(req_key)[..16]);
    resp_iv.copy_from_slice(&Sha256::digest(req_iv)[..16]);

    let key = cmd_key(&option.uuid);
    let header = request_body(&req_iv, &req_key, resp_v, option.cipher, target);
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let sealed = seal_header(&key, &header, unix);
    stream
        .write_all(&sealed)
        .await
        .map_err(|e| handshake("vmess", e))?;
    stream.flush().await.map_err(|e| handshake("vmess", e))?;
    read_response(&mut stream, &resp_key, &resp_iv, resp_v)
        .await
        .map_err(|e| handshake("vmess response", e))?;

    let stream: BoxStream = Box::new(VmessStream::new(
        stream,
        option.cipher,
        req_iv,
        req_key,
        resp_iv,
        resp_key,
    ));
    Ok(Dialed { stream, server })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn kdf_matches_the_pinned_go_reference() {
        // Printed by a standalone Go program (crypto/hmac + crypto/sha256) that
        // copies `transport/vmess.kdf` verbatim, including its nested
        // `hmac.New(parent.Create, value)` construction.
        let key = [0x11u8; 16];
        let auth = [0x22u8; 16];
        let nonce = [0x33u8; 8];
        assert_eq!(
            hex(&kdf(&key, &[SALT_HEADER_KEY, &auth, &nonce])),
            "07e1f284c0e855cc140258d823fb42689f163a2bf09e9dfcfbdd5e29dfc9b263"
        );
        assert_eq!(
            hex(&kdf(&key, &[SALT_AUTH_ID])),
            "17006ab48d2107259c44f8ff7eb8348aaa910497084f75620e632f8a20be5ccd"
        );
        assert_eq!(
            hex(&kdf(&key, &[SALT_RESP_LEN_KEY])),
            "bad3b323f26684f1dd54dc6578811c26546bbdaf4b4bb4cb06dacc0e6ee78156"
        );
    }

    #[test]
    fn auth_id_and_sealed_header_match_the_go_reference() {
        let key = [0x11u8; 16];
        assert_eq!(
            hex(&auth_id_with(&key, 1_700_000_000, [0xde, 0xad, 0xbe, 0xef])),
            "80544976f90e708c2b1c309a8e8383b7"
        );
        let header: Vec<u8> = (0..40u8).collect();
        let sealed = seal_header_with(
            &key,
            &header,
            1_700_000_000,
            [0xde, 0xad, 0xbe, 0xef],
            [0x33; 8],
        );
        assert_eq!(
            hex(&sealed),
            "80544976f90e708c2b1c309a8e8383b7fc40be4c350f0fcf565320a07df7dd0949903333333333333333e867910ea847f58c2ff35829804ffdce35b166f6074e962ee96be371882f06d823bb14cdd0dadebf4f4c257f9e8f2edf8fbdccdcb2f4412d"
        );
    }

    #[test]
    fn request_body_layout_is_fixed() {
        let target = Target {
            host: "example.com".into(),
            port: 443,
        };
        let body = request_body(
            &[1u8; 16],
            &[2u8; 16],
            7,
            VmessCipher::Aes128Gcm,
            &target,
        );
        assert_eq!(body[0], VERSION);
        assert_eq!(&body[1..17], &[1u8; 16]);
        assert_eq!(&body[17..33], &[2u8; 16]);
        assert_eq!(body[33], 7);
        assert_eq!(body[34], OPTION_CHUNK_STREAM);
        assert_eq!(body[35] & 0x0f, 3);
        assert_eq!(body[36], 0);
        assert_eq!(body[37], COMMAND_TCP);
        assert_eq!(&body[38..40], &[1, 187]);
        assert_eq!(body[40], ATYP_DOMAIN);
        assert_eq!(body[41], 11);
        assert_eq!(&body[42..53], b"example.com");
        // Padding is `p` bytes, then the four checksum bytes.
        let p = (body[35] >> 4) as usize;
        assert_eq!(body.len(), 53 + p + 4);
        let checksum = fnv1a32(&body[..body.len() - 4]);
        assert_eq!(&body[body.len() - 4..], &checksum.to_be_bytes());
    }

    #[test]
    fn crc32_and_fnv_match_the_reference() {
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
        assert_eq!(fnv1a32(b""), 0x811c_9dc5);
        assert_eq!(fnv1a32(b"a"), 0xe40c_292c);
    }

    #[test]
    fn cmd_key_is_md5_of_uuid_and_salt() {
        let uuid = [0u8; 16];
        let key = cmd_key(&uuid);
        let mut material = vec![0u8; 16];
        material.extend_from_slice(CMD_KEY_SALT);
        assert_eq!(key, md5(&material));
    }
}
