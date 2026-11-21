//! SSR protocol plugins (`transport/ssr/protocol` in the pinned tree).
//!
//! The protocol layer sits above the stream cipher and the obfs layer: it turns
//! one `write` into one or more framed records, and `read` into the plaintext
//! stream. `origin` is a pass-through; the `auth_*` plugins add an
//! authentication block (password-derived key + timestamp + client id) and a
//! per-record integrity check, and `auth_chain_*` additionally encrypt the
//! payload with an RC4 stream seeded from the client's first record.
//!
//! Every framing decision below is a direct port of the pinned client code
//! (`protocol/auth_sha1_v4.go`, `protocol/auth_aes128_sha1.go`,
//! `protocol/auth_chain_a.go`, `protocol/auth_chain_b.go`), including the
//! variable-length random padding, the per-record length masks and the
//! `XorShift128Plus` padding schedule of `auth_chain_b`. The lengths are not
//! free: the receiver derives them from the previous record hash, so a client
//! that picks its own padding cannot interoperate.
//!
//! UDP packets carry no obfs layer in the pinned client (`protocol.PacketConn`
//! over the cipher `PacketConn`); [`Protocol::encode_packet`] and
//! [`Protocol::decode_packet`] implement that path.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use rand::Rng;
use rand::RngCore;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::keys::{evp_bytes_to_key, md5};
use crate::outbound::base64;
use crate::proxies::{SsrOutbound, SsrProtocolKind};

use super::Rc4;

/// One protocol plugin: stream framing plus the datagram codec.
pub trait Protocol: Send {
    /// Frame `data` and append the wire bytes to `out`.
    fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()>;
    /// Consume complete records from the front of `buf` and append the
    /// plaintext to `out`; a partial record stays in `buf`.
    fn decode(&mut self, buf: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()>;
    fn encode_packet(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()>;
    fn decode_packet(&mut self, data: &[u8]) -> io::Result<Vec<u8>>;
}

pub fn build(
    option: &SsrOutbound,
    key: Vec<u8>,
    iv: Vec<u8>,
    overhead: usize,
) -> Box<dyn Protocol> {
    let param = option.protocol_param.as_deref();
    match option.protocol {
        SsrProtocolKind::Origin => Box::new(Origin),
        SsrProtocolKind::AuthSha1V4 => Box::new(AuthSha1V4::new(key, iv)),
        SsrProtocolKind::AuthAes128Md5 => {
            Box::new(AuthAes128::new(key, iv, DigestMethod::Md5, param, overhead))
        }
        SsrProtocolKind::AuthAes128Sha1 => {
            Box::new(AuthAes128::new(key, iv, DigestMethod::Sha1, param, overhead))
        }
        SsrProtocolKind::AuthChainA => Box::new(AuthChain::new(key, iv, param, false, overhead)),
        SsrProtocolKind::AuthChainB => Box::new(AuthChain::new(key, iv, param, true, overhead)),
    }
}

/// The protocol layer as a stream: frames on write, reassembles records on
/// read. A read that ends in the middle of a record keeps the partial bytes and
/// waits for more instead of reporting EOF.
pub struct ProtocolStream<S> {
    inner: S,
    protocol: Box<dyn Protocol>,
    under: Vec<u8>,
    decoded: Vec<u8>,
    decoded_pos: usize,
    pending: Vec<u8>,
    pending_pos: usize,
}

impl<S> ProtocolStream<S> {
    pub fn new(inner: S, protocol: Box<dyn Protocol>) -> ProtocolStream<S> {
        ProtocolStream {
            inner,
            protocol,
            under: Vec::new(),
            decoded: Vec::new(),
            decoded_pos: 0,
            pending: Vec::new(),
            pending_pos: 0,
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ssr protocol stream stopped accepting bytes",
                    )))
                }
                Poll::Ready(Ok(n)) => self.pending_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ProtocolStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.decoded_pos < this.decoded.len() {
                let available = this.decoded.len() - this.decoded_pos;
                let take = available.min(buf.remaining());
                let start = this.decoded_pos;
                buf.put_slice(&this.decoded[start..start + take]);
                this.decoded_pos += take;
                return Poll::Ready(Ok(()));
            }
            this.decoded.clear();
            this.decoded_pos = 0;
            let ProtocolStream {
                protocol,
                under,
                decoded,
                ..
            } = &mut *this;
            protocol.decode(under, decoded)?;
            if !this.decoded.is_empty() {
                continue;
            }
            let mut scratch = [0u8; 4096];
            let mut piece = ReadBuf::new(&mut scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut piece) {
                Poll::Ready(Ok(())) => {
                    let filled = piece.filled().to_vec();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    this.under.extend_from_slice(&filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ProtocolStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending_pos < this.pending.len() {
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        this.pending.clear();
        this.pending_pos = 0;
        let ProtocolStream {
            protocol, pending, ..
        } = &mut *this;
        protocol.encode(buf, pending)?;
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------
// Small helpers shared by the plugins.
// ---------------------------------------------------------------------------

fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

pub(crate) fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    // HMAC-MD5 by hand: the workspace has an MD5 but no `md5` crate that would
    // implement `Digest` for the `hmac` crate.
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..16].copy_from_slice(&md5(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + data.len());
    inner.extend(key_block.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(data);
    let inner_hash = md5(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 16);
    outer.extend(key_block.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    md5(&outer)
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
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

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in data {
        a = (a + *byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

/// `getHeadSize`: the address length of the first plaintext chunk.
fn head_size(bytes: &[u8], default: usize) -> usize {
    if bytes.len() < 2 {
        return default;
    }
    match bytes[0] & 7 {
        1 => 7,
        4 => 19,
        3 => 4 + bytes[1] as usize,
        _ => default,
    }
}

/// `getDataLength`: the address plus a random tail, capped at the input.
fn data_length(bytes: &[u8]) -> usize {
    let wanted = head_size(bytes, 30) + rand::thread_rng().gen_range(0..32);
    wanted.min(bytes.len())
}

fn pack_rand_prefix(out: &mut Vec<u8>, size: usize, big_endian: bool) {
    if size < 128 {
        out.push(size as u8 + 1);
    } else {
        out.push(0xff);
        if big_endian {
            out.extend_from_slice(&(size as u16 + 3).to_be_bytes());
        } else {
            out.extend_from_slice(&(size as u16 + 3).to_le_bytes());
        }
    }
    append_rand(out, size);
}

fn append_rand(out: &mut Vec<u8>, size: usize) {
    let start = out.len();
    out.resize(start + size, 0);
    rand::thread_rng().fill_bytes(&mut out[start..]);
}

/// The per-connection authentication block (`authData` in the pinned code).
struct AuthData {
    client_id: [u8; 4],
    connection_id: u32,
}

impl AuthData {
    fn fresh() -> AuthData {
        let mut client_id = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut client_id);
        let base = rand::thread_rng().gen::<u32>() & 0x00ff_ffff;
        AuthData {
            client_id,
            connection_id: base + 1,
        }
    }

    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&now_secs().to_le_bytes());
        out.extend_from_slice(&self.client_id);
        out.extend_from_slice(&self.connection_id.to_le_bytes());
    }

    /// `putEncryptedData`: the 16-byte AES-CBC (zero IV) block carrying the
    /// timestamp, client id, connection id and the two padding lengths.
    fn put_encrypted(
        &self,
        out: &mut Vec<u8>,
        user_key: &[u8],
        paddings: (u16, u16),
        salt: &str,
    ) {
        let mut block = [0u8; 16];
        block[..4].copy_from_slice(&now_secs().to_le_bytes());
        block[4..8].copy_from_slice(&self.client_id);
        block[8..12].copy_from_slice(&self.connection_id.to_le_bytes());
        block[12..14].copy_from_slice(&paddings.0.to_le_bytes());
        block[14..16].copy_from_slice(&paddings.1.to_le_bytes());
        let material = format!("{}{}", base64(user_key), salt);
        let key = evp_bytes_to_key(material.as_bytes(), 16);
        let cipher = aes::Aes128::new(GenericArray::from_slice(&key));
        let mut block = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
}

fn split_param(param: Option<&str>) -> Option<(u32, &str)> {
    let param = param?;
    let (id, key) = param.split_once(':')?;
    let id = id.parse::<u32>().ok()?;
    Some((id, key))
}

// ---------------------------------------------------------------------------
// origin
// ---------------------------------------------------------------------------

pub struct Origin;

impl Protocol for Origin {
    fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        out.extend_from_slice(data);
        Ok(())
    }

    fn decode(&mut self, buf: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        out.extend_from_slice(buf);
        buf.clear();
        Ok(())
    }

    fn encode_packet(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        out.extend_from_slice(data);
        Ok(())
    }

    fn decode_packet(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        Ok(data.to_vec())
    }
}

// ---------------------------------------------------------------------------
// auth_sha1_v4
// ---------------------------------------------------------------------------

pub struct AuthSha1V4 {
    key: Vec<u8>,
    iv: Vec<u8>,
    auth: AuthData,
    sent_header: bool,
    raw_trans: bool,
}

impl AuthSha1V4 {
    fn new(key: Vec<u8>, iv: Vec<u8>) -> AuthSha1V4 {
        AuthSha1V4 {
            key,
            iv,
            auth: AuthData::fresh(),
            sent_header: false,
            raw_trans: false,
        }
    }

    fn rand_length(size: usize) -> usize {
        if size > 1200 {
            0
        } else if size > 400 {
            rand::thread_rng().gen_range(0..256)
        } else {
            rand::thread_rng().gen_range(0..512)
        }
    }

    fn pack_data(&self, data: &[u8], out: &mut Vec<u8>) {
        let rand = Self::rand_length(data.len());
        let mut packed = 2 + 2 + 3 + rand + data.len() + 4;
        if rand < 128 {
            packed -= 2;
        }
        let start = out.len();
        out.extend_from_slice(&(packed as u16).to_be_bytes());
        let crc = crc32_ieee(&out[start..start + 2]) as u16;
        out.extend_from_slice(&crc.to_le_bytes());
        pack_rand_prefix(out, rand, true);
        out.extend_from_slice(data);
        // `packedDataLength` counts from the length field, so the adler covers
        // the whole frame except its own four bytes.
        let adler = adler32(&out[start..]);
        out.extend_from_slice(&adler.to_le_bytes());
    }

    fn pack_auth_data(&self, data: &[u8], out: &mut Vec<u8>) {
        let rand = Self::rand_length(12 + data.len());
        let mut packed = 2 + 4 + 3 + rand + 12 + data.len() + 10;
        if rand < 128 {
            packed -= 2;
        }
        let start = out.len();
        let mut crc_data = Vec::with_capacity(2 + 12 + self.key.len());
        crc_data.extend_from_slice(&(packed as u16).to_be_bytes());
        crc_data.extend_from_slice(b"auth_sha1_v4");
        crc_data.extend_from_slice(&self.key);
        out.extend_from_slice(&crc_data[..2]);
        out.extend_from_slice(&crc32_ieee(&crc_data).to_le_bytes());
        pack_rand_prefix(out, rand, true);
        self.auth.put(out);
        out.extend_from_slice(data);
        let mut mac_key = self.iv.clone();
        mac_key.extend_from_slice(&self.key);
        let mac = hmac_sha1(&mac_key, &out[start..]);
        out.extend_from_slice(&mac[..10]);
    }
}

impl Protocol for AuthSha1V4 {
    fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let mut rest = data;
        if !self.sent_header {
            let first = data_length(rest);
            self.pack_auth_data(&rest[..first], out);
            rest = &rest[first..];
            self.sent_header = true;
        }
        while rest.len() > 8100 {
            self.pack_data(&rest[..8100], out);
            rest = &rest[8100..];
        }
        if !rest.is_empty() {
            self.pack_data(rest, out);
        }
        Ok(())
    }

    fn decode(&mut self, buf: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        if self.raw_trans {
            out.extend_from_slice(buf);
            buf.clear();
            return Ok(());
        }
        while buf.len() > 4 {
            let crc = crc32_ieee(&buf[0..2]) as u16;
            if crc != u16::from_le_bytes([buf[2], buf[3]]) {
                self.raw_trans = true;
                buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_sha1_v4 decode data wrong crc32",
                ));
            }
            let length = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if !(7..8192).contains(&length) {
                self.raw_trans = true;
                buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_sha1_v4 decode data wrong length",
                ));
            }
            if length > buf.len() {
                break;
            }
            let adler = adler32(&buf[..length - 4]);
            if adler != u32::from_le_bytes([
                buf[length - 4],
                buf[length - 3],
                buf[length - 2],
                buf[length - 1],
            ]) {
                self.raw_trans = true;
                buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_sha1_v4 decode data wrong adler32",
                ));
            }
            let mut pos = buf[4] as usize;
            if pos < 255 {
                pos += 4;
            } else {
                if length < 7 {
                    self.raw_trans = true;
                    buf.clear();
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "auth_sha1_v4 decode data wrong length",
                    ));
                }
                pos = u16::from_be_bytes([buf[5], buf[6]]) as usize + 4;
            }
            if pos > length - 4 {
                self.raw_trans = true;
                buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_sha1_v4 decode data padding out of range",
                ));
            }
            out.extend_from_slice(&buf[pos..length - 4]);
            buf.drain(..length);
        }
        Ok(())
    }

    fn encode_packet(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        out.extend_from_slice(data);
        Ok(())
    }

    fn decode_packet(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        Ok(data.to_vec())
    }
}

// ---------------------------------------------------------------------------
// auth_aes128_md5 / auth_aes128_sha1
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum DigestMethod {
    Md5,
    Sha1,
}

impl DigestMethod {
    fn salt(self) -> &'static str {
        match self {
            DigestMethod::Md5 => "auth_aes128_md5",
            DigestMethod::Sha1 => "auth_aes128_sha1",
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            DigestMethod::Md5 => hmac_md5(key, data).to_vec(),
            DigestMethod::Sha1 => hmac_sha1(key, data).to_vec(),
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            DigestMethod::Md5 => md5(data).to_vec(),
            DigestMethod::Sha1 => sha1_digest(data).to_vec(),
        }
    }
}

pub struct AuthAes128 {
    key: Vec<u8>,
    iv: Vec<u8>,
    auth: AuthData,
    method: DigestMethod,
    user_key: Vec<u8>,
    user_id: [u8; 4],
    overhead: usize,
    pack_id: u32,
    recv_id: u32,
    sent_header: bool,
    raw_trans: bool,
}

impl AuthAes128 {
    fn new(
        key: Vec<u8>,
        iv: Vec<u8>,
        method: DigestMethod,
        param: Option<&str>,
        overhead: usize,
    ) -> AuthAes128 {
        let mut user_key = Vec::new();
        let mut user_id = [0u8; 4];
        if let Some((id, rest)) = split_param(param) {
            user_id = id.to_le_bytes();
            user_key = method.digest(rest.as_bytes());
        }
        if user_key.is_empty() {
            user_key = key.clone();
            rand::rngs::OsRng.fill_bytes(&mut user_id);
        }
        AuthAes128 {
            key,
            iv,
            auth: AuthData::fresh(),
            method,
            user_key,
            user_id,
            overhead,
            pack_id: 1,
            recv_id: 1,
            sent_header: false,
            raw_trans: false,
        }
    }

    /// `getRandDataLengthForPackData`: keeps a record close to one MSS.
    fn rand_for_data(&self, data_len: usize, full_len: usize) -> usize {
        if full_len >= 32 * 1024 - self.overhead {
            return 0;
        }
        let rev = 1460i64 - data_len as i64 - 9;
        if rev == 0 {
            0
        } else if rev < 0 {
            if rev > -1460 {
                trapezoid(rev + 1460, -0.3)
            } else {
                rand::thread_rng().gen_range(0..32)
            }
        } else if data_len > 900 {
            rand::thread_rng().gen_range(0..rev as usize)
        } else {
            trapezoid(rev, -0.3)
        }
    }

    fn pack_data(&mut self, data: &[u8], full_len: usize, out: &mut Vec<u8>) {
        let rand = self.rand_for_data(data.len(), full_len);
        let mut packed = 2 + 2 + 3 + rand + data.len() + 4;
        if rand < 128 {
            packed -= 2;
        }
        let mut mac_key = self.user_key.clone();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());
        self.pack_id = self.pack_id.wrapping_add(1);
        let start = out.len();
        out.extend_from_slice(&(packed as u16).to_le_bytes());
        let mac = self.method.hmac(&mac_key, &out[start..start + 2]);
        out.extend_from_slice(&mac[..2]);
        pack_rand_prefix(out, rand, false);
        out.extend_from_slice(data);
        let mac = self.method.hmac(&mac_key, &out[start..]);
        out.extend_from_slice(&mac[..4]);
    }

    fn pack_auth_data(&mut self, data: &[u8], out: &mut Vec<u8>) {
        let rand = if data.len() > 400 {
            rand::thread_rng().gen_range(0..512)
        } else {
            rand::thread_rng().gen_range(0..1024)
        };
        let packed = 7 + 4 + 16 + 4 + rand + data.len() + 4;
        let mut mac_key = self.iv.clone();
        mac_key.extend_from_slice(&self.key);
        let start = out.len();
        out.push(rand::thread_rng().gen::<u8>());
        let mac = self.method.hmac(&mac_key, &out[start..]);
        out.extend_from_slice(&mac[..6]);
        out.extend_from_slice(&self.user_id);
        self.auth.put_encrypted(
            out,
            &self.user_key,
            (packed as u16, rand as u16),
            self.method.salt(),
        );
        let mac = self.method.hmac(&mac_key, &out[start + 7..]);
        out.extend_from_slice(&mac[..4]);
        append_rand(out, rand);
        out.extend_from_slice(data);
        let mac = self.method.hmac(&self.user_key, &out[start..]);
        out.extend_from_slice(&mac[..4]);
    }
}

impl Protocol for AuthAes128 {
    fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let full_len = data.len();
        let mut rest = data;
        if !self.sent_header {
            let first = data_length(rest);
            self.pack_auth_data(&rest[..first], out);
            rest = &rest[first..];
            self.sent_header = true;
        }
        while rest.len() > 8100 {
            self.pack_data(&rest[..8100], full_len, out);
            rest = &rest[8100..];
        }
        if !rest.is_empty() {
            self.pack_data(rest, full_len, out);
        }
        Ok(())
    }

    fn decode(&mut self, buf: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        if self.raw_trans {
            out.extend_from_slice(buf);
            buf.clear();
            return Ok(());
        }
        while buf.len() > 4 {
            let mut mac_key = self.user_key.clone();
            mac_key.extend_from_slice(&self.recv_id.to_le_bytes());
            let mac = self.method.hmac(&mac_key, &buf[..2]);
            if mac[..2] != buf[2..4] {
                buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_aes128 decode data wrong mac",
                ));
            }
            let length = u16::from_le_bytes([buf[0], buf[1]]) as usize;
            if !(7..8192).contains(&length) {
                self.raw_trans = true;
                buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_aes128 decode data wrong length",
                ));
            }
            if length > buf.len() {
                break;
            }
            let mac = self.method.hmac(&mac_key, &buf[..length - 4]);
            if mac[..4] != buf[length - 4..length] {
                self.raw_trans = true;
                buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_aes128 decode data wrong checksum",
                ));
            }
            self.recv_id = self.recv_id.wrapping_add(1);
            let mut pos = buf[4] as usize;
            if pos < 255 {
                pos += 4;
            } else {
                pos = u16::from_le_bytes([buf[5], buf[6]]) as usize + 4;
            }
            if pos > length - 4 {
                self.raw_trans = true;
                buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_aes128 decode data padding out of range",
                ));
            }
            out.extend_from_slice(&buf[pos..length - 4]);
            buf.drain(..length);
        }
        Ok(())
    }

    fn encode_packet(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let start = out.len();
        out.extend_from_slice(data);
        out.extend_from_slice(&self.user_id);
        let mac = self.method.hmac(&self.user_key, &out[start..]);
        out.extend_from_slice(&mac[..4]);
        Ok(())
    }

    fn decode_packet(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        if data.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_aes128 decode data wrong length",
            ));
        }
        // The pinned client verifies datagrams with `Key`, not `userKey`; with
        // no `protocol-param` the two are the same value.
        let mac = self.method.hmac(&self.key, &data[..data.len() - 4]);
        if mac[..4] != data[data.len() - 4..] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_aes128 decode data wrong checksum",
            ));
        }
        Ok(data[..data.len() - 4].to_vec())
    }
}

/// `trapezoidRandom` from the pinned code: a trapezoidal distribution over
/// `0..max` with shape `d`.
fn trapezoid(max: i64, d: f64) -> usize {
    let mut base = rand::thread_rng().gen::<f64>();
    if d > 1e-6 {
        let a = 1.0 - d;
        base = ((a * a + 4.0 * d * base).sqrt() - a) / (2.0 * d);
    }
    (base * max as f64) as usize
}

// ---------------------------------------------------------------------------
// auth_chain_a / auth_chain_b
// ---------------------------------------------------------------------------

/// `tools.XorShift128Plus`.
pub struct XorShift128Plus {
    s: [u64; 2],
}

impl XorShift128Plus {
    fn new() -> XorShift128Plus {
        XorShift128Plus { s: [0, 0] }
    }

    fn next(&mut self) -> u64 {
        let mut x = self.s[0];
        let y = self.s[1];
        self.s[0] = y;
        x ^= x << 23;
        x ^= y ^ (x >> 17) ^ (y >> 26);
        self.s[1] = x;
        x.wrapping_add(y)
    }

    /// `InitFromBin` (requires at least 16 bytes, as every pinned call site).
    fn init_from_bin(&mut self, bin: &[u8]) {
        self.s[0] = u64::from_le_bytes(bin[..8].try_into().expect("8 bytes"));
        self.s[1] = u64::from_le_bytes(bin[8..16].try_into().expect("8 bytes"));
    }

    /// `InitFromBinAndLength`: the pinned code writes the length into the first
    /// two bytes of the seed buffer before reading it back, so the length is
    /// part of the state.
    fn init_from_bin_and_length(&mut self, bin: &[u8], length: usize) {
        let mut seed = bin.to_vec();
        if seed.len() < 16 {
            seed.resize(16, 0);
        }
        seed[..2].copy_from_slice(&(length as u16).to_le_bytes());
        self.s[0] = u64::from_le_bytes(seed[..8].try_into().expect("8 bytes"));
        self.s[1] = u64::from_le_bytes(seed[8..16].try_into().expect("8 bytes"));
        for _ in 0..4 {
            self.next();
        }
    }
}

pub struct AuthChain {
    key: Vec<u8>,
    iv: Vec<u8>,
    auth: AuthData,
    salt: &'static str,
    user_key: Vec<u8>,
    user_id: [u8; 4],
    overhead: usize,
    pack_id: u32,
    recv_id: u32,
    sent_header: bool,
    raw_trans: bool,
    last_client_hash: [u8; 16],
    last_server_hash: [u8; 16],
    encrypter: Rc4,
    decrypter: Rc4,
    random_client: XorShift128Plus,
    random_server: XorShift128Plus,
    chain_b: bool,
    data_size_list: Vec<i64>,
    data_size_list2: Vec<i64>,
}

impl AuthChain {
    fn new(
        key: Vec<u8>,
        iv: Vec<u8>,
        param: Option<&str>,
        chain_b: bool,
        overhead: usize,
    ) -> AuthChain {
        let mut user_key = Vec::new();
        let mut user_id = [0u8; 4];
        if let Some((id, rest)) = split_param(param) {
            user_id = id.to_le_bytes();
            // `auth_chain_a` keeps the raw parameter bytes (no digest).
            user_key = rest.as_bytes().to_vec();
        }
        if user_key.is_empty() {
            user_key = key.clone();
            rand::rngs::OsRng.fill_bytes(&mut user_id);
        }
        let mut chain = AuthChain {
            key,
            iv,
            auth: AuthData::fresh(),
            salt: if chain_b { "auth_chain_b" } else { "auth_chain_a" },
            user_key,
            user_id,
            overhead,
            pack_id: 1,
            recv_id: 1,
            sent_header: false,
            raw_trans: false,
            last_client_hash: [0u8; 16],
            last_server_hash: [0u8; 16],
            encrypter: Rc4::new(&[0u8]),
            decrypter: Rc4::new(&[0u8]),
            random_client: XorShift128Plus::new(),
            random_server: XorShift128Plus::new(),
            chain_b,
            data_size_list: Vec::new(),
            data_size_list2: Vec::new(),
        };
        if chain_b {
            chain.init_data_size();
        }
        chain
    }

    /// `authChainB.initDataSize`: the padding schedule is seeded from the key.
    fn init_data_size(&mut self) {
        self.random_server.init_from_bin(&self.key);
        let mut length = self.random_server.next() % 8 + 4;
        while length > 0 {
            let value = self.random_server.next() % 2340 % 2040 % 1440;
            self.data_size_list.push(value as i64);
            length -= 1;
        }
        self.data_size_list.sort_unstable();
        let mut length = self.random_server.next() % 16 + 8;
        while length > 0 {
            let value = self.random_server.next() % 2340 % 2040 % 1440;
            self.data_size_list2.push(value as i64);
            length -= 1;
        }
        self.data_size_list2.sort_unstable();
    }

    fn init_rc4(&mut self) {
        let material = format!(
            "{}{}",
            base64(&self.user_key),
            base64(&self.last_client_hash)
        );
        let key = evp_bytes_to_key(material.as_bytes(), 16);
        self.encrypter = Rc4::new(&key);
        self.decrypter = Rc4::new(&key);
    }

    /// The client's padding schedule: the send side uses `random_client`, the
    /// receive side `random_server` (the pinned `randDataLength` argument).
    fn rand_length(
        &mut self,
        length: usize,
        last_hash: &[u8; 16],
        server: bool,
    ) -> usize {
        if self.chain_b {
            self.rand_length_b(length, last_hash, server)
        } else {
            self.rand_length_a(length, last_hash, server)
        }
    }

    fn rand_length_a(&mut self, length: usize, last_hash: &[u8; 16], server: bool) -> usize {
        if length > 1440 {
            return 0;
        }
        let random = if server {
            &mut self.random_server
        } else {
            &mut self.random_client
        };
        random.init_from_bin_and_length(last_hash, length);
        if length > 1300 {
            (random.next() % 31) as usize
        } else if length > 900 {
            (random.next() % 127) as usize
        } else if length > 400 {
            (random.next() % 521) as usize
        } else {
            (random.next() % 1021) as usize
        }
    }

    fn rand_length_b(&mut self, length: usize, last_hash: &[u8; 16], server: bool) -> usize {
        if length >= 1440 {
            return 0;
        }
        let random = if server {
            &mut self.random_server
        } else {
            &mut self.random_client
        };
        random.init_from_bin_and_length(last_hash, length);
        let threshold = length as i64 + self.overhead as i64;
        let pos = self.data_size_list.partition_point(|v| *v < threshold);
        let final_pos = pos + (random.next() % self.data_size_list.len() as u64) as usize;
        if final_pos < self.data_size_list.len() {
            return (self.data_size_list[final_pos] - threshold).max(0) as usize;
        }
        let pos2 = self.data_size_list2.partition_point(|v| *v < threshold);
        let final_pos2 = pos2 + (random.next() % self.data_size_list2.len() as u64) as usize;
        if final_pos2 < self.data_size_list2.len() {
            return (self.data_size_list2[final_pos2] - threshold).max(0) as usize;
        }
        if final_pos2 + 1 < pos2 + self.data_size_list2.len() {
            return 0;
        }
        if length > 1300 {
            (random.next() % 31) as usize
        } else if length > 900 {
            (random.next() % 127) as usize
        } else if length > 400 {
            (random.next() % 521) as usize
        } else {
            (random.next() % 1021) as usize
        }
    }

    fn rand_start_pos(length: usize, random: &mut XorShift128Plus) -> usize {
        if length == 0 {
            0
        } else {
            (random.next() % 8_589_934_609) as usize % length
        }
    }

    fn pack_data(&mut self, data: &[u8], out: &mut Vec<u8>) {
        let mut encrypted = data.to_vec();
        self.encrypter.xor(&mut encrypted);
        let mut mac_key = self.user_key.clone();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());
        self.pack_id = self.pack_id.wrapping_add(1);
        let masked = (data.len() as u16)
            ^ u16::from_le_bytes([self.last_client_hash[14], self.last_client_hash[15]]);
        let start = out.len();
        out.extend_from_slice(&masked.to_le_bytes());
        // `putMixedRandDataAndData`
        let last_hash = self.last_client_hash;
        let rand = self.rand_length(data.len(), &last_hash, false);
        if data.is_empty() {
            append_rand(out, rand);
        } else if rand > 0 {
            let start_pos = Self::rand_start_pos(rand, &mut self.random_client);
            append_rand(out, start_pos);
            out.extend_from_slice(&encrypted);
            append_rand(out, rand - start_pos);
        } else {
            out.extend_from_slice(&encrypted);
        }
        self.last_client_hash = hmac_md5(&mac_key, &out[start..]);
        out.extend_from_slice(&self.last_client_hash[..2]);
    }

    fn pack_auth_data(&mut self, data: &[u8], out: &mut Vec<u8>) {
        let mut mac_key = self.iv.clone();
        mac_key.extend_from_slice(&self.key);
        let start = out.len();
        append_rand(out, 4);
        self.last_client_hash = hmac_md5(&mac_key, &out[start..]);
        self.init_rc4();
        out.extend_from_slice(&self.last_client_hash[..8]);
        let uid = u32::from_le_bytes(self.user_id)
            ^ u32::from_le_bytes([
                self.last_client_hash[8],
                self.last_client_hash[9],
                self.last_client_hash[10],
                self.last_client_hash[11],
            ]);
        out.extend_from_slice(&uid.to_le_bytes());
        self.auth.put_encrypted(
            out,
            &self.user_key,
            (self.overhead as u16, 0),
            self.salt,
        );
        self.last_server_hash = hmac_md5(&self.user_key, &out[start + 12..]);
        out.extend_from_slice(&self.last_server_hash[..4]);
        self.pack_data(data, out);
    }

    fn udp_rand_length(last_hash: &[u8], random: &mut XorShift128Plus) -> usize {
        random.init_from_bin(last_hash);
        (random.next() % 127) as usize
    }
}

impl Protocol for AuthChain {
    fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let mut rest = data;
        if !self.sent_header {
            let first = data_length(rest);
            self.pack_auth_data(&rest[..first], out);
            rest = &rest[first..];
            self.sent_header = true;
        }
        while rest.len() > 2800 {
            self.pack_data(&rest[..2800], out);
            rest = &rest[2800..];
        }
        if !rest.is_empty() {
            self.pack_data(rest, out);
        }
        Ok(())
    }

    fn decode(&mut self, buf: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        if self.raw_trans {
            out.extend_from_slice(buf);
            buf.clear();
            return Ok(());
        }
        while buf.len() > 4 {
            let mut mac_key = self.user_key.clone();
            mac_key.extend_from_slice(&self.recv_id.to_le_bytes());
            let data_len = (u16::from_le_bytes([buf[0], buf[1]])
                ^ u16::from_le_bytes([self.last_server_hash[14], self.last_server_hash[15]]))
                as usize;
            let last_hash = self.last_server_hash;
            let rand_len = self.rand_length(data_len, &last_hash, true);
            let length = data_len + rand_len;
            if length >= 4096 {
                self.raw_trans = true;
                buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_chain decode data wrong length",
                ));
            }
            if 4 + length > buf.len() {
                break;
            }
            let server_hash = hmac_md5(&mac_key, &buf[..length + 2]);
            if server_hash[..2] != buf[length + 2..length + 4] {
                self.raw_trans = true;
                buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_chain decode data wrong checksum",
                ));
            }
            self.last_server_hash = server_hash;
            let mut pos = 2;
            if data_len > 0 && rand_len > 0 {
                pos += Self::rand_start_pos(rand_len, &mut self.random_server);
            }
            if pos + data_len > buf.len() {
                self.raw_trans = true;
                buf.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_chain decode data padding out of range",
                ));
            }
            let mut wanted = buf[pos..pos + data_len].to_vec();
            self.decrypter.xor(&mut wanted);
            if self.recv_id == 1 {
                // The first record also carries the two-byte address type the
                // server already consumed.
                out.extend_from_slice(&wanted[2.min(wanted.len())..]);
            } else {
                out.extend_from_slice(&wanted);
            }
            self.recv_id = self.recv_id.wrapping_add(1);
            buf.drain(..length + 4);
        }
        Ok(())
    }

    fn encode_packet(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let mut auth = [0u8; 3];
        rand::rngs::OsRng.fill_bytes(&mut auth);
        let md5_data = hmac_md5(&self.key, &auth);
        let rand_len = Self::udp_rand_length(&md5_data, &mut self.random_client);
        let material = format!("{}{}", base64(&self.user_key), base64(&md5_data));
        let key = evp_bytes_to_key(material.as_bytes(), 16);
        let mut rc4 = Rc4::new(&key);
        let mut payload = data.to_vec();
        rc4.xor(&mut payload);
        let start = out.len();
        out.extend_from_slice(&payload);
        append_rand(out, rand_len);
        out.extend_from_slice(&auth);
        let uid = u32::from_le_bytes(self.user_id)
            ^ u32::from_le_bytes([md5_data[0], md5_data[1], md5_data[2], md5_data[3]]);
        out.extend_from_slice(&uid.to_le_bytes());
        let mac = hmac_md5(&self.user_key, &out[start..]);
        out.extend_from_slice(&mac[..1]);
        Ok(())
    }

    fn decode_packet(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        if data.len() < 9 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_chain decode data wrong length",
            ));
        }
        let mac = hmac_md5(&self.user_key, &data[..data.len() - 1]);
        if mac[..1] != data[data.len() - 1..] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_chain decode data wrong checksum",
            ));
        }
        let md5_data = hmac_md5(&self.key, &data[data.len() - 8..data.len() - 1]);
        let rand_len = Self::udp_rand_length(&md5_data, &mut self.random_server);
        let material = format!("{}{}", base64(&self.user_key), base64(&md5_data));
        let key = evp_bytes_to_key(material.as_bytes(), 16);
        let mut rc4 = Rc4::new(&key);
        if 8 + rand_len > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_chain decode data wrong length",
            ));
        }
        let mut wanted = data[..data.len() - 8 - rand_len].to_vec();
        rc4.xor(&mut wanted);
        Ok(wanted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_and_adler32_match_the_go_reference_values() {
        // `crc32.ChecksumIEEE("123456789")` and `adler32.Checksum("123456789")`.
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
        assert_eq!(adler32(b"123456789"), 0x091e_01de);
        assert_eq!(crc32_ieee(b""), 0);
        assert_eq!(adler32(b""), 1);
    }

    #[test]
    fn hmac_md5_matches_rfc_2202_case_1() {
        let mac = hmac_md5(&[0x0b; 16], b"Hi There");
        assert_eq!(
            mac.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
    }

    #[test]
    fn hmac_sha1_matches_rfc_2202_case_1() {
        let mac = hmac_sha1(&[0x0b; 20], b"Hi There");
        assert_eq!(
            mac.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
    }

    #[test]
    fn head_size_reads_the_socks_address_form() {
        assert_eq!(head_size(&[0x01, 1, 2, 3, 4, 0, 80], 30), 7);
        assert_eq!(head_size(&[0x03, 9], 30), 13);
        assert_eq!(head_size(&[0x04], 30), 30);
    }

    #[test]
    fn xor_shift_sequence_matches_the_pinned_generator() {
        // Printed by tool/kernel-compat/peers/ssr-plugins (`-vectors`), which
        // runs the pinned `tools.XorShift128Plus`.
        let mut random = XorShift128Plus::new();
        random.init_from_bin(&[7u8; 16]);
        let values: Vec<u64> = (0..4).map(|_| random.next()).collect();
        assert_eq!(
            values,
            vec![
                9983012281162304137,
                9983012414829509192,
                7749566919588107026,
                6130972981263191596
            ]
        );
        let mut with_length = XorShift128Plus::new();
        with_length.init_from_bin_and_length(&[7u8; 16], 100);
        let after: Vec<u64> = (0..2).map(|_| with_length.next()).collect();
        assert_eq!(
            after,
            vec![15602647799304538188, 4206497952017397991]
        );
    }

    #[test]
    fn chain_b_padding_schedule_matches_the_pinned_generator() {
        // `-vectors` for the key derived from "ssr-plugin-peer".
        let key = evp_bytes_to_key(b"ssr-plugin-peer", 32);
        let mut random = XorShift128Plus::new();
        random.init_from_bin(&key);
        let mut first = Vec::new();
        let mut length = random.next() % 8 + 4;
        while length > 0 {
            first.push(random.next() % 2340 % 2040 % 1440);
            length -= 1;
        }
        first.sort_unstable();
        assert_eq!(first, vec![105, 116, 299, 426, 982, 1219]);
        let mut second = Vec::new();
        let mut length = random.next() % 16 + 8;
        while length > 0 {
            second.push(random.next() % 2340 % 2040 % 1440);
            length -= 1;
        }
        second.sort_unstable();
        assert_eq!(
            second,
            vec![45, 76, 85, 85, 136, 275, 482, 558, 818, 1161, 1202, 1254]
        );
    }
}
