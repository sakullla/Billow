//! ShadowsocksR outbound: the stream cipher plus the SSR plugin layers.
//!
//! The SSR outbound is a stack of three layers in the pinned implementation:
//! the stream cipher (`shadowstream`), the obfs wrapper and the protocol
//! wrapper. This module owns the cipher layer ([`SsrStream`]) and the datagram
//! codec; `obfs` and `protocol` own the plugin layers. The client writes a
//! random IV, then the obfs framing, then the protocol records that carry the
//! SOCKS5 target address and the payload; replies are the reverse.
//!
//! Cipher vectors in the unit tests come from the pinned Go implementation
//! (`transport/shadowsocks/shadowstream`), recorded by
//! `tool/kernel-compat/peers/ssr-cipher-vectors`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{connect_tcp, handshake, BoxStream, DialError, Dialed, SocksAddr, Target};
use crate::keys::{evp_bytes_to_key, md5};
use crate::proxies::{SsrCipher, SsrOutbound};

pub mod obfs;
pub mod protocol;

const MAX_READ_IV: usize = 24;

pub async fn dial(option: &SsrOutbound, target: &Target) -> Result<Dialed, DialError> {
    let tcp = connect_tcp(&option.server, option.port).await?;
    let server = tcp.peer_addr().map_err(|e| handshake("ssr", e))?;
    let key = evp_bytes_to_key(option.password.expose().as_bytes(), option.cipher.key_len());
    let iv_size = option.cipher.iv_len();
    let mut iv = vec![0u8; iv_size];
    if iv_size > 0 {
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut iv);
    }
    // The obfs layer is the outermost wrapper: the cipher's IV travels inside
    // it (URL-encoded for `http_simple`, in the Finished record for
    // `tls1.2_ticket_auth`), exactly as in the pinned client.
    let obfs = obfs::build(option, key.clone(), iv_size, Box::new(tcp) as BoxStream);
    let overhead = option.obfs.overhead() + option.protocol.overhead();
    let cipher = SsrStream::client(obfs, option.cipher, key.clone(), iv.clone());
    let protocol = protocol::build(option, key, iv, overhead);
    let mut stream = protocol::ProtocolStream::new(cipher, protocol);
    // Every protocol writes the target address through its first record; the
    // `origin` plugin has no other client-side work.
    tokio::io::AsyncWriteExt::write_all(&mut stream, &SocksAddr::encode(target))
        .await
        .map_err(|e| handshake("ssr address", e))?;
    // `tls1.2_ticket_auth` and `random_head` finish their handshake on the
    // first flush (the pinned client does it on the first read).
    tokio::io::AsyncWriteExt::flush(&mut stream)
        .await
        .map_err(|e| handshake("ssr flush", e))?;
    Ok(Dialed {
        stream: Box::new(stream),
        server,
    })
}

/// One SSR stream: the cipher state is lazily initialised for reads (the IV
/// arrives first) and created up front for writes (the dial wrote the IV).
pub struct SsrStream<S> {
    inner: S,
    cipher: SsrCipher,
    key: Vec<u8>,
    write_state: Option<Keystream>,
    read_state: Option<Keystream>,
    read_iv: Vec<u8>,
    pending: Vec<u8>,
    pending_pos: usize,
}

impl<S> SsrStream<S> {
    /// Wrap a stream whose write IV has already been sent. Reads take the
    /// peer IV lazily, so this constructor serves both client and server.
    pub fn new(inner: S, cipher: SsrCipher, key: Vec<u8>, write_iv: Vec<u8>) -> Self {
        let write_state = Some(Keystream::new(cipher, &key, &write_iv, true));
        SsrStream {
            inner,
            cipher,
            key,
            write_state,
            read_state: None,
            read_iv: Vec::with_capacity(cipher.iv_len()),
            pending: Vec::new(),
            pending_pos: 0,
        }
    }

    /// Client constructor: the IV is queued in front of the first write, so it
    /// travels through the obfs layer instead of straight to the socket.
    pub fn client(inner: S, cipher: SsrCipher, key: Vec<u8>, write_iv: Vec<u8>) -> Self {
        let mut stream = SsrStream::new(inner, cipher, key, write_iv.clone());
        stream.pending = write_iv;
        stream
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
                        "ssr stream stopped accepting bytes",
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

impl<S: AsyncRead + Unpin> AsyncRead for SsrStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let iv_len = self.cipher.iv_len();
        while self.read_state.is_none() && self.read_iv.len() < iv_len {
            let mut scratch = [0u8; MAX_READ_IV];
            let want = iv_len - self.read_iv.len();
            let mut piece = ReadBuf::new(&mut scratch[..want]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut piece) {
                Poll::Ready(Ok(())) => {
                    let filled = piece.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ssr stream ended before the IV",
                        )));
                    }
                    let filled = filled.to_vec();
                    self.read_iv.extend_from_slice(&filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.read_state.is_none() {
            let iv = self.read_iv.clone();
            self.read_state = Some(Keystream::new(self.cipher, &self.key, &iv, false));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                if after > before {
                    let state = self.read_state.as_mut().expect("read state initialised");
                    state.xor(&mut buf.filled_mut()[before..after]);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SsrStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Back-pressure: while a previous write is still queued, do not accept
        // more bytes (returning Pending is what `write_all` waits on).
        if self.pending_pos < self.pending.len() {
            match self.poll_drain(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        let mut encrypted = buf.to_vec();
        self.write_state
            .as_mut()
            .expect("write state exists")
            .xor(&mut encrypted);
        self.pending.extend_from_slice(&encrypted);
        // This call's bytes are buffered even if the socket is not ready yet;
        // the next write waits until they are drained.
        if let Poll::Ready(Err(e)) = self.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

enum AesBlock {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl AesBlock {
    fn new(key: &[u8]) -> AesBlock {
        match key.len() {
            16 => AesBlock::A128(aes::Aes128::new(GenericArray::from_slice(key))),
            24 => AesBlock::A192(aes::Aes192::new(GenericArray::from_slice(key))),
            32 => AesBlock::A256(aes::Aes256::new(GenericArray::from_slice(key))),
            _ => unreachable!("SSR AES key sizes are 16/24/32"),
        }
    }

    fn encrypt(&self, block: &mut [u8; 16]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            AesBlock::A128(cipher) => cipher.encrypt_block(block),
            AesBlock::A192(cipher) => cipher.encrypt_block(block),
            AesBlock::A256(cipher) => cipher.encrypt_block(block),
        }
    }
}

/// AES CFB-128 with continuous feedback across writes (Go `cipher.NewCFB*`).
struct Cfb {
    block: AesBlock,
    feedback: [u8; 16],
    keystream: [u8; 16],
    pos: usize,
    encrypt: bool,
}

impl Cfb {
    fn xor(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.pos == 16 {
                self.keystream = self.feedback;
                self.block.encrypt(&mut self.keystream);
                self.pos = 0;
            }
            let input = *byte;
            *byte ^= self.keystream[self.pos];
            self.feedback[self.pos] = if self.encrypt { *byte } else { input };
            self.pos += 1;
        }
    }
}

/// AES CTR with a big-endian counter, as Go's `cipher.NewCTR` increments it.
struct Ctr {
    block: AesBlock,
    counter: [u8; 16],
    keystream: [u8; 16],
    pos: usize,
}

impl Ctr {
    fn xor(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.pos == 16 {
                self.keystream = self.counter;
                self.block.encrypt(&mut self.keystream);
                for index in (0..16).rev() {
                    let (value, carry) = self.counter[index].overflowing_add(1);
                    self.counter[index] = value;
                    if !carry {
                        break;
                    }
                }
                self.pos = 0;
            }
            *byte ^= self.keystream[self.pos];
            self.pos += 1;
        }
    }
}

pub(crate) struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub(crate) fn new(key: &[u8]) -> Rc4 {
        let mut state = [0u8; 256];
        for (index, slot) in state.iter_mut().enumerate() {
            *slot = index as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j
                .wrapping_add(state[i])
                .wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }
        Rc4 { state, i: 0, j: 0 }
    }

    pub(crate) fn xor(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
            let index = self.state[self.i as usize].wrapping_add(self.state[self.j as usize]);
            *byte ^= self.state[index as usize];
        }
    }
}

enum Keystream {    Dummy,
    Rc4(Rc4),
    Cfb(Cfb),
    Ctr(Ctr),
    ChaChaIetf(chacha20::ChaCha20),
    ChaChaLegacy(chacha20::ChaCha20Legacy),
    XChaCha(chacha20::XChaCha20),
}

impl Keystream {
    fn new(cipher: SsrCipher, key: &[u8], iv: &[u8], encrypt: bool) -> Keystream {
        match cipher {
            SsrCipher::Dummy => Keystream::Dummy,
            SsrCipher::Rc4Md5 => {
                let mut material = Vec::with_capacity(key.len() + iv.len());
                material.extend_from_slice(key);
                material.extend_from_slice(iv);
                Keystream::Rc4(Rc4::new(&md5(&material)))
            }
            SsrCipher::Aes128Cfb | SsrCipher::Aes192Cfb | SsrCipher::Aes256Cfb => {
                let mut feedback = [0u8; 16];
                feedback.copy_from_slice(iv);
                Keystream::Cfb(Cfb {
                    block: AesBlock::new(key),
                    feedback,
                    keystream: [0u8; 16],
                    pos: 16,
                    encrypt,
                })
            }
            SsrCipher::Aes128Ctr | SsrCipher::Aes192Ctr | SsrCipher::Aes256Ctr => {
                let mut counter = [0u8; 16];
                counter.copy_from_slice(iv);
                Keystream::Ctr(Ctr {
                    block: AesBlock::new(key),
                    counter,
                    keystream: [0u8; 16],
                    pos: 16,
                })
            }
            SsrCipher::ChaCha20 => Keystream::ChaChaLegacy(
                chacha20::ChaCha20Legacy::new_from_slices(key, iv)
                    .expect("SSR chacha20 key/nonce sizes"),
            ),
            SsrCipher::ChaCha20Ietf => Keystream::ChaChaIetf(
                chacha20::ChaCha20::new_from_slices(key, iv)
                    .expect("SSR chacha20-ietf key/nonce sizes"),
            ),
            SsrCipher::XChaCha20 => Keystream::XChaCha(
                chacha20::XChaCha20::new_from_slices(key, iv)
                    .expect("SSR xchacha20 key/nonce sizes"),
            ),
        }
    }

    fn xor(&mut self, data: &mut [u8]) {
        match self {
            Keystream::Dummy => {}
            Keystream::Rc4(state) => state.xor(data),
            Keystream::Cfb(state) => state.xor(data),
            Keystream::Ctr(state) => state.xor(data),
            Keystream::ChaChaIetf(state) => state.apply_keystream(data),
            Keystream::ChaChaLegacy(state) => state.apply_keystream(data),
            Keystream::XChaCha(state) => state.apply_keystream(data),
        }
    }
}

/// One SSR datagram: a random IV followed by the ciphertext (`shadowstream`'s
/// `Pack`). `dummy` has no IV.
pub(crate) fn pack_datagram(cipher: SsrCipher, key: &[u8], plain: &[u8]) -> Vec<u8> {
    let iv_size = cipher.iv_len();
    let mut out = vec![0u8; iv_size + plain.len()];
    if iv_size > 0 {
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut out[..iv_size]);
    }
    out[iv_size..].copy_from_slice(plain);
    let mut state = Keystream::new(cipher, key, &out[..iv_size], true);
    state.xor(&mut out[iv_size..]);
    out
}

/// Open one SSR datagram; a packet shorter than the IV is refused.
pub(crate) fn unpack_datagram(
    cipher: SsrCipher,
    key: &[u8],
    packet: &[u8],
) -> io::Result<Vec<u8>> {
    let iv_size = cipher.iv_len();
    if packet.len() < iv_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ssr datagram shorter than its IV",
        ));
    }
    let mut plain = packet[iv_size..].to_vec();
    let mut state = Keystream::new(cipher, key, &packet[..iv_size], false);
    state.xor(&mut plain);
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn keystream(cipher: SsrCipher, password: &str, iv: &[u8], data: &[u8]) -> Vec<u8> {
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_len());
        let mut state = Keystream::new(cipher, &key, iv, true);
        let mut out = data.to_vec();
        state.xor(&mut out);
        out
    }

    /// Vectors printed by the pinned `shadowstream` implementation (Go), with
    /// password `ssr-test-password`, IV `0123456789abcdef...` and plaintext
    /// `ssr-cipher-vector`; regenerate with
    /// `tool/kernel-compat/peers/ssr-cipher-vectors` (`go run .`).
    #[test]
    fn stream_ciphers_match_the_pinned_go_vectors() {
        let iv = b"0123456789abcdef";
        let data = b"ssr-cipher-vector";
        let cases = [
            (SsrCipher::Aes128Cfb, "06d4fd7b873259a22a46eb3117aecc8cbd"),
            (SsrCipher::Aes192Cfb, "0082273b01067df5fabcf8916eb78641bc"),
            (SsrCipher::Aes256Cfb, "7af17ea8b72264fd45cbcfa97a61a72460"),
            (SsrCipher::Aes128Ctr, "06d4fd7b873259a22a46eb3117aecc8c0e"),
            (SsrCipher::Aes192Ctr, "0082273b01067df5fabcf8916eb786416e"),
            (SsrCipher::Aes256Ctr, "7af17ea8b72264fd45cbcfa97a61a72477"),
            (SsrCipher::Rc4Md5, "4e8974fe4bca9c275fe6edf87276a46c35"),
        ];
        for (cipher, expected) in cases {
            assert_eq!(
                hex(&keystream(cipher, "ssr-test-password", iv, data)),
                expected,
                "{cipher:?}"
            );
        }
        let short_iv = b"01234567";
        assert_eq!(
            hex(&keystream(SsrCipher::ChaCha20, "ssr-test-password", short_iv, data)),
            "103f61df371541818a14d56c0848e1c210"
        );
        let ietf_iv = b"0123456789ab";
        assert_eq!(
            hex(&keystream(SsrCipher::ChaCha20Ietf, "ssr-test-password", ietf_iv, data)),
            "02c1ab8d0d96b7ce763f212c7f85a1386a"
        );
        let x_iv = b"0123456789abcdef01234567";
        assert_eq!(
            hex(&keystream(SsrCipher::XChaCha20, "ssr-test-password", x_iv, data)),
            "63d6daa424afc78a6f0ed041efd39daf31"
        );
    }

    #[test]
    fn cfb_roundtrips_across_chunk_boundaries() {
        let key = evp_bytes_to_key(b"pw", 16);
        let iv = [7u8; 16];
        let mut enc = Keystream::new(SsrCipher::Aes128Cfb, &key, &iv, true);
        let mut dec = Keystream::new(SsrCipher::Aes128Cfb, &key, &iv, false);
        let plain = b"chunked-cfb-payload-0123456789";
        let mut a = plain[..7].to_vec();
        let mut b = plain[7..23].to_vec();
        let mut c = plain[23..].to_vec();
        enc.xor(&mut a);
        enc.xor(&mut b);
        enc.xor(&mut c);
        dec.xor(&mut a);
        dec.xor(&mut b);
        dec.xor(&mut c);
        assert_eq!([a, b, c].concat(), plain.to_vec());
    }

    #[test]
    fn ctr_and_rc4_roundtrip() {
        for cipher in [SsrCipher::Aes128Ctr, SsrCipher::Aes192Ctr, SsrCipher::Aes256Ctr] {
            let key = evp_bytes_to_key(b"pw", cipher.key_len());
            let iv = [3u8; 16];
            let mut enc = Keystream::new(cipher, &key, &iv, true);
            let mut dec = Keystream::new(cipher, &key, &iv, false);
            let mut data = b"counter-mode-payload".to_vec();
            let original = data.clone();
            enc.xor(&mut data);
            assert_ne!(data, original, "{cipher:?}");
            dec.xor(&mut data);
            assert_eq!(data, original, "{cipher:?}");
        }
        let key = evp_bytes_to_key(b"pw", 16);
        let iv = [9u8; 16];
        let mut enc = Keystream::new(SsrCipher::Rc4Md5, &key, &iv, true);
        let mut dec = Keystream::new(SsrCipher::Rc4Md5, &key, &iv, false);
        let mut data = b"rc4-md5-payload".to_vec();
        let original = data.clone();
        enc.xor(&mut data);
        dec.xor(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn dummy_leaves_bytes_untouched() {
        let mut state = Keystream::new(SsrCipher::Dummy, &[], &[], true);
        let mut data = b"plain".to_vec();
        state.xor(&mut data);
        assert_eq!(data, b"plain".to_vec());
    }
}

#[cfg(test)]
mod dial_wire_tests {
    use super::*;
    use crate::proxies::{SsrCipher, SsrObfsKind, SsrProtocolKind};
    use tokio::io::AsyncReadExt;

    fn option(protocol: SsrProtocolKind, obfs: SsrObfsKind) -> SsrOutbound {
        SsrOutbound {
            server: "127.0.0.1".into(),
            port: 1,
            password: crate::keys::Secret::new("p"),
            cipher: SsrCipher::Aes256Cfb,
            protocol,
            protocol_param: None,
            obfs,
            obfs_param: None,
            udp: false,
            dialer_proxy: None,
        }
    }

    #[tokio::test]
    async fn origin_plain_writes_the_iv_then_the_address_and_payload() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut option = option(SsrProtocolKind::Origin, SsrObfsKind::Plain);
        option.server = "127.0.0.1".into();
        option.port = addr.port();
        let client = {
            let option = option.clone();
            tokio::spawn(async move {
                let target = Target {
                    host: "1.2.3.4".into(),
                    port: 80,
                };
                dial(&option, &target).await.map(|d| d.stream)
            })
        };
        let (mut server, _) = listener.accept().await.unwrap();
        let mut iv = [0u8; 16];
        server.read_exact(&mut iv).await.unwrap();
        let mut encrypted = [0u8; 7];
        server.read_exact(&mut encrypted).await.unwrap();
        let key = crate::keys::evp_bytes_to_key(b"p", 32);
        let mut state = Keystream::new(SsrCipher::Aes256Cfb, &key, &iv, false);
        let mut plain = encrypted.to_vec();
        state.xor(&mut plain);
        assert_eq!(plain, vec![1, 1, 2, 3, 4, 0, 80]);
        let stream = client.await.unwrap().unwrap();
        let (_r, mut stream) = tokio::io::split(stream);
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"marker").await.unwrap();
        let mut more = [0u8; 6];
        server.read_exact(&mut more).await.unwrap();
        let mut plain = more.to_vec();
        state.xor(&mut plain);
        assert_eq!(plain, b"marker".to_vec());
    }
}
