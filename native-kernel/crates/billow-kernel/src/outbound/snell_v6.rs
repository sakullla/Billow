// SPDX-License-Identifier: GPL-3.0-only

//! Snell v6 transport, based on Mihomo v1.19.34 (GPL-3.0),
//! transport/snell/{v6,snell,pool}.go.

use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use rand::RngCore;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

use super::snell::{increment, read_reply, request_header, snell_key};
use super::snell_v6_profile::Profile;
use super::{connect_tcp, handshake, DialError, Dialed, SocksAddr, Target};
use crate::{keys::Secret, proxies::SnellOutbound};

const SALT_SIZE: usize = 16;
const HEADER_SIZE: usize = 7;
const TAG_SIZE: usize = 16;
const MAX_PAYLOAD: usize = u16::MAX as usize;
const MAX_UDP_REQUEST: usize = 0x3fff;
const POOL_SIZE: usize = 10;
const POOL_TTL: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Default,
    Unshaped,
    UnsafeRaw,
}

#[derive(Clone)]
pub struct Config {
    mode: Mode,
    profile: Option<Arc<Profile>>,
    pool: Option<Arc<Pool>>,
}

impl Config {
    pub(crate) fn new(mode: Mode, reuse: bool, psk: &Secret) -> Self {
        Self {
            mode,
            profile: (mode == Mode::Default)
                .then(|| Arc::new(Profile::new(psk.expose().as_bytes()))),
            pool: reuse.then(|| Arc::new(Pool::default())),
        }
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnellV6Config")
            .field("mode", &self.mode)
            .field("reuse", &self.pool.is_some())
            .finish()
    }
}

impl PartialEq for Config {
    fn eq(&self, other: &Self) -> bool {
        self.mode == other.mode && self.pool.is_some() == other.pool.is_some()
    }
}
impl Eq for Config {}

#[derive(Default)]
struct Pool {
    idle: Mutex<Vec<(Instant, RecordStream)>>,
}

impl Pool {
    fn take(&self) -> Option<RecordStream> {
        let mut idle = self.idle.lock().unwrap_or_else(|error| error.into_inner());
        idle.retain(|(time, _)| time.elapsed() < POOL_TTL);
        idle.pop().map(|(_, stream)| stream)
    }

    fn put(self: &Arc<Self>, stream: RecordStream) {
        {
            let mut idle = self.idle.lock().unwrap_or_else(|error| error.into_inner());
            if idle.len() >= POOL_SIZE {
                return;
            }
            idle.push((Instant::now(), stream));
        }
        let pool = Arc::downgrade(self);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                tokio::time::sleep(POOL_TTL).await;
                if let Some(pool) = pool.upgrade() {
                    pool.idle
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .retain(|(time, _)| time.elapsed() < POOL_TTL);
                }
            });
        }
    }
}

struct Cipher {
    aead: Aes128Gcm,
    nonce: [u8; 12],
}

impl Cipher {
    fn new(psk: &Secret, salt: &[u8]) -> Self {
        let key = snell_key(psk.expose().as_bytes(), salt);
        Self {
            aead: Aes128Gcm::new_from_slice(&key[..16]).expect("16-byte AES key"),
            nonce: [0; 12],
        }
    }

    fn seal(&mut self, msg: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let result = self
            .aead
            .encrypt(Nonce::from_slice(&self.nonce), Payload { msg, aad });
        increment(&mut self.nonce);
        result.map_err(|_| io::Error::other("Snell v6 record encryption failed"))
    }

    fn open(&mut self, msg: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let result = self
            .aead
            .decrypt(Nonce::from_slice(&self.nonce), Payload { msg, aad });
        increment(&mut self.nonce);
        result.map_err(|_| invalid("Snell v6 record authentication failed"))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Copy)]
enum ReadPhase {
    Salt,
    Header,
    Body { padding: usize, payload: usize },
}

enum Record {
    Payload(Vec<u8>),
    End,
    Closed,
}

struct Reader {
    phase: ReadPhase,
    input: Vec<u8>,
    filled: usize,
    cipher: Option<Cipher>,
    seq: u32,
}

impl Reader {
    fn new(mode: Mode, profile: Option<&Profile>) -> Self {
        let (phase, size) = if mode == Mode::UnsafeRaw {
            (ReadPhase::Header, HEADER_SIZE)
        } else {
            (
                ReadPhase::Salt,
                profile.map_or(SALT_SIZE, |profile| profile.salt_block_len),
            )
        };
        Self {
            phase,
            input: vec![0; size],
            filled: 0,
            cipher: None,
            seq: 0,
        }
    }

    fn advance(&mut self, phase: ReadPhase, size: usize) {
        self.phase = phase;
        self.input.resize(size, 0);
        self.filled = 0;
    }

    fn poll_record(
        &mut self,
        tcp: &mut TcpStream,
        cx: &mut Context<'_>,
        psk: &Secret,
        mode: Mode,
        profile: Option<&Profile>,
    ) -> Poll<io::Result<Record>> {
        loop {
            while self.filled < self.input.len() {
                let mut buffer = ReadBuf::new(&mut self.input[self.filled..]);
                ready!(Pin::new(&mut *tcp).poll_read(cx, &mut buffer))?;
                let read = buffer.filled().len();
                if read == 0 {
                    return if self.filled == 0 && matches!(self.phase, ReadPhase::Header) {
                        Poll::Ready(Ok(Record::Closed))
                    } else {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated Snell v6 record",
                        )))
                    };
                }
                self.filled += read;
            }

            let prefix = profile.map_or(0, |profile| profile.prefix_len(self.seq));
            let header_size =
                prefix + HEADER_SIZE + if mode == Mode::UnsafeRaw { 0 } else { TAG_SIZE };
            match self.phase {
                ReadPhase::Salt => {
                    let salt = match profile {
                        Some(profile) => profile.extract_salt(&self.input),
                        None => self.input.as_slice().try_into().expect("fixed salt length"),
                    };
                    self.cipher = Some(Cipher::new(psk, &salt));
                    self.advance(ReadPhase::Header, header_size);
                }
                ReadPhase::Header => {
                    let head = if let Some(cipher) = &mut self.cipher {
                        cipher.open(&self.input[prefix..], &self.input[..prefix])?
                    } else {
                        self.input.clone()
                    };
                    if head[0] != 4 || (mode != Mode::Default && head[1..3] != [0, 0]) {
                        return Poll::Ready(Err(invalid("invalid Snell v6 record header")));
                    }
                    let padding = usize::from(u16::from_be_bytes([head[3], head[4]]));
                    let payload = usize::from(u16::from_be_bytes([head[5], head[6]]));
                    if mode != Mode::Default && padding != 0 {
                        return Poll::Ready(Err(invalid(
                            "unexpected padding in unshaped Snell v6 record",
                        )));
                    }
                    let tag = if self.cipher.is_some() && payload != 0 {
                        TAG_SIZE
                    } else {
                        0
                    };
                    self.advance(
                        ReadPhase::Body { padding, payload },
                        padding + payload + tag,
                    );
                }
                ReadPhase::Body { padding, payload } => {
                    let record = if payload == 0 {
                        Record::End
                    } else if let Some(cipher) = &mut self.cipher {
                        let (padding, ciphertext) = self.input.split_at_mut(padding);
                        if let Some(profile) = profile {
                            profile.mix(self.seq, padding, ciphertext);
                        }
                        Record::Payload(cipher.open(ciphertext, padding)?)
                    } else {
                        Record::Payload(std::mem::take(&mut self.input))
                    };
                    self.seq = self.seq.wrapping_add(1);
                    let next_prefix = profile.map_or(0, |profile| profile.prefix_len(self.seq));
                    self.advance(ReadPhase::Header, header_size - prefix + next_prefix);
                    return Poll::Ready(Ok(record));
                }
            }
        }
    }
}

struct Writer {
    mode: Mode,
    cipher: Option<Cipher>,
    salt_block: Vec<u8>,
    seq: u32,
    chunk: usize,
    last_write: u64,
}

impl Writer {
    fn new(psk: &Secret, mode: Mode, profile: Option<&Profile>) -> Self {
        let (cipher, salt_block) = if mode == Mode::UnsafeRaw {
            (None, Vec::new())
        } else {
            let mut salt = [0; SALT_SIZE];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            let block = profile.map_or_else(|| salt.to_vec(), |profile| profile.salt_block(&salt));
            (Some(Cipher::new(psk, &salt)), block)
        };
        Self {
            mode,
            cipher,
            salt_block,
            seq: 0,
            chunk: profile.map_or(MAX_PAYLOAD, |profile| profile.chunk_initial),
            last_write: 0,
        }
    }

    fn payload_limit(&mut self, profile: Option<&Profile>) -> usize {
        let Some(profile) = profile else {
            return MAX_PAYLOAD;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.last_write == 0 || now.saturating_sub(self.last_write) > profile.idle_reset_sec {
            self.chunk = profile.chunk_initial;
        }
        self.last_write = now;
        profile.payload_limit(self.seq, &mut self.chunk)
    }

    fn record(&mut self, payload: &[u8], profile: Option<&Profile>) -> io::Result<Vec<u8>> {
        let mut output = std::mem::take(&mut self.salt_block);
        let padding_len = profile.map_or(0, |profile| profile.padding_len(self.seq, payload.len()));
        let mut head = [4, 0, 0, 0, 0, 0, 0];
        head[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
        head[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        if self.mode == Mode::UnsafeRaw {
            output.extend(head);
            output.extend_from_slice(payload);
        } else {
            let cipher = self.cipher.as_mut().expect("encrypted mode");
            let prefix_start = output.len();
            if let Some(profile) = profile {
                output.resize(prefix_start + profile.prefix_len(self.seq), 0);
                profile.fill_padding(self.seq, &mut output[prefix_start..]);
            }
            output.extend(cipher.seal(&head, &output[prefix_start..])?);
            let padding_start = output.len();
            output.resize(padding_start + padding_len, 0);
            let padding = &mut output[padding_start..];
            if let Some(profile) = profile {
                profile.fill_padding(self.seq, padding);
            }
            if !payload.is_empty() {
                let mut sealed = cipher.seal(payload, padding)?;
                if let Some(profile) = profile {
                    profile.mix(self.seq, padding, &mut sealed);
                }
                output.extend(sealed);
            }
        }
        self.seq = self.seq.wrapping_add(1);
        Ok(output)
    }
}

struct RecordStream {
    tcp: TcpStream,
    psk: Secret,
    mode: Mode,
    profile: Option<Arc<Profile>>,
    reader: Reader,
    writer: Writer,
    input: Vec<u8>,
    input_pos: usize,
    output: Vec<u8>,
    output_pos: usize,
    peer_end: bool,
    peer_closed: bool,
    sent_end: bool,
}

impl RecordStream {
    fn new(tcp: TcpStream, psk: Secret, config: &Config) -> Self {
        let profile = config.profile.as_deref();
        Self {
            tcp,
            mode: config.mode,
            reader: Reader::new(config.mode, profile),
            writer: Writer::new(&psk, config.mode, profile),
            psk,
            profile: config.profile.clone(),
            input: Vec::new(),
            input_pos: 0,
            output: Vec::new(),
            output_pos: 0,
            peer_end: false,
            peer_closed: false,
            sent_end: false,
        }
    }

    fn poll_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Record>> {
        self.reader.poll_record(
            &mut self.tcp,
            cx,
            &self.psk,
            self.mode,
            self.profile.as_deref(),
        )
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.output_pos < self.output.len() {
            let count =
                ready!(Pin::new(&mut self.tcp).poll_write(cx, &self.output[self.output_pos..]))?;
            if count == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "Snell v6 record not written",
                )));
            }
            self.output_pos += count;
        }
        self.output.clear();
        self.output_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn enqueue(&mut self, payload: &[u8]) -> io::Result<()> {
        self.output = self.writer.record(payload, self.profile.as_deref())?;
        self.output_pos = 0;
        Ok(())
    }
}

impl AsyncRead for RecordStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let stream = &mut *self;
        if stream.peer_end || stream.peer_closed || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if stream.input_pos == stream.input.len() {
            match ready!(stream.poll_record(cx))? {
                Record::Payload(bytes) => {
                    stream.input = bytes;
                    stream.input_pos = 0;
                }
                Record::End => {
                    stream.peer_end = true;
                    return Poll::Ready(Ok(()));
                }
                Record::Closed => {
                    stream.peer_closed = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
        let input = &stream.input[stream.input_pos..];
        let count = input.len().min(buf.remaining());
        buf.put_slice(&input[..count]);
        stream.input_pos += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RecordStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream = &mut *self;
        ready!(stream.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let size = buf
            .len()
            .min(stream.writer.payload_limit(stream.profile.as_deref()));
        stream.enqueue(&buf[..size])?;
        if let Poll::Ready(result) = stream.poll_drain(cx) {
            result?;
        }
        Poll::Ready(Ok(size))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

struct Connection {
    stream: Option<RecordStream>,
    pool: Option<Arc<Pool>>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let (Some(pool), Some(mut stream)) = (&self.pool, self.stream.take()) {
            if stream.sent_end && stream.peer_end && stream.output.is_empty() && !stream.peer_closed
            {
                stream.sent_end = false;
                stream.peer_end = false;
                pool.put(stream);
            }
        }
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.stream.as_mut().expect("active Snell stream")).poll_read(cx, buf)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.stream.as_mut().expect("active Snell stream")).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.stream.as_mut().expect("active Snell stream")).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let reusable = self.pool.is_some();
        let stream = self.stream.as_mut().expect("active Snell stream");
        if !reusable {
            return Pin::new(stream).poll_shutdown(cx);
        }
        ready!(stream.poll_drain(cx))?;
        if !stream.sent_end {
            stream.writer.payload_limit(stream.profile.as_deref());
            stream.enqueue(&[])?;
            stream.sent_end = true;
        }
        Pin::new(stream).poll_flush(cx)
    }
}

async fn open(option: &SnellOutbound, config: &Config) -> Result<RecordStream, DialError> {
    let tcp = connect_tcp(&option.server, option.port).await?;
    Ok(RecordStream::new(tcp, option.psk.clone(), config))
}

async fn establish(stream: &mut RecordStream, header: &[u8]) -> io::Result<SocketAddr> {
    let server = stream.tcp.peer_addr()?;
    stream.write_all(header).await?;
    stream.flush().await?;
    read_reply(stream).await?;
    Ok(server)
}

pub(super) async fn dial(
    option: &SnellOutbound,
    config: &Config,
    target: &Target,
) -> Result<Dialed, DialError> {
    let mut header = request_header(6, target);
    if config.pool.is_some() {
        header[1] = 5;
    }
    if let Some(mut stream) = config.pool.as_ref().and_then(|pool| pool.take()) {
        // A remotely closed or half-open idle socket may still accept a write.
        // Bound the reuse attempt so a fresh dial still has time to complete.
        if let Ok(Ok(server)) =
            tokio::time::timeout(Duration::from_secs(2), establish(&mut stream, &header)).await
        {
            return Ok(Dialed {
                stream: Box::new(Connection {
                    stream: Some(stream),
                    pool: config.pool.clone(),
                }),
                server,
            });
        }
    }
    let mut stream = open(option, config).await?;
    let server = establish(&mut stream, &header)
        .await
        .map_err(|error| handshake("Snell v6", error))?;
    Ok(Dialed {
        stream: Box::new(Connection {
            stream: Some(stream),
            pool: config.pool.clone(),
        }),
        server,
    })
}

/// One TCP-backed Snell datagram association. A datagram occupies one record.
pub struct SnellUdp(RecordStream);

impl SnellUdp {
    pub async fn connect(option: &SnellOutbound) -> Result<Self, DialError> {
        let config = option.v6.as_ref().expect("Snell UDP is enabled for v6");
        let mut stream = open(option, config).await?;
        establish(&mut stream, &[1, 6, 0])
            .await
            .map_err(|error| handshake("Snell v6 UDP", error))?;
        Ok(Self(stream))
    }

    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        let address = SocksAddr::encode(target);
        let mut frame = Vec::with_capacity(address.len() + payload.len() + 2);
        frame.push(1);
        match address[0] {
            1 => frame.extend([0, 4]),
            4 => frame.extend([0, 6]),
            3 => {}
            _ => return Err(invalid("invalid Snell UDP destination")),
        }
        frame.extend_from_slice(&address[1..]);
        frame.extend_from_slice(payload);
        if frame.len() > MAX_UDP_REQUEST {
            return Err(invalid("Snell UDP datagram is too large"));
        }
        let stream = &mut self.0;
        stream.writer.payload_limit(stream.profile.as_deref());
        stream.enqueue(&frame)?;
        stream.flush().await
    }

    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        let Record::Payload(frame) = std::future::poll_fn(|cx| self.0.poll_record(cx)).await?
        else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Snell UDP peer closed",
            ));
        };
        let (ip, offset) = match frame.first() {
            Some(4) if frame.len() >= 7 => (
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&frame[1..5]).unwrap())),
                5,
            ),
            Some(6) if frame.len() >= 19 => (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&frame[1..17]).unwrap())),
                17,
            ),
            _ => return Ok(None),
        };
        let port = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
        let payload = &frame[offset + 2..];
        let length = buffer.len().min(payload.len());
        buffer[..length].copy_from_slice(&payload[..length]);
        Ok(Some((
            Target {
                host: ip.to_string(),
                port,
            },
            length,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn both_logical_half_closes_return_the_physical_connection_to_the_pool() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let psk = Secret::new("snell-v6-reuse-test");
        let config = Config::new(Mode::Default, true, &psk);
        let option = SnellOutbound {
            server: address.ip().to_string(),
            port: address.port(),
            psk: psk.clone(),
            version: 6,
            udp: true,
            v6: Some(config.clone()),
            obfs: None,
            dialer_proxy: None,
        };
        let target = Target {
            host: "example.test".into(),
            port: 443,
        };
        let mut expected_header = request_header(6, &target);
        expected_header[1] = 5;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            drop(listener); // A replacement physical connection would be refused.
            let mut peer =
                RecordStream::new(tcp, psk.clone(), &Config::new(Mode::Default, false, &psk));
            for marker in [b'a', b'b'] {
                let mut header = vec![0; expected_header.len()];
                peer.read_exact(&mut header).await.unwrap();
                assert_eq!(header, expected_header);
                peer.write_all(&[0]).await.unwrap();
                peer.flush().await.unwrap();

                assert_eq!(peer.read_u8().await.unwrap(), marker);
                assert!(matches!(
                    std::future::poll_fn(|cx| peer.poll_record(cx))
                        .await
                        .unwrap(),
                    Record::End
                ));
                peer.write_all(&[marker]).await.unwrap();
                peer.flush().await.unwrap();
                peer.enqueue(&[]).unwrap();
                peer.flush().await.unwrap();
            }
        });

        tokio::time::timeout(Duration::from_secs(4), async {
            for marker in [b'a', b'b'] {
                let mut stream = dial(&option, &config, &target).await.unwrap().stream;
                stream.write_all(&[marker]).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, [marker]);
            }
            server.await.unwrap();
        })
        .await
        .unwrap();
    }
}
