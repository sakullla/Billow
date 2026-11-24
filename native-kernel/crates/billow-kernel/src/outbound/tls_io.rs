//! A TCP TLS client stream driven by an explicit `rustls::ClientConnection`.
//!
//! `tokio-rustls` owns the `ClientConnection` it creates, which is enough for
//! the plain TLS outbounds but not for the two modes that must touch the
//! cleartext handshake:
//!
//! - **JLS** (`anytls` `jls-opts`): the ClientHello random is sealed by
//!   [`super::jls::tcp_client`] and the ServerHello random must be verified
//!   *before* the certificate is accepted, exactly like the QUIC session
//!   wrapper does. The verifier reads the flag this module sets.
//! - **ShadowTLS v2** (`anytls` `shadow-tls-opts`): the outer TLS handshake is
//!   camouflage; the client hashes every byte it reads and the connection is
//!   then taken over as framed plaintext. [`TlsIo::into_parts`] hands the raw
//!   stream and the running HMAC back to the ShadowTLS layer.
//!
//! The read path watches cleartext handshake records as they arrive (before
//! they are handed to rustls) and never modifies them.

use std::io::{self, Read as _, Write as _};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::jls;
use super::BoxStream;

const RECORD_HEADER: usize = 5;
const RECORD_HANDSHAKE: u8 = 22;
const HANDSHAKE_SERVER_HELLO: u8 = 2;

/// A SHA-1 HMAC over every byte read from the socket (ShadowTLS v2).
pub type ReadHash = hmac::Hmac<Sha1>;

/// Watches the first cleartext ServerHello and marks the JLS state.
struct JlsWatch {
    credentials: jls::JlsCredentials,
    state: Arc<jls::JlsState>,
    /// Raw bytes received but not yet parsed into records.
    raw: Vec<u8>,
    /// Cleartext handshake bytes seen so far (type-22 records only).
    handshake: Vec<u8>,
    done: bool,
}

impl JlsWatch {
    fn observe(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.done {
            return Ok(());
        }
        self.raw.extend_from_slice(bytes);
        loop {
            if self.raw.len() < RECORD_HEADER {
                return Ok(());
            }
            let length = (usize::from(self.raw[3]) << 8) | usize::from(self.raw[4]);
            if self.raw.len() < RECORD_HEADER + length {
                return Ok(());
            }
            let record: Vec<u8> = self.raw.drain(..RECORD_HEADER + length).collect();
            if record[0] != RECORD_HANDSHAKE {
                continue;
            }
            self.handshake
                .extend_from_slice(&record[RECORD_HEADER..RECORD_HEADER + length]);
            let mut at = 0usize;
            while self.handshake.len() >= at + 4 {
                let len = (usize::from(self.handshake[at + 1]) << 16)
                    | (usize::from(self.handshake[at + 2]) << 8)
                    | usize::from(self.handshake[at + 3]);
                if self.handshake.len() < at + 4 + len {
                    break;
                }
                let message = &self.handshake[at..at + 4 + len];
                at += 4 + len;
                if message[0] != HANDSHAKE_SERVER_HELLO {
                    continue;
                }
                self.done = true;
                let message = message.to_vec();
                self.raw.clear();
                self.handshake.clear();
                let auth_data = jls::server_hello_auth_data(&message)
                    .ok_or_else(|| invalid("jls: malformed ServerHello"))?;
                let random = jls::server_hello_random(&message)
                    .ok_or_else(|| invalid("jls: ServerHello random is missing"))?;
                if jls::verify_random(&self.credentials, &auth_data, random) {
                    self.state.mark_authenticated();
                    return Ok(());
                }
                self.state.mark_rejected();
                return Err(invalid(
                    "jls: the ServerHello did not authenticate the configured account",
                ));
            }
            if at > 0 {
                self.handshake.drain(..at);
            }
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Open a JLS-protected TLS session over `stream` (anytls `jls-opts`).
///
/// The ClientHello is built by [`jls::tcp_client`] and its random is a sealed
/// JLS value; the ServerHello is verified on the read path before the
/// certificate is accepted. A server that does not authenticate the account
/// aborts the dial exactly like the pinned `ErrJLSAuthFailed` (it does not fall
/// back to plain TLS), while a server that did not authenticate but presents a
/// valid certificate is also rejected after the handshake.
pub async fn connect_jls(
    stream: BoxStream,
    server: &str,
    settings: &crate::proxies::TlsSettings,
    tls: &super::tls::ClientTls,
    credentials: &jls::JlsCredentials,
) -> io::Result<BoxStream> {
    let state = Arc::new(jls::JlsState::new());
    let config = super::tls::jls_tcp_client_config(settings, tls, state.clone())?;
    let name = settings.sni.clone().unwrap_or_else(|| server.to_string());
    let client = jls::tcp_client(&config, credentials, &name)
        .map_err(|reason| invalid_owned(format!("jls: {reason}")))?;
    let mut io = TlsIo::start(
        client.connection,
        stream,
        Some(&client.hello),
        Some((credentials.clone(), state.clone())),
        None,
    )
    .await?;
    io.handshake()
        .await
        .map_err(|error| io::Error::new(error.kind(), format!("jls handshake: {error}")))?;
    if !state.authenticated() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "jls: the server did not authenticate the configured account",
        ));
    }
    Ok(Box::new(io))
}

/// TLS over a stream with an explicit connection.
pub struct TlsIo {
    connection: rustls::ClientConnection,
    io: BoxStream,
    read_scratch: Vec<u8>,
    write_scratch: Vec<u8>,
    watch: Option<JlsWatch>,
    read_hash: Option<ReadHash>,
    eof: bool,
}

impl TlsIo {
    /// Wrap `io`, sending `greeting` (a pre-serialised ClientHello) first.
    pub async fn start(
        connection: rustls::ClientConnection,
        mut io: BoxStream,
        greeting: Option<&[u8]>,
        credentials: Option<(jls::JlsCredentials, Arc<jls::JlsState>)>,
        read_hash: Option<ReadHash>,
    ) -> io::Result<TlsIo> {
        if let Some(greeting) = greeting {
            use tokio::io::AsyncWriteExt;
            io.write_all(greeting).await?;
            io.flush().await?;
        }
        let watch = credentials.map(|(credentials, state)| JlsWatch {
            credentials,
            state,
            raw: Vec::new(),
            handshake: Vec::new(),
            done: false,
        });
        Ok(TlsIo {
            connection,
            io,
            read_scratch: vec![0u8; 16 * 1024],
            write_scratch: vec![0u8; 20 * 1024],
            watch,
            read_hash,
            eof: false,
        })
    }

    /// Hand back the raw stream and the SHA-1 HMAC of every byte read so far.
    pub fn into_parts(self) -> (BoxStream, Option<ReadHash>) {
        (self.io, self.read_hash)
    }

    /// Drive the handshake to completion (writing and reading as needed).
    pub async fn handshake(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| loop {
            if self.connection.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if !self.connection.is_handshaking() {
                return Poll::Ready(Ok(()));
            }
            if self.connection.wants_read() {
                match self.read_io(cx) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))
                    }
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await?;
        std::future::poll_fn(|cx| self.flush_io(cx)).await
    }

    fn read_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut buf = ReadBuf::new(&mut self.read_scratch);
        match Pin::new(&mut self.io).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled();
                if filled.is_empty() {
                    self.eof = true;
                    return Poll::Ready(Ok(0));
                }
                if let Some(hash) = self.read_hash.as_mut() {
                    use hmac::Mac;
                    hash.update(filled);
                }
                if let Some(watch) = self.watch.as_mut() {
                    watch.observe(filled)?;
                }
                let mut slice: &[u8] = filled;
                let read = self
                    .connection
                    .read_tls(&mut slice)
                    .map_err(|e| invalid_owned(format!("tls: {e}")))?;
                self.connection
                    .process_new_packets()
                    .map_err(|e| invalid_owned(format!("tls: {e}")))?;
                Poll::Ready(Ok(read))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn write_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.connection.wants_write() {
            let mut target: &mut [u8] = &mut self.write_scratch;
            let n = self
                .connection
                .write_tls(&mut target)
                .map_err(|e| invalid_owned(format!("tls: {e}")))?;
            if n == 0 {
                break;
            }
            let mut slice = &self.write_scratch[..n];
            while !slice.is_empty() {
                match Pin::new(&mut self.io).poll_write(cx, slice) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)))
                    }
                    Poll::Ready(Ok(wrote)) => slice = &slice[wrote..],
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn flush_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.write_io(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }
}

impl AsyncRead for TlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.connection.reader().read(buf.initialize_unfilled()) {
                Ok(0) => {
                    if self.eof || !self.connection.wants_read() {
                        return Poll::Ready(Ok(()));
                    }
                }
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            if !self.connection.wants_read() {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            match self.read_io(cx) {
                Poll::Ready(Ok(0)) => {
                    if self.connection.is_handshaking() {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for TlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut pos = 0usize;
        while pos < buf.len() {
            match self.connection.writer().write(&buf[pos..]) {
                Ok(n) => pos += n,
                Err(error) => return Poll::Ready(Err(error)),
            }
            match self.flush_io(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    return if pos == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(pos))
                    }
                }
            }
        }
        Poll::Ready(Ok(pos))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_io(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.connection.send_close_notify();
        match self.flush_io(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
