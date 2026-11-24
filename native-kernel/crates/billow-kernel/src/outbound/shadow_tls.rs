//! ShadowTLS (`transport/shadowtls`) as used by `anytls` `shadow-tls-opts`.
//!
//! A ShadowTLS client first performs a *real* TLS handshake (the camouflage
//! handshake, relayed by the ShadowTLS server to a genuine host), then throws
//! that TLS session away and continues in plain cleartext framed as TLS
//! application-data records. The authentication lives in the transition:
//!
//! - **v2** (the pinned default, `version: 0` -> 2): the client HMAC-SHA1s every
//!   byte it *read* during the handshake and prefixes the first application
//!   write with `HMAC[..8]`. The server keeps the last two hashes of what it
//!   wrote, so a `NewSessionTicket` the client has not read yet does not break
//!   the match.
//! - **v1**: only the camouflage handshake; the pinned client then returns the
//!   raw connection.
//! - **v3**: the ClientHello session id carries `HMAC-SHA1(password)` over the
//!   whole hello and the post-handshake records chain HMAC/kdf state. Setting a
//!   ClientHello session id is not expressible through `rustls` (its session id
//!   is generated internally and a rewrite would invalidate the handshake
//!   transcript), so v3 stays a named rejection at load time instead of being
//!   accepted and ignored.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tls::{self, ClientTls};
use super::tls_io::TlsIo;
use super::BoxStream;
use crate::proxies::TlsSettings;

const RECORD_HEADER: usize = 5;
const APPLICATION_DATA: u8 = 23;
const MAX_PLAINTEXT: usize = 16384;
const HMAC_PREFIX: usize = 8;

/// ShadowTLS version selected by `shadow-tls-opts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
}

impl Version {
    /// `version: 0` is the pinned `NewConfig` default (2).
    pub fn from_number(version: i64) -> Option<Version> {
        match version {
            0 | 2 => Some(Version::V2),
            1 => Some(Version::V1),
            _ => None,
        }
    }
}

/// Wrap `stream` in the ShadowTLS v1/v2 security layer (camouflage handshake,
/// then framed cleartext).
pub async fn wrap(
    stream: BoxStream,
    server: &str,
    settings: &TlsSettings,
    tls: &ClientTls,
    password: &str,
    version: u8,
) -> io::Result<BoxStream> {
    let version = Version::from_number(i64::from(version)).unwrap_or(Version::V2);
    // The camouflage handshake hashes every byte read from the socket; the
    // first application write carries the digest (v2 only).
    let hasher = match version {
        Version::V1 => None,
        Version::V2 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(password.as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "shadow-tls: password"))?;
            // `new_from_slice` only fails on an empty key, which the parser
            // rejects; keep the value ready for the running update.
            mac.reset();
            Some(mac)
        }
    };
    let name = settings.sni.clone().unwrap_or_else(|| server.to_string());
    let server_name = rustls_pki_types::ServerName::try_from(name.clone())
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("shadow-tls: invalid server name '{name}': {error}"),
            )
        })?
        .to_owned();
    // Pinned `NewShadowTLS`: an unset ALPN becomes the browser-ish default the
    // camouflage handshake advertises.
    let mut settings = settings.clone();
    if settings.alpn.is_empty() {
        settings.alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    }
    // Pinned `NewShadowTLS`: version 1 caps the camouflage handshake at
    // TLS 1.2 (its relay cannot follow a TLS 1.3 server flight).
    let config = match version {
        Version::V1 => tls::client_config_tls12(&settings, tls)?,
        Version::V2 => tls::shadow_tls_client_config(&settings, tls)?,
    };
    let connection = rustls::ClientConnection::new(config, server_name)
        .map_err(|error| io::Error::other(format!("shadow-tls: {error}")))?;
    let mut io = TlsIo::start(connection, stream, None, None, hasher).await?;
    io.handshake()
        .await
        .map_err(|error| io_error("shadow-tls handshake", error))?;
    let (stream, hasher) = io.into_parts();
    match version {
        Version::V1 => Ok(stream),
        Version::V2 => {
            let mac = hasher.expect("shadow-tls v2 records reads");
            let prefix = mac.finalize().into_bytes()[..HMAC_PREFIX].to_vec();
            Ok(Box::new(ShadowFramed {
                inner: stream,
                out: Vec::new(),
                out_at: 0,
                prefix: Some(prefix),
                read_remaining: 0,
                read_header: [0u8; RECORD_HEADER],
                read_header_at: 0,
                read_scratch: vec![0u8; 16 * 1024],
            }))
        }
    }
}

fn io_error(context: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

/// The post-handshake ShadowTLS framing: plaintext inside TLS application-data
/// records (the outer TLS session is no longer used).
struct ShadowFramed {
    inner: BoxStream,
    out: Vec<u8>,
    out_at: usize,
    /// The 8-byte HMAC prefix of the first write.
    prefix: Option<Vec<u8>>,
    read_remaining: usize,
    read_header: [u8; RECORD_HEADER],
    read_header_at: usize,
    read_scratch: Vec<u8>,
}

impl ShadowFramed {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_at < self.out.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_at..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)))
                }
                Poll::Ready(Ok(wrote)) => self.out_at += wrote,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out.clear();
        self.out_at = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ShadowFramed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Flush leftovers before accepting more input.
        if !self.out.is_empty() {
            match self.poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        // The pinned `clientConn.Write` builds `prefix || p` and then frames
        // it, so the 8-byte digest is the *payload* of the first application
        // record, not bytes written before its header.
        let mut framed = Vec::with_capacity(buf.len() + HMAC_PREFIX);
        if let Some(prefix) = self.prefix.take() {
            framed.extend_from_slice(&prefix);
        }
        framed.extend_from_slice(buf);
        for chunk in framed.chunks(MAX_PLAINTEXT) {
            self.out.push(APPLICATION_DATA);
            self.out.push(3);
            self.out.push(3);
            self.out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            self.out.extend_from_slice(chunk);
        }
        // The whole input is buffered; a pending socket write is flushed by the
        // next call or by `poll_flush`.
        let _ = self.poll_drain(cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl AsyncRead for ShadowFramed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if this.read_remaining > 0 {
                let want = buf.remaining().min(this.read_remaining).min(this.read_scratch.len());
                let mut chunk = ReadBuf::new(&mut this.read_scratch[..want]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut chunk) {
                    Poll::Ready(Ok(())) => {
                        let filled = chunk.filled().len();
                        if filled == 0 {
                            return Poll::Ready(Err(io::Error::from(
                                io::ErrorKind::UnexpectedEof,
                            )));
                        }
                        buf.put_slice(&this.read_scratch[..filled]);
                        this.read_remaining -= filled;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            // Fill the record header.
            let at = this.read_header_at;
            let mut header = ReadBuf::new(&mut this.read_header[at..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut header) {
                Poll::Ready(Ok(())) => {
                    let filled = header.filled().len();
                    if filled == 0 {
                        return Poll::Ready(if this.read_header_at == 0 {
                            Ok(())
                        } else {
                            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
                        });
                    }
                    this.read_header_at += filled;
                    if this.read_header_at < RECORD_HEADER {
                        continue;
                    }
                    this.read_header_at = 0;
                    if this.read_header[0] != APPLICATION_DATA {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "shadow-tls: unexpected TLS record type {}",
                                this.read_header[0]
                            ),
                        )));
                    }
                    this.read_remaining =
                        (usize::from(this.read_header[3]) << 8) | usize::from(this.read_header[4]);
                    if this.read_remaining == 0 {
                        continue;
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_version_numbers_map_to_the_supported_modes() {
        // `NewConfig` keeps `version: 0` as 2; 1 and 2 are the implemented
        // modes and 3 stays a named rejection.
        assert_eq!(Version::from_number(0), Some(Version::V2));
        assert_eq!(Version::from_number(1), Some(Version::V1));
        assert_eq!(Version::from_number(2), Some(Version::V2));
        assert_eq!(Version::from_number(3), None);
    }

    #[tokio::test]
    async fn framing_prefixes_the_hmac_and_uses_application_data_records() {
        let (client, server) = tokio::io::duplex(4096);
        let stream: BoxStream = Box::new(client);
        let (_, mac) = {
            let mut mac = Hmac::<Sha1>::new_from_slice(b"password").unwrap();
            mac.update(b"server-bytes");
            (
                (),
                mac.finalize().into_bytes()[..HMAC_PREFIX].to_vec(),
            )
        };
        let mut framed = ShadowFramed {
            inner: stream,
            out: Vec::new(),
            out_at: 0,
            prefix: Some(mac.clone()),
            read_remaining: 0,
            read_header: [0u8; RECORD_HEADER],
            read_header_at: 0,
            read_scratch: vec![0u8; 4096],
        };
        use tokio::io::AsyncWriteExt;
        framed.write_all(b"hello").await.unwrap();
        framed.flush().await.unwrap();
        let mut server = server;
        let mut received = vec![0u8; 64];
        use tokio::io::AsyncReadExt;
        let n = server.read(&mut received).await.unwrap();
        // The digest is the first eight payload bytes of the first
        // application-data record (pinned `clientConn.Write`).
        assert_eq!(received[0], APPLICATION_DATA);
        assert_eq!(&received[3..5], &[0, 5 + HMAC_PREFIX as u8]);
        assert_eq!(&received[5..5 + HMAC_PREFIX], &mac[..]);
        assert_eq!(&received[5 + HMAC_PREFIX..n], b"hello");
    }
}
