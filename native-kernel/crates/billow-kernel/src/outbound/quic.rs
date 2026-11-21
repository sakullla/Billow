//! QUIC transport shared by the T10 families (`hysteria`, `hysteria2`, `tuic`,
//! `shadowquic`).
//!
//! `quinn` 0.11 is the QUIC implementation. It is configured from the same
//! `ClientTls` roots and `TlsSettings` as the TCP/TLS outbounds, but a QUIC
//! handshake always uses TLS 1.3 and a non-empty ALPN list. One endpoint (UDP
//! socket) and one connection are created per dial: the pinned clients pool
//! connections, which changes performance and port-hopping behaviour but not
//! the wire protocol, so a pooled client is a later optimisation recorded in
//! `tool/kernel-compat/evidence/rust-mapping.json` rather than a compatibility
//! claim.
//!
//! A bidirectional QUIC stream is exposed as the kernel's normal
//! `AsyncRead + AsyncWrite` stream. The wrapper keeps the `Connection` and
//! `Endpoint` alive for as long as the stream is used.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, TransportConfig, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tls::{self, ClientTls};
use super::DialError;
use crate::proxies::TlsSettings;

/// A bidirectional QUIC stream plus the handles that keep its connection and
/// UDP endpoint alive. Dropping the wrapper closes the connection.
pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
    connection: Connection,
    endpoint: Endpoint,
    /// Streams that must stay open while this session is used (HTTP/3 control
    /// and QPACK streams for Hysteria2).
    hold: Vec<SendStream>,
}

impl QuicStream {
    pub fn new(
        send: SendStream,
        recv: RecvStream,
        connection: Connection,
        endpoint: Endpoint,
    ) -> QuicStream {
        QuicStream::with_hold(send, recv, connection, endpoint, Vec::new())
    }

    pub fn with_hold(
        send: SendStream,
        recv: RecvStream,
        connection: Connection,
        endpoint: Endpoint,
        hold: Vec<SendStream>,
    ) -> QuicStream {
        QuicStream {
            send,
            recv,
            connection,
            endpoint,
            hold,
        }
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Split into the send/receive halves while keeping the connection alive in
    /// both halves (used by UDP associations).
    pub fn into_halves(
        self,
    ) -> (
        SendStream,
        RecvStream,
        Connection,
        Endpoint,
        Vec<SendStream>,
    ) {
        (
            self.send,
            self.recv,
            self.connection,
            self.endpoint,
            self.hold,
        )
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map(|result| result.map_err(|e| io::Error::other(e.to_string())))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // quinn flushes on every write; there is no separate flush state.
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // `finish` sends the QUIC FIN; the connection stays alive for the
        // peer's response and the wrapper's other direction.
        std::pin::Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// Knobs a family sets on the QUIC handshake. The pinned clients differ in
/// keep-alive, idle timeout and datagram buffers; only values that change the
/// handshake/transport behaviour are carried here.
#[derive(Debug, Clone)]
pub struct QuicOptions {
    /// ALPN protocols; a QUIC handshake requires at least one.
    pub alpn: Vec<String>,
    /// QUIC idle timeout; `None` keeps quinn's default (30 s).
    pub max_idle_timeout: Option<Duration>,
    /// Keep-alive interval; `None` disables keep-alive.
    pub keep_alive: Option<Duration>,
    /// Advertise and buffer QUIC datagrams (TUIC native UDP, hysteria UDP).
    pub datagrams: bool,
    /// `disable-sni`: send no SNI and accept any certificate (TUIC).
    pub disable_sni: bool,
}

impl QuicOptions {
    pub fn new(alpn: Vec<String>) -> QuicOptions {
        QuicOptions {
            alpn,
            max_idle_timeout: Some(Duration::from_secs(30)),
            keep_alive: None,
            datagrams: false,
            disable_sni: false,
        }
    }
}

/// Establish one QUIC connection to `server:port`.
///
/// `address` is the host actually dialled (`tuic`'s `ip` option overrides the
/// configured server while the certificate name stays `server`/`sni`).
pub async fn connect(
    server: &str,
    address: &str,
    port: u16,
    settings: &TlsSettings,
    tls: &ClientTls,
    options: &QuicOptions,
    timeout: Duration,
) -> Result<(Connection, Endpoint), DialError> {
    if options.alpn.is_empty() {
        return Err(DialError::Handshake {
            protocol: "quic",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "a QUIC handshake needs at least one ALPN protocol",
            ),
        });
    }
    let target = super::resolve(address, port).await?;
    let bind: SocketAddr = if target.is_ipv4() {
        SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0)
    } else {
        SocketAddr::new(IpAddr::from([0u16; 8]), 0)
    };
    let endpoint = Endpoint::client(bind).map_err(|source| DialError::Connect {
        addr: bind.to_string(),
        source,
    })?;

    let rustls_config = tls::quic_client_config(settings, tls, &options.alpn, !options.disable_sni)
        .map_err(|source| DialError::Handshake {
            protocol: "quic tls",
            source,
        })?;
    let quic_crypto =
        QuicClientConfig::try_from(rustls_config).map_err(|e| DialError::Handshake {
            protocol: "quic tls",
            source: io::Error::new(io::ErrorKind::InvalidInput, e.to_string()),
        })?;
    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = TransportConfig::default();
    // T7's 40 MB iOS budget: the quinn defaults are 1.25 MB per stream
    // receive window, a 10 MB send window and an unbounded connection receive
    // window. Those defaults are for a desktop proxy, not a Network Extension;
    // cap them here and record the numbers in evidence/t10-feasibility.json.
    // Window sizes are local flow-control choices and do not change the wire
    // protocol.
    transport.stream_receive_window(VarInt::from_u32(512 * 1024));
    transport.receive_window(VarInt::from_u32(2 * 1024 * 1024));
    transport.send_window(2 * 1024 * 1024);
    if let Some(idle) = options.max_idle_timeout {
        let idle = quinn::IdleTimeout::try_from(idle).map_err(|_| DialError::Handshake {
            protocol: "quic",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC idle timeout out of range",
            ),
        })?;
        transport.max_idle_timeout(Some(idle));
    }
    transport.keep_alive_interval(options.keep_alive);
    if options.datagrams {
        transport.datagram_receive_buffer_size(Some(64 * 1024));
        transport.datagram_send_buffer_size(64 * 1024);
    }
    client_config.transport_config(Arc::new(transport));

    // The certificate name is `sni` when set, else the configured server (never
    // the `ip` override: that is only the address that is dialled).
    let server_name = settings.sni.as_deref().unwrap_or(server).to_string();
    let connecting = endpoint
        .connect_with(client_config, target, &server_name)
        .map_err(|e| DialError::Connect {
            addr: target.to_string(),
            source: io::Error::other(e.to_string()),
        })?;
    let connection = tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| DialError::Timeout(timeout))?
        .map_err(|e| DialError::Handshake {
            protocol: "quic",
            source: io::Error::other(e.to_string()),
        })?;
    Ok((connection, endpoint))
}

/// Export TLS keying material (TUIC v5 token). `label`/`context` are the exact
/// bytes the pinned `GenToken` passes to `ExportKeyingMaterial`.
pub fn export_keying_material(
    connection: &Connection,
    output: &mut [u8],
    label: &[u8],
    context: &[u8],
) -> Result<(), DialError> {
    connection
        .export_keying_material(output, label, context)
        .map_err(|e| DialError::Handshake {
            protocol: "quic exporter",
            source: io::Error::other(format!("TLS exporter failed: {e:?}")),
        })
}

/// Error code helper for QUIC application close codes.
pub fn varint(value: u64) -> VarInt {
    VarInt::from_u64(value).unwrap_or(VarInt::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_never_panics_on_out_of_range_values() {
        assert_eq!(varint(0).into_inner(), 0);
        assert_eq!(varint(u64::MAX), VarInt::MAX);
    }
}
