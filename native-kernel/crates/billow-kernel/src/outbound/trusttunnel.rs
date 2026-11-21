//! TrustTunnel outbound: TLS + HTTP/2 `CONNECT`.
//!
//! The pinned `transport/trusttunnel` client opens an HTTP/2 connection (ALPN
//! `h2`) and sends a `CONNECT` request whose `:authority` is the target and
//! whose `Proxy-Authorization` is `Basic base64(user:password)`. A `200`
//! response turns the stream into the tunnel: request body bytes travel as
//! DATA frames, response body bytes come back as DATA frames. The server's
//! UDP (`_udp2`) and ICMP (`_icmp`) magic authorities are not implemented, and
//! neither is the QUIC transport, so `udp: true` and `quic: true` are rejected
//! at load time instead of being ignored.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tls::ClientTls;
use super::{base64, connect_tcp, handshake, tls, BoxStream, DialError, Dialed, Target};
use crate::proxies::TrustTunnelOutbound;

type ConnectionFuture = Pin<Box<dyn Future<Output = Result<(), h2::Error>> + Send>>;

/// The HTTP/2 tunnel stream handed to the session.
///
/// The h2 connection future is owned by the stream (not spawned), so it is
/// driven by the session task and dropped with it: `Kernel::stop()` still
/// joins everything, and no connection task outlives the tunnel.
pub struct H2Tunnel {
    send: SendStream<Bytes>,
    recv: RecvStream,
    connection: ConnectionFuture,
    connection_done: bool,
    read_buf: Bytes,
    read_eof: bool,
    write_eof: bool,
}

impl H2Tunnel {
    fn new(send: SendStream<Bytes>, recv: RecvStream, connection: ConnectionFuture) -> H2Tunnel {
        H2Tunnel {
            send,
            recv,
            connection,
            connection_done: false,
            read_buf: Bytes::new(),
            read_eof: false,
            write_eof: false,
        }
    }

    /// Drive the connection future; a completed connection means the peer (or
    /// the transport) closed it.
    fn poll_connection(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.connection_done {
            return Poll::Ready(Ok(()));
        }
        match self.connection.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                self.connection_done = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.connection_done = true;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("trusttunnel connection: {error}"),
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for H2Tunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Poll::Ready(Err(error)) = self.poll_connection(cx) {
            return Poll::Ready(Err(error));
        }
        loop {
            if !self.read_buf.is_empty() {
                let take = self.read_buf.len().min(buf.remaining());
                let chunk = self.read_buf.split_to(take);
                buf.put_slice(&chunk);
                // Return the consumed flow-control window to the peer.
                let _ = self.recv.flow_control().release_capacity(take);
                return Poll::Ready(Ok(()));
            }
            if self.read_eof {
                return Poll::Ready(Ok(()));
            }
            match self.recv.poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    if data.is_empty() {
                        let _ = self.recv.flow_control().release_capacity(0);
                        continue;
                    }
                    self.read_buf = data;
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("trusttunnel stream: {error}"),
                    )))
                }
                Poll::Ready(None) => {
                    self.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2Tunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_eof {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "trusttunnel stream is already half-closed",
            )));
        }
        if let Poll::Ready(Err(error)) = self.poll_connection(cx) {
            return Poll::Ready(Err(error));
        }
        // h2 assigns capacity only after it is requested (see
        // `SendStream::reserve_capacity`), so request the whole buffer first.
        self.send.reserve_capacity(buf.len());
        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(0))) => Poll::Pending,
            Poll::Ready(Some(Ok(capacity))) => {
                let take = capacity.min(buf.len());
                self.send
                    .send_data(Bytes::copy_from_slice(&buf[..take]), false)
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!("trusttunnel stream: {error}"),
                        )
                    })?;
                Poll::Ready(Ok(take))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("trusttunnel stream: {error}"),
            ))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "trusttunnel stream closed by the peer",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // `send_data` queues the frames; the connection task flushes them.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_eof {
            self.write_eof = true;
            self.send
                .send_data(Bytes::new(), true)
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("trusttunnel stream: {error}"),
                    )
                })?;
        }
        Poll::Ready(Ok(()))
    }
}

pub async fn dial(
    option: &TrustTunnelOutbound,
    target: &Target,
    tls: &ClientTls,
) -> Result<Dialed, DialError> {
    let tcp = connect_tcp(&option.server, option.port).await?;
    let server = tcp.peer_addr().map_err(|e| handshake("trusttunnel", e))?;
    let mut settings = option.tls_settings.clone();
    if settings.alpn.is_empty() {
        settings.alpn = vec!["h2".to_string()];
    }
    let stream = tls::wrap(tcp, &option.server, &settings, tls)
        .await
        .map_err(|e| handshake("trusttunnel tls", e))?;

    let (send_request, connection) = h2::client::handshake(stream)
        .await
        .map_err(|e| handshake("trusttunnel h2", io::Error::other(e)))?;
    let mut connection: ConnectionFuture = Box::pin(connection);

    let mut send_request = send_request;
    let auth = format!(
        "Basic {}",
        base64(
            format!("{}:{}", option.username.expose(), option.password.expose()).as_bytes()
        )
    );
    let user_agent = format!("{} billow-kernel/{}", std::env::consts::OS, env!("CARGO_PKG_VERSION"));
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(target.authority())
        .header(http::header::PROXY_AUTHORIZATION, auth)
        .header(http::header::USER_AGENT, user_agent)
        .body(())
        .map_err(|e| handshake("trusttunnel request", io::Error::other(e)))?;

    let (response, send) = send_request
        .send_request(request, false)
        .map_err(|e| handshake("trusttunnel request", io::Error::other(e)))?;
    // Await the response while driving the connection: the connection future
    // is later owned by the tunnel, so it must not be spawned or abandoned.
    let mut response = response;
    let response = loop {
        tokio::select! {
            result = &mut response => break result
                .map_err(|e| handshake("trusttunnel response", io::Error::other(e)))?,
            result = &mut connection => {
                let _ = result;
                return Err(handshake(
                    "trusttunnel response",
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "the HTTP/2 connection closed before the CONNECT response",
                    ),
                ));
            }
        }
    };
    let status = response.status();
    if status != http::StatusCode::OK {
        return Err(handshake(
            "trusttunnel response",
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "trusttunnel server answered {status} (wrong credentials or unsupported target)"
                ),
            ),
        ));
    }
    let recv = response.into_body();
    let stream: BoxStream = Box::new(H2Tunnel::new(send, recv, connection));
    Ok(Dialed { stream, server })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_authorization_matches_rfc7617() {
        assert_eq!(
            format!(
                "Basic {}",
                base64(format!("{}:{}", "alice", "s3cret").as_bytes())
            ),
            "Basic YWxpY2U6czNjcmV0"
        );
    }
}
