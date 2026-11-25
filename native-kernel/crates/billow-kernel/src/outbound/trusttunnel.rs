//! TrustTunnel outbound: TLS + HTTP/2 `CONNECT`.
//!
//! The pinned `transport/trusttunnel` client opens an HTTP/2 connection (ALPN
//! `h2`) and sends a `CONNECT` request whose `:authority` is the target and
//! whose `Proxy-Authorization` is `Basic base64(user:password)`. A `200`
//! response turns the stream into the tunnel: request body bytes travel as
//! DATA frames, response body bytes come back as DATA frames. The `_udp2`
//! magic authority opens the same h2 stream as a framed packet association
//! ([`TrustTunnelUdp`]); ICMP (`_icmp`) and the QUIC transport are still
//! rejected at load time instead of being ignored.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::tls::ClientTls;
use super::{base64, connect_tcp, handshake, tls, DialError, Dialed, Target};
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
    let user_agent = format!("{} billow-kernel/{}", std::env::consts::OS, env!("CARGO_PKG_VERSION"));
    let (stream, server) = open(option, &target.authority(), &user_agent, tls).await?;
    Ok(Dialed {
        stream: Box::new(stream),
        server,
    })
}

/// Open one HTTP/2 CONNECT stream whose `:authority` is `authority`. The TCP
/// transport passes the target, the UDP association the `_udp2` magic name;
/// both share the pinned TLS/h2/auth setup.
async fn open(
    option: &TrustTunnelOutbound,
    authority: &str,
    user_agent: &str,
    tls: &ClientTls,
) -> Result<(H2Tunnel, std::net::SocketAddr), DialError> {
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
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(authority)
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
    Ok((H2Tunnel::new(send, recv, connection), server))
}

/// The `_udp2` packet stream of one TrustTunnel association.
///
/// Pinned `writePacketToServer` / `readPacketFromServer`: every datagram is a
/// length-prefixed record on the h2 stream,
/// `u32 length | source 16+2 | destination 16+2 | u8 app-name length | app name | payload`
/// in the client-to-server direction and
/// `u32 length | source 16+2 | local 16+2 | payload` back. Addresses are
/// 16-byte forms (IPv4 in the last four bytes) and the length covers
/// everything after itself. Like the pinned client, a destination must be an
/// IP: names are resolved first (that is what the pinned `ResolveUDP` does
/// before it builds the association).
pub struct TrustTunnelUdp {
    tunnel: H2Tunnel,
    read_buf: Vec<u8>,
}

/// The pinned `AppName` field's value (`C.Name`); the server only skips it.
const APP_NAME: &str = "mihomo";

impl TrustTunnelUdp {
    /// `via` is the `dialer-proxy` chain of the matched proxy. The association
    /// is an h2 stream over the TLS connection to the server, and the TCP
    /// transport already refuses a `dialer-proxy` exit at dial time, so a
    /// chain is refused here rather than silently bypassed.
    pub async fn connect(
        option: &TrustTunnelOutbound,
        via: &[&crate::proxies::Proxy],
        _timeout: std::time::Duration,
        tls: &ClientTls,
    ) -> Result<TrustTunnelUdp, DialError> {
        debug_assert!(option.udp);
        if via.len() > 1 {
            return Err(DialError::Chain(format!(
                "udp through {}({}): trusttunnel does not support a dialer-proxy chain",
                via[0].name,
                via[0].type_name()
            )));
        }
        let user_agent = format!("{} _udp2", std::env::consts::OS);
        let (tunnel, _) = open(option, "_udp2", &user_agent, tls).await?;
        Ok(TrustTunnelUdp {
            tunnel,
            read_buf: Vec::new(),
        })
    }

    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        let address = match target.host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => super::udp::resolve(target).await?.ip(),
        };
        if payload.len() > super::udp::MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trusttunnel UDP payload exceeds the datagram limit",
            ));
        }
        let frame = encode_packet(address, target.port, payload);
        self.tunnel.write_all(&frame).await?;
        self.tunnel.flush().await
    }

    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        loop {
            if self.read_buf.len() >= 4 {
                let length = u32::from_be_bytes([
                    self.read_buf[0],
                    self.read_buf[1],
                    self.read_buf[2],
                    self.read_buf[3],
                ]) as usize;
                if length < 16 + 2 + 16 + 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trusttunnel UDP length is shorter than its header",
                    ));
                }
                if self.read_buf.len() >= 4 + length {
                    let (target, payload) = decode_packet(&self.read_buf[4..4 + length])?;
                    if payload.len() > buffer.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "trusttunnel UDP payload exceeds the receive buffer",
                        ));
                    }
                    buffer[..payload.len()].copy_from_slice(payload);
                    let read = payload.len();
                    self.read_buf.drain(..4 + length);
                    return Ok(Some((target, read)));
                }
            }
            let mut chunk = [0u8; 4096];
            let read = self.tunnel.read(&mut chunk).await?;
            if read == 0 {
                return Ok(None);
            }
            self.read_buf.extend_from_slice(&chunk[..read]);
            if self.read_buf.len() > 4 * super::udp::MAX_DATAGRAM {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "trusttunnel UDP frame buffer exceeded",
                ));
            }
        }
    }
}

/// The client-to-server record of pinned `writePacketToServer`: the length
/// covers everything after itself, the source address/port are zero (unknown)
/// and the destination is the padded 16-byte address.
fn encode_packet(address: IpAddr, port: u16, payload: &[u8]) -> Vec<u8> {
    let app = APP_NAME;
    let length = 16 + 2 + 16 + 2 + 1 + app.len() + payload.len();
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&(length as u32).to_be_bytes());
    frame.extend_from_slice(&[0u8; 16]);
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&padding_ip(address));
    frame.extend_from_slice(&port.to_be_bytes());
    frame.push(app.len() as u8);
    frame.extend_from_slice(app.as_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// The server-to-client record body of pinned `readPacketFromServer`:
/// `source 16+2 | local 16+2 | payload`.
fn decode_packet(body: &[u8]) -> io::Result<(Target, &[u8])> {
    if body.len() < 36 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trusttunnel UDP record is shorter than its header",
        ));
    }
    let address = parse_padding_ip(&body[..16]);
    let port = u16::from_be_bytes([body[16], body[17]]);
    Ok((
        Target {
            host: address.to_string(),
            port,
        },
        &body[36..],
    ))
}

/// `buildPaddingIP`: IPv4 in the last four bytes of the 16-byte form.
fn padding_ip(addr: IpAddr) -> [u8; 16] {
    let mut buffer = [0u8; 16];
    match addr {
        IpAddr::V4(ip) => buffer[12..].copy_from_slice(&ip.octets()),
        IpAddr::V6(ip) => buffer = ip.octets(),
    }
    buffer
}

/// `parse16BytesIP`: a zero prefix (except `::1`) means IPv4 in the last four
/// bytes, as the pinned helper decodes it.
fn parse_padding_ip(bytes: &[u8]) -> IpAddr {
    let zero_prefix = bytes[..12].iter().all(|byte| *byte == 0);
    let loopback = bytes[12..16] == [0, 0, 0, 1];
    if zero_prefix && !loopback {
        IpAddr::V4(std::net::Ipv4Addr::new(
            bytes[12], bytes[13], bytes[14], bytes[15],
        ))
    } else {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&bytes[..16]);
        IpAddr::V6(octets.into())
    }
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

    #[test]
    fn udp_packet_framing_matches_the_pinned_layout() {
        // `packet.go::writePacketToServer`: IPv4 padded into the last four
        // bytes, zero source address/port, `mihomo` app name, payload.
        let frame = encode_packet(
            "10.0.0.7".parse().unwrap(),
            5353,
            b"payload",
        );
        assert_eq!(&frame[..4], &((16 + 2 + 16 + 2 + 1 + 6 + 7u32) as u32).to_be_bytes());
        assert!(frame[4..20].iter().all(|byte| *byte == 0), "source address");
        assert_eq!(&frame[20..22], &[0, 0], "source port");
        assert_eq!(&frame[22..38], &padding_ip("10.0.0.7".parse().unwrap()));
        assert_eq!(&frame[38..40], &5353u16.to_be_bytes());
        assert_eq!(frame[40], 6);
        assert_eq!(&frame[41..47], b"mihomo");
        assert_eq!(&frame[47..], b"payload");

        // The reply body the pinned `readPacketFromServer` parses back:
        // `source 16+2 | local 16+2 | payload`.
        let mut body = Vec::new();
        body.extend_from_slice(&padding_ip("192.0.2.9".parse().unwrap()));
        body.extend_from_slice(&443u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(b"reply");
        let (target, payload) = decode_packet(&body).expect("reply decodes");
        assert_eq!(target.host, "192.0.2.9");
        assert_eq!(target.port, 443);
        assert_eq!(payload, b"reply");

        // IPv6 keeps the full 16 bytes; `::1` is not read as an IPv4 address.
        let ipv6 = padding_ip("2001:db8::1".parse().unwrap());
        assert_eq!(parse_padding_ip(&ipv6), "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(
            parse_padding_ip(&padding_ip("::1".parse().unwrap())),
            "::1".parse::<IpAddr>().unwrap()
        );
    }
}
