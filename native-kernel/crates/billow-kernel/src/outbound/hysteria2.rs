//! Hysteria2 outbound (`adapter/outbound/hysteria2.go`,
//! `sing-quic/hysteria2`).
//!
//! The authentication request is HTTP/3: a POST to `https://hysteria/auth`
//! with the password in `Hysteria-Auth`, the receive rate in
//! `Hysteria-CC-RX` and random padding in `Hysteria-Padding`; the server
//! answers status `233` when the password is accepted. After that each TCP
//! session is a bidirectional QUIC stream with a Hysteria2 request frame:
//!
//! ```text
//! 0x401 (QUIC varint) || address length (varint) || address ||
//! padding length (varint) || padding
//! ```
//!
//! and the server answers `status (0=ok,1=error) || message length (varint) ||
//! message || padding length (varint) || padding`, then the byte stream.
//!
//! Implemented: TCP, `password`, `sni`/`skip-cert-verify`/`alpn`, `up`/`down`
//! validation, `handshake-timeout`. Rejected by name: `ports`/`hop-interval`
//! (port hopping), `obfs`/`obfs-password` (Salamander/Gecko packet
//! obfuscation needs a custom UDP socket wrapper), `realm-opts`, UDP
//! (`udp-mtu`), and the QUIC congestion/receive-window tuning.
//!
//! A new QUIC connection is created per dial; the pinned client pools one.

use std::io;
use std::time::Duration;

use super::h3;
use super::quic::{self, CongestionController, QuicOptions, QuicStream};
use super::tls::ClientTls;
use super::{DialError, Dialed, Target};
use quinn::RecvStream;

use crate::proxies::Hysteria2Outbound;

const AUTH_STATUS: u16 = 233;
const TCP_REQUEST: u64 = 0x401;

fn timeout_error(timeout: Duration) -> DialError {
    DialError::Timeout(timeout)
}

fn handshake(protocol: &'static str, message: impl std::fmt::Display) -> DialError {
    DialError::Handshake {
        protocol,
        source: io::Error::other(message.to_string()),
    }
}

async fn read_varint(recv: &mut RecvStream) -> Result<u64, DialError> {
    h3::read_varint_async(recv)
        .await
        .map_err(|e| handshake("hysteria2", e))?
        .ok_or_else(|| handshake("hysteria2", "stream ended inside a varint"))
}

async fn read_tcp_response(recv: &mut RecvStream) -> Result<(), DialError> {
    let mut status = [0u8; 1];
    recv.read_exact(&mut status)
        .await
        .map_err(|e| handshake("hysteria2", format!("TCP response: {e}")))?;
    let message_len = read_varint(recv).await?;
    if message_len > 2048 {
        return Err(handshake("hysteria2", "TCP response message too long"));
    }
    let mut message = vec![0u8; message_len as usize];
    recv.read_exact(&mut message)
        .await
        .map_err(|e| handshake("hysteria2", format!("TCP response message: {e}")))?;
    let padding_len = read_varint(recv).await?;
    if padding_len > 4096 {
        return Err(handshake("hysteria2", "TCP response padding too long"));
    }
    let mut padding = vec![0u8; padding_len as usize];
    recv.read_exact(&mut padding)
        .await
        .map_err(|e| handshake("hysteria2", format!("TCP response padding: {e}")))?;
    if status[0] == 0 {
        Ok(())
    } else {
        Err(DialError::Handshake {
            protocol: "hysteria2",
            source: io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("remote error: {}", String::from_utf8_lossy(&message)),
            ),
        })
    }
}

/// Dial `target` through a Hysteria2 server.
pub async fn dial(
    option: &Hysteria2Outbound,
    target: &Target,
    tls: &ClientTls,
    timeout: Duration,
) -> Result<Dialed, DialError> {
    let alpn = if option.alpn.is_empty() {
        vec!["h3".to_string()]
    } else {
        option.alpn.clone()
    };
    let mut quic_options = QuicOptions::new(alpn);
    quic_options.keep_alive = Some(Duration::from_secs(10));
    quic_options.datagrams = true;
    // The pinned client always switches hysteria2 to BBR (`SetBBRCongestion`)
    // with `cwnd` packets (default 32) as the initial window.
    let packets = if option.cwnd == 0 { 32 } else { option.cwnd };
    quic_options.congestion_controller = CongestionController::Bbr;
    quic_options.initial_congestion_window = Some(u64::from(packets) * 1200);
    if let Some(window) = option.stream_receive_window {
        quic_options.stream_receive_window = window;
    }
    if let Some(window) = option.connection_receive_window {
        quic_options.connection_receive_window = window;
    }
    let handshake_timeout = if option.handshake_timeout == 0 {
        timeout
    } else {
        Duration::from_secs(option.handshake_timeout)
    };
    let (connection, endpoint) = quic::connect(
        &option.server,
        &option.server,
        option.port,
        &option.tls_settings,
        tls,
        &quic_options,
        handshake_timeout,
    )
    .await?;

    // HTTP/3 authentication.
    let session = h3::Session::open(connection.clone(), endpoint.clone())
        .await
        .map_err(|e| handshake("hysteria2", format!("HTTP/3 session: {e}")))?;
    let padding = "a".repeat(256);
    let receive = option.receive_bps.to_string();
    let headers = [
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "hysteria"),
        (":path", "/auth"),
        ("hysteria-auth", option.password.expose()),
        ("hysteria-cc-rx", receive.as_str()),
        ("hysteria-padding", padding.as_str()),
    ];
    let response = tokio::time::timeout(handshake_timeout, session.request(&headers))
        .await
        .map_err(|_| timeout_error(handshake_timeout))?
        .map_err(|e| handshake("hysteria2", format!("auth request: {e}")))?;
    if response.status != AUTH_STATUS {
        return Err(DialError::Handshake {
            protocol: "hysteria2",
            source: io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("authentication failed, status code: {}", response.status),
            ),
        });
    }
    let hold = session.into_hold();

    // One bidirectional stream per TCP session.
    let (mut send, mut recv) = tokio::time::timeout(timeout, connection.open_bi())
        .await
        .map_err(|_| timeout_error(timeout))?
        .map_err(|e| handshake("hysteria2", format!("open stream: {e}")))?;
    let mut request = Vec::with_capacity(target.host.len() + 20);
    h3::encode_varint(TCP_REQUEST, &mut request);
    h3::encode_varint(target.authority().len() as u64, &mut request);
    request.extend_from_slice(target.authority().as_bytes());
    h3::encode_varint(0, &mut request); // padding length
    send.write_all(&request)
        .await
        .map_err(|e| handshake("hysteria2", format!("TCP request: {e}")))?;
    read_tcp_response(&mut recv).await?;

    let server = connection.remote_address();
    let stream = QuicStream::with_hold(send, recv, connection, endpoint, hold);
    Ok(Dialed {
        stream: Box::new(stream),
        server,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_request_frame_has_the_pinned_layout() {
        let target = Target {
            host: "example.com".into(),
            port: 443,
        };
        let mut frame = Vec::new();
        h3::encode_varint(TCP_REQUEST, &mut frame);
        h3::encode_varint(target.authority().len() as u64, &mut frame);
        frame.extend_from_slice(target.authority().as_bytes());
        h3::encode_varint(0, &mut frame);
        assert_eq!(&frame[..2], &[0x44, 0x01]); // 0x401 in two-byte QUIC varint
        assert_eq!(frame[2], 15); // "example.com:443"
        assert_eq!(&frame[3..18], b"example.com:443");
        assert_eq!(frame[18], 0);
    }
}
