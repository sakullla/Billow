//! TUIC v5 outbound (`adapter/outbound/tuic.go`, `transport/tuic/v5`).
//!
//! One QUIC connection (TLS 1.3, ALPN `h3` by default) carries every session:
//!
//! 1. the client opens a unidirectional stream and writes
//!    `0x05 0x00 || uuid[16] || token[32]`, where `token` is the TLS exporter
//!    output with the raw 16 UUID bytes as label and the password as context
//!    (`GenToken` in `transport/tuic/v5/protocol.go`);
//! 2. each TCP session opens a bidirectional stream and writes
//!    `0x05 0x01 || address`, then the raw byte stream.
//!
//! Only the v5 `uuid`/`password` authentication is implemented. The legacy v4
//! `token` form needs BLAKE3 (`GenTKN`), which is not in the offline cargo
//! cache, so a `token` entry is rejected by name instead of being loaded as if
//! it were v5. UDP relay modes (`quic` datagrams / `native` uni streams) are
//! not wired into the engine's UDP association yet and are recorded as a gap.
//!
//! A new QUIC connection is established per dial. The pinned client pools one
//! connection and re-authenticates once; pooling changes latency and
//! connection count, not the wire format, and is recorded as an optimisation.

use std::io;
use std::time::Duration;

use super::quic::{self, CongestionController, QuicOptions, QuicStream};
use super::tls::ClientTls;
use super::{DialError, Dialed, Target};

use crate::proxies::TuicOutbound;

const COMMAND_AUTHENTICATE: u8 = 0x00;
const COMMAND_CONNECT: u8 = 0x01;
const VERSION: u8 = 0x05;

/// Encode one target in TUIC's address form: `type` 0 = domain (length byte +
/// name), 1 = IPv4, 2 = IPv6, then the big-endian port.
pub fn encode_address(target: &Target) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(target.host.len() + 19);
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.push(1);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(2);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let name = target.host.as_bytes();
        if name.is_empty() || name.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("TUIC domain name length {} is out of range", name.len()),
            ));
        }
        out.push(0);
        out.push(name.len() as u8);
        out.extend_from_slice(name);
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

/// Read one TUIC address (used by the loopback peer and the tests).
pub fn read_address(bytes: &[u8], offset: usize) -> Option<(Target, usize)> {
    let kind = *bytes.get(offset)?;
    let mut cursor = offset + 1;
    let host = match kind {
        0 => {
            let len = *bytes.get(cursor)? as usize;
            cursor += 1;
            let name = bytes.get(cursor..cursor + len)?;
            cursor += len;
            String::from_utf8(name.to_vec()).ok()?
        }
        1 => {
            let addr = bytes.get(cursor..cursor + 4)?;
            cursor += 4;
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(addr).ok()?).to_string()
        }
        2 => {
            let addr = bytes.get(cursor..cursor + 16)?;
            cursor += 16;
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(addr).ok()?).to_string()
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*bytes.get(cursor)?, *bytes.get(cursor + 1)?]);
    cursor += 2;
    Some((Target { host, port }, cursor - offset))
}

fn timeout_error(timeout: Duration) -> DialError {
    DialError::Timeout(timeout)
}

/// Dial `target` through a TUIC v5 server.
pub async fn dial(
    option: &TuicOutbound,
    target: &Target,
    tls: &ClientTls,
    timeout: Duration,
) -> Result<Dialed, DialError> {
    let address = option.ip.as_deref().unwrap_or(&option.server);
    let alpn = if option.alpn.is_empty() {
        vec!["h3".to_string()]
    } else {
        option.alpn.clone()
    };
    let mut quic_options = QuicOptions::new(alpn);
    quic_options.keep_alive = Some(Duration::from_millis(option.heartbeat_interval.max(1)));
    quic_options.datagrams = true;
    quic_options.disable_sni = option.disable_sni;
    quic_options.mtu_discovery = !option.disable_mtu_discovery;
    if let Some(window) = option.stream_receive_window {
        quic_options.stream_receive_window = window;
    }
    if let Some(window) = option.connection_receive_window {
        quic_options.connection_receive_window = window;
    }
    if let Some(name) = option.congestion_controller.as_deref() {
        quic_options.congestion_controller = match name {
            "cubic" => CongestionController::Cubic,
            "new_reno" => CongestionController::NewReno,
            "bbr" => CongestionController::Bbr,
            _ => CongestionController::Default,
        };
        let packets = if option.cwnd == 0 { 32 } else { option.cwnd };
        quic_options.initial_congestion_window = Some(u64::from(packets) * 1200);
    } else if option.cwnd != 0 {
        // quic-go ignores `cwnd` when no controller is named; applying it to
        // the default controller keeps the value meaningful.
        quic_options.initial_congestion_window = Some(u64::from(option.cwnd) * 1200);
    }
    let (connection, endpoint) = quic::connect(
        &option.server,
        address,
        option.port,
        &option.tls_settings,
        tls,
        &quic_options,
        timeout,
    )
    .await?;

    // `request-timeout` bounds each TUIC request operation (the auth stream
    // and the Connect stream). The pinned v5 client has no Connect response to
    // read, so this is the closest observable use of the option; the value is
    // milliseconds and defaults to 8000, as in `TuicOption`.
    let request_timeout = Duration::from_millis(option.request_timeout.max(1));

    // Authentication: one unidirectional stream per connection.
    let mut token = [0u8; 32];
    quic::export_keying_material(
        &connection,
        &mut token,
        &option.uuid,
        option.password.expose().as_bytes(),
    )?;
    let mut auth = Vec::with_capacity(2 + 16 + 32);
    auth.push(VERSION);
    auth.push(COMMAND_AUTHENTICATE);
    auth.extend_from_slice(&option.uuid);
    auth.extend_from_slice(&token);
    let mut auth_stream = tokio::time::timeout(request_timeout, connection.open_uni())
        .await
        .map_err(|_| timeout_error(request_timeout))?
        .map_err(|e| DialError::Handshake {
            protocol: "tuic",
            source: io::Error::other(format!("open unidirectional stream: {e}")),
        })?;
    tokio::time::timeout(request_timeout, auth_stream.write_all(&auth))
        .await
        .map_err(|_| timeout_error(request_timeout))?
        .map_err(|e| DialError::Handshake {
            protocol: "tuic",
            source: io::Error::other(format!("authentication: {e}")),
        })?;
    auth_stream.finish().map_err(|e| DialError::Handshake {
        protocol: "tuic",
        source: io::Error::other(format!("authentication finish: {e}")),
    })?;

    // One bidirectional stream per TCP session.
    let (mut send, recv) = tokio::time::timeout(request_timeout, connection.open_bi())
        .await
        .map_err(|_| timeout_error(request_timeout))?
        .map_err(|e| DialError::Handshake {
            protocol: "tuic",
            source: io::Error::other(format!("open stream: {e}")),
        })?;
    let mut header = Vec::with_capacity(2 + target.host.len() + 19);
    header.push(VERSION);
    header.push(COMMAND_CONNECT);
    header.extend_from_slice(
        &encode_address(target).map_err(|source| DialError::Handshake {
            protocol: "tuic",
            source,
        })?,
    );
    tokio::time::timeout(request_timeout, send.write_all(&header))
        .await
        .map_err(|_| timeout_error(request_timeout))?
        .map_err(|e| DialError::Handshake {
            protocol: "tuic",
            source: io::Error::other(format!("connect request: {e}")),
        })?;

    let server = connection.remote_address();
    let stream = QuicStream::new(send, recv, connection, endpoint);
    Ok(Dialed {
        stream: Box::new(stream),
        server,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_encoding_uses_tuic_type_numbers() {
        let v4 = encode_address(&Target {
            host: "127.0.0.1".into(),
            port: 443,
        })
        .unwrap();
        assert_eq!(v4, vec![1, 127, 0, 0, 1, 1, 187]);
        let v6 = encode_address(&Target {
            host: "::1".into(),
            port: 1,
        })
        .unwrap();
        assert_eq!(v6[0], 2);
        assert_eq!(v6.len(), 19);
        let name = encode_address(&Target {
            host: "example.org".into(),
            port: 80,
        })
        .unwrap();
        assert_eq!(&name[..2], &[0, 11]);
        assert_eq!(&name[2..13], b"example.org");
        assert_eq!(&name[13..], &[0, 80]);
        let (target, used) = read_address(&name, 0).unwrap();
        assert_eq!(target.host, "example.org");
        assert_eq!(target.port, 80);
        assert_eq!(used, name.len());
    }

    #[test]
    fn empty_domain_is_rejected() {
        assert!(encode_address(&Target {
            host: String::new(),
            port: 1
        })
        .is_err());
    }
}
