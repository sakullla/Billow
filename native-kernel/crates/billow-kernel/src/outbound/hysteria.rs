//! Hysteria v1 outbound (`adapter/outbound/hysteria.go`,
//! `transport/hysteria/core`).
//!
//! One QUIC connection (ALPN `hysteria` by default) carries a control stream
//! with a binary hello and one bidirectional stream per TCP session:
//!
//! - control: `version=3 (u8) || sendBPS (u64 BE) || recvBPS (u64 BE) ||
//!   auth length (u16 BE) || auth`, answered by `ok (u8) || sendBPS (u64) ||
//!   recvBPS (u64) || message length (u16) || message`;
//! - session: `udp (u8=0) || host length (u16 BE) || host || port (u16 BE)`,
//!   answered by `ok (u8) || udp session id (u32) || message length (u16) ||
//!   message`, then the raw byte stream.
//!
//! Implemented: TCP, `auth`/`auth-str`, `sni`/`skip-cert-verify`/`alpn`,
//! `up`/`down` validation. Not implemented and rejected by name: port hopping
//! (`ports`/`hop-interval`), the XPlus obfuscator (`obfs`), the `faketcp` and
//! `wechat` transports, UDP datagrams, and the receive-window/MTU/0-RTT tuning.
//! The pinned client pools one connection; this client dials one connection per
//! session (same wire format, no pooling).

use std::io;
use std::time::Duration;

use super::quic::{self, QuicOptions, QuicStream};
use super::tls::ClientTls;
use super::{DialError, Dialed, Target};

use crate::proxies::HysteriaOutbound;

const PROTOCOL_VERSION: u8 = 3;

fn timeout_error(timeout: Duration) -> DialError {
    DialError::Timeout(timeout)
}

/// Decode standard base64 (the `auth` option is `base64.StdEncoding` in the
/// pinned client). Padding is required, as Go's decoder requires it by default.
pub fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err("base64 length is not a multiple of 4".to_string());
    }
    let value = |c: u8| -> Option<u8> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let last = index + 1 == bytes.len() / 4;
        let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (!last && pad > 0) {
            return Err("base64 padding is misplaced".to_string());
        }
        let mut block = [0u8; 4];
        for (slot, byte) in block.iter_mut().zip(chunk) {
            *slot = if *byte == b'=' {
                0
            } else {
                value(*byte).ok_or_else(|| "base64 has an invalid character".to_string())?
            };
        }
        let triple = ((block[0] as u32) << 18)
            | ((block[1] as u32) << 12)
            | ((block[2] as u32) << 6)
            | block[3] as u32;
        out.push((triple >> 16) as u8);
        if pad < 2 {
            out.push((triple >> 8) as u8);
        }
        if pad < 1 {
            out.push(triple as u8);
        }
    }
    Ok(out)
}

/// `utils.StringToBps`: a bare integer means Mbps (1e6 bits/s = 125000
/// bytes/s); otherwise `^(\d+)\s*([KMGT]?)([Bb])ps$`, where `bps` is bits and
/// `Bps` is bytes.
pub fn string_to_bps(input: &str) -> u64 {
    if input.is_empty() {
        return 0;
    }
    if let Ok(value) = input.parse::<u64>() {
        return value.saturating_mul(125_000);
    }
    let Some((number, rest)) = input.split_once(|c: char| !c.is_ascii_digit()) else {
        return 0;
    };
    let Ok(value) = number.parse::<u64>() else {
        return 0;
    };
    let rest = rest.trim_start();
    let (multiplier, tail) = match rest.chars().next() {
        Some('K') => (1_000u64, &rest[1..]),
        Some('M') => (1_000_000, &rest[1..]),
        Some('G') => (1_000_000_000, &rest[1..]),
        Some('T') => (1_000_000_000_000, &rest[1..]),
        _ => (1, rest),
    };
    let mut bps = value.saturating_mul(multiplier);
    match tail {
        "bps" => bps /= 8,
        "Bps" => {}
        _ => return 0,
    }
    bps
}

/// `utils.StringToBps` validation: a bare integer means Mbps; otherwise the
/// pinned regex is `^(\d+)\s*([KMGT]?)([Bb])ps$`.
pub fn valid_speed(input: &str) -> bool {
    string_to_bps(input) > 0
}

fn write_u16(out: &mut Vec<u8>, value: usize) -> Result<(), DialError> {
    let value = u16::try_from(value).map_err(|_| DialError::Handshake {
        protocol: "hysteria",
        source: io::Error::new(io::ErrorKind::InvalidInput, "field longer than 65535 bytes"),
    })?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Dial `target` through a Hysteria v1 server.
pub async fn dial(
    option: &HysteriaOutbound,
    target: &Target,
    tls: &ClientTls,
    timeout: Duration,
) -> Result<Dialed, DialError> {
    let alpn = if option.alpn.is_empty() {
        vec!["hysteria".to_string()]
    } else {
        option.alpn.clone()
    };
    let mut quic_options = QuicOptions::new(alpn);
    quic_options.keep_alive = Some(Duration::from_secs(10));
    quic_options.datagrams = true;
    quic_options.mtu_discovery = !option.disable_mtu_discovery;
    if let Some(window) = option.stream_receive_window {
        quic_options.stream_receive_window = window;
    }
    if let Some(window) = option.connection_receive_window {
        quic_options.connection_receive_window = window;
    }
    let (connection, endpoint) = quic::connect(
        &option.server,
        &option.server,
        option.port,
        &option.tls_settings,
        tls,
        &quic_options,
        timeout,
    )
    .await?;

    // Control stream: hello and the server's verdict.
    let (mut control_send, mut control_recv) = tokio::time::timeout(timeout, connection.open_bi())
        .await
        .map_err(|_| timeout_error(timeout))?
        .map_err(|e| DialError::Handshake {
            protocol: "hysteria",
            source: io::Error::other(format!("open control stream: {e}")),
        })?;
    let mut hello = Vec::with_capacity(19 + option.auth.len());
    hello.push(PROTOCOL_VERSION);
    hello.extend_from_slice(&option.send_bps.to_be_bytes());
    hello.extend_from_slice(&option.receive_bps.to_be_bytes());
    write_u16(&mut hello, option.auth.len())?;
    hello.extend_from_slice(&option.auth);
    control_send
        .write_all(&hello)
        .await
        .map_err(|e| DialError::Handshake {
            protocol: "hysteria",
            source: io::Error::other(format!("client hello: {e}")),
        })?;

    let mut head = [0u8; 19];
    control_recv
        .read_exact(&mut head)
        .await
        .map_err(|e| DialError::Handshake {
            protocol: "hysteria",
            source: io::Error::other(format!("server hello: {e}")),
        })?;
    if head[0] != 1 {
        let message_len = u16::from_be_bytes([head[17], head[18]]) as usize;
        let mut message = vec![0u8; message_len.min(2048)];
        let _ = control_recv.read_exact(&mut message).await;
        return Err(DialError::Handshake {
            protocol: "hysteria",
            source: io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "authentication failed: {}",
                    String::from_utf8_lossy(&message)
                ),
            ),
        });
    }
    // The control stream is not used after the hello.
    let _ = control_send.finish();
    drop(control_recv);

    // One bidirectional stream per TCP session.
    let (mut send, recv) = tokio::time::timeout(timeout, connection.open_bi())
        .await
        .map_err(|_| timeout_error(timeout))?
        .map_err(|e| DialError::Handshake {
            protocol: "hysteria",
            source: io::Error::other(format!("open stream: {e}")),
        })?;
    let mut request = Vec::with_capacity(5 + target.host.len());
    request.push(0); // TCP, not UDP
    write_u16(&mut request, target.host.len())?;
    request.extend_from_slice(target.host.as_bytes());
    request.extend_from_slice(&target.port.to_be_bytes());
    send.write_all(&request)
        .await
        .map_err(|e| DialError::Handshake {
            protocol: "hysteria",
            source: io::Error::other(format!("client request: {e}")),
        })?;

    let mut response = [0u8; 7];
    let mut recv = recv;
    recv.read_exact(&mut response)
        .await
        .map_err(|e| DialError::Handshake {
            protocol: "hysteria",
            source: io::Error::other(format!("server response: {e}")),
        })?;
    if response[0] != 1 {
        let message_len = u16::from_be_bytes([response[5], response[6]]) as usize;
        let mut message = vec![0u8; message_len.min(2048)];
        let _ = recv.read_exact(&mut message).await;
        return Err(DialError::Handshake {
            protocol: "hysteria",
            source: io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("connection rejected: {}", String::from_utf8_lossy(&message)),
            ),
        });
    }

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
    fn base64_matches_the_standard_alphabet() {
        for (raw, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("hello world", "aGVsbG8gd29ybGQ="),
        ] {
            assert_eq!(decode_base64(encoded).unwrap(), raw.as_bytes());
        }
        assert!(decode_base64("Zg=").is_err());
        assert!(decode_base64("!!!!").is_err());
    }

    #[test]
    fn speed_validation_matches_the_pinned_regex() {
        for good in ["50", "50 Mbps", "1 Gbps", "1000 bps", "2KBps"] {
            assert!(valid_speed(good), "{good}");
        }
        for bad in ["", "0", "50 mbps", "fast", "Mbps"] {
            assert!(!valid_speed(bad), "{bad}");
        }
    }
}
