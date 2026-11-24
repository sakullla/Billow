//! VLESS outbound over TLS, optionally with the WebSocket transport.
//!
//! Request header (VLESS spec / v2ray): version `0`, 16-byte user id,
//! addon length `0`, command `1` (TCP), port (BE), address type + address,
//! then the payload. The address is the domain form when the target is a
//! name, so the server resolves it; `network: ws` wraps the whole stream in a
//! WebSocket binary stream (WHATWG path matching the listener's `ws-path`).

use std::io;

use tokio::io::AsyncWriteExt;

use super::{connect_tcp, handshake, tls, ws, BoxStream, DialError, Dialed, Target};
use crate::proxies::VlessOutbound;

use super::tls::ClientTls;

const VERSION: u8 = 0;
const CMD_TCP: u8 = 1;
/// VLESS command 2: one UDP destination per stream, length-framed payloads.
pub const CMD_UDP: u8 = 2;
/// VLESS command 3: the XUDP frames carry their own destination.
pub const CMD_MUX: u8 = 3;

/// Bytes the VLESS client sends before the payload.
pub fn request_header(uuid: &[u8; 16], target: &Target) -> Vec<u8> {
    request_header_command(uuid, Some(target), CMD_TCP)
}

/// Request header for a command. `target` is `None` for the mux command,
/// whose frames carry the destination instead.
pub fn request_header_command(uuid: &[u8; 16], target: Option<&Target>, command: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(23 + target.map(|t| t.host.len()).unwrap_or(0));
    out.push(VERSION);
    out.extend_from_slice(uuid);
    out.push(0); // addon length
    out.push(command);
    let Some(target) = target else {
        return out;
    };
    out.extend_from_slice(&target.port.to_be_bytes());
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(0x03);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        out.push(0x02);
        out.push(target.host.len() as u8);
        out.extend_from_slice(target.host.as_bytes());
    }
    out
}

pub async fn dial(
    option: &VlessOutbound,
    target: &Target,
    tls: &ClientTls,
) -> Result<Dialed, DialError> {
    let tcp = connect_tcp(&option.server, option.port).await?;
    let server = tcp.peer_addr().map_err(|e| handshake("vless", e))?;
    let mut stream: BoxStream = match &option.network {
        crate::proxies::VlessNetwork::Tcp => {
            let stream = tls::wrap(tcp, &option.server, &option.tls_settings, tls)
                .await
                .map_err(|e| handshake("vless tls", e))?;
            Box::new(stream)
        }
        crate::proxies::VlessNetwork::Ws(ws_settings) => {
            // The server's WebSocket ALPN negotiation (Mihomo's vless listener
            // with `ws-path`) expects the plain TLS handshake first; the
            // `ws-opts` request follows over that connection.
            let stream = tls::wrap(tcp, &option.server, &option.tls_settings, tls)
                .await
                .map_err(|e| handshake("vless tls", e))?;
            let host = option
                .tls_settings
                .sni
                .clone()
                .unwrap_or_else(|| option.server.clone());
            let tunnel = ws::connect(
                stream,
                &host,
                &ws_settings.path,
                &ws_settings.headers,
                ws_settings.v2ray_http_upgrade,
            )
            .await
            .map_err(|e| handshake("vless ws", e))?;
            Box::new(tunnel)
        }
    };
    stream
        .write_all(&request_header(&option.uuid, target))
        .await
        .map_err(|e| handshake("vless", e))?;
    stream.flush().await.map_err(|e| handshake("vless", e))?;
    Ok(Dialed { stream, server })
}

/// Parse the request header the way a VLESS server does (tests and diagnostics).
pub fn parse_header(raw: &[u8]) -> io::Result<([u8; 16], Target)> {
    let invalid = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    if raw.len() < 19 {
        return Err(invalid("vless header too short"));
    }
    if raw[0] != VERSION {
        return Err(invalid("bad vless version"));
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&raw[1..17]);
    let addon = raw[17] as usize;
    let cmd = raw[18];
    if cmd != CMD_TCP {
        return Err(invalid("unsupported vless command"));
    }
    let mut pos = 19 + addon;
    if raw.len() < pos + 3 {
        return Err(invalid("vless header cut"));
    }
    let port = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
    pos += 2;
    let atyp = raw[pos];
    pos += 1;
    let host = match atyp {
        0x01 => {
            std::net::Ipv4Addr::new(raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]).to_string()
        }
        0x02 | 0x03 => {
            let len = raw[pos] as usize;
            pos += 1;
            if raw.len() < pos + len {
                return Err(invalid("vless address cut"));
            }
            String::from_utf8_lossy(&raw[pos..pos + len]).to_string()
        }
        _ => return Err(invalid("bad vless address type")),
    };
    Ok((uuid, Target { host, port }))
}
