//! Trojan outbound over TLS (optional WebSocket transport).
//!
//! Wire format (trojan-gfw), as implemented by Mihomo's `listener/trojan`:
//! `hex(sha224(password)) CRLF cmd CRLF SOCKS-addr CRLF [CRLF] payload`.
//! `cmd` is `1` for CONNECT; a server closes the TLS connection when the hash,
//! command or address is rejected, which the caller observes as EOF/error.

use std::io;

use tokio::io::AsyncWriteExt;

use super::{connect_tcp, handshake, tls, ws, BoxStream, DialError, Dialed, SocksAddr, Target};
use crate::keys::trojan_password_key;
use crate::proxies::TrojanOutbound;

use super::tls::ClientTls;

pub async fn dial(
    option: &TrojanOutbound,
    target: &Target,
    tls: &ClientTls,
) -> Result<Dialed, DialError> {
    let tcp = connect_tcp(&option.server, option.port).await?;
    let server = tcp.peer_addr().map_err(|e| handshake("trojan", e))?;
    let stream = tls::wrap(tcp, &option.server, &option.tls_settings, tls)
        .await
        .map_err(|e| handshake("trojan tls", e))?;
    let mut stream: BoxStream = match &option.network {
        crate::proxies::TrojanNetwork::Tcp => Box::new(stream),
        crate::proxies::TrojanNetwork::Ws(ws_settings) => {
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
            .map_err(|e| handshake("trojan ws", e))?;
            Box::new(tunnel)
        }
    };
    stream = wrap_ss(stream, option).await?;
    let mut header = trojan_password_key(option.password.expose());
    header.extend_from_slice(&request_tail(target));
    stream
        .write_all(&header)
        .await
        .map_err(|e| handshake("trojan", e))?;
    stream.flush().await.map_err(|e| handshake("trojan", e))?;
    Ok(Dialed { stream, server })
}

/// Wrap the stream in trojan's optional `ss-opts` Shadowsocks AEAD layer.
/// The pinned `StreamConnContext` applies `core.Cipher.StreamConn` after TLS/WS
/// and before the trojan header, so the header and everything after it are
/// sealed chunks.
pub async fn wrap_ss(
    stream: BoxStream,
    option: &TrojanOutbound,
) -> Result<BoxStream, DialError> {
    let Some(ss) = &option.ss_opts else {
        return Ok(stream);
    };
    let wrapped = super::shadowsocks::connect_layer(
        stream,
        ss.cipher,
        ss.password.expose(),
    )
    .await
    .map_err(|e| handshake("trojan ss-opts", e))?;
    Ok(Box::new(wrapped))
}

/// `CRLF cmd SOCKS5-addr CRLF`, exactly as Mihomo's `transport/trojan.WriteHeader`
/// writes it (the address uses the RFC 1928 ATYP forms, not `host:port` text).
fn request_tail(target: &Target) -> Vec<u8> {
    let mut tail = Vec::with_capacity(3 + 2 + target.host.len() + 2);
    tail.extend_from_slice(b"\r\n");
    tail.push(0x01);
    tail.extend_from_slice(&SocksAddr::encode(target));
    tail.extend_from_slice(b"\r\n");
    tail
}

/// The exact request prefix for `target`, exposed for tests and diagnostics.
pub fn request_header(password: &str, target: &Target) -> Vec<u8> {
    let mut header = trojan_password_key(password);
    header.extend_from_slice(&request_tail(target));
    header
}

/// Split one Trojan header the way the server does; used by the loopback
/// server in the tests to prove the client's bytes.
pub fn parse_header(raw: &[u8]) -> io::Result<(Vec<u8>, String)> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 trojan header"))?;
    let mut parts = text.split("\r\n");
    let key = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty trojan header"))?;
    let cmd = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing cmd"))?;
    if cmd != "\x01" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported trojan cmd",
        ));
    }
    let addr = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing address"))?;
    Ok((key.as_bytes().to_vec(), addr.to_string()))
}
