//! SOCKS5 outbound (RFC 1928 + RFC 1929 username/password), optionally over TLS.

use std::io;

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::{connect_hop, handshake, tls, BoxStream, DialError, Dialed, SocksAddr, Target};
use crate::proxies::{Proxy, Socks5Outbound};

pub async fn dial(
    option: &Socks5Outbound,
    target: &Target,
    via: &[&Proxy],
    _timeout: Duration,
) -> Result<Dialed, DialError> {
    if !via.is_empty() {
        // `tunnel()` is how dial_with_rest reaches a hop that itself carries a
        // chain; calling `dial` directly for such a hop would bypass it.
        return Err(DialError::Chain(format!(
            "socks5 '{}' reached through a dialer-proxy chain: internal dispatch reached dial() instead of tunnel()",
            option.server
        )));
    }
    let (tcp, server) = connect_hop(&option.server, option.port).await?;
    let stream: BoxStream = if option.tls {
        let mut stream = tls::wrap(tcp, &option.server, &option.tls_settings)
            .await
            .map_err(|e| handshake("socks5 tls", e))?;
        negotiate(&mut stream, option, target)
            .await
            .map_err(|e| handshake("socks5", e))?;
        Box::new(stream)
    } else {
        let mut stream = tcp;
        negotiate(&mut stream, option, target)
            .await
            .map_err(|e| handshake("socks5", e))?;
        Box::new(stream)
    };
    Ok(Dialed { stream, server })
}

/// Tunnel a destination through this SOCKS5 proxy (used when this proxy is
/// the `dialer-proxy` of another hop), returning the split stream.
pub async fn tunnel(
    option: &Socks5Outbound,
    target: &str,
    port: u16,
    via: &[&Proxy],
    timeout: Duration,
) -> Result<(ReadHalf<BoxStream>, WriteHalf<BoxStream>), DialError> {
    let request = Target {
        host: target.to_string(),
        port,
    };
    let dialed = dial(option, &request, via, timeout).await?;
    Ok(dialed.into_parts())
}

/// SOCKS5 negotiation over an existing stream (a hop reached through a
/// `dialer-proxy`); TLS is not re-applied here because the transport already
/// belongs to the previous hop.
pub async fn negotiate_stream(
    mut stream: BoxStream,
    option: &Socks5Outbound,
    target: &Target,
) -> std::io::Result<BoxStream> {
    if option.tls {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a socks5 hop reached through a dialer-proxy cannot use tls: true (the transport is owned by the previous hop)",
        ));
    }
    negotiate(&mut stream, option, target).await?;
    Ok(stream)
}

async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    option: &Socks5Outbound,
    target: &Target,
) -> io::Result<()> {
    let mut request = Vec::new();
    if option.username.is_some() {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await?;
    if selection[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SOCKS5 server",
        ));
    }
    match selection[1] {
        0x00 => {}
        0x02 => {
            let Some(username) = &option.username else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 server requires username/password but none was configured",
                ));
            };
            let password = option.password.as_ref().map(|p| p.expose()).unwrap_or("");
            let mut auth = vec![0x01, username.expose().len() as u8];
            auth.extend_from_slice(username.expose().as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream.write_all(&auth).await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 username/password authentication failed",
                ));
            }
        }
        0xFF => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 server accepted none of the offered methods",
            ));
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("SOCKS5 server selected unoffered method {other:#x}"),
            ));
        }
    }
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    request.extend_from_slice(&SocksAddr::encode(target));
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SOCKS5 reply version",
        ));
    }
    if reply[1] != 0x00 {
        let reason = match reply[1] {
            0x01 => "general failure",
            0x02 => "not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown",
        };
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT failed: {reason} ({:#04x})", reply[1]),
        ));
    }
    // Skip BND.ADDR/BND.PORT.
    let mut skip = match reply[3] {
        0x01 => 4 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        0x04 => 16 + 2,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("SOCKS5 reply address type {other}"),
            ))
        }
    };
    let mut discard = [0u8; 18];
    while skip > 0 {
        let n = skip.min(discard.len());
        stream.read_exact(&mut discard[..n]).await?;
        skip -= n;
    }
    Ok(())
}
