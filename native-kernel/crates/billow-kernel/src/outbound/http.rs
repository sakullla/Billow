//! HTTP CONNECT outbound with optional Basic authentication and TLS (`tls: true`).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{base64, connect_tcp, handshake, tls, BoxStream, DialError, Dialed, Target};
use crate::proxies::HttpOutbound;

const MAX_HEAD: usize = 16 * 1024;

pub async fn dial(option: &HttpOutbound, target: &Target) -> Result<Dialed, DialError> {
    let tcp = connect_tcp(&option.server, option.port).await?;
    let server = tcp.peer_addr().map_err(|e| handshake("http", e))?;
    let stream: BoxStream = if option.tls {
        let mut stream = tls::wrap(tcp, &option.server, &option.tls_settings)
            .await
            .map_err(|e| handshake("http tls", e))?;
        connect_request(&mut stream, option, target)
            .await
            .map_err(|e| handshake("http", e))?;
        Box::new(stream)
    } else {
        let mut stream = tcp;
        connect_request(&mut stream, option, target)
            .await
            .map_err(|e| handshake("http", e))?;
        Box::new(stream)
    };
    Ok(Dialed { stream, server })
}

async fn connect_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    option: &HttpOutbound,
    target: &Target,
) -> io::Result<()> {
    let authority = target.authority();
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some(username) = &option.username {
        let password = option.password.as_ref().map(|p| p.expose()).unwrap_or("");
        let token = base64(format!("{}:{password}", username.expose()).as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    for (name, value) in &option.headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if head.len() >= MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT response head too large",
            ));
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP proxy closed without a CONNECT response",
            ));
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let status = text.split("\r\n").next().unwrap_or_default();
    let code = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok());
    match code {
        Some(200..=299) => Ok(()),
        Some(407) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("HTTP CONNECT authentication failed: {status}"),
        )),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("HTTP CONNECT refused: {status}"),
        )),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("not an HTTP response: {status}"),
        )),
    }
}
