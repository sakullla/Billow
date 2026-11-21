//! Mixed inbound: one TCP port that speaks SOCKS5 (RFC 1928, optional
//! RFC 1929 username/password) and HTTP CONNECT on the same listener.
//!
//! Either way the handshake ends in a [`Request`] that the engine evaluates
//! against the rule set before dialling (DIRECT) or refusing (REJECT).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound for the inbound handshake, independent of the host size limit.
const MAX_HANDSHAKE_BYTES: usize = 8 * 1024;
/// Maximum host/authority length accepted in a request line.
pub const MAX_HOST_BYTES: usize = 255;

/// What the client asked for before the reply is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    /// HTTP CONNECT headers (lowercased names), empty for SOCKS5.
    pub headers: Vec<(String, String)>,
}

impl Request {
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Socks5,
    HttpConnect,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Socks5 => "socks5",
            Protocol::HttpConnect => "http-connect",
        }
    }
}

/// Handshake failure. `status` is what the engine maps to the reply the
/// client receives and `code` is a stable metric/log tag.
/// Credentials accepted on the mixed inbound (global `authentication` or a
/// listener-level `users` list). `None` means no authentication is configured.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboundAuth {
    pub users: Vec<(String, String)>,
}

impl InboundAuth {
    pub fn none() -> Self {
        InboundAuth { users: Vec::new() }
    }

    pub fn is_enabled(&self) -> bool {
        !self.users.is_empty()
    }

    fn accepts(&self, username: &[u8], password: &[u8]) -> bool {
        self.users
            .iter()
            .any(|(u, p)| u.as_bytes() == username && p.as_bytes() == password)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("client closed during handshake")]
    Closed,
    #[error("SOCKS5: unsupported request {0}")]
    SocksUnsupported(&'static str),
    #[error("SOCKS5: no acceptable authentication method offered")]
    SocksAuthRequired,
    #[error("SOCKS5: username/password authentication failed")]
    SocksAuthFailed,
    #[error("first byte is neither SOCKS5 (0x05) nor an HTTP method: 0x{0:02x}")]
    UnknownProtocol(u8),
    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("bad HTTP request: {0}")]
    BadHttp(&'static str),
    #[error("host name exceeds {MAX_HOST_BYTES} bytes")]
    HostTooLong,
    #[error("handshake exceeded {MAX_HANDSHAKE_BYTES} bytes or its deadline")]
    TooLarge,
    #[error("I/O error: {0}")]
    Io(io::Error),
}

impl HandshakeError {
    /// Stable tag for logs/metrics.
    pub fn code(&self) -> &'static str {
        match self {
            HandshakeError::Closed => "closed",
            HandshakeError::SocksUnsupported(_) => "socks_unsupported",
            HandshakeError::SocksAuthRequired => "socks_auth_required",
            HandshakeError::SocksAuthFailed => "socks_auth_failed",
            HandshakeError::UnknownProtocol(_) => "unknown_protocol",
            HandshakeError::UnsupportedProtocol(_) => "unsupported_protocol",
            HandshakeError::BadHttp(_) => "bad_http",
            HandshakeError::HostTooLong => "host_too_long",
            HandshakeError::TooLarge => "handshake_too_large",
            HandshakeError::Io(_) => "io",
        }
    }
}

impl From<io::Error> for HandshakeError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            HandshakeError::Closed
        } else {
            HandshakeError::Io(e)
        }
    }
}

/// SOCKS5 reply code for a handshake/outbound failure.
pub fn socks_reply_code(err: &HandshakeError) -> u8 {
    match err {
        HandshakeError::SocksUnsupported("command") => 0x07,
        HandshakeError::SocksUnsupported(_) => 0x08,
        HandshakeError::SocksAuthRequired => 0x07,
        HandshakeError::SocksAuthFailed => 0x01,
        HandshakeError::UnknownProtocol(_)
        | HandshakeError::UnsupportedProtocol(_)
        | HandshakeError::BadHttp(_) => 0x07,
        _ => 0x01,
    }
}

/// Read the request without writing any bytes yet (no inbound authentication).
pub async fn accept_request<S>(stream: &mut S) -> Result<Request, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    accept_request_with_auth(stream, &InboundAuth::none()).await
}

/// Like [`accept_request`], enforcing SOCKS5 username/password when `auth`
/// lists users. HTTP CONNECT authentication is checked by the engine after
/// the head is parsed (it needs the `Proxy-Authorization` header).
pub async fn accept_request_with_auth<S>(
    stream: &mut S,
    auth: &InboundAuth,
) -> Result<Request, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut first = [0u8; 1];
    if stream.read(&mut first).await? == 0 {
        return Err(HandshakeError::Closed);
    }
    if first[0] == 0x05 {
        return socks5_request(stream, auth).await;
    }
    if first[0].is_ascii_uppercase() {
        match http_connect_request(stream, first[0]).await {
            Err(HandshakeError::UnsupportedProtocol(method)) => {
                stream
                    .write_all(http_error("405 Method Not Allowed").as_bytes())
                    .await?;
                Err(HandshakeError::UnsupportedProtocol(method))
            }
            other => other,
        }
    } else {
        Err(HandshakeError::UnknownProtocol(first[0]))
    }
}

/// Reply success and return the stream positioned at the tunnel payload.
pub async fn reply_success<S>(stream: &mut S, request: &Request) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    match request.protocol {
        Protocol::Socks5 => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
        }
        Protocol::HttpConnect => {
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: billow-kernel\r\n\r\n")
                .await
        }
    }
}

/// Reply failure and shut the write side down. Best effort: the client may be gone.
/// HTTP CONNECT authentication check: no users -> allow; otherwise a
/// `Proxy-Authorization: Basic base64(user:pass)` line matching one user.
pub fn http_authorized(request: &Request, auth: &InboundAuth) -> bool {
    if !auth.is_enabled() {
        return true;
    }
    let Some(value) = request
        .headers
        .iter()
        .find(|(name, _)| name == "proxy-authorization")
        .map(|(_, value)| value)
    else {
        return false;
    };
    let Some(token) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    else {
        return false;
    };
    let Some(decoded) = base64_decode(token.trim()) else {
        return false;
    };
    match decoded
        .iter()
        .position(|b| *b == b':')
        .map(|at| (&decoded[..at], &decoded[at + 1..]))
    {
        Some((user, pass)) => auth.accepts(user, pass),
        None => false,
    }
}

/// Reply `407 Proxy Authentication Required` for an unauthenticated CONNECT and close.
pub async fn reply_http_auth_required<S>(stream: &mut S)
where
    S: AsyncWrite + Unpin,
{
    let _ = stream
        .write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"billow\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
    let _ = stream.shutdown().await;
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = input
        .bytes()
        .filter(|c| *c != b'\r' && *c != b'\n')
        .collect();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut triple = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            let v = if *c == b'=' { 0 } else { value(*c)? };
            triple |= v << (18 - 6 * i);
        }
        out.push((triple >> 16) as u8);
        if pad < 2 {
            out.push((triple >> 8) as u8);
        }
        if pad < 1 {
            out.push(triple as u8);
        }
    }
    Some(out)
}

pub async fn reply_failure<S>(stream: &mut S, protocol: Protocol, code: u8)
where
    S: AsyncWrite + Unpin,
{
    match protocol {
        Protocol::Socks5 => {
            let _ = stream
                .write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
        }
        Protocol::HttpConnect => {
            let status = match code {
                0x07 => "403 Forbidden",
                _ => "502 Bad Gateway",
            };
            let _ = stream.write_all(http_error(status).as_bytes()).await;
        }
    }
    let _ = stream.shutdown().await;
}

fn http_error(status: &str) -> String {
    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nProxy-Agent: billow-kernel\r\nConnection: close\r\n\r\n")
}

async fn socks5_request<S>(stream: &mut S, auth: &InboundAuth) -> Result<Request, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // `first` was the version byte; the method count follows.
    let mut head = [0u8; 1];
    stream.read_exact(&mut head).await?;
    let n_methods = head[0] as usize;
    if n_methods == 0 {
        return Err(HandshakeError::SocksAuthRequired);
    }
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;
    if auth.is_enabled() {
        if !methods.contains(&0x02) {
            let _ = stream.write_all(&[0x05, 0xff]).await;
            return Err(HandshakeError::SocksAuthRequired);
        }
        stream.write_all(&[0x05, 0x02]).await?;
        sock5_authenticate(stream, auth).await?;
    } else {
        if !methods.contains(&0x00) {
            // No-auth is the only method this listener offers.
            let _ = stream.write_all(&[0x05, 0xff]).await;
            return Err(HandshakeError::SocksAuthRequired);
        }
        stream.write_all(&[0x05, 0x00]).await?;
    }

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 0x05 {
        return Err(HandshakeError::SocksUnsupported("version"));
    }
    if request[1] != 0x01 {
        // CONNECT only; BIND and UDP ASSOCIATE are refused with the SOCKS5
        // "command not supported" reply instead of a silent close.
        let _ = stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err(HandshakeError::SocksUnsupported("command"));
    }
    let host = read_socks_address(stream, request[3]).await?;
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(Request {
        host,
        port: u16::from_be_bytes(port),
        protocol: Protocol::Socks5,
        headers: Vec::new(),
    })
}

/// RFC 1929 username/password sub-negotiation.
async fn sock5_authenticate<S>(stream: &mut S, auth: &InboundAuth) -> Result<(), HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut version = [0u8; 1];
    stream.read_exact(&mut version).await?;
    if version[0] != 0x01 {
        let _ = stream.write_all(&[0x01, 0x01]).await;
        return Err(HandshakeError::SocksAuthFailed);
    }
    let mut len = [0u8; 1];
    stream.read_exact(&mut len).await?;
    let mut username = vec![0u8; len[0] as usize];
    stream.read_exact(&mut username).await?;
    stream.read_exact(&mut len).await?;
    let mut password = vec![0u8; len[0] as usize];
    stream.read_exact(&mut password).await?;
    let ok = len[0] > 0 && auth.accepts(&username, &password);
    let _ = stream
        .write_all(&[0x01, if ok { 0x00 } else { 0x01 }])
        .await;
    if ok {
        Ok(())
    } else {
        Err(HandshakeError::SocksAuthFailed)
    }
}

async fn read_socks_address<S>(stream: &mut S, atyp: u8) -> Result<String, HandshakeError>
where
    S: AsyncRead + Unpin,
{
    match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            Ok(std::net::Ipv4Addr::from(addr).to_string())
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let len = len[0] as usize;
            if len == 0 || len > MAX_HOST_BYTES {
                return Err(HandshakeError::HostTooLong);
            }
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await?;
            let name = std::str::from_utf8(&name)
                .map_err(|_| HandshakeError::BadHttp("non-UTF-8 host"))?;
            Ok(name.to_ascii_lowercase())
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            Ok(std::net::Ipv6Addr::from(addr).to_string())
        }
        _ => Err(HandshakeError::SocksUnsupported("address type")),
    }
}

async fn http_connect_request<S>(stream: &mut S, first: u8) -> Result<Request, HandshakeError>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = vec![first];
    let mut byte = [0u8; 1];
    // Find the end of the header block, bounding both count and size.
    loop {
        if buffer.len() > MAX_HANDSHAKE_BYTES {
            return Err(HandshakeError::TooLarge);
        }
        if buffer.ends_with(b"\r\n\r\n") {
            break;
        }
        if buffer.ends_with(b"\n\n") {
            break;
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(HandshakeError::Closed);
        }
        buffer.push(byte[0]);
    }
    let text =
        std::str::from_utf8(&buffer).map_err(|_| HandshakeError::BadHttp("non-UTF-8 request"))?;
    let mut lines = text.split('\n').map(|l| l.trim_end_matches('\r'));
    let request_line = lines
        .next()
        .ok_or(HandshakeError::BadHttp("empty request"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts
        .next()
        .ok_or(HandshakeError::BadHttp("missing target"))?;
    let version = parts
        .next()
        .ok_or(HandshakeError::BadHttp("missing version"))?;
    if parts.next().is_some() {
        return Err(HandshakeError::BadHttp("extra tokens in request line"));
    }
    if !version.starts_with("HTTP/1.") {
        return Err(HandshakeError::BadHttp("not HTTP/1.x"));
    }
    if !lines.all(|l| !l.contains('\0')) {
        return Err(HandshakeError::BadHttp("NUL byte in header"));
    }
    if method != "CONNECT" {
        return Err(HandshakeError::UnsupportedProtocol(format!(
            "HTTP {method} (only CONNECT)"
        )));
    }
    let (host, port) = parse_authority(target)?;
    // Re-collect the header lines (the iterator above consumed nothing else).
    let headers = text
        .split('\n')
        .skip(1)
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    Ok(Request {
        host,
        port,
        protocol: Protocol::HttpConnect,
        headers,
    })
}

fn parse_authority(target: &str) -> Result<(String, u16), HandshakeError> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or(HandshakeError::BadHttp("unterminated IPv6 literal"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or(HandshakeError::BadHttp("missing port"))?;
        (host.to_string(), port)
    } else {
        let (host, port) = target
            .rsplit_once(':')
            .ok_or(HandshakeError::BadHttp("authority needs host:port"))?;
        if host.contains(':') {
            return Err(HandshakeError::BadHttp("IPv6 literal must be bracketed"));
        }
        (host.to_string(), port)
    };
    if host.is_empty() || host.len() > MAX_HOST_BYTES {
        return Err(HandshakeError::HostTooLong);
    }
    if host
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '/')
    {
        return Err(HandshakeError::BadHttp("invalid host"));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| HandshakeError::BadHttp("invalid port"))?;
    if port == 0 {
        return Err(HandshakeError::BadHttp("port must be 1..=65535"));
    }
    Ok((host.to_ascii_lowercase(), port))
}
