//! Minimal RFC 6455 WebSocket client for the `network: ws` transport.
//!
//! Only what a proxy tunnel needs: an HTTP/1.1 upgrade, then binary frames in
//! both directions with client-side masking, fragmentation reassembly,
//! ping/pong and close. Text and compressed (per-message deflate) frames are
//! not negotiated and are refused if a peer sends them anyway.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const OP_CONT: u8 = 0x0;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;
/// Upper bound for one incoming frame; a tunnel never needs more.
const MAX_FRAME: usize = 1 << 20;
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Upgrade an established stream to a WebSocket tunnel.
///
/// `host_header` is the `Host` of the upgrade request (the TLS name / server),
/// `path` the request target, `headers` extra request headers.
pub async fn connect<S>(
    mut stream: S,
    host_header: &str,
    path: &str,
    headers: &[(String, String)],
) -> io::Result<WebSocketStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut key_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let key = super::base64(&key_bytes);
    // No `Sec-WebSocket-Protocol`: Mihomo's server reads a non-empty value as
    // Xray 0-RTT early data, and its own client only sets the header then.
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("upgrade")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("sec-websocket-key")
            || name.eq_ignore_ascii_case("sec-websocket-version")
            || name.eq_ignore_ascii_case("sec-websocket-protocol")
        {
            continue;
        }
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if head.len() >= MAX_HEAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WebSocket response head too large",
            ));
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "WebSocket upgrade closed without a response",
            ));
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split('\n').map(|l| l.trim_end_matches('\r'));
    let status = lines.next().unwrap_or_default();
    let code = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok());
    if code != Some(101) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("WebSocket upgrade refused: {status}"),
        ));
    }
    let mut accept = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("sec-websocket-accept") {
                accept = Some(value.trim().to_string());
            }
        }
    }
    let expected = base64_sha1(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes());
    if accept.as_deref() != Some(expected.as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WebSocket upgrade: bad Sec-WebSocket-Accept",
        ));
    }
    Ok(WebSocketStream {
        inner: stream,
        raw: Vec::new(),
        read_buf: Vec::new(),
        read_pos: 0,
        fragment: Vec::new(),
        pending_write: Vec::new(),
        write_pos: 0,
        pending_len: 0,
        control: Vec::new(),
        control_pos: 0,
        closed: false,
    })
}

/// `base64(SHA-1(input))`, the RFC 6455 handshake digest.
pub fn base64_sha1(input: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, input);
    super::base64(digest.as_ref())
}

/// One stream carrying WebSocket frames.
pub struct WebSocketStream<S> {
    inner: S,
    /// Bytes already read from the transport but not parsed yet.
    raw: Vec<u8>,
    /// Reassembled application bytes ready for the caller.
    read_buf: Vec<u8>,
    read_pos: usize,
    fragment: Vec<u8>,
    /// Encoded frame bytes waiting for the transport.
    pending_write: Vec<u8>,
    write_pos: usize,
    pending_len: usize,
    /// Control frames (pong, close) waiting for the transport; written ahead of
    /// application data and retried on every poll.
    control: Vec<u8>,
    control_pos: usize,
    closed: bool,
}

/// What one parsed frame turned out to be.
enum Frame {
    /// Not enough bytes buffered yet.
    NeedMore,
    /// A complete application message (binary, possibly reassembled fragments).
    Message(Vec<u8>),
    /// A control frame already handled (ping answered, pong or close seen).
    Control,
    /// A frame the tunnel cannot interpret; the session fails with this text.
    Bad(&'static str),
}

impl<S> WebSocketStream<S> {
    fn frame(opcode: u8, payload: &[u8], mask: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 14);
        out.push(0x80 | opcode);
        let mask_bit = if mask { 0x80 } else { 0 };
        if payload.len() < 126 {
            out.push(mask_bit | payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        if mask {
            let mut key = [0u8; 4];
            rand::thread_rng().fill_bytes(&mut key);
            out.extend_from_slice(&key);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        } else {
            out.extend_from_slice(payload);
        }
        out
    }

    /// Parse one frame from `raw` (consuming its bytes). No I/O and no future
    /// state: a poll that ends early continues from the same buffered bytes.
    /// The caller turns `Unsupported` outcomes into a session error.
    fn parse(raw: &mut Vec<u8>, fragment: &mut Vec<u8>, control: &mut Vec<u8>) -> Frame {
        if raw.len() < 2 {
            return Frame::NeedMore;
        }
        if raw[0] & 0x70 != 0 {
            // RSV bits: compression is not negotiated.
            return Frame::Bad("websocket RSV bits set (compression not negotiated)");
        }
        let fin = raw[0] & 0x80 != 0;
        let opcode = raw[0] & 0x0F;
        let masked = raw[1] & 0x80 != 0;
        let short = (raw[1] & 0x7F) as usize;
        let mut offset = 2;
        let len = match short {
            126 => {
                if raw.len() < offset + 2 {
                    return Frame::NeedMore;
                }
                let value = u16::from_be_bytes([raw[offset], raw[offset + 1]]) as usize;
                offset += 2;
                value
            }
            127 => {
                if raw.len() < offset + 8 {
                    return Frame::NeedMore;
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&raw[offset..offset + 8]);
                offset += 8;
                let value = u64::from_be_bytes(bytes);
                if value > MAX_FRAME as u64 {
                    return Frame::Bad("websocket frame too large");
                }
                value as usize
            }
            other => other,
        };
        if len > MAX_FRAME {
            return Frame::Bad("websocket frame too large");
        }
        if masked {
            offset += 4;
        }
        if raw.len() < offset + len {
            return Frame::NeedMore;
        }
        let mask = if masked {
            let mut key = [0u8; 4];
            key.copy_from_slice(&raw[offset - 4..offset]);
            Some(key)
        } else {
            None
        };
        let mut payload = raw[offset..offset + len].to_vec();
        raw.drain(..offset + len);
        if let Some(key) = mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[i % 4];
            }
        }
        match opcode {
            OP_BINARY => {
                if fragment.len() + payload.len() > MAX_FRAME {
                    return Frame::Bad("websocket message too large");
                }
                fragment.extend_from_slice(&payload);
                if fin {
                    Frame::Message(std::mem::take(fragment))
                } else {
                    Frame::Control
                }
            }
            OP_CONT => {
                if fragment.len() + payload.len() > MAX_FRAME {
                    return Frame::Bad("websocket message too large");
                }
                fragment.extend_from_slice(&payload);
                if fin {
                    Frame::Message(std::mem::take(fragment))
                } else {
                    Frame::Control
                }
            }
            OP_PING => {
                control.extend_from_slice(&Self::frame(OP_PONG, &payload, true));
                Frame::Control
            }
            OP_PONG | OP_CLOSE => Frame::Control,
            // Text and unknown opcodes are refused rather than guessed.
            _ => Frame::Bad("websocket text or unknown opcode where proxy data was expected"),
        }
    }
}

/// Write every queued byte to the transport (`Pending` keeps the position).
fn flush_queue<S: AsyncWrite + Unpin>(
    inner: &mut S,
    queue: &[u8],
    pos: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while *pos < queue.len() {
        match Pin::new(&mut *inner).poll_write(cx, &queue[*pos..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "websocket peer closed",
                )))
            }
            Poll::Ready(Ok(n)) => *pos += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WebSocketStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Answer a pending ping first.
        if this.control_pos < this.control.len() {
            match flush_queue(&mut this.inner, &this.control, &mut this.control_pos, cx) {
                Poll::Ready(Ok(())) => {
                    this.control.clear();
                    this.control_pos = 0;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let len = buf.len().min(MAX_FRAME);
        // `poll_write` is polled again with the same buffer after `Pending`;
        // the frame must not be re-encoded then.
        let resumed = this.pending_len == len && !this.pending_write.is_empty();
        if !resumed {
            this.pending_write = Self::frame(OP_BINARY, &buf[..len], true);
            this.write_pos = 0;
            this.pending_len = len;
        }
        match flush_queue(&mut this.inner, &this.pending_write, &mut this.write_pos, cx) {
            Poll::Ready(Ok(())) => {
                this.pending_write.clear();
                this.write_pos = 0;
                this.pending_len = 0;
                Poll::Ready(Ok(len))
            }
            other => other.map(|r| r.map(|_| 0)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.control_pos < this.control.len() {
            match flush_queue(&mut this.inner, &this.control, &mut this.control_pos, cx) {
                Poll::Ready(Ok(())) => {
                    this.control.clear();
                    this.control_pos = 0;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        match flush_queue(&mut this.inner, &this.pending_write, &mut this.write_pos, cx) {
            Poll::Ready(Ok(())) => {
                this.pending_write.clear();
                this.write_pos = 0;
                this.pending_len = 0;
                Pin::new(&mut this.inner).poll_flush(cx)
            }
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.closed {
            this.closed = true;
            // Best effort: a peer that already left must not block shutdown.
            let close = Self::frame(OP_CLOSE, &1000u16.to_be_bytes(), true);
            this.control.extend_from_slice(&close);
        }
        match Pin::new(&mut *this).poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.read_pos < this.read_buf.len() {
                let n = buf.remaining().min(this.read_buf.len() - this.read_pos);
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
                if this.read_pos == this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            this.read_buf.clear();
            this.read_pos = 0;
            match Self::parse(&mut this.raw, &mut this.fragment, &mut this.control) {
                Frame::Message(message) => {
                    if message.is_empty() {
                        continue;
                    }
                    this.read_buf = message;
                    this.read_pos = 0;
                    continue;
                }
                Frame::Control => {
                    // Answer a ping that was just parsed, without blocking the
                    // read: a pong that cannot be sent now is retried later.
                    if this.control_pos < this.control.len() {
                        if let Poll::Ready(Err(e)) =
                            flush_queue(&mut this.inner, &this.control, &mut this.control_pos, cx)
                        {
                            return Poll::Ready(Err(e));
                        }
                        if this.control_pos >= this.control.len() {
                            this.control.clear();
                            this.control_pos = 0;
                        }
                    }
                    continue;
                }
                Frame::Bad(reason) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, reason)))
                }
                Frame::NeedMore => {
                    let mut scratch = [0u8; 4096];
                    let mut view = ReadBuf::new(&mut scratch);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut view) {
                        Poll::Ready(Ok(())) => {
                            if view.filled().is_empty() {
                                // Peer closed the transport (a TCP FIN or close_notify).
                                return Poll::Ready(Ok(()));
                            }
                            this.raw.extend_from_slice(view.filled());
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}
