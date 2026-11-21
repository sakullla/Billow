//! A minimal smux client stream, for `gost-relay` with `mux: true`.
//!
//! The pinned relay dialer wraps its server connection in `github.com/metacubex/smux`
//! (`smux.Client` with `DefaultConfig`, keep-alive disabled) and opens one
//! stream per relay dial. `DefaultConfig` is protocol version 1, so the wire is
//! the version-1 frame:
//!
//! ```text
//! version(1) command(1) length(u16 LE) stream id(u32 LE) payload
//! ```
//!
//! Commands: `SYN` 0, `FIN` 1, `PSH` 2, `NOP` 3, `UPD` 4 (v2 only). The client
//! opens stream id 3 (the session starts at 1 and adds 2 per stream). Version 1
//! has no per-stream window, so no `UPD` frames are sent; the session-level
//! receive buffer still applies back-pressure on the peer.
//!
//! Only one stream per connection is needed because the pinned relay dialer
//! creates a fresh session for every `DialContext`/`ListenPacket`, so this
//! module implements exactly that: open stream 3, frame writes, reassemble
//! frames on read, and treat `FIN` for stream 3 as EOF.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

const VERSION: u8 = 1;
const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const CMD_UPD: u8 = 4;
const HEADER: usize = 8;
/// `DefaultConfig().MaxFrameSize`.
const MAX_FRAME: usize = 32768;
/// The first client stream: the session starts at id 1 and `OpenStream` adds 2.
const STREAM_ID: u32 = 3;

pub struct SmuxStream<S> {
    inner: S,
    under: Vec<u8>,
    decoded: Vec<u8>,
    decoded_pos: usize,
    pending: Vec<u8>,
    pending_pos: usize,
    peer_fin: bool,
    shutdown_sent: bool,
}

/// Open the smux session on `inner` and its first client stream.
pub async fn open<S>(mut inner: S) -> io::Result<SmuxStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; HEADER];
    header[0] = VERSION;
    header[1] = CMD_SYN;
    header[4..8].copy_from_slice(&STREAM_ID.to_le_bytes());
    inner.write_all(&header).await?;
    inner.flush().await?;
    Ok(SmuxStream {
        inner,
        under: Vec::new(),
        decoded: Vec::new(),
        decoded_pos: 0,
        pending: Vec::new(),
        pending_pos: 0,
        peer_fin: false,
        shutdown_sent: false,
    })
}

impl<S> SmuxStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "smux session stopped accepting bytes",
                    )))
                }
                Poll::Ready(Ok(n)) => self.pending_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Peel complete frames; `Ok(false)` when more bytes are needed.
    fn parse_frames(&mut self) -> io::Result<bool> {
        let mut consumed = 0;
        while self.under.len() >= consumed + HEADER {
            let frame = &self.under[consumed..];
            if frame[0] != VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "smux invalid protocol version",
                ));
            }
            let cmd = frame[1];
            let length = u16::from_le_bytes([frame[2], frame[3]]) as usize;
            let sid = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
            if self.under.len() < consumed + HEADER + length {
                break;
            }
            let payload = self.under[consumed + HEADER..consumed + HEADER + length].to_vec();
            consumed += HEADER + length;
            match cmd {
                CMD_NOP => {}
                CMD_UPD => {
                    // Version 1 never sends these; a version-2 peer's window
                    // update is consumed (the payload was already skipped).
                }
                CMD_SYN => {
                    // The relay server never opens streams; ignore instead of
                    // failing the session.
                }
                CMD_PSH => {
                    if sid == STREAM_ID && !payload.is_empty() {
                        self.decoded.extend_from_slice(&payload);
                    }
                }
                CMD_FIN => {
                    if sid == STREAM_ID {
                        self.peer_fin = true;
                    }
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("smux unknown command {other}"),
                    ))
                }
            }
        }
        if consumed > 0 {
            self.under.drain(..consumed);
        }
        Ok(consumed > 0)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SmuxStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.decoded_pos < self.decoded.len() {
                let available = self.decoded.len() - self.decoded_pos;
                let take = available.min(buf.remaining());
                let start = self.decoded_pos;
                buf.put_slice(&self.decoded[start..start + take]);
                self.decoded_pos += take;
                return Poll::Ready(Ok(()));
            }
            self.decoded.clear();
            self.decoded_pos = 0;
            self.parse_frames()?;
            if !self.decoded.is_empty() {
                continue;
            }
            if self.peer_fin {
                return Poll::Ready(Ok(()));
            }
            let mut scratch = [0u8; 4096];
            let mut piece = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut piece) {
                Poll::Ready(Ok(())) => {
                    let filled = piece.filled().to_vec();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    self.under.extend_from_slice(&filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SmuxStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_pos < self.pending.len() {
            match self.poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        let mut rest = buf;
        while !rest.is_empty() {
            let size = rest.len().min(MAX_FRAME);
            let mut header = [0u8; HEADER];
            header[0] = VERSION;
            header[1] = CMD_PSH;
            header[2..4].copy_from_slice(&(size as u16).to_le_bytes());
            header[4..8].copy_from_slice(&STREAM_ID.to_le_bytes());
            self.pending.extend_from_slice(&header);
            self.pending.extend_from_slice(&rest[..size]);
            rest = &rest[size..];
        }
        if let Poll::Ready(Err(e)) = self.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown_sent {
            self.shutdown_sent = true;
            let mut header = [0u8; HEADER];
            header[0] = VERSION;
            header[1] = CMD_FIN;
            header[4..8].copy_from_slice(&STREAM_ID.to_le_bytes());
            self.pending.extend_from_slice(&header);
        }
        match self.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_header_matches_the_pinned_layout() {
        let mut header = [0u8; HEADER];
        header[0] = VERSION;
        header[1] = CMD_PSH;
        header[2..4].copy_from_slice(&(3u16).to_le_bytes());
        header[4..8].copy_from_slice(&STREAM_ID.to_le_bytes());
        assert_eq!(header, [1, 2, 3, 0, 3, 0, 0, 0]);
    }
}
