//! SSR obfs plugins (`transport/ssr/obfs` in the pinned tree).
//!
//! The obfs layer is the outermost wrapper: it sits directly on the TCP socket
//! and everything above it (the stream cipher's IV included) travels inside its
//! framing. `plain` is a pass-through; `http_simple`/`http_post` wrap the first
//! chunk in an HTTP request and strip the response head; `random_head` sends a
//! random first chunk and waits for the peer's; `tls1.2_ticket_auth` performs a
//! fake TLS handshake and then frames data as TLS application records.
//!
//! The client roles below are ports of the pinned `obfs/*.go`. The pinned tree
//! has no server side for these plugins, so the server framing used by the
//! controlled peer is derived from the same client code (see
//! `tool/kernel-compat/peers/ssr-plugins`, which also runs the pinned client
//! packages against that peer).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxies::{SsrObfsKind, SsrOutbound};

use super::protocol::hmac_sha1;

/// The obfs wrapper as one enum so the cipher layer sees a single stream type.
pub enum ObfsStream<S> {
    Plain(S),
    Http(HttpStream<S>),
    RandomHead(RandomHeadStream<S>),
    Tls12(Tls12Stream<S>),
}

pub fn build<S>(option: &SsrOutbound, key: Vec<u8>, iv_size: usize, inner: S) -> ObfsStream<S> {
    let param = option.obfs_param.clone();
    match option.obfs {
        SsrObfsKind::Plain => ObfsStream::Plain(inner),
        SsrObfsKind::HttpSimple | SsrObfsKind::HttpPost => ObfsStream::Http(HttpStream::new(
            inner,
            option.obfs == SsrObfsKind::HttpPost,
            &option.server,
            option.port,
            iv_size,
            param,
        )),
        SsrObfsKind::RandomHead => ObfsStream::RandomHead(RandomHeadStream::new(inner)),
        SsrObfsKind::Tls12TicketAuth | SsrObfsKind::Tls12TicketFastAuth => {
            ObfsStream::Tls12(Tls12Stream::new(inner, key, &option.server, param))
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ObfsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ObfsStream::Plain(inner) => Pin::new(inner).poll_read(cx, buf),
            ObfsStream::Http(stream) => Pin::new(stream).poll_read(cx, buf),
            ObfsStream::RandomHead(stream) => Pin::new(stream).poll_read(cx, buf),
            ObfsStream::Tls12(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ObfsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ObfsStream::Plain(inner) => Pin::new(inner).poll_write(cx, buf),
            ObfsStream::Http(stream) => Pin::new(stream).poll_write(cx, buf),
            ObfsStream::RandomHead(stream) => Pin::new(stream).poll_write(cx, buf),
            ObfsStream::Tls12(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ObfsStream::Plain(inner) => Pin::new(inner).poll_flush(cx),
            ObfsStream::Http(stream) => Pin::new(stream).poll_flush(cx),
            ObfsStream::RandomHead(stream) => Pin::new(stream).poll_flush(cx),
            ObfsStream::Tls12(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ObfsStream::Plain(inner) => Pin::new(inner).poll_shutdown(cx),
            ObfsStream::Http(stream) => Pin::new(stream).poll_shutdown(cx),
            ObfsStream::RandomHead(stream) => Pin::new(stream).poll_shutdown(cx),
            ObfsStream::Tls12(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Buffered write queue shared by the wrappers: the head and the payload are
/// written as one queue so a partially drained socket never reorders them.
pub(super) struct WriteQueue {
    pending: Vec<u8>,
    pos: usize,
}

impl WriteQueue {
    pub(super) fn new() -> WriteQueue {
        WriteQueue {
            pending: Vec::new(),
            pos: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.pending.len()
    }

    fn push(&mut self, bytes: &[u8]) {
        if self.is_empty() {
            self.pending.clear();
            self.pos = 0;
        }
        self.pending.extend_from_slice(bytes);
    }
}

fn drain_queue<S: AsyncWrite + Unpin>(
    queue: &mut WriteQueue,
    cx: &mut Context<'_>,
    inner: &mut S,
) -> Poll<io::Result<()>> {
    while queue.pos < queue.pending.len() {
        match Pin::new(&mut *inner).poll_write(cx, &queue.pending[queue.pos..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "ssr obfs stream stopped accepting bytes",
                )))
            }
            Poll::Ready(Ok(n)) => queue.pos += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    queue.pending.clear();
    queue.pos = 0;
    Poll::Ready(Ok(()))
}

fn take_buffered(store: &mut Vec<u8>, pos: &mut usize, buf: &mut ReadBuf<'_>) -> bool {
    if *pos >= store.len() {
        store.clear();
        *pos = 0;
        return false;
    }
    let available = store.len() - *pos;
    let take = available.min(buf.remaining());
    let start = *pos;
    buf.put_slice(&store[start..start + take]);
    *pos += take;
    true
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

// ---------------------------------------------------------------------------
// http_simple / http_post
// ---------------------------------------------------------------------------

pub struct HttpStream<S> {
    inner: S,
    post: bool,
    host: String,
    port: u16,
    iv_size: usize,
    param: Option<String>,
    sent_header: bool,
    recv_header: bool,
    queue: WriteQueue,
    payload: Vec<u8>,
    payload_pos: usize,
    head: Vec<u8>,
}

impl<S> HttpStream<S> {
    fn new(
        inner: S,
        post: bool,
        host: &str,
        port: u16,
        iv_size: usize,
        param: Option<String>,
    ) -> HttpStream<S> {
        HttpStream {
            inner,
            post,
            host: host.to_string(),
            port,
            iv_size,
            param,
            sent_header: false,
            recv_header: false,
            queue: WriteQueue::new(),
            payload: Vec::new(),
            payload_pos: 0,
            head: Vec::new(),
        }
    }

    fn build_head(&self, data: &[u8]) -> Vec<u8> {
        let head_length = self.iv_size + 30;
        let head_data_length = match data.len().checked_sub(head_length) {
            Some(rest) if rest > 64 => head_length + rand::thread_rng().gen_range(0..=64),
            _ => data.len(),
        };
        let head_data = &data[..head_data_length];
        let mut host = self.host.clone();
        let mut body = String::new();
        if let Some(param) = self.param.as_deref().filter(|p| !p.is_empty()) {
            match param.find('#') {
                Some(pos) => {
                    body = param[pos + 1..].replace('\n', "\r\n").replace("\\n", "\r\n");
                    host = param[..pos].to_string();
                }
                None => host = param.to_string(),
            }
        }
        let hosts: Vec<&str> = host.split(',').collect();
        let host = hosts[rand::thread_rng().gen_range(0..hosts.len())];
        let mut out = String::new();
        out.push_str(if self.post { "POST /" } else { "GET /" });
        for byte in head_data {
            out.push('%');
            out.push_str(&format!("{byte:02x}"));
        }
        out.push_str(" HTTP/1.1\r\nHost: ");
        out.push_str(host);
        if self.port != 80 {
            out.push(':');
            out.push_str(&self.port.to_string());
        }
        out.push_str("\r\n");
        if !body.is_empty() {
            out.push_str(&body);
            out.push_str("\r\n\r\n");
        } else {
            out.push_str("User-Agent: ");
            out.push_str(USER_AGENTS[rand::thread_rng().gen_range(0..USER_AGENTS.len())]);
            out.push_str("\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\n");
            if self.post {
                out.push_str("Content-Type: multipart/form-data; boundary=");
                let set = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                for _ in 0..32 {
                    out.push(set[rand::thread_rng().gen_range(0..62)] as char);
                }
                out.push_str("\r\n");
            }
            out.push_str("DNT: 1\r\nConnection: keep-alive\r\n\r\n");
        }
        let mut head = out.into_bytes();
        head.extend_from_slice(&data[head_data_length..]);
        head
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HttpStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if take_buffered(&mut this.payload, &mut this.payload_pos, buf) {
                return Poll::Ready(Ok(()));
            }
            if this.recv_header {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            if let Some(pos) = find_head_end(&this.head) {
                this.recv_header = true;
                let rest = this.head[pos + 4..].to_vec();
                this.head.clear();
                this.payload = rest;
                this.payload_pos = 0;
                continue;
            }
            let mut scratch = [0u8; 2048];
            let mut piece = ReadBuf::new(&mut scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut piece) {
                Poll::Ready(Ok(())) => {
                    let filled = piece.filled().to_vec();
                    if filled.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "ssr http obfs ended before the response head",
                        )));
                    }
                    this.head.extend_from_slice(&filled);
                    if this.head.len() > 64 * 1024 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ssr http obfs response head too large",
                        )));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HttpStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.queue.is_empty() {
            match drain_queue(&mut this.queue, cx, &mut this.inner) {
                Poll::Ready(Ok(())) => {}
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        if !this.sent_header {
            let head = this.build_head(buf);
            this.sent_header = true;
            this.queue.push(&head);
            if let Poll::Ready(Err(e)) = drain_queue(&mut this.queue, cx, &mut this.inner) {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(buf.len()));
        }
        this.queue.push(buf);
        if let Poll::Ready(Err(e)) = drain_queue(&mut this.queue, cx, &mut this.inner) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match drain_queue(&mut this.queue, cx, &mut this.inner) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match drain_queue(&mut this.queue, cx, &mut this.inner) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------
// random_head
// ---------------------------------------------------------------------------

pub struct RandomHeadStream<S> {
    inner: S,
    sent_header: bool,
    raw_sent: bool,
    raw_recv: bool,
    queue: WriteQueue,
    buffered: Vec<u8>,
    flushing: bool,
    /// The peer's random head, accumulated until its checksum matches (a head
    /// split across TCP reads must not leak bytes into the cipher stream).
    head: Vec<u8>,
    /// Bytes that arrived together with the peer's head and belong to the
    /// stream; served before the next inner read.
    pending_read: Vec<u8>,
    pending_read_pos: usize,
}

impl<S> RandomHeadStream<S> {
    fn new(inner: S) -> RandomHeadStream<S> {
        RandomHeadStream {
            inner,
            sent_header: false,
            raw_sent: false,
            raw_recv: false,
            queue: WriteQueue::new(),
            buffered: Vec::new(),
            flushing: false,
            head: Vec::new(),
            pending_read: Vec::new(),
            pending_read_pos: 0,
        }
    }
}

impl<S> RandomHeadStream<S> {
    /// Send the buffered payload and switch to raw mode; `Pending` when the
    /// socket cannot take it yet.
    fn poll_flush_buffer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        if self.raw_sent {
            return Poll::Ready(Ok(()));
        }
        if !self.flushing {
            if self.buffered.is_empty() {
                self.raw_sent = true;
                return Poll::Ready(Ok(()));
            }
            self.flushing = true;
            let buffered = std::mem::take(&mut self.buffered);
            self.queue.push(&buffered);
        }
        match drain_queue(&mut self.queue, cx, &mut self.inner) {
            Poll::Ready(Ok(())) => {
                self.flushing = false;
                self.raw_sent = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.flushing = false;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RandomHeadStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if take_buffered(&mut this.pending_read, &mut this.pending_read_pos, buf) {
                return Poll::Ready(Ok(()));
            }
            if !this.raw_recv {
                // The peer answers the random head; that head is discarded and
                // only then is the buffered payload sent (pinned client order).
                if let Some(length) = random_head_length(&this.head) {
                    let rest = this.head.split_off(length);
                    this.head.clear();
                    this.pending_read = rest;
                    this.pending_read_pos = 0;
                    this.raw_recv = true;
                    continue;
                }
                let mut scratch = [0u8; 256];
                let mut piece = ReadBuf::new(&mut scratch);
                match Pin::new(&mut this.inner).poll_read(cx, &mut piece) {
                    Poll::Ready(Ok(())) => {
                        let filled = piece.filled().to_vec();
                        if filled.is_empty() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "ssr random_head ended before the peer head",
                            )));
                        }
                        this.head.extend_from_slice(&filled);
                        if this.head.len() > 256 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "ssr random_head peer head too large",
                            )));
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }
            if !this.raw_sent {
                match this.poll_flush_buffer(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
                continue;
            }
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RandomHeadStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.raw_sent {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if !this.queue.is_empty() {
            match drain_queue(&mut this.queue, cx, &mut this.inner) {
                Poll::Ready(Ok(())) => {}
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        this.buffered.extend_from_slice(buf);
        if !this.sent_header {
            this.sent_header = true;
            let length = rand::thread_rng().gen_range(0..96) + 4;
            let mut head = vec![0u8; length];
            rand::rngs::OsRng.fill_bytes(&mut head);
            let crc = crc32(&head);
            head.extend_from_slice(&(0xffff_ffffu32 - crc).to_le_bytes());
            this.queue.push(&head);
            if let Poll::Ready(Err(e)) = drain_queue(&mut this.queue, cx, &mut this.inner) {
                return Poll::Ready(Err(e));
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.raw_sent {
            return Pin::new(&mut this.inner).poll_flush(cx);
        }
        drain_queue(&mut this.queue, cx, &mut this.inner)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match drain_queue(&mut this.queue, cx, &mut this.inner) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

/// The length (random part plus the four checksum bytes) of the peer's random
/// head, or `None` while the head is incomplete.
///
/// The scan runs from the longest candidate down: the CRC check is not unique
/// for every random length — for some lengths `crc32(head[:n-1])` also matches
/// the four bytes at `n-1`, and an ascending scan would then take the head one
/// byte short and misalign the cipher stream (observed as an intermittent
/// `auth_* wrong mac`). The longest match is the real head boundary.
fn random_head_length(head: &[u8]) -> Option<usize> {
    let upper = 99usize.min(head.len().saturating_sub(4));
    for length in (4..=upper).rev() {
        let stored = u32::from_le_bytes([
            head[length],
            head[length + 1],
            head[length + 2],
            head[length + 3],
        ]);
        if crc32(&head[..length]).wrapping_add(stored) == 0xffff_ffff {
            return Some(length + 4);
        }
    }
    None
}

pub(super) fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// tls1.2_ticket_auth / tls1.2_ticket_fastauth
// ---------------------------------------------------------------------------

pub struct Tls12Stream<S> {
    inner: S,
    key: Vec<u8>,
    client_id: [u8; 32],
    host: String,
    param: Option<String>,
    /// 0: nothing sent, 1: ClientHello sent, 8: data records.
    status: u8,
    send_buf: Vec<u8>,
    queue: WriteQueue,
    under: Vec<u8>,
    decoded: Vec<u8>,
    decoded_pos: usize,
    hello: Vec<u8>,
}

impl<S> Tls12Stream<S> {
    fn new(inner: S, key: Vec<u8>, host: &str, param: Option<String>) -> Tls12Stream<S> {
        let mut client_id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_id);
        Tls12Stream {
            inner,
            key,
            client_id,
            host: host.to_string(),
            param,
            status: 0,
            send_buf: Vec::new(),
            queue: WriteQueue::new(),
            under: Vec::new(),
            decoded: Vec::new(),
            decoded_pos: 0,
            hello: Vec::new(),
        }
    }

    fn hmac(&self, data: &[u8]) -> [u8; 10] {
        let mut key = self.key.clone();
        key.extend_from_slice(&self.client_id);
        let mac = hmac_sha1(&key, data);
        let mut out = [0u8; 10];
        out.copy_from_slice(&mac[..10]);
        out
    }

    fn sni_host(&self) -> String {
        let mut host = match self.param.as_deref().filter(|p| !p.is_empty()) {
            Some(param) => param.to_string(),
            None => self.host.clone(),
        };
        if host.chars().last().is_some_and(|c| c.is_ascii_digit()) {
            host.clear();
        }
        let hosts: Vec<&str> = host.split(',').collect();
        hosts[rand::thread_rng().gen_range(0..hosts.len())].to_string()
    }

    fn client_hello(&self) -> Vec<u8> {
        let mut data = vec![3u8, 3];
        data.extend_from_slice(&now_secs().to_le_bytes());
        let mut auth_random = [0u8; 18];
        rand::rngs::OsRng.fill_bytes(&mut auth_random);
        data.extend_from_slice(&auth_random);
        let auth_mac = self.hmac(&data[data.len() - 22..]);
        data.extend_from_slice(&auth_mac);
        data.push(0x20);
        data.extend_from_slice(&self.client_id);
        data.extend_from_slice(&[
            0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13,
            0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f,
            0x00, 0x0a,
        ]);
        data.extend_from_slice(&[0x01, 0x00]);

        let host = self.sni_host();
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
        let host_len = host.len() as u16;
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&(host_len + 5).to_be_bytes());
        ext.extend_from_slice(&(host_len + 3).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&host_len.to_be_bytes());
        ext.extend_from_slice(host.as_bytes());
        ext.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
        let ticket_len = 16 * (rand::thread_rng().gen_range(0..17u16) + 8);
        ext.extend_from_slice(&[0x00, 0x23]);
        ext.extend_from_slice(&ticket_len.to_be_bytes());
        let mut ticket = vec![0u8; ticket_len as usize];
        rand::rngs::OsRng.fill_bytes(&mut ticket);
        ext.extend_from_slice(&ticket);
        ext.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03,
            0x04, 0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03,
        ]);
        ext.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
        ext.extend_from_slice(&[0x00, 0x12, 0x00, 0x00]);
        ext.extend_from_slice(&[0x75, 0x50, 0x00, 0x00]);
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18]);
        data.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        data.extend_from_slice(&ext);

        let mut out = Vec::with_capacity(data.len() + 9);
        out.extend_from_slice(&[0x16, 3, 1]);
        out.extend_from_slice(&((data.len() + 4) as u16).to_be_bytes());
        out.extend_from_slice(&[0x01, 0x00]);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
        out
    }
}

impl<S> Tls12Stream<S> {
    /// Read and verify the fake ServerHello, then send the Finished record and
    /// the buffered payload (the pinned client does this from its first read).
    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            if !self.queue.is_empty() {
                match drain_queue(&mut self.queue, cx, &mut self.inner) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }
            let complete = if self.hello.len() >= 5 {
                let record_len = u16::from_be_bytes([self.hello[3], self.hello[4]]) as usize;
                self.hello.len() >= 5 + record_len && self.hello.len() >= 76
            } else {
                false
            };
            if complete {
                let record_len = u16::from_be_bytes([self.hello[3], self.hello[4]]) as usize;
                let total = 5 + record_len;
                let hello = self.hello[..total].to_vec();
                let auth_mac = self.hmac(&hello[11..33]);
                if auth_mac != hello[33..43] {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tls1.2_ticket_auth hmac verifying failed",
                    )));
                }
                let tail = self.hmac(&hello[..total - 10]);
                if tail != hello[total - 10..total] {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tls1.2_ticket_auth hmac verifying failed",
                    )));
                }
                self.hello.clear();
                let mut finished = vec![0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 0x20];
                let mut random = [0u8; 22];
                rand::rngs::OsRng.fill_bytes(&mut random);
                finished.extend_from_slice(&random);
                let mac = self.hmac(&finished);
                finished.extend_from_slice(&mac);
                finished.extend_from_slice(&self.send_buf);
                self.send_buf.clear();
                self.status = 8;
                self.queue.push(&finished);
                match drain_queue(&mut self.queue, cx, &mut self.inner) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
                return Poll::Ready(Ok(()));
            }
            let mut scratch = [0u8; 2048];
            let mut piece = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut piece) {
                Poll::Ready(Ok(())) => {
                    let filled = piece.filled().to_vec();
                    if filled.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "tls1.2_ticket_auth too short data",
                        )));
                    }
                    self.hello.extend_from_slice(&filled);
                    if self.hello.len() > 16 * 1024 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "tls1.2_ticket_auth hello too large",
                        )));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn pack_record(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&[0x17, 3, 3]);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Tls12Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if take_buffered(&mut this.decoded, &mut this.decoded_pos, buf) {
                return Poll::Ready(Ok(()));
            }
            if this.status == 1 {
                match this.poll_handshake(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }
            if this.status != 8 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tls1.2_ticket_auth read before the ClientHello was written",
                )));
            }
            let mut consumed = 0;
            while this.under.len() >= consumed + 5 {
                let head = &this.under[consumed..];
                if head[..3] != [0x17, 3, 3] {
                    this.under.clear();
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tls1.2_ticket_auth incorrect magic number",
                    )));
                }
                let size = u16::from_be_bytes([head[3], head[4]]) as usize;
                if this.under.len() < consumed + 5 + size {
                    break;
                }
                let start = consumed + 5;
                this.decoded.extend_from_slice(&this.under[start..start + size]);
                consumed += 5 + size;
            }
            if consumed > 0 {
                this.under.drain(..consumed);
                continue;
            }
            let mut scratch = [0u8; 2048];
            let mut piece = ReadBuf::new(&mut scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut piece) {
                Poll::Ready(Ok(())) => {
                    let filled = piece.filled().to_vec();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    this.under.extend_from_slice(&filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Tls12Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.status == 8 {
            if !this.queue.is_empty() {
                match drain_queue(&mut this.queue, cx, &mut this.inner) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }
            let mut framed = Vec::with_capacity(buf.len() + 5);
            let mut rest = buf;
            while rest.len() > 2048 {
                let size = (rand::thread_rng().gen_range(0..4096) + 100).min(rest.len());
                pack_record(&mut framed, &rest[..size]);
                rest = &rest[size..];
            }
            if !rest.is_empty() {
                pack_record(&mut framed, rest);
            }
            this.queue.push(&framed);
            if let Poll::Ready(Err(e)) = drain_queue(&mut this.queue, cx, &mut this.inner) {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(buf.len()));
        }
        if !buf.is_empty() {
            let mut framed = Vec::with_capacity(buf.len() + 5);
            pack_record(&mut framed, buf);
            this.send_buf.extend_from_slice(&framed);
        }
        if this.status == 0 {
            this.status = 1;
            let hello = this.client_hello();
            this.queue.push(&hello);
            if let Poll::Ready(Err(e)) = drain_queue(&mut this.queue, cx, &mut this.inner) {
                return Poll::Ready(Err(e));
            }
        }
        if this.send_buf.len() > 1024 * 1024 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth buffered payload too large",
            )));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.status == 1 {
            match this.poll_handshake(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        match drain_queue(&mut this.queue, cx, &mut this.inner) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match drain_queue(&mut this.queue, cx, &mut this.inner) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

// The pinned client picks one of these per request; a shorter list would still
// interop (the server ignores it) but the head would look less like the pinned
// implementation.
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.162 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 7.0; Moto C Build/NRD90M.059) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_head_carries_the_url_encoded_first_chunk() {
        let stream = HttpStream::new(Vec::<u8>::new(), false, "example.org", 8080, 16, None);
        let data: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
        let head = stream.build_head(&data);
        let text = String::from_utf8_lossy(&head);
        assert!(text.starts_with("GET /%00%01%02"), "{text}");
        assert!(
            text.contains(" HTTP/1.1\r\nHost: example.org:8080\r\n"),
            "{text}"
        );
        let end = head.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        // The bytes after the head are the untouched tail of the first write.
        let tail = &head[end..];
        assert!(!tail.is_empty());
        assert_eq!(tail, &data[data.len() - tail.len()..]);
    }

    #[test]
    fn http_post_adds_a_boundary_and_uses_the_param_host() {
        let stream = HttpStream::new(
            Vec::<u8>::new(),
            true,
            "ignored.example",
            80,
            0,
            Some("bing.com#X-Test: 1\\nX-Two: 2".to_string()),
        );
        let head = stream.build_head(b"abc");
        let text = String::from_utf8_lossy(&head);
        assert!(
            text.starts_with("POST /%61%62%63 HTTP/1.1\r\nHost: bing.com\r\n"),
            "{text}"
        );
        assert!(text.contains("X-Test: 1\r\nX-Two: 2\r\n\r\n"), "{text}");
    }

    #[test]
    fn tls_hello_has_the_pinned_record_and_handshake_headers() {
        let stream = Tls12Stream::new(Vec::<u8>::new(), b"key".to_vec(), "example.org", None);
        let hello = stream.client_hello();
        assert_eq!(&hello[..3], &[0x16, 3, 1]);
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_len, hello.len() - 5);
        let data_len = u16::from_be_bytes([hello[7], hello[8]]) as usize;
        assert_eq!(data_len, hello.len() - 9);
        // The auth block is timestamp(4) + 18 random + hmac(10); the record
        // header (5) and the handshake header (4) come first.
        let mac = stream.hmac(&hello[11..33]);
        assert_eq!(&mac, &hello[33..43]);
        let text = String::from_utf8_lossy(&hello);
        assert!(text.contains("example.org"), "{text}");
    }

    #[test]
    fn random_head_checksum_is_the_go_complement() {
        let head = b"random-head";
        let stored = 0xffff_ffffu32 - crc32(head);
        assert_eq!(stored.wrapping_add(crc32(head)), 0xffff_ffff);
    }

    #[test]
    fn random_head_length_picks_the_real_boundary() {
        // This five-byte head is also accepted one byte short: the crc32 of
        // `head[..4]` equals the four bytes at offset 4. An ascending scan
        // returns 8 (the head one byte short) and misaligns everything after
        // it; the real head is 5 bytes, i.e. 9 with the checksum.
        let head = [0xff, 0x71, 0x8f, 0x3b, 0xd5];
        let mut buf = head.to_vec();
        buf.extend_from_slice(&(0xffff_ffffu32 - crc32(&head)).to_le_bytes());
        let false_boundary = crc32(&buf[..4])
            .wrapping_add(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]));
        assert_eq!(false_boundary, 0xffff_ffff, "the short boundary is a real false match");
        assert_eq!(random_head_length(&buf), Some(9));
        // A prefix of the head is not accepted yet.
        assert_eq!(random_head_length(&buf[..8]), Some(8));
        assert_eq!(random_head_length(&buf[..7]), None);
    }
}
