//! AnyTLS outbound (Mihomo `adapter/outbound/anytls.go`, protocol version 2).
//!
//! One TLS connection carries a session of multiplexed streams. The client
//! opens with `SHA-256(password) || u16 padding length`, then sends a settings
//! frame (`v=2`, `padding-md5`), one `SYN` and the destination in the server's
//! address serialiser (ATYP 1/4 for IPs, the FQDN form for names, then the
//! port - as `sing`'s SocksaddrSerializer writes it), then `PSH` frames.
//!
//! Frame: `cmd(1) | stream id(4, BE) | length(2, BE) | data`.
//! This client opens one stream per connection and sends no optional padding
//! frames; the initial padding length is 0, which the server accepts.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use ring::digest::{digest, SHA256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{connect_tcp, handshake, tls, DialError, Dialed, Target};
use crate::proxies::AnytlsOutbound;

use super::tls::ClientTls;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const HEADER: usize = 7;
const MAX_FRAME: usize = 0xFF_FF;

fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + data.len());
    out.push(cmd);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// The destination as `sing`'s SocksaddrSerializer writes it (ATYP, address, port).
pub fn write_destination(target: &Target) -> Vec<u8> {
    let mut out = Vec::with_capacity(target.host.len() + 9);
    if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.push(1);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(4);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        out.push(3);
        out.push(target.host.len() as u8);
        out.extend_from_slice(target.host.as_bytes());
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    out
}

/// The first bytes of a session: password hash and the (empty) padding header.
pub fn hello(password: &str) -> Vec<u8> {
    let mut out = digest(&SHA256, password.as_bytes()).as_ref().to_vec();
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

fn settings() -> Vec<u8> {
    b"client=\npadding-md5=\nv=2".to_vec()
}

struct StreamState {
    synack: Mutex<Option<tokio::sync::oneshot::Sender<io::Result<()>>>>,
    recv: tokio::sync::Notify,
    inbox: Mutex<Vec<u8>>,
    closed: Mutex<Option<io::Result<()>>>,
    fin_sent: AtomicBool,
}

impl StreamState {
    fn fail(&self, error: io::Error) {
        let mut closed = self.closed.lock().expect("anytls closed");
        if closed.is_none() {
            *closed = Some(Err(error));
        }
        drop(closed);
        self.recv.notify_waiters();
    }
}

struct Session<W> {
    writer: tokio::sync::Mutex<W>,
    streams: Mutex<HashMap<u32, Arc<StreamState>>>,
}

impl<W: AsyncWrite + Unpin> Session<W> {
    async fn send(&self, bytes: &[u8]) -> io::Result<()> {
        let mut writer = self.writer.lock().await;
        writer.write_all(bytes).await?;
        writer.flush().await
    }
}

/// Poll a `write` on the shared session writer without blocking the caller:
/// when the mutex is contended the task is woken and tries again.
fn poll_session_write<W: AsyncWrite + Unpin>(
    session: &Session<W>,
    cx: &mut Context<'_>,
    bytes: &[u8],
    flush: bool,
) -> Poll<io::Result<()>> {
    let mut writer = match session.writer.try_lock() {
        Ok(writer) => writer,
        Err(_) => {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
    };
    let mut written = 0;
    while written < bytes.len() {
        match Pin::new(&mut *writer).poll_write(cx, &bytes[written..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "anytls session closed",
                )))
            }
            Poll::Ready(Ok(n)) => written += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }
    if flush {
        match Pin::new(&mut *writer).poll_flush(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    } else {
        Poll::Ready(Ok(()))
    }
}

/// The AnyTLS stream handed to the relay.
pub struct AnytlsStream<W> {
    session: Arc<Session<W>>,
    state: Arc<StreamState>,
    sid: u32,
    /// Bytes of the current inbox chunk already delivered.
    delivered: usize,
}

impl<W: AsyncWrite + Unpin + Send> AsyncWrite for AnytlsStream<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let len = buf.len().min(MAX_FRAME);
        let bytes = frame(CMD_PSH, this.sid, &buf[..len]);
        match poll_session_write(&this.session, cx, &bytes, false) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(len)),
            other => other.map(|r| r.map(|_| 0)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_session_write(&this.session, cx, &[], true)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.state.fin_sent.swap(true, Ordering::SeqCst) {
            let bytes = frame(CMD_FIN, this.sid, &[]);
            match poll_session_write(&this.session, cx, &bytes, false) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.state.fin_sent.store(false, Ordering::SeqCst);
                    return Poll::Pending;
                }
            }
        }
        poll_session_write(&this.session, cx, &[], true)
    }
}

impl<W: AsyncWrite + Unpin + Send> AsyncRead for AnytlsStream<W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            {
                let mut inbox = this.state.inbox.lock().expect("anytls inbox");
                if this.delivered < inbox.len() {
                    let n = buf.remaining().min(inbox.len() - this.delivered);
                    buf.put_slice(&inbox[this.delivered..this.delivered + n]);
                    this.delivered += n;
                    if this.delivered == inbox.len() {
                        inbox.clear();
                        this.delivered = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                inbox.clear();
                this.delivered = 0;
            }
            if let Some(result) = this.state.closed.lock().expect("anytls closed").take() {
                return Poll::Ready(result);
            }
            let notified = this.state.recv.notified();
            match std::future::Future::poll(Pin::new(&mut Box::pin(notified)), cx) {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Read frames until the session ends; a stream that is still open then fails.
async fn recv_loop<R, W>(mut reader: R, session: Arc<Session<W>>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut header = [0u8; HEADER];
    'frames: loop {
        if reader.read_exact(&mut header).await.is_err() {
            break;
        }
        let cmd = header[0];
        let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let len = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut data = vec![0u8; len];
        if len > 0 && reader.read_exact(&mut data).await.is_err() {
            break;
        }
        let state = session
            .streams
            .lock()
            .expect("anytls streams")
            .get(&sid)
            .cloned();
        match cmd {
            CMD_PSH => {
                if let Some(state) = &state {
                    state
                        .inbox
                        .lock()
                        .expect("anytls inbox")
                        .extend_from_slice(&data);
                    state.recv.notify_waiters();
                }
            }
            CMD_SYNACK => {
                if let Some(state) = &state {
                    if let Some(tx) = state.synack.lock().expect("anytls synack").take() {
                        let result = if data.is_empty() {
                            Ok(())
                        } else {
                            Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                String::from_utf8_lossy(&data).to_string(),
                            ))
                        };
                        let _ = tx.send(result);
                    }
                }
            }
            CMD_FIN => {
                if let Some(state) = &state {
                    *state.closed.lock().expect("anytls closed") = Some(Ok(()));
                    state.recv.notify_waiters();
                }
            }
            CMD_ALERT => {
                let message = format!("anytls server alert: {}", String::from_utf8_lossy(&data));
                for state in session.streams.lock().expect("anytls streams").values() {
                    state.fail(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        message.clone(),
                    ));
                }
                break 'frames;
            }
            CMD_HEART_REQUEST => {
                let _ = session.send(&frame(CMD_HEART_RESPONSE, sid, &[])).await;
            }
            CMD_SERVER_SETTINGS | CMD_UPDATE_PADDING | CMD_SETTINGS | CMD_WASTE
            | CMD_HEART_RESPONSE => {}
            _ => {}
        }
    }
    for state in session.streams.lock().expect("anytls streams").values() {
        state.fail(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "anytls session closed",
        ));
    }
}

pub async fn dial(
    option: &AnytlsOutbound,
    target: &Target,
    tls: &ClientTls,
) -> Result<Dialed, DialError> {
    let tcp = connect_tcp(&option.server, option.port).await?;
    let server = tcp.peer_addr().map_err(|e| handshake("anytls", e))?;
    let mut stream = tls::wrap(tcp, &option.server, &option.tls_settings, tls)
        .await
        .map_err(|e| handshake("anytls tls", e))?;
    stream
        .write_all(&hello(option.password.expose()))
        .await
        .map_err(|e| handshake("anytls", e))?;
    let mut opening = frame(CMD_SETTINGS, 0, &settings());
    opening.extend_from_slice(&frame(CMD_SYN, 1, &[]));
    opening.extend_from_slice(&frame(CMD_PSH, 1, &write_destination(target)));
    stream
        .write_all(&opening)
        .await
        .map_err(|e| handshake("anytls", e))?;
    stream.flush().await.map_err(|e| handshake("anytls", e))?;

    let (reader, writer) = tokio::io::split(stream);
    // The server's success/failure report for this stream (SYNACK).
    let (syn_tx, _syn_rx) = tokio::sync::oneshot::channel();
    let state = Arc::new(StreamState {
        synack: Mutex::new(Some(syn_tx)),
        recv: tokio::sync::Notify::new(),
        inbox: Mutex::new(Vec::new()),
        closed: Mutex::new(None),
        fin_sent: AtomicBool::new(false),
    });
    let mut streams = HashMap::new();
    streams.insert(1u32, state.clone());
    let session = Arc::new(Session {
        writer: tokio::sync::Mutex::new(writer),
        streams: Mutex::new(streams),
    });
    tokio::spawn(recv_loop(reader, session.clone()));
    Ok(Dialed {
        stream: Box::new(AnytlsStream {
            session,
            state,
            sid: 1,
            delivered: 0,
        }),
        server,
    })
}
