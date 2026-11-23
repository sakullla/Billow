//! ShadowQUIC outbound (QUIC v1 only with this quinn build).
//!
//! The framing below is an independent Rust implementation of the observable
//! ShadowQUIC data path: a command byte + SOCKS5 address on a bidirectional
//! stream for TCP, and a command byte + unspecified address on a control
//! stream with `u16` id mappings for UDP (QUIC datagrams or one uni stream per
//! destination with `u16` lengths). The process and the black-box observations
//! are recorded in `tool/kernel-compat/evidence/t15-cleanroom.md`; no GPL-3.0
//! source is vendored, linked, or copied. The JLS license/text is in
//! `native-kernel/THIRD_PARTY_NOTICES.md`.
//!
//! One QUIC connection carries every session:
//!
//! ```text
//! CommandConnect           0x01  + SOCKS5 address, then the raw stream
//! CommandAssociateDatagram 0x03  + unspecified address, UDP via QUIC datagrams
//! CommandAssociateStream   0x04  + unspecified address, UDP via uni streams
//! ```
//!
//! A UDP association is one bidirectional control stream plus per-destination
//! ids:
//!
//! - each side writes `address + u16 id` on the control stream to map an id;
//! - datagram mode sends `u16 id + payload` in QUIC datagrams;
//! - stream mode sends one uni stream per destination, `u16 id` then repeated
//!   `u16 length + payload`.
//!
//! The extension commands (`0xff`) are not used by the client: the private
//! mihomo Brutal negotiation is not implemented because quinn has no Brutal
//! congestion controller, and the pinned server answers the stats/user
//! extensions with errors anyway.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::jls::JlsCredentials;
use super::quic::{self, QuicOptions, QuicStream};
use super::tls::ClientTls;
use super::{DialError, Dialed, SocksAddr, Target};
use crate::proxies::ShadowQuicOutbound;

pub const COMMAND_CONNECT: u8 = 0x01;
pub const COMMAND_ASSOCIATE_DATAGRAM: u8 = 0x03;
pub const COMMAND_ASSOCIATE_STREAM: u8 = 0x04;

const MAX_UDP_PACKET: usize = 0xffff;
const PENDING_PER_ID: usize = 32;
const PENDING_BYTES: usize = 64 * 1024;
const UNSPECIFIED_ADDRESS: [u8; 7] = [0x01, 0, 0, 0, 0, 0, 0];

fn handshake(kind: io::ErrorKind, message: impl Into<String>) -> DialError {
    DialError::Handshake {
        protocol: "shadowquic",
        source: io::Error::new(kind, message.into()),
    }
}

fn alloc_id(used: &HashMap<Target, u16>, next_id: &mut u16) -> io::Result<u16> {
    let start = *next_id;
    loop {
        let id = *next_id;
        *next_id = next_id.wrapping_add(1);
        if !used.values().any(|used| *used == id) {
            return Ok(id);
        }
        if *next_id == start {
            return Err(io::Error::other("shadowquic: too many UDP destinations"));
        }
    }
}

/// Read one SOCKS5 address (`socks5.Addr`) from a stream.
async fn read_address<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Target> {
    let kind = reader.read_u8().await?;
    let host = match kind {
        0x01 => {
            let mut raw = [0u8; 4];
            reader.read_exact(&mut raw).await?;
            std::net::Ipv4Addr::from(raw).to_string()
        }
        0x04 => {
            let mut raw = [0u8; 16];
            reader.read_exact(&mut raw).await?;
            std::net::Ipv6Addr::from(raw).to_string()
        }
        0x03 => {
            let len = reader.read_u8().await? as usize;
            if len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "shadowquic: empty domain address",
                ));
            }
            let mut name = vec![0u8; len];
            reader.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "shadowquic: non-UTF-8 domain")
            })?
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("shadowquic: address type {other:#x} is invalid"),
            ))
        }
    };
    let port = reader.read_u16().await?;
    Ok(Target { host, port })
}

/// Dial `target` through a ShadowQUIC server.
pub async fn dial(
    option: &ShadowQuicOutbound,
    target: &Target,
    tls: &ClientTls,
    timeout: Duration,
) -> Result<Dialed, DialError> {
    let alpn = if option.alpn.is_empty() {
        vec!["h3".to_string()]
    } else {
        option.alpn.clone()
    };
    let mut quic_options = QuicOptions::new(alpn);
    quic_options.datagrams = true;
    quic_options.keep_alive =
        (option.keep_alive_interval > 0).then(|| Duration::from_millis(option.keep_alive_interval));
    quic_options.stream_receive_window = option.recv_window_conn;
    quic_options.connection_receive_window = option.recv_window;
    quic_options.max_concurrent_uni_streams = Some(option.max_open_streams);
    quic_options.max_concurrent_bidi_streams = Some(option.max_open_streams);
    quic_options.mtu_discovery = !option.disable_mtu_discovery;
    quic_options.datagram_receive_buffer = Some(option.max_datagram_frame_size);
    quic_options.datagram_send_buffer = Some(option.max_datagram_frame_size);

    let settings = crate::proxies::TlsSettings {
        sni: option.sni.clone(),
        skip_cert_verify: false,
        alpn: quic_options.alpn.clone(),
        ..Default::default()
    };
    let credentials = JlsCredentials {
        username: option.username.clone(),
        password: option.password.clone(),
    };
    let (connection, endpoint) = quic::connect_jls(
        &option.server,
        &option.server,
        option.port,
        &settings,
        tls,
        &quic_options,
        timeout,
        &credentials,
    )
    .await?;
    let server = connection.remote_address();
    let (mut send, recv) = match tokio::time::timeout(timeout, connection.open_bi()).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return Err(handshake(io::ErrorKind::ConnectionAborted, e.to_string())),
        Err(_) => return Err(DialError::Timeout(timeout)),
    };
    let mut request = Vec::with_capacity(1 + target.host.len() + 8);
    request.push(COMMAND_CONNECT);
    request.extend_from_slice(&SocksAddr::encode(target));
    if let Err(e) = send.write_all(&request).await {
        return Err(handshake(io::ErrorKind::BrokenPipe, e.to_string()));
    }
    Ok(Dialed {
        stream: Box::new(QuicStream::new(send, recv, connection, endpoint)),
        server,
    })
}

/// Masks queued datagrams for one association. The id map is shared by the
/// control reader and the datagram/uni-stream readers.
struct Shared {
    state: std::sync::Mutex<SharedState>,
    inbound: mpsc::Sender<(Target, Vec<u8>)>,
    /// Incremented for every new control stream; an old reader must not write
    /// stale id mappings into the new association.
    generation: std::sync::atomic::AtomicU64,
}

#[derive(Default)]
struct SharedState {
    ids: HashMap<u16, Target>,
    pending: HashMap<u16, Vec<Vec<u8>>>,
    pending_bytes: usize,
}

impl Shared {
    async fn deliver(&self, id: u16, payload: Vec<u8>, buffer_limit: usize) {
        let mut payload = Some(payload);
        let target = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(target) = state.ids.get(&id) {
                Some(target.clone())
            } else {
                // The pinned client buffers up to 32 packets per unknown id
                // until the control entry arrives; the server writes the
                // control entry first but QUIC does not order streams.
                let size = payload.as_ref().map(|packet| packet.len()).unwrap_or(0);
                let fits = size <= buffer_limit
                    && state.pending_bytes + size <= PENDING_BYTES
                    && state
                        .pending
                        .get(&id)
                        .map(|slot| slot.len() < PENDING_PER_ID)
                        .unwrap_or(true);
                if fits {
                    let packet = payload.take().expect("size was read from it");
                    state.pending_bytes += packet.len();
                    state.pending.entry(id).or_default().push(packet);
                }
                None
            }
        };
        if let (Some(target), Some(payload)) = (target, payload) {
            let _ = self.inbound.send((target, payload)).await;
        }
    }

    /// Drop every id mapping when a new control stream replaces the old
    /// association. In-flight datagrams of the old association are discarded
    /// instead of being attributed to an id the new peer may reuse.
    fn reset(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.ids.clear();
        state.pending.clear();
        state.pending_bytes = 0;
    }

    async fn map(&self, id: u16, target: Target) {
        let pending = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.ids.insert(id, target.clone());
            let pending = state.pending.remove(&id).unwrap_or_default();
            for packet in &pending {
                state.pending_bytes = state.pending_bytes.saturating_sub(packet.len());
            }
            pending
        };
        for packet in pending {
            let _ = self.inbound.send((target.clone(), packet)).await;
        }
    }
}

/// One ShadowQUIC UDP association over a shared QUIC connection.
pub struct ShadowQuicUdp {
    connection: Connection,
    endpoint: Endpoint,
    control: Option<SendStream>,
    shared: std::sync::Arc<Shared>,
    command: u8,
    inbound: mpsc::Receiver<(Target, Vec<u8>)>,
    over_stream: bool,
    max_datagram: usize,
    send_ids: HashMap<Target, u16>,
    next_id: u16,
    uni: HashMap<Target, SendStream>,
}

impl ShadowQuicUdp {
    /// Open the UDP association; `option.udp_over_stream` selects the stream
    /// carrier instead of QUIC datagrams.
    pub async fn connect(
        option: &ShadowQuicOutbound,
        tls: &ClientTls,
        timeout: Duration,
    ) -> Result<ShadowQuicUdp, DialError> {
        let alpn = if option.alpn.is_empty() {
            vec!["h3".to_string()]
        } else {
            option.alpn.clone()
        };
        let mut quic_options = QuicOptions::new(alpn);
        quic_options.datagrams = true;
        quic_options.keep_alive = (option.keep_alive_interval > 0)
            .then(|| Duration::from_millis(option.keep_alive_interval));
        quic_options.stream_receive_window = option.recv_window_conn;
        quic_options.connection_receive_window = option.recv_window;
        quic_options.max_concurrent_uni_streams = Some(option.max_open_streams);
        quic_options.max_concurrent_bidi_streams = Some(option.max_open_streams);
        quic_options.mtu_discovery = !option.disable_mtu_discovery;
        quic_options.datagram_receive_buffer = Some(option.max_datagram_frame_size);
        quic_options.datagram_send_buffer = Some(option.max_datagram_frame_size);

        let settings = crate::proxies::TlsSettings {
            sni: option.sni.clone(),
            skip_cert_verify: false,
            alpn: quic_options.alpn.clone(),
            ..Default::default()
        };
        let credentials = JlsCredentials {
            username: option.username.clone(),
            password: option.password.clone(),
        };
        let (connection, endpoint) = quic::connect_jls(
            &option.server,
            &option.server,
            option.port,
            &settings,
            tls,
            &quic_options,
            timeout,
            &credentials,
        )
        .await?;
        let command = if option.udp_over_stream {
            COMMAND_ASSOCIATE_STREAM
        } else {
            COMMAND_ASSOCIATE_DATAGRAM
        };
        match tokio::time::timeout(
            timeout,
            build_association(
                connection,
                endpoint,
                command,
                option.max_datagram_frame_size,
            ),
        )
        .await
        {
            Ok(result) => result.map_err(|e| handshake(io::ErrorKind::Other, e.to_string())),
            Err(_) => Err(DialError::Timeout(timeout)),
        }
    }

    /// Build an association over an already-authenticated connection. The
    /// production path reaches it through [`connect`]; tests use it with a
    /// plain quinn connection to exercise stream-reopen recovery without JLS.
    #[doc(hidden)]
    pub async fn from_connection_for_test(
        connection: Connection,
        endpoint: Endpoint,
        over_stream: bool,
        max_datagram: usize,
    ) -> io::Result<ShadowQuicUdp> {
        let command = if over_stream {
            COMMAND_ASSOCIATE_STREAM
        } else {
            COMMAND_ASSOCIATE_DATAGRAM
        };
        build_association(connection, endpoint, command, max_datagram).await
    }

    fn alloc_id(&mut self) -> io::Result<u16> {
        alloc_id(&self.send_ids, &mut self.next_id)
    }

    /// Send one UDP payload to `target`.
    pub async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_UDP_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shadowquic: UDP payload is too large",
            ));
        }
        let id = match self.send_ids.get(target).copied() {
            Some(id) => id,
            None => {
                let id = self.alloc_id()?;
                let mut entry = SocksAddr::encode(target);
                entry.extend_from_slice(&id.to_be_bytes());
                self.write_control(&entry).await?;
                self.send_ids.insert(target.clone(), id);
                id
            }
        };

        if self.over_stream {
            // A peer may stop/reset a uni stream at any time (the pinned server
            // closes its per-destination stream when the association is torn
            // down). Remove the cached stream and rebuild it once; the id
            // mapping itself stays on the control stream.
            for attempt in 0..2 {
                let mut stream = match self.uni.remove(target) {
                    Some(stream) => stream,
                    None => self.open_uni(id).await?,
                };
                let written = async {
                    stream.write_u16(payload.len() as u16).await?;
                    stream
                        .write_all(payload)
                        .await
                        .map_err(|e| io::Error::other(e.to_string()))
                }
                .await;
                match written {
                    Ok(()) => {
                        self.uni.insert(target.clone(), stream);
                        return Ok(());
                    }
                    Err(error) if attempt == 0 => {
                        // Dropping the stream sends its reset; the next loop
                        // opens a fresh uni stream with the same id.
                        let _ = error;
                    }
                    Err(error) => return Err(error),
                }
            }
            unreachable!("the loop returns on success or the second error")
        } else {
            // `max_datagram_frame_size` is the configured frame limit; the
            // usable payload is also bounded by the path MTU, which quinn
            // exposes once the handshake has completed.
            let limit = self
                .connection
                .max_datagram_size()
                .unwrap_or(self.max_datagram)
                .min(self.max_datagram);
            if payload.len() + 2 > limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "shadowquic: UDP payload {} plus the 2-byte id exceeds the usable datagram size {limit} (max-datagram-frame-size {}); use udp-over-stream for larger packets",
                        payload.len(),
                        self.max_datagram
                    ),
                ));
            }
            let mut packet = Vec::with_capacity(2 + payload.len());
            packet.extend_from_slice(&id.to_be_bytes());
            packet.extend_from_slice(payload);
            self.connection
                .send_datagram(Bytes::from(packet))
                .map_err(|e| io::Error::other(e.to_string()))
        }
    }

    /// Open one client-to-server uni stream and write its id.
    async fn open_uni(&self, id: u16) -> io::Result<SendStream> {
        let mut stream = self
            .connection
            .open_uni()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        stream
            .write_all(&id.to_be_bytes())
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(stream)
    }

    /// Write one control entry, reopening the control stream (and the server
    /// association) once if the old stream was closed by the peer.
    async fn write_control(&mut self, entry: &[u8]) -> io::Result<()> {
        if let Some(control) = self.control.as_mut() {
            match control.write_all(entry).await {
                Ok(()) => return Ok(()),
                Err(_) => {
                    // The write half was stopped/reset; drop it and rebuild the
                    // whole association below.
                    self.control = None;
                }
            }
        }
        self.reopen_control().await?;
        self.control
            .as_mut()
            .expect("reopen_control installs a stream")
            .write_all(entry)
            .await
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Re-create the control stream and re-register every live target id. The
    /// peer treats a new control stream as a new association, so cached uni
    /// streams belong to the old one and are dropped.
    async fn reopen_control(&mut self) -> io::Result<()> {
        self.uni.clear();
        self.shared.reset();
        let mut send = open_control(&self.connection, self.command, self.shared.clone()).await?;
        for (target, id) in &self.send_ids {
            let mut entry = SocksAddr::encode(target);
            entry.extend_from_slice(&id.to_be_bytes());
            send.write_all(&entry)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        self.control = Some(send);
        Ok(())
    }

    /// Receive one UDP payload; returns the destination it belongs to.
    pub async fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<(Target, usize)>> {
        loop {
            let Some((target, payload)) = self.inbound.recv().await else {
                return Ok(None);
            };
            if payload.len() > buffer.len() {
                continue;
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            return Ok(Some((target, payload.len())));
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let ip = self
            .connection
            .local_ip()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        Ok(SocketAddr::new(ip, 0))
    }
}

/// Open the initial bidirectional control stream and its reader.
async fn open_control(
    connection: &Connection,
    command: u8,
    shared: std::sync::Arc<Shared>,
) -> io::Result<SendStream> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let generation = shared
        .generation
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
        + 1;
    let mut request = Vec::with_capacity(8);
    request.push(command);
    request.extend_from_slice(&UNSPECIFIED_ADDRESS);
    send.write_all(&request)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    tokio::spawn(async move {
        loop {
            let target = match read_address(&mut recv).await {
                Ok(target) => target,
                Err(_) => return,
            };
            let id = match recv.read_u16().await {
                Ok(id) => id,
                Err(_) => return,
            };
            if shared.generation.load(std::sync::atomic::Ordering::Acquire) != generation {
                return;
            }
            shared.map(id, target).await;
        }
    });
    Ok(send)
}

/// Start the carrier readers for one association.
fn spawn_data_readers(
    connection: &Connection,
    over_stream: bool,
    shared: std::sync::Arc<Shared>,
    buffer_limit: usize,
) {
    if over_stream {
        let streams = connection.clone();
        tokio::spawn(async move {
            loop {
                let stream = match streams.accept_uni().await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let reader_shared = shared.clone();
                tokio::spawn(async move {
                    read_datagram_stream(stream, reader_shared, buffer_limit).await;
                });
            }
        });
    } else {
        let datagrams = connection.clone();
        tokio::spawn(async move {
            loop {
                let packet = match datagrams.read_datagram().await {
                    Ok(packet) => packet,
                    Err(_) => return,
                };
                if packet.len() < 2 {
                    continue;
                }
                let id = u16::from_be_bytes([packet[0], packet[1]]);
                shared.deliver(id, packet[2..].to_vec(), buffer_limit).await;
            }
        });
    }
}

/// Build one association over a connected QUIC transport.
async fn build_association(
    connection: Connection,
    endpoint: Endpoint,
    command: u8,
    max_datagram: usize,
) -> io::Result<ShadowQuicUdp> {
    // The pinned client queues 128 packets per association. This kernel is
    // also the iOS extension (T7's 40 MB budget), so the receive queue is
    // bounded to 32 packets (at most ~2 MB with 64 KiB payloads) and the
    // connection's flow-control windows remain the T10 caps.
    let (inbound_tx, inbound) = mpsc::channel(32);
    let shared = std::sync::Arc::new(Shared {
        state: std::sync::Mutex::new(SharedState::default()),
        inbound: inbound_tx,
        generation: std::sync::atomic::AtomicU64::new(0),
    });
    let control = open_control(&connection, command, shared.clone()).await?;
    let over_stream = command == COMMAND_ASSOCIATE_STREAM;
    let buffer_limit = if over_stream {
        MAX_UDP_PACKET
    } else {
        max_datagram
    };
    spawn_data_readers(&connection, over_stream, shared.clone(), buffer_limit);
    Ok(ShadowQuicUdp {
        connection,
        endpoint,
        control: Some(control),
        shared,
        command,
        inbound,
        over_stream,
        max_datagram,
        send_ids: HashMap::new(),
        next_id: 0,
        uni: HashMap::new(),
    })
}

impl Drop for ShadowQuicUdp {
    fn drop(&mut self) {
        // The reader tasks hold clones of the connection; closing here ends
        // them with the association instead of waiting for the idle timeout.
        self.connection
            .close(0u32.into(), b"shadowquic association closed");
        let _ = &self.endpoint;
    }
}

async fn read_datagram_stream(
    mut stream: RecvStream,
    shared: std::sync::Arc<Shared>,
    buffer_limit: usize,
) {
    let id = match stream.read_u16().await {
        Ok(id) => id,
        Err(_) => return,
    };
    loop {
        let length = match stream.read_u16().await {
            Ok(length) => length as usize,
            Err(_) => return,
        };
        let mut payload = vec![0u8; length];
        if stream.read_exact(&mut payload).await.is_err() {
            return;
        }
        shared.deliver(id, payload, buffer_limit).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn address_round_trip() {
        for target in [
            Target {
                host: "example.org".to_string(),
                port: 443,
            },
            Target {
                host: "127.0.0.1".to_string(),
                port: 53,
            },
            Target {
                host: "2001:db8::1".to_string(),
                port: 853,
            },
        ] {
            let bytes = SocksAddr::encode(&target);
            let read = read_address(&mut bytes.as_slice()).await.expect("address");
            assert_eq!(read, target);
        }
    }

    #[tokio::test]
    async fn invalid_address_types_are_rejected() {
        assert!(read_address(&mut [0x02u8, 0, 1].as_slice()).await.is_err());
        assert!(read_address(&mut [0x03u8, 0].as_slice()).await.is_err());
        assert!(read_address(&mut [0x01u8, 1, 2].as_slice()).await.is_err());
    }

    #[test]
    fn id_allocation_skips_used_ids() {
        let mut used = HashMap::new();
        used.insert(
            Target {
                host: "a".to_string(),
                port: 1,
            },
            0u16,
        );
        let mut next = 0u16;
        assert_eq!(alloc_id(&used, &mut next).unwrap(), 1);
        used.insert(
            Target {
                host: "b".to_string(),
                port: 1,
            },
            1u16,
        );
        assert_eq!(alloc_id(&used, &mut next).unwrap(), 2);
    }
}
