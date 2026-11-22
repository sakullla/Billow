//! Minimal TCP client for the MASQUE CONNECT-IP tunnel.
//!
//! CONNECT-IP (RFC 9484) carries whole IP packets, so serving a TCP target
//! means terminating TCP in userspace. The pinned adapter uses mipstack or
//! gVisor for that; this module is the smallest correct active-open client the
//! kernel needs, with the limits written down instead of hidden:
//!
//! * active open only (the kernel always initiates): SYN, SYN-ACK/ACK,
//!   data/ACK, FIN/RST; no passive open, no simultaneous open;
//! * one connection per tunnel, one MSS-sized segment per packet, no
//!   window scaling (RFC 7323 is not negotiated, so the advertised window is
//!   the 16-bit field), no SACK, no timestamps, no urgent data;
//! * a 64 KiB send buffer and a 64 KiB receive buffer (in-order plus a bounded
//!   out-of-order map);
//! * retransmission with an RFC 6298-style initial RTO of 1 s, exponential
//!   backoff to 8 s and at most 8 retries; fast retransmit after three
//!   duplicate ACKs; a zero window waits for the peer's update (no persist
//!   timer: the connection's dial timeout bounds it);
//! * the receive side reorders inside the window and delivers in order; a
//!   segment outside the window is acknowledged (to prompt a retransmit) and
//!   dropped.
//!
//! The state machine is synchronous and owns no sockets: the actor in
//! `masque_ip` feeds it parsed IP packets and timers and takes the packets it
//! wants to send (IP packets, already checksummed). That keeps the wire logic
//! unit-testable against scripted peers.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::ipstack;

pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_PSH: u8 = 0x08;
pub const FLAG_ACK: u8 = 0x10;

/// Bytes the application may queue for transmission.
pub const SEND_BUFFER: usize = 64 * 1024;
/// Bytes buffered for the application (in-order plus out-of-order).
pub const RECEIVE_BUFFER: usize = 64 * 1024;
/// Advertised receive window (no window scaling is negotiated).
const ADVERTISED_WINDOW: u16 = u16::MAX;
/// MSS to assume when the peer sends no MSS option (RFC 1122 §4.2.2.6).
const DEFAULT_MSS: u16 = 536;
/// RFC 6298 initial RTO before any RTT measurement.
const INITIAL_RTO: Duration = Duration::from_secs(1);
const MAX_RTO: Duration = Duration::from_secs(8);
const MAX_RETRIES: u32 = 8;
/// Out-of-order segments kept per connection; each is bounded by the MSS.
const MAX_OUT_OF_ORDER: usize = 32;
const MAX_OOO_BYTES: usize = 64 * 1024;

/// TCP connection states this client can be in (active open).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
    Closed,
}

/// One parsed TCP segment of a tunnel packet.
#[derive(Debug)]
pub struct TcpSegment<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub ws: Option<u8>,
    pub payload: &'a [u8],
}

/// Parse one TCP segment out of an IP packet, verifying the transport checksum.
pub fn parse_segment(packet: &[u8]) -> Result<TcpSegment<'_>, String> {
    let parsed = ipstack::parse_ip_packet(packet).map_err(|error| error.to_string())?;
    if parsed.protocol == ipstack::IPPROTO_UDP {
        return Err("UDP packet is not a TCP segment".to_string());
    }
    if parsed.protocol != ipstack::IPPROTO_TCP {
        return Err(format!("IP protocol {} is not TCP", parsed.protocol));
    }
    let bytes = parsed.payload;
    if bytes.len() < 20 {
        return Err("TCP header shorter than 20 bytes".to_string());
    }
    let header_len = usize::from(bytes[12] >> 4) * 4;
    if header_len < 20 || header_len > bytes.len() {
        return Err(format!("TCP header length {header_len}"));
    }
    if !ipstack::transport_checksum_valid(parsed.src, parsed.dst, ipstack::IPPROTO_TCP, &bytes[..])
    {
        return Err("TCP checksum".to_string());
    }
    let mut mss = None;
    let mut ws = None;
    let mut pos = 20;
    while pos < header_len {
        match bytes[pos] {
            0 => break,
            1 => pos += 1,
            kind => {
                let Some(&length) = bytes.get(pos + 1) else {
                    break;
                };
                let length = usize::from(length);
                if length < 2 || pos + length > header_len {
                    break;
                }
                if kind == 2 && length == 4 {
                    mss = Some(u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]));
                } else if kind == 3 && length == 3 {
                    ws = Some(bytes[pos + 2]);
                }
                pos += length;
            }
        }
    }
    Ok(TcpSegment {
        src: parsed.src,
        dst: parsed.dst,
        src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
        seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        flags: bytes[13],
        window: u16::from_be_bytes([bytes[14], bytes[15]]),
        mss,
        ws,
        payload: &bytes[header_len..],
    })
}

/// Build one TCP segment (without the IP header) and fill its checksum.
#[allow(clippy::too_many_arguments)]
fn build_segment(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    payload: &[u8],
) -> Vec<u8> {
    let options: Vec<u8> = match mss {
        Some(mss) => vec![2, 4, (mss >> 8) as u8, mss as u8],
        None => Vec::new(),
    };
    let header_len = 20 + options.len();
    let mut segment = Vec::with_capacity(header_len + payload.len());
    segment.extend_from_slice(&src_port.to_be_bytes());
    segment.extend_from_slice(&dst_port.to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&ack.to_be_bytes());
    segment.push(((header_len / 4) as u8) << 4);
    segment.push(flags);
    segment.extend_from_slice(&window.to_be_bytes());
    segment.extend_from_slice(&[0, 0]); // checksum placeholder
    segment.extend_from_slice(&[0, 0]); // urgent pointer
    segment.extend_from_slice(&options);
    segment.extend_from_slice(payload);
    let checksum = ipstack::transport_checksum(src, dst, ipstack::IPPROTO_TCP, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    segment
}

/// One segment that has been sent and not cumulatively acknowledged. Its
/// payload is retained for retransmission (bounded by [`SEND_BUFFER`] in
/// total: `send_queue + unacked` never exceeds it).
struct Sent {
    seq: u32,
    flags: u8,
    len: usize,
    payload: Vec<u8>,
    mss: Option<u16>,
    sent_at: Instant,
    retransmits: u32,
}

/// How one tunnel TCP connection is opened. `mss` is what the client
/// advertises (tunnel MTU minus the IPv4/IPv6 and TCP header sizes).
#[derive(Debug, Clone, Copy)]
pub struct TcpConfig {
    pub local: IpAddr,
    pub remote: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub mss: u16,
    pub initial_seq: u32,
    pub connect_deadline: Instant,
    pub hop_limit: u8,
}

/// The client side of one TCP connection, driven by `masque_ip`.
pub struct TcpConnection {
    cfg: TcpConfig,
    state: TcpState,
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u16,
    snd_mss: u16,
    snd_wl1: u32,
    snd_wl2: u32,
    rcv_nxt: u32,
    send_queue: VecDeque<u8>,
    unacked: VecDeque<Sent>,
    received: VecDeque<Vec<u8>>,
    buffered: usize,
    ooo: BTreeMap<u32, Vec<u8>>,
    ooo_bytes: usize,
    ack_pending: bool,
    app_shutdown: bool,
    fin_sent: bool,
    fin_acked: bool,
    fin_received: bool,
    rto: Duration,
    dup_acks: u32,
    error: Option<io::Error>,
    /// Packets ready to send (retransmissions), drained before new segments.
    outbox: VecDeque<Vec<u8>>,
}

impl TcpConnection {
    pub fn new(cfg: TcpConfig, _now: Instant) -> TcpConnection {
        TcpConnection {
            cfg,
            state: TcpState::SynSent,
            snd_una: cfg.initial_seq,
            snd_nxt: cfg.initial_seq,
            snd_wnd: 0,
            snd_mss: DEFAULT_MSS,
            snd_wl1: 0,
            snd_wl2: 0,
            rcv_nxt: 0,
            send_queue: VecDeque::new(),
            unacked: VecDeque::new(),
            received: VecDeque::new(),
            buffered: 0,
            ooo: BTreeMap::new(),
            ooo_bytes: 0,
            ack_pending: false,
            app_shutdown: false,
            fin_sent: false,
            fin_acked: false,
            fin_received: false,
            rto: INITIAL_RTO,
            dup_acks: 0,
            error: None,
            outbox: VecDeque::new(),
        }
    }

    pub fn state(&self) -> TcpState {
        self.state
    }

    pub fn established(&self) -> bool {
        self.state != TcpState::SynSent && self.state != TcpState::Closed
    }

    /// A terminal failure (RST, timeout, retry exhaustion). Once set, the
    /// connection sends nothing more.
    pub fn failure(&self) -> Option<&io::Error> {
        self.error.as_ref()
    }

    /// True once the peer's FIN has arrived (the inbound direction ended).
    pub fn peer_closed(&self) -> bool {
        self.fin_received
    }

    /// True while received payload is still waiting for the application.
    pub fn received_empty(&self) -> bool {
        self.received.is_empty()
    }

    /// True once no more data can arrive and every segment is acknowledged.
    pub fn finished(&self) -> bool {
        matches!(self.state, TcpState::Closed)
            && self.unacked.is_empty()
            && self.received.is_empty()
    }

    /// Whether the application may hand over more bytes.
    pub fn can_accept(&self) -> bool {
        self.error.is_none()
            && matches!(self.state, TcpState::Established | TcpState::CloseWait)
            && !self.app_shutdown
            && self.send_queue.len() < SEND_BUFFER
    }

    /// Queue application bytes; returns how many were accepted (0 when the
    /// send buffer is full or the connection cannot carry data).
    pub fn enqueue(&mut self, data: &[u8]) -> usize {
        if !self.can_accept() {
            return 0;
        }
        let accepted = data.len().min(SEND_BUFFER - self.send_queue.len());
        self.send_queue.extend(&data[..accepted]);
        accepted
    }

    /// Half-close: send FIN once the queued data has been sent.
    pub fn shutdown(&mut self) {
        self.app_shutdown = true;
    }

    /// The next in-order payload for the application.
    pub fn take_received(&mut self) -> Option<Vec<u8>> {
        let data = self.received.pop_front()?;
        self.buffered -= data.len();
        // The window opened: tell the peer on the next transmission.
        self.ack_pending = true;
        Some(data)
    }

    /// Feed one inbound IP packet. Malformed segments and segments of another
    /// connection are ignored (the caller logs them at debug level).
    pub fn on_packet(&mut self, packet: &[u8], now: Instant) {
        let _ = now;
        if self.error.is_some() {
            return;
        }
        let segment = match parse_segment(packet) {
            Ok(segment) => segment,
            Err(_) => return,
        };
        if segment.src != self.cfg.remote
            || segment.dst != self.cfg.local
            || segment.src_port != self.cfg.remote_port
            || segment.dst_port != self.cfg.local_port
        {
            return;
        }
        if segment.flags & FLAG_RST != 0 {
            self.fail(io::ErrorKind::ConnectionReset, "connection reset by peer");
            return;
        }
        if self.state == TcpState::SynSent {
            self.on_syn_ack(&segment);
            return;
        }
        if segment.flags & FLAG_ACK == 0 {
            return;
        }
        self.on_ack(&segment);
        self.on_payload(&segment);
        if self.error.is_some() {
            return;
        }
        if segment.flags & FLAG_FIN != 0 {
            self.on_fin(&segment);
        }
        self.advance_close_state();
    }

    fn on_syn_ack(&mut self, segment: &TcpSegment<'_>) {
        if segment.flags & (FLAG_SYN | FLAG_ACK) != FLAG_SYN | FLAG_ACK {
            return;
        }
        if segment.ack != self.cfg.initial_seq.wrapping_add(1) {
            return;
        }
        self.snd_una = segment.ack;
        self.snd_wnd = segment.window;
        self.snd_mss = self.cfg.mss.min(segment.mss.unwrap_or(DEFAULT_MSS)).max(1);
        self.rcv_nxt = segment.seq.wrapping_add(1);
        self.state = TcpState::Established;
        self.ack_pending = true;
        // The SYN is acknowledged; nothing remains unacked.
        self.unacked.clear();
        self.rto = INITIAL_RTO;
        self.dup_acks = 0;
    }

    fn on_ack(&mut self, segment: &TcpSegment<'_>) {
        if seq_after(segment.ack, self.snd_nxt) {
            // Acknowledges data never sent: ignore the segment, as RFC 793
            // requires (the peer is broken).
            return;
        }
        if seq_after(segment.ack, self.snd_una) {
            self.snd_una = segment.ack;
            while let Some(front) = self.unacked.front() {
                let end = front.seq.wrapping_add(front.len as u32);
                if !seq_after(end, self.snd_una) {
                    let sent = self.unacked.pop_front().expect("front exists");
                    if sent.flags & FLAG_FIN != 0 {
                        self.fin_acked = true;
                    }
                } else {
                    break;
                }
            }
            self.rto = INITIAL_RTO;
            self.dup_acks = 0;
            for sent in self.unacked.iter_mut() {
                sent.retransmits = 0;
            }
        } else if segment.payload.is_empty() && segment.window == self.snd_wnd {
            // Duplicate ACK: three in a row trigger a fast retransmit.
            self.dup_acks = self.dup_acks.saturating_add(1);
        }
        // Window update (SND.WL1/SND.WL2, RFC 793 §3.9).
        if seq_after(segment.ack, self.snd_wl1)
            || (segment.ack == self.snd_wl1 && seq_after(segment.seq, self.snd_wl2))
        {
            self.snd_wnd = segment.window;
            self.snd_wl1 = segment.ack;
            self.snd_wl2 = segment.seq;
        }
    }

    fn on_payload(&mut self, segment: &TcpSegment<'_>) {
        let mut payload = segment.payload;
        let mut seq = segment.seq;
        if payload.is_empty() {
            return;
        }
        if seq_before(seq, self.rcv_nxt) {
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip >= payload.len() {
                // Entirely old data: acknowledge it again.
                self.ack_pending = true;
                return;
            }
            payload = &payload[skip..];
            seq = self.rcv_nxt;
        }
        if seq == self.rcv_nxt {
            self.buffered += payload.len();
            if self.buffered > RECEIVE_BUFFER {
                // The peer ignored the advertised window; drop the excess and
                // acknowledge what fits so it can retry later.
                self.buffered -= payload.len();
                self.ack_pending = true;
                return;
            }
            self.received.push_back(payload.to_vec());
            self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
            self.ack_pending = true;
            self.drain_out_of_order();
        } else if seq_after(seq, self.rcv_nxt) {
            let offset = seq.wrapping_sub(self.rcv_nxt) as usize;
            if offset < RECEIVE_BUFFER
                && self.ooo.len() < MAX_OUT_OF_ORDER
                && self.ooo_bytes + payload.len() <= MAX_OOO_BYTES
            {
                self.ooo_bytes += payload.len();
                self.ooo.insert(seq, payload.to_vec());
            }
            // Acknowledge the gap so the peer retransmits it.
            self.ack_pending = true;
        }
    }

    fn drain_out_of_order(&mut self) {
        while let Some((&seq, _)) = self.ooo.iter().next() {
            if seq != self.rcv_nxt {
                break;
            }
            let data = self.ooo.remove(&seq).expect("key exists");
            self.ooo_bytes -= data.len();
            self.buffered += data.len();
            self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
            self.received.push_back(data);
        }
    }

    fn on_fin(&mut self, segment: &TcpSegment<'_>) {
        let end = segment.seq.wrapping_add(segment.payload.len() as u32);
        if end != self.rcv_nxt || self.fin_received {
            // Out-of-order FIN: the peer retransmits it with the data.
            self.ack_pending = true;
            return;
        }
        self.fin_received = true;
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.ack_pending = true;
        match self.state {
            TcpState::Established => self.state = TcpState::CloseWait,
            TcpState::FinWait1 => self.state = TcpState::Closing,
            TcpState::FinWait2 => self.state = TcpState::TimeWait,
            other => self.state = other,
        }
    }

    fn advance_close_state(&mut self) {
        if self.fin_acked && self.state == TcpState::FinWait1 {
            self.state = TcpState::FinWait2;
        }
        if self.fin_acked && self.fin_received && matches!(self.state, TcpState::Closing) {
            self.state = TcpState::Closed;
        }
        if self.fin_acked && self.fin_received && self.state == TcpState::CloseWait {
            // The application never half-closed, but both directions ended.
            self.state = TcpState::LastAck;
        }
        if self.fin_acked && self.fin_received && self.state == TcpState::LastAck {
            self.state = TcpState::Closed;
        }
        if self.fin_acked && self.state == TcpState::FinWait2 && self.fin_received {
            self.state = TcpState::TimeWait;
        }
        if self.fin_acked && self.state == TcpState::TimeWait {
            self.state = TcpState::Closed;
        }
    }

    fn fail(&mut self, kind: io::ErrorKind, message: &str) {
        if self.error.is_none() {
            self.error = Some(io::Error::new(kind, message.to_string()));
        }
        self.state = TcpState::Closed;
    }

    /// Retransmission / handshake timers.
    pub fn on_timer(&mut self, now: Instant) {
        if self.error.is_some() {
            return;
        }
        if !self.established() {
            if now >= self.cfg.connect_deadline {
                self.fail(io::ErrorKind::TimedOut, "TCP handshake timed out");
                return;
            }
            let due = self.unacked.front().map(|sent| sent.sent_at + self.rto);
            if let Some(due) = due {
                if now >= due {
                    let retransmits = self
                        .unacked
                        .front()
                        .map(|sent| sent.retransmits)
                        .unwrap_or(0)
                        + 1;
                    if retransmits > MAX_RETRIES {
                        self.fail(io::ErrorKind::TimedOut, "TCP SYN was never answered");
                        return;
                    }
                    self.rto = (self.rto * 2).min(MAX_RTO);
                    self.retransmit_front(now, retransmits);
                }
            }
            return;
        }
        if let Some(front) = self.unacked.front() {
            let due = front.sent_at + self.rto;
            if now >= due {
                let retransmits = front.retransmits + 1;
                if retransmits > MAX_RETRIES {
                    self.fail(
                        io::ErrorKind::TimedOut,
                        "TCP retransmission limit reached (peer stopped acknowledging)",
                    );
                    return;
                }
                self.rto = (self.rto * 2).min(MAX_RTO);
                self.retransmit_front(now, retransmits);
                return;
            }
        }
        if self.dup_acks >= 3 && self.unacked.len() > 1 {
            self.dup_acks = 0;
            self.retransmit_front(now, 1);
        }
    }

    fn retransmit_front(&mut self, now: Instant, retransmits: u32) {
        let Some(front) = self.unacked.front_mut() else {
            return;
        };
        front.sent_at = now;
        front.retransmits = retransmits;
        let packet = {
            let seq = front.seq;
            let flags = front.flags;
            let mss = front.mss;
            let payload = front.payload.clone();
            self.packet(seq, self.rcv_nxt, flags, mss, &payload)
        };
        self.outbox.push_back(packet);
    }

    /// The next IP packet the connection wants to send, if any.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Vec<u8>> {
        if self.error.is_some() {
            return None;
        }
        if let Some(packet) = self.outbox.pop_front() {
            return Some(packet);
        }
        // A FIN can close the connection while the acknowledgement of the
        // peer's FIN is still owed; that last ACK is the only packet a closed
        // connection may send.
        if self.ack_pending && self.error.is_none() {
            self.ack_pending = false;
            return Some(self.packet(self.snd_nxt, self.rcv_nxt, FLAG_ACK, None, &[]));
        }
        if self.state == TcpState::Closed {
            return None;
        }
        if self.state == TcpState::SynSent {
            if !self.unacked.is_empty() {
                return None;
            }
            let seq = self.cfg.initial_seq;
            let packet = self.packet(seq, 0, FLAG_SYN, Some(self.cfg.mss), &[]);
            self.unacked.push_back(Sent {
                seq,
                flags: FLAG_SYN,
                len: 0,
                payload: Vec::new(),
                mss: Some(self.cfg.mss),
                sent_at: now,
                retransmits: 0,
            });
            self.snd_nxt = seq.wrapping_add(1);
            return Some(packet);
        }
        if self.can_send_data() {
            let inflight = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
            let allowed = usize::from(self.snd_wnd).saturating_sub(inflight);
            let count = self
                .send_queue
                .len()
                .min(usize::from(self.snd_mss))
                .min(allowed);
            if count > 0 {
                let payload: Vec<u8> = self.send_queue.drain(..count).collect();
                let seq = self.snd_nxt;
                let packet = self.packet(seq, self.rcv_nxt, FLAG_ACK | FLAG_PSH, None, &payload);
                self.unacked.push_back(Sent {
                    seq,
                    flags: FLAG_ACK | FLAG_PSH,
                    len: count,
                    payload: payload.clone(),
                    mss: None,
                    sent_at: now,
                    retransmits: 0,
                });
                self.snd_nxt = seq.wrapping_add(count as u32);
                return Some(packet);
            }
        }
        let fin_due = self.app_shutdown
            && self.send_queue.is_empty()
            && !self.fin_sent
            && matches!(self.state, TcpState::Established | TcpState::CloseWait);
        if fin_due {
            let seq = self.snd_nxt;
            let packet = self.packet(seq, self.rcv_nxt, FLAG_FIN | FLAG_ACK, None, &[]);
            self.fin_sent = true;
            self.unacked.push_back(Sent {
                seq,
                flags: FLAG_FIN | FLAG_ACK,
                len: 0,
                payload: Vec::new(),
                mss: None,
                sent_at: now,
                retransmits: 0,
            });
            self.snd_nxt = seq.wrapping_add(1);
            self.state = if self.state == TcpState::Established {
                TcpState::FinWait1
            } else {
                TcpState::LastAck
            };
            return Some(packet);
        }
        None
    }

    fn can_send_data(&self) -> bool {
        self.send_queue.len() > 0
            && matches!(self.state, TcpState::Established | TcpState::CloseWait)
    }

    /// The next timer deadline, or `None` when only inbound traffic can make
    /// progress.
    pub fn next_timer(&self) -> Option<Instant> {
        if self.error.is_some() || self.state == TcpState::Closed {
            return None;
        }
        let retransmit = self.unacked.front().map(|sent| sent.sent_at + self.rto);
        if !self.established() {
            return Some(match retransmit {
                Some(due) => due.min(self.cfg.connect_deadline),
                None => self.cfg.connect_deadline,
            });
        }
        retransmit
    }

    fn advertised_window(&self) -> u16 {
        let buffered = self.buffered + self.ooo_bytes;
        ADVERTISED_WINDOW.saturating_sub(buffered.min(usize::from(ADVERTISED_WINDOW)) as u16)
    }

    fn packet(&self, seq: u32, ack: u32, flags: u8, mss: Option<u16>, payload: &[u8]) -> Vec<u8> {
        let segment = build_segment(
            self.cfg.local,
            self.cfg.remote,
            self.cfg.local_port,
            self.cfg.remote_port,
            seq,
            ack,
            flags,
            self.advertised_window(),
            mss,
            payload,
        );
        ipstack::build_packet(
            self.cfg.local,
            self.cfg.remote,
            ipstack::IPPROTO_TCP,
            &segment,
            self.cfg.hop_limit,
        )
        .unwrap_or_default()
    }
}

fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> TcpConfig {
        TcpConfig {
            local: IpAddr::from([10, 0, 0, 2]),
            remote: IpAddr::from([10, 0, 0, 1]),
            local_port: 40_000,
            remote_port: 80,
            mss: 1460,
            initial_seq: 1000,
            connect_deadline: Instant::now() + Duration::from_secs(5),
            hop_limit: 64,
        }
    }

    fn server_packet(
        cfg: &TcpConfig,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        mss: Option<u16>,
        payload: &[u8],
    ) -> Vec<u8> {
        let segment = build_segment(
            cfg.remote,
            cfg.local,
            cfg.remote_port,
            cfg.local_port,
            seq,
            ack,
            flags,
            window,
            mss,
            payload,
        );
        ipstack::build_packet(cfg.remote, cfg.local, ipstack::IPPROTO_TCP, &segment, 64).unwrap()
    }

    /// SYN -> SYN-ACK -> ACK (the handshake every test below starts from).
    fn established(cfg: &TcpConfig, now: Instant, window: u16, mss: Option<u16>) -> TcpConnection {
        let mut conn = TcpConnection::new(*cfg, now);
        let syn = conn.poll_transmit(now).expect("SYN");
        let parsed = parse_segment(&syn).unwrap();
        assert_eq!(parsed.flags & FLAG_SYN, FLAG_SYN);
        assert_eq!(parsed.seq, cfg.initial_seq);
        assert_eq!(parsed.mss, Some(cfg.mss));
        conn.on_packet(
            &server_packet(cfg, 5000, 1001, FLAG_SYN | FLAG_ACK, window, mss, &[]),
            now,
        );
        assert_eq!(conn.state(), TcpState::Established);
        let ack = conn.poll_transmit(now).expect("handshake ACK");
        let parsed = parse_segment(&ack).unwrap();
        assert_eq!(parsed.flags, FLAG_ACK);
        assert_eq!(parsed.seq, 1001);
        assert_eq!(parsed.ack, 5001);
        conn
    }

    #[test]
    fn segment_codec_round_trips_and_validates_the_checksum() {
        let cfg = config();
        let packet = server_packet(&cfg, 7, 9, FLAG_ACK, 1024, Some(1200), b"payload");
        let segment = parse_segment(&packet).unwrap();
        assert_eq!((segment.seq, segment.ack), (7, 9));
        assert_eq!(segment.window, 1024);
        assert_eq!(segment.mss, Some(1200));
        assert_eq!(segment.payload, b"payload");
        assert_eq!(
            (segment.src, segment.dst, segment.src_port, segment.dst_port),
            (cfg.remote, cfg.local, 80, 40_000)
        );

        let mut corrupt = packet;
        corrupt[20 + 16] ^= 0xff; // TCP checksum
        assert!(parse_segment(&corrupt).is_err());

        // IPv6 uses the same layout with the mandatory checksum.
        let cfg6 = TcpConfig {
            local: "fd00::2".parse().unwrap(),
            remote: "fd00::1".parse().unwrap(),
            ..config()
        };
        let packet = server_packet(&cfg6, 1, 2, FLAG_ACK, 4096, None, b"v6");
        let segment = parse_segment(&packet).unwrap();
        assert_eq!(segment.payload, b"v6");
        assert!(segment.src.is_ipv6());
    }

    #[test]
    fn handshake_and_bidirectional_data() {
        let cfg = config();
        let now = Instant::now();
        let mut conn = established(&cfg, now, 4096, Some(1200));
        assert_eq!(conn.snd_wnd, 4096);
        assert_eq!(conn.snd_mss, 1200);

        assert_eq!(conn.enqueue(b"hello"), 5);
        let data = conn.poll_transmit(now).unwrap();
        let segment = parse_segment(&data).unwrap();
        assert_eq!(segment.flags, FLAG_ACK | FLAG_PSH);
        assert_eq!(segment.seq, 1001);
        assert_eq!(segment.ack, 5001);
        assert_eq!(segment.payload, b"hello");

        // The peer acknowledges the data.
        conn.on_packet(
            &server_packet(&cfg, 5001, 1006, FLAG_ACK, 4096, None, &[]),
            now,
        );
        assert!(conn.unacked.is_empty());
        assert!(conn.failure().is_none());

        // The peer sends data and we acknowledge it.
        conn.on_packet(
            &server_packet(&cfg, 5001, 1006, FLAG_ACK | FLAG_PSH, 4096, None, b"world"),
            now,
        );
        assert_eq!(conn.take_received().unwrap(), b"world");
        let ack = conn.poll_transmit(now).unwrap();
        let segment = parse_segment(&ack).unwrap();
        assert_eq!(segment.flags, FLAG_ACK);
        assert_eq!(segment.ack, 5006);
        assert_eq!(segment.payload, b"");
    }

    #[test]
    fn data_is_clamped_by_the_peer_mss_and_window() {
        let cfg = config();
        let now = Instant::now();
        // A zero receive window keeps the data queued.
        let mut conn = established(&cfg, now, 0, Some(1200));
        assert_eq!(conn.enqueue(&vec![7u8; 3000]), 3000);
        assert!(conn.poll_transmit(now).is_none(), "a zero window must wait");

        // A window update opens it; one segment per poll, bounded by the MSS.
        conn.on_packet(
            &server_packet(&cfg, 5001, 1001, FLAG_ACK, 4096, None, &[]),
            now,
        );
        let first = conn.poll_transmit(now).unwrap();
        let segment = parse_segment(&first).unwrap();
        assert_eq!(segment.payload.len(), 1200);
        let second = conn.poll_transmit(now).unwrap();
        assert_eq!(parse_segment(&second).unwrap().payload.len(), 1200);
        // snd_wnd 4096 - inflight 2400 = 1696 left; the MSS bounds the next.
        let third = conn.poll_transmit(now).unwrap();
        assert_eq!(parse_segment(&third).unwrap().payload.len(), 600);
        // Inflight 3000 < 4096 but the send queue is empty: nothing more.
        assert!(conn.poll_transmit(now).is_none());
    }

    #[test]
    fn a_lost_segment_is_retransmitted_with_backoff() {
        let cfg = config();
        let now = Instant::now();
        let mut conn = established(&cfg, now, 4096, None);
        conn.enqueue(b"lost-data");
        let first = conn.poll_transmit(now).unwrap();
        let segment = parse_segment(&first).unwrap();
        assert_eq!(segment.payload, b"lost-data");

        // The retransmission timer fires; the same bytes go again.
        let deadline = conn.next_timer().expect("RTO timer");
        conn.on_timer(deadline);
        let again = conn.poll_transmit(deadline).unwrap();
        let segment = parse_segment(&again).unwrap();
        assert_eq!(segment.payload, b"lost-data");
        assert_eq!(segment.seq, 1001);
        assert!(conn.rto > INITIAL_RTO, "RTO backs off");

        // After MAX_RETRIES the connection fails with a timeout.
        let mut at = deadline;
        for _ in 0..(MAX_RETRIES + 2) {
            at += Duration::from_secs(10);
            conn.on_timer(at);
            let _ = conn.poll_transmit(at);
            if conn.failure().is_some() {
                break;
            }
        }
        let error = conn.failure().expect("retry exhaustion is an error");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn a_reset_fails_the_connection() {
        let cfg = config();
        let now = Instant::now();
        let mut conn = established(&cfg, now, 4096, None);
        conn.on_packet(
            &server_packet(&cfg, 5001, 1001, FLAG_RST | FLAG_ACK, 0, None, &[]),
            now,
        );
        let error = conn.failure().expect("RST is fatal");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(conn.state(), TcpState::Closed);
        assert!(conn.poll_transmit(now).is_none());
    }

    #[test]
    fn half_close_and_fin_acknowledgement() {
        let cfg = config();
        let now = Instant::now();
        let mut conn = established(&cfg, now, 4096, None);
        conn.shutdown();
        let fin = conn.poll_transmit(now).unwrap();
        let segment = parse_segment(&fin).unwrap();
        assert_eq!(segment.flags, FLAG_FIN | FLAG_ACK);
        assert_eq!(segment.seq, 1001);
        assert_eq!(conn.state(), TcpState::FinWait1);

        // The peer acknowledges the FIN and half-closes too.
        conn.on_packet(
            &server_packet(&cfg, 5001, 1002, FLAG_FIN | FLAG_ACK, 4096, None, &[]),
            now,
        );
        assert!(conn.failure().is_none());
        assert_eq!(conn.state(), TcpState::Closed);
        assert!(conn.finished());
        // The final ACK for the peer's FIN is still sent.
        let last = conn.poll_transmit(now).unwrap();
        assert_eq!(parse_segment(&last).unwrap().flags, FLAG_ACK);
    }

    #[test]
    fn out_of_order_data_is_reordered_before_delivery() {
        let cfg = config();
        let now = Instant::now();
        let mut conn = established(&cfg, now, 4096, None);
        // Gap first: 5006 arrives before 5001.
        conn.on_packet(
            &server_packet(&cfg, 5006, 1001, FLAG_ACK, 4096, None, b"second"),
            now,
        );
        assert!(conn.take_received().is_none(), "the gap is not delivered");
        let ack = conn.poll_transmit(now).unwrap();
        assert_eq!(parse_segment(&ack).unwrap().ack, 5001, "ACK the gap");
        conn.on_packet(
            &server_packet(&cfg, 5001, 1001, FLAG_ACK | FLAG_PSH, 4096, None, b"first"),
            now,
        );
        assert_eq!(conn.take_received().unwrap(), b"first");
        assert_eq!(conn.take_received().unwrap(), b"second");
        assert_eq!(conn.rcv_nxt, 5012);
    }

    #[test]
    fn retransmitted_old_data_is_acknowledged_again() {
        let cfg = config();
        let now = Instant::now();
        let mut conn = established(&cfg, now, 4096, None);
        conn.on_packet(
            &server_packet(&cfg, 5001, 1001, FLAG_ACK, 4096, None, b"abc"),
            now,
        );
        assert_eq!(conn.take_received().unwrap(), b"abc");
        // A duplicate of the same bytes must not be delivered twice.
        conn.on_packet(
            &server_packet(&cfg, 5001, 1001, FLAG_ACK, 4096, None, b"abc"),
            now,
        );
        assert!(conn.take_received().is_none());
        let ack = conn.poll_transmit(now).unwrap();
        assert_eq!(parse_segment(&ack).unwrap().ack, 5004);
    }

    #[test]
    fn a_syn_without_an_answer_times_out() {
        let cfg = TcpConfig {
            connect_deadline: Instant::now() + Duration::from_millis(50),
            ..config()
        };
        let now = Instant::now();
        let mut conn = TcpConnection::new(cfg, now);
        conn.poll_transmit(now).expect("SYN");
        // SYN retransmission uses the RTO; the deadline still bounds it.
        let timer = conn.next_timer().unwrap();
        conn.on_timer(timer);
        let _ = conn.poll_transmit(timer);
        conn.on_timer(cfg.connect_deadline);
        assert_eq!(
            conn.failure().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
    }
}
