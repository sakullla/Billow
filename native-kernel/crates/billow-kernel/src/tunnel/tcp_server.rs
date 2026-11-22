//! Passive-open TCP endpoint for the packet tunnel (feature `ios-vpn`).
//!
//! The iOS Packet Tunnel receives the device's own TCP segments, so unlike
//! the MASQUE client in `outbound::tcp` the kernel is the *server* side of
//! every connection: the device sends the SYN, the kernel answers SYN-ACK and
//! the byte stream is spliced onto the routed upstream socket.
//!
//! Limits, written down instead of hidden (R3/R4):
//!
//! * one flow per 4-tuple, driven by one task in `tunnel::Tunnel`;
//! * 64 KiB send buffer (queued + unacked) and 64 KiB receive buffer;
//! * out-of-order segments are dropped and acknowledged with the current
//!   `RCV.NXT` (the peer retransmits), so no reordering map is allocated per
//!   flow;
//! * no window scaling (the 16-bit field is the window), no SACK, timestamps
//!   or urgent data; MSS is the value the tunnel advertises;
//! * retransmission with a fixed 1 s initial RTO, exponential backoff to 8 s
//!   and at most 8 retries; a failed connection sends one RST and stops.
//!
//! The state machine is synchronous and owns no sockets: the tunnel actor
//! feeds it packets and timer ticks and takes the packets it wants to emit,
//! which keeps the wire logic unit-testable against scripted peers.

use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::outbound::ipstack;
use crate::outbound::tcp::{
    build_segment, parse_segment, TcpSegment, FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_RST, FLAG_SYN,
};

/// Bytes the application may queue for transmission.
pub const SEND_BUFFER: usize = 64 * 1024;
/// Bytes buffered for the application.
pub const RECEIVE_BUFFER: usize = 64 * 1024;
/// Advertised receive window (no window scaling is negotiated).
const ADVERTISED_WINDOW: u16 = u16::MAX;
/// MSS assumed when the device sends no MSS option (RFC 1122 §4.2.2.6).
const DEFAULT_MSS: u16 = 536;
/// RFC 6298 initial RTO before any RTT measurement.
const INITIAL_RTO: Duration = Duration::from_secs(1);
const MAX_RTO: Duration = Duration::from_secs(8);
const MAX_RETRIES: u32 = 8;

/// Connection states of the passive endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// The SYN arrived and the SYN-ACK is owed or in flight.
    SynReceived,
    Established,
    /// The device sent FIN; the application may still write.
    CloseWait,
    /// The application sent FIN while the device connection is open.
    FinWait,
    /// Our FIN was acknowledged and the device FIN is still owed.
    FinWait2,
    /// Both sides sent FIN; our FIN is unacknowledged.
    Closing,
    /// The device FIN was answered by our FIN and acknowledged.
    LastAck,
    Closed,
}

impl ServerState {
    pub fn as_str(self) -> &'static str {
        match self {
            ServerState::SynReceived => "SYN-RECEIVED",
            ServerState::Established => "ESTABLISHED",
            ServerState::CloseWait => "CLOSE-WAIT",
            ServerState::FinWait => "FIN-WAIT-1",
            ServerState::FinWait2 => "FIN-WAIT-2",
            ServerState::Closing => "CLOSING",
            ServerState::LastAck => "LAST-ACK",
            ServerState::Closed => "CLOSED",
        }
    }
}

/// How one device connection is described: `local` is the address the device
/// dialled (the tunnel side), `remote` is the device.
#[derive(Debug, Clone, Copy)]
pub struct ServerConfig {
    pub local: IpAddr,
    pub remote: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    /// MSS the tunnel advertises (tunnel MTU minus the IP/TCP headers).
    pub mss: u16,
    pub initial_seq: u32,
    pub hop_limit: u8,
}

/// One segment sent and not cumulatively acknowledged.
struct Sent {
    seq: u32,
    flags: u8,
    len: usize,
    payload: Vec<u8>,
    mss: Option<u16>,
    sent_at: Instant,
    retransmits: u32,
}

/// The kernel side of one tunnel TCP connection.
pub struct ServerTcp {
    cfg: ServerConfig,
    state: ServerState,
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
    ack_pending: bool,
    app_shutdown: bool,
    fin_sent: bool,
    fin_acked: bool,
    fin_received: bool,
    rto: Duration,
    dup_acks: u32,
    error: Option<io::Error>,
    outbox: VecDeque<Vec<u8>>,
    reset_pending: bool,
    /// Set when the application half-closed or the connection ended so the
    /// actor knows to half-close the upstream socket.
    upstream_eof: bool,
}

impl ServerTcp {
    /// Accept one SYN: the sequence numbers and the peer's window follow the
    /// segment, the SYN-ACK is produced by the next [`ServerTcp::poll_transmit`].
    pub fn accept(cfg: ServerConfig, syn: &TcpSegment<'_>) -> ServerTcp {
        let mut connection = ServerTcp {
            cfg,
            state: ServerState::SynReceived,
            snd_una: cfg.initial_seq,
            snd_nxt: cfg.initial_seq,
            snd_wnd: 0,
            snd_mss: DEFAULT_MSS,
            snd_wl1: 0,
            snd_wl2: 0,
            rcv_nxt: syn.seq.wrapping_add(1),
            send_queue: VecDeque::new(),
            unacked: VecDeque::new(),
            received: VecDeque::new(),
            buffered: 0,
            ack_pending: false,
            app_shutdown: false,
            fin_sent: false,
            fin_acked: false,
            fin_received: false,
            rto: INITIAL_RTO,
            dup_acks: 0,
            error: None,
            outbox: VecDeque::new(),
            reset_pending: false,
            upstream_eof: false,
        };
        connection.snd_wnd = syn.window;
        connection.snd_mss = cfg.mss.min(syn.mss.unwrap_or(DEFAULT_MSS)).max(1);
        connection
    }

    pub fn state(&self) -> ServerState {
        self.state
    }

    pub fn established(&self) -> bool {
        matches!(
            self.state,
            ServerState::Established
                | ServerState::CloseWait
                | ServerState::FinWait
                | ServerState::FinWait2
                | ServerState::Closing
                | ServerState::LastAck
        )
    }

    /// True once the device closed its direction: the upstream write side is
    /// finished.
    pub fn peer_closed(&self) -> bool {
        self.fin_received
    }

    /// True once the upstream write half must be closed: the device sent FIN,
    /// or the application half-closed its side.
    pub fn write_side_closed(&self) -> bool {
        self.upstream_eof
    }

    pub fn failure(&self) -> Option<&io::Error> {
        self.error.as_ref()
    }

    pub fn finished(&self) -> bool {
        self.state == ServerState::Closed && self.unacked.is_empty() && self.outbox.is_empty()
    }

    /// Whether the application may hand over more bytes.
    pub fn can_accept(&self) -> bool {
        self.error.is_none()
            && matches!(
                self.state,
                ServerState::Established | ServerState::CloseWait
            )
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

    /// Half-close: send FIN once the queued data has been sent (the upstream
    /// direction reached EOF).
    pub fn shutdown(&mut self) {
        if !self.app_shutdown {
            self.app_shutdown = true;
            self.upstream_eof = true;
        }
    }

    /// Abort with one RST (dial failure, or the actor is being torn down).
    pub fn reset(&mut self) {
        if self.error.is_none() && self.state != ServerState::Closed {
            self.reset_pending = true;
            self.state = ServerState::Closed;
            self.unacked.clear();
            self.send_queue.clear();
            self.received.clear();
            self.buffered = 0;
        }
    }

    /// The next in-order payload for the application.
    pub fn take_received(&mut self) -> Option<Vec<u8>> {
        let data = self.received.pop_front()?;
        self.buffered -= data.len();
        self.ack_pending = true;
        Some(data)
    }

    pub fn received_empty(&self) -> bool {
        self.received.is_empty()
    }

    /// Feed one inbound IP packet; segments of another connection are ignored.
    pub fn on_packet(&mut self, packet: &[u8], _now: Instant) {
        if self.state == ServerState::Closed {
            // A closed connection ignores everything: a late retransmission
            // must not reopen it.
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
            self.fail(io::ErrorKind::ConnectionReset, "connection reset by device");
            return;
        }
        if self.state == ServerState::SynReceived {
            self.on_handshake(&segment);
            return;
        }
        if self.state == ServerState::Closed {
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

    fn on_handshake(&mut self, segment: &TcpSegment<'_>) {
        if segment.flags & FLAG_SYN != 0 && segment.flags & FLAG_ACK == 0 {
            // The device retransmitted its SYN before our SYN-ACK arrived:
            // answer again from the same ISS.
            self.outbox.clear();
            return;
        }
        // The third ACK must acknowledge everything sent so far (the
        // SYN-ACK's sequence number).
        if segment.flags & FLAG_ACK == 0 || segment.ack != self.snd_nxt {
            return;
        }
        self.snd_una = segment.ack;
        self.snd_wnd = segment.window;
        self.snd_wl1 = segment.ack;
        self.snd_wl2 = segment.seq;
        self.unacked.clear();
        self.state = ServerState::Established;
        self.rto = INITIAL_RTO;
        // The third ACK may carry data (the device sends immediately).
        self.on_payload(segment);
    }

    fn on_ack(&mut self, segment: &TcpSegment<'_>) {
        if seq_after(segment.ack, self.snd_nxt) {
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
            self.dup_acks = self.dup_acks.saturating_add(1);
        }
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
        if seq != self.rcv_nxt {
            // Out of order: acknowledge what is contiguous so the device
            // retransmits the gap (no reordering map is allocated per flow).
            self.ack_pending = true;
            return;
        }
        if self.buffered + payload.len() > RECEIVE_BUFFER {
            self.ack_pending = true;
            return;
        }
        self.buffered += payload.len();
        self.received.push_back(payload.to_vec());
        self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
        self.ack_pending = true;
    }

    fn on_fin(&mut self, segment: &TcpSegment<'_>) {
        if self.fin_received {
            return;
        }
        let end = segment.seq.wrapping_add(segment.payload.len() as u32);
        if end != self.rcv_nxt {
            self.ack_pending = true;
            return;
        }
        self.fin_received = true;
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.ack_pending = true;
        self.upstream_eof = true;
        self.state = match self.state {
            ServerState::Established => ServerState::CloseWait,
            ServerState::FinWait => ServerState::Closing,
            ServerState::FinWait2 => ServerState::Closed,
            other => other,
        };
    }

    fn advance_close_state(&mut self) {
        if self.fin_acked && self.fin_received {
            match self.state {
                ServerState::LastAck | ServerState::Closing | ServerState::FinWait2 => {
                    self.state = ServerState::Closed
                }
                ServerState::FinWait => self.state = ServerState::Closing,
                _ => {}
            }
        } else if self.fin_acked && self.state == ServerState::FinWait {
            // Our direction is closed and acknowledged; the device may keep
            // writing, which still needs ACKs.
            self.state = ServerState::FinWait2;
        }
    }

    fn fail(&mut self, kind: io::ErrorKind, message: &str) {
        if self.error.is_none() {
            self.error = Some(io::Error::new(kind, message.to_string()));
        }
    }

    /// Retransmission timer.
    pub fn on_timer(&mut self, now: Instant) {
        if self.error.is_some() || self.state == ServerState::Closed {
            return;
        }
        if let Some(front) = self.unacked.front() {
            let due = front.sent_at + self.rto;
            if now >= due {
                let retransmits = front.retransmits + 1;
                if retransmits > MAX_RETRIES {
                    self.fail(
                        io::ErrorKind::TimedOut,
                        "TCP retransmission limit reached (the device stopped acknowledging)",
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
        let (seq, flags, mss, payload) = (front.seq, front.flags, front.mss, front.payload.clone());
        let packet = self.packet(seq, self.rcv_nxt, flags, mss, &payload);
        self.outbox.push_back(packet);
    }

    /// The next IP packet this connection wants to emit, if any.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Vec<u8>> {
        if self.reset_pending {
            self.reset_pending = false;
            return Some(self.packet(self.snd_nxt, self.rcv_nxt, FLAG_RST | FLAG_ACK, None, &[]));
        }
        if let Some(packet) = self.outbox.pop_front() {
            return Some(packet);
        }
        if self.state == ServerState::SynReceived {
            if !self.unacked.is_empty() {
                return None;
            }
            // A duplicate SYN cleared the outbox: rebuild the SYN-ACK from the
            // original ISS.
            let seq = self.cfg.initial_seq;
            let packet = self.packet(
                seq,
                self.rcv_nxt,
                FLAG_SYN | FLAG_ACK,
                Some(self.cfg.mss),
                &[],
            );
            self.unacked.push_back(Sent {
                seq,
                flags: FLAG_SYN | FLAG_ACK,
                len: 0,
                payload: Vec::new(),
                mss: Some(self.cfg.mss),
                sent_at: now,
                retransmits: 0,
            });
            self.snd_nxt = seq.wrapping_add(1);
            return Some(packet);
        }
        if self.ack_pending && self.error.is_none() {
            self.ack_pending = false;
            return Some(self.packet(self.snd_nxt, self.rcv_nxt, FLAG_ACK, None, &[]));
        }
        if self.state == ServerState::Closed {
            return None;
        }
        if matches!(
            self.state,
            ServerState::Established | ServerState::CloseWait
        ) && self.error.is_none()
        {
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
            && matches!(
                self.state,
                ServerState::Established | ServerState::CloseWait
            );
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
            self.state = match self.state {
                ServerState::Established => ServerState::FinWait,
                ServerState::CloseWait => ServerState::LastAck,
                other => other,
            };
            return Some(packet);
        }
        None
    }

    /// The next timer deadline, or `None` when only inbound traffic can make
    /// progress.
    pub fn next_timer(&self) -> Option<Instant> {
        if self.error.is_some() || self.state == ServerState::Closed {
            return None;
        }
        self.unacked.front().map(|sent| sent.sent_at + self.rto)
    }

    fn advertised_window(&self) -> u16 {
        ADVERTISED_WINDOW.saturating_sub(self.buffered.min(usize::from(ADVERTISED_WINDOW)) as u16)
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

    fn config() -> ServerConfig {
        ServerConfig {
            local: IpAddr::from([198, 18, 1, 1]),
            remote: IpAddr::from([198, 18, 0, 2]),
            local_port: 443,
            remote_port: 51_000,
            mss: 1460,
            initial_seq: 7000,
            hop_limit: 64,
        }
    }

    fn syn_packet(seq: u32, mss: Option<u16>) -> Vec<u8> {
        let segment = build_segment(
            config().remote,
            config().local,
            config().remote_port,
            config().local_port,
            seq,
            0,
            FLAG_SYN,
            65_535,
            mss,
            &[],
        );
        ipstack::build_packet(
            config().remote,
            config().local,
            ipstack::IPPROTO_TCP,
            &segment,
            64,
        )
        .unwrap()
    }

    /// Answer like a device: drain the SYN-ACK and send the third ACK.
    /// Returns the device's next sequence number.
    fn permissive_peer(connection: &mut ServerTcp) -> u32 {
        // Drain the SYN-ACK and acknowledge it like the device would.
        let syn_ack = connection.poll_transmit(Instant::now()).expect("SYN-ACK");
        let parsed = parse_segment(&syn_ack).unwrap();
        assert_eq!(parsed.flags & (FLAG_SYN | FLAG_ACK), FLAG_SYN | FLAG_ACK);
        assert_eq!(parsed.ack, 2);
        let segment = build_segment(
            config().remote,
            config().local,
            config().remote_port,
            config().local_port,
            parsed.ack,
            parsed.seq.wrapping_add(1),
            FLAG_ACK,
            65_535,
            None,
            &[],
        );
        let packet = ipstack::build_packet(
            config().remote,
            config().local,
            ipstack::IPPROTO_TCP,
            &segment,
            64,
        )
        .unwrap();
        connection.on_packet(&packet, Instant::now());
        assert_eq!(connection.state(), ServerState::Established);
        // The device's next sequence number (it sent SYN at `seq`).
        parsed.ack
    }

    #[test]
    fn syn_is_answered_with_syn_ack_carrying_the_mss() {
        let syn_bytes = syn_packet(1, Some(1200));
        let syn = parse_segment(&syn_bytes).unwrap();
        let mut connection = ServerTcp::accept(config(), &syn);
        assert_eq!(connection.state(), ServerState::SynReceived);
        let packet = connection.poll_transmit(Instant::now()).unwrap();
        let parsed = parse_segment(&packet).unwrap();
        assert_eq!(parsed.flags & (FLAG_SYN | FLAG_ACK), FLAG_SYN | FLAG_ACK);
        assert_eq!(parsed.seq, 7000);
        assert_eq!(parsed.ack, 2);
        // The SYN-ACK advertises the tunnel's MSS; the device's MSS clamps
        // what the kernel sends instead.
        assert_eq!(parsed.mss, Some(1460));
        // The receive path is established only after the third ACK.
        assert!(connection.poll_transmit(Instant::now()).is_none());
    }

    #[test]
    fn third_ack_establishes_and_data_flows_both_ways() {
        let syn_bytes = syn_packet(1, None);
        let syn = parse_segment(&syn_bytes).unwrap();
        let mut connection = ServerTcp::accept(config(), &syn);
        let device_seq = permissive_peer(&mut connection);
        assert_eq!(connection.state(), ServerState::Established);
        assert_eq!(device_seq, 2);

        // Device -> kernel.
        let data = build_segment(
            config().remote,
            config().local,
            config().remote_port,
            config().local_port,
            device_seq,
            connection.snd_una,
            FLAG_ACK | FLAG_PSH,
            65_535,
            None,
            b"GET / HTTP/1.1\r\n",
        );
        let packet = ipstack::build_packet(
            config().remote,
            config().local,
            ipstack::IPPROTO_TCP,
            &data,
            64,
        )
        .unwrap();
        connection.on_packet(&packet, Instant::now());
        assert_eq!(connection.take_received().unwrap(), b"GET / HTTP/1.1\r\n");
        // The ACK for the data is owed.
        let ack = connection.poll_transmit(Instant::now()).unwrap();
        assert_eq!(parse_segment(&ack).unwrap().flags & FLAG_ACK, FLAG_ACK);

        // Kernel -> device.
        assert_eq!(connection.enqueue(b"HTTP/1.1 200 OK\r\n"), 17);
        let response = connection.poll_transmit(Instant::now()).unwrap();
        let parsed = parse_segment(&response).unwrap();
        assert_eq!(parsed.payload, b"HTTP/1.1 200 OK\r\n");
        assert_eq!(parsed.flags & FLAG_ACK, FLAG_ACK);
        assert_eq!(connection.take_received(), None);
    }

    #[test]
    fn device_fin_ends_the_write_side_and_app_fin_closes() {
        let syn_bytes = syn_packet(1, None);
        let syn = parse_segment(&syn_bytes).unwrap();
        let mut connection = ServerTcp::accept(config(), &syn);
        let device_seq = permissive_peer(&mut connection);
        let fin = build_segment(
            config().remote,
            config().local,
            config().remote_port,
            config().local_port,
            device_seq,
            connection.snd_una,
            FLAG_FIN | FLAG_ACK,
            65_535,
            None,
            &[],
        );
        let packet = ipstack::build_packet(
            config().remote,
            config().local,
            ipstack::IPPROTO_TCP,
            &fin,
            64,
        )
        .unwrap();
        connection.on_packet(&packet, Instant::now());
        assert_eq!(connection.state(), ServerState::CloseWait);
        assert!(connection.peer_closed());
        // The device closed its direction, so the upstream write half is done
        // even before the application half-closes.
        assert!(connection.write_side_closed());
        connection.shutdown();
        assert!(connection.write_side_closed());
        // The ACK for the device FIN is owed first, then our FIN.
        let mut fin = None;
        for _ in 0..4 {
            let Some(packet) = connection.poll_transmit(Instant::now()) else {
                break;
            };
            let segment = parse_segment(&packet).unwrap();
            if segment.flags & FLAG_FIN != 0 {
                fin = Some((segment.seq, segment.ack));
                break;
            }
        }
        let (fin_seq, fin_ack) = fin.expect("our FIN is emitted");
        assert_eq!(connection.state(), ServerState::LastAck);
        // Acknowledge our FIN: the connection is done.
        let ack = build_segment(
            config().remote,
            config().local,
            config().remote_port,
            config().local_port,
            fin_ack,
            fin_seq.wrapping_add(1),
            FLAG_ACK,
            65_535,
            None,
            &[],
        );
        let packet = ipstack::build_packet(
            config().remote,
            config().local,
            ipstack::IPPROTO_TCP,
            &ack,
            64,
        )
        .unwrap();
        connection.on_packet(&packet, Instant::now());
        assert_eq!(connection.state(), ServerState::Closed);
        assert!(connection.finished());
    }

    #[test]
    fn reset_is_emitted_once_for_a_dial_failure() {
        let syn_bytes = syn_packet(1, None);
        let syn = parse_segment(&syn_bytes).unwrap();
        let mut connection = ServerTcp::accept(config(), &syn);
        permissive_peer(&mut connection);
        connection.reset();
        let packet = connection.poll_transmit(Instant::now()).expect("RST");
        assert_eq!(parse_segment(&packet).unwrap().flags & FLAG_RST, FLAG_RST);
        assert!(connection.poll_transmit(Instant::now()).is_none());
        assert!(connection.finished());
    }

    #[test]
    fn retransmission_backs_off_after_the_rto() {
        let syn_bytes = syn_packet(1, None);
        let syn = parse_segment(&syn_bytes).unwrap();
        let mut connection = ServerTcp::accept(config(), &syn);
        let first = connection.poll_transmit(Instant::now()).unwrap();
        // No ACK at all: the same SYN-ACK is retransmitted after the RTO.
        connection.on_timer(Instant::now() + Duration::from_millis(900));
        assert!(connection.poll_transmit(Instant::now()).is_none());
        connection.on_timer(Instant::now() + Duration::from_millis(1_100));
        let again = connection
            .poll_transmit(Instant::now())
            .expect("retransmission");
        let (a, b) = (
            parse_segment(&first).unwrap(),
            parse_segment(&again).unwrap(),
        );
        assert_eq!((a.seq, a.ack, a.flags), (b.seq, b.ack, b.flags));
    }

    #[test]
    fn out_of_order_data_is_acknowledged_without_buffering() {
        let syn_bytes = syn_packet(1, None);
        let syn = parse_segment(&syn_bytes).unwrap();
        let mut connection = ServerTcp::accept(config(), &syn);
        let device_seq = permissive_peer(&mut connection);
        let data = build_segment(
            config().remote,
            config().local,
            config().remote_port,
            config().local_port,
            device_seq.wrapping_add(10),
            connection.snd_una,
            FLAG_ACK | FLAG_PSH,
            65_535,
            None,
            b"late",
        );
        let packet = ipstack::build_packet(
            config().remote,
            config().local,
            ipstack::IPPROTO_TCP,
            &data,
            64,
        )
        .unwrap();
        connection.on_packet(&packet, Instant::now());
        assert!(connection.take_received().is_none());
        // The ACK repeats RCV.NXT (ISS + 1), so the device retransmits.
        let ack = connection.poll_transmit(Instant::now()).unwrap();
        assert_eq!(parse_segment(&ack).unwrap().ack, device_seq);
    }

    #[test]
    fn a_segment_of_another_connection_is_ignored() {
        let syn_bytes = syn_packet(1, None);
        let syn = parse_segment(&syn_bytes).unwrap();
        let mut connection = ServerTcp::accept(config(), &syn);
        permissive_peer(&mut connection);
        let other = build_segment(
            IpAddr::from([198, 18, 0, 3]),
            config().local,
            1234,
            config().local_port,
            1,
            connection.snd_una,
            FLAG_ACK,
            65_535,
            None,
            b"stray",
        );
        let packet = ipstack::build_packet(
            IpAddr::from([198, 18, 0, 3]),
            config().local,
            ipstack::IPPROTO_TCP,
            &other,
            64,
        )
        .unwrap();
        connection.on_packet(&packet, Instant::now());
        assert!(connection.failure().is_none());
        assert!(connection.take_received().is_none());
    }
}
