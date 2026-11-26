//! mKCP (`transport/mkcp`, the KCP transport used by VMess `network: mkcp`).
//!
//! Each UDP datagram carries exactly one KCP segment. The segment stream is
//! optionally prefixed with a camouflage header (`srtp`, `utp`, `wechat-video`,
//! `dtls`, `wireguard`) and authenticated with either the pinned
//! `simpleAuthenticator` (FNV-1a checksum + length, no key) or, when `seed` is
//! set, AES-128-GCM keyed by `SHA-256(seed)[..16]`.
//!
//! The state machine is a direct translation of the pinned `conn.go` subset a
//! client needs: the send window with retransmission, ACK assembly, receive
//! reordering, the ping/terminate commands and the RTT estimator. Congestion
//! control follows the pinned `congestion` flag. The worker thread owns the
//! blocking UDP socket; the async stream exchanges buffers with it over
//! unbounded channels.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::proxies::MkcpOptions;

/// The packet transport under KCP. mKCP uses a connected UDP socket; mekya
/// uses HTTP/2 bundles over a TLS connection. `recv` returns
/// `WouldBlock` on its short poll timeout so the worker can still flush.
pub trait PacketIo: Send {
    fn send(&mut self, packet: &[u8]) -> io::Result<()>;
    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
}

struct UdpIo {
    socket: UdpSocket,
}

impl PacketIo for UdpIo {
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.socket.send(packet).map(|_| ())
    }

    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buffer)
    }
}

const DATA_OVERHEAD: usize = 18;
const COMMAND_ACK: u8 = 0;
const COMMAND_DATA: u8 = 1;
const COMMAND_TERMINATE: u8 = 2;
const COMMAND_PING: u8 = 3;
const OPTION_CLOSE: u8 = 1;

/// The runtime knobs `MkcpOptions` resolves to (pinned `Config` defaults).
#[derive(Debug, Clone)]
struct Config {
    mtu: u32,
    tti: u32,
    uplink_capacity: u32,
    downlink_capacity: u32,
    congestion: bool,
    write_buffer: u32,
}

impl Config {
    fn new(options: &MkcpOptions) -> Config {
        Config {
            mtu: if options.mtu == 0 { 1350 } else { options.mtu },
            tti: if options.tti == 0 { 50 } else { options.tti },
            uplink_capacity: if options.uplink_capacity == 0 {
                5
            } else {
                options.uplink_capacity
            },
            downlink_capacity: if options.downlink_capacity == 0 {
                20
            } else {
                options.downlink_capacity
            },
            congestion: options.congestion,
            write_buffer: if options.write_buffer == 0 {
                2 * 1024 * 1024
            } else {
                options.write_buffer
            },
        }
    }

    fn sending_in_flight(&self) -> u32 {
        (self.uplink_capacity * 1024 * 1024 / self.mtu / (1000 / self.tti)).max(8)
    }

    fn receiving_in_flight(&self) -> u32 {
        (self.downlink_capacity * 1024 * 1024 / self.mtu / (1000 / self.tti)).max(8)
    }

    fn sending_buffer(&self) -> u32 {
        self.write_buffer / self.mtu
    }
}

/// Packet-level header of the pinned `header.go`.
#[derive(Debug, Clone)]
enum Header {
    None,
    Srtp { number: u16 },
    Utp { connection: u16 },
    Wechat { sequence: u32 },
    Dtls { epoch: u16, length: u16, sequence: u32 },
    Wireguard,
}

impl Header {
    fn new(name: &str) -> Header {
        let mut random = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut random);
        let value = u16::from_be_bytes([random[0], random[1]]);
        match name.to_ascii_lowercase().as_str() {
            "srtp" => Header::Srtp { number: value },
            "utp" => Header::Utp { connection: value },
            "wechat-video" | "wechat" => Header::Wechat {
                sequence: u32::from(value),
            },
            "dtls" => Header::Dtls {
                epoch: value,
                length: 17,
                sequence: 0,
            },
            "wireguard" => Header::Wireguard,
            _ => Header::None,
        }
    }

    fn size(&self) -> usize {
        match self {
            Header::None => 0,
            Header::Srtp { .. } | Header::Utp { .. } | Header::Wireguard => 4,
            Header::Wechat { .. } | Header::Dtls { .. } => 13,
        }
    }

    fn serialize(&mut self, out: &mut Vec<u8>) {
        match self {
            Header::None => {}
            Header::Srtp { number } => {
                *number = number.wrapping_add(1);
                out.extend_from_slice(&0xb5e8u16.to_be_bytes());
                out.extend_from_slice(&number.to_be_bytes());
            }
            Header::Utp { connection } => {
                out.extend_from_slice(&connection.to_be_bytes());
                out.push(1);
                out.push(0);
            }
            Header::Wechat { sequence } => {
                *sequence = sequence.wrapping_add(1);
                out.push(0xa1);
                out.push(0x08);
                out.extend_from_slice(&sequence.to_be_bytes());
                out.extend_from_slice(&[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
            }
            Header::Dtls {
                epoch,
                length,
                sequence,
            } => {
                out.push(23);
                out.push(254);
                out.push(253);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.push(0);
                out.push(0);
                out.extend_from_slice(&sequence.to_be_bytes());
                *sequence = sequence.wrapping_add(1);
                out.extend_from_slice(&length.to_be_bytes());
                *length = length.wrapping_add(17);
                if *length > 100 {
                    *length = length.wrapping_sub(50);
                }
            }
            Header::Wireguard => out.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]),
        }
    }
}

/// The pinned `simpleAuthenticator` or seed-derived AES-128-GCM.
#[derive(Clone)]
enum Security {
    Simple,
    AesGcm(Box<Aes128Gcm>),
}

impl Security {
    fn new(seed: &str) -> Security {
        if seed.is_empty() {
            return Security::Simple;
        }
        let digest = Sha256::digest(seed.as_bytes());
        let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&digest[..16]);
        Security::AesGcm(Box::new(Aes128Gcm::new(key)))
    }

    fn overhead(&self) -> usize {
        match self {
            Security::Simple => 6,
            Security::AesGcm(_) => 16,
        }
    }

    fn seal(&self, payload: &[u8]) -> Vec<u8> {
        match self {
            Security::Simple => {
                let mut out = Vec::with_capacity(6 + payload.len());
                out.extend_from_slice(&[0, 0, 0, 0]);
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
                let checksum = fnv1a32(&out[4..]);
                out[..4].copy_from_slice(&checksum.to_be_bytes());
                // The pinned writer pads to a 4-byte boundary for the XOR
                // chain but returns the unpadded length.
                let dst_len = out.len();
                let padding = 4 - dst_len % 4;
                if padding != 4 {
                    out.resize(dst_len + padding, 0);
                    xorfwd(&mut out);
                    out.truncate(dst_len);
                } else {
                    xorfwd(&mut out);
                }
                out
            }
            Security::AesGcm(gcm) => {
                let mut nonce = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce);
                let sealed = gcm
                    .encrypt(Nonce::from_slice(&nonce), Payload { msg: payload, aad: &[] })
                    .expect("AES-GCM encryption cannot fail for a valid key");
                let mut out = Vec::with_capacity(12 + sealed.len());
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&sealed);
                out
            }
        }
    }

    fn open(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        match self {
            Security::Simple => {
                let mut data = ciphertext.to_vec();
                let dst_len = data.len();
                let padding = 4 - dst_len % 4;
                if padding != 4 {
                    data.resize(dst_len + padding, 0);
                    xorbkd(&mut data);
                    data.truncate(dst_len);
                } else {
                    xorbkd(&mut data);
                }
                if data.len() < 6 {
                    return None;
                }
                let checksum = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                if checksum != fnv1a32(&data[4..]) {
                    return None;
                }
                let length = u16::from_be_bytes([data[4], data[5]]) as usize;
                if data.len() - 6 != length {
                    return None;
                }
                Some(data[6..].to_vec())
            }
            Security::AesGcm(gcm) => {
                if ciphertext.len() < 12 + 16 {
                    return None;
                }
                gcm.decrypt(
                    Nonce::from_slice(&ciphertext[..12]),
                    Payload {
                        msg: &ciphertext[12..],
                        aad: &[],
                    },
                )
                .ok()
            }
        }
    }
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in data {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn xorfwd(data: &mut [u8]) {
    for index in 4..data.len() {
        data[index] ^= data[index - 4];
    }
}

fn xorbkd(data: &mut [u8]) {
    for index in (4..data.len()).rev() {
        data[index] ^= data[index - 4];
    }
}

#[derive(Debug, Clone)]
struct DataSegment {
    conv: u16,
    option: u8,
    timestamp: u32,
    number: u32,
    sending_next: u32,
    payload: Vec<u8>,
    timeout: u32,
    transmit: u32,
}

#[derive(Debug, Clone)]
struct AckSegment {
    conv: u16,
    option: u8,
    receiving_window: u32,
    receiving_next: u32,
    timestamp: u32,
    numbers: Vec<u32>,
}

#[derive(Debug, Clone)]
struct CmdSegment {
    conv: u16,
    cmd: u8,
    option: u8,
    sending_next: u32,
    receiving_next: u32,
    peer_rto: u32,
}

#[derive(Debug, Clone)]
enum Segment {
    Data(DataSegment),
    Ack(AckSegment),
    Cmd(CmdSegment),
}

fn read_segments(mut data: &[u8]) -> Vec<Segment> {
    let mut out = Vec::new();
    while data.len() >= 4 {
        let conv = u16::from_be_bytes([data[0], data[1]]);
        let command = data[2];
        let option = data[3];
        data = &data[4..];
        match command {
            COMMAND_DATA => {
                if data.len() < 14 {
                    break;
                }
                let length =
                    u16::from_be_bytes([data[12], data[13]]) as usize;
                if data.len() < 14 + length {
                    break;
                }
                out.push(Segment::Data(DataSegment {
                    conv,
                    option,
                    timestamp: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                    number: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                    sending_next: u32::from_be_bytes([
                        data[8], data[9], data[10], data[11],
                    ]),
                    payload: data[14..14 + length].to_vec(),
                    timeout: 0,
                    transmit: 0,
                }));
                data = &data[14 + length..];
            }
            COMMAND_ACK => {
                if data.len() < 13 {
                    break;
                }
                let count = data[12] as usize;
                if data.len() < 13 + count * 4 {
                    break;
                }
                let mut numbers = Vec::with_capacity(count);
                for index in 0..count {
                    let at = 13 + index * 4;
                    numbers.push(u32::from_be_bytes([
                        data[at],
                        data[at + 1],
                        data[at + 2],
                        data[at + 3],
                    ]));
                }
                out.push(Segment::Ack(AckSegment {
                    conv,
                    option,
                    receiving_window: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                    receiving_next: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                    timestamp: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
                    numbers,
                }));
                data = &data[13 + count * 4..];
            }
            _ => {
                if data.len() < 12 {
                    break;
                }
                out.push(Segment::Cmd(CmdSegment {
                    conv,
                    cmd: command,
                    option,
                    sending_next: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                    receiving_next: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                    peer_rto: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
                }));
                data = &data[12..];
            }
        }
    }
    out
}

fn serialize(segment: &Segment) -> Vec<u8> {
    match segment {
        Segment::Data(data) => {
            let mut out = Vec::with_capacity(18 + data.payload.len());
            out.extend_from_slice(&data.conv.to_be_bytes());
            out.extend_from_slice(&[COMMAND_DATA, data.option]);
            out.extend_from_slice(&data.timestamp.to_be_bytes());
            out.extend_from_slice(&data.number.to_be_bytes());
            out.extend_from_slice(&data.sending_next.to_be_bytes());
            out.extend_from_slice(&(data.payload.len() as u16).to_be_bytes());
            out.extend_from_slice(&data.payload);
            out
        }
        Segment::Ack(ack) => {
            let mut out = Vec::with_capacity(17 + ack.numbers.len() * 4);
            out.extend_from_slice(&ack.conv.to_be_bytes());
            out.extend_from_slice(&[COMMAND_ACK, ack.option]);
            out.extend_from_slice(&ack.receiving_window.to_be_bytes());
            out.extend_from_slice(&ack.receiving_next.to_be_bytes());
            out.extend_from_slice(&ack.timestamp.to_be_bytes());
            out.push(ack.numbers.len() as u8);
            for number in &ack.numbers {
                out.extend_from_slice(&number.to_be_bytes());
            }
            out
        }
        Segment::Cmd(cmd) => {
            let mut out = Vec::with_capacity(16);
            out.extend_from_slice(&cmd.conv.to_be_bytes());
            out.extend_from_slice(&[cmd.cmd, cmd.option]);
            out.extend_from_slice(&cmd.sending_next.to_be_bytes());
            out.extend_from_slice(&cmd.receiving_next.to_be_bytes());
            out.extend_from_slice(&cmd.peer_rto.to_be_bytes());
            out
        }
    }
}

#[derive(Debug)]
struct AckItem {
    number: u32,
    timestamp: u32,
    next_flush: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Active,
    ReadyToClose,
    PeerClosed,
    Terminating,
    PeerTerminating,
    Terminated,
}

enum Outgoing {
    Data(Vec<u8>),
    Close,
}

struct Worker {
    io: Box<dyn PacketIo>,
    cfg: Config,
    conv: u16,
    created: Instant,
    header: Header,
    security: Security,

    send_window: Vec<DataSegment>,
    send_next: u32,
    first_unacked: u32,
    remote_recv_win: u32,
    total_in_flight: u32,
    control_window: u32,
    first_unacked_updated: bool,

    recv_cache: HashMap<u32, Vec<u8>>,
    recv_next: u32,
    ack_list: Vec<AckItem>,
    ack_dirty: bool,

    rto: u32,
    srtt: u32,
    rtt_variation: u32,
    min_rtt: u32,
    rto_updated: u32,

    state: State,
    state_begin: u32,
    last_incoming: u32,
    last_ping: u32,
}

impl Worker {
    fn elapsed(&self) -> u32 {
        self.created.elapsed().as_millis() as u32
    }

    fn set_state(&mut self, state: State) {
        if self.state == state {
            return;
        }
        self.state = state;
        self.state_begin = self.elapsed();
        if matches!(
            state,
            State::ReadyToClose
                | State::PeerClosed
                | State::Terminating
                | State::PeerTerminating
                | State::Terminated
        ) {
            if matches!(
                state,
                State::PeerClosed | State::Terminating | State::PeerTerminating | State::Terminated
            ) {
                self.send_window.clear();
            }
        }
    }

    fn input(&mut self, segments: Vec<Segment>, incoming: &mpsc::UnboundedSender<Vec<u8>>) {
        if segments.is_empty() || self.state == State::Terminated {
            return;
        }
        let current = self.elapsed();
        self.last_incoming = current;
        for segment in segments {
            let conv = match &segment {
                Segment::Data(data) => data.conv,
                Segment::Ack(ack) => ack.conv,
                Segment::Cmd(cmd) => cmd.conv,
            };
            if conv != self.conv {
                break;
            }
            match segment {
                Segment::Data(data) => {
                    self.handle_option(data.option);
                    self.process_sending_next(data.sending_next);
                    let index = data.number.wrapping_sub(self.recv_next);
                    if index < self.cfg.receiving_in_flight() {
                        self.ack_list.push(AckItem {
                            number: data.number,
                            timestamp: data.timestamp,
                            next_flush: 0,
                        });
                        self.ack_dirty = true;
                        self.recv_cache.entry(data.number).or_insert(data.payload);
                    }
                    self.deliver(incoming);
                }
                Segment::Ack(ack) => {
                    self.handle_option(ack.option);
                    if ack.receiving_window > self.remote_recv_win {
                        self.remote_recv_win = ack.receiving_window;
                    }
                    self.process_receiving_next(ack.receiving_next);
                    if ack.numbers.is_empty() {
                        continue;
                    }
                    let mut max_ack = 0;
                    let mut max_removed = false;
                    for number in ack.numbers {
                        let removed = self.process_ack(number);
                        if max_ack < number {
                            max_ack = number;
                            max_removed = removed;
                        }
                    }
                    if max_removed && current.wrapping_sub(ack.timestamp) < 10_000 {
                        self.update_rtt(current.wrapping_sub(ack.timestamp));
                    }
                }
                Segment::Cmd(cmd) => {
                    self.handle_option(cmd.option);
                    if cmd.cmd == COMMAND_TERMINATE {
                        match self.state {
                            State::Active | State::PeerClosed => {
                                self.set_state(State::PeerTerminating)
                            }
                            State::ReadyToClose => self.set_state(State::Terminating),
                            State::Terminating => self.set_state(State::Terminated),
                            _ => {}
                        }
                    }
                    self.process_receiving_next(cmd.receiving_next);
                    self.process_sending_next(cmd.sending_next);
                    self.update_peer_rto(cmd.peer_rto);
                }
            }
        }
    }

    fn handle_option(&mut self, option: u8) {
        if option & OPTION_CLOSE != 0 {
            match self.state {
                State::ReadyToClose => self.set_state(State::Terminating),
                State::Active => self.set_state(State::PeerClosed),
                _ => {}
            }
        }
    }

    fn deliver(&mut self, incoming: &mpsc::UnboundedSender<Vec<u8>>) {
        while let Some(payload) = self.recv_cache.remove(&self.recv_next) {
            self.recv_next = self.recv_next.wrapping_add(1);
            if incoming.send(payload).is_err() {
                self.set_state(State::Terminated);
                return;
            }
        }
    }

    fn process_sending_next(&mut self, next: u32) {
        if !self.ack_list.is_empty() {
            self.ack_list.retain(|ack| ack.number >= next);
        }
    }

    fn process_receiving_next(&mut self, next: u32) {
        self.send_window.retain(|segment| segment.number >= next);
        self.first_unacked = self
            .send_window
            .first()
            .map(|segment| segment.number)
            .unwrap_or(self.send_next);
    }

    fn process_ack(&mut self, number: u32) -> bool {
        if number.wrapping_sub(self.first_unacked) > 0x7fff_ffff
            || number.wrapping_sub(self.send_next) < 0x7fff_ffff
        {
            return false;
        }
        if let Some(index) = self.send_window.iter().position(|segment| segment.number == number) {
            self.send_window.remove(index);
            self.total_in_flight = self.total_in_flight.saturating_sub(1);
            self.first_unacked = self
                .send_window
                .first()
                .map(|segment| segment.number)
                .unwrap_or(self.send_next);
            return true;
        }
        false
    }

    fn update_rtt(&mut self, rtt: u32) {
        if rtt > 0x7fff_ffff {
            return;
        }
        if self.srtt == 0 {
            self.srtt = rtt;
            self.rtt_variation = rtt / 2;
        } else {
            let delta = if self.srtt > rtt {
                self.srtt - rtt
            } else {
                rtt - self.srtt
            };
            self.rtt_variation = (3 * self.rtt_variation + delta) / 4;
            self.srtt = (7 * self.srtt + rtt) / 8;
            if self.srtt < self.min_rtt {
                self.srtt = self.min_rtt;
            }
        }
        let rto = if self.min_rtt < 4 * self.rtt_variation {
            self.srtt + 4 * self.rtt_variation
        } else {
            self.srtt + self.rtt_variation
        };
        self.rto = rto.min(10_000) * 5 / 4;
        self.rto_updated = self.elapsed();
    }

    fn update_peer_rto(&mut self, rto: u32) {
        let current = self.elapsed();
        if rto == 0 || current.wrapping_sub(self.rto_updated) < 3_000 {
            return;
        }
        self.rto_updated = current;
        self.rto = rto;
    }

    fn flush(&mut self) {
        let current = self.elapsed();
        if self.state == State::Terminated {
            return;
        }
        if self.state == State::Active && current.wrapping_sub(self.last_incoming) >= 30_000 {
            self.set_state(State::ReadyToClose);
        }
        if self.state == State::ReadyToClose && self.send_window.is_empty() {
            self.set_state(State::Terminating);
        }
        if self.state == State::Terminating {
            let segment = self.ping(COMMAND_TERMINATE, current);
            self.write(segment);
            if current.wrapping_sub(self.state_begin) > 8_000 {
                self.set_state(State::Terminated);
            }
            return;
        }
        if self.state == State::PeerTerminating && current.wrapping_sub(self.state_begin) > 4_000 {
            self.set_state(State::Terminating);
        }
        if self.state == State::ReadyToClose && current.wrapping_sub(self.state_begin) > 15_000 {
            self.set_state(State::Terminating);
        }
        let mut segments = self.flush_acks(current);
        segments.extend(self.flush_send(current));
        if current.wrapping_sub(self.last_ping) >= 3_000 {
            segments.push(self.ping(COMMAND_PING, current));
        }
        for segment in segments {
            self.write(segment);
        }
    }

    fn flush_acks(&mut self, current: u32) -> Vec<Segment> {
        if self.ack_list.is_empty() {
            return Vec::new();
        }
        let mut segments = Vec::new();
        let mut ack = self.new_ack();
        for index in 0..self.ack_list.len() {
            let item = &mut self.ack_list[index];
            if item.next_flush > current {
                continue;
            }
            ack.numbers.push(item.number);
            if item.timestamp.wrapping_sub(ack.timestamp) < 0x7fff_ffff {
                ack.timestamp = item.timestamp;
            }
            item.next_flush = current + (self.rto / 2).max(20);
            if ack.numbers.len() == 128 {
                segments.push(Segment::Ack(ack));
                ack = self.new_ack();
                self.ack_dirty = false;
            }
        }
        if self.ack_dirty || !ack.numbers.is_empty() {
            segments.push(Segment::Ack(ack));
            self.ack_dirty = false;
        }
        segments
    }

    fn flush_send(&mut self, current: u32) -> Vec<Segment> {
        if self.send_window.is_empty() {
            if self.first_unacked_updated {
                self.first_unacked_updated = false;
                return vec![self.ping(COMMAND_PING, current)];
            }
            return Vec::new();
        }
        let mut cwnd = self.cfg.sending_in_flight();
        let remote = self.remote_recv_win.wrapping_sub(self.first_unacked);
        if cwnd > remote {
            cwnd = remote;
        }
        if self.cfg.congestion && cwnd > self.control_window {
            cwnd = self.control_window;
        }
        let cwnd = cwnd.saturating_mul(20).max(1);

        let mut lost = 0u32;
        let mut in_flight = 0u32;
        let mut segments = Vec::new();
        for segment in &mut self.send_window {
            // `current - timeout` wraps when the timeout is in the future.
            if current.wrapping_sub(segment.timeout) >= 0x7fff_ffff {
                continue;
            }
            if segment.transmit == 0 {
                self.total_in_flight += 1;
            } else {
                lost += 1;
            }
            segment.timestamp = current;
            segment.sending_next = self.first_unacked;
            segment.option = if self.state == State::ReadyToClose {
                OPTION_CLOSE
            } else {
                0
            };
            segment.transmit += 1;
            segment.timeout = current + self.rto.max(self.cfg.tti);
            segments.push(Segment::Data(segment.clone()));
            in_flight += 1;
            if in_flight >= cwnd {
                break;
            }
        }
        if self.cfg.congestion && in_flight > 0 && self.total_in_flight != 0 {
            let rate = lost * 100 / self.total_in_flight;
            self.on_packet_loss(rate);
        }
        self.first_unacked_updated = false;
        segments
    }

    fn on_packet_loss(&mut self, rate: u32) {
        if rate >= 15 {
            self.control_window = 3 * self.control_window / 4;
        } else if rate <= 5 {
            self.control_window += self.control_window / 4;
        }
        self.control_window = self.control_window.max(16);
        self.control_window = self
            .control_window
            .min(2 * self.cfg.sending_in_flight());
    }

    fn new_ack(&self) -> AckSegment {
        AckSegment {
            conv: self.conv,
            option: if self.state == State::ReadyToClose {
                OPTION_CLOSE
            } else {
                0
            },
            receiving_window: self.recv_next.wrapping_add(self.cfg.receiving_in_flight()),
            receiving_next: self.recv_next,
            timestamp: 0,
            numbers: Vec::new(),
        }
    }

    fn ping(&mut self, cmd: u8, current: u32) -> Segment {
        self.last_ping = current;
        Segment::Cmd(CmdSegment {
            conv: self.conv,
            cmd,
            option: if self.state == State::ReadyToClose {
                OPTION_CLOSE
            } else {
                0
            },
            sending_next: self.first_unacked,
            receiving_next: self.recv_next,
            peer_rto: self.rto,
        })
    }

    fn write(&mut self, segment: Segment) {
        let payload = serialize(&segment);
        let mut packet = Vec::with_capacity(self.header.size() + self.security.overhead() + payload.len());
        self.header.serialize(&mut packet);
        let sealed = self.security.seal(&payload);
        packet.extend_from_slice(&sealed);
        let _ = self.io.send(&packet);
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<Vec<Segment>>> {
        let read = self.io.recv(buffer)?;
        let mut data = &buffer[..read];
        if data.len() <= self.header.size() {
            return Ok(None);
        }
        data = &data[self.header.size()..];
        let Some(plain) = self.security.open(data) else {
            return Ok(None);
        };
        let segments = read_segments(&plain);
        if segments.is_empty() {
            return Ok(None);
        }
        Ok(Some(segments))
    }
}

/// The async handle over the worker thread.
struct MkcpStream {
    outgoing: mpsc::UnboundedSender<Outgoing>,
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    buffered: Vec<u8>,
    at: usize,
    closed: Arc<AtomicBool>,
}

impl AsyncRead for MkcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.at < self.buffered.len() {
                let take = (self.buffered.len() - self.at).min(buf.remaining());
                buf.put_slice(&self.buffered[self.at..self.at + take]);
                self.at += take;
                if self.at == self.buffered.len() {
                    self.buffered.clear();
                    self.at = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match self.incoming.poll_recv(cx) {
                Poll::Ready(Some(payload)) => {
                    self.buffered = payload;
                    self.at = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MkcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        if self
            .outgoing
            .send(Outgoing::Data(buf.to_vec()))
            .is_err()
        {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let _ = self.outgoing.send(Outgoing::Close);
        Poll::Ready(Ok(()))
    }
}

/// Dial a mKCP stream to `address` (`server:port` already resolved by the
/// caller or resolved here).
pub async fn connect(
    address: &str,
    port: u16,
    options: &MkcpOptions,
) -> io::Result<super::BoxStream> {
    let target = super::resolve(address, port)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    let socket = super::udp_socket_std_blocking(
        if target.is_ipv4() {
            "0.0.0.0:0".parse().expect("literal")
        } else {
            "[::]:0".parse().expect("literal")
        },
        &crate::proxies::DialerOptions::default(),
    )?;
    socket.connect(target)?;
    socket.set_read_timeout(Some(Duration::from_millis(50)))?;
    connect_packet_io(Box::new(UdpIo { socket }), options)
}

/// Run KCP over an already-established packet transport (mekya's HTTP/2
/// request bundles). The transport's `recv` must poll with a short timeout.
pub fn connect_packet_io(
    io: Box<dyn PacketIo>,
    options: &MkcpOptions,
) -> io::Result<super::BoxStream> {
    let cfg = Config::new(options);
    let mss = (cfg.mtu as usize)
        .saturating_sub(Security::new(&options.seed).overhead() + Header::new(&options.header).size())
        .saturating_sub(DATA_OVERHEAD)
        .max(576);
    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();
    let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
    let closed = Arc::new(AtomicBool::new(false));
    let closed_thread = closed.clone();
    let seed = options.seed.clone();
    let header = options.header.clone();
    let cfg_thread = cfg.clone();
    std::thread::Builder::new()
        .name("billow-mkcp".to_string())
        .spawn(move || {
            let mut random = [0u8; 2];
            rand::thread_rng().fill_bytes(&mut random);
            let conv = u16::from_be_bytes(random);
            let mut worker = Worker {
                io,
                cfg: cfg_thread,
                conv,
                created: Instant::now(),
                header: Header::new(&header),
                security: Security::new(&seed),
                send_window: Vec::new(),
                send_next: 0,
                first_unacked: 0,
                remote_recv_win: 32,
                total_in_flight: 0,
                control_window: cfg.sending_in_flight(),
                first_unacked_updated: false,
                recv_cache: HashMap::new(),
                recv_next: 0,
                ack_list: Vec::new(),
                ack_dirty: false,
                rto: 100,
                srtt: 0,
                rtt_variation: 0,
                min_rtt: cfg.tti,
                rto_updated: 0,
                state: State::Active,
                state_begin: 0,
                last_incoming: 0,
                last_ping: 0,
            };
            let mut buffer = vec![0u8; 64 * 1024];
            let mut queue: Vec<u8> = Vec::new();
            let mut next_flush = Instant::now();
            'outer: loop {
                if closed_thread.load(Ordering::Relaxed) {
                    break;
                }
                // Drain queued application writes.
                loop {
                    match outgoing_rx.try_recv() {
                        Ok(Outgoing::Data(data)) => queue.extend_from_slice(&data),
                        Ok(Outgoing::Close) => {
                            worker.set_state(State::ReadyToClose);
                        }
                        Err(_) => break,
                    }
                }
                while !queue.is_empty() {
                    if worker.send_window.len() as u32 >= cfg.sending_buffer().max(1) {
                        break;
                    }
                    let take = queue.len().min(mss);
                    let payload: Vec<u8> = queue.drain(..take).collect();
                    worker.send_window.push(DataSegment {
                        conv: worker.conv,
                        option: 0,
                        timestamp: 0,
                        number: worker.send_next,
                        sending_next: worker.first_unacked,
                        payload,
                        timeout: 0,
                        transmit: 0,
                    });
                    worker.send_next = worker.send_next.wrapping_add(1);
                }
                if Instant::now() >= next_flush {
                    worker.flush();
                    next_flush = Instant::now() + Duration::from_millis(u64::from(cfg.tti));
                }
                match worker.receive(&mut buffer) {
                    Ok(Some(segments)) => {
                        worker.input(segments, &incoming_tx);
                        worker.flush();
                    }
                    Ok(None) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
                if worker.state == State::Terminated {
                    break;
                }
                if incoming_tx.is_closed() {
                    break 'outer;
                }
                // Avoid a busy spin when the socket read times out: the loop
                // is paced by the 50 ms socket timeout.
            }
            closed_thread.store(true, Ordering::Relaxed);
        })
        .map_err(|error| io::Error::other(format!("mkcp worker: {error}")))?;
    Ok(Box::new(MkcpStream {
        outgoing: outgoing_tx,
        incoming: incoming_rx,
        buffered: Vec::new(),
        at: 0,
        closed,
    }))
}

/// Expose the resolved server address type for callers that need it.
pub type MkcpTarget = SocketAddr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_sizes_and_wireguard_layout_match_the_pinned_header() {
        assert_eq!(Header::new("none").size(), 0);
        assert_eq!(Header::new("srtp").size(), 4);
        assert_eq!(Header::new("utp").size(), 4);
        assert_eq!(Header::new("wechat-video").size(), 13);
        assert_eq!(Header::new("dtls").size(), 13);
        let mut header = Header::new("wireguard");
        let mut out = Vec::new();
        header.serialize(&mut out);
        assert_eq!(out, vec![4, 0, 0, 0]);
    }

    #[test]
    fn simple_authenticator_round_trips_and_pads_without_changing_the_length() {
        let security = Security::Simple;
        for length in [0usize, 1, 3, 4, 5, 4096] {
            let payload: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let sealed = security.seal(&payload);
            assert_eq!(sealed.len(), length + 6);
            assert_eq!(security.open(&sealed).unwrap(), payload);
        }
    }

    #[test]
    fn segment_round_trip_carries_all_fields() {
        let segment = Segment::Data(DataSegment {
            conv: 0x1234,
            option: 1,
            timestamp: 7,
            number: 9,
            sending_next: 11,
            payload: b"hello".to_vec(),
            timeout: 0,
            transmit: 0,
        });
        let bytes = serialize(&segment);
        let parsed = read_segments(&bytes);
        match &parsed[0] {
            Segment::Data(data) => {
                assert_eq!(data.timestamp, 7);
                assert_eq!(data.number, 9);
                assert_eq!(data.sending_next, 11);
                assert_eq!(data.payload, b"hello");
            }
            other => panic!("expected data, got {other:?}"),
        }
    }
}
