//! Bounded in-memory `smoltcp` device.
//!
//! The carrier (a WireGuard session, an OpenVPN data channel, or a test
//! fixture) owns the real transport. It hands received IP packets to
//! [`MemDevice::push_rx`] and drains the packets smoltcp produced with
//! [`MemDevice::pop_tx`]. Both directions are bounded queues: a full queue is
//! reported (and counted), never grown without a limit.

use std::collections::VecDeque;

use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

/// RX packets that may wait for one `poll` without being dropped.
pub const RX_QUEUE_PACKETS: usize = 256;
/// TX packets a poll may produce before the carrier has drained them. The
/// interface stops transmitting when this is full, so TCP retries instead of
/// silently losing segments.
pub const TX_QUEUE_PACKETS: usize = 256;

/// One IP-packet device with bounded RX/TX queues.
pub struct MemDevice {
    mtu: usize,
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    rx_limit: usize,
    tx_limit: usize,
    dropped_rx: u64,
    dropped_tx: u64,
}

impl MemDevice {
    pub fn new(mtu: usize) -> MemDevice {
        MemDevice {
            mtu: mtu.clamp(68, 65535),
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            rx_limit: RX_QUEUE_PACKETS,
            tx_limit: TX_QUEUE_PACKETS,
            dropped_rx: 0,
            dropped_tx: 0,
        }
    }

    /// Queue one received packet. Returns `false` (and counts the drop) when
    /// the RX queue is full or the packet exceeds the MTU.
    pub fn push_rx(&mut self, packet: &[u8]) -> bool {
        if packet.is_empty() || packet.len() > self.mtu || self.rx.len() >= self.rx_limit {
            self.dropped_rx += 1;
            return false;
        }
        self.rx.push_back(packet.to_vec());
        true
    }

    /// Take one packet smoltcp produced.
    pub fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }

    pub fn has_tx(&self) -> bool {
        !self.tx.is_empty()
    }

    pub fn tx_len(&self) -> usize {
        self.tx.len()
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Packets dropped because a queue was full (RX at ingress, TX at egress).
    pub fn dropped(&self) -> (u64, u64) {
        (self.dropped_rx, self.dropped_tx)
    }
}

impl Device for MemDevice {
    type RxToken<'a> = MemRxToken;
    type TxToken<'a> = MemTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        let tx = MemTxToken {
            queue: &mut self.tx,
            limit: self.tx_limit,
            dropped: &mut self.dropped_tx,
        };
        Some((MemRxToken { packet }, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.tx.len() >= self.tx_limit {
            // Stop the egress loop; smoltcp retries after the carrier drains.
            return None;
        }
        Some(MemTxToken {
            queue: &mut self.tx,
            limit: self.tx_limit,
            dropped: &mut self.dropped_tx,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        // One packet per poll keeps the queue accounting simple: smoltcp asks
        // `transmit` again on the next iteration when it has more to send.
        capabilities.max_burst_size = Some(1);
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }
}

pub struct MemRxToken {
    packet: Vec<u8>,
}

impl RxToken for MemRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = self.packet;
        f(&mut packet)
    }
}

pub struct MemTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    limit: usize,
    dropped: &'a mut u64,
}

impl TxToken for MemTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        if self.queue.len() >= self.limit {
            *self.dropped += 1;
        } else {
            self.queue.push_back(packet);
        }
        result
    }
}
