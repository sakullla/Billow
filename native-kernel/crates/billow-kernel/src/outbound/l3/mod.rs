//! Shared userspace L3 client stack for the packet-oriented VPN outbounds.
//!
//! WireGuard and OpenVPN produce and consume whole IP packets. This module
//! turns that packet stream into the two surfaces the rest of the kernel
//! needs: an `AsyncRead + AsyncWrite` TCP stream ([`Stack::dial_tcp`]) and an
//! unconnected UDP association ([`Stack::udp_socket`]).
//!
//! Design facts worth keeping in mind:
//!
//! * one stack per proxy-configuration fingerprint, kept in a `Weak` registry
//!   ([`lookup`], [`publish`]) so a stopped proxy leaves nothing behind;
//! * `smoltcp` owns the TCP state machine; the module never reimplements RFC
//!   793;
//! * the carrier is swappable: it pushes received IP packets with
//!   [`Stack::push_rx_packet`] and drains [`Stack::take_tx_packet`]. WireGuard
//!   drives that from tokio tasks, OpenVPN from its blocking data-channel
//!   thread, and the tests from an in-memory peer;
//! * every queue and socket count is bounded and every refusal has a name
//!   ([`StackError`]).
//!
//! What this module does **not** claim: that it makes WireGuard/OpenVPN
//! end-to-end compatible with the pinned device stack (mips/gVisor). It
//! terminates the same IP packets over smoltcp; observed peer tests are
//! recorded separately.

mod device;
mod stack;

pub use device::{
    MemDevice, RX_QUEUE_PACKETS, TX_QUEUE_PACKETS,
};
pub use stack::{
    fingerprint, forget, lookup, publish, registry_lock, L3TcpStream, L3UdpSocket, Stack,
    StackConfig, StackError, IDLE_RECLAIM, TCP_BUFFER_BYTES, TCP_SOCKETS, UDP_PACKET_BYTES,
    UDP_QUEUE_PACKETS, UDP_SOCKETS,
};
