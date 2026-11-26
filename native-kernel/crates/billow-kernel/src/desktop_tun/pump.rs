//! Bidirectional IP packet pump between a TUN device and the userspace stack.
//!
//! A reader thread polls the device, hands each IP packet to
//! [`Tunnel::ingest`] and counts what it dropped. A writer thread drains a
//! **bounded** queue fed by [`PacketSink::emit`], so a slow device drops
//! packets (counted) instead of growing memory (R3/R4). This is the same shape
//! Android's inherited-fd pump uses; both entries share it.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use super::device::{TunDevice, MAX_PACKET};
use crate::tunnel::{PacketSink, Tunnel};

/// How long the reader/writer sleep between stop checks.
pub const POLL_TIMEOUT: Duration = Duration::from_millis(200);

/// Device-side counters in addition to the tunnel counters.
#[derive(Debug, Default)]
pub struct PumpCounters {
    reads: AtomicU64,
    written: AtomicU64,
    dropped: AtomicU64,
    read_errors: AtomicU64,
    write_errors: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PumpStats {
    pub reads: u64,
    pub written: u64,
    pub dropped: u64,
    pub read_errors: u64,
    pub write_errors: u64,
}

struct DeviceSink {
    tx: SyncSender<Vec<u8>>,
    counters: Arc<PumpCounters>,
}

impl PacketSink for DeviceSink {
    fn emit(&self, packet: &[u8]) -> bool {
        if packet.is_empty() {
            return false;
        }
        match self.tx.try_send(packet.to_vec()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

/// A running reader/writer pair.
pub struct Pump {
    stop: Arc<AtomicBool>,
    counters: Arc<PumpCounters>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
}

impl Pump {
    /// Start the pump around `tunnel`. The device must stay alive for the
    /// returned pump (the caller owns the `Arc`).
    pub fn start(
        tunnel: Arc<Tunnel>,
        device: Arc<dyn TunDevice>,
        egress_queue: usize,
    ) -> Result<Pump, String> {
        let counters = Arc::new(PumpCounters::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = sync_channel::<Vec<u8>>(egress_queue.max(1));
        let sink = Arc::new(DeviceSink {
            tx,
            counters: counters.clone(),
        });
        tunnel.set_sink(sink as Arc<dyn PacketSink>);

        let reader = {
            let stop = stop.clone();
            let counters = counters.clone();
            let tunnel = tunnel.clone();
            let device = device.clone();
            std::thread::Builder::new()
                .name("billow-tun-read".to_string())
                .spawn(move || reader_loop(device, stop, counters, tunnel))
        };
        let reader = match reader {
            Ok(handle) => handle,
            Err(error) => return Err(format!("desktop-tun: reader thread: {error}")),
        };
        let writer = {
            let stop = stop.clone();
            let counters = counters.clone();
            let device = device.clone();
            std::thread::Builder::new()
                .name("billow-tun-write".to_string())
                .spawn(move || writer_loop(device, stop, counters, rx))
        };
        let writer = match writer {
            Ok(handle) => handle,
            Err(error) => {
                stop.store(true, Ordering::SeqCst);
                let _ = reader.join();
                return Err(format!("desktop-tun: writer thread: {error}"));
            }
        };
        Ok(Pump {
            stop,
            counters,
            reader: Some(reader),
            writer: Some(writer),
        })
    }

    pub fn stats(&self) -> PumpStats {
        let counters = &self.counters;
        PumpStats {
            reads: counters.reads.load(Ordering::Relaxed),
            written: counters.written.load(Ordering::Relaxed),
            dropped: counters.dropped.load(Ordering::Relaxed),
            read_errors: counters.read_errors.load(Ordering::Relaxed),
            write_errors: counters.write_errors.load(Ordering::Relaxed),
        }
    }

    /// False when a device read/write failed and the pump stopped itself.
    pub fn running(&self) -> bool {
        !self.stop.load(Ordering::SeqCst)
    }

    /// Join both threads. Idempotent; `Drop` calls it.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.writer.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Pump {
    fn drop(&mut self) {
        self.stop();
    }
}

fn reader_loop(
    device: Arc<dyn TunDevice>,
    stop: Arc<AtomicBool>,
    counters: Arc<PumpCounters>,
    tunnel: Arc<Tunnel>,
) {
    // Room for the utun header even on raw devices.
    let mut buffer = vec![0u8; MAX_PACKET + super::framing::UTUN_HEADER];
    while !stop.load(Ordering::SeqCst) {
        match device.read_packet(&mut buffer) {
            Ok(Some(read)) => {
                counters.reads.fetch_add(1, Ordering::Relaxed);
                let _ = tunnel.ingest(&buffer[..read]);
            }
            Ok(None) => std::thread::sleep(POLL_TIMEOUT),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                std::thread::sleep(POLL_TIMEOUT);
            }
            Err(error) => {
                counters.read_errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%error, "desktop TUN read failed; stopping the pump");
                break;
            }
        }
    }
    // A hard read error means the device is gone; the writer must not keep
    // draining packets into it.
    stop.store(true, Ordering::SeqCst);
}

fn writer_loop(
    device: Arc<dyn TunDevice>,
    stop: Arc<AtomicBool>,
    counters: Arc<PumpCounters>,
    rx: Receiver<Vec<u8>>,
) {
    while !stop.load(Ordering::SeqCst) {
        match rx.recv_timeout(POLL_TIMEOUT) {
            Ok(packet) => match device.write_packet(&packet) {
                Ok(()) => {
                    counters.written.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    counters.write_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%error, "desktop TUN write failed; stopping the pump");
                    stop.store(true, Ordering::SeqCst);
                    break;
                }
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}
