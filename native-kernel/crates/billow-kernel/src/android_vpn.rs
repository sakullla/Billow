//! Android VpnService data plane (feature `android-vpn`).
//!
//! Android's `VpnService.Builder.establish()` returns a `ParcelFileDescriptor`
//! that carries whole IP packets. The VpnService lives in the Billow host
//! process; the Rust kernel runs as its own process next to it (the same
//! packaging model as Mihomo). The host clears `FD_CLOEXEC` on the TUN fd and
//! passes its number as `--tun-fd <fd>`; this module owns that inherited fd and
//! pumps packets in both directions:
//!
//! * a reader thread polls the fd, reads one IP packet at a time and feeds
//!   [`Tunnel::ingest`] (the shared T7 userspace IP stack: TCP passive open,
//!   UDP associations, DNS hijack, rules/groups/outbounds);
//! * a bounded writer queue receives the packets [`Tunnel`] emits and a writer
//!   thread writes them back to the fd. A full queue is a counted drop, never
//!   an unbounded buffer.
//!
//! `start_at` owns the fd: `stop()` (also on `Drop`) joins both threads, closes
//! the fd and stops the tunnel, so switching back to Mihomo or losing the VPN
//! revoke leaves no descriptor or flow behind.
//!
//! The C ABI below (`billow_android_vpn_*`) is the in-process embed point for a
//! host that links this crate directly instead of spawning the CLI. It has the
//! same ownership rule: a successful `start` takes the fd.

use std::ffi::{c_char, c_void, CStr, CString};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::identity::Identity;
use crate::tunnel::stage::stage_config;
use crate::tunnel::{PacketSink, Tunnel, TunnelOptions, TunnelStats};

/// The kernel version prefix the host and the settings card report.
pub const VERSION_PREFIX: &str = "billow-rust";

/// How long the reader/writer threads sleep between stop checks.
const POLL_TIMEOUT: Duration = Duration::from_millis(200);
/// Largest IP packet a TUN read may return (IPv4/IPv6 headers included).
const MAX_PACKET: usize = 65_535;

/// Tunables of the Android data plane.
#[derive(Debug, Clone)]
pub struct AndroidVpnOptions {
    /// The shared T7 data-plane options.
    pub tunnel: TunnelOptions,
    /// Emitted packets held before the TUN writer drops them.
    pub egress_queue: usize,
}

impl Default for AndroidVpnOptions {
    fn default() -> Self {
        AndroidVpnOptions {
            tunnel: TunnelOptions::default(),
            egress_queue: 256,
        }
    }
}

/// File-descriptor counters in addition to the tunnel counters.
#[derive(Debug, Default)]
struct FdCounters {
    reads: AtomicU64,
    written: AtomicU64,
    dropped: AtomicU64,
    read_errors: AtomicU64,
    write_errors: AtomicU64,
}

/// One point-in-time copy of the fd side, printed by the stats ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidFdStats {
    pub reads: u64,
    pub written: u64,
    pub dropped: u64,
    pub read_errors: u64,
    pub write_errors: u64,
}

/// The tunnel counters plus the fd counters and the running flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidVpnStats {
    pub tunnel: TunnelStats,
    pub fd: AndroidFdStats,
    pub running: bool,
}

/// Egress through the bounded writer queue.
struct FdSink {
    tx: SyncSender<Vec<u8>>,
    counters: Arc<FdCounters>,
}

impl PacketSink for FdSink {
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

/// A running Android data plane.
pub struct AndroidVpn {
    tunnel: Arc<Tunnel>,
    fd: RawFd,
    stop_flag: Arc<AtomicBool>,
    counters: Arc<FdCounters>,
    reader: Mutex<Option<std::thread::JoinHandle<()>>>,
    writer: Mutex<Option<std::thread::JoinHandle<()>>>,
    stopped: Mutex<bool>,
}

impl AndroidVpn {
    /// Stages `config_yaml` for the Rust engine (a `tun`/`sniffer` block with
    /// `enable: true` is removed; the fd is a launch argument, never a YAML
    /// key) and starts the pump from the staged file.
    pub fn start(
        fd: RawFd,
        config_yaml: &str,
        base_dir: std::path::PathBuf,
        options: AndroidVpnOptions,
    ) -> Result<AndroidVpn, String> {
        validate_fd(fd)?;
        let staged = stage_config(&base_dir, config_yaml)?;
        Self::start_at(fd, &staged.yaml, staged.path, base_dir, options)
    }

    /// Starts the engine and the fd pump. A successful call owns `fd`; the
    /// caller must not read, write or close it afterwards. A failed call
    /// leaves the descriptor open and owned by the caller (this function never
    /// closes it on failure), so the caller closes it exactly once.
    pub fn start_at(
        fd: RawFd,
        config_yaml: &str,
        config_path: std::path::PathBuf,
        base_dir: std::path::PathBuf,
        options: AndroidVpnOptions,
    ) -> Result<AndroidVpn, String> {
        validate_fd(fd)?;
        let counters = Arc::new(FdCounters::default());
        let (tx, rx) = sync_channel::<Vec<u8>>(options.egress_queue.max(1));
        let sink = Arc::new(FdSink {
            tx,
            counters: counters.clone(),
        });
        let tunnel = Arc::new(Tunnel::start_at(
            config_yaml,
            config_path,
            base_dir,
            options.tunnel,
            Some(sink as Arc<dyn PacketSink>),
        )?);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let reader = {
            let stop = stop_flag.clone();
            let counters = counters.clone();
            let tunnel = tunnel.clone();
            std::thread::Builder::new()
                .name("billow-tun-read".to_string())
                .spawn(move || reader_loop(fd, stop, counters, tunnel))
        };
        let reader = match reader {
            Ok(handle) => handle,
            Err(error) => {
                // A failed start leaves the descriptor with the caller (see
                // `start_at`); closing it here would double-close the host's fd.
                tunnel.stop();
                return Err(format!("android-vpn: reader thread: {error}"));
            }
        };
        let writer = {
            let stop = stop_flag.clone();
            let counters = counters.clone();
            std::thread::Builder::new()
                .name("billow-tun-write".to_string())
                .spawn(move || writer_loop(fd, stop, counters, rx))
        };
        let writer = match writer {
            Ok(handle) => handle,
            Err(error) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = reader.join();
                tunnel.stop();
                // Same ownership rule: the caller still owns `fd` after a
                // failed start and closes it exactly once.
                return Err(format!("android-vpn: writer thread: {error}"));
            }
        };
        Ok(AndroidVpn {
            tunnel,
            fd,
            stop_flag,
            counters,
            reader: Mutex::new(Some(reader)),
            writer: Mutex::new(Some(writer)),
            stopped: Mutex::new(false),
        })
    }

    /// Engine identity of the running generation.
    pub fn identity(&self) -> Option<Identity> {
        self.tunnel.identity()
    }

    /// Tunnel and fd counters.
    pub fn stats(&self) -> AndroidVpnStats {
        let counters = &self.counters;
        AndroidVpnStats {
            tunnel: self.tunnel.stats(),
            fd: AndroidFdStats {
                reads: counters.reads.load(Ordering::Relaxed),
                written: counters.written.load(Ordering::Relaxed),
                dropped: counters.dropped.load(Ordering::Relaxed),
                read_errors: counters.read_errors.load(Ordering::Relaxed),
                write_errors: counters.write_errors.load(Ordering::Relaxed),
            },
            running: !self.stop_flag.load(Ordering::SeqCst),
        }
    }

    /// Reloads the same configuration file, closing every flow on success.
    pub fn reload(&self) -> Result<Vec<String>, String> {
        self.tunnel.reload()
    }

    /// Stops both threads, the tunnel and closes the fd. Idempotent; `Drop`
    /// calls it, so a panic before an explicit stop still releases the fd.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        {
            let mut stopped = self
                .stopped
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if *stopped {
                return;
            }
            *stopped = true;
        }
        if let Some(handle) = self
            .reader
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = handle.join();
        }
        if let Some(handle) = self
            .writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = handle.join();
        }
        self.tunnel.stop();
        // The fd is ours after `start_at`; close it last so neither thread can
        // observe a reused descriptor.
        unsafe { libc::close(self.fd) };
    }
}

impl Drop for AndroidVpn {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Rejects a negative or closed descriptor before any thread touches it.
fn validate_fd(fd: RawFd) -> Result<(), String> {
    if fd < 0 {
        return Err(format!("android-vpn: invalid TUN fd {fd}"));
    }
    // A closed or non-descriptor number must fail here, before any thread
    // reads from it.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(format!(
            "android-vpn: TUN fd {fd} is not open: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn reader_loop(fd: RawFd, stop: Arc<AtomicBool>, counters: Arc<FdCounters>, tunnel: Arc<Tunnel>) {
    let mut buffer = vec![0u8; MAX_PACKET];
    while !stop.load(Ordering::SeqCst) {
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, POLL_TIMEOUT.as_millis() as i32) };
        if ready < 0 {
            if interrupted() {
                continue;
            }
            counters.read_errors.fetch_add(1, Ordering::Relaxed);
            break;
        }
        if ready == 0 {
            continue;
        }
        if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            // A revoked VPN or a closed fd: stop reading and let `stop` close.
            break;
        }
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut c_void, buffer.len()) };
        if read > 0 {
            counters.reads.fetch_add(1, Ordering::Relaxed);
            let _ = tunnel.ingest(&buffer[..read as usize]);
        } else if read == 0 {
            // The peer (the VpnService side) closed the descriptor.
            break;
        } else if !interrupted() && !would_block() {
            counters.read_errors.fetch_add(1, Ordering::Relaxed);
            break;
        }
    }
    // A revoked VPN or a hard read error ends the pump; the writer must not
    // keep draining packets into a descriptor the host is releasing.
    stop.store(true, Ordering::SeqCst);
}

fn writer_loop(fd: RawFd, stop: Arc<AtomicBool>, counters: Arc<FdCounters>, rx: Receiver<Vec<u8>>) {
    while !stop.load(Ordering::SeqCst) {
        match rx.recv_timeout(POLL_TIMEOUT) {
            Ok(packet) => {
                if write_packet(fd, &packet, &stop, &counters) {
                    counters.written.fetch_add(1, Ordering::Relaxed);
                } else {
                    // `stop` was requested or the descriptor failed; either way
                    // the writer must not keep draining the queue.
                    stop.store(true, Ordering::SeqCst);
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// Writes one whole packet. Retries `EINTR`/`EAGAIN`; a short write of a
/// packet-oriented fd is a counted failure instead of a silently split packet.
fn write_packet(fd: RawFd, packet: &[u8], stop: &AtomicBool, counters: &FdCounters) -> bool {
    loop {
        if stop.load(Ordering::SeqCst) {
            return false;
        }
        let written = unsafe { libc::write(fd, packet.as_ptr() as *const c_void, packet.len()) };
        if written == packet.len() as isize {
            return true;
        }
        if written < 0 && interrupted() {
            continue;
        }
        if written < 0 && would_block() {
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let _ = unsafe { libc::poll(&mut poll, 1, POLL_TIMEOUT.as_millis() as i32) };
            continue;
        }
        counters.write_errors.fetch_add(1, Ordering::Relaxed);
        return false;
    }
}

fn interrupted() -> bool {
    std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
}

fn would_block() -> bool {
    let error = std::io::Error::last_os_error();
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) || error.raw_os_error() == Some(libc::EAGAIN)
}

/// One running data plane and the home it was staged from, reachable from the
/// C ABI.
struct Running {
    vpn: AndroidVpn,
    home: std::path::PathBuf,
}

/// One running data plane, reachable from the C ABI.
fn state() -> &'static Mutex<Option<Running>> {
    static STATE: OnceLock<Mutex<Option<Running>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

fn lock() -> std::sync::MutexGuard<'static, Option<Running>> {
    state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// `malloc` an error string; the caller frees it (`free`).
unsafe fn set_error(error: *mut *mut c_char, message: &str) {
    if error.is_null() {
        return;
    }
    let text = CString::new(message.replace('\0', " ")).unwrap_or_default();
    let bytes = text.as_bytes_with_nul();
    let buffer = libc::malloc(bytes.len()) as *mut c_char;
    if buffer.is_null() {
        *error = std::ptr::null_mut();
        return;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buffer, bytes.len());
    *error = buffer;
}

/// `int32_t billow_android_vpn_start(int32_t fd, const char *home, char **error)`.
///
/// Reads `<home>/config.yaml`, stages it for the Rust engine and starts the
/// fd pump. A successful call owns `fd`. On failure the caller still owns and
/// closes `fd` (this entry point never closes it), and a `malloc`'d `*error`
/// explains the rejection. Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn billow_android_vpn_start(
    fd: i32,
    home: *const c_char,
    error: *mut *mut c_char,
) -> i32 {
    if !error.is_null() {
        *error = std::ptr::null_mut();
    }
    if home.is_null() {
        set_error(error, "billow_android_vpn_start: home is null");
        return 2;
    }
    let home = match CStr::from_ptr(home).to_str() {
        Ok(text) => std::path::PathBuf::from(text),
        Err(_) => {
            set_error(error, "billow_android_vpn_start: home is not UTF-8");
            return 2;
        }
    };
    // Stop a previous generation outside the global lock (stop joins threads).
    let previous = lock().take();
    if let Some(previous) = previous {
        previous.vpn.stop();
    }
    let config_path = home.join("config.yaml");
    let yaml = match std::fs::read_to_string(&config_path) {
        Ok(yaml) => yaml,
        Err(read_error) => {
            set_error(
                error,
                &format!(
                    "billow_android_vpn_start: read {}: {read_error}",
                    config_path.display()
                ),
            );
            return 1;
        }
    };
    let start_home = home.clone();
    match AndroidVpn::start(fd, &yaml, start_home, AndroidVpnOptions::default()) {
        Ok(vpn) => {
            *lock() = Some(Running { vpn, home });
            0
        }
        Err(message) => {
            set_error(error, &format!("billow_android_vpn_start: {message}"));
            1
        }
    }
}

/// `void billow_android_vpn_stop(void)`: stops the pump and the engine and
/// closes the fd.
#[no_mangle]
pub extern "C" fn billow_android_vpn_stop() {
    let previous = lock().take();
    if let Some(previous) = previous {
        previous.vpn.stop();
    }
}

/// `int32_t billow_android_vpn_reload(char **error)`.
#[no_mangle]
pub unsafe extern "C" fn billow_android_vpn_reload(error: *mut *mut c_char) -> i32 {
    if !error.is_null() {
        *error = std::ptr::null_mut();
    }
    let running = {
        let guard = lock();
        guard
            .as_ref()
            .map(|running| (running.home.clone(), running.vpn.tunnel.clone()))
    };
    let Some((home, tunnel)) = running else {
        set_error(error, "billow_android_vpn_reload: no tunnel is running");
        return -1;
    };
    // The host may have edited the shared config.yaml while this session
    // stayed alive: restage before pointing the reload at the staged file.
    let config_path = home.join("config.yaml");
    let yaml = match std::fs::read_to_string(&config_path) {
        Ok(yaml) => yaml,
        Err(read_error) => {
            set_error(
                error,
                &format!(
                    "billow_android_vpn_reload: read {}: {read_error}",
                    config_path.display()
                ),
            );
            return 1;
        }
    };
    if let Err(message) = stage_config(&home, &yaml) {
        set_error(error, &format!("billow_android_vpn_reload: {message}"));
        return 1;
    }
    match tunnel.reload() {
        Ok(warnings) => {
            for warning in &warnings {
                tracing::warn!(warning, "reload warning");
            }
            0
        }
        Err(message) => {
            set_error(error, &format!("billow_android_vpn_reload: {message}"));
            1
        }
    }
}

/// `int32_t billow_android_vpn_stats(char *buf, int32_t size)`: one JSON object
/// with the tunnel, fd and process counters. Returns the length, or the
/// required length when the buffer is too small.
#[no_mangle]
pub unsafe extern "C" fn billow_android_vpn_stats(buf: *mut c_char, size: i32) -> i32 {
    let json = stats_json();
    let bytes = json.as_bytes();
    if buf.is_null() || size <= 0 {
        return bytes.len() as i32;
    }
    if bytes.len() + 1 > size as usize {
        return (bytes.len() + 1) as i32;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, bytes.len());
    *buf.add(bytes.len()) = 0;
    bytes.len() as i32
}

fn stats_json() -> String {
    let stats = lock().as_ref().map(|running| running.vpn.stats());
    let peak = peak_rss_bytes();
    match stats {
        Some(stats) => {
            let tunnel = &stats.tunnel;
            format!(
                concat!(
                    "{{\"running\":{},\"version\":\"{} {}\",",
                    "\"generation\":{},\"reloads\":{},\"peakRssBytes\":{},",
                    "\"inPackets\":{},\"inBytes\":{},\"outPackets\":{},\"outBytes\":{},",
                    "\"tcpOpened\":{},\"tcpClosed\":{},\"tcpRejected\":{},\"tcpFlows\":{},",
                    "\"tcpFlowHigh\":{},\"udpDatagrams\":{},\"udpReplies\":{},\"udpFlows\":{},",
                    "\"udpFlowHigh\":{},\"dnsQueries\":{},\"dnsFailures\":{},",
                    "\"invalidPackets\":{},\"fragments\":{},\"unsupportedProtocols\":{},",
                    "\"icmpDropped\":{},\"droppedInbound\":{},\"droppedEgress\":{},",
                    "\"queueHigh\":{},\"queuedPackets\":{},",
                    "\"fdReads\":{},\"fdWritten\":{},\"fdDropped\":{},\"fdReadErrors\":{},",
                    "\"fdWriteErrors\":{}}}"
                ),
                stats.running,
                VERSION_PREFIX,
                crate::engine::VERSION,
                tunnel.generation,
                tunnel.reloads,
                peak,
                tunnel.in_packets,
                tunnel.in_bytes,
                tunnel.out_packets,
                tunnel.out_bytes,
                tunnel.tcp_opened,
                tunnel.tcp_closed,
                tunnel.tcp_rejected,
                tunnel.tcp_flows,
                tunnel.tcp_flow_high,
                tunnel.udp_datagrams,
                tunnel.udp_replies,
                tunnel.udp_flows,
                tunnel.udp_flow_high,
                tunnel.dns_queries,
                tunnel.dns_failures,
                tunnel.invalid_packets,
                tunnel.fragments,
                tunnel.unsupported_protocols,
                tunnel.icmp_dropped,
                tunnel.dropped_inbound,
                tunnel.dropped_egress,
                tunnel.queue_high,
                tunnel.queued_packets,
                stats.fd.reads,
                stats.fd.written,
                stats.fd.dropped,
                stats.fd.read_errors,
                stats.fd.write_errors,
            )
        }
        None => format!(
            "{{\"running\":false,\"version\":\"{} {}\",\"peakRssBytes\":{}}}",
            VERSION_PREFIX,
            crate::engine::VERSION,
            peak
        ),
    }
}

/// Peak resident set size of this process in bytes (`ru_maxrss` is bytes on
/// Darwin and KiB on Linux; the value is reported in bytes here).
fn peak_rss_bytes() -> u64 {
    #[cfg(unix)]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        if rc == 0 {
            let usage = unsafe { usage.assume_init() };
            #[cfg(target_os = "linux")]
            {
                return usage.ru_maxrss.max(0) as u64 * 1024;
            }
            #[cfg(not(target_os = "linux"))]
            {
                return usage.ru_maxrss.max(0) as u64;
            }
        }
    }
    0
}

/// `void billow_android_vpn_free_error(char *error)`.
#[no_mangle]
pub unsafe extern "C" fn billow_android_vpn_free_error(error: *mut c_char) {
    if !error.is_null() {
        libc::free(error as *mut c_void);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_without_a_tunnel_report_the_process_and_not_running() {
        let mut buffer = vec![0i8; 512];
        let length = unsafe { billow_android_vpn_stats(buffer.as_mut_ptr(), 512) };
        assert!(length > 0);
        let text = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_str().unwrap();
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(value["running"], serde_json::Value::Bool(false));
        assert!(text.contains("peakRssBytes"));
        // No fd counters exist without a running pump.
        assert!(value.get("fdReads").is_none());
    }

    #[test]
    fn start_with_a_null_home_reports_an_error_and_stop_is_safe() {
        let mut error: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { billow_android_vpn_start(3, std::ptr::null(), &mut error) };
        assert_eq!(rc, 2);
        assert!(!error.is_null());
        unsafe { billow_android_vpn_free_error(error) };
        billow_android_vpn_stop();
    }
}
