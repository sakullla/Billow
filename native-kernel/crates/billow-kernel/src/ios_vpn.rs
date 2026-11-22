//! C ABI of the iOS Packet Tunnel (feature `ios-vpn`).
//!
//! The contract is `src-tauri/gen/apple/network-extension/RustExtension/include/billow_ios_vpn.h`;
//! this module is the implementation the header refers to. It is compiled only
//! with `--features ios-vpn`, so desktop and Android builds neither compile
//! the tunnel nor export these symbols.
//!
//! Ownership rules (all of them are in the header):
//! * `start` failure: `*error` is a `malloc` string the caller frees with
//!   `billow_ios_vpn_free_error` (which is `free`);
//! * `drain`: the caller's buffer is only borrowed for the call;
//! * `write`: the packet bytes are copied before the call returns;
//! * `port->write`: called synchronously from a tunnel thread with a packet
//!   that is valid only for the call (the Swift side copies it into
//!   `packetFlow.writePackets`);
//! * `stop`: after it returns no callback or buffer from earlier calls may be
//!   used.

use std::ffi::{c_char, c_void, CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::tunnel::{PacketSink, Tunnel, TunnelOptions};

/// The kernel version string the extension reports (`billow-rust 0.1.0`).
pub const VERSION_PREFIX: &str = "billow-rust";

/// Mirrors `rust_tunnel_port_t` in `billow_ios_vpn.h`.
#[repr(C)]
pub struct RustTunnelPort {
    pub start: Option<unsafe extern "C" fn(*mut c_void, *const c_char) -> i32>,
    pub write: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, u32) -> i64>,
    pub stop: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// Egress through the extension's `port->write` (packetFlow.writePackets).
struct CallbackSink {
    ctx: *mut c_void,
    write: unsafe extern "C" fn(*mut c_void, *mut c_void, u32) -> i64,
}

// The context is the Swift `NEPacketTunnelProvider` (kept alive by the
// extension for the lifetime of the tunnel) and `packetFlow.writePackets` is
// documented as callable from any thread. The tunnel never keeps a packet
// pointer past the call, which is the contract in `billow_ios_vpn.h`.
unsafe impl Send for CallbackSink {}
unsafe impl Sync for CallbackSink {}

impl PacketSink for CallbackSink {
    fn emit(&self, packet: &[u8]) -> bool {
        if packet.is_empty() || packet.len() > u32::MAX as usize {
            return false;
        }
        // `write` is documented to copy; the mutable pointer only matches the
        // C signature.
        let rc = unsafe {
            (self.write)(
                self.ctx,
                packet.as_ptr() as *mut c_void,
                packet.len() as u32,
            )
        };
        rc >= 0
    }
}

struct State {
    /// Shared so drain/write/reload can release the global lock before a
    /// potentially blocking engine call.
    tunnel: Option<Arc<Tunnel>>,
    home: Option<PathBuf>,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(State {
            tunnel: None,
            home: None,
        })
    })
}

static RUNNING: AtomicBool = AtomicBool::new(false);

fn lock() -> std::sync::MutexGuard<'static, State> {
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

/// The App Group container of `home` (`<container>/versions/<version>/`).
fn container_of(home: &Path) -> Option<PathBuf> {
    let versions = home.parent()?;
    if versions.file_name()? != "versions" {
        return None;
    }
    versions.parent().map(Path::to_path_buf)
}

/// One Rust-specific view of the shared `config.yaml`.
#[derive(Debug)]
struct Staged {
    yaml: String,
    path: PathBuf,
}

/// Prepares the configuration the Rust kernel can actually run:
///
/// * `mixed-port` (and every other listener key) is preserved: the engine
///   binds its mixed listener from this file;
/// * a vendor `tun` block with `enable: true` is removed. On iOS the Packet
///   Tunnel itself is the device side and the device route belongs to
///   NetworkExtension; the shared file keeps the block for Mihomo, which uses
///   its launcher TUN;
/// * a `sniffer` block with `enable: true` is removed as well. This kernel
///   does not implement sniffing (`config.rs` rejects the enabled block by
///   name), and the iOS Tunnel cannot accept a configuration it refuses. The
///   difference is visible: domain rules after staging match on the
///   destination IP/DNS result rather than a sniffed SNI/Host;
/// * `rule-providers.*.path` / `proxy-providers.*.path` files referenced
///   outside the version directory are copied next to the config and the path
///   is rewritten to the basename (the extension cannot read the host sandbox);
/// * the result is written to `config.rust.yaml` beside the shared file.
fn stage_config(home: &Path, yaml: &str) -> Result<Staged, String> {
    let mut value: serde_yaml::Value = serde_yaml::from_str(yaml)
        .map_err(|error| format!("ios-staging: config.yaml is not YAML: {error}"))?;
    let mapping = value
        .as_mapping_mut()
        .ok_or_else(|| "ios-staging: config.yaml top level must be a mapping".to_string())?;
    if block_enabled(mapping.get(serde_yaml::Value::String("tun".into()))) {
        mapping.remove(serde_yaml::Value::String("tun".into()));
        tracing::warn!(
            "tun.enable was removed for the Rust engine: the iOS Packet Tunnel owns the device route"
        );
    }
    if block_enabled(mapping.get(serde_yaml::Value::String("sniffer".into()))) {
        mapping.remove(serde_yaml::Value::String("sniffer".into()));
        tracing::warn!(
            "sniffer.enable was removed for the Rust engine: sniffing is not implemented, so domain rules use the destination IP/DNS result instead of a sniffed SNI/Host"
        );
    }
    for group in ["rule-providers", "proxy-providers"] {
        let Some(providers) = mapping
            .get_mut(serde_yaml::Value::String(group.into()))
            .and_then(serde_yaml::Value::as_mapping_mut)
        else {
            continue;
        };
        for (_name, provider) in providers.iter_mut() {
            let Some(entry) = provider.as_mapping_mut() else {
                continue;
            };
            let key = serde_yaml::Value::String("path".into());
            let Some(raw) = entry.get(&key).and_then(serde_yaml::Value::as_str) else {
                continue;
            };
            let raw = raw.to_string();
            let source = if Path::new(&raw).is_absolute() {
                PathBuf::from(&raw)
            } else {
                home.join(&raw)
            };
            let Some(name) = source.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if source.is_file() {
                let destination = home.join(name);
                if source != destination {
                    std::fs::copy(&source, &destination).map_err(|error| {
                        format!("ios-staging: copy {}: {error}", source.display())
                    })?;
                }
                entry.insert(key, serde_yaml::Value::String(name.to_string()));
            }
        }
    }
    let yaml = serde_yaml::to_string(&value)
        .map_err(|error| format!("ios-staging: serialize config: {error}"))?;
    let path = home.join("config.rust.yaml");
    std::fs::write(&path, &yaml)
        .map_err(|error| format!("ios-staging: write {}: {error}", path.display()))?;
    Ok(Staged { yaml, path })
}

fn block_enabled(block: Option<&serde_yaml::Value>) -> bool {
    match block {
        Some(serde_yaml::Value::Bool(value)) => *value,
        Some(serde_yaml::Value::Mapping(mapping)) => mapping
            .get(serde_yaml::Value::String("enable".into()))
            .and_then(serde_yaml::Value::as_bool)
            .unwrap_or(false),
        _ => false,
    }
}

/// Read `engine.json` (written by the host when the engine is selected):
/// `{"selected": "rust" | "mihomo"}`.
fn selected_at(home: &Path) -> i32 {
    let Some(container) = container_of(home) else {
        return -1;
    };
    let path = container.join("engine.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return -1;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return -1;
    };
    match value
        .get("selected")
        .and_then(|value| value.as_str())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("rust") => 1,
        Some(_) => 0,
        None => -1,
    }
}

/// Device source addresses are the job of the OS; the tunnel only needs the
/// configuration and the App Group directory.
fn tunnel_options() -> TunnelOptions {
    // The extension may tune the MTU through the environment (the iOS
    // provider cannot pass a providerConfiguration key into libapp.a without
    // another ABI entry, so this is the smallest honest knob).
    let mut options = TunnelOptions::default();
    if let Ok(value) = std::env::var("BILLOW_TUNNEL_MTU") {
        if let Ok(mtu) = value.parse::<usize>() {
            if (576..=9000).contains(&mtu) {
                options.mtu = mtu;
            }
        }
    }
    options
}

/// `int32_t billow_ios_vpn_start(rust_tunnel_port_t *port, void *ctx, char *home, char **error)`.
///
/// Reads `<home>/config.yaml`, starts the engine and the packet data plane.
/// Returns 0 on success and sets a `malloc`'d `*error` otherwise. A tunnel
/// that is already running is stopped first (the extension always calls stop,
/// this only makes a restart safe).
#[no_mangle]
pub unsafe extern "C" fn billow_ios_vpn_start(
    port: *mut RustTunnelPort,
    ctx: *mut c_void,
    home: *mut c_char,
    error: *mut *mut c_char,
) -> i32 {
    if !error.is_null() {
        *error = std::ptr::null_mut();
    }
    if home.is_null() {
        set_error(error, "billow_ios_vpn_start: home is null");
        return 2;
    }
    let home = match CStr::from_ptr(home).to_str() {
        Ok(text) => PathBuf::from(text),
        Err(_) => {
            set_error(error, "billow_ios_vpn_start: home is not UTF-8");
            return 2;
        }
    };
    let previous = {
        let mut guard = lock();
        guard.home = Some(home.clone());
        guard.tunnel.take()
    };
    // Stop the previous generation outside the global lock: `stop` waits for
    // the engine tasks and must not block drain/write/status on other threads.
    if let Some(tunnel) = previous {
        tunnel.stop();
    }
    let config_path = home.join("config.yaml");
    let yaml = match std::fs::read_to_string(&config_path) {
        Ok(yaml) => yaml,
        Err(read_error) => {
            set_error(
                error,
                &format!(
                    "billow_ios_vpn_start: read {}: {read_error}",
                    config_path.display()
                ),
            );
            return 1;
        }
    };
    let staged = match stage_config(&home, &yaml) {
        Ok(staged) => staged,
        Err(message) => {
            set_error(error, &format!("billow_ios_vpn_start: {message}"));
            return 1;
        }
    };
    let sink: Option<Arc<dyn PacketSink>> = if !port.is_null() && !ctx.is_null() {
        let write = (*port).write;
        match write {
            Some(write) => Some(Arc::new(CallbackSink { ctx, write })),
            None => None,
        }
    } else {
        None
    };
    match Tunnel::start_at(&staged.yaml, staged.path, home.clone(), tunnel_options(), sink) {
        Ok(tunnel) => {
            let mut guard = lock();
            guard.home = Some(home);
            guard.tunnel = Some(Arc::new(tunnel));
            RUNNING.store(true, Ordering::Relaxed);
            0
        }
        Err(message) => {
            set_error(error, &format!("billow_ios_vpn_start: {message}"));
            1
        }
    }
}

/// `int32_t billow_ios_vpn_drain(uint8_t *packets, uint32_t max_count, uint32_t *packet_count)`.
///
/// Copies up to `max_count` records into `packets` (see the header: the buffer
/// must hold `max_count` records of up to `4 + 65535` bytes) and stores the
/// count. Returns 0, -1 when no tunnel runs, -2 on a null argument.
#[no_mangle]
pub unsafe extern "C" fn billow_ios_vpn_drain(
    packets: *mut u8,
    max_count: u32,
    packet_count: *mut u32,
) -> i32 {
    if packets.is_null() || packet_count.is_null() {
        return -2;
    }
    *packet_count = 0;
    let tunnel = lock().tunnel.clone();
    let Some(tunnel) = tunnel else {
        return -1;
    };
    // The ABI has no buffer length; clamp the record count so a wrong caller
    // cannot create an unbounded slice.
    let max_count = max_count.min(1024);
    let capacity = max_count as usize * (4 + 65_535);
    let buffer = std::slice::from_raw_parts_mut(packets, capacity);
    let count = tunnel.drain_into(buffer, max_count as usize);
    *packet_count = count as u32;
    0
}

/// `int32_t billow_ios_vpn_write(void *packet, uint32_t length)`.
///
/// Feeds one record (as produced by `drain`, `[4-byte big-endian length][IP
/// packet]`) or one bare IP packet from the device. Returns 0 accepted, -1 when
/// no tunnel runs, -2 for a malformed record.
#[no_mangle]
pub unsafe extern "C" fn billow_ios_vpn_write(packet: *mut c_void, length: u32) -> i32 {
    if packet.is_null() || length == 0 {
        return -2;
    }
    let bytes = std::slice::from_raw_parts(packet as *const u8, length as usize);
    // Either a record ([4-byte big-endian length][IP packet]) or a bare IP
    // packet. A bare packet starts with an IP version nibble (4 or 6), which a
    // plausible length prefix never does (that would be a 1 GiB record).
    let bare = matches!(bytes.first().map(|byte| byte >> 4), Some(4) | Some(6));
    let payload = if !bare && bytes.len() > 4 {
        let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if declared == bytes.len() - 4 {
            &bytes[4..]
        } else {
            return -2;
        }
    } else {
        bytes
    };
    let tunnel = lock().tunnel.clone();
    let Some(tunnel) = tunnel else {
        return -1;
    };
    match tunnel.ingest(payload) {
        crate::tunnel::Ingest::Accepted => 0,
        // A named rejection still consumed the packet; the caller's loop must
        // not treat it as a fatal engine error (only -1 is fatal).
        crate::tunnel::Ingest::Dropped(_) => 0,
    }
}

/// `void billow_ios_vpn_stop(void)`: stops the data plane and the engine and
/// releases every buffer.
#[no_mangle]
pub extern "C" fn billow_ios_vpn_stop() {
    let tunnel = {
        let mut guard = lock();
        guard.tunnel.take()
    };
    RUNNING.store(false, Ordering::Relaxed);
    // `stop` joins the data-plane tasks and the engine supervisor before it
    // returns (bounded by the tunnel's stop timeout), matching the header
    // contract: no callback or buffer from an earlier call is used afterwards.
    if let Some(tunnel) = tunnel {
        tunnel.stop();
    }
}

/// `int32_t billow_ios_vpn_version(char *buf, int32_t size)`: writes
/// `billow-rust <version>` as a NUL-terminated string and returns its length.
#[no_mangle]
pub unsafe extern "C" fn billow_ios_vpn_version(buf: *mut c_char, size: i32) -> i32 {
    if buf.is_null() || size <= 0 {
        return 0;
    }
    let text = format!("{VERSION_PREFIX} {}", crate::engine::VERSION);
    let bytes = text.as_bytes();
    let count = bytes.len().min(size as usize - 1);
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, count);
    *buf.add(count) = 0;
    count as i32
}

/// `int32_t billow_ios_vpn_selected(void)`: 1 when the app state selects the
/// Rust kernel, 0 for Mihomo, -1 when the host never wrote `engine.json`.
/// The App Group directory comes from the last [`billow_ios_vpn_set_home`].
#[no_mangle]
pub extern "C" fn billow_ios_vpn_selected() -> i32 {
    let home = lock().home.clone();
    match home.as_deref() {
        Some(home) => selected_at(home),
        None => -1,
    }
}

/// Records the App Group version directory before `selected` runs (the
/// extension calls this with the validated `<AppGroup>/versions/<version>`
/// path). Safe to call repeatedly.
#[no_mangle]
pub unsafe extern "C" fn billow_ios_vpn_set_home(home: *const c_char) {
    if home.is_null() {
        return;
    }
    if let Ok(text) = CStr::from_ptr(home).to_str() {
        lock().home = Some(PathBuf::from(text));
    }
}

/// `int32_t billow_ios_vpn_reload(char **error)`: reloads `<home>/config.yaml`.
/// A rejected reload keeps the running generation; an accepted one closes every
/// flow so the previous generation is released. Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn billow_ios_vpn_reload(error: *mut *mut c_char) -> i32 {
    if !error.is_null() {
        *error = std::ptr::null_mut();
    }
    let (tunnel, home) = {
        let guard = lock();
        (guard.tunnel.clone(), guard.home.clone())
    };
    let Some(tunnel) = tunnel else {
        set_error(error, "billow_ios_vpn_reload: no tunnel is running");
        return -1;
    };
    // The host may have switched versions or edited the shared config while
    // this session stayed alive: restage `config.yaml` before re-reading the
    // Rust-specific file the tunnel actually runs.
    if let Some(home) = home {
        match std::fs::read_to_string(home.join("config.yaml")) {
            Ok(yaml) => {
                if let Err(message) = stage_config(&home, &yaml) {
                    set_error(error, &format!("billow_ios_vpn_reload: {message}"));
                    return 1;
                }
            }
            Err(read_error) => {
                set_error(
                    error,
                    &format!(
                        "billow_ios_vpn_reload: read {}: {read_error}",
                        home.join("config.yaml").display()
                    ),
                );
                return 1;
            }
        }
    }
    match tunnel.reload() {
        Ok(warnings) => {
            for warning in &warnings {
                tracing::warn!(warning, "reload warning");
            }
            0
        }
        Err(message) => {
            set_error(error, &format!("billow_ios_vpn_reload: {message}"));
            1
        }
    }
}

/// `int32_t billow_ios_vpn_stats(char *buf, int32_t size)`: writes one JSON
/// object with the tunnel counters and the process peak RSS (`ru_maxrss`, the
/// value R3/R4 record) and returns its length, or the required length when the
/// buffer is too small.
#[no_mangle]
pub unsafe extern "C" fn billow_ios_vpn_stats(buf: *mut c_char, size: i32) -> i32 {
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
    let (running, stats) = {
        let tunnel = lock().tunnel.clone();
        (
            tunnel.is_some(),
            tunnel.as_ref().map(|tunnel| tunnel.stats()),
        )
    };
    let peak = peak_rss_bytes();
    match stats {
        Some(stats) => format!(
            concat!(
                "{{\"running\":{},\"version\":\"{} {}\",",
                "\"generation\":{},\"reloads\":{},\"peakRssBytes\":{},",
                "\"inPackets\":{},\"inBytes\":{},\"outPackets\":{},\"outBytes\":{},",
                "\"tcpOpened\":{},\"tcpClosed\":{},\"tcpRejected\":{},\"tcpFlows\":{},",
                "\"tcpFlowHigh\":{},\"udpDatagrams\":{},\"udpReplies\":{},\"udpFlows\":{},",
                "\"udpFlowHigh\":{},\"dnsQueries\":{},\"dnsFailures\":{},",
                "\"invalidPackets\":{},\"fragments\":{},\"unsupportedProtocols\":{},",
                "\"icmpDropped\":{},\"droppedInbound\":{},\"droppedEgress\":{},",
                "\"queueHigh\":{},\"queuedPackets\":{}}}"
            ),
            running,
            VERSION_PREFIX,
            crate::engine::VERSION,
            stats.generation,
            stats.reloads,
            peak,
            stats.in_packets,
            stats.in_bytes,
            stats.out_packets,
            stats.out_bytes,
            stats.tcp_opened,
            stats.tcp_closed,
            stats.tcp_rejected,
            stats.tcp_flows,
            stats.tcp_flow_high,
            stats.udp_datagrams,
            stats.udp_replies,
            stats.udp_flows,
            stats.udp_flow_high,
            stats.dns_queries,
            stats.dns_failures,
            stats.invalid_packets,
            stats.fragments,
            stats.unsupported_protocols,
            stats.icmp_dropped,
            stats.dropped_inbound,
            stats.dropped_egress,
            stats.queue_high,
            stats.queued_packets,
        ),
        None => format!(
            "{{\"running\":{},\"version\":\"{} {}\",\"peakRssBytes\":{}}}",
            running,
            VERSION_PREFIX,
            crate::engine::VERSION,
            peak
        ),
    }
}

/// Peak resident set size of this process in bytes (`ru_maxrss` is bytes on
/// Darwin). 0 when the platform does not report it.
fn peak_rss_bytes() -> u64 {
    #[cfg(unix)]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        if rc == 0 {
            let usage = unsafe { usage.assume_init() };
            return usage.ru_maxrss.max(0) as u64;
        }
    }
    0
}

/// `void billow_ios_vpn_free_error(char *error)`.
#[no_mangle]
pub unsafe extern "C" fn billow_ios_vpn_free_error(error: *mut c_char) {
    if !error.is_null() {
        libc::free(error as *mut c_void);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_is_reported() {
        let mut buf = [0i8; 32];
        let length = unsafe { billow_ios_vpn_version(buf.as_mut_ptr(), 32) };
        let text = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(text, format!("{VERSION_PREFIX} {}", crate::engine::VERSION));
        assert_eq!(length as usize, text.len());
    }

    #[test]
    fn version_refuses_a_small_buffer() {
        let mut buf = [0i8; 4];
        let length = unsafe { billow_ios_vpn_version(buf.as_mut_ptr(), 4) };
        assert_eq!(length, 3);
        assert_eq!(
            unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap(),
            "bil"
        );
    }

    #[test]
    fn selected_follows_the_host_state_file() {
        let root = std::env::temp_dir().join(format!("billow-t7-{}", std::process::id()));
        let home = root.join("versions").join("v1");
        std::fs::create_dir_all(&home).unwrap();
        assert_eq!(selected_at(&home), -1);
        std::fs::write(root.join("engine.json"), r#"{"selected":"rust"}"#).unwrap();
        assert_eq!(selected_at(&home), 1);
        std::fs::write(root.join("engine.json"), r#"{"selected":"mihomo"}"#).unwrap();
        assert_eq!(selected_at(&home), 0);
        std::fs::write(root.join("engine.json"), "not json").unwrap();
        assert_eq!(selected_at(&home), -1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn error_strings_are_allocated_and_released() {
        let mut error: *mut c_char = std::ptr::null_mut();
        unsafe {
            set_error(&mut error, "boom");
            assert!(!error.is_null());
            assert_eq!(CStr::from_ptr(error).to_str().unwrap(), "boom");
            billow_ios_vpn_free_error(error);
        }
        let mut error: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            billow_ios_vpn_start(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut error,
            )
        };
        assert_eq!(rc, 2);
        assert!(!error.is_null());
        unsafe { billow_ios_vpn_free_error(error) };
    }

    #[test]
    fn start_without_a_config_reports_the_path() {
        let root = std::env::temp_dir().join(format!("billow-t7-missing-{}", std::process::id()));
        let home = root.join("versions").join("v1");
        std::fs::create_dir_all(&home).unwrap();
        let home_c = CString::new(home.display().to_string()).unwrap();
        let mut error: *mut c_char = std::ptr::null_mut();
        let mut port = RustTunnelPort {
            start: None,
            write: None,
            stop: None,
        };
        let rc = unsafe {
            billow_ios_vpn_start(
                &mut port as *mut RustTunnelPort,
                std::ptr::null_mut(),
                home_c.as_ptr() as *mut c_char,
                &mut error as *mut *mut c_char,
            )
        };
        assert_eq!(rc, 1);
        let message = unsafe { CStr::from_ptr(error).to_str().unwrap().to_string() };
        assert!(message.contains("config.yaml"), "{message}");
        unsafe { billow_ios_vpn_free_error(error) };
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn drain_and_write_need_a_running_tunnel() {
        let mut count = 0u32;
        let mut buffer = [0u8; 16];
        let drain = unsafe { billow_ios_vpn_drain(buffer.as_mut_ptr(), 1, &mut count) };
        assert_eq!(drain, -1);
        let write = unsafe { billow_ios_vpn_write(buffer.as_mut_ptr() as *mut c_void, 4) };
        assert_eq!(write, -1);
        let mut error: *mut c_char = std::ptr::null_mut();
        assert_eq!(unsafe { billow_ios_vpn_reload(&mut error) }, -1);
        unsafe { billow_ios_vpn_free_error(error) };
    }

    #[test]
    fn stats_without_a_tunnel_report_the_process() {
        let mut buf = vec![0i8; 512];
        let length = unsafe { billow_ios_vpn_stats(buf.as_mut_ptr(), 512) };
        assert!(length > 0);
        let text = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(value["running"], serde_json::Value::Bool(false));
        assert!(text.contains("peakRssBytes"));
    }

    fn stage_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "billow-t7-stage-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn staging_strips_enabled_tun_and_keeps_mixed_port() {
        let home = stage_dir("tun");
        let yaml = "mixed-port: 17890\n\
                    tun:\n  enable: true\n  stack: gvisor\n\
                    rules:\n  - MATCH,DIRECT\n";
        let staged = stage_config(&home, yaml).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&staged.yaml).unwrap();
        assert_eq!(
            value.get("mixed-port").and_then(serde_yaml::Value::as_u64),
            Some(17_890)
        );
        assert!(value.get("tun").is_none(), "{}", staged.yaml);
        assert!(staged.path.ends_with("config.rust.yaml"));
        assert!(std::fs::read_to_string(&staged.path)
            .unwrap()
            .contains("mixed-port"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn staging_strips_enabled_sniffer_so_the_config_loader_accepts_it() {
        use crate::config::load_config;

        let home = stage_dir("sniffer");
        let yaml = "mixed-port: 17893\n\
                    sniffer:\n  enable: true\n  sniff:\n    HTTP:\n      ports: [80]\n\
                    rules:\n  - MATCH,DIRECT\n";
        // The shared file is rejected by name before staging.
        let error = load_config(yaml, "config.yaml").unwrap_err().to_string();
        assert!(error.contains("sniffer"), "{error}");
        let staged = stage_config(&home, yaml).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&staged.yaml).unwrap();
        assert_eq!(
            value.get("mixed-port").and_then(serde_yaml::Value::as_u64),
            Some(17_893)
        );
        assert!(value.get("sniffer").is_none(), "{}", staged.yaml);
        load_config(&staged.yaml, "config.rust.yaml").expect("staged config must load");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn staging_keeps_a_disabled_tun_block_for_the_config_loader() {
        let home = stage_dir("tun-off");
        let yaml = "mixed-port: 17891\ntun:\n  enable: false\nrules:\n  - MATCH,DIRECT\n";
        let staged = stage_config(&home, yaml).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&staged.yaml).unwrap();
        assert_eq!(
            value
                .get("tun")
                .and_then(|tun| tun.get("enable"))
                .and_then(serde_yaml::Value::as_bool),
            Some(false)
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn staging_copies_referenced_rule_sets_into_the_home_and_rewrites_paths() {
        let root = stage_dir("providers");
        let home = root.join("versions").join("v1");
        std::fs::create_dir_all(&home).unwrap();
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("ads.mrs"), b"mrs-bytes").unwrap();
        let mrs = outside.join("ads.mrs");
        let yaml = format!(
            "mixed-port: 17892\n\
             rule-providers:\n  ads:\n    type: file\n    behavior: domain\n    format: mrs\n    path: '{}'\n\
             proxy-providers:\n  local:\n    type: file\n    path: '{}'\n\
             rules:\n  - RULE-SET,ads,DIRECT\n  - MATCH,DIRECT\n",
            mrs.display(),
            outside.join("proxies.yaml").display()
        );
        std::fs::write(outside.join("proxies.yaml"), b"proxies: []\n").unwrap();
        let staged = stage_config(&home, &yaml).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&staged.yaml).unwrap();
        assert_eq!(
            value["rule-providers"]["ads"]["path"],
            serde_yaml::Value::String("ads.mrs".to_string())
        );
        assert_eq!(
            value["proxy-providers"]["local"]["path"],
            serde_yaml::Value::String("proxies.yaml".to_string())
        );
        assert_eq!(std::fs::read(home.join("ads.mrs")).unwrap(), b"mrs-bytes");
        assert!(home.join("proxies.yaml").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn staging_rejects_non_mapping_configuration() {
        let home = stage_dir("bad");
        let error = stage_config(&home, "- just\n- a\n- list\n").unwrap_err();
        assert!(error.contains("top level must be a mapping"), "{error}");
        let _ = std::fs::remove_dir_all(&home);
    }
}
