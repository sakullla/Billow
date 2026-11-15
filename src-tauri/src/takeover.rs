use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Condvar, Mutex};

use serde::Serialize;

pub const TUN_DENIED: &str = "系统授权被拒绝";
pub const VPN_DENIED: &str = "VPN 授权被拒绝";
pub const NO_PROFILE: &str = "没有生效配置";
const PROXY_HOST: &str = "127.0.0.1";
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const EXCLUDE_FILE: &str = "vpn-excluded.txt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPlatform {
    Desktop,
    Android,
}

impl ClientPlatform {
    pub fn current() -> Self {
        #[cfg(target_os = "android")]
        {
            Self::Android
        }
        #[cfg(not(target_os = "android"))]
        {
            Self::Desktop
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Android => "android",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
}

/// HTTP and HTTPS system proxy. Tests inject [`MemoryProxy`]; the host
/// implementation is not used by unit tests.
pub trait SystemProxy: Send {
    fn set_http_https(&mut self, endpoint: &ProxyEndpoint) -> Result<(), String>;
    /// Clear a protocol only when it still points at `endpoint`.
    fn clear_if_pointing_at(&mut self, endpoint: &ProxyEndpoint) -> Result<(), String>;
}

/// Desktop TUN authorization. A denial must not be treated as success.
pub trait TunGrant: Send {
    fn authorize(&mut self) -> Result<bool, String>;
    fn set_enabled(&mut self, enabled: bool) -> Result<(), String>;
}

/// Android VPN. `authorize` asks the system. `establish` starts the service and returns the TUN fd.
pub trait VpnGrant: Send {
    fn authorize(&mut self) -> Result<bool, String>;
    fn establish(&mut self, excluded: &[String]) -> Result<i32, String>;
    fn close(&mut self) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstalledApp {
    pub name: String,
    pub package_name: String,
}

/// Search keeps installed apps whose names match. The query itself is not an app.
pub fn filter_installed<'a>(apps: &'a [InstalledApp], query: &str) -> Vec<&'a InstalledApp> {
    let query = query.trim();
    if query.is_empty() {
        return apps.iter().collect();
    }
    apps.iter().filter(|app| app.name.contains(query)).collect()
}

/// Keeps display names, including internal spaces. Empty packages and duplicates are dropped.
pub fn normalize_installed(apps: Vec<InstalledApp>) -> Vec<InstalledApp> {
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for app in apps {
        let package_name = app.package_name.trim().to_string();
        if package_name.is_empty() || seen.iter().any(|item: &String| item == &package_name) {
            continue;
        }
        let name = if app.name.trim().is_empty() {
            package_name.clone()
        } else {
            app.name
        };
        seen.push(package_name.clone());
        out.push(InstalledApp { name, package_name });
    }
    out.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.package_name.cmp(&right.package_name))
    });
    out
}

pub trait InstalledApps: Send {
    fn list(&mut self) -> Result<Vec<InstalledApp>, String>;
}

pub struct HostInstalledApps;

impl InstalledApps for HostInstalledApps {
    fn list(&mut self) -> Result<Vec<InstalledApp>, String> {
        host_installed_apps()
    }
}

pub fn host_installed_apps() -> Result<Vec<InstalledApp>, String> {
    #[cfg(target_os = "android")]
    {
        android_installed_apps()
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkModel {
    pub platform: ClientPlatform,
    pub tun_wanted: bool,
    pub excluded: Vec<String>,
    pub system_proxy: bool,
    pub tun: bool,
    pub vpn: bool,
    pub connected: bool,
    pub failure: Option<String>,
    pub endpoint: Option<ProxyEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformRelease {
    pub endpoint: Option<ProxyEndpoint>,
    pub close_tun: bool,
    pub close_vpn: bool,
}

/// Clears the owned proxy when `release.endpoint` is set.
/// `false` means the proxy is still pointing at us, so the caller must keep the flag and port.
pub fn release_platform(
    proxy: &mut dyn SystemProxy,
    tun: &mut dyn TunGrant,
    vpn: &mut dyn VpnGrant,
    release: &PlatformRelease,
) -> bool {
    let cleared = match &release.endpoint {
        Some(endpoint) => proxy.clear_if_pointing_at(endpoint).is_ok(),
        None => true,
    };
    if release.close_tun {
        let _ = tun.set_enabled(false);
    }
    if release.close_vpn {
        let _ = vpn.close();
    }
    cleared
}

/// Kernel start failed. TUN and VPN close. The system proxy is marked off only after a successful clear.
pub fn fail_kernel(
    model: &mut LinkModel,
    proxy: &mut dyn SystemProxy,
    tun: &mut dyn TunGrant,
    vpn: &mut dyn VpnGrant,
    message: String,
) {
    let cleared = release_platform(
        proxy,
        tun,
        vpn,
        &PlatformRelease {
            endpoint: model.endpoint.clone(),
            close_tun: model.tun,
            close_vpn: model.vpn,
        },
    );
    if cleared {
        model.system_proxy = false;
        model.endpoint = None;
    }
    model.tun = false;
    model.vpn = false;
    model.connected = false;
    model.failure = Some(if message.is_empty() {
        "内核没有启动".to_string()
    } else {
        message
    });
}

pub fn disconnect(
    model: &mut LinkModel,
    proxy: &mut dyn SystemProxy,
    tun: &mut dyn TunGrant,
    vpn: &mut dyn VpnGrant,
) {
    let _ = tun.set_enabled(false);
    let _ = vpn.close();
    model.tun = false;
    model.vpn = false;
    if !clear_owned(model, proxy) {
        model.connected = model.system_proxy;
        return;
    }
    model.system_proxy = false;
    model.connected = false;
}

fn clear_owned(model: &mut LinkModel, proxy: &mut dyn SystemProxy) -> bool {
    let Some(endpoint) = model.endpoint.clone() else {
        return true;
    };
    match proxy.clear_if_pointing_at(&endpoint) {
        Ok(()) => true,
        Err(message) => {
            model.failure = Some(if message.is_empty() {
                "系统代理没有关闭".to_string()
            } else {
                message
            });
            false
        }
    }
}

pub fn set_system_proxy(
    model: &mut LinkModel,
    enabled: bool,
    port: Option<u16>,
    proxy: &mut dyn SystemProxy,
) {
    if model.platform != ClientPlatform::Desktop {
        return;
    }
    if !enabled {
        if !clear_owned(model, proxy) {
            model.connected = model.system_proxy;
            return;
        }
        model.system_proxy = false;
        model.connected = false;
        return;
    }
    let Some(port) = port else {
        model.system_proxy = false;
        model.connected = false;
        model.failure = Some("没有本地端口".to_string());
        return;
    };
    if open_proxy(model, port, proxy) {
        model.system_proxy = true;
        model.connected = true;
    }
}

pub fn set_tun(model: &mut LinkModel, enabled: bool, tun: &mut dyn TunGrant) {
    if model.platform != ClientPlatform::Desktop {
        return;
    }
    if !enabled {
        let _ = tun.set_enabled(false);
        model.tun = false;
        model.tun_wanted = false;
        if model.failure.as_deref() == Some(TUN_DENIED) {
            model.failure = None;
        }
        model.connected = model.system_proxy;
        return;
    }
    // Denial leaves the previous system-proxy switch untouched.
    let previous_proxy = model.system_proxy;
    if !granted(tun.authorize()) || tun.set_enabled(true).is_err() {
        let _ = tun.set_enabled(false);
        model.tun = false;
        model.system_proxy = previous_proxy;
        model.connected = false;
        model.failure = Some(TUN_DENIED.to_string());
        return;
    }
    model.tun = true;
    model.tun_wanted = true;
    model.connected = model.system_proxy;
}

pub fn exclude_package(
    model: &mut LinkModel,
    package_name: &str,
    vpn: &mut dyn VpnGrant,
) -> Option<i32> {
    if model.platform != ClientPlatform::Android {
        return None;
    }
    let Some(package_name) = clean_package(package_name) else {
        return None;
    };
    if !model.excluded.iter().any(|item| item == &package_name) {
        model.excluded.push(package_name);
    }
    refresh_vpn(model, vpn)
}

pub fn include_package(
    model: &mut LinkModel,
    package_name: &str,
    vpn: &mut dyn VpnGrant,
) -> Option<i32> {
    if model.platform != ClientPlatform::Android {
        return None;
    }
    let Some(package_name) = clean_package(package_name) else {
        return None;
    };
    model.excluded.retain(|item| item != &package_name);
    refresh_vpn(model, vpn)
}

/// `None` means the list was saved and VPN stayed down, or establish failed.
/// `Some` is the replacement TUN fd. The previous fd no longer reads traffic.
fn refresh_vpn(model: &mut LinkModel, vpn: &mut dyn VpnGrant) -> Option<i32> {
    if !model.vpn {
        return None;
    }
    match vpn.establish(&model.excluded) {
        Ok(fd) => Some(fd),
        Err(_) => {
            let _ = vpn.close();
            model.vpn = false;
            model.connected = false;
            model.failure = Some("VPN 没有建立".to_string());
            None
        }
    }
}

fn open_proxy(model: &mut LinkModel, port: u16, proxy: &mut dyn SystemProxy) -> bool {
    let endpoint = ProxyEndpoint {
        host: PROXY_HOST.to_string(),
        port,
    };
    if proxy.set_http_https(&endpoint).is_err() {
        model.failure = Some("系统代理没有打开".to_string());
        return false;
    }
    model.endpoint = Some(endpoint);
    true
}

fn granted(result: Result<bool, String>) -> bool {
    matches!(result, Ok(true))
}

fn clean_package(package_name: &str) -> Option<String> {
    let package_name = package_name.trim();
    if package_name.is_empty() {
        None
    } else {
        Some(package_name.to_string())
    }
}

#[derive(Debug, Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct MemoryProxy {
    pub http: Option<ProxyEndpoint>,
    pub https: Option<ProxyEndpoint>,
    pub sets: u32,
}

impl SystemProxy for MemoryProxy {
    fn set_http_https(&mut self, endpoint: &ProxyEndpoint) -> Result<(), String> {
        self.sets += 1;
        self.http = Some(endpoint.clone());
        self.https = Some(endpoint.clone());
        Ok(())
    }

    fn clear_if_pointing_at(&mut self, endpoint: &ProxyEndpoint) -> Result<(), String> {
        if self.http.as_ref() == Some(endpoint) {
            self.http = None;
        }
        if self.https.as_ref() == Some(endpoint) {
            self.https = None;
        }
        Ok(())
    }
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct MemoryTun {
    pub grant: bool,
    pub enabled: bool,
    pub authorize_calls: u32,
}

impl Default for MemoryTun {
    fn default() -> Self {
        Self {
            grant: true,
            enabled: false,
            authorize_calls: 0,
        }
    }
}

impl TunGrant for MemoryTun {
    fn authorize(&mut self) -> Result<bool, String> {
        self.authorize_calls += 1;
        Ok(self.grant)
    }

    fn set_enabled(&mut self, enabled: bool) -> Result<(), String> {
        self.enabled = enabled;
        Ok(())
    }
}

#[derive(Debug, Default)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct MemoryVpn {
    pub grant: bool,
    pub open: bool,
    pub last_excluded: Vec<String>,
    pub establish_calls: u32,
}

impl VpnGrant for MemoryVpn {
    fn authorize(&mut self) -> Result<bool, String> {
        Ok(self.grant)
    }

    fn establish(&mut self, excluded: &[String]) -> Result<i32, String> {
        self.establish_calls += 1;
        self.last_excluded = excluded.to_vec();
        self.open = true;
        Ok(1)
    }

    fn close(&mut self) -> Result<(), String> {
        self.open = false;
        Ok(())
    }
}

/// Which desktop TUN device the grant refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunHost {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Linux,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Macos,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    Windows,
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    Other,
}

impl TunHost {
    pub fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(target_os = "macos")]
        {
            Self::Macos
        }
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Self::Other
        }
    }
}

/// Results of the platform probes. macOS and Windows do not consult `linux_node`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunEvidence {
    pub linux_node: bool,
    pub utun: bool,
    pub windows: bool,
}

/// Linux allows TUN when `/dev/net/tun` or `/dev/tun` opens.
/// macOS allows it when utun opens. Windows allows it when WinTUN can be created or opened.
/// A missing Linux device node is not a denial on macOS or Windows.
pub fn tun_allowed(host: TunHost, evidence: TunEvidence) -> bool {
    match host {
        TunHost::Linux => evidence.linux_node,
        TunHost::Macos => evidence.utun,
        TunHost::Windows => evidence.windows,
        TunHost::Other => false,
    }
}

/// Desktop TUN grant. Authorization uses [`tun_allowed`] and the host's own probe.
pub struct HostTun {
    evidence: fn() -> TunEvidence,
    enabled: bool,
}

impl HostTun {
    pub fn host() -> Self {
        Self {
            evidence: live_tun_evidence,
            enabled: false,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_evidence(evidence: fn() -> TunEvidence) -> Self {
        Self {
            evidence,
            enabled: false,
        }
    }
}

impl Default for HostTun {
    fn default() -> Self {
        Self::host()
    }
}

impl TunGrant for HostTun {
    fn authorize(&mut self) -> Result<bool, String> {
        Ok(tun_allowed(TunHost::current(), (self.evidence)()))
    }

    fn set_enabled(&mut self, enabled: bool) -> Result<(), String> {
        self.enabled = enabled;
        Ok(())
    }
}

fn live_tun_evidence() -> TunEvidence {
    match TunHost::current() {
        TunHost::Linux => TunEvidence {
            linux_node: linux_tun_node_open(),
            utun: false,
            windows: false,
        },
        TunHost::Macos => TunEvidence {
            linux_node: false,
            utun: macos_utun_open(),
            windows: false,
        },
        TunHost::Windows => TunEvidence {
            linux_node: false,
            utun: false,
            windows: windows_tun_open(),
        },
        TunHost::Other => TunEvidence {
            linux_node: false,
            utun: false,
            windows: false,
        },
    }
}

fn linux_tun_node_open() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .is_ok()
        || std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tun")
            .is_ok()
}

#[cfg(target_os = "macos")]
fn macos_utun_open() -> bool {
    const PF_SYSTEM: i32 = 32;
    const AF_SYS_CONTROL: u16 = 2;
    const SYSPROTO_CONTROL: i32 = 2;
    const SOCK_DGRAM: i32 = 2;
    const CTLIOCGINFO: u64 = 0xc0644e03;
    const NAME: &[u8] = b"com.apple.net.utun_control";

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [u8; 96],
    }

    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    unsafe extern "C" {
        fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
        fn ioctl(fd: i32, request: u64, argp: *mut CtlInfo) -> i32;
        fn connect(fd: i32, addr: *const SockaddrCtl, len: u32) -> i32;
        fn close(fd: i32) -> i32;
    }

    unsafe {
        let fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if fd < 0 {
            return false;
        }
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        let name_len = NAME.len().min(info.ctl_name.len() - 1);
        info.ctl_name[..name_len].copy_from_slice(&NAME[..name_len]);
        if ioctl(fd, CTLIOCGINFO, &mut info) < 0 {
            close(fd);
            return false;
        }
        let mut addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: PF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        let mut opened = false;
        for unit in 0..16u32 {
            addr.sc_unit = unit;
            if connect(fd, &addr, std::mem::size_of::<SockaddrCtl>() as u32) == 0 {
                opened = true;
                break;
            }
            let err = std::io::Error::last_os_error().raw_os_error();
            if err == Some(1) || err == Some(13) {
                break;
            }
        }
        close(fd);
        opened
    }
}

#[cfg(not(target_os = "macos"))]
fn macos_utun_open() -> bool {
    false
}

/// Injected WinTUN probe. `elevated` is not a grant; only create or open is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsTunProbe {
    elevated: bool,
    created_or_opened: bool,
}

/// Token elevation is not WinTUN's answer.
fn windows_tun_granted(probe: WindowsTunProbe) -> bool {
    let _ = probe.elevated;
    probe.created_or_opened
}

/// Load WinTUN and create or open an adapter. A missing DLL or a failed call is a denial.
#[cfg(target_os = "windows")]
fn wintun_create_or_open() -> bool {
    use core::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
    }

    type Create = unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> *mut c_void;
    type Open = unsafe extern "system" fn(*const u16) -> *mut c_void;
    type Close = unsafe extern "system" fn(*mut c_void);

    fn utf16z(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe {
        // Never search the working directory for a privileged DLL.
        let Ok(exe) = std::env::current_exe() else { return false; };
        let Some(directory) = exe.parent() else { return false; };
        use std::os::windows::ffi::OsStrExt;
        let dll: Vec<u16> = directory.join("wintun.dll").as_os_str().encode_wide().chain(Some(0)).collect();
        let module = LoadLibraryW(dll.as_ptr());
        if module.is_null() {
            return false;
        }
        let create = GetProcAddress(module, b"WintunCreateAdapter\0".as_ptr());
        let open = GetProcAddress(module, b"WintunOpenAdapter\0".as_ptr());
        let close = GetProcAddress(module, b"WintunCloseAdapter\0".as_ptr());
        if create.is_null() || open.is_null() || close.is_null() {
            FreeLibrary(module);
            return false;
        }
        let create = std::mem::transmute::<*mut c_void, Create>(create);
        let open = std::mem::transmute::<*mut c_void, Open>(open);
        let close = std::mem::transmute::<*mut c_void, Close>(close);
        let name = utf16z("Billow");
        let mut adapter = open(name.as_ptr());
        if adapter.is_null() {
            let tunnel = utf16z("Billow");
            adapter = create(name.as_ptr(), tunnel.as_ptr(), std::ptr::null());
        }
        let opened = !adapter.is_null();
        if opened {
            close(adapter);
        }
        FreeLibrary(module);
        opened
    }
}

#[cfg(not(target_os = "windows"))]
fn wintun_create_or_open() -> bool {
    false
}

fn windows_tun_open() -> bool {
    windows_tun_granted(WindowsTunProbe {
        elevated: false,
        created_or_opened: wintun_create_or_open(),
    })
}

/// Calls `prepare` and then `start`. Tests inject [`VpnBridge`]; the OS bridge does not run in unit tests.
pub struct HostVpn {
    bridge: Box<dyn VpnBridge>,
    fd: Option<i32>,
    calls: Vec<String>,
    last_excluded: Vec<String>,
}

pub trait VpnBridge: Send {
    fn prepare(&mut self) -> Result<bool, String>;
    fn start(&mut self, excluded: &[String]) -> Result<i32, String>;
    fn stop(&mut self) -> Result<(), String>;
}

impl HostVpn {
    pub fn new(bridge: Box<dyn VpnBridge>) -> Self {
        Self {
            bridge,
            fd: None,
            calls: Vec::new(),
            last_excluded: Vec::new(),
        }
    }

    pub fn host() -> Self {
        Self::new(Box::new(OsVpnBridge))
    }

    pub fn calls(&self) -> &[String] {
        &self.calls
    }

    pub fn last_excluded(&self) -> &[String] {
        &self.last_excluded
    }
}

impl VpnGrant for HostVpn {
    fn authorize(&mut self) -> Result<bool, String> {
        self.calls.push("prepare".to_string());
        self.bridge.prepare()
    }

    fn establish(&mut self, excluded: &[String]) -> Result<i32, String> {
        self.calls.push("start".to_string());
        self.last_excluded = excluded.to_vec();
        let fd = self.bridge.start(excluded)?;
        if fd < 0 {
            return Err("VPN 没有建立".to_string());
        }
        self.fd = Some(fd);
        Ok(fd)
    }

    fn close(&mut self) -> Result<(), String> {
        self.fd = None;
        self.bridge.stop()
    }
}

/// Records prepare/start so tests can see the host adapter's calls.
#[derive(Debug, Default)]
pub struct RecordingVpn {
    pub grant: bool,
    pub calls: Vec<String>,
    pub excluded: Vec<String>,
    pub fd: i32,
    pub fail_start: bool,
}

impl RecordingVpn {
    pub fn granted() -> Self {
        Self {
            grant: true,
            fd: 42,
            ..Self::default()
        }
    }
}

impl VpnBridge for RecordingVpn {
    fn prepare(&mut self) -> Result<bool, String> {
        self.calls.push("prepare".to_string());
        Ok(self.grant)
    }

    fn start(&mut self, excluded: &[String]) -> Result<i32, String> {
        self.calls.push("start".to_string());
        self.excluded = excluded.to_vec();
        if self.fail_start {
            return Err("VPN 没有建立".to_string());
        }
        Ok(self.fd)
    }

    fn stop(&mut self) -> Result<(), String> {
        self.calls.push("stop".to_string());
        Ok(())
    }
}

struct OsVpnBridge;

impl VpnBridge for OsVpnBridge {
    fn prepare(&mut self) -> Result<bool, String> {
        #[cfg(target_os = "android")]
        {
            return android_prepare();
        }
        #[cfg(not(target_os = "android"))]
        {
            Err("VPN 不可用".to_string())
        }
    }

    fn start(&mut self, excluded: &[String]) -> Result<i32, String> {
        #[cfg(target_os = "android")]
        {
            return android_start(excluded);
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = excluded;
            Err("VPN 没有建立".to_string())
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        #[cfg(target_os = "android")]
        {
            android_stop();
        }
        Ok(())
    }
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
static VPN_CONSENT: AtomicBool = AtomicBool::new(false);
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
static VPN_FD: AtomicI32 = AtomicI32::new(-1);
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
static VPN_FD_READY: AtomicBool = AtomicBool::new(false);
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
static VPN_READY: Condvar = Condvar::new();
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
static VPN_LOCK: Mutex<()> = Mutex::new(());

#[cfg(target_os = "android")]
fn android_prepare() -> Result<bool, String> {
    VPN_CONSENT.store(false, Ordering::SeqCst);
    // BillowVpnBridge.prepare shows the system dialog and reports back through nativeConsent.
    let ctx = ndk_context::android_context();
    let vm =
        unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }.map_err(|_| "VPN 不可用".to_string())?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|_| "VPN 不可用".to_string())?;
    let activity = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
    let already = env
        .call_static_method(
            "app/billow/client/BillowVpnBridge",
            "prepare",
            "(Landroid/app/Activity;)Z",
            &[jni::objects::JValue::Object(&activity)],
        )
        .map_err(|_| "VPN 不可用".to_string())?
        .z()
        .map_err(|_| "VPN 不可用".to_string())?;
    if already {
        return Ok(true);
    }
    let guard = VPN_LOCK.lock().map_err(|_| "VPN 不可用".to_string())?;
    let _guard = VPN_READY
        .wait_timeout(guard, std::time::Duration::from_secs(120))
        .map_err(|_| "VPN 授权被拒绝".to_string())?;
    Ok(VPN_CONSENT.load(Ordering::SeqCst))
}

#[cfg(any(target_os = "android", test))]
fn clear_written_vpn_fd() {
    let reset = || {
        VPN_FD.store(-1, Ordering::SeqCst);
        VPN_FD_READY.store(false, Ordering::SeqCst);
    };
    match VPN_LOCK.lock() {
        Ok(guard) => {
            reset();
            drop(guard);
        }
        Err(_) => reset(),
    }
}

/// The service may write the fd before waiting starts. Return as soon as that write is visible.
#[cfg(any(target_os = "android", test))]
fn wait_for_written_vpn_fd(timeout: std::time::Duration) -> Result<i32, String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut guard = VPN_LOCK.lock().map_err(|_| "VPN 没有建立".to_string())?;
    loop {
        if VPN_FD_READY.load(Ordering::SeqCst) {
            let fd = VPN_FD.load(Ordering::SeqCst);
            return if fd >= 0 {
                Ok(fd)
            } else {
                Err("VPN 没有建立".to_string())
            };
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err("VPN 没有建立".to_string());
        }
        let (next, _) = VPN_READY
            .wait_timeout(guard, deadline - now)
            .map_err(|_| "VPN 没有建立".to_string())?;
        guard = next;
    }
}

#[cfg(target_os = "android")]
fn android_start(excluded: &[String]) -> Result<i32, String> {
    clear_written_vpn_fd();
    let ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
        .map_err(|_| "VPN 没有建立".to_string())?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|_| "VPN 没有建立".to_string())?;
    let list = env
        .new_object("java/util/ArrayList", "()V", &[])
        .map_err(|_| "VPN 没有建立".to_string())?;
    for package_name in excluded {
        let value = env
            .new_string(package_name)
            .map_err(|_| "VPN 没有建立".to_string())?;
        env.call_method(
            &list,
            "add",
            "(Ljava/lang/Object;)Z",
            &[jni::objects::JValue::Object(&value)],
        )
        .map_err(|_| "VPN 没有建立".to_string())?;
    }
    let context = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
    env.call_static_method(
        "app/billow/client/BillowVpnBridge",
        "start",
        "(Landroid/content/Context;Ljava/util/List;)V",
        &[
            jni::objects::JValue::Object(&context),
            jni::objects::JValue::Object(&list),
        ],
    )
    .map_err(|_| "VPN 没有建立".to_string())?;
    wait_for_written_vpn_fd(std::time::Duration::from_secs(15))
}

#[cfg(target_os = "android")]
fn android_stop() {
    let _ = (|| -> Result<(), ()> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }.map_err(|_| ())?;
        let mut env = vm.attach_current_thread().map_err(|_| ())?;
        let context = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
        env.call_static_method(
            "app/billow/client/BillowVpnBridge",
            "stop",
            "(Landroid/content/Context;)V",
            &[jni::objects::JValue::Object(&context)],
        )
        .map_err(|_| ())?;
        Ok(())
    })();
}

#[cfg(target_os = "android")]
fn signal_vpn() {
    if let Ok(guard) = VPN_LOCK.lock() {
        VPN_READY.notify_all();
        drop(guard);
    }
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn report_vpn_consent(granted: bool) {
    VPN_CONSENT.store(granted, Ordering::SeqCst);
    #[cfg(target_os = "android")]
    signal_vpn();
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn report_vpn_fd(fd: i32) {
    let publish = || {
        VPN_FD.store(fd, Ordering::SeqCst);
        VPN_FD_READY.store(true, Ordering::SeqCst);
    };
    match VPN_LOCK.lock() {
        Ok(guard) => {
            publish();
            VPN_READY.notify_all();
            drop(guard);
        }
        Err(_) => publish(),
    }
}

/// Kotlin `BillowVpnBridge.nativeConsent` reports the system dialog here.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_billow_client_BillowVpnBridge_nativeConsent(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    granted: i32,
) {
    report_vpn_consent(granted != 0);
}

#[cfg(target_os = "android")]
fn android_installed_apps() -> Result<Vec<InstalledApp>, String> {
    let ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
        .map_err(|_| "已安装应用没有读取".to_string())?;
    let mut guard = vm
        .attach_current_thread()
        .map_err(|_| "已安装应用没有读取".to_string())?;
    let env = &mut *guard;
    let context = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
    let pm = env
        .call_method(
            &context,
            "getPackageManager",
            "()Landroid/content/pm/PackageManager;",
            &[],
        )
        .and_then(|value| value.l())
        .map_err(|_| "已安装应用没有读取".to_string())?;
    let list = env
        .call_method(
            &pm,
            "getInstalledApplications",
            "(I)Ljava/util/List;",
            &[jni::objects::JValue::Int(0)],
        )
        .and_then(|value| value.l())
        .map_err(|_| {
            let _ = env.exception_clear();
            "已安装应用没有读取".to_string()
        })?;
    let size = env
        .call_method(&list, "size", "()I", &[])
        .and_then(|value| value.i())
        .map_err(|_| {
            let _ = env.exception_clear();
            "已安装应用没有读取".to_string()
        })?;
    let pm_raw = pm.as_raw();
    let list_raw = list.as_raw();
    let mut apps = Vec::new();
    for index in 0..size {
        let read = env.with_local_frame(
            16,
            |env| -> Result<Option<InstalledApp>, jni::errors::Error> {
                let pm = unsafe { jni::objects::JObject::from_raw(pm_raw) };
                let list = unsafe { jni::objects::JObject::from_raw(list_raw) };
                let info = env
                    .call_method(
                        &list,
                        "get",
                        "(I)Ljava/lang/Object;",
                        &[jni::objects::JValue::Int(index)],
                    )?
                    .l()?;
                let package_obj = env
                    .get_field(&info, "packageName", "Ljava/lang/String;")?
                    .l()?;
                let package_name = java_string(env, &package_obj)?;
                if package_name.is_empty() {
                    return Ok(None);
                }
                let label = env
                    .call_method(
                        &info,
                        "loadLabel",
                        "(Landroid/content/pm/PackageManager;)Ljava/lang/CharSequence;",
                        &[jni::objects::JValue::Object(&pm)],
                    )?
                    .l()?;
                let label_obj = env
                    .call_method(label, "toString", "()Ljava/lang/String;", &[])?
                    .l()?;
                let mut name = java_string(env, &label_obj)?;
                if name.trim().is_empty() {
                    name = package_name.clone();
                }
                Ok(Some(InstalledApp { name, package_name }))
            },
        );
        match read {
            Ok(Some(app)) => apps.push(app),
            Ok(None) => {}
            Err(_) => {
                let _ = env.exception_clear();
            }
        }
    }
    Ok(normalize_installed(apps))
}

#[cfg(target_os = "android")]
fn java_string(
    env: &mut jni::JNIEnv,
    object: &jni::objects::JObject,
) -> Result<String, jni::errors::Error> {
    let text = env.get_string(<&jni::objects::JString>::from(object))?;
    Ok(std::borrow::Cow::<str>::from(&*text).into_owned())
}

/// Kotlin reports the TUN fd after `VpnService.Builder.establish`.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_billow_client_BillowVpnBridge_nativeTunFd(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    fd: i32,
) {
    report_vpn_fd(fd);
}

/// Real HTTP/HTTPS system proxy. Unit tests use [`MemoryProxy`] instead.
#[derive(Debug, Default)]
pub struct HostSystemProxy;

impl SystemProxy for HostSystemProxy {
    fn set_http_https(&mut self, endpoint: &ProxyEndpoint) -> Result<(), String> {
        host_proxy::set(endpoint)
    }

    fn clear_if_pointing_at(&mut self, endpoint: &ProxyEndpoint) -> Result<(), String> {
        host_proxy::clear_if_matches(endpoint)
    }
}

pub fn host_proxy() -> HostSystemProxy {
    HostSystemProxy
}

pub fn host_tun() -> HostTun {
    HostTun::host()
}

pub fn host_vpn() -> HostVpn {
    HostVpn::host()
}

/// `networksetup -getwebproxy` text. Enabled must be Yes.
pub fn parse_macos_proxy(text: &str) -> Option<ProxyEndpoint> {
    let mut enabled = false;
    let mut server = None;
    let mut port = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("Enabled:") {
            enabled = value.trim().eq_ignore_ascii_case("yes");
        } else if let Some(value) = line.strip_prefix("Server:") {
            let host = value.trim();
            if !host.is_empty() {
                server = Some(host.to_string());
            }
        } else if let Some(value) = line.strip_prefix("Port:") {
            port = value.trim().parse::<u16>().ok().filter(|port| *port > 0);
        }
    }
    if !enabled {
        return None;
    }
    Some(ProxyEndpoint {
        host: server?,
        port: port?,
    })
}

fn parse_network_services(text: &str) -> Vec<String> {
    text.lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(str::to_string)
        .collect()
}

mod host_proxy {
    use super::ProxyEndpoint;

    pub fn set(endpoint: &ProxyEndpoint) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            return macos::set(endpoint);
        }
        #[cfg(target_os = "windows")]
        {
            return windows::set(endpoint);
        }
        #[cfg(all(target_os = "linux", not(target_os = "android")))]
        {
            return linux::set(endpoint);
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "windows",
            all(target_os = "linux", not(target_os = "android"))
        )))]
        {
            let _ = endpoint;
            Err("系统代理不可用".to_string())
        }
    }

    pub fn clear_if_matches(endpoint: &ProxyEndpoint) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            return macos::clear_if_matches(endpoint);
        }
        #[cfg(target_os = "windows")]
        {
            return windows::clear_if_matches(endpoint);
        }
        #[cfg(all(target_os = "linux", not(target_os = "android")))]
        {
            return linux::clear_if_matches(endpoint);
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "windows",
            all(target_os = "linux", not(target_os = "android"))
        )))]
        {
            let _ = endpoint;
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    mod macos {
        use std::process::Command;

        use super::super::{ProxyEndpoint, parse_macos_proxy, parse_network_services};

        pub fn set(endpoint: &ProxyEndpoint) -> Result<(), String> {
            let port = endpoint.port.to_string();
            for service in services()? {
                run(&["-setwebproxy", &service, &endpoint.host, &port, "off"])?;
                run(&["-setsecurewebproxy", &service, &endpoint.host, &port, "off"])?;
            }
            Ok(())
        }

        pub fn clear_if_matches(endpoint: &ProxyEndpoint) -> Result<(), String> {
            for service in services()? {
                if read_service(&service, false)?.as_ref() == Some(endpoint) {
                    run(&["-setwebproxystate", &service, "off"])?;
                }
                if read_service(&service, true)?.as_ref() == Some(endpoint) {
                    run(&["-setsecurewebproxystate", &service, "off"])?;
                }
            }
            Ok(())
        }

        fn services() -> Result<Vec<String>, String> {
            let text = run_text(&["-listallnetworkservices"])?;
            let services = parse_network_services(&text);
            if services.is_empty() {
                Err("系统代理没有打开".to_string())
            } else {
                Ok(services)
            }
        }

        fn read_service(service: &str, https: bool) -> Result<Option<ProxyEndpoint>, String> {
            let flag = if https {
                "-getsecurewebproxy"
            } else {
                "-getwebproxy"
            };
            let text = run_text(&[flag, service])?;
            Ok(parse_macos_proxy(&text))
        }

        fn run(args: &[&str]) -> Result<(), String> {
            let _ = run_text(args)?;
            Ok(())
        }

        fn run_text(args: &[&str]) -> Result<String, String> {
            let output = Command::new("networksetup")
                .args(args)
                .output()
                .map_err(|_| "系统代理没有打开".to_string())?;
            if !output.status.success() {
                return Err("系统代理没有打开".to_string());
            }
            String::from_utf8(output.stdout).map_err(|_| "系统代理没有打开".to_string())
        }
    }

    #[cfg(target_os = "windows")]
    mod windows {
        use std::process::Command;
        use std::os::windows::process::CommandExt;

        use super::super::ProxyEndpoint;

        const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        pub fn set(endpoint: &ProxyEndpoint) -> Result<(), String> {
            let server = format!("{}:{}", endpoint.host, endpoint.port);
            reg(&[
                "add",
                KEY,
                "/v",
                "ProxyServer",
                "/t",
                "REG_SZ",
                "/d",
                &server,
                "/f",
            ])?;
            reg(&[
                "add",
                KEY,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])?;
            Ok(())
        }

        pub fn clear_if_matches(endpoint: &ProxyEndpoint) -> Result<(), String> {
            let server = format!("{}:{}", endpoint.host, endpoint.port);
            let current = reg_query("ProxyServer");
            if current.as_deref() == Some(server.as_str()) {
                reg(&[
                    "add",
                    KEY,
                    "/v",
                    "ProxyEnable",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "0",
                    "/f",
                ])?;
            }
            Ok(())
        }

        fn reg(args: &[&str]) -> Result<(), String> {
            let status = Command::new("reg")
                .creation_flags(0x08000000)
                .args(args)
                .status()
                .map_err(|_| "系统代理没有打开".to_string())?;
            if status.success() {
                Ok(())
            } else {
                Err("系统代理没有打开".to_string())
            }
        }

        fn reg_query(name: &str) -> Option<String> {
            let output = Command::new("reg")
                .creation_flags(0x08000000)
                .args(["query", KEY, "/v", name])
                .output()
                .ok()?;
            let text = String::from_utf8(output.stdout).ok()?;
            for line in text.lines() {
                let mut parts = line.split_whitespace();
                if parts.next() == Some(name) {
                    return parts.nth(1).map(str::to_string);
                }
            }
            None
        }
    }

    #[cfg(all(target_os = "linux", not(target_os = "android")))]
    mod linux {
        use std::process::Command;

        use super::super::ProxyEndpoint;

        pub fn set(endpoint: &ProxyEndpoint) -> Result<(), String> {
            gsettings(&["set", "org.gnome.system.proxy", "mode", "manual"])?;
            gsettings(&["set", "org.gnome.system.proxy.http", "host", &endpoint.host])?;
            gsettings(&[
                "set",
                "org.gnome.system.proxy.http",
                "port",
                &endpoint.port.to_string(),
            ])?;
            gsettings(&[
                "set",
                "org.gnome.system.proxy.https",
                "host",
                &endpoint.host,
            ])?;
            gsettings(&[
                "set",
                "org.gnome.system.proxy.https",
                "port",
                &endpoint.port.to_string(),
            ])?;
            Ok(())
        }

        pub fn clear_if_matches(endpoint: &ProxyEndpoint) -> Result<(), String> {
            let http_host = gsettings_get(&["get", "org.gnome.system.proxy.http", "host"]);
            let http_port = gsettings_get(&["get", "org.gnome.system.proxy.http", "port"]);
            let https_host = gsettings_get(&["get", "org.gnome.system.proxy.https", "host"]);
            let https_port = gsettings_get(&["get", "org.gnome.system.proxy.https", "port"]);
            let port = endpoint.port.to_string();
            let host = format!("'{}'", endpoint.host);
            if http_host.as_deref() == Some(host.as_str())
                && http_port.as_deref() == Some(port.as_str())
            {
                gsettings(&["set", "org.gnome.system.proxy.http", "host", ""])?;
            }
            if https_host.as_deref() == Some(host.as_str())
                && https_port.as_deref() == Some(port.as_str())
            {
                gsettings(&["set", "org.gnome.system.proxy.https", "host", ""])?;
            }
            let mode = gsettings_get(&["get", "org.gnome.system.proxy", "mode"]);
            if mode.as_deref() == Some("'manual'")
                && gsettings_get(&["get", "org.gnome.system.proxy.http", "host"]).as_deref()
                    != Some(host.as_str())
                && gsettings_get(&["get", "org.gnome.system.proxy.https", "host"]).as_deref()
                    != Some(host.as_str())
            {
                gsettings(&["set", "org.gnome.system.proxy", "mode", "none"])?;
            }
            Ok(())
        }

        fn gsettings(args: &[&str]) -> Result<(), String> {
            let status = Command::new("gsettings")
                .args(args)
                .status()
                .map_err(|_| "系统代理没有打开".to_string())?;
            if status.success() {
                Ok(())
            } else {
                Err("系统代理没有打开".to_string())
            }
        }

        fn gsettings_get(args: &[&str]) -> Option<String> {
            let output = Command::new("gsettings").args(args).output().ok()?;
            if !output.status.success() {
                return None;
            }
            Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
        }
    }
}

/// The exclude file lives in the application data directory. On Android that is the files dir.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn excluded_file(directory: &Path) -> PathBuf {
    directory.join(EXCLUDE_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{KernelLaunch, ProfileBook, SubscriptionSource};
    use std::fs;

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(name: &str) -> TempDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "billow-takeover-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    struct UnusedSource;

    impl SubscriptionSource for UnusedSource {
        fn fetch(&self, _url: &str) -> Result<crate::profile::FetchedSubscription, String> {
            Err("订阅没有取回".to_string())
        }
    }

    struct TestKernel {
        fail: bool,
        calls: u32,
        last: String,
        alive: bool,
    }

    impl KernelLaunch for TestKernel {
        fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
            self.calls += 1;
            if self.fail {
                self.alive = false;
                return Err("内核没有启动".to_string());
            }
            self.last = config_yaml.to_string();
            self.alive = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.alive
        }
    }

    fn tun_enable(yaml: &str) -> Option<bool> {
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        value
            .get("tun")
            .and_then(|item| item.get("enable"))
            .and_then(|item| item.as_bool())
    }

    fn tun_fd(yaml: &str) -> Option<i64> {
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        value
            .get("tun")
            .and_then(|item| item.get("file-descriptor"))
            .and_then(|item| item.as_i64())
    }

    fn ready_book(dir: &Path, platform: ClientPlatform) -> (ProfileBook, TestKernel) {
        let mut book = ProfileBook::open(dir);
        book.set_platform(platform);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = TestKernel {
            fail: false,
            calls: 0,
            last: String::new(),
            alive: false,
        };
        book.enable("p1", &UnusedSource, &mut kernel);
        (book, kernel)
    }

    fn endpoint() -> ProxyEndpoint {
        ProxyEndpoint {
            host: "127.0.0.1".to_string(),
            port: 7890,
        }
    }

    #[test]
    fn desktop_connect_opens_system_proxy_and_leaves_tun_off_until_the_user_enables_it() {
        let dir = temp_dir("connect");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let snapshot = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(snapshot.system_proxy);
        assert!(!snapshot.tun);
        assert!(!snapshot.tun_wanted);
        assert!(snapshot.connected);
        assert!(!snapshot.vpn);
        assert!(snapshot.failure.is_none());
        assert_eq!(proxy.http.as_ref(), Some(&endpoint()));
        assert_eq!(proxy.https.as_ref(), Some(&endpoint()));
        assert!(!tun.enabled);
        assert_eq!(tun.authorize_calls, 0);
        assert_eq!(tun_enable(&kernel.last), Some(false));
        assert!(!vpn.open);

        tun.grant = true;
        let enabled = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert_eq!(tun_enable(&kernel.last), Some(true));
        assert!(enabled.tun);
        assert!(enabled.tun_wanted);
        assert!(enabled.system_proxy);
        assert!(enabled.connected);
        assert!(tun.enabled);
        assert_eq!(proxy.sets, 1);
    }

    #[test]
    fn tun_expectation_survives_disconnect_and_stays_off_after_the_user_closes_it() {
        let dir = temp_dir("remember");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        let disconnected = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!disconnected.system_proxy && !disconnected.tun && !disconnected.vpn);
        assert!(!disconnected.connected);
        assert!(disconnected.tun_wanted);
        assert!(proxy.http.is_none() && proxy.https.is_none());
        assert!(!tun.enabled);

        let again = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(again.system_proxy && again.tun && again.connected);
        assert!(tun.enabled);
        assert_eq!(proxy.http.as_ref(), Some(&endpoint()));

        book.set_tun(false, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        let closed = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(closed.system_proxy && closed.connected);
        assert!(!closed.tun && !closed.tun_wanted);
        assert!(!tun.enabled);

        let mut reopened = ProfileBook::open(&dir.0);
        reopened.set_platform(ClientPlatform::Desktop);
        assert!(!reopened.snapshot().tun_wanted);
    }

    #[test]
    fn wanted_tun_is_still_wanted_after_reopen() {
        let dir = temp_dir("reopen");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        let mut reopened = ProfileBook::open(&dir.0);
        reopened.set_platform(ClientPlatform::Desktop);
        assert!(reopened.snapshot().tun_wanted);
        assert!(!reopened.snapshot().system_proxy && !reopened.snapshot().tun);
        let mut kernel = TestKernel {
            fail: false,
            calls: 0,
            last: String::new(),
            alive: false,
        };
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let snapshot = reopened.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(snapshot.tun && snapshot.system_proxy && snapshot.connected);
    }

    #[test]
    fn denied_tun_fails_without_changing_the_previous_system_proxy() {
        let dir = temp_dir("deny-tun");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun {
            grant: false,
            ..MemoryTun::default()
        };
        let mut vpn = MemoryVpn::default();

        let denied = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!denied.connected);
        assert!(!denied.tun && !denied.tun_wanted);
        assert!(!denied.system_proxy);
        assert_eq!(denied.failure.as_deref(), Some(TUN_DENIED));
        assert!(proxy.http.is_none() && proxy.https.is_none());
        assert_eq!(proxy.sets, 0);
        assert!(!tun.enabled);

        tun.grant = true;
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        let sets = proxy.sets;
        tun.grant = false;
        let again = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(again.system_proxy);
        assert!(!again.tun);
        assert!(again.connected, "denying TUN keeps the working system proxy connected");
        assert_eq!(again.failure.as_deref(), Some(TUN_DENIED));
        assert_eq!(proxy.sets, sets);
        assert_eq!(proxy.http.as_ref(), Some(&endpoint()));
        assert_eq!(proxy.https.as_ref(), Some(&endpoint()));

        book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!book.snapshot().tun_wanted);
        tun.grant = true;
        book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        tun.grant = false;
        let sets = proxy.sets;
        let reconnect = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!reconnect.system_proxy && !reconnect.tun && !reconnect.connected);
        assert!(reconnect.tun_wanted);
        assert_eq!(reconnect.failure.as_deref(), Some(TUN_DENIED));
        assert_eq!(proxy.sets, sets);
        assert!(proxy.http.is_none() && proxy.https.is_none());
    }

    #[test]
    fn clear_leaves_a_system_proxy_that_no_longer_points_at_us() {
        let dir = temp_dir("clear");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        proxy.https = Some(ProxyEndpoint {
            host: "127.0.0.1".to_string(),
            port: 1,
        });
        book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(proxy.http.is_none());
        assert_eq!(proxy.https.as_ref().map(|item| item.port), Some(1));
    }

    #[test]
    fn android_starts_with_no_exclusions_and_keeps_an_excluded_package_out_of_vpn() {
        let dir = temp_dir("exclude");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Android);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn {
            grant: true,
            ..MemoryVpn::default()
        };
        assert!(book.snapshot().excluded.is_empty());
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.vpn && connected.connected);
        assert!(!connected.system_proxy && !connected.tun);
        assert!(vpn.last_excluded.is_empty());
        assert_eq!(proxy.sets, 0);
        assert_eq!(tun.authorize_calls, 0);

        let excluded = book.exclude_package("com.example.mail", &mut kernel, &mut vpn);
        assert_eq!(excluded.excluded, vec!["com.example.mail".to_string()]);
        assert_eq!(vpn.last_excluded, vec!["com.example.mail".to_string()]);
        assert!(
            !vpn.last_excluded
                .iter()
                .any(|item| item == "com.example.browser")
        );

        book.exclude_package("com.example.mail", &mut kernel, &mut vpn);
        assert_eq!(book.snapshot().excluded.len(), 1);
        book.exclude_package("  ", &mut kernel, &mut vpn);
        assert_eq!(book.snapshot().excluded.len(), 1);

        let desktop_dir = temp_dir("desktop-exclude");
        let mut desktop = ProfileBook::open(&desktop_dir.0);
        desktop.set_platform(ClientPlatform::Desktop);
        let mut idle_kernel = TestKernel {
            fail: false,
            calls: 0,
            last: String::new(),
            alive: false,
        };
        desktop.exclude_package("com.example.mail", &mut idle_kernel, &mut vpn);
        assert!(desktop.snapshot().excluded.is_empty());

        let mut reopened = ProfileBook::open(&dir.0);
        reopened.set_platform(ClientPlatform::Android);
        assert_eq!(
            reopened.snapshot().excluded,
            vec!["com.example.mail".to_string()]
        );
    }

    struct SequenceVpn {
        fds: Vec<i32>,
        cursor: usize,
        open: bool,
        establish_calls: u32,
        last_excluded: Vec<String>,
    }

    impl SequenceVpn {
        fn new(fds: Vec<i32>) -> Self {
            Self {
                fds,
                cursor: 0,
                open: false,
                establish_calls: 0,
                last_excluded: Vec::new(),
            }
        }
    }

    impl VpnGrant for SequenceVpn {
        fn authorize(&mut self) -> Result<bool, String> {
            Ok(true)
        }

        fn establish(&mut self, excluded: &[String]) -> Result<i32, String> {
            self.establish_calls += 1;
            self.last_excluded = excluded.to_vec();
            let fd = self.fds[self.cursor];
            self.cursor += 1;
            self.open = true;
            Ok(fd)
        }

        fn close(&mut self) -> Result<(), String> {
            self.open = false;
            Ok(())
        }
    }

    struct RejectingKernel {
        last: String,
    }

    impl KernelLaunch for RejectingKernel {
        fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
            self.last = config_yaml.to_string();
            Err("内核没有启动".to_string())
        }

        fn running(&mut self) -> bool {
            false
        }
    }

    #[test]
    fn connected_exclude_reloads_kernel_with_the_new_fd_and_the_saved_list() {
        let dir = temp_dir("exclude-fd");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Android);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = SequenceVpn::new(vec![7, 11, 13]);
        let calls = kernel.calls;

        let saved = book.exclude_package("com.example.mail", &mut kernel, &mut vpn);
        assert_eq!(saved.excluded, vec!["com.example.mail".to_string()]);
        assert!(!saved.vpn && !saved.connected);
        assert!(saved.failure.is_none());
        assert_eq!(vpn.establish_calls, 0);
        assert!(!vpn.open);
        assert_eq!(kernel.calls, calls);
        assert_eq!(proxy.sets, 0);

        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.vpn && connected.connected);
        assert_eq!(tun_fd(&kernel.last), Some(7));
        assert_eq!(vpn.last_excluded, vec!["com.example.mail".to_string()]);
        assert_eq!(proxy.sets, 0);

        let excluded = book.exclude_package("com.example.browser", &mut kernel, &mut vpn);
        assert!(excluded.vpn && excluded.connected);
        assert!(excluded.failure.is_none());
        assert_eq!(tun_fd(&kernel.last), Some(11));
        assert_eq!(
            excluded.excluded,
            vec![
                "com.example.mail".to_string(),
                "com.example.browser".to_string()
            ]
        );
        assert_eq!(vpn.last_excluded, excluded.excluded);
        assert!(vpn.open);

        let mut reopened = ProfileBook::open(&dir.0);
        reopened.set_platform(ClientPlatform::Android);
        assert_eq!(reopened.snapshot().excluded, excluded.excluded);

        let restored = book.include_package("com.example.browser", &mut kernel, &mut vpn);
        assert!(restored.vpn && restored.connected);
        assert!(restored.failure.is_none());
        assert_eq!(tun_fd(&kernel.last), Some(13));
        assert_eq!(restored.excluded, vec!["com.example.mail".to_string()]);
        assert_eq!(vpn.last_excluded, vec!["com.example.mail".to_string()]);
        assert!(vpn.open);
        assert_eq!(proxy.sets, 0);
    }

    #[test]
    fn excluding_while_connected_keeps_the_home_failure_and_hands_over_the_new_fd() {
        let dir = temp_dir("exclude-keeps-failure");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Android);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = SequenceVpn::new(vec![7, 11, 13, 15]);
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.vpn && connected.connected);
        assert!(connected.failure.is_none());
        assert_eq!(tun_fd(&kernel.last), Some(7));

        let marked = book.set_outbound_mode("nope", &mut kernel);
        assert_eq!(marked.failure.as_deref(), Some("模式没有切换"));
        assert!(marked.vpn && marked.connected);

        let excluded = book.exclude_package("com.example.mail", &mut kernel, &mut vpn);
        assert_eq!(tun_fd(&kernel.last), Some(11));
        assert_eq!(excluded.excluded, vec!["com.example.mail".to_string()]);
        assert_eq!(excluded.failure.as_deref(), Some("模式没有切换"));
        assert!(excluded.connected && excluded.vpn);
        assert_eq!(vpn.last_excluded, excluded.excluded);
        assert_eq!(proxy.sets, 0);

        let restored = book.include_package("com.example.mail", &mut kernel, &mut vpn);
        assert_eq!(tun_fd(&kernel.last), Some(13));
        assert!(restored.excluded.is_empty());
        assert_eq!(restored.failure.as_deref(), Some("模式没有切换"));
        assert!(restored.connected && restored.vpn);

        let again = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(again.connected && again.vpn);
        assert!(again.failure.is_none());
        assert_eq!(proxy.sets, 0);
    }

    #[test]
    fn failed_exclusion_reload_closes_vpn_and_is_not_connected() {
        let dir = temp_dir("exclude-reload-fail");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Android);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = SequenceVpn::new(vec![4, 8, 15, 16]);
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.vpn && connected.connected);
        assert_eq!(tun_fd(&kernel.last), Some(4));

        let mut rejecting = RejectingKernel {
            last: String::new(),
        };
        let failed = book.exclude_package("com.example.mail", &mut rejecting, &mut vpn);
        assert_eq!(tun_fd(&rejecting.last), Some(8));
        assert!(!failed.vpn && !failed.connected);
        assert_eq!(failed.failure.as_deref(), Some("内核没有启动"));
        assert!(!vpn.open);
        assert_eq!(failed.excluded, vec!["com.example.mail".to_string()]);
        assert_eq!(vpn.last_excluded, failed.excluded);
        assert_eq!(proxy.sets, 0);

        let again = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(again.vpn && again.connected);
        assert_eq!(tun_fd(&kernel.last), Some(15));
        assert_eq!(again.excluded, vec!["com.example.mail".to_string()]);
        assert_eq!(vpn.last_excluded, again.excluded);

        let mut rejecting = RejectingKernel {
            last: String::new(),
        };
        let restored = book.include_package("com.example.mail", &mut rejecting, &mut vpn);
        assert_eq!(tun_fd(&rejecting.last), Some(16));
        assert!(!restored.vpn && !restored.connected);
        assert_eq!(restored.failure.as_deref(), Some("内核没有启动"));
        assert!(!vpn.open);
        assert!(restored.excluded.is_empty());
        assert_eq!(proxy.sets, 0);
    }

    #[test]
    fn vpn_denial_or_a_missing_kernel_closes_vpn_and_is_not_connected() {
        let dir = temp_dir("vpn-deny");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Android);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn {
            grant: false,
            open: true,
            ..MemoryVpn::default()
        };
        let denied = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!denied.vpn && !denied.connected);
        assert_eq!(denied.failure.as_deref(), Some(VPN_DENIED));
        assert!(!vpn.open);
        assert_eq!(vpn.establish_calls, 0);

        vpn.grant = true;
        kernel.fail = true;
        let failed = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!failed.vpn && !failed.connected);
        assert!(!failed.system_proxy && !failed.tun);
        assert_eq!(failed.failure.as_deref(), Some("内核没有启动"));
        assert_eq!(vpn.establish_calls, 1);
        assert!(!vpn.open);
    }

    #[test]
    fn failed_vpn_establish_closes_and_does_not_show_connected() {
        let dir = temp_dir("vpn-start-fail");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Android);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = HostVpn::new(Box::new(RecordingVpn {
            grant: true,
            fail_start: true,
            ..RecordingVpn::default()
        }));
        let failed = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!failed.vpn && !failed.connected);
        assert!(!failed.system_proxy && !failed.tun);
        assert_eq!(failed.failure.as_deref(), Some("VPN 没有建立"));
        assert_eq!(vpn.calls(), ["prepare", "start"]);
    }

    #[test]
    fn written_vpn_fd_returns_without_burning_the_timeout() {
        clear_written_vpn_fd();
        let started = std::time::Instant::now();
        let missing = wait_for_written_vpn_fd(std::time::Duration::from_millis(80));
        assert_eq!(missing.unwrap_err(), "VPN 没有建立");
        assert!(started.elapsed() >= std::time::Duration::from_millis(40));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));

        report_vpn_fd(-1);
        let started = std::time::Instant::now();
        assert_eq!(
            wait_for_written_vpn_fd(std::time::Duration::from_secs(15)).unwrap_err(),
            "VPN 没有建立"
        );
        assert!(started.elapsed() < std::time::Duration::from_millis(500));

        clear_written_vpn_fd();
        report_vpn_fd(6);
        let started = std::time::Instant::now();
        assert_eq!(
            wait_for_written_vpn_fd(std::time::Duration::from_secs(15)).unwrap(),
            6
        );
        assert!(started.elapsed() < std::time::Duration::from_millis(500));

        clear_written_vpn_fd();
        let started = std::time::Instant::now();
        let waiting =
            std::thread::spawn(|| wait_for_written_vpn_fd(std::time::Duration::from_secs(15)));
        std::thread::sleep(std::time::Duration::from_millis(40));
        report_vpn_fd(9);
        assert_eq!(waiting.join().unwrap().unwrap(), 9);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        clear_written_vpn_fd();
    }

    #[test]
    fn desktop_kernel_failure_closes_system_proxy_and_tun() {
        let dir = temp_dir("kernel");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        kernel.fail = true;
        let failed = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!failed.system_proxy && !failed.tun && !failed.vpn);
        assert!(!failed.connected);
        assert!(proxy.http.is_none() && proxy.https.is_none());
        assert!(!tun.enabled);
        assert!(failed.tun_wanted);
    }

    #[test]
    fn macos_proxy_text_requires_an_enabled_server_and_port() {
        assert_eq!(
            parse_macos_proxy("Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n"),
            Some(endpoint())
        );
        assert!(parse_macos_proxy("Enabled: No\nServer: 127.0.0.1\nPort: 7890\n").is_none());
        assert!(parse_macos_proxy("Enabled: Yes\nServer: 127.0.0.1\nPort: 0\n").is_none());
        assert_eq!(
            parse_network_services(
                "An asterisk (*) denotes that a network service is disabled.\n*Disabled\nWi-Fi\n"
            ),
            vec!["Wi-Fi".to_string()]
        );
    }

    fn open_without_linux_node() -> TunEvidence {
        match TunHost::current() {
            TunHost::Linux => TunEvidence {
                linux_node: true,
                utun: false,
                windows: false,
            },
            TunHost::Macos => TunEvidence {
                linux_node: false,
                utun: true,
                windows: false,
            },
            TunHost::Windows => TunEvidence {
                linux_node: false,
                utun: false,
                windows: true,
            },
            TunHost::Other => TunEvidence {
                linux_node: false,
                utun: false,
                windows: false,
            },
        }
    }

    fn native_denial() -> TunEvidence {
        TunEvidence {
            linux_node: true,
            utun: false,
            windows: false,
        }
    }

    #[test]
    fn macos_and_windows_do_not_deny_tun_for_a_missing_linux_node() {
        let missing = TunEvidence {
            linux_node: false,
            utun: true,
            windows: true,
        };
        assert!(tun_allowed(TunHost::Macos, missing));
        assert!(tun_allowed(TunHost::Windows, missing));
        assert!(!tun_allowed(TunHost::Linux, missing));
        assert!(!tun_allowed(TunHost::Macos, native_denial()));
        assert!(!tun_allowed(TunHost::Windows, native_denial()));
        assert!(tun_allowed(TunHost::Linux, native_denial()));
        assert!(!linux_tun_node_open() || cfg!(target_os = "linux"));

        let evidence = open_without_linux_node();
        if matches!(TunHost::current(), TunHost::Macos | TunHost::Windows) {
            assert!(!evidence.linux_node);
        }
        let mut tun = HostTun::with_evidence(open_without_linux_node);
        assert!(tun.authorize().unwrap());
        let mut denied = HostTun::with_evidence(native_denial);
        assert!(!denied.authorize().unwrap());
        assert_eq!(
            HostTun::host().authorize().unwrap(),
            tun_allowed(TunHost::current(), live_tun_evidence())
        );
    }

    #[test]
    fn windows_grant_follows_wintun_open_and_not_token_elevation() {
        let closed = WindowsTunProbe {
            elevated: true,
            created_or_opened: false,
        };
        let opened = WindowsTunProbe {
            elevated: false,
            created_or_opened: true,
        };
        assert!(!windows_tun_granted(closed));
        assert!(windows_tun_granted(opened));
        assert_eq!(
            windows_tun_granted(WindowsTunProbe {
                elevated: true,
                created_or_opened: true,
            }),
            windows_tun_granted(opened)
        );
        assert_eq!(
            windows_tun_granted(WindowsTunProbe {
                elevated: false,
                created_or_opened: false,
            }),
            windows_tun_granted(closed)
        );
        assert!(!tun_allowed(
            TunHost::Windows,
            TunEvidence {
                linux_node: false,
                utun: false,
                windows: windows_tun_granted(closed),
            }
        ));
        assert!(tun_allowed(
            TunHost::Windows,
            TunEvidence {
                linux_node: false,
                utun: false,
                windows: windows_tun_granted(opened),
            }
        ));
        #[cfg(not(target_os = "windows"))]
        assert!(!wintun_create_or_open());

        let source = include_str!("takeover.rs");
        assert!(!source.contains(&["TOKEN_", "ELEVATION"].concat()));
        assert!(!source.contains(&["Open", "Process", "Token"].concat()));
        assert!(source.contains("WintunCreateAdapter"));
        assert!(source.contains("WintunOpenAdapter"));
        assert!(source.contains("com.apple.net.utun_control"));

        let dir = temp_dir("wintun-grant");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun {
            grant: windows_tun_granted(closed),
            ..MemoryTun::default()
        };
        let mut vpn = MemoryVpn::default();
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        let denied = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(denied.connected && !denied.tun);
        assert!(denied.system_proxy);
        assert_eq!(denied.failure.as_deref(), Some(TUN_DENIED));
        assert_eq!(proxy.http.as_ref(), Some(&endpoint()));

        tun.grant = windows_tun_granted(opened);
        let allowed = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(allowed.tun && allowed.connected && allowed.system_proxy);
        assert_eq!(allowed.failure.as_deref(), Some(TUN_DENIED));
        assert_eq!(proxy.http.as_ref(), Some(&endpoint()));
    }

    #[test]
    fn host_adapter_reloads_tun_and_can_deny_authorization() {
        let dir = temp_dir("host-tun");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local(
            "a.yaml",
            "mixed-port: 7890\nmode: rule\ntun:\n  enable: true\n",
        );
        let mut kernel = TestKernel {
            fail: false,
            calls: 0,
            last: String::new(),
            alive: false,
        };
        book.enable("p1", &UnusedSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = HostTun::with_evidence(open_without_linux_node);
        let mut vpn = MemoryVpn::default();
        let first = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(first.system_proxy && first.connected);
        assert!(!first.tun);
        assert_eq!(tun_enable(&kernel.last), Some(false));
        assert_eq!(proxy.http.as_ref(), Some(&endpoint()));

        book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert_eq!(tun_enable(&kernel.last), Some(true));
        assert!(tun.authorize().unwrap());
        let mut denied = HostTun::with_evidence(native_denial);
        let previous = proxy.sets;
        let rejected = book.set_tun(true, &mut kernel, &mut proxy, &mut denied, &mut vpn);
        assert!(rejected.connected && rejected.tun, "denied redundant enable preserves the existing TUN");
        assert!(rejected.system_proxy);
        assert_eq!(proxy.sets, previous);
        assert_eq!(tun_enable(&kernel.last), Some(true));
    }

    #[test]
    fn host_vpn_prepares_then_starts_and_hands_the_fd_to_the_kernel() {
        let dir = temp_dir("host-vpn");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Android);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = HostVpn::new(Box::new(RecordingVpn::granted()));
        let snapshot = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(snapshot.vpn && snapshot.connected);
        assert_eq!(vpn.calls(), ["prepare", "start"]);
        assert_eq!(tun_fd(&kernel.last), Some(42));
        assert!(vpn.last_excluded().is_empty());

        let mut denied = HostVpn::new(Box::new(RecordingVpn::default()));
        let rejected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut denied);
        assert!(!rejected.vpn && !rejected.connected);
        assert_eq!(denied.calls(), ["prepare"]);
    }

    #[test]
    fn installed_app_search_keeps_spaced_names_and_ignores_the_query_text() {
        let apps = vec![
            InstalledApp {
                name: "电子 邮箱".to_string(),
                package_name: "com.example.mail".to_string(),
            },
            InstalledApp {
                name: "浏览器".to_string(),
                package_name: "com.example.browser".to_string(),
            },
        ];
        let matched = filter_installed(&apps, "浏览器");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].package_name, "com.example.browser");
        assert!(filter_installed(&apps, "不存在的原文").is_empty());
        let spaced = filter_installed(&apps, "电子");
        assert_eq!(spaced.len(), 1);
        assert_eq!(spaced[0].name, "电子 邮箱");
        assert!(spaced[0].name.contains(' '));

        let dir = temp_dir("apps");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Android);
        book.set_installed(apps);
        let mut vpn = MemoryVpn {
            grant: true,
            ..MemoryVpn::default()
        };
        book.exclude_package("com.example.mail", &mut kernel, &mut vpn);
        assert_eq!(
            book.snapshot().excluded,
            vec!["com.example.mail".to_string()]
        );
        assert!(
            book.matching_installed("电子")
                .iter()
                .any(|app| app.name == "电子 邮箱")
        );
        book.connect(
            &mut kernel,
            &mut MemoryProxy::default(),
            &mut MemoryTun::default(),
            &mut vpn,
        );
        assert_eq!(vpn.last_excluded, vec!["com.example.mail".to_string()]);
    }

    struct StickyProxy {
        inner: MemoryProxy,
        fail_clear: bool,
    }

    impl SystemProxy for StickyProxy {
        fn set_http_https(&mut self, endpoint: &ProxyEndpoint) -> Result<(), String> {
            self.inner.set_http_https(endpoint)
        }

        fn clear_if_pointing_at(&mut self, endpoint: &ProxyEndpoint) -> Result<(), String> {
            if self.fail_clear {
                return Err("系统代理没有关闭".to_string());
            }
            self.inner.clear_if_pointing_at(endpoint)
        }
    }

    #[test]
    fn failed_proxy_clear_keeps_the_switch_and_startup_retries() {
        let dir = temp_dir("sticky");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = StickyProxy {
            inner: MemoryProxy::default(),
            fail_clear: false,
        };
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let opened = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(opened.system_proxy);
        assert_eq!(proxy.inner.http.as_ref(), Some(&endpoint()));
        proxy.fail_clear = true;
        let stuck = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(stuck.system_proxy);
        assert!(!stuck.tun);
        assert_eq!(stuck.failure.as_deref(), Some("系统代理没有关闭"));
        assert_eq!(proxy.inner.http.as_ref(), Some(&endpoint()));
        assert_eq!(tun_enable(&kernel.last), Some(false));

        let mut reopened = ProfileBook::open(&dir.0);
        reopened.release_lingering_proxy(&mut proxy);
        assert!(reopened.snapshot().system_proxy);
        assert_eq!(
            reopened.snapshot().failure.as_deref(),
            Some("系统代理没有关闭")
        );
        proxy.fail_clear = false;
        reopened.release_lingering_proxy(&mut proxy);
        assert!(!reopened.snapshot().system_proxy);
        assert!(proxy.inner.http.is_none());
    }

    #[test]
    fn android_vpn_service_establishes_tun_and_reports_consent() {
        let source =
            include_str!("../gen/android/app/src/main/java/app/billow/client/BillowVpnService.kt");
        assert!(source.contains("VpnService"));
        assert!(source.contains("addDisallowedApplication"));
        assert!(source.contains("nativeConsent"));
        assert!(source.contains("nativeTunFd"));
        assert!(source.contains("prepare"));
        assert!(source.contains("start"));
        assert!(source.contains("BillowVpnBridge"));
        assert!(!source.to_ascii_lowercase().contains("mihomo"));
        let manifest = include_str!("../gen/android/app/src/main/AndroidManifest.xml");
        assert!(manifest.contains("android.net.VpnService"));
        assert!(manifest.contains("BIND_VPN_SERVICE"));
        assert!(manifest.contains("BillowVpnService"));
        assert!(manifest.contains("QUERY_ALL_PACKAGES"));
        let activity =
            include_str!("../gen/android/app/src/main/java/app/billow/client/MainActivity.kt");
        assert!(activity.contains("BillowVpnBridge.onActivityResult"));
    }

    #[test]
    fn jni_consent_symbol_is_billow_vpn_bridge() {
        let rust = include_str!("takeover.rs");
        let bridge = [
            "fn Java_app_billow_client_",
            "BillowVpnBridge_nativeConsent",
        ]
        .concat();
        let service = [
            "fn Java_app_billow_client_",
            "BillowVpnService_nativeConsent",
        ]
        .concat();
        assert!(rust.contains(&bridge));
        assert!(!rust.contains(&service));
        let kotlin =
            include_str!("../gen/android/app/src/main/java/app/billow/client/BillowVpnService.kt");
        assert!(kotlin.contains("class BillowVpnBridge"));
        assert!(kotlin.contains("external fun nativeConsent"));
        assert!(kotlin.contains("fun onActivityResult"));
    }

    struct FixedInstalled(Vec<InstalledApp>);

    impl InstalledApps for FixedInstalled {
        fn list(&mut self) -> Result<Vec<InstalledApp>, String> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn installed_apps_enter_the_android_snapshot() {
        let apps = vec![
            InstalledApp {
                name: "电子 邮箱".to_string(),
                package_name: "com.example.mail".to_string(),
            },
            InstalledApp {
                name: "浏览器".to_string(),
                package_name: "com.example.browser".to_string(),
            },
        ];
        let normalized = normalize_installed(apps.clone());
        assert_eq!(
            normalized
                .iter()
                .find(|app| app.package_name == "com.example.mail")
                .unwrap()
                .name,
            "电子 邮箱"
        );
        let dir = temp_dir("installed-snapshot");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        let mut source = FixedInstalled(apps);
        book.refresh_installed(&mut source);
        let snapshot = book.snapshot();
        assert_eq!(snapshot.installed.len(), 2);
        assert!(
            snapshot
                .installed
                .iter()
                .any(|app| app.name == "电子 邮箱" && app.package_name == "com.example.mail")
        );
        assert!(
            book.matching_installed("浏览器")
                .iter()
                .all(|app| app.package_name == "com.example.browser")
        );
        assert!(book.matching_installed("不存在的原文").is_empty());
        assert!(
            book.matching_installed("电子")
                .iter()
                .any(|app| app.name == "电子 邮箱")
        );

        book.set_platform(ClientPlatform::Desktop);
        book.refresh_installed(&mut source);
        assert!(book.snapshot().installed.is_empty());
        let wiring = include_str!("lib.rs");
        assert!(wiring.contains("refresh_installed"));
        assert!(wiring.contains("HostInstalledApps"));
    }

    #[test]
    fn fail_kernel_keeps_system_proxy_and_endpoint_when_clear_fails() {
        let mut model = LinkModel {
            platform: ClientPlatform::Desktop,
            tun_wanted: true,
            excluded: Vec::new(),
            system_proxy: true,
            tun: true,
            vpn: false,
            connected: true,
            failure: None,
            endpoint: Some(endpoint()),
        };
        let mut proxy = StickyProxy {
            inner: MemoryProxy {
                http: Some(endpoint()),
                https: Some(endpoint()),
                sets: 1,
            },
            fail_clear: true,
        };
        let mut tun = MemoryTun {
            grant: true,
            enabled: true,
            authorize_calls: 0,
        };
        let mut vpn = MemoryVpn::default();
        let cleared = release_platform(
            &mut proxy,
            &mut tun,
            &mut vpn,
            &PlatformRelease {
                endpoint: Some(endpoint()),
                close_tun: true,
                close_vpn: false,
            },
        );
        assert!(!cleared);
        assert!(proxy.inner.http.as_ref() == Some(&endpoint()));
        assert!(!tun.enabled);

        tun.enabled = true;
        fail_kernel(
            &mut model,
            &mut proxy,
            &mut tun,
            &mut vpn,
            "内核没有启动".to_string(),
        );
        assert!(model.system_proxy);
        assert_eq!(model.endpoint.as_ref(), Some(&endpoint()));
        assert!(!model.connected);
        assert!(!model.tun && !model.vpn);
        assert_eq!(model.failure.as_deref(), Some("内核没有启动"));
        assert_eq!(proxy.inner.http.as_ref(), Some(&endpoint()));

        proxy.fail_clear = false;
        fail_kernel(
            &mut model,
            &mut proxy,
            &mut tun,
            &mut vpn,
            "内核没有启动".to_string(),
        );
        assert!(!model.system_proxy);
        assert!(model.endpoint.is_none());
        assert!(proxy.inner.http.is_none() && proxy.inner.https.is_none());

        let dir = temp_dir("fail-kernel-sticky");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = StickyProxy {
            inner: MemoryProxy::default(),
            fail_clear: false,
        };
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        proxy.fail_clear = true;
        kernel.fail = true;
        let failed = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(failed.system_proxy);
        assert!(!failed.connected);
        assert!(!failed.tun);
        assert_eq!(failed.failure.as_deref(), Some("内核没有启动"));
        assert_eq!(proxy.inner.http.as_ref(), Some(&endpoint()));
        let mut reopened = ProfileBook::open(&dir.0);
        reopened.release_lingering_proxy(&mut proxy);
        assert!(reopened.snapshot().system_proxy);
        proxy.fail_clear = false;
        reopened.release_lingering_proxy(&mut proxy);
        assert!(!reopened.snapshot().system_proxy);
        assert!(proxy.inner.http.is_none());
    }

    #[test]
    fn set_tun_kernel_failure_keeps_proxy_when_clear_fails() {
        let dir = temp_dir("set-tun-sticky");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = StickyProxy {
            inner: MemoryProxy::default(),
            fail_clear: false,
        };
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        proxy.fail_clear = true;
        kernel.fail = true;
        let failed = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(failed.system_proxy);
        assert!(!failed.connected);
        assert!(!failed.tun);
        assert_eq!(proxy.inner.http.as_ref(), Some(&endpoint()));
        let mut reopened = ProfileBook::open(&dir.0);
        reopened.release_lingering_proxy(&mut proxy);
        assert!(reopened.snapshot().system_proxy);
    }

    #[test]
    fn fail_activation_keeps_proxy_and_endpoint_when_clear_fails() {
        let dir = temp_dir("activation-sticky");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = StickyProxy {
            inner: MemoryProxy::default(),
            fail_clear: false,
        };
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let opened = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(opened.system_proxy);
        proxy.fail_clear = true;
        kernel.fail = true;
        book.add_local("other.yaml", "mixed-port: 7891\nmode: rule\n");
        let mid = book.enable("p2", &UnusedSource, &mut kernel);
        assert!(mid.system_proxy);
        assert!(!mid.connected);
        book.apply_release(&mut proxy, &mut tun, &mut vpn);
        let failed = book.snapshot();
        assert!(failed.system_proxy);
        assert!(!failed.tun && !failed.vpn && !failed.connected);
        assert_eq!(proxy.inner.http.as_ref(), Some(&endpoint()));
        let mut reopened = ProfileBook::open(&dir.0);
        reopened.release_lingering_proxy(&mut proxy);
        assert!(reopened.snapshot().system_proxy);
        proxy.fail_clear = false;
        reopened.release_lingering_proxy(&mut proxy);
        assert!(!reopened.snapshot().system_proxy);
        assert!(proxy.inner.http.is_none());
    }

    #[test]
    fn session_commands_are_exposed() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>();
        for permission in [
            "allow-connect-session",
            "allow-disconnect-session",
            "allow-set-system-proxy",
            "allow-set-tun-enabled",
            "allow-exclude-package",
            "allow-include-package",
        ] {
            assert!(permissions.contains(&permission), "{permission}");
        }
    }
}
