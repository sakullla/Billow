use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Condvar, Mutex};

use serde::{Deserialize, Serialize};

pub const TUN_DENIED: &str = "系统授权被拒绝";
/// Machine sentinel for a cancelled TUN authorization prompt. ASCII on purpose:
/// it is matched as a protocol token, never as user-visible text (T8).
pub const TUN_AUTHORIZATION_FAILED: &str = "tun-authorization-failed";
pub const VPN_DENIED: &str = "VPN 授权被拒绝";
pub const NO_PROFILE: &str = "没有生效配置";
pub const DEFAULT_PROXY_HOST: &str = "127.0.0.1";
pub const DEFAULT_PAC_SCRIPT: &str = "function FindProxyForURL(url, host) {\n  if (isPlainHostName(host) || shExpMatch(host, '*.local') || host === 'localhost' || host === '127.0.0.1' || host === '::1') {\n    return 'DIRECT';\n  }\n  return 'PROXY %proxy-host%:%mixed-port%; SOCKS5 %proxy-host%:%mixed-port%; DIRECT';\n}\n";
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const EXCLUDE_FILE: &str = "vpn-excluded.txt";

pub fn default_proxy_bypass() -> Vec<String> {
    [
        "localhost",
        "127.*",
        "192.168.*",
        "10.*",
        "172.16.*",
        "172.17.*",
        "172.18.*",
        "172.19.*",
        "172.20.*",
        "172.21.*",
        "172.22.*",
        "172.23.*",
        "172.24.*",
        "172.25.*",
        "172.26.*",
        "172.27.*",
        "172.28.*",
        "172.29.*",
        "172.30.*",
        "172.31.*",
        "*.local",
        "<local>",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

pub fn normalize_proxy_host(raw: &str) -> String {
    let trimmed: String = raw
        .trim()
        .chars()
        .filter(|ch| !ch.is_control() && !ch.is_whitespace())
        .take(128)
        .collect();
    if trimmed.is_empty() {
        DEFAULT_PROXY_HOST.to_string()
    } else {
        trimmed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SystemProxySettings {
    /// Custom proxy host; empty means `127.0.0.1`.
    pub host: String,
    /// `"manual"` or `"pac"`.
    pub mode: String,
    /// Custom PAC script template (`%proxy-host%` and `%mixed-port%` are expanded).
    pub pac_script: String,
    /// Domains/IP ranges that bypass system proxy in manual mode.
    pub bypass: Vec<String>,
}

impl Default for SystemProxySettings {
    fn default() -> Self {
        Self {
            host: String::new(),
            mode: "manual".to_string(),
            pac_script: DEFAULT_PAC_SCRIPT.to_string(),
            bypass: default_proxy_bypass(),
        }
    }
}

impl SystemProxySettings {
    pub fn normalized(mut self) -> Self {
        let host: String = self
            .host
            .trim()
            .chars()
            .filter(|ch| !ch.is_control() && !ch.is_whitespace())
            .take(128)
            .collect();
        self.host = if host == DEFAULT_PROXY_HOST { String::new() } else { host };
        self.mode = if self.mode.trim().eq_ignore_ascii_case("pac") {
            "pac".to_string()
        } else {
            "manual".to_string()
        };
        let script = self.pac_script.trim();
        if script.is_empty() {
            self.pac_script = DEFAULT_PAC_SCRIPT.to_string();
        } else {
            self.pac_script = self.pac_script.chars().take(32_768).collect();
        }
        let mut bypass = Vec::new();
        for item in self.bypass {
            let clean: String = item
                .trim()
                .chars()
                .filter(|ch| !ch.is_control() && !ch.is_whitespace() && *ch != ';')
                .take(200)
                .collect();
            if !clean.is_empty() && !bypass.contains(&clean) {
                bypass.push(clean);
            }
            if bypass.len() >= 256 {
                break;
            }
        }
        self.bypass = bypass;
        self
    }

    pub fn effective_host(&self) -> String {
        normalize_proxy_host(&self.host)
    }
}

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
    fn configure(&mut self, _settings: &SystemProxySettings) {}
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
    fn establish(&mut self, filter: &AppFilter) -> Result<i32, String>;
    fn close(&mut self) -> Result<(), String>;
}

/// Which apps the Android VPN carries. `only` lists the apps that use the VPN
/// (allowlist); otherwise `packages` bypass it. An allowlist with nothing in it
/// would route every app on Android, so it degrades to "bypass nothing".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppFilter {
    pub only: bool,
    pub packages: Vec<String>,
}

impl AppFilter {
    pub fn bypassed(&self) -> &[String] {
        if self.only { &[] } else { &self.packages }
    }
}

pub const APP_MODE_EXCLUDE: &str = "exclude";
pub const APP_MODE_INCLUDE: &str = "include";

pub fn normalize_app_mode(mode: &str) -> &'static str {
    if mode == APP_MODE_INCLUDE { APP_MODE_INCLUDE } else { APP_MODE_EXCLUDE }
}

/// Trimmed, de-duplicated package names in first-seen order.
pub fn clean_packages(packages: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for package in packages {
        if let Some(clean) = clean_package(package) {
            if !out.contains(&clean) {
                out.push(clean);
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstalledApp {
    pub name: String,
    pub package_name: String,
    /// Preinstalled system app; the list hides these by default.
    #[serde(default)]
    pub system: bool,
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
        out.push(InstalledApp { name, package_name, system: app.system });
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
    /// Allowlist used when `app_mode` is include.
    pub included: Vec<String>,
    pub app_mode: String,
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
    set_system_proxy_with_settings(
        model,
        enabled,
        port,
        &SystemProxySettings::default(),
        proxy,
    );
}

pub fn set_system_proxy_with_settings(
    model: &mut LinkModel,
    enabled: bool,
    port: Option<u16>,
    settings: &SystemProxySettings,
    proxy: &mut dyn SystemProxy,
) {
    if model.platform != ClientPlatform::Desktop {
        return;
    }
    if !enabled {
        if !clear_owned(model, proxy) {
            model.connected = model.system_proxy || model.tun;
            return;
        }
        model.system_proxy = false;
        model.connected = model.tun;
        return;
    }
    let Some(port) = port else {
        model.system_proxy = false;
        model.connected = model.tun;
        model.failure = Some("没有本地端口".to_string());
        return;
    };
    proxy.configure(settings);
    if open_proxy(model, &settings.effective_host(), port, proxy) {
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
        if model.failure.as_deref() == Some(crate::i18n::tr(crate::i18n::Key::TunDenied)) {
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
        model.failure = Some(crate::i18n::tr(crate::i18n::Key::TunDenied).to_string());
        return;
    }
    model.tun = true;
    model.tun_wanted = true;
    model.connected = true;
}

impl LinkModel {
    pub fn app_filter(&self) -> AppFilter {
        if self.app_mode == APP_MODE_INCLUDE && !self.included.is_empty() {
            AppFilter { only: true, packages: self.included.clone() }
        } else {
            AppFilter { only: false, packages: self.excluded.clone() }
        }
    }
}

/// Replace the app list of one mode and make that mode current; re-establishes a live VPN.
pub fn set_app_rules(
    model: &mut LinkModel,
    mode: &str,
    packages: &[String],
    vpn: &mut dyn VpnGrant,
) -> Option<i32> {
    if model.platform != ClientPlatform::Android {
        return None;
    }
    let mode = normalize_app_mode(mode);
    let before = model.app_filter();
    let clean = clean_packages(packages);
    model.app_mode = mode.to_string();
    if mode == APP_MODE_INCLUDE {
        model.included = clean;
    } else {
        model.excluded = clean;
    }
    if model.app_filter() == before {
        return None;
    }
    refresh_vpn(model, vpn)
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
    match vpn.establish(&model.app_filter()) {
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

fn open_proxy(model: &mut LinkModel, host: &str, port: u16, proxy: &mut dyn SystemProxy) -> bool {
    let endpoint = ProxyEndpoint {
        host: normalize_proxy_host(host),
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
    pub settings: Option<SystemProxySettings>,
    pub sets: u32,
}

impl SystemProxy for MemoryProxy {
    fn configure(&mut self, settings: &SystemProxySettings) {
        self.settings = Some(settings.clone());
    }

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
    pub last_filter: AppFilter,
    pub establish_calls: u32,
}

impl VpnGrant for MemoryVpn {
    fn authorize(&mut self) -> Result<bool, String> {
        Ok(self.grant)
    }

    fn establish(&mut self, filter: &AppFilter) -> Result<i32, String> {
        self.establish_calls += 1;
        self.last_excluded = filter.bypassed().to_vec();
        self.last_filter = filter.clone();
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

/// Desktop TUN authorization. Windows defers consent to the managed kernel
/// supervisor; macOS authorizes the core binary. Other hosts use their own probe.
pub struct HostTun {
    evidence: fn() -> TunEvidence,
    enabled: bool,
    kernel_path: Option<PathBuf>,
}

impl HostTun {
    pub fn host() -> Self {
        Self {
            evidence: live_tun_evidence,
            enabled: false,
            kernel_path: None,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_evidence(evidence: fn() -> TunEvidence) -> Self {
        Self {
            evidence,
            enabled: false,
            kernel_path: None,
        }
    }

    pub fn set_kernel_path(&mut self, path: Option<PathBuf>) {
        self.kernel_path = path;
    }
}

impl Default for HostTun {
    fn default() -> Self {
        Self::host()
    }
}

pub fn unix_mode_has_setuid_root(uid: u32, mode: u32) -> bool {
    uid == 0 && (mode & 0o4000) != 0 && (mode & 0o0111) != 0
}

pub fn build_macos_tun_grant_applescript(kernel_path: &Path) -> Result<String, String> {
    let raw = kernel_path
        .to_str()
        .filter(|text| !text.is_empty() && !text.contains('\0') && !text.contains('\n') && !text.contains('\r'))
        .ok_or_else(|| "内核路径包含无效字符，无法请求系统授权".to_string())?;
    let shell_quoted = format!("'{}'", raw.replace('\'', "'\\''"));
    let shell_cmd = format!(
        "xattr -d com.apple.quarantine {shell_quoted} >/dev/null 2>&1 || true; chown root:admin {shell_quoted} && chmod u+s,g+s,a+rx {shell_quoted}"
    );
    let apple_escaped = shell_cmd.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!(
        "do shell script \"{apple_escaped}\" with administrator privileges"
    ))
}

#[cfg(target_os = "macos")]
pub fn macos_kernel_has_setuid_root(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .ok()
        .filter(|meta| meta.is_file())
        .is_some_and(|meta| unix_mode_has_setuid_root(meta.uid(), meta.mode()))
}

#[cfg(target_os = "macos")]
fn macos_authorize_kernel(path: &Path) -> Result<bool, String> {
    if !path.is_file() {
        return Err("还没有可用内核，请先等待内核准备完成".to_string());
    }
    if macos_kernel_has_setuid_root(path) {
        return Ok(true);
    }
    let script = build_macos_tun_grant_applescript(path)?;
    let output = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output()
        .map_err(|error| format!("无法拉起 macOS 系统授权弹窗：{error}"))?;
    if output.status.success() {
        if macos_kernel_has_setuid_root(path) {
            return Ok(true);
        }
        return Err("macOS TUN 授权未生效，请检查系统安全设置".to_string());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stderr} {stdout}");
    let lower = combined.to_ascii_lowercase();
    if lower.contains("-128")
        || lower.contains("user canceled")
        || lower.contains("user cancelled")
        || combined.contains("取消")
    {
        return Ok(false);
    }
    let detail = stderr.trim();
    if detail.is_empty() {
        Ok(false)
    } else {
        Err(format!("macOS TUN 授权失败：{detail}"))
    }
}

impl TunGrant for HostTun {
    fn authorize(&mut self) -> Result<bool, String> {
        // Windows elevates only the kernel supervisor at launch. Creating and
        // immediately deleting a probe adapter here duplicates expensive driver
        // setup; the actual kernel's listener check verifies the resulting TUN.
        #[cfg(target_os = "windows")]
        if let Some(path) = &self.kernel_path {
            return if path.is_file() { Ok(true) } else {
                Err("还没有可用内核，请先等待内核准备完成".to_string())
            };
        }
        // Opening a utun in the app does not grant the separately launched kernel
        // permission to configure its interface and routes.
        #[cfg(target_os = "macos")]
        if let Some(path) = self.kernel_path.clone() {
            return macos_authorize_kernel(&path);
        }
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
    fn start(&mut self, filter: &AppFilter) -> Result<i32, String>;
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

    fn establish(&mut self, filter: &AppFilter) -> Result<i32, String> {
        self.calls.push("start".to_string());
        self.last_excluded = filter.bypassed().to_vec();
        let fd = self.bridge.start(filter)?;
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

    fn start(&mut self, filter: &AppFilter) -> Result<i32, String> {
        self.calls.push("start".to_string());
        self.excluded = filter.bypassed().to_vec();
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

    fn start(&mut self, filter: &AppFilter) -> Result<i32, String> {
        #[cfg(target_os = "android")]
        {
            return android_start(filter);
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = filter;
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
static VPN_CONSENT_READY: AtomicBool = AtomicBool::new(false);
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
static VPN_FD: AtomicI32 = AtomicI32::new(-1);
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
static VPN_FD_READY: AtomicBool = AtomicBool::new(false);
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
static VPN_READY: Condvar = Condvar::new();
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
static VPN_LOCK: Mutex<()> = Mutex::new(());

#[cfg(target_os = "android")]
pub fn inherit_vpn_tunnel(command: &mut std::process::Command, configured_fd: Option<i64>) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let fd = VPN_FD.load(Ordering::SeqCst);
    if fd < 0 || configured_fd != Some(i64::from(fd)) {
        return Err("VPN 没有建立".to_string());
    }
    // Only the kernel that uses this tunnel may inherit it. An idle kernel started
    // during disconnect would otherwise keep Android's VPN and its service bound.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

// Rust worker threads attach with the system class loader. Resolve our bridge through
// the Activity's loader, otherwise FindClass throws and terminates the app on connect.
#[cfg(target_os = "android")]
fn android_class<'local>(
    env: &mut jni::JNIEnv<'local>,
    activity: &jni::objects::JObject<'_>,
    name: &str,
) -> Result<jni::objects::JClass<'local>, String> {
    let result = (|| -> jni::errors::Result<jni::objects::JClass<'local>> {
        let loader = env.call_method(activity, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?.l()?;
        let class_name = env.new_string(name)?;
        let class = env.call_method(&loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", &[jni::objects::JValue::Object(&class_name)])?.l()?;
        Ok(jni::objects::JClass::from(class))
    })();
    result.map_err(|error| {
        let _ = env.exception_clear();
        format!("Android 桥接不可用：{error}")
    })
}

#[cfg(target_os = "android")]
fn vpn_bridge_class<'local>(env: &mut jni::JNIEnv<'local>, activity: &jni::objects::JObject<'_>) -> Result<jni::objects::JClass<'local>, String> {
    android_class(env, activity, "app.billow.client.BillowVpnBridge")
}

#[cfg(target_os = "android")]
fn android_prepare() -> Result<bool, String> {
    VPN_CONSENT.store(false, Ordering::SeqCst);
    VPN_CONSENT_READY.store(false, Ordering::SeqCst);
    // BillowVpnBridge.prepare shows the system dialog and reports back through nativeConsent.
    let ctx = ndk_context::android_context();
    let vm =
        unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }.map_err(|_| "VPN 不可用".to_string())?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|_| "VPN 不可用".to_string())?;
    let activity = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
    let bridge = vpn_bridge_class(&mut env, &activity)?;
    let already = env
        .call_static_method(
            bridge,
            "prepare",
            "(Landroid/content/Context;)Z",
            &[jni::objects::JValue::Object(&activity)],
        )
        .map_err(|_| { let _ = env.exception_clear(); "VPN 不可用".to_string() })?
        .z()
        .map_err(|_| "VPN 不可用".to_string())?;
    if already {
        return Ok(true);
    }
    let guard = VPN_LOCK.lock().map_err(|_| "VPN 不可用".to_string())?;
    let _guard = VPN_READY
        .wait_timeout_while(guard, std::time::Duration::from_secs(120), |_| !VPN_CONSENT_READY.load(Ordering::SeqCst))
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
fn android_start(filter: &AppFilter) -> Result<i32, String> {
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
    for package_name in &filter.packages {
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
    let bridge = vpn_bridge_class(&mut env, &context)?;
    env.call_static_method(
        bridge,
        "start",
        "(Landroid/content/Context;Ljava/util/List;Z)V",
        &[
            jni::objects::JValue::Object(&context),
            jni::objects::JValue::Object(&list),
            jni::objects::JValue::Bool(u8::from(filter.only)),
        ],
    )
    .map_err(|_| { let _ = env.exception_clear(); "VPN 没有建立".to_string() })?;
    wait_for_written_vpn_fd(std::time::Duration::from_secs(15))
}

#[cfg(target_os = "android")]
fn android_stop() {
    let _ = (|| -> Result<(), ()> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }.map_err(|_| ())?;
        let mut env = vm.attach_current_thread().map_err(|_| ())?;
        let context = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
        let bridge = vpn_bridge_class(&mut env, &context).map_err(|_| ())?;
        env.call_static_method(
            bridge,
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
    VPN_CONSENT_READY.store(true, Ordering::SeqCst);
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
                // FLAG_SYSTEM without FLAG_UPDATED_SYSTEM_APP: preinstalled and never updated
                // from the store. Updated system apps (Chrome, Gmail) are user-facing.
                let flags = env.get_field(&info, "flags", "I")?.i()?;
                let system = flags & 1 != 0 && flags & 0x80 == 0;
                Ok(Some(InstalledApp { name, package_name, system }))
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

// ---------------------------------------------------------------------------
// Android tile, widget and notification (R41)
//
// Rust owns the connection, so it is the one source of truth these surfaces
// render: it publishes the state, the running profile's name, the two rates and
// the UI language to Kotlin, and a tap on the tile or the widget switch runs the
// same connection toggle as the tray.
// ---------------------------------------------------------------------------

/// The three states the Quick Settings tile shows.
#[cfg(any(target_os = "android", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Disconnected,
    Connecting,
    Connected,
}

#[cfg(any(target_os = "android", test))]
impl LinkState {
    /// The key `BillowStatus` in Kotlin understands.
    pub fn key(self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
        }
    }
}

/// One snapshot of what the tile, the widget and the notification show (R41).
///
/// `language` carries the effective UI language from T1, so all three render
/// their own text in the language the app is set to instead of the system one.
#[cfg(any(target_os = "android", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidStatus {
    pub state: LinkState,
    pub profile: Option<String>,
    /// Bytes per second; the widget shows no speed while disconnected (R41).
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub language: &'static str,
    /// Why a connection attempt failed; the notification explains it (R41).
    pub reason: Option<String>,
}

#[cfg(any(target_os = "android", test))]
impl AndroidStatus {
    pub fn of(link: &crate::profile::LinkStatus, connecting: bool, locale: crate::i18n::Locale) -> Self {
        let state = if connecting {
            LinkState::Connecting
        } else if link.connected {
            LinkState::Connected
        } else {
            LinkState::Disconnected
        };
        let moving = state == LinkState::Connected;
        Self {
            state,
            profile: link.profile.clone(),
            upload: if moving { link.upload } else { None },
            download: if moving { link.download } else { None },
            language: locale.tag(),
            // A stale banner from an earlier attempt must not become a new
            // notification while the tile reads "connected" (R41).
            reason: if state == LinkState::Disconnected {
                link.failure.clone()
            } else {
                None
            },
        }
    }
}

/// Remembers the last published status so an unchanged one stays in Rust.
#[cfg(any(target_os = "android", test))]
#[derive(Debug, Default)]
pub struct StatusPublisher {
    last: Option<AndroidStatus>,
}

#[cfg(any(target_os = "android", test))]
impl StatusPublisher {
    /// `Some` means the tile, widget or notification must be told; `None` means
    /// nothing they render has changed.
    pub fn changed(&mut self, next: AndroidStatus) -> Option<AndroidStatus> {
        if self.last.as_ref() == Some(&next) {
            return None;
        }
        self.last = Some(next.clone());
        Some(next)
    }
}

#[cfg(target_os = "android")]
static STATUS: Mutex<StatusPublisher> = Mutex::new(StatusPublisher { last: None });

/// Push a status to Kotlin when it changed. Returns whether it was sent.
#[cfg(target_os = "android")]
pub fn publish_status(next: AndroidStatus) -> bool {
    let changed = match STATUS.lock() {
        Ok(mut publisher) => publisher.changed(next),
        Err(poisoned) => poisoned.into_inner().changed(next),
    };
    let Some(status) = changed else {
        return false;
    };
    if let Err(error) = android_push_status(&status) {
        eprintln!("Billow status was not published: {error}");
    }
    true
}

/// What a tap on the tile or the widget switch does (R41).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapPlan {
    /// Run the shared connection toggle.
    Toggle,
    /// Bring Billow to the front on the profiles page: there is nothing to run.
    OpenProfiles,
    /// Bring Billow to the front so the activity can ask for VPN permission.
    OpenForConsent,
}

/// A tap needs the app only when it cannot do the work itself (R41): without a
/// profile the profiles page is the useful answer, and without VPN permission the
/// activity has to run the system dialog. A tap that happens inside the app skips
/// the permission branch, because the activity is already there to show it.
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn plan_tap(connected: bool, has_profile: bool, consent: bool, in_app: bool) -> TapPlan {
    if connected {
        return TapPlan::Toggle;
    }
    if !has_profile {
        return TapPlan::OpenProfiles;
    }
    if !in_app && !consent {
        return TapPlan::OpenForConsent;
    }
    TapPlan::Toggle
}

/// `BillowVpnBridge.hasConsent` asks the system without showing a dialog, so a
/// tap knows whether it can connect on its own (R41).
#[cfg(target_os = "android")]
pub fn android_has_consent() -> bool {
    let ask = || -> Result<bool, String> {
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|_| "Android 桥接不可用".to_string())?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|_| "Android 桥接不可用".to_string())?;
        let context = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
        let bridge = android_class(&mut env, &context, "app.billow.client.BillowVpnBridge")?;
        env.call_static_method(
            bridge,
            "hasConsent",
            "(Landroid/content/Context;)Z",
            &[jni::objects::JValue::Object(&context)],
        )
        .map_err(|_| {
            let _ = env.exception_clear();
            "Android 桥接不可用".to_string()
        })?
        .z()
        .map_err(|_| "Android 桥接不可用".to_string())
    };
    ask().unwrap_or(false)
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub fn android_has_consent() -> bool {
    false
}

/// `BillowStatus.publish(context, state, profile, up, down, language, reason)`.
#[cfg(target_os = "android")]
fn android_push_status(status: &AndroidStatus) -> Result<(), String> {
    let ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
        .map_err(|_| "Android 桥接不可用".to_string())?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|_| "Android 桥接不可用".to_string())?;
    // A caller can already be attached to the JVM. Bound local references to
    // this publish even when dropping the attach guard will not detach it.
    env.with_local_frame(16, |env| -> jni::errors::Result<Result<(), String>> {
        let context = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
        let status_class = match android_class(env, &context, "app.billow.client.BillowStatus") {
            Ok(class) => class,
            Err(error) => return Ok(Err(error)),
        };
        let state = env.new_string(status.state.key())?;
        let profile = env.new_string(status.profile.as_deref().unwrap_or_default())?;
        let language = env.new_string(status.language)?;
        let reason = env.new_string(status.reason.as_deref().unwrap_or_default())?;
        env.call_static_method(
            status_class,
            "publish",
            "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;JJLjava/lang/String;Ljava/lang/String;)V",
            &[
                jni::objects::JValue::Object(&context),
                jni::objects::JValue::Object(&state),
                jni::objects::JValue::Object(&profile),
                jni::objects::JValue::Long(status.upload.unwrap_or(0) as i64),
                jni::objects::JValue::Long(status.download.unwrap_or(0) as i64),
                jni::objects::JValue::Object(&language),
                jni::objects::JValue::Object(&reason),
            ],
        )?;
        Ok(Ok(()))
    })
    .map_err(|error| {
        let _ = env.exception_clear();
        error.to_string()
    })?
}

/// Real HTTP/HTTPS/PAC system proxy. Unit tests use [`MemoryProxy`] instead.
#[derive(Debug, Default)]
pub struct HostSystemProxy {
    settings: SystemProxySettings,
}

impl SystemProxy for HostSystemProxy {
    fn configure(&mut self, settings: &SystemProxySettings) {
        self.settings = settings.clone().normalized();
    }

    fn set_http_https(&mut self, endpoint: &ProxyEndpoint) -> Result<(), String> {
        host_proxy::set(endpoint, &self.settings)
    }

    fn clear_if_pointing_at(&mut self, endpoint: &ProxyEndpoint) -> Result<(), String> {
        host_proxy::clear_if_matches(endpoint)
    }
}

pub fn host_proxy() -> HostSystemProxy {
    HostSystemProxy::default()
}

pub fn host_tun() -> HostTun {
    HostTun::host()
}

pub fn host_vpn() -> HostVpn {
    HostVpn::host()
}

pub fn render_pac_script(template: &str, host: &str, port: u16) -> String {
    let base = if template.trim().is_empty() {
        DEFAULT_PAC_SCRIPT
    } else {
        template
    };
    base.replace("%proxy-host%", host)
        .replace("%mixed-port%", &port.to_string())
}

pub fn is_billow_pac_url(url: &str) -> bool {
    let trimmed = url.trim().trim_matches('\'').trim_matches('"');
    trimmed.starts_with("http://127.0.0.1:") && trimmed.ends_with("/billow.pac")
}

struct PacServerState {
    port: u16,
    script: std::sync::Arc<Mutex<String>>,
}

static PAC_SERVER: Mutex<Option<PacServerState>> = Mutex::new(None);

pub fn ensure_pac_server(host: &str, port: u16, template: &str) -> Result<String, String> {
    let rendered = render_pac_script(template, host, port);
    let mut guard = PAC_SERVER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(state) = guard.as_ref() {
        let mut slot = state
            .script
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = rendered;
        return Ok(format!("http://127.0.0.1:{}/billow.pac", state.port));
    }
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "无法启动本地 PAC 服务".to_string())?;
    let listen_port = listener
        .local_addr()
        .map_err(|_| "无法启动本地 PAC 服务".to_string())?
        .port();
    let script = std::sync::Arc::new(Mutex::new(rendered));
    let shared = std::sync::Arc::clone(&script);
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            while let Ok(n) = stream.read(&mut tmp) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 8192 {
                    break;
                }
            }
            let body = shared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(std::net::Shutdown::Write);
        }
    });
    *guard = Some(PacServerState {
        port: listen_port,
        script,
    });
    Ok(format!("http://127.0.0.1:{listen_port}/billow.pac"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UwpApp {
    pub name: String,
    pub display_name: String,
    pub family_name: String,
    pub sid: String,
    pub exempted: bool,
}

#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
#[derive(Debug, Deserialize)]
struct RawUwpApp {
    #[serde(default)]
    name: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    family_name: String,
    #[serde(default)]
    sid: String,
}

pub fn is_valid_uwp_family_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 256
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Parses `CheckNetIsolation LoopbackExempt -s` output (English and localized Windows builds)
/// into a lowercased set of exempted SIDs and PackageFamilyNames.
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub fn parse_loopback_exempt_output(output: &str) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Extract any AppContainer SID token (`S-1-15-2-...`) regardless of OS language.
        for token in trimmed.split(|c: char| c.is_whitespace() || matches!(c, ':' | '：' | '[' | ']' | '(' | ')')) {
            let clean = token.trim();
            if clean.len() > 8 && clean.to_ascii_uppercase().starts_with("S-1-15-2-") {
                set.insert(clean.to_ascii_lowercase());
            }
        }
        // Extract package family name after `Name:` / `名称:` / `名称：`
        if let Some((_, rest)) = trimmed.split_once(':').or_else(|| trimmed.split_once('：')) {
            let value = rest.trim();
            if is_valid_uwp_family_name(value) && value.contains('_') {
                set.insert(value.to_ascii_lowercase());
            }
        }
    }
    set
}

/// Parses the JSON emitted by the PowerShell AppContainer/Appx enumeration script and merges
/// the current loopback exemption state.
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub fn parse_uwp_apps_json(
    json: &str,
    exempt: &std::collections::HashSet<String>,
) -> Result<Vec<UwpApp>, String> {
    let trimmed = json.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }
    let raw_list: Vec<RawUwpApp> = if trimmed.starts_with('[') {
        serde_json::from_str(trimmed).map_err(|e| format!("无法解析 UWP 应用列表：{e}"))?
    } else {
        let single: RawUwpApp =
            serde_json::from_str(trimmed).map_err(|e| format!("无法解析 UWP 应用列表：{e}"))?;
        vec![single]
    };

    let mut seen = std::collections::HashSet::new();
    let mut apps = Vec::with_capacity(raw_list.len());
    for item in raw_list {
        let family = item.family_name.trim().to_string();
        if !is_valid_uwp_family_name(&family) {
            continue;
        }
        let family_lower = family.to_ascii_lowercase();
        if !seen.insert(family_lower.clone()) {
            continue;
        }
        let sid = item.sid.trim().to_string();
        let name = if item.name.trim().is_empty() {
            family.split('_').next().unwrap_or(&family).to_string()
        } else {
            item.name.trim().to_string()
        };
        let raw_display = item.display_name.trim();
        let display_name = if raw_display.is_empty() || raw_display.starts_with("@{") || raw_display.starts_with("ms-resource:") {
            name.clone()
        } else {
            raw_display.to_string()
        };
        let exempted = exempt.contains(&family_lower)
            || (!sid.is_empty() && exempt.contains(&sid.to_ascii_lowercase()));
        apps.push(UwpApp {
            name,
            display_name,
            family_name: family,
            sid,
            exempted,
        });
    }
    apps.sort_by(|a, b| {
        b.exempted
            .cmp(&a.exempted)
            .then_with(|| a.display_name.to_ascii_lowercase().cmp(&b.display_name.to_ascii_lowercase()))
            .then_with(|| a.family_name.cmp(&b.family_name))
    });
    Ok(apps)
}

/// Computes `(to_add, to_remove)` family names between the current UWP list and desired exempted families.
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
pub fn diff_uwp_exemptions(current: &[UwpApp], desired_families: &[String]) -> (Vec<String>, Vec<String>) {
    let desired: std::collections::HashSet<String> = desired_families
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| is_valid_uwp_family_name(s))
        .collect();
    let mut to_add = Vec::new();
    let mut to_remove = Vec::new();
    for app in current {
        let want = desired.contains(&app.family_name.to_ascii_lowercase());
        if want && !app.exempted {
            to_add.push(app.family_name.clone());
        } else if !want && app.exempted {
            to_remove.push(app.family_name.clone());
        }
    }
    (to_add, to_remove)
}

#[cfg(target_os = "windows")]
const UWP_APP_ENUMERATION_SCRIPT: &str = concat!(
    "$ErrorActionPreference='Stop'; ",
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; ",
    "$map = @{}; ",
    "Get-ChildItem 'HKCU:\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings' -ErrorAction SilentlyContinue | ForEach-Object { ",
    "  $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue; ",
    "  if ($p.Moniker) { $map[$p.Moniker.ToLowerInvariant()] = @{ sid = $_.PSChildName; display = [string]$p.DisplayName; moniker = [string]$p.Moniker } } ",
    "}; ",
    "$out = New-Object System.Collections.Generic.List[object]; ",
    "$seen = @{}; ",
    "Get-AppxPackage | ForEach-Object { ",
    "  $fam = [string]$_.PackageFamilyName; ",
    "  if (-not $fam) { return }; ",
    "  $key = $fam.ToLowerInvariant(); ",
    "  if ($seen.ContainsKey($key)) { return }; ",
    "  $seen[$key] = $true; ",
    "  $entry = $map[$key]; ",
    "  $disp = if ($entry -and $entry.display) { $entry.display } else { [string]$_.Name }; ",
    "  $sid = if ($entry -and $entry.sid) { $entry.sid } else { '' }; ",
    "  $out.Add([PSCustomObject]@{ name = [string]$_.Name; display_name = $disp; family_name = $fam; sid = $sid }) ",
    "}; ",
    "foreach ($kv in $map.GetEnumerator()) { ",
    "  if (-not $seen.ContainsKey($kv.Key)) { ",
    "    $fam = $kv.Value.moniker; ",
    "    $short = ($fam -split '_')[0]; ",
    "    $out.Add([PSCustomObject]@{ name = $short; display_name = if ($kv.Value.display) { $kv.Value.display } else { $short }; family_name = $fam; sid = $kv.Value.sid }) ",
    "  } ",
    "}; ",
    // Windows PowerShell can fail when @() wraps a list created by New-Object.
    "ConvertTo-Json -InputObject ($out.ToArray()) -Depth 3 -Compress"
);

#[cfg(target_os = "windows")]
fn read_uwp_apps_json(script: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;

    let output = std::process::Command::new("powershell")
        .creation_flags(0x08000000)
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|error| format!("无法枚举 UWP 应用：{error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        return if detail.is_empty() {
            Err(format!("无法枚举 UWP 应用：PowerShell {}", output.status))
        } else {
            Err(format!("无法枚举 UWP 应用：{detail}"))
        };
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Lists installed Windows UWP / AppContainer applications together with their loopback exemption state.
pub fn list_uwp_apps() -> Result<Vec<UwpApp>, String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let exempt_out = std::process::Command::new("CheckNetIsolation")
            .creation_flags(0x08000000)
            .args(["LoopbackExempt", "-s"])
            .output()
            .map_err(|error| format!("无法读取 UWP 回环豁免列表：{error}"))?;
        let exempt_text = String::from_utf8_lossy(&exempt_out.stdout);
        let exempt = parse_loopback_exempt_output(&exempt_text);

        let json = read_uwp_apps_json(UWP_APP_ENUMERATION_SCRIPT)?;
        return parse_uwp_apps_json(&json, &exempt);
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("UWP 回环工具仅适用于 Windows 系统".to_string())
    }
}

/// Applies the desired set of exempted UWP PackageFamilyNames via `CheckNetIsolation`,
/// elevating once via UAC only if the process is not already elevated and changes are needed.
pub fn save_uwp_exemptions(family_names: Vec<String>) -> Result<Vec<UwpApp>, String> {
    for name in &family_names {
        if !is_valid_uwp_family_name(name) {
            return Err(format!("无效的 UWP 包名：{name}"));
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let current = list_uwp_apps()?;
        let (to_add, to_remove) = diff_uwp_exemptions(&current, &family_names);
        if to_add.is_empty() && to_remove.is_empty() {
            return Ok(current);
        }
        let mut lines = Vec::with_capacity(to_add.len() + to_remove.len() + 1);
        lines.push("$ErrorActionPreference='Continue'".to_string());
        for fam in &to_add {
            lines.push(format!("CheckNetIsolation LoopbackExempt -a -n=\"{fam}\" | Out-Null"));
        }
        for fam in &to_remove {
            lines.push(format!("CheckNetIsolation LoopbackExempt -d -n=\"{fam}\" | Out-Null"));
        }
        let script = lines.join("\r\n");
        let temp_path = std::env::temp_dir().join(format!(
            "billow-uwp-{}-{}.ps1",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        std::fs::write(&temp_path, script.as_bytes())
            .map_err(|error| format!("无法准备 UWP 豁免脚本：{error}"))?;
        let run_result = if crate::elevation::is_admin() {
            std::process::Command::new("powershell")
                .creation_flags(0x08000000)
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                ])
                .arg(&temp_path)
                .status()
                .map_err(|error| format!("执行 UWP 回环豁免失败：{error}"))
        } else {
            let escaped = temp_path.to_string_lossy().replace('\'', "''");
            let elevate_cmd = format!(
                "$p = Start-Process powershell -Verb RunAs -PassThru -Wait -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{escaped}'; exit $p.ExitCode"
            );
            std::process::Command::new("powershell")
                .creation_flags(0x08000000)
                .args(["-NoProfile", "-NonInteractive", "-Command", &elevate_cmd])
                .status()
                .map_err(|error| format!("请求管理员权限失败：{error}"))
        };
        let _ = std::fs::remove_file(&temp_path);
        let status = run_result?;
        if !status.success() {
            return Err("未获得管理员权限或 UWP 豁免未能保存".to_string());
        }
        return list_uwp_apps();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = family_names;
        Err("UWP 回环工具仅适用于 Windows 系统".to_string())
    }
}

/// Launch the Windows UWP loopback exemption utility so Microsoft Store / UWP apps can
/// connect to the local `127.0.0.1` system proxy.
pub fn open_uwp_loopback_tool() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // Native Windows PowerShell GUI picker (`Out-GridView`) backed by `CheckNetIsolation`.
        let ps_script = concat!(
            "$ErrorActionPreference='SilentlyContinue'; ",
            "$exempt = (CheckNetIsolation LoopbackExempt -s) -join \"`n\"; ",
            "$apps = Get-AppxPackage | Sort-Object Name | ForEach-Object { ",
            "[PSCustomObject]@{ ",
            "Status = if ($exempt -match [regex]::Escape($_.PackageFamilyName)) { '已豁免' } else { '未豁免' }; ",
            "Name = $_.Name; ",
            "PackageFamilyName = $_.PackageFamilyName ",
            "} }; ",
            "$picked = $apps | Out-GridView -Title 'Billow UWP 回环豁免工具（按住 Ctrl 多选后点击确定添加本地代理豁免）' -PassThru; ",
            "if ($picked) { ",
            "$cmds = ($picked | ForEach-Object { \"CheckNetIsolation LoopbackExempt -a -n=`\"$($_.PackageFamilyName)`\"\" }) -join '; '; ",
            "Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile','-Command',$cmds ",
            "}"
        );
        std::process::Command::new("powershell")
            .creation_flags(0x08000000)
            .args(["-NoProfile", "-STA", "-Command", ps_script])
            .spawn()
            .map_err(|error| format!("无法打开 UWP 回环工具：{error}"))?;
        return Ok(());
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("UWP 回环工具仅适用于 Windows 系统".to_string())
    }
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

/// `networksetup -getautoproxyurl` text. Enabled must be Yes.
pub fn parse_macos_autoproxy(text: &str) -> Option<String> {
    let mut enabled = false;
    let mut url = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("Enabled:") {
            enabled = value.trim().eq_ignore_ascii_case("yes");
        } else if let Some(value) = line.strip_prefix("URL:") {
            let raw = value.trim();
            if !raw.is_empty() && !raw.eq_ignore_ascii_case("(null)") {
                url = Some(raw.to_string());
            }
        }
    }
    if enabled { url } else { None }
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn parse_network_services(text: &str) -> Vec<String> {
    text.lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(str::to_string)
        .collect()
}

mod host_proxy {
    use super::{ProxyEndpoint, SystemProxySettings};

    pub fn set(endpoint: &ProxyEndpoint, settings: &SystemProxySettings) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            return macos::set(endpoint, settings);
        }
        #[cfg(target_os = "windows")]
        {
            return windows::set(endpoint, settings);
        }
        #[cfg(all(target_os = "linux", not(target_os = "android")))]
        {
            return linux::set(endpoint, settings);
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "windows",
            all(target_os = "linux", not(target_os = "android"))
        )))]
        {
            let _ = (endpoint, settings);
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

        use super::super::{
            ProxyEndpoint, SystemProxySettings, ensure_pac_server, is_billow_pac_url,
            parse_macos_autoproxy, parse_macos_proxy, parse_network_services,
        };

        pub fn set(endpoint: &ProxyEndpoint, settings: &SystemProxySettings) -> Result<(), String> {
            let services = services()?;
            if settings.mode == "pac" {
                let pac_url = ensure_pac_server(&endpoint.host, endpoint.port, &settings.pac_script)?;
                for service in &services {
                    let _ = run(&["-setwebproxystate", service, "off"]);
                    let _ = run(&["-setsecurewebproxystate", service, "off"]);
                    let _ = run(&["-setsocksfirewallproxystate", service, "off"]);
                    run(&["-setautoproxyurl", service, &pac_url])?;
                    run(&["-setautoproxystate", service, "on"])?;
                    if parse_macos_autoproxy(&run_text(&["-getautoproxyurl", service])?).as_deref() != Some(&pac_url) {
                        return Err(format!("系统代理没有生效：{service} 的 PAC 设置与预期不符"));
                    }
                }
                return Ok(());
            }
            let bypass: Vec<&str> = settings
                .bypass
                .iter()
                .map(String::as_str)
                .filter(|entry| *entry != "<local>")
                .collect();
            for service in &services {
                let _ = run(&["-setautoproxystate", service, "off"]);
                enable_manual_proxy(service, endpoint, &mut run_text)?;
                if bypass.is_empty() {
                    let _ = run(&["-setproxybypassdomains", service, "Empty"]);
                } else {
                    let mut args = vec!["-setproxybypassdomains", service.as_str()];
                    args.extend_from_slice(&bypass);
                    let _ = run(&args);
                }
            }
            Ok(())
        }

        fn enable_manual_proxy(
            service: &str,
            endpoint: &ProxyEndpoint,
            run: &mut impl FnMut(&[&str]) -> Result<String, String>,
        ) -> Result<(), String> {
            let port = endpoint.port.to_string();
            for (set, state, get) in [
                ("-setwebproxy", "-setwebproxystate", "-getwebproxy"),
                ("-setsecurewebproxy", "-setsecurewebproxystate", "-getsecurewebproxy"),
                ("-setsocksfirewallproxy", "-setsocksfirewallproxystate", "-getsocksfirewallproxy"),
            ] {
                // The final `off` disables proxy authentication, not the proxy itself.
                run(&[set, service, &endpoint.host, &port, "off"])?;
                run(&[state, service, "on"])?;
                if parse_macos_proxy(&run(&[get, service])?).as_ref() != Some(endpoint) {
                    return Err(format!("系统代理没有生效：{service} 的 {get} 设置与预期不符"));
                }
            }
            Ok(())
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            #[ignore = "requires BILLOW_TEST_PROXY_SERVICE; temporarily changes that macOS service's proxy"]
            fn macos_real_system_proxy_roundtrip() {
                let service = std::env::var("BILLOW_TEST_PROXY_SERVICE").expect("BILLOW_TEST_PROXY_SERVICE");
                struct Restore(Vec<Vec<String>>);
                impl Drop for Restore {
                    fn drop(&mut self) {
                        for args in &self.0 {
                            let _ = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
                        }
                    }
                }
                let mut restore = Restore(Vec::new());
                for (set, state, get) in [
                    ("-setwebproxy", "-setwebproxystate", "-getwebproxy"),
                    ("-setsecurewebproxy", "-setsecurewebproxystate", "-getsecurewebproxy"),
                    ("-setsocksfirewallproxy", "-setsocksfirewallproxystate", "-getsocksfirewallproxy"),
                ] {
                    let text = run_text(&[get, &service]).unwrap();
                    let field = |key: &str| text.lines().find_map(|line| line.strip_prefix(key)).unwrap_or("").trim().to_string();
                    assert_eq!(field("Authenticated Proxy Enabled:"), "0", "do not overwrite authenticated proxy settings");
                    let host = field("Server:");
                    let port = field("Port:");
                    assert!(!host.is_empty() && host != "(null)" && port.parse::<u16>().is_ok_and(|p| p > 0), "smoke test requires a restorable endpoint");
                    restore.0.push(vec![set.into(), service.clone(), host, port, "off".into()]);
                    restore.0.push(vec![state.into(), service.clone(), if field("Enabled:") == "Yes" { "on" } else { "off" }.into()]);
                }
                let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
                let endpoint = ProxyEndpoint { host: "127.0.0.1".into(), port: listener.local_addr().unwrap().port() };
                enable_manual_proxy(&service, &endpoint, &mut run_text).unwrap();
                for get in ["-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy"] {
                    assert_eq!(read_service(&service, get).unwrap(), Some(endpoint.clone()));
                }
                drop(restore);
            }

            #[test]
            fn proxy_enable_checks_the_observed_endpoint_and_enabled_state() {
                let endpoint = ProxyEndpoint { host: "127.0.0.1".into(), port: 7890 };
                for observed in [
                    "Enabled: No\nServer: 127.0.0.1\nPort: 7890\n",
                    "Enabled: Yes\nServer: 127.0.0.1\nPort: 7891\n",
                ] {
                    assert!(enable_manual_proxy("Wi-Fi", &endpoint, &mut |_| Ok(observed.into())).is_err());
                }
                let mut enabled = Vec::new();
                enable_manual_proxy("Wi-Fi", &endpoint, &mut |args| {
                    if args.last() == Some(&"on") { enabled.push(args[0].to_string()); }
                    Ok("Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n".into())
                }).unwrap();
                assert_eq!(enabled, ["-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"]);
                assert!(enable_manual_proxy("Wi-Fi", &endpoint, &mut |_| Err("permission denied".into())).is_err());
            }
        }

        pub fn clear_if_matches(endpoint: &ProxyEndpoint) -> Result<(), String> {
            for service in services()? {
                if read_service(&service, "-getwebproxy")?.as_ref() == Some(endpoint) {
                    run(&["-setwebproxystate", &service, "off"])?;
                }
                if read_service(&service, "-getsecurewebproxy")?.as_ref() == Some(endpoint) {
                    run(&["-setsecurewebproxystate", &service, "off"])?;
                }
                if let Ok(Some(socks)) = read_service(&service, "-getsocksfirewallproxy") {
                    if &socks == endpoint {
                        let _ = run(&["-setsocksfirewallproxystate", &service, "off"]);
                    }
                }
                if let Ok(auto_text) = run_text(&["-getautoproxyurl", &service]) {
                    if parse_macos_autoproxy(&auto_text).is_some_and(|url| is_billow_pac_url(&url)) {
                        run(&["-setautoproxystate", &service, "off"])?;
                    }
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

        fn read_service(service: &str, flag: &str) -> Result<Option<ProxyEndpoint>, String> {
            let text = run_text(&[flag, service])?;
            Ok(parse_macos_proxy(&text))
        }

        fn run(args: &[&str]) -> Result<(), String> {
            let _ = run_text(args)?;
            Ok(())
        }

        fn run_text(args: &[&str]) -> Result<String, String> {
            let output = Command::new("/usr/sbin/networksetup")
                .args(args)
                .output()
                .map_err(|error| format!("无法设置系统代理：{error}"))?;
            if !output.status.success() {
                let detail = format!("{} {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
                return Err(format!("无法设置系统代理：{}", detail.trim()));
            }
            String::from_utf8(output.stdout).map_err(|_| "系统代理没有打开".to_string())
        }
    }

    #[cfg(target_os = "windows")]
    mod windows {
        use std::os::windows::process::CommandExt;
        use std::process::Command;

        use super::super::{
            ProxyEndpoint, SystemProxySettings, ensure_pac_server, is_billow_pac_url,
        };

        const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        pub fn set(endpoint: &ProxyEndpoint, settings: &SystemProxySettings) -> Result<(), String> {
            if settings.mode == "pac" {
                let pac_url = ensure_pac_server(&endpoint.host, endpoint.port, &settings.pac_script)?;
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
                reg(&[
                    "add",
                    KEY,
                    "/v",
                    "AutoConfigURL",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &pac_url,
                    "/f",
                ])?;
                notify_wininet();
                return Ok(());
            }
            let _ = reg(&["delete", KEY, "/v", "AutoConfigURL", "/f"]);
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
            let override_val = settings.bypass.join(";");
            reg(&[
                "add",
                KEY,
                "/v",
                "ProxyOverride",
                "/t",
                "REG_SZ",
                "/d",
                &override_val,
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
            notify_wininet();
            Ok(())
        }

        pub fn clear_if_matches(endpoint: &ProxyEndpoint) -> Result<(), String> {
            let server = format!("{}:{}", endpoint.host, endpoint.port);
            let current = reg_query("ProxyServer");
            let mut changed = false;
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
                changed = true;
            }
            if reg_query("AutoConfigURL").is_some_and(|url| is_billow_pac_url(&url)) {
                let _ = reg(&["delete", KEY, "/v", "AutoConfigURL", "/f"]);
                changed = true;
            }
            if changed {
                notify_wininet();
            }
            Ok(())
        }

        fn notify_wininet() {
            use core::ffi::c_void;
            #[link(name = "wininet")]
            unsafe extern "system" {
                fn InternetSetOptionW(
                    hInternet: *mut c_void,
                    dwOption: u32,
                    lpBuffer: *mut c_void,
                    dwBufferLength: u32,
                ) -> i32;
            }
            const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
            const INTERNET_OPTION_REFRESH: u32 = 37;
            unsafe {
                let _ = InternetSetOptionW(
                    std::ptr::null_mut(),
                    INTERNET_OPTION_SETTINGS_CHANGED,
                    std::ptr::null_mut(),
                    0,
                );
                let _ = InternetSetOptionW(
                    std::ptr::null_mut(),
                    INTERNET_OPTION_REFRESH,
                    std::ptr::null_mut(),
                    0,
                );
            }
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

        use super::super::{
            ProxyEndpoint, SystemProxySettings, ensure_pac_server, is_billow_pac_url,
        };

        pub fn set(endpoint: &ProxyEndpoint, settings: &SystemProxySettings) -> Result<(), String> {
            if settings.mode == "pac" {
                let pac_url = ensure_pac_server(&endpoint.host, endpoint.port, &settings.pac_script)?;
                gsettings(&["set", "org.gnome.system.proxy", "autoconfig-url", &pac_url])?;
                gsettings(&["set", "org.gnome.system.proxy", "mode", "auto"])?;
                return Ok(());
            }
            let port = endpoint.port.to_string();
            gsettings(&["set", "org.gnome.system.proxy", "mode", "manual"])?;
            for proto in ["http", "https", "socks"] {
                let schema = format!("org.gnome.system.proxy.{proto}");
                let _ = gsettings(&["set", &schema, "host", &endpoint.host]);
                let _ = gsettings(&["set", &schema, "port", &port]);
            }
            let bypass_items: Vec<String> = settings
                .bypass
                .iter()
                .filter(|item| item.as_str() != "<local>")
                .map(|item| format!("'{}'", item.replace('\'', "")))
                .collect();
            let variant = format!("[{}]", bypass_items.join(", "));
            let _ = gsettings(&["set", "org.gnome.system.proxy", "ignore-hosts", &variant]);
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
            let socks_host = gsettings_get(&["get", "org.gnome.system.proxy.socks", "host"]);
            let socks_port = gsettings_get(&["get", "org.gnome.system.proxy.socks", "port"]);
            if socks_host.as_deref() == Some(host.as_str())
                && socks_port.as_deref() == Some(port.as_str())
            {
                let _ = gsettings(&["set", "org.gnome.system.proxy.socks", "host", ""]);
            }
            let mode = gsettings_get(&["get", "org.gnome.system.proxy", "mode"]);
            if mode.as_deref() == Some("'manual'")
                && gsettings_get(&["get", "org.gnome.system.proxy.http", "host"]).as_deref()
                    != Some(host.as_str())
                && gsettings_get(&["get", "org.gnome.system.proxy.https", "host"]).as_deref()
                    != Some(host.as_str())
            {
                gsettings(&["set", "org.gnome.system.proxy", "mode", "none"])?;
            } else if mode.as_deref() == Some("'auto'")
                && gsettings_get(&["get", "org.gnome.system.proxy", "autoconfig-url"])
                    .is_some_and(|url| is_billow_pac_url(&url))
            {
                let _ = gsettings(&["set", "org.gnome.system.proxy", "autoconfig-url", ""]);
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
    use crate::profile::{KernelLaunch, LinkStatus, ProfileBook, SubscriptionSource};
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
    fn tun_alone_is_connected_and_survives_disabling_system_proxy() {
        let dir = temp_dir("tun-only");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let enabled = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(enabled.tun && enabled.connected && enabled.kernel_running);
        assert!(!enabled.system_proxy);
        assert_eq!(proxy.sets, 0, "TUN enable must not change OS proxy settings");
        assert_eq!(tun_enable(&kernel.last), Some(true));
        let both = book.set_system_proxy(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(both.tun && both.system_proxy && both.connected);
        let tun_only = book.set_system_proxy(false, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(tun_only.tun && tun_only.connected && !tun_only.system_proxy);
        assert!(proxy.http.is_none());
        assert_eq!(tun_enable(&kernel.last), Some(true));
        let stopped = book.set_tun(false, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!stopped.tun && !stopped.system_proxy && !stopped.connected);
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
    fn app_rules_switch_between_bypass_and_allowlist_and_persist() {
        let dir = temp_dir("app-rules");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Android);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn { grant: true, ..MemoryVpn::default() };
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        let calls = vpn.establish_calls;

        // Allowlist: only the listed apps use the VPN; duplicates and blanks are dropped.
        let only = vec![" com.a ".to_string(), "com.b".to_string(), "com.a".to_string(), "".to_string()];
        let snap = book.set_app_rules("include", &only, &mut kernel, &mut vpn);
        assert_eq!(snap.app_mode, "include");
        assert_eq!(snap.included, ["com.a", "com.b"]);
        assert_eq!(vpn.last_filter, AppFilter { only: true, packages: vec!["com.a".into(), "com.b".into()] });
        assert_eq!(vpn.establish_calls, calls + 1);

        // Saving the same list again does not rebuild the tunnel.
        book.set_app_rules("include", &["com.a".to_string(), "com.b".to_string()], &mut kernel, &mut vpn);
        assert_eq!(vpn.establish_calls, calls + 1);

        // An empty allowlist would route every app on Android; it means "bypass nothing".
        book.set_app_rules("include", &[], &mut kernel, &mut vpn);
        assert_eq!(vpn.last_filter, AppFilter { only: false, packages: Vec::new() });

        // Switching back keeps each mode's own list.
        book.set_app_rules("include", &["com.a".to_string()], &mut kernel, &mut vpn);
        let snap = book.set_app_rules("exclude", &["com.bank".to_string()], &mut kernel, &mut vpn);
        assert_eq!((snap.app_mode.as_str(), snap.included.clone(), snap.excluded.clone()), ("exclude", vec!["com.a".to_string()], vec!["com.bank".to_string()]));
        assert_eq!(vpn.last_filter, AppFilter { only: false, packages: vec!["com.bank".into()] });

        let reopened = ProfileBook::open(&dir.0);
        let snap = reopened.snapshot();
        assert_eq!((snap.app_mode.as_str(), snap.included, snap.excluded), ("exclude", vec!["com.a".to_string()], vec!["com.bank".to_string()]));
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

        fn establish(&mut self, filter: &AppFilter) -> Result<i32, String> {
            self.establish_calls += 1;
            self.last_excluded = filter.bypassed().to_vec();
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
        assert_eq!(
            denied.authorize().unwrap(),
            matches!(TunHost::current(), TunHost::Linux)
        );
        let mut all_closed = HostTun::with_evidence(|| TunEvidence {
            linux_node: false,
            utun: false,
            windows: false,
        });
        assert!(!all_closed.authorize().unwrap());
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
        // A successful TUN start clears the TUN failure it was shown for (T8).
        assert_eq!(allowed.failure, None);
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
                system: false,
            },
            InstalledApp {
                name: "浏览器".to_string(),
                package_name: "com.example.browser".to_string(),
                system: false,
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
                system: false,
            },
            InstalledApp {
                name: "浏览器".to_string(),
                package_name: "com.example.browser".to_string(),
                system: false,
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
            included: Vec::new(),
            app_mode: APP_MODE_EXCLUDE.to_string(),
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
                settings: Default::default(),
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
            "allow-open-uwp-tool",
            "allow-list-uwp-apps",
            "allow-save-uwp-exemptions",
        ] {
            assert!(permissions.contains(&permission), "{permission}");
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn uwp_enumeration_serializes_packages_as_a_json_array() {
        let empty_packages = "function Get-ChildItem {}; function Get-AppxPackage {}; ";
        let json =
            read_uwp_apps_json(&format!("{empty_packages}{UWP_APP_ENUMERATION_SCRIPT}")).unwrap();
        assert_eq!(json.trim(), "[]");

        let one_package = concat!(
            "function Get-ChildItem {}; ",
            "function Get-AppxPackage { ",
            "  [PSCustomObject]@{ Name = 'Billow.Test'; PackageFamilyName = 'Billow.Test_example' } ",
            "}; "
        );
        let json =
            read_uwp_apps_json(&format!("{one_package}{UWP_APP_ENUMERATION_SCRIPT}")).unwrap();
        let packages: Vec<RawUwpApp> = serde_json::from_str(&json).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].family_name, "Billow.Test_example");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn uwp_enumeration_reports_powershell_errors() {
        let mock_commands = concat!(
            "function Get-ChildItem {}; ",
            "function Get-AppxPackage { Write-Error 'Appx enumeration failed' }; "
        );
        let error = read_uwp_apps_json(&format!("{mock_commands}{UWP_APP_ENUMERATION_SCRIPT}"))
            .unwrap_err();
        assert!(error.contains("Appx enumeration failed"), "{error}");

        let error = read_uwp_apps_json("exit 7").unwrap_err();
        assert!(error.contains("PowerShell") && error.contains('7'), "{error}");
    }

    #[test]
    fn uwp_loopback_parsers_and_diff_handle_english_chinese_and_validation() {
        let exempt_output = "
[1] -----------------------------------------------------------------
    Name: Microsoft.WindowsStore_8wekyb3d8bbwe
    SID:  S-1-15-2-1609473798-1231923017-684268153-4268514328-882773646-2760585773-1760938157
[2] -----------------------------------------------------------------
    名称：Microsoft.WindowsTerminal_8wekyb3d8bbwe
    SID:  S-1-15-2-9999-8888
";
        let exempt = parse_loopback_exempt_output(exempt_output);
        assert!(exempt.contains("microsoft.windowsstore_8wekyb3d8bbwe"));
        assert!(exempt.contains("microsoft.windowsterminal_8wekyb3d8bbwe"));
        assert!(exempt.contains("s-1-15-2-9999-8888"));

        let json = r#"[
            {"name":"Microsoft.WindowsStore","display_name":"Microsoft Store","family_name":"Microsoft.WindowsStore_8wekyb3d8bbwe","sid":"S-1-15-2-1"},
            {"name":"Microsoft.XboxApp","display_name":"@{Microsoft.XboxApp?ms-resource://title}","family_name":"Microsoft.XboxApp_8wekyb3d8bbwe","sid":"S-1-15-2-2"},
            {"name":"Bad","display_name":"Bad","family_name":"bad;rm -rf","sid":""}
        ]"#;
        let apps = parse_uwp_apps_json(json, &exempt).unwrap();
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].family_name, "Microsoft.WindowsStore_8wekyb3d8bbwe");
        assert!(apps[0].exempted);
        assert_eq!(apps[1].family_name, "Microsoft.XboxApp_8wekyb3d8bbwe");
        assert_eq!(apps[1].display_name, "Microsoft.XboxApp");
        assert!(!apps[1].exempted);

        let (to_add, to_remove) = diff_uwp_exemptions(
            &apps,
            &["Microsoft.XboxApp_8wekyb3d8bbwe".to_string()],
        );
        assert_eq!(to_add, vec!["Microsoft.XboxApp_8wekyb3d8bbwe"]);
        assert_eq!(to_remove, vec!["Microsoft.WindowsStore_8wekyb3d8bbwe"]);
    }

    #[test]
    fn pac_server_and_system_proxy_settings_render_and_normalize_cleanly() {
        let settings = SystemProxySettings {
            host: " 127.0.0.1 ".to_string(),
            mode: "PAC".to_string(),
            pac_script: String::new(),
            bypass: vec![" localhost ".to_string(), "127.*".to_string(), "localhost".to_string(), "bad;item".to_string()],
        }
        .normalized();
        assert_eq!(settings.host, "");
        assert_eq!(settings.effective_host(), "127.0.0.1");
        assert_eq!(settings.mode, "pac");
        assert_eq!(settings.bypass, vec!["localhost", "127.*", "baditem"]);

        let url = ensure_pac_server("127.0.0.1", 7891, &settings.pac_script).unwrap();
        assert!(is_billow_pac_url(&url));
        let body = ureq::get(&url).call().unwrap().into_string().unwrap();
        assert!(body.contains("PROXY 127.0.0.1:7891; SOCKS5 127.0.0.1:7891; DIRECT"));

        let url2 = ensure_pac_server("192.168.1.5", 7899, "return 'PROXY %proxy-host%:%mixed-port%';").unwrap();
        assert_eq!(url, url2, "PAC server reuses the same loopback listener port");
        let body2 = ureq::get(&url2).call().unwrap().into_string().unwrap();
        assert_eq!(body2, "return 'PROXY 192.168.1.5:7899';");
        assert_eq!(
            parse_macos_autoproxy("URL: http://127.0.0.1:12345/billow.pac\nEnabled: Yes\n").as_deref(),
            Some("http://127.0.0.1:12345/billow.pac")
        );
        assert!(parse_macos_autoproxy("URL: http://127.0.0.1:12345/billow.pac\nEnabled: No\n").is_none());
    }

    #[test]
    fn macos_setuid_probe_and_applescript_escape_paths_safely() {
        assert!(unix_mode_has_setuid_root(0, 0o104755));
        assert!(!unix_mode_has_setuid_root(501, 0o104755));
        assert!(!unix_mode_has_setuid_root(0, 0o100755));

        let script = build_macos_tun_grant_applescript(Path::new("/Users/a'b/Library/Application Support/Billow/core")).unwrap();
        assert!(script.contains("with administrator privileges"));
        assert!(script.contains("chown root:admin"));
        assert!(script.contains("chmod u+s,g+s,a+rx"));
        assert!(script.contains("'\\\\''"));
        assert!(build_macos_tun_grant_applescript(Path::new("bad\npath")).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_utun_probe_does_not_authorize_an_unavailable_kernel() {
        let dir = temp_dir("missing-tun-kernel");
        let mut tun = HostTun::with_evidence(open_without_linux_node);
        tun.set_kernel_path(Some(dir.0.join("missing-core")));
        assert!(tun.authorize().is_err());
    }

    #[test]
    fn a_tap_only_opens_the_app_when_it_cannot_run_the_toggle_itself() {
        // Connected: a tap disconnects, whatever else is missing.
        assert_eq!(plan_tap(true, true, true, false), TapPlan::Toggle);
        assert_eq!(plan_tap(true, true, false, false), TapPlan::Toggle);
        assert_eq!(plan_tap(true, false, false, false), TapPlan::Toggle);
        // Nothing to run: the profiles page is the useful answer, permission or not.
        assert_eq!(plan_tap(false, false, false, false), TapPlan::OpenProfiles);
        assert_eq!(plan_tap(false, false, true, false), TapPlan::OpenProfiles);
        // A profile but no VPN permission: only the activity can show the dialog.
        assert_eq!(plan_tap(false, true, false, false), TapPlan::OpenForConsent);
        // A tap already inside the app has the activity it needs.
        assert_eq!(plan_tap(false, true, false, true), TapPlan::Toggle);
        assert_eq!(plan_tap(false, true, true, false), TapPlan::Toggle);
        assert_eq!(plan_tap(false, true, true, true), TapPlan::Toggle);
    }

    #[test]
    fn the_tile_and_widget_are_told_about_every_visible_change() {
        let mut publisher = StatusPublisher::default();
        let idle = LinkStatus::default();
        let first = publisher
            .changed(AndroidStatus::of(&idle, false, crate::i18n::Locale::ZhCn))
            .expect("the first status is always published");
        assert_eq!(first.state, LinkState::Disconnected);
        assert_eq!(first.state.key(), "disconnected");
        assert_eq!(first.language, "zh-CN");
        assert!(first.profile.is_none() && first.upload.is_none() && first.download.is_none());
        // Nothing the surfaces show has changed: no second push.
        assert!(publisher
            .changed(AndroidStatus::of(&idle, false, crate::i18n::Locale::ZhCn))
            .is_none());

        // Connecting replaces the state without showing the previous rates.
        let mut running = LinkStatus {
            connected: true,
            profile: Some("星河云".to_string()),
            upload: Some(1200),
            download: Some(3400),
            failure: Some("旧的失败原因".to_string()),
            failure_hint: None,
        };
        let connecting = publisher
            .changed(AndroidStatus::of(&running, true, crate::i18n::Locale::ZhCn))
            .expect("连接中 is a new state");
        assert_eq!(connecting.state.key(), "connecting");
        assert_eq!(connecting.profile.as_deref(), Some("星河云"));
        assert!(connecting.upload.is_none() && connecting.download.is_none());
        assert!(connecting.reason.is_none(), "a stale banner is not a new failure");

        let connected = publisher
            .changed(AndroidStatus::of(&running, false, crate::i18n::Locale::ZhCn))
            .expect("connected carries the rates");
        assert_eq!(connected.state, LinkState::Connected);
        assert_eq!((connected.upload, connected.download), (Some(1200), Some(3400)));
        assert!(connected.reason.is_none());

        // The two rates move every sample, so the widget follows them.
        running.upload = Some(2400);
        running.download = Some(6800);
        let moved = publisher
            .changed(AndroidStatus::of(&running, false, crate::i18n::Locale::ZhCn))
            .expect("a rate change is published");
        assert_eq!((moved.upload, moved.download), (Some(2400), Some(6800)));

        // A language switch re-renders the same state in the other language (T1).
        let translated = publisher
            .changed(AndroidStatus::of(&running, false, crate::i18n::Locale::En))
            .expect("the language is part of what the surfaces render");
        assert_eq!(translated.language, "en");

        // A failed attempt returns the tile to 未连接 with the reason and no speed.
        let failed = LinkStatus {
            connected: false,
            profile: Some("星河云".to_string()),
            upload: Some(2400),
            download: Some(6800),
            failure: Some(VPN_DENIED.to_string()),
            failure_hint: None,
        };
        let failure = publisher
            .changed(AndroidStatus::of(&failed, false, crate::i18n::Locale::En))
            .expect("a failure is published");
        assert_eq!(failure.state, LinkState::Disconnected);
        assert!(failure.upload.is_none() && failure.download.is_none());
        assert_eq!(failure.reason.as_deref(), Some(VPN_DENIED));

        // Disconnecting clears both the rates and the reason.
        let idle_again = publisher
            .changed(AndroidStatus::of(
                &LinkStatus {
                    connected: false,
                    profile: Some("星河云".to_string()),
                    ..LinkStatus::default()
                },
                false,
                crate::i18n::Locale::En,
            ))
            .expect("disconnecting is a new state");
        assert_eq!(idle_again.state, LinkState::Disconnected);
        assert!(idle_again.reason.is_none() && idle_again.upload.is_none());
    }

    /// Returns a traffic sample, so a connected book reports the two rates.
    struct RateKernel {
        alive: bool,
        rate: (u64, u64),
    }

    impl KernelLaunch for RateKernel {
        fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
            self.alive = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.alive
        }

        fn traffic(&mut self) -> Option<(u64, u64)> {
            if self.alive { Some(self.rate) } else { None }
        }
    }

    #[test]
    fn the_published_state_follows_the_android_connection() {
        let dir = temp_dir("android-status");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Android);
        book.add_local("home.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = RateKernel { alive: false, rate: (900, 1800) };
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn { grant: true, ..MemoryVpn::default() };
        book.enable("p1", &UnusedSource, &mut kernel);
        let mut publisher = StatusPublisher::default();

        let idle = publisher
            .changed(AndroidStatus::of(&book.link_status(), false, crate::i18n::Locale::En))
            .expect("the first status is published");
        assert_eq!(idle.state, LinkState::Disconnected);
        assert_eq!(idle.profile.as_deref(), Some("home.yaml"));

        // The tap shows 连接中 while the VPN and the kernel come up.
        assert_eq!(
            publisher
                .changed(AndroidStatus::of(&book.link_status(), true, crate::i18n::Locale::En))
                .expect("连接中 is a new state")
                .state,
            LinkState::Connecting
        );

        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        book.refresh_link_rates(&mut kernel);
        let connected = publisher
            .changed(AndroidStatus::of(&book.link_status(), false, crate::i18n::Locale::En))
            .expect("a finished connect is published");
        assert_eq!(connected.state, LinkState::Connected);
        assert_eq!(connected.profile.as_deref(), Some("home.yaml"));
        assert_eq!((connected.upload, connected.download), (Some(900), Some(1800)));

        // A refused permission returns the tile to 未连接 and names the reason.
        book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        let mut denied = MemoryVpn { grant: false, ..MemoryVpn::default() };
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut denied);
        let failed = publisher
            .changed(AndroidStatus::of(&book.link_status(), false, crate::i18n::Locale::En))
            .expect("a failed connect is published");
        assert_eq!(failed.state, LinkState::Disconnected);
        assert_eq!(failed.reason.as_deref(), Some(VPN_DENIED));
        assert!(failed.upload.is_none() && failed.download.is_none(), "未连接 shows no speed");
    }
}
