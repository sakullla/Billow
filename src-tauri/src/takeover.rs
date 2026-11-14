use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

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

/// Android VPN. `establish` receives the package names Rust decided to exclude.
pub trait VpnGrant: Send {
    fn authorize(&mut self) -> Result<bool, String>;
    fn establish(&mut self, excluded: &[String]) -> Result<(), String>;
    fn close(&mut self) -> Result<(), String>;
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

pub fn release_platform(
    proxy: &mut dyn SystemProxy,
    tun: &mut dyn TunGrant,
    vpn: &mut dyn VpnGrant,
    release: &PlatformRelease,
) {
    if let Some(endpoint) = &release.endpoint {
        let _ = proxy.clear_if_pointing_at(endpoint);
    }
    if release.close_tun {
        let _ = tun.set_enabled(false);
    }
    if release.close_vpn {
        let _ = vpn.close();
    }
}

/// Kernel start failed: system proxy, TUN and VPN are all off.
pub fn fail_kernel(
    model: &mut LinkModel,
    proxy: &mut dyn SystemProxy,
    tun: &mut dyn TunGrant,
    vpn: &mut dyn VpnGrant,
    message: String,
) {
    release_platform(
        proxy,
        tun,
        vpn,
        &PlatformRelease {
            endpoint: model.endpoint.clone(),
            close_tun: model.tun,
            close_vpn: model.vpn,
        },
    );
    model.system_proxy = false;
    model.tun = false;
    model.vpn = false;
    model.connected = false;
    model.endpoint = None;
    model.failure = Some(if message.is_empty() {
        "内核没有启动".to_string()
    } else {
        message
    });
}

pub fn connect(model: &mut LinkModel, port: u16, proxy: &mut dyn SystemProxy, tun: &mut dyn TunGrant, vpn: &mut dyn VpnGrant) {
    match model.platform {
        ClientPlatform::Desktop => connect_desktop(model, port, proxy, tun),
        ClientPlatform::Android => connect_android(model, vpn),
    }
}

pub fn disconnect(model: &mut LinkModel, proxy: &mut dyn SystemProxy, tun: &mut dyn TunGrant, vpn: &mut dyn VpnGrant) {
    release_platform(
        proxy,
        tun,
        vpn,
        &PlatformRelease {
            endpoint: model.endpoint.clone(),
            close_tun: model.tun || model.tun_wanted,
            close_vpn: model.vpn,
        },
    );
    // Always stop the device even if the flag was already false.
    let _ = tun.set_enabled(false);
    let _ = vpn.close();
    model.system_proxy = false;
    model.tun = false;
    model.vpn = false;
    model.connected = false;
    // Keep the endpoint we last installed so a later close can still recognize it.
    model.failure = None;
}

pub fn set_system_proxy(model: &mut LinkModel, enabled: bool, port: Option<u16>, proxy: &mut dyn SystemProxy) {
    if model.platform != ClientPlatform::Desktop {
        return;
    }
    if !enabled {
        if let Some(endpoint) = &model.endpoint {
            let _ = proxy.clear_if_pointing_at(endpoint);
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
        model.failure = None;
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
    model.failure = None;
    model.connected = model.system_proxy;
}

pub fn exclude_package(model: &mut LinkModel, package_name: &str, vpn: &mut dyn VpnGrant) {
    if model.platform != ClientPlatform::Android {
        return;
    }
    let Some(package_name) = clean_package(package_name) else {
        return;
    };
    if !model.excluded.iter().any(|item| item == &package_name) {
        model.excluded.push(package_name);
    }
    refresh_vpn(model, vpn);
}

pub fn include_package(model: &mut LinkModel, package_name: &str, vpn: &mut dyn VpnGrant) {
    if model.platform != ClientPlatform::Android {
        return;
    }
    let Some(package_name) = clean_package(package_name) else {
        return;
    };
    model.excluded.retain(|item| item != &package_name);
    refresh_vpn(model, vpn);
}

fn connect_desktop(model: &mut LinkModel, port: u16, proxy: &mut dyn SystemProxy, tun: &mut dyn TunGrant) {
    let previous_proxy = model.system_proxy;
    if model.tun_wanted {
        // Ask before touching the system proxy, so a denial can leave it as it was.
        if !granted(tun.authorize()) || tun.set_enabled(true).is_err() {
            let _ = tun.set_enabled(false);
            model.tun = false;
            model.system_proxy = previous_proxy;
            model.connected = false;
            model.failure = Some(TUN_DENIED.to_string());
            return;
        }
        model.tun = true;
    } else if model.tun {
        let _ = tun.set_enabled(false);
        model.tun = false;
    }
    if open_proxy(model, port, proxy) {
        model.system_proxy = true;
        model.connected = true;
        model.failure = None;
    } else {
        model.system_proxy = false;
        model.connected = false;
    }
}

fn connect_android(model: &mut LinkModel, vpn: &mut dyn VpnGrant) {
    model.system_proxy = false;
    model.tun = false;
    match vpn.authorize() {
        Ok(true) => {
            if vpn.establish(&model.excluded).is_err() {
                let _ = vpn.close();
                model.vpn = false;
                model.connected = false;
                model.failure = Some("VPN 没有建立".to_string());
                return;
            }
            model.vpn = true;
            model.connected = true;
            model.failure = None;
        }
        _ => {
            let _ = vpn.close();
            model.vpn = false;
            model.connected = false;
            model.failure = Some(VPN_DENIED.to_string());
        }
    }
}

fn refresh_vpn(model: &mut LinkModel, vpn: &mut dyn VpnGrant) {
    if !model.vpn {
        return;
    }
    if vpn.establish(&model.excluded).is_err() {
        let _ = vpn.close();
        model.vpn = false;
        model.connected = false;
        model.failure = Some("VPN 没有建立".to_string());
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
    if package_name.is_empty() || package_name.chars().any(char::is_whitespace) {
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

    fn establish(&mut self, excluded: &[String]) -> Result<(), String> {
        self.establish_calls += 1;
        self.last_excluded = excluded.to_vec();
        self.open = true;
        Ok(())
    }

    fn close(&mut self) -> Result<(), String> {
        self.open = false;
        Ok(())
    }
}

/// In-process TUN gate. It does not create a device or change routing.
#[derive(Debug, Default)]
pub struct HostTun {
    #[allow(dead_code)]
    enabled: bool,
}

impl TunGrant for HostTun {
    fn authorize(&mut self) -> Result<bool, String> {
        Ok(true)
    }

    fn set_enabled(&mut self, enabled: bool) -> Result<(), String> {
        self.enabled = enabled;
        Ok(())
    }
}

/// Desktop never starts a VPN. Android consent arrives from [`report_vpn_consent`].
pub struct HostVpn {
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    directory: PathBuf,
}

impl HostVpn {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }
}

impl VpnGrant for HostVpn {
    fn authorize(&mut self) -> Result<bool, String> {
        #[cfg(target_os = "android")]
        {
            Ok(VPN_CONSENT.load(Ordering::SeqCst))
        }
        #[cfg(not(target_os = "android"))]
        {
            Ok(false)
        }
    }

    fn establish(&mut self, excluded: &[String]) -> Result<(), String> {
        #[cfg(target_os = "android")]
        {
            std::fs::create_dir_all(&self.directory).map_err(|_| "VPN 没有建立".to_string())?;
            let text = excluded.join("\n");
            return std::fs::write(excluded_file(&self.directory), text).map_err(|_| "VPN 没有建立".to_string());
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = excluded;
            Err("VPN 不可用".to_string())
        }
    }

    fn close(&mut self) -> Result<(), String> {
        #[cfg(target_os = "android")]
        {
            let _ = std::fs::remove_file(self.directory.join(EXCLUDE_FILE));
        }
        Ok(())
    }
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
static VPN_CONSENT: AtomicBool = AtomicBool::new(false);

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn report_vpn_consent(granted: bool) {
    VPN_CONSENT.store(granted, Ordering::SeqCst);
}

/// Kotlin `BillowVpnBridge.nativeConsent` reports the system dialog here.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_app_billow_client_BillowVpnService_nativeConsent(
    _env: *mut std::ffi::c_void,
    _class: *mut std::ffi::c_void,
    granted: u8,
) {
    report_vpn_consent(granted != 0);
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
    HostTun::default()
}

pub fn host_vpn(directory: impl Into<PathBuf>) -> HostVpn {
    HostVpn::new(directory)
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

        use super::super::{parse_macos_proxy, parse_network_services, ProxyEndpoint};

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
            let flag = if https { "-getsecurewebproxy" } else { "-getwebproxy" };
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

        use super::super::ProxyEndpoint;

        const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        pub fn set(endpoint: &ProxyEndpoint) -> Result<(), String> {
            let server = format!("{}:{}", endpoint.host, endpoint.port);
            reg(&["add", KEY, "/v", "ProxyServer", "/t", "REG_SZ", "/d", &server, "/f"])?;
            reg(&["add", KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"])?;
            Ok(())
        }

        pub fn clear_if_matches(endpoint: &ProxyEndpoint) -> Result<(), String> {
            let server = format!("{}:{}", endpoint.host, endpoint.port);
            let current = reg_query("ProxyServer");
            if current.as_deref() == Some(server.as_str()) {
                reg(&["add", KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"])?;
            }
            Ok(())
        }

        fn reg(args: &[&str]) -> Result<(), String> {
            let status = Command::new("reg")
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
            let output = Command::new("reg").args(["query", KEY, "/v", name]).output().ok()?;
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
            gsettings(&["set", "org.gnome.system.proxy.https", "host", &endpoint.host])?;
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
            if http_host.as_deref() == Some(host.as_str()) && http_port.as_deref() == Some(port.as_str()) {
                gsettings(&["set", "org.gnome.system.proxy.http", "host", ""])?;
            }
            if https_host.as_deref() == Some(host.as_str()) && https_port.as_deref() == Some(port.as_str()) {
                gsettings(&["set", "org.gnome.system.proxy.https", "host", ""])?;
            }
            let mode = gsettings_get(&["get", "org.gnome.system.proxy", "mode"]);
            if mode.as_deref() == Some("'manual'")
                && gsettings_get(&["get", "org.gnome.system.proxy.http", "host"]).as_deref() != Some(host.as_str())
                && gsettings_get(&["get", "org.gnome.system.proxy.https", "host"]).as_deref() != Some(host.as_str())
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
        let path = std::env::temp_dir().join(format!("billow-takeover-{name}-{}-{nanos}", std::process::id()));
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
        running: bool,
    }

    impl KernelLaunch for TestKernel {
        fn is_running(&self) -> bool {
            self.running
        }

        fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
            self.calls += 1;
            if self.fail {
                return Err("内核没有启动".to_string());
            }
            self.running = true;
            Ok(())
        }
    }

    fn ready_book(dir: &Path, platform: ClientPlatform) -> (ProfileBook, TestKernel) {
        let mut book = ProfileBook::open(dir);
        book.set_platform(platform);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = TestKernel {
            fail: false,
            calls: 0,
            running: false,
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
        let calls = kernel.calls;
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
        assert_eq!(kernel.calls, calls);
        assert!(!vpn.open);

        tun.grant = true;
        let enabled = book.set_tun(true, &mut tun);
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
        book.set_tun(true, &mut tun);
        let disconnected = book.disconnect(&mut proxy, &mut tun, &mut vpn);
        assert!(!disconnected.system_proxy && !disconnected.tun && !disconnected.vpn);
        assert!(!disconnected.connected);
        assert!(disconnected.tun_wanted);
        assert!(proxy.http.is_none() && proxy.https.is_none());
        assert!(!tun.enabled);

        let again = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(again.system_proxy && again.tun && again.connected);
        assert!(tun.enabled);
        assert_eq!(proxy.http.as_ref(), Some(&endpoint()));

        book.set_tun(false, &mut tun);
        book.disconnect(&mut proxy, &mut tun, &mut vpn);
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
        book.set_tun(true, &mut tun);
        book.disconnect(&mut proxy, &mut tun, &mut vpn);
        let mut reopened = ProfileBook::open(&dir.0);
        reopened.set_platform(ClientPlatform::Desktop);
        assert!(reopened.snapshot().tun_wanted);
        assert!(!reopened.snapshot().system_proxy && !reopened.snapshot().tun);
        let mut kernel = TestKernel {
            fail: false,
            calls: 0,
            running: false,
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

        let denied = book.set_tun(true, &mut tun);
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
        let again = book.set_tun(true, &mut tun);
        assert!(again.system_proxy);
        assert!(!again.tun);
        assert!(!again.connected);
        assert_eq!(again.failure.as_deref(), Some(TUN_DENIED));
        assert_eq!(proxy.sets, sets);
        assert_eq!(proxy.http.as_ref(), Some(&endpoint()));
        assert_eq!(proxy.https.as_ref(), Some(&endpoint()));

        book.set_tun(true, &mut tun);
        assert!(!book.snapshot().tun_wanted);
        tun.grant = true;
        book.set_tun(true, &mut tun);
        book.disconnect(&mut proxy, &mut tun, &mut vpn);
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
        book.disconnect(&mut proxy, &mut tun, &mut vpn);
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

        let excluded = book.exclude_package("com.example.mail", &mut vpn);
        assert_eq!(excluded.excluded, vec!["com.example.mail".to_string()]);
        assert_eq!(vpn.last_excluded, vec!["com.example.mail".to_string()]);
        assert!(!vpn.last_excluded.iter().any(|item| item == "com.example.browser"));

        book.exclude_package("com.example.mail", &mut vpn);
        assert_eq!(book.snapshot().excluded.len(), 1);
        book.exclude_package("  ", &mut vpn);
        assert_eq!(book.snapshot().excluded.len(), 1);

        let desktop_dir = temp_dir("desktop-exclude");
        let mut desktop = ProfileBook::open(&desktop_dir.0);
        desktop.set_platform(ClientPlatform::Desktop);
        desktop.exclude_package("com.example.mail", &mut vpn);
        assert!(desktop.snapshot().excluded.is_empty());

        let mut reopened = ProfileBook::open(&dir.0);
        reopened.set_platform(ClientPlatform::Android);
        assert_eq!(reopened.snapshot().excluded, vec!["com.example.mail".to_string()]);
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
        kernel.running = false;
        let failed = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!failed.vpn && !failed.connected);
        assert!(!failed.system_proxy && !failed.tun);
        assert_eq!(failed.failure.as_deref(), Some("内核没有启动"));
        assert_eq!(vpn.establish_calls, 0);
        assert!(!vpn.open);
    }

    #[test]
    fn desktop_kernel_failure_closes_system_proxy_and_tun() {
        let dir = temp_dir("kernel");
        let (mut book, mut kernel) = ready_book(&dir.0, ClientPlatform::Desktop);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        book.set_tun(true, &mut tun);
        kernel.fail = true;
        kernel.running = false;
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
            parse_network_services("An asterisk (*) denotes that a network service is disabled.\n*Disabled\nWi-Fi\n"),
            vec!["Wi-Fi".to_string()]
        );
    }

    #[test]
    fn android_vpn_service_establishes_tun_and_reports_consent() {
        let source = include_str!("../android/app/src/main/java/app/billow/client/BillowVpnService.kt");
        assert!(source.contains("VpnService"));
        assert!(source.contains("addDisallowedApplication"));
        assert!(source.contains("nativeConsent"));
        assert!(source.contains("profiles/vpn/vpn-excluded.txt"));
        assert!(!source.to_ascii_lowercase().contains("mihomo"));
        let manifest = include_str!("../android/app/src/main/AndroidManifest.xml");
        assert!(manifest.contains("android.net.VpnService"));
        assert!(manifest.contains("BIND_VPN_SERVICE"));
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
