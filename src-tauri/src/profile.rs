use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

use crate::diagnostics::{self, ConnectionView, LogView, TrafficTotals};
use crate::nodes::{
    self, ControllerEndpoint, KERNEL_DOWN, NEED_PROFILE, NO_MATCH, NO_NODES, NOT_MANUAL, NodeDelay,
    NodeGroupView, ParsedGroup, SELECT_FAILED,
};
use crate::takeover::{
    self, ClientPlatform, PlatformRelease, ProxyEndpoint, SystemProxy, TunGrant, VpnGrant,
};

const BODY_LIMIT: u64 = 2_000_000;
const CONTENT_ERROR: &str = "配置无法应用";
const OVERRIDE_ERROR: &str = "覆写无法应用";
const FETCH_ERROR: &str = "订阅没有取回";
const KERNEL_ERROR: &str = "内核没有启动";
const MISSING_KERNEL: &str = "没有本地内核";
const LINK_ERROR: &str = "不支持这个导入链接";
const ONE_LINK_ERROR: &str = "需要一条订阅链接";
const URL_ERROR: &str = "订阅链接不可用";
const DUPLICATE_ERROR: &str = "该订阅已存在";
const MISSING_PROFILE: &str = "没有这份配置";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ProfileKind {
    Subscription,
    Local,
}

impl ProfileKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Subscription => "subscription",
            Self::Local => "local",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Usage {
    used: Option<u64>,
    total: Option<u64>,
    expire: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Profile {
    id: String,
    name: String,
    kind: ProfileKind,
    source: String,
    content: String,
    override_text: String,
    /// Override included in the last successful apply. Editor text can be newer.
    applied_override: String,
    override_error: Option<String>,
    failure: Option<String>,
    last_success_ms: Option<u64>,
    usage: Option<Usage>,
    selected: BTreeMap<String, String>,
    interval_hours: u32,
    updated_ms: Option<u64>,
    proxy_count: usize,
}

/// Values the app writes over every profile before the kernel starts. `None` follows the profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KernelSettings {
    #[serde(default)]
    pub mixed_port: Option<u16>,
    #[serde(default)]
    pub allow_lan: Option<bool>,
    #[serde(default)]
    pub ipv6: Option<bool>,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub unified_delay: Option<bool>,
    #[serde(default)]
    pub tcp_concurrent: Option<bool>,
    #[serde(default)]
    pub find_process_mode: Option<String>,
    #[serde(default)]
    pub test_url: String,
    #[serde(default)]
    pub test_timeout_ms: u64,
    /// Domain sniffing; `None` follows the profile.
    #[serde(default)]
    pub sniffer: Option<bool>,
    /// When on, the app's `dns` block replaces the profile's.
    #[serde(default)]
    pub dns_override: bool,
    #[serde(default)]
    pub dns: DnsSettings,
    #[serde(default)]
    pub tun: TunSettings,
    /// GEO databases: `None` follows the profile.
    #[serde(default)]
    pub geo_auto_update: Option<bool>,
    #[serde(default)]
    pub geo_update_interval: Option<u32>,
    /// Download source for GEO databases: `""` follows the profile's `geox-url`.
    #[serde(default)]
    pub geo_source: String,
}

/// `geox-url` for a named GEO source; `None` leaves the profile's own value.
pub fn geo_source_urls(source: &str) -> Option<[(&'static str, String); 4]> {
    let base = match source {
        "github" => "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest",
        "jsdelivr" => "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release",
        "testingcf" => "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release",
        _ => return None,
    };
    Some([
        ("geoip", format!("{base}/geoip.dat")),
        ("geosite", format!("{base}/geosite.dat")),
        ("mmdb", format!("{base}/geoip.metadb")),
        ("asn", format!("{base}/GeoLite2-ASN.mmdb")),
    ])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsSettings {
    pub enhanced_mode: String,
    pub fake_ip_range: String,
    pub fake_ip_filter: Vec<String>,
    pub ipv6: bool,
    pub use_hosts: bool,
    pub respect_rules: bool,
    pub default_nameserver: Vec<String>,
    pub nameserver: Vec<String>,
    pub fallback: Vec<String>,
    pub proxy_server_nameserver: Vec<String>,
    pub direct_nameserver: Vec<String>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        let list = |items: &[&str]| items.iter().map(|item| item.to_string()).collect();
        Self {
            enhanced_mode: "fake-ip".to_string(),
            fake_ip_range: "198.18.0.1/16".to_string(),
            fake_ip_filter: list(&[
                "*.lan",
                "*.local",
                "*.localdomain",
                "localhost.ptlogin2.qq.com",
                "+.msftconnecttest.com",
                "+.msftncsi.com",
                "+.stun.*.*",
                "+.stun.*.*.*",
                "time.*.com",
                "ntp.*.com",
                "+.market.xiaomi.com",
            ]),
            ipv6: false,
            use_hosts: true,
            respect_rules: false,
            default_nameserver: list(&["223.5.5.5", "119.29.29.29"]),
            nameserver: list(&["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]),
            fallback: Vec::new(),
            proxy_server_nameserver: list(&["https://doh.pub/dns-query"]),
            direct_nameserver: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TunSettings {
    pub stack: String,
    pub auto_route: bool,
    pub auto_detect_interface: bool,
    pub strict_route: bool,
    pub dns_hijack: Vec<String>,
    pub mtu: u32,
    pub device: String,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self {
            stack: "mixed".to_string(),
            auto_route: true,
            auto_detect_interface: true,
            strict_route: false,
            dns_hijack: vec!["any:53".to_string(), "tcp://any:53".to_string()],
            mtu: 1500,
            device: String::new(),
        }
    }
}

fn clean_list(items: Vec<String>, limit: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let item: String = item.trim().chars().filter(|ch| !ch.is_control()).take(300).collect();
        if !item.is_empty() && !out.contains(&item) {
            out.push(item);
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

impl DnsSettings {
    fn normalized(mut self) -> Self {
        let fallback = Self::default();
        self.enhanced_mode = match self.enhanced_mode.trim().to_ascii_lowercase().as_str() {
            "redir-host" => "redir-host".to_string(),
            "normal" => "normal".to_string(),
            _ => "fake-ip".to_string(),
        };
        self.fake_ip_range = self.fake_ip_range.trim().to_string();
        if self.fake_ip_range.is_empty() || !self.fake_ip_range.contains('/') {
            self.fake_ip_range = fallback.fake_ip_range;
        }
        self.fake_ip_filter = clean_list(self.fake_ip_filter, 500);
        self.default_nameserver = clean_list(self.default_nameserver, 20);
        self.nameserver = clean_list(self.nameserver, 20);
        self.fallback = clean_list(self.fallback, 20);
        self.proxy_server_nameserver = clean_list(self.proxy_server_nameserver, 20);
        self.direct_nameserver = clean_list(self.direct_nameserver, 20);
        if self.nameserver.is_empty() {
            self.nameserver = fallback.nameserver;
        }
        if self.default_nameserver.is_empty() {
            self.default_nameserver = fallback.default_nameserver;
        }
        self
    }

    fn to_value(&self) -> Value {
        let key = |name: &str| Value::String(name.to_string());
        let strings =
            |items: &[String]| Value::Sequence(items.iter().map(|item| Value::String(item.clone())).collect());
        let mut map = serde_yaml::Mapping::new();
        map.insert(key("enable"), Value::Bool(true));
        map.insert(key("ipv6"), Value::Bool(self.ipv6));
        map.insert(key("use-hosts"), Value::Bool(self.use_hosts));
        map.insert(key("respect-rules"), Value::Bool(self.respect_rules));
        map.insert(key("enhanced-mode"), Value::String(self.enhanced_mode.clone()));
        if self.enhanced_mode == "fake-ip" {
            map.insert(key("fake-ip-range"), Value::String(self.fake_ip_range.clone()));
            map.insert(key("fake-ip-filter"), strings(&self.fake_ip_filter));
        }
        map.insert(key("default-nameserver"), strings(&self.default_nameserver));
        map.insert(key("nameserver"), strings(&self.nameserver));
        if !self.fallback.is_empty() {
            map.insert(key("fallback"), strings(&self.fallback));
        }
        if !self.proxy_server_nameserver.is_empty() {
            map.insert(key("proxy-server-nameserver"), strings(&self.proxy_server_nameserver));
        }
        if !self.direct_nameserver.is_empty() {
            map.insert(key("direct-nameserver"), strings(&self.direct_nameserver));
        }
        Value::Mapping(map)
    }
}

impl TunSettings {
    fn normalized(mut self) -> Self {
        self.stack = match self.stack.trim().to_ascii_lowercase().as_str() {
            "system" => "system".to_string(),
            "gvisor" => "gvisor".to_string(),
            _ => "mixed".to_string(),
        };
        self.dns_hijack = clean_list(self.dns_hijack, 20);
        self.mtu = if self.mtu == 0 { 0 } else { self.mtu.clamp(576, 9000) };
        self.device = self
            .device
            .trim()
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
            .take(32)
            .collect();
        self
    }
}

/// What the active profile itself says, so the settings page can show "follow profile" values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct ConfigValues {
    pub mixed_port: Option<i64>,
    pub allow_lan: Option<bool>,
    pub ipv6: Option<bool>,
    pub log_level: Option<String>,
    pub unified_delay: Option<bool>,
    pub tcp_concurrent: Option<bool>,
    pub find_process_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProvidersSnapshot {
    pub providers: Vec<diagnostics::ProviderView>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RulesSnapshot {
    pub rules: Vec<diagnostics::RuleRowView>,
    pub error: Option<String>,
    /// Rule keys disabled for this run; cleared when the app restarts or the config changes.
    pub disabled: Vec<String>,
}

/// One runtime rule toggle from the rules page.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleToggle {
    pub key: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Takeover {
    system_proxy: bool,
    tun: bool,
    vpn: bool,
}

impl Default for Takeover {
    fn default() -> Self {
        Self {
            system_proxy: false,
            tun: false,
            vpn: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct ProfileView {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub source: String,
    pub current: bool,
    pub failure: Option<String>,
    pub override_text: String,
    pub override_error: Option<String>,
    pub used: Option<u64>,
    pub total: Option<u64>,
    pub expire: Option<u64>,
    pub last_success_ms: Option<u64>,
    pub interval_hours: u32,
    pub updated_ms: Option<u64>,
    pub proxy_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct ProfileSnapshot {
    pub profiles: Vec<ProfileView>,
    pub active_id: Option<String>,
    pub mixed_port: Option<i64>,
    pub mode: Option<String>,
    pub system_proxy: bool,
    pub tun: bool,
    pub vpn: bool,
    pub pending_url: Option<String>,
    pub failure: Option<String>,
    pub input_error: Option<String>,
    pub connected: bool,
    pub platform: String,
    pub tun_wanted: bool,
    pub excluded: Vec<String>,
    pub installed: Vec<crate::takeover::InstalledApp>,
    pub node_groups: Vec<NodeGroupView>,
    pub node_catalog: Vec<NodeGroupView>,
    pub node_query: String,
    pub nodes_notice: Option<String>,
    pub nodes_error: Option<String>,
    pub nodes_profile_id: Option<String>,
    pub kernel_running: bool,
    /// Kernel memory in bytes; `None` when the kernel does not report it.
    pub kernel_memory: Option<u64>,
    /// Seconds since the kernel process started; `None` while it is not running.
    pub kernel_uptime_secs: Option<u64>,
    pub connections: Vec<ConnectionView>,
    /// Open connections the kernel reported, even when the list keeps only 500 rows.
    pub connection_total: usize,
    /// Set when `/connections` could not be read; empty results are not failures.
    pub connections_error: Option<String>,
    pub connection_query: String,
    pub logs: Vec<LogView>,
    pub log_filter: String,
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub upload_total: Option<u64>,
    pub download_total: Option<u64>,
    pub settings: KernelSettings,
    pub config_values: ConfigValues,
    pub notice: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedSubscription {
    pub content: String,
    pub userinfo: Option<String>,
}

pub trait SubscriptionSource {
    fn fetch(&self, url: &str) -> Result<FetchedSubscription, String>;
}

pub trait KernelLaunch {
    fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String>;

    /// Applies a filtered runtime config without restarting the process, so the
    /// rule list can be toggled while TUN/VPN stays up.
    fn reload_config(&mut self, config_yaml: &str) -> Result<(), String> {
        self.start_or_reload(config_yaml)
    }

    fn running(&mut self) -> bool {
        false
    }

    fn select_proxy(&mut self, _group: &str, _node: &str) -> Result<(), String> {
        Err(KERNEL_DOWN.to_string())
    }

    fn probe_delays(&mut self, _group: &str, _nodes: &[String]) -> Result<Vec<NodeDelay>, String> {
        Err(KERNEL_DOWN.to_string())
    }

    /// Reports each finished node as it returns, then the ordered results.
    fn probe_delays_with_progress(
        &mut self,
        group: &str,
        nodes: &[String],
        on_result: &mut dyn FnMut(&str, Option<u64>, bool),
    ) -> Result<Vec<NodeDelay>, String> {
        let results = self.probe_delays(group, nodes)?;
        for item in &results {
            on_result(&item.name, item.delay_ms, item.delay_ms.is_none());
        }
        Ok(results)
    }

    fn auto_now(&mut self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    fn connections(&mut self) -> Vec<ConnectionView> {
        Vec::new()
    }

    /// Open connections counted by the last `/connections` read, before the view keeps 500 rows.
    fn connection_total(&mut self) -> Option<usize> {
        None
    }

    /// Why the last `/connections` read failed, if it did.
    fn connections_error(&mut self) -> Option<String> {
        None
    }

    /// Kernel memory in bytes, from `/memory`. `None` when the kernel does not report it.
    fn kernel_memory(&mut self) -> Option<u64> {
        None
    }

    /// Seconds since this kernel process started, tracked by the app.
    fn kernel_uptime_secs(&mut self) -> Option<u64> {
        None
    }

    fn pull_logs(&mut self) -> Vec<LogView> {
        Vec::new()
    }

    fn set_mode(&mut self, _mode: &str) -> Result<(), String> {
        Ok(())
    }

    fn traffic(&mut self) -> Option<(u64, u64)> {
        None
    }

    /// Byte totals from the last `/connections` read.
    fn connection_totals(&mut self) -> Option<TrafficTotals> {
        None
    }

    /// Loopback controller of the running kernel, for one-off reads such as rules.
    fn controller(&mut self) -> Option<ControllerEndpoint> {
        None
    }
}

pub struct HttpSubscriptionClient {
    agent: ureq::Agent,
}

impl HttpSubscriptionClient {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(30))
            .build();
        Self { agent }
    }
}

impl Default for HttpSubscriptionClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscriptionSource for HttpSubscriptionClient {
    fn fetch(&self, url: &str) -> Result<FetchedSubscription, String> {
        if validate_subscription_url(url).is_err() {
            return Err(FETCH_ERROR.to_string());
        }
        let response = self
            .agent
            .get(url)
            .set("User-Agent", "Billow")
            .call()
            .map_err(|_| FETCH_ERROR.to_string())?;
        let userinfo = response.header("subscription-userinfo").map(str::to_string);
        let mut body = Vec::new();
        response
            .into_reader()
            .take(BODY_LIMIT + 1)
            .read_to_end(&mut body)
            .map_err(|_| FETCH_ERROR.to_string())?;
        if body.len() as u64 > BODY_LIMIT {
            return Err(FETCH_ERROR.to_string());
        }
        let text = String::from_utf8(body).map_err(|_| FETCH_ERROR.to_string())?;
        Ok(FetchedSubscription {
            content: normalize_subscription_content(&text),
            userinfo,
        })
    }
}

/// Spawns the already installed kernel. Tests inject [`KernelLaunch`] instead.
pub struct ProcessRuntime {
    kernel_path: Option<PathBuf>,
    work_dir: PathBuf,
    child: Option<Child>,
    config_path: Option<PathBuf>,
    controller: Option<ControllerEndpoint>,
    cached_now: BTreeMap<String, String>,
    log_buffer: Option<CapturedLogs>,
    traffic_watch: Option<TrafficWatch>,
    totals: Option<TrafficTotals>,
    connection_total: Option<usize>,
    connections_error: Option<String>,
    started: Option<Instant>,
}

struct TrafficWatch {
    latest: Arc<Mutex<Option<(u64, u64)>>>,
    stop: Arc<AtomicBool>,
    waited: bool,
}

impl TrafficWatch {
    fn spawn(endpoint: ControllerEndpoint) -> Self {
        let latest = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::clone(&latest);
        let flag = Arc::clone(&stop);
        std::thread::spawn(move || diagnostics::watch_traffic(endpoint, shared, flag));
        Self {
            latest,
            stop,
            waited: false,
        }
    }

    fn latest(&self) -> Option<(u64, u64)> {
        *self
            .latest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn halt(self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl ProcessRuntime {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            kernel_path: None,
            work_dir: work_dir.into(),
            child: None,
            config_path: None,
            controller: None,
            cached_now: BTreeMap::new(),
            log_buffer: None,
            traffic_watch: None,
            totals: None,
            connection_total: None,
            connections_error: None,
            started: None,
        }
    }

    pub fn set_kernel_path(&mut self, path: Option<PathBuf>) {
        self.kernel_path = path;
    }

    fn stop(&mut self) {
        self.halt_traffic();
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            {
                let pid = child.id();
                let _ = Command::new("kill")
                    .args(["-KILL", &format!("-{pid}")])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(path) = self.config_path.take() {
            let _ = fs::remove_file(path);
        }
        self.controller = None;
        self.cached_now.clear();
        self.log_buffer = None;
        self.totals = None;
        self.connection_total = None;
        self.connections_error = None;
        self.started = None;
    }

    fn halt_traffic(&mut self) {
        if let Some(watch) = self.traffic_watch.take() {
            watch.halt();
        }
    }
}

struct CapturedLogs {
    lines: Arc<Mutex<Vec<LogView>>>,
}

fn spawn_log_buffer(stdout: ChildStdout) -> CapturedLogs {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let shared = Arc::clone(&lines);
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let Some(item) = diagnostics::parse_log_line(&line) else {
                continue;
            };
            let mut guard = shared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.push(item);
            let overflow = guard.len().saturating_sub(diagnostics::LOG_LIMIT);
            if overflow > 0 {
                guard.drain(0..overflow);
            }
        }
    });
    CapturedLogs { lines }
}

impl Drop for ProcessRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

impl KernelLaunch for ProcessRuntime {
    fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
        let Some(path) = self.kernel_path.clone() else {
            return Err(MISSING_KERNEL.to_string());
        };
        if !path.is_file() {
            return Err(MISSING_KERNEL.to_string());
        }
        fs::create_dir_all(&self.work_dir).map_err(|_| "配置没有写入".to_string())?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let config_path = self.work_dir.join(format!("runtime-{nanos}.yaml"));
        fs::write(&config_path, config_yaml).map_err(|_| "配置没有写入".to_string())?;
        let controller = nodes::controller_from_yaml(config_yaml);
        let mut command = Command::new(&path);
        command
            .arg("-f")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        // A stand-in process has no controller. Leaving its stdout discarded avoids a full pipe.
        if controller.is_some() {
            command.stdout(Stdio::piped());
        } else {
            command.stdout(Stdio::null());
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Own process group so stopping the kernel does not signal this app.
            command.process_group(0);
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                let _ = fs::remove_file(&config_path);
                return Err(KERNEL_ERROR.to_string());
            }
        };
        let deadline = std::time::Instant::now() + Duration::from_millis(300);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    let _ = fs::remove_file(&config_path);
                    return Err(KERNEL_ERROR.to_string());
                }
                Ok(None) if std::time::Instant::now() >= deadline => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => {
                    let _ = fs::remove_file(&config_path);
                    return Err(KERNEL_ERROR.to_string());
                }
            }
        }
        let stdout = child.stdout.take();
        self.stop();
        self.started = Some(Instant::now());
        self.child = Some(child);
        self.config_path = Some(config_path);
        self.controller = controller;
        self.cached_now.clear();
        if let Some(stdout) = stdout {
            self.log_buffer = Some(spawn_log_buffer(stdout));
        }
        if let Some(endpoint) = self.controller.clone() {
            self.traffic_watch = Some(TrafficWatch::spawn(endpoint));
        }
        Ok(())
    }

    fn running(&mut self) -> bool {
        let alive = match self.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        };
        if !alive {
            self.child = None;
            self.controller = None;
            self.cached_now.clear();
            self.halt_traffic();
        }
        alive
    }

    fn select_proxy(&mut self, group: &str, node: &str) -> Result<(), String> {
        if !self.running() {
            return Err(KERNEL_DOWN.to_string());
        }
        let Some(endpoint) = self.controller.clone() else {
            return Err(KERNEL_DOWN.to_string());
        };
        let mut last = SELECT_FAILED.to_string();
        for _ in 0..5 {
            match nodes::put_selection(&endpoint, group, node) {
                Ok(()) => return Ok(()),
                Err(message) => last = message,
            }
            if !self.running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(last)
    }

    fn probe_delays(&mut self, _group: &str, names: &[String]) -> Result<Vec<NodeDelay>, String> {
        if !self.running() {
            return Err(KERNEL_DOWN.to_string());
        }
        let Some(endpoint) = self.controller.clone() else {
            return Err(KERNEL_DOWN.to_string());
        };
        nodes::fetch_delays(&endpoint, names)
    }

    fn probe_delays_with_progress(
        &mut self,
        _group: &str,
        names: &[String],
        on_result: &mut dyn FnMut(&str, Option<u64>, bool),
    ) -> Result<Vec<NodeDelay>, String> {
        if !self.running() {
            return Err(KERNEL_DOWN.to_string());
        }
        let Some(endpoint) = self.controller.clone() else {
            return Err(KERNEL_DOWN.to_string());
        };
        nodes::fetch_delays_with_progress(&endpoint, names, on_result)
    }

    fn reload_config(&mut self, config_yaml: &str) -> Result<(), String> {
        if !self.running() {
            return Err(KERNEL_DOWN.to_string());
        }
        let Some(endpoint) = self.controller.clone() else {
            return Err(KERNEL_DOWN.to_string());
        };
        nodes::put_config(&endpoint, config_yaml)
    }

    fn auto_now(&mut self) -> BTreeMap<String, String> {
        if !self.running() {
            return BTreeMap::new();
        }
        let Some(endpoint) = self.controller.clone() else {
            return BTreeMap::new();
        };
        match nodes::fetch_now(&endpoint) {
            Ok(now) => {
                self.cached_now = now.clone();
                now
            }
            Err(_) => self.cached_now.clone(),
        }
    }

    fn connections(&mut self) -> Vec<ConnectionView> {
        if !self.running() {
            return Vec::new();
        }
        let Some(endpoint) = self.controller.clone() else {
            return Vec::new();
        };
        let reading = diagnostics::fetch_connections_with_totals(&endpoint);
        self.totals = reading.totals;
        self.connection_total = Some(reading.total);
        self.connections_error = reading.error;
        reading.rows
    }

    fn connection_total(&mut self) -> Option<usize> {
        self.connection_total
    }

    fn connections_error(&mut self) -> Option<String> {
        self.connections_error.clone()
    }

    fn kernel_memory(&mut self) -> Option<u64> {
        if !self.running() {
            return None;
        }
        let endpoint = self.controller.clone()?;
        diagnostics::fetch_memory(&endpoint)
    }

    fn kernel_uptime_secs(&mut self) -> Option<u64> {
        if !self.running() {
            return None;
        }
        self.started.map(|start| start.elapsed().as_secs())
    }

    fn connection_totals(&mut self) -> Option<TrafficTotals> {
        self.totals
    }

    fn controller(&mut self) -> Option<ControllerEndpoint> {
        if !self.running() {
            return None;
        }
        self.controller.clone()
    }

    fn pull_logs(&mut self) -> Vec<LogView> {
        let Some(buffer) = &self.log_buffer else {
            return Vec::new();
        };
        let mut guard = buffer
            .lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut *guard)
    }

    fn set_mode(&mut self, mode: &str) -> Result<(), String> {
        if !self.running() {
            return Ok(());
        }
        let Some(endpoint) = self.controller.clone() else {
            return Ok(());
        };
        nodes::patch_mode(&endpoint, mode)
    }

    fn traffic(&mut self) -> Option<(u64, u64)> {
        if !self.running() {
            return None;
        }
        let Some(watch) = self.traffic_watch.as_mut() else {
            return None;
        };
        if let Some(sample) = watch.latest() {
            return Some(sample);
        }
        // The controller emits the first sample after its one-second tick.
        if watch.waited {
            return None;
        }
        watch.waited = true;
        let deadline = Instant::now() + Duration::from_millis(1200);
        while Instant::now() < deadline {
            if let Some(sample) = watch.latest() {
                return Some(sample);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        watch.latest()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DiskState {
    #[serde(default)]
    next_id: u64,
    #[serde(default)]
    active_id: Option<String>,
    #[serde(default)]
    home_failure: Option<String>,
    #[serde(default)]
    tun_wanted: bool,
    #[serde(default)]
    excluded_packages: Vec<String>,
    #[serde(default)]
    proxy_host: Option<String>,
    #[serde(default)]
    proxy_port: Option<u16>,
    #[serde(default)]
    profiles: Vec<DiskProfile>,
    #[serde(default)]
    chosen_mode: Option<String>,
    #[serde(default)]
    settings: KernelSettings,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiskProfile {
    id: String,
    name: String,
    kind: ProfileKind,
    source: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    override_text: String,
    #[serde(default)]
    applied_override: String,
    #[serde(default)]
    override_error: Option<String>,
    #[serde(default)]
    failure: Option<String>,
    #[serde(default)]
    last_success_ms: Option<u64>,
    #[serde(default)]
    used: Option<u64>,
    #[serde(default)]
    total: Option<u64>,
    #[serde(default)]
    expire: Option<u64>,
    #[serde(default)]
    selected: BTreeMap<String, String>,
    #[serde(default)]
    interval_hours: u32,
    #[serde(default)]
    updated_ms: Option<u64>,
}

pub struct ProfileBook {
    path: PathBuf,
    next_id: u64,
    active_id: Option<String>,
    profiles: Vec<Profile>,
    takeover: Takeover,
    pending_url: Option<String>,
    home_failure: Option<String>,
    input_error: Option<String>,
    mixed_port: Option<i64>,
    mode: Option<String>,
    platform: ClientPlatform,
    tun_wanted: bool,
    excluded: Vec<String>,
    installed: Vec<crate::takeover::InstalledApp>,
    connected: bool,
    our_endpoint: Option<ProxyEndpoint>,
    pending_release: Option<PlatformRelease>,
    node_query: String,
    node_sort: BTreeMap<String, String>,
    delays: BTreeMap<String, BTreeMap<String, BTreeMap<String, DelayMark>>>,
    auto_now: BTreeMap<String, String>,
    nodes_error: Option<String>,
    kernel_running: bool,
    kernel_memory: Option<u64>,
    kernel_uptime_secs: Option<u64>,
    connections: Vec<ConnectionView>,
    connection_total: usize,
    connections_error: Option<String>,
    connection_query: String,
    logs: Vec<LogView>,
    log_filter: String,
    /// Runtime-only disabled rule keys; never persisted, so a restart re-enables rules.
    disabled_rules: BTreeSet<String>,
    /// Last unfiltered runtime config, kept so later toggles filter the full rule
    /// list (stable occurrence keys) while preserving TUN fd and settings.
    runtime_base: Option<String>,
    chosen_mode: Option<String>,
    upload: Option<u64>,
    download: Option<u64>,
    totals: Option<TrafficTotals>,
    settings: KernelSettings,
    notice: Option<String>,
}

struct DelayMark {
    delay_ms: Option<u64>,
    failed: bool,
}

impl ProfileBook {
    pub fn open(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        let path = directory.join("profiles.json");
        let mut book = Self {
            path,
            next_id: 1,
            active_id: None,
            profiles: Vec::new(),
            takeover: Takeover::default(),
            pending_url: None,
            home_failure: None,
            input_error: None,
            mixed_port: None,
            mode: None,
            platform: ClientPlatform::current(),
            tun_wanted: false,
            excluded: Vec::new(),
            installed: Vec::new(),
            connected: false,
            our_endpoint: None,
            pending_release: None,
            node_query: String::new(),
            node_sort: BTreeMap::new(),
            delays: BTreeMap::new(),
            auto_now: BTreeMap::new(),
            nodes_error: None,
            kernel_running: false,
            kernel_memory: None,
            kernel_uptime_secs: None,
            connections: Vec::new(),
            connection_total: 0,
            connections_error: None,
            connection_query: String::new(),
            logs: Vec::new(),
            log_filter: "all".to_string(),
            disabled_rules: BTreeSet::new(),
            runtime_base: None,
            chosen_mode: None,
            upload: None,
            download: None,
            totals: None,
            settings: KernelSettings::default(),
            notice: None,
        };
        book.load();
        book
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn set_platform(&mut self, platform: ClientPlatform) {
        self.platform = platform;
    }

    pub fn snapshot(&self) -> ProfileSnapshot {
        let profiles = self
            .profiles
            .iter()
            .map(|profile| ProfileView {
                id: profile.id.clone(),
                name: profile.name.clone(),
                kind: profile.kind.as_str().to_string(),
                source: profile.source.clone(),
                current: self.active_id.as_deref() == Some(profile.id.as_str()),
                failure: profile.failure.clone(),
                override_text: profile.override_text.clone(),
                override_error: profile.override_error.clone(),
                used: profile.usage.as_ref().and_then(|usage| usage.used),
                total: profile.usage.as_ref().and_then(|usage| usage.total),
                expire: profile.usage.as_ref().and_then(|usage| usage.expire),
                last_success_ms: profile.last_success_ms,
                interval_hours: profile.interval_hours,
                updated_ms: profile.updated_ms,
                proxy_count: profile.proxy_count,
            })
            .collect();
        let (node_catalog, node_groups, nodes_notice, nodes_profile_id) = self.node_views();
        ProfileSnapshot {
            profiles,
            active_id: self.active_id.clone(),
            mixed_port: self.mixed_port,
            mode: self.mode.clone(),
            system_proxy: self.takeover.system_proxy,
            tun: self.takeover.tun,
            vpn: self.takeover.vpn,
            pending_url: self.pending_url.clone(),
            failure: self.home_failure.clone(),
            input_error: self.input_error.clone(),
            connected: self.connected,
            platform: self.platform.as_str().to_string(),
            tun_wanted: self.tun_wanted,
            excluded: self.excluded.clone(),
            installed: self.installed.clone(),
            node_groups,
            node_catalog,
            node_query: self.node_query.clone(),
            nodes_notice,
            nodes_error: self.nodes_error.clone(),
            nodes_profile_id,
            kernel_running: self.kernel_running,
            kernel_memory: self.kernel_memory,
            kernel_uptime_secs: self.kernel_uptime_secs,
            connections: if self.connected {
                diagnostics::filter_connections(&self.connections, &self.connection_query)
            } else {
                Vec::new()
            },
            connection_total: if self.connected { self.connection_total } else { 0 },
            connections_error: if self.connected {
                self.connections_error.clone()
            } else {
                None
            },
            connection_query: self.connection_query.clone(),
            logs: diagnostics::filter_logs(&self.logs, &self.log_filter),
            log_filter: self.log_filter.clone(),
            upload: self.upload,
            download: self.download,
            upload_total: self.totals.map(|item| item.upload),
            download_total: self.totals.map(|item| item.download),
            settings: self.settings.clone(),
            config_values: self.config_values(),
            notice: self.notice.clone(),
        }
    }

    pub fn set_installed(&mut self, apps: Vec<crate::takeover::InstalledApp>) {
        self.installed = apps;
    }

    /// Android home reads installed apps into the snapshot. Desktop has no per-app exclusion.
    pub fn refresh_installed(&mut self, source: &mut dyn takeover::InstalledApps) {
        if self.platform != ClientPlatform::Android {
            self.installed.clear();
            return;
        }
        if let Ok(apps) = source.list() {
            self.installed = takeover::normalize_installed(apps);
        }
    }

    pub fn matching_installed(&self, query: &str) -> Vec<&crate::takeover::InstalledApp> {
        takeover::filter_installed(&self.installed, query)
    }

    /// On exit and the next launch, clear a system proxy that still points at our last port.
    pub fn release_lingering_proxy(&mut self, proxy: &mut dyn SystemProxy) {
        let Some(endpoint) = self.our_endpoint.clone() else {
            return;
        };
        match proxy.clear_if_pointing_at(&endpoint) {
            Ok(()) => {
                self.takeover.system_proxy = false;
                self.connected = false;
                self.our_endpoint = None;
                if self.home_failure.as_deref() == Some("系统代理没有关闭") {
                    self.home_failure = None;
                }
                self.persist();
            }
            Err(message) => {
                self.takeover.system_proxy = true;
                self.connected = false;
                self.home_failure = Some(if message.is_empty() {
                    "系统代理没有关闭".to_string()
                } else {
                    message
                });
                self.persist();
            }
        }
    }

    pub fn add_subscription(&mut self, url: &str) -> ProfileSnapshot {
        match validate_subscription_url(url.trim()) {
            Ok(url) => {
                // Trimmed comparison against existing sources: deep links and other
                // entry points cannot silently add a duplicate card (R27).
                if self
                    .profiles
                    .iter()
                    .any(|profile| profile.kind == ProfileKind::Subscription && profile.source.trim() == url)
                {
                    self.input_error = Some(DUPLICATE_ERROR.to_string());
                } else {
                    self.push_profile(
                        ProfileKind::Subscription,
                        subscription_name(&url),
                        url,
                        String::new(),
                    );
                    self.input_error = None;
                    self.persist();
                }
            }
            Err(message) => self.input_error = Some(message),
        }
        self.snapshot()
    }

    pub fn add_local(&mut self, name: &str, content: &str) -> ProfileSnapshot {
        if content.trim().is_empty() {
            self.input_error = Some(CONTENT_ERROR.to_string());
            return self.snapshot();
        }
        let name = clean_name(name, "本地配置");
        self.push_profile(ProfileKind::Local, name, String::new(), content.to_string());
        self.input_error = None;
        self.persist();
        self.snapshot()
    }

    pub fn stage_install_link(&mut self, raw: &str) -> ProfileSnapshot {
        match parse_install_link(raw) {
            Ok(url) => {
                self.pending_url = Some(url);
                self.input_error = None;
            }
            Err(message) => self.input_error = Some(message),
        }
        self.snapshot()
    }

    pub fn confirm_pending(&mut self) -> ProfileSnapshot {
        let Some(url) = self.pending_url.clone() else {
            return self.snapshot();
        };
        let before = self.profiles.len();
        let snapshot = self.add_subscription(&url);
        if self.profiles.len() == before + 1 {
            self.pending_url = None;
            self.input_error = None;
            self.persist();
        }
        if self.pending_url.is_none() {
            return self.snapshot();
        }
        snapshot
    }

    pub fn cancel_pending(&mut self) -> ProfileSnapshot {
        self.pending_url = None;
        self.input_error = None;
        self.snapshot()
    }

    pub fn save_override(&mut self, id: &str, text: &str) -> ProfileSnapshot {
        if let Some(profile) = self.profiles.iter_mut().find(|profile| profile.id == id) {
            profile.override_text = text.to_string();
            self.input_error = None;
            self.persist();
        } else {
            self.input_error = Some(MISSING_PROFILE.to_string());
        }
        self.snapshot()
    }

    pub fn enable(
        &mut self,
        id: &str,
        source: &dyn SubscriptionSource,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        self.activate(id, source, kernel)
    }

    pub fn update(
        &mut self,
        id: &str,
        source: &dyn SubscriptionSource,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        self.activate(id, source, kernel)
    }

    pub fn connect(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        // A new connection attempt retires the previous home failure. Switches do not.
        self.home_failure = None;
        if self.platform == ClientPlatform::Android {
            return self.connect_android(kernel, vpn);
        }
        self.connect_desktop(kernel, proxy, tun, vpn)
    }

    pub fn disconnect(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        let _ = self.reload(kernel, false, None);
        let mut model = self.link_model();
        takeover::disconnect(&mut model, proxy, tun, vpn);
        self.apply_model(model);
        self.connections.clear();
        self.publish(kernel)
    }

    pub fn set_system_proxy(
        &mut self,
        enabled: bool,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        if self.platform != ClientPlatform::Desktop {
            return self.snapshot();
        }
        if !enabled {
            let mut model = self.link_model();
            takeover::set_system_proxy(&mut model, false, None, proxy);
            self.apply_model(model);
            return self.publish(kernel);
        }
        let previous = self.takeover.system_proxy;
        let tun_enable = if self.tun_wanted {
            match tun.authorize() {
                Ok(true) => true,
                _ => {
                    let _ = self.reload(kernel, false, None);
                    let mut model = self.link_model();
                    model.tun = false;
                    model.system_proxy = previous;
                    model.connected = false;
                    model.failure = Some(takeover::TUN_DENIED.to_string());
                    self.apply_model(model);
                    self.remember_current_failure();
                    return self.publish(kernel);
                }
            }
        } else {
            false
        };
        match self.reload(kernel, tun_enable, None) {
            Ok(port) => {
                let mut model = self.link_model();
                takeover::set_system_proxy(&mut model, true, Some(port), proxy);
                if tun_enable {
                    model.tun = true;
                }
                self.apply_model(model);
            }
            Err(StartError::Idle(message)) => {
                self.home_failure = Some(message);
                self.connected = false;
                self.remember_current_failure();
            }
            Err(StartError::Failed(message)) => {
                let mut model = self.link_model();
                takeover::fail_kernel(&mut model, proxy, tun, vpn, message);
                self.apply_model(model);
                self.remember_current_failure();
            }
        }
        self.publish(kernel)
    }

    pub fn set_tun(
        &mut self,
        enabled: bool,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        if self.platform != ClientPlatform::Desktop {
            return self.snapshot();
        }
        let previous = self.takeover.system_proxy;
        if !enabled {
            let _ = self.reload(kernel, false, None);
            let mut model = self.link_model();
            takeover::set_tun(&mut model, false, tun);
            self.apply_model(model);
            return self.publish(kernel);
        }
        if !matches!(tun.authorize(), Ok(true)) {
            let _ = self.reload(kernel, false, None);
            let _ = tun.set_enabled(false);
            let mut model = self.link_model();
            model.tun = false;
            model.system_proxy = previous;
            model.connected = false;
            model.failure = Some(takeover::TUN_DENIED.to_string());
            self.apply_model(model);
            self.remember_current_failure();
            return self.publish(kernel);
        }
        match self.reload(kernel, true, None) {
            Ok(_) => {
                let _ = tun.set_enabled(true);
                let mut model = self.link_model();
                model.tun = true;
                model.tun_wanted = true;
                model.connected = model.system_proxy;
                self.apply_model(model);
            }
            Err(StartError::Idle(message)) => {
                self.home_failure = Some(message);
                self.connected = false;
                self.remember_current_failure();
            }
            Err(StartError::Failed(message)) => {
                let mut model = self.link_model();
                takeover::fail_kernel(&mut model, proxy, tun, vpn, message);
                self.apply_model(model);
                self.remember_current_failure();
            }
        }
        self.publish(kernel)
    }

    fn connect_desktop(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        let previous = self.takeover.system_proxy;
        let tun_enable = if self.tun_wanted {
            match tun.authorize() {
                Ok(true) => true,
                _ => {
                    let _ = self.reload(kernel, false, None);
                    let _ = tun.set_enabled(false);
                    let mut model = self.link_model();
                    model.tun = false;
                    model.system_proxy = previous;
                    model.connected = false;
                    model.failure = Some(takeover::TUN_DENIED.to_string());
                    self.apply_model(model);
                    self.remember_current_failure();
                    return self.publish(kernel);
                }
            }
        } else {
            false
        };
        match self.reload(kernel, tun_enable, None) {
            Ok(port) => {
                let _ = tun.set_enabled(tun_enable);
                let mut model = self.link_model();
                takeover::set_system_proxy(&mut model, true, Some(port), proxy);
                model.tun = tun_enable;
                let _ = vpn.close();
                model.vpn = false;
                self.apply_model(model);
            }
            Err(StartError::Idle(message)) => {
                self.home_failure = Some(message);
                self.connected = false;
                self.remember_current_failure();
            }
            Err(StartError::Failed(message)) => {
                let mut model = self.link_model();
                takeover::fail_kernel(&mut model, proxy, tun, vpn, message);
                self.apply_model(model);
                self.remember_current_failure();
            }
        }
        self.publish(kernel)
    }

    fn connect_android(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        if self.active_id.is_none() {
            self.home_failure = Some(takeover::NO_PROFILE.to_string());
            self.connected = false;
            self.remember_current_failure();
            return self.publish(kernel);
        }
        if !matches!(vpn.authorize(), Ok(true)) {
            let _ = vpn.close();
            let mut model = self.link_model();
            model.vpn = false;
            model.connected = false;
            model.system_proxy = false;
            model.tun = false;
            model.failure = Some(takeover::VPN_DENIED.to_string());
            self.apply_model(model);
            self.remember_current_failure();
            return self.publish(kernel);
        }
        let fd = match vpn.establish(&self.excluded) {
            Ok(fd) => fd,
            Err(_) => {
                let _ = vpn.close();
                let mut model = self.link_model();
                model.vpn = false;
                model.connected = false;
                model.failure = Some("VPN 没有建立".to_string());
                self.apply_model(model);
                self.remember_current_failure();
                return self.publish(kernel);
            }
        };
        let model = self.link_model();
        self.finish_android_fd(kernel, vpn, model, fd)
    }

    pub fn exclude_package(
        &mut self,
        package_name: &str,
        kernel: &mut dyn KernelLaunch,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        self.change_exclusion(package_name, true, kernel, vpn)
    }

    pub fn include_package(
        &mut self,
        package_name: &str,
        kernel: &mut dyn KernelLaunch,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        self.change_exclusion(package_name, false, kernel, vpn)
    }

    fn change_exclusion(
        &mut self,
        package_name: &str,
        exclude: bool,
        kernel: &mut dyn KernelLaunch,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        let mut model = self.link_model();
        let fd = if exclude {
            takeover::exclude_package(&mut model, package_name, vpn)
        } else {
            takeover::include_package(&mut model, package_name, vpn)
        };
        if let Some(fd) = fd {
            return self.finish_android_fd(kernel, vpn, model, fd);
        }
        self.apply_model(model);
        self.snapshot()
    }

    fn finish_android_fd(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        vpn: &mut dyn VpnGrant,
        mut model: takeover::LinkModel,
        fd: i32,
    ) -> ProfileSnapshot {
        match self.reload(kernel, true, Some(fd)) {
            Ok(_) => {
                model.vpn = true;
                model.connected = true;
                model.system_proxy = false;
                model.tun = false;
                // connect() already retires the home failure. Package changes do not.
                self.apply_model(model);
            }
            Err(StartError::Failed(message)) | Err(StartError::Idle(message)) => {
                let _ = vpn.close();
                model.vpn = false;
                model.connected = false;
                model.system_proxy = false;
                model.tun = false;
                model.failure = Some(message);
                self.apply_model(model);
                self.remember_current_failure();
            }
        }
        self.publish(kernel)
    }

    fn activate(
        &mut self,
        id: &str,
        source: &dyn SubscriptionSource,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        let Some(index) = self.profiles.iter().position(|profile| profile.id == id) else {
            self.home_failure = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        let fetched = if self.profiles[index].kind == ProfileKind::Subscription {
            match source.fetch(&self.profiles[index].source) {
                Ok(fetched) => Some(FetchedSubscription {
                    content: normalize_subscription_content(&fetched.content),
                    userinfo: fetched.userinfo,
                }),
                Err(_) => {
                    self.fail_activation(index, FETCH_ERROR.to_string());
                    return self.publish(kernel);
                }
            }
        } else {
            None
        };
        let content = fetched
            .as_ref()
            .map(|item| item.content.as_str())
            .unwrap_or(self.profiles[index].content.as_str());
        let override_text = self.profiles[index].override_text.clone();
        let prepared = match prepare(content, &override_text) {
            Ok(prepared) => prepared,
            Err(PrepareError::Content) => {
                self.fail_activation(index, CONTENT_ERROR.to_string());
                return self.publish(kernel);
            }
            Err(PrepareError::Override) => {
                // Judged before the running config changes, so takeover and the active id stay.
                self.profiles[index].override_error = Some(OVERRIDE_ERROR.to_string());
                self.persist();
                return self.snapshot();
            }
        };
        let selected = self.profiles[index].selected.clone();
        let desktop = self.platform == ClientPlatform::Desktop;
        let (settled, settled_port) = match apply_settings(&prepared.yaml, &self.settings, desktop)
            .and_then(|(yaml, port)| ensure_tun_dns(&yaml, &self.settings).map(|yaml| (yaml, port)))
        {
            Ok(result) => result,
            Err(message) => {
                self.fail_activation(index, message);
                return self.publish(kernel);
            }
        };
        let yaml = nodes::ensure_controller(&nodes::prioritize_selections(&settled, &selected));
        if let Err(message) = kernel.start_or_reload(&yaml) {
            let message = if message.is_empty() {
                KERNEL_ERROR.to_string()
            } else {
                message
            };
            self.fail_activation(index, message);
            return self.publish(kernel);
        }
        self.runtime_base = Some(yaml);
        self.disabled_rules.clear();
        let now = now_ms();
        {
            let profile = &mut self.profiles[index];
            if let Some(fetched) = fetched {
                profile.content = fetched.content;
                profile.usage = parse_userinfo(fetched.userinfo.as_deref());
                profile.updated_ms = Some(now);
                profile.proxy_count = count_proxies(&profile.content);
            }
            profile.applied_override = profile.override_text.clone();
            profile.override_error = None;
            profile.failure = None;
            profile.last_success_ms = Some(now);
            self.active_id = Some(profile.id.clone());
        }
        self.mixed_port = settled_port.or(prepared.mixed_port);
        self.mode = prepared.mode.clone();
        self.chosen_mode = prepared.mode;
        self.home_failure = None;
        self.input_error = None;
        self.apply_live_selections(kernel);
        self.persist();
        self.publish(kernel)
    }

    fn fail_activation(&mut self, index: usize, message: String) {
        self.profiles[index].failure = Some(message.clone());
        self.home_failure = Some(message);
        let endpoint = self.our_endpoint.clone();
        self.pending_release = Some(PlatformRelease {
            endpoint: endpoint.clone(),
            close_tun: self.takeover.tun,
            close_vpn: self.takeover.vpn,
        });
        self.takeover.tun = false;
        self.takeover.vpn = false;
        self.connected = false;
        if endpoint.is_none() {
            self.takeover.system_proxy = false;
        }
        self.persist();
        self.remember_current_failure();
    }

    fn publish(&mut self, kernel: &mut dyn KernelLaunch) -> ProfileSnapshot {
        self.sync_runtime(kernel);
        self.snapshot()
    }

    fn remember_current_failure(&mut self) {
        let Some(message) = self.home_failure.clone() else {
            return;
        };
        self.connections.clear();
        self.append_logs(vec![diagnostics::failure_log(&message)]);
    }

    fn append_logs(&mut self, lines: Vec<LogView>) {
        diagnostics::push_logs(&mut self.logs, lines);
    }

    /// Runs a deferred proxy clear. The flag and port are dropped only when the clear succeeds.
    pub fn apply_release(
        &mut self,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) {
        let Some(release) = self.pending_release.take() else {
            return;
        };
        let cleared = takeover::release_platform(proxy, tun, vpn, &release);
        if cleared {
            self.takeover.system_proxy = false;
            self.our_endpoint = None;
        } else if release.endpoint.is_some() {
            self.our_endpoint = release.endpoint;
            self.takeover.system_proxy = true;
        }
        self.persist();
    }

    fn reload(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        tun_enable: bool,
        fd: Option<i32>,
    ) -> Result<u16, StartError> {
        let (base, port) = self.kernel_yaml(tun_enable, fd)?;
        let yaml = if self.disabled_rules.is_empty() {
            base.clone()
        } else {
            diagnostics::filter_disabled_rules(&base, &self.disabled_rules)
                .map_err(StartError::Failed)?
        };
        kernel.start_or_reload(&yaml).map_err(|message| {
            StartError::Failed(if message.is_empty() {
                KERNEL_ERROR.to_string()
            } else {
                message
            })
        })?;
        self.runtime_base = Some(base);
        self.apply_live_selections(kernel);
        Ok(port)
    }

    /// The YAML the kernel runs (or would run) for the active profile: content,
    /// applied override, kernel settings, TUN, mode and controller, in launch order.
    /// While a kernel config is loaded this is exactly that YAML (with rules
    /// disabled at runtime removed); otherwise it previews the next launch.
    pub fn effective_config(&self) -> Result<String, String> {
        if let Some(base) = &self.runtime_base {
            if self.disabled_rules.is_empty() {
                return Ok(base.clone());
            }
            return diagnostics::filter_disabled_rules(base, &self.disabled_rules);
        }
        self.kernel_yaml(self.takeover.tun, None)
            .map(|(yaml, _)| yaml)
            .map_err(|error| match error {
                StartError::Idle(message) | StartError::Failed(message) => message,
            })
    }

    fn kernel_yaml(&self, tun_enable: bool, fd: Option<i32>) -> Result<(String, u16), StartError> {
        let Some(active) = self.active_id.clone() else {
            return Err(StartError::Idle(takeover::NO_PROFILE.to_string()));
        };
        let Some(profile) = self.profiles.iter().find(|profile| profile.id == active) else {
            return Err(StartError::Idle(takeover::NO_PROFILE.to_string()));
        };
        let prepared = match prepare(&profile.content, &profile.applied_override) {
            Ok(prepared) => prepared,
            Err(_) => return Err(StartError::Failed(CONTENT_ERROR.to_string())),
        };
        let (settled, settled_port) =
            apply_settings(&prepared.yaml, &self.settings, self.platform == ClientPlatform::Desktop)
                .map_err(StartError::Failed)?;
        let prepared = Prepared {
            mixed_port: settled_port.or(prepared.mixed_port),
            mode: prepared.mode,
            yaml: settled,
        };
        let Some(port) = prepared
            .mixed_port
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value > 0)
        else {
            return Err(StartError::Failed("没有本地端口".to_string()));
        };
        let selected = profile.selected.clone();
        let yaml = force_tun(&prepared.yaml, tun_enable, fd).map_err(StartError::Failed)?;
        let yaml = ensure_tun_dns(&yaml, &self.settings).map_err(StartError::Failed)?;
        let yaml = match self.mode.as_deref().and_then(normalize_outbound) {
            Some(mode) => force_mode(&yaml, mode).map_err(StartError::Failed)?,
            None => yaml,
        };
        let yaml = nodes::ensure_controller(&nodes::prioritize_selections(&yaml, &selected));
        Ok((yaml, port))
    }

    fn link_model(&self) -> takeover::LinkModel {
        takeover::LinkModel {
            platform: self.platform,
            tun_wanted: self.tun_wanted,
            excluded: self.excluded.clone(),
            system_proxy: self.takeover.system_proxy,
            tun: self.takeover.tun,
            vpn: self.takeover.vpn,
            connected: self.connected,
            failure: self.home_failure.clone(),
            endpoint: self.our_endpoint.clone(),
        }
    }

    fn apply_model(&mut self, model: takeover::LinkModel) {
        self.platform = model.platform;
        self.tun_wanted = model.tun_wanted;
        self.excluded = model.excluded;
        self.takeover.system_proxy = model.system_proxy;
        self.takeover.tun = model.tun;
        self.takeover.vpn = model.vpn;
        self.connected = model.connected;
        self.home_failure = model.failure;
        self.our_endpoint = model.endpoint;
        self.pending_release = None;
        self.persist();
    }

    fn push_profile(&mut self, kind: ProfileKind, name: String, source: String, content: String) {
        let id = format!("p{}", self.next_id);
        self.next_id += 1;
        self.profiles.push(Profile {
            id,
            name,
            kind,
            source,
            content,
            override_text: String::new(),
            applied_override: String::new(),
            override_error: None,
            failure: None,
            last_success_ms: None,
            usage: None,
            selected: BTreeMap::new(),
            interval_hours: 0,
            updated_ms: None,
            proxy_count: 0,
        });
        if let Some(profile) = self.profiles.last_mut() {
            profile.proxy_count = count_proxies(&profile.content);
            if profile.kind == ProfileKind::Local {
                profile.updated_ms = Some(now_ms());
            }
        }
    }

    fn load(&mut self) {
        let Ok(text) = fs::read_to_string(&self.path) else {
            return;
        };
        let Ok(disk) = serde_json::from_str::<DiskState>(&text) else {
            return;
        };
        self.next_id = disk.next_id.max(1);
        self.home_failure = disk.home_failure;
        self.profiles = disk
            .profiles
            .into_iter()
            .filter(|profile| !profile.id.is_empty())
            .map(|profile| {
                let usage = usage_from_parts(profile.used, profile.total, profile.expire);
                Profile {
                    id: profile.id,
                    name: profile.name,
                    kind: profile.kind,
                    source: profile.source,
                    content: profile.content,
                    override_text: profile.override_text,
                    applied_override: profile.applied_override,
                    override_error: profile.override_error,
                    failure: profile.failure,
                    last_success_ms: profile.last_success_ms,
                    usage,
                    proxy_count: 0,
                    selected: profile.selected,
                    interval_hours: profile.interval_hours,
                    updated_ms: profile.updated_ms,
                }
            })
            .collect();
        for profile in &mut self.profiles {
            profile.proxy_count = count_proxies(&profile.content);
        }
        self.settings = disk.settings;
        nodes::set_probe(&self.settings.test_url, self.settings.test_timeout_ms_or_default());
        let known = self
            .profiles
            .iter()
            .any(|profile| disk.active_id.as_deref() == Some(profile.id.as_str()));
        self.active_id = if known { disk.active_id } else { None };
        self.tun_wanted = disk.tun_wanted;
        self.excluded = disk
            .excluded_packages
            .into_iter()
            .map(|package| package.trim().to_string())
            .filter(|package| !package.is_empty())
            .collect();
        self.our_endpoint = match (disk.proxy_host, disk.proxy_port) {
            (Some(host), Some(port)) if !host.is_empty() && port > 0 => {
                Some(ProxyEndpoint { host, port })
            }
            _ => None,
        };
        self.next_id = self.next_id.max(
            self.profiles
                .iter()
                .filter_map(|profile| profile.id.strip_prefix('p')?.parse::<u64>().ok())
                .max()
                .unwrap_or(0)
                + 1,
        );
        self.chosen_mode = disk
            .chosen_mode
            .and_then(|mode| normalize_outbound(&mode).map(|mode| mode.to_string()));
        self.recompute_effective();
        if let Some(mode) = self.chosen_mode.clone() {
            self.mode = Some(mode);
        }
        if let Some(message) = self.home_failure.clone() {
            self.append_logs(vec![diagnostics::failure_log(&message)]);
        }
    }

    fn recompute_effective(&mut self) {
        self.mixed_port = None;
        self.mode = None;
        let Some(active) = self.active_id.as_deref() else {
            return;
        };
        let Some(profile) = self.profiles.iter().find(|profile| profile.id == active) else {
            return;
        };
        if let Ok(prepared) = prepare(&profile.content, &profile.applied_override) {
            self.mixed_port = prepared.mixed_port;
            self.mode = prepared.mode;
        }
    }

    fn persist(&self) {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
            && fs::create_dir_all(parent).is_err()
        {
            return;
        }
        let disk = DiskState {
            next_id: self.next_id,
            active_id: self.active_id.clone(),
            home_failure: self.home_failure.clone(),
            tun_wanted: self.tun_wanted,
            excluded_packages: self.excluded.clone(),
            proxy_host: self
                .our_endpoint
                .as_ref()
                .map(|endpoint| endpoint.host.clone()),
            proxy_port: self.our_endpoint.as_ref().map(|endpoint| endpoint.port),
            chosen_mode: self.chosen_mode.clone(),
            settings: self.settings.clone(),
            profiles: self
                .profiles
                .iter()
                .map(|profile| DiskProfile {
                    id: profile.id.clone(),
                    name: profile.name.clone(),
                    kind: profile.kind,
                    source: profile.source.clone(),
                    content: profile.content.clone(),
                    override_text: profile.override_text.clone(),
                    applied_override: profile.applied_override.clone(),
                    override_error: profile.override_error.clone(),
                    failure: profile.failure.clone(),
                    last_success_ms: profile.last_success_ms,
                    used: profile.usage.as_ref().and_then(|usage| usage.used),
                    total: profile.usage.as_ref().and_then(|usage| usage.total),
                    expire: profile.usage.as_ref().and_then(|usage| usage.expire),
                    selected: profile.selected.clone(),
                    interval_hours: profile.interval_hours,
                    updated_ms: profile.updated_ms,
                })
                .collect(),
        };
        let Ok(data) = serde_json::to_vec_pretty(&disk) else {
            return;
        };
        let temporary = self.path.with_extension("json.tmp");
        if fs::write(&temporary, data).is_ok() {
            let _ = fs::rename(&temporary, &self.path);
        }
    }

    pub fn sync_runtime(&mut self, kernel: &mut dyn KernelLaunch) {
        let running = kernel.running();
        self.kernel_running = running;
        self.append_logs(kernel.pull_logs());
        if running {
            self.auto_now = kernel.auto_now();
            self.kernel_memory = kernel.kernel_memory();
            self.kernel_uptime_secs = kernel.kernel_uptime_secs();
            if self.connected {
                self.connections = diagnostics::accept_connections(kernel.connections());
                if let Some(totals) = kernel.connection_totals() {
                    self.totals = Some(totals);
                }
                self.connection_total = kernel
                    .connection_total()
                    .unwrap_or(self.connections.len());
                self.connections_error = kernel.connections_error();
            } else {
                self.connections.clear();
                self.connection_total = 0;
                self.connections_error = None;
            }
        } else {
            self.auto_now.clear();
            self.connections.clear();
            self.kernel_memory = None;
            self.kernel_uptime_secs = None;
            self.connection_total = 0;
            self.connections_error = None;
            self.runtime_base = None;
            // A stopped kernel is not connected. The system-proxy switch may stay on.
            self.connected = false;
        }
        if self.connected {
            // None is not a zero reading. A later sample still replaces the last one.
            if let Some((upload, download)) = kernel.traffic() {
                self.upload = Some(upload);
                self.download = Some(download);
            }
        } else {
            self.upload = None;
            self.download = None;
            self.totals = None;
        }
    }

    pub fn set_outbound_mode(
        &mut self,
        mode: &str,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        let Some(next) = normalize_outbound(mode) else {
            self.home_failure = Some("模式没有切换".to_string());
            self.remember_current_failure();
            return self.snapshot();
        };
        if self.active_id.is_none() {
            self.home_failure = Some("没有生效配置".to_string());
            self.remember_current_failure();
            return self.snapshot();
        }
        if kernel.running() {
            if let Err(message) = kernel.set_mode(next) {
                self.home_failure = Some(if message.is_empty() {
                    "模式没有切换".to_string()
                } else {
                    message
                });
                self.remember_current_failure();
                return self.publish(kernel);
            }
        }
        self.mode = Some(next.to_string());
        self.chosen_mode = Some(next.to_string());
        self.persist();
        self.publish(kernel)
    }

    pub fn set_connection_query(
        &mut self,
        query: &str,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        self.connection_query = query.chars().take(200).collect();
        self.publish(kernel)
    }

    pub fn set_log_filter(
        &mut self,
        filter: &str,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        self.log_filter = diagnostics::normalize_log_filter(filter).to_string();
        self.publish(kernel)
    }

    pub fn set_node_query(&mut self, query: &str) -> ProfileSnapshot {
        self.node_query = query.chars().take(200).collect();
        self.snapshot()
    }

    pub fn set_node_sort(&mut self, group: &str, sort: &str) -> ProfileSnapshot {
        let group = group.trim();
        if !group.is_empty() {
            self.node_sort
                .insert(group.to_string(), nodes::normalize_sort(sort).to_string());
        }
        self.snapshot()
    }

    pub fn select_node(
        &mut self,
        group: &str,
        node: &str,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        self.sync_runtime(kernel);
        let group_name = group.trim();
        let node_name = node.trim();
        let Some(index) = self.nodes_profile_index() else {
            self.nodes_error = Some(NEED_PROFILE.to_string());
            return self.snapshot();
        };
        if self.profiles[index].content.trim().is_empty() {
            self.nodes_error = Some(NEED_PROFILE.to_string());
            return self.snapshot();
        }
        let Some(document) = document_value(&self.profiles[index]) else {
            self.nodes_error = Some(NO_NODES.to_string());
            return self.snapshot();
        };
        let parsed = nodes::parse_proxy_groups(&document);
        let Some(found) = parsed.iter().find(|item| item.name == group_name) else {
            self.nodes_error = Some("没有这个代理组".to_string());
            return self.snapshot();
        };
        if !found.manual {
            self.nodes_error = Some(NOT_MANUAL.to_string());
            return self.snapshot();
        }
        if !found.proxies.iter().any(|item| item.as_str() == node_name) {
            self.nodes_error = Some("没有这个节点".to_string());
            return self.snapshot();
        }
        if self.kernel_running {
            if let Err(message) = kernel.select_proxy(group_name, node_name) {
                self.nodes_error = Some(if message.is_empty() {
                    SELECT_FAILED.to_string()
                } else {
                    message
                });
                return self.snapshot();
            }
        }
        self.profiles[index]
            .selected
            .insert(group_name.to_string(), node_name.to_string());
        self.nodes_error = None;
        self.persist();
        self.snapshot()
    }

    pub fn test_group(&mut self, group: &str, kernel: &mut dyn KernelLaunch) -> ProfileSnapshot {
        self.sync_runtime(kernel);
        if !self.kernel_running {
            self.nodes_error = Some(KERNEL_DOWN.to_string());
            return self.snapshot();
        }
        let Some(index) = self.nodes_profile_index() else {
            self.nodes_error = Some(NEED_PROFILE.to_string());
            return self.snapshot();
        };
        let Some(document) = document_value(&self.profiles[index]) else {
            self.nodes_error = Some(NO_NODES.to_string());
            return self.snapshot();
        };
        let parsed = nodes::parse_proxy_groups(&document);
        let Some(found) = parsed.iter().find(|item| item.name == group.trim()) else {
            self.nodes_error = Some("没有这个代理组".to_string());
            return self.snapshot();
        };
        let manual = found.manual;
        let group_key = found.name.clone();
        let mut members = found.proxies.clone();
        if !manual {
            if let Some(now) = self.auto_now.get(&group_key).cloned() {
                if !members.iter().any(|item| item == &now) {
                    members.push(now);
                }
            }
        }
        let profile_id = self.profiles[index].id.clone();
        match kernel.probe_delays(&group_key, &members) {
            Ok(results) => {
                let slot = self
                    .delays
                    .entry(profile_id)
                    .or_default()
                    .entry(group_key)
                    .or_default();
                for item in results {
                    if !members.iter().any(|name| name == &item.name) {
                        continue;
                    }
                    if let Some(ms) = item.delay_ms {
                        slot.insert(
                            item.name,
                            DelayMark {
                                delay_ms: Some(ms),
                                failed: false,
                            },
                        );
                    } else {
                        slot.insert(
                            item.name,
                            DelayMark {
                                delay_ms: None,
                                failed: true,
                            },
                        );
                    }
                }
                self.nodes_error = None;
            }
            Err(message) => {
                self.nodes_error = Some(if message.is_empty() {
                    KERNEL_DOWN.to_string()
                } else {
                    message
                });
            }
        }
        self.snapshot()
    }

    fn nodes_profile_index(&self) -> Option<usize> {
        if let Some(id) = self.active_id.as_deref() {
            if let Some(index) = self.profiles.iter().position(|profile| profile.id == id) {
                return Some(index);
            }
        }
        self.profiles
            .iter()
            .rposition(|profile| !profile.content.trim().is_empty())
    }

    fn node_views(
        &self,
    ) -> (
        Vec<NodeGroupView>,
        Vec<NodeGroupView>,
        Option<String>,
        Option<String>,
    ) {
        let Some(index) = self.nodes_profile_index() else {
            return (Vec::new(), Vec::new(), Some(NEED_PROFILE.to_string()), None);
        };
        let profile = &self.profiles[index];
        let profile_id = profile.id.clone();
        if profile.content.trim().is_empty() {
            return (
                Vec::new(),
                Vec::new(),
                Some(NEED_PROFILE.to_string()),
                Some(profile_id),
            );
        }
        let Some(document) = document_value(profile) else {
            return (
                Vec::new(),
                Vec::new(),
                Some(NO_NODES.to_string()),
                Some(profile_id),
            );
        };
        let parsed = nodes::parse_proxy_groups(&document);
        if parsed.is_empty() {
            return (
                Vec::new(),
                Vec::new(),
                Some(NO_NODES.to_string()),
                Some(profile_id),
            );
        }
        let types = nodes::proxy_infos(&document);
        let catalog: Vec<NodeGroupView> = parsed
            .iter()
            .map(|group| self.present_group(profile, group, &types))
            .collect();
        let mut visible = catalog.clone();
        for group in &mut visible {
            group.nodes = nodes::sorted_nodes(std::mem::take(&mut group.nodes), &group.sort);
        }
        let (visible, none) = nodes::filter_visible(visible, &self.node_query);
        if none {
            return (
                catalog,
                Vec::new(),
                Some(NO_MATCH.to_string()),
                Some(profile_id),
            );
        }
        (catalog, visible, None, Some(profile_id))
    }

    fn present_group(
        &self,
        profile: &Profile,
        group: &ParsedGroup,
        types: &BTreeMap<String, nodes::ProxyInfo>,
    ) -> NodeGroupView {
        let sort = self.sort_of(&group.name);
        if !group.manual {
            let now = self.auto_now.get(&group.name).cloned().unwrap_or_default();
            let mut members = group.proxies.clone();
            if !now.is_empty() && !members.iter().any(|item| item == &now) {
                members.push(now.clone());
            }
            let nodes = members
                .iter()
                .map(|name| self.node_item(profile, &group.name, name, !now.is_empty() && *name == now, types))
                .collect();
            return NodeGroupView {
                name: group.name.clone(),
                kind: "auto".to_string(),
                now,
                sort,
                nodes,
                group_type: group.group_type.clone(),
                icon: group.icon.clone(),
            };
        }
        let chosen = profile
            .selected
            .get(&group.name)
            .filter(|name| group.proxies.iter().any(|item| item == *name))
            .cloned();
        let now = chosen
            .clone()
            .or_else(|| group.proxies.first().cloned())
            .unwrap_or_default();
        let nodes = group
            .proxies
            .iter()
            .map(|name| {
                let selected = match &chosen {
                    Some(choice) => choice == name,
                    None => group.proxies.first() == Some(name),
                };
                self.node_item(profile, &group.name, name, selected, types)
            })
            .collect();
        NodeGroupView {
            name: group.name.clone(),
            kind: "manual".to_string(),
            now,
            sort,
            nodes,
            group_type: group.group_type.clone(),
            icon: group.icon.clone(),
        }
    }

    fn node_item(
        &self,
        profile: &Profile,
        group: &str,
        name: &str,
        selected: bool,
        types: &BTreeMap<String, nodes::ProxyInfo>,
    ) -> nodes::NodeItemView {
        let mark = self
            .delays
            .get(&profile.id)
            .and_then(|groups| groups.get(group))
            .and_then(|nodes| nodes.get(name));
        nodes::NodeItemView {
            name: name.to_string(),
            delay_ms: mark.and_then(|item| item.delay_ms),
            failed: mark.is_some_and(|item| item.failed),
            selected,
            node_type: types.get(name).map(|info| info.kind.clone()).unwrap_or_default(),
            tags: types.get(name).map(|info| info.tags.clone()).unwrap_or_default(),
        }
    }

    fn sort_of(&self, group: &str) -> String {
        nodes::normalize_sort(
            self.node_sort
                .get(group)
                .map(String::as_str)
                .unwrap_or("default"),
        )
        .to_string()
    }

    fn apply_live_selections(&self, kernel: &mut dyn KernelLaunch) {
        if !kernel.running() {
            return;
        }
        let Some(id) = self.active_id.as_deref() else {
            return;
        };
        let Some(profile) = self.profiles.iter().find(|profile| profile.id == id) else {
            return;
        };
        let Some(document) = document_value(profile) else {
            return;
        };
        for group in nodes::parse_proxy_groups(&document) {
            if !group.manual {
                continue;
            }
            let Some(node) = profile.selected.get(&group.name) else {
                continue;
            };
            if group.proxies.iter().any(|item| item == node) {
                let _ = kernel.select_proxy(&group.name, node);
            }
        }
    }

    #[cfg(test)]
    fn set_takeover(&mut self, system_proxy: bool, tun: bool, vpn: bool) {
        self.takeover = Takeover {
            system_proxy,
            tun,
            vpn,
        };
    }
}

impl KernelSettings {
    pub fn test_timeout_ms_or_default(&self) -> u64 {
        if self.test_timeout_ms == 0 {
            5000
        } else {
            self.test_timeout_ms
        }
    }

    fn normalized(mut self) -> Self {
        self.mixed_port = self.mixed_port.filter(|port| *port > 0);
        self.log_level = self
            .log_level
            .map(|level| level.trim().to_ascii_lowercase())
            .filter(|level| matches!(level.as_str(), "debug" | "info" | "warning" | "error" | "silent"));
        self.find_process_mode = self
            .find_process_mode
            .map(|mode| mode.trim().to_ascii_lowercase())
            .filter(|mode| matches!(mode.as_str(), "always" | "strict" | "off"));
        self.test_url = self.test_url.trim().chars().take(500).collect();
        if !self.test_url.is_empty()
            && !(self.test_url.starts_with("http://") || self.test_url.starts_with("https://"))
        {
            self.test_url.clear();
        }
        if self.test_timeout_ms != 0 {
            self.test_timeout_ms = self.test_timeout_ms.clamp(1000, 30000);
        }
        self.dns = self.dns.normalized();
        self.tun = self.tun.normalized();
        self
    }

    /// Everything except the delay probe, which never needs a kernel restart.
    fn kernel_part(&self) -> Self {
        let mut copy = self.clone();
        copy.test_url.clear();
        copy.test_timeout_ms = 0;
        copy
    }
}

/// Default port written when neither the profile nor settings name one.
const FALLBACK_MIXED_PORT: i64 = 7890;

fn apply_settings(
    yaml: &str,
    settings: &KernelSettings,
    desktop: bool,
) -> Result<(String, Option<i64>), String> {
    let mut value: Value = serde_yaml::from_str(yaml).map_err(|_| CONTENT_ERROR.to_string())?;
    let Some(map) = value.as_mapping_mut() else {
        return Err(CONTENT_ERROR.to_string());
    };
    let key = |name: &str| Value::String(name.to_string());
    if let Some(port) = settings.mixed_port {
        map.insert(key("mixed-port"), Value::Number(i64::from(port).into()));
    } else if !map.contains_key(key("mixed-port")) && !map.contains_key(key("port")) {
        map.insert(key("mixed-port"), Value::Number(FALLBACK_MIXED_PORT.into()));
    } else if !map.contains_key(key("mixed-port")) {
        // Only an HTTP `port`: reuse it as the mixed listener so system proxy has a target.
        if let Some(port) = map.get(key("port")).and_then(Value::as_i64) {
            map.insert(key("mixed-port"), Value::Number(port.into()));
        }
    }
    if let Some(flag) = settings.allow_lan {
        map.insert(key("allow-lan"), Value::Bool(flag));
    }
    if let Some(flag) = settings.ipv6 {
        map.insert(key("ipv6"), Value::Bool(flag));
    }
    if let Some(level) = &settings.log_level {
        map.insert(key("log-level"), Value::String(level.clone()));
    }
    if let Some(flag) = settings.unified_delay {
        map.insert(key("unified-delay"), Value::Bool(flag));
    }
    if let Some(flag) = settings.tcp_concurrent {
        map.insert(key("tcp-concurrent"), Value::Bool(flag));
    }
    if let Some(mode) = &settings.find_process_mode {
        map.insert(key("find-process-mode"), Value::String(mode.clone()));
    }
    if settings.dns_override {
        map.insert(key("dns"), settings.dns.to_value());
    }
    if let Some(flag) = settings.geo_auto_update {
        map.insert(key("geo-auto-update"), Value::Bool(flag));
    }
    if let Some(hours) = settings.geo_update_interval.filter(|hours| *hours > 0) {
        map.insert(key("geo-update-interval"), Value::Number(i64::from(hours).into()));
    }
    if let Some(urls) = geo_source_urls(&settings.geo_source) {
        let mut geox = serde_yaml::Mapping::new();
        for (name, url) in urls {
            geox.insert(key(name), Value::String(url));
        }
        map.insert(key("geox-url"), Value::Mapping(geox));
    }
    if let Some(flag) = settings.sniffer {
        if flag {
            map.insert(key("sniffer"), default_sniffer());
        } else {
            let mut off = serde_yaml::Mapping::new();
            off.insert(key("enable"), Value::Bool(false));
            map.insert(key("sniffer"), Value::Mapping(off));
        }
    }
    if desktop {
        // Android hands the kernel a VPN fd; routing options there belong to the system.
        let mut tun = map
            .get(key("tun"))
            .and_then(Value::as_mapping)
            .cloned()
            .unwrap_or_default();
        let tun_settings = &settings.tun;
        tun.insert(key("stack"), Value::String(tun_settings.stack.clone()));
        tun.insert(key("auto-route"), Value::Bool(tun_settings.auto_route));
        tun.insert(key("auto-detect-interface"), Value::Bool(tun_settings.auto_detect_interface));
        tun.insert(key("strict-route"), Value::Bool(tun_settings.strict_route));
        tun.insert(
            key("dns-hijack"),
            Value::Sequence(tun_settings.dns_hijack.iter().map(|item| Value::String(item.clone())).collect()),
        );
        if tun_settings.mtu > 0 {
            tun.insert(key("mtu"), Value::Number(u64::from(tun_settings.mtu).into()));
        }
        if !tun_settings.device.is_empty() {
            tun.insert(key("device"), Value::String(tun_settings.device.clone()));
        }
        map.insert(key("tun"), Value::Mapping(tun));
    }
    let port = map.get(key("mixed-port")).and_then(Value::as_i64);
    let text = serde_yaml::to_string(&value).map_err(|_| CONTENT_ERROR.to_string())?;
    Ok((text, port))
}

fn default_sniffer() -> Value {
    serde_yaml::from_str(
        "enable: true\nforce-dns-mapping: true\nparse-pure-ip: true\nsniff:\n  HTTP:\n    ports: [80, 8080-8880]\n    override-destination: true\n  TLS:\n    ports: [443, 8443]\n  QUIC:\n    ports: [443, 8443]\nskip-domain:\n  - Mijia Cloud\n  - +.push.apple.com\n",
    )
    .unwrap_or(Value::Null)
}

/// TUN hijacks DNS, so the kernel must answer it. Without a `dns` block that is enabled,
/// a profile written for system-proxy use would leave every lookup unanswered under TUN.
fn ensure_tun_dns(yaml: &str, settings: &KernelSettings) -> Result<String, String> {
    let mut value: Value = serde_yaml::from_str(yaml).map_err(|_| CONTENT_ERROR.to_string())?;
    let Some(map) = value.as_mapping_mut() else {
        return Err(CONTENT_ERROR.to_string());
    };
    let key = |name: &str| Value::String(name.to_string());
    let tun_on = map
        .get(key("tun"))
        .and_then(|tun| tun.get("enable"))
        .and_then(Value::as_bool)
        == Some(true);
    if !tun_on {
        return Ok(yaml.to_string());
    }
    let dns_on = map
        .get(key("dns"))
        .and_then(|dns| dns.get("enable"))
        .and_then(Value::as_bool)
        == Some(true);
    if dns_on {
        return Ok(yaml.to_string());
    }
    map.insert(key("dns"), settings.dns.clone().normalized().to_value());
    serde_yaml::to_string(&value).map_err(|_| CONTENT_ERROR.to_string())
}

fn count_proxies(content: &str) -> usize {
    if content.trim().is_empty() {
        return 0;
    }
    let Ok(value) = serde_yaml::from_str::<Value>(content) else {
        return 0;
    };
    mapping_get(&value, "proxies")
        .and_then(Value::as_sequence)
        .map(|list| list.len())
        .unwrap_or(0)
}

const REFRESH_SLACK_MS: u64 = 60_000;

impl ProfileBook {
    fn config_values(&self) -> ConfigValues {
        let Some(profile) = self
            .active_id
            .as_deref()
            .and_then(|id| self.profiles.iter().find(|profile| profile.id == id))
        else {
            return ConfigValues::default();
        };
        let Some(value) = document_value(profile) else {
            return ConfigValues::default();
        };
        let flag = |name: &str| mapping_get(&value, name).and_then(Value::as_bool);
        ConfigValues {
            mixed_port: read_i64(&value, "mixed-port").or_else(|| read_i64(&value, "port")),
            allow_lan: flag("allow-lan"),
            ipv6: flag("ipv6"),
            log_level: read_string(&value, "log-level"),
            unified_delay: flag("unified-delay"),
            tcp_concurrent: flag("tcp-concurrent"),
            find_process_mode: read_string(&value, "find-process-mode"),
        }
    }

    fn index_of(&self, id: &str) -> Option<usize> {
        self.profiles.iter().position(|profile| profile.id == id)
    }

    pub fn clear_notice(&mut self) -> ProfileSnapshot {
        self.notice = None;
        self.snapshot()
    }

    /// Removes a profile. The active one can go only while nothing is connected.
    pub fn delete_profile(&mut self, id: &str) -> ProfileSnapshot {
        let Some(index) = self.index_of(id) else {
            self.input_error = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        let active = self.active_id.as_deref() == Some(id);
        if active && (self.connected || self.kernel_running) {
            self.notice = Some("请先断开连接再删除当前配置".to_string());
            return self.snapshot();
        }
        self.profiles.remove(index);
        self.delays.remove(id);
        if active {
            self.active_id = None;
            self.disabled_rules.clear();
            self.runtime_base = None;
            self.recompute_effective();
        }
        self.notice = None;
        self.persist();
        self.snapshot()
    }

    pub fn rename_profile(&mut self, id: &str, name: &str) -> ProfileSnapshot {
        let Some(index) = self.index_of(id) else {
            self.input_error = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        let name = clean_name(name, &self.profiles[index].name.clone());
        self.profiles[index].name = name;
        self.persist();
        self.snapshot()
    }

    pub fn set_profile_source(&mut self, id: &str, url: &str) -> ProfileSnapshot {
        let Some(index) = self.index_of(id) else {
            self.input_error = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        if self.profiles[index].kind != ProfileKind::Subscription {
            return self.snapshot();
        }
        match validate_subscription_url(url.trim()) {
            Ok(url) => {
                self.profiles[index].source = url;
                self.input_error = None;
                self.persist();
            }
            Err(message) => self.input_error = Some(message),
        }
        self.snapshot()
    }

    pub fn set_profile_interval(&mut self, id: &str, hours: u32) -> ProfileSnapshot {
        if let Some(index) = self.index_of(id) {
            self.profiles[index].interval_hours = hours.min(24 * 30);
            self.persist();
        }
        self.snapshot()
    }

    pub fn profile_content(&self, id: &str) -> Option<String> {
        self.profiles
            .iter()
            .find(|profile| profile.id == id)
            .map(|profile| profile.content.clone())
    }

    /// Replaces a profile's saved YAML after checking it is a usable config.
    pub fn save_profile_content(
        &mut self,
        id: &str,
        content: &str,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        let Some(index) = self.index_of(id) else {
            self.input_error = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        if parse_config(content).is_err() {
            self.profiles[index].failure = Some(CONTENT_ERROR.to_string());
            self.input_error = Some(CONTENT_ERROR.to_string());
            return self.snapshot();
        }
        let profile = &mut self.profiles[index];
        profile.content = content.to_string();
        profile.proxy_count = count_proxies(content);
        profile.updated_ms = Some(now_ms());
        profile.failure = None;
        self.input_error = None;
        let active = self.active_id.as_deref() == Some(id);
        self.persist();
        if active {
            self.disabled_rules.clear();
            self.recompute_effective();
            if kernel.running() && self.platform == ClientPlatform::Desktop {
                let tun = self.takeover.tun;
                if let Err(StartError::Failed(message)) | Err(StartError::Idle(message)) =
                    self.reload(kernel, tun, None)
                {
                    self.notice = Some(message);
                }
            }
        }
        self.publish(kernel)
    }

    /// Fetches a subscription again without switching the active profile.
    pub fn refresh_profile(
        &mut self,
        id: &str,
        source: &dyn SubscriptionSource,
        kernel: &mut dyn KernelLaunch,
    ) -> ProfileSnapshot {
        let Some(index) = self.index_of(id) else {
            self.input_error = Some(MISSING_PROFILE.to_string());
            return self.snapshot();
        };
        if self.profiles[index].kind != ProfileKind::Subscription {
            return self.snapshot();
        }
        let fetched = match source.fetch(&self.profiles[index].source) {
            Ok(fetched) => fetched,
            Err(_) => {
                self.profiles[index].failure = Some(FETCH_ERROR.to_string());
                // A failed attempt still counts as a try so the timer does not spin.
                self.profiles[index].updated_ms = Some(now_ms());
                self.persist();
                return self.snapshot();
            }
        };
        let content = normalize_subscription_content(&fetched.content);
        if parse_config(&content).is_err() {
            self.profiles[index].failure = Some(CONTENT_ERROR.to_string());
            self.profiles[index].updated_ms = Some(now_ms());
            self.persist();
            return self.snapshot();
        }
        let now = now_ms();
        {
            let profile = &mut self.profiles[index];
            profile.content = content;
            profile.usage = parse_userinfo(fetched.userinfo.as_deref());
            profile.proxy_count = count_proxies(&profile.content);
            profile.updated_ms = Some(now);
            profile.last_success_ms = Some(now);
            profile.failure = None;
        }
        self.persist();
        if self.active_id.as_deref() == Some(id) {
            self.disabled_rules.clear();
            self.recompute_effective();
            if kernel.running() && self.platform == ClientPlatform::Desktop {
                let tun = self.takeover.tun;
                if let Err(StartError::Failed(message)) | Err(StartError::Idle(message)) =
                    self.reload(kernel, tun, None)
                {
                    self.notice = Some(message);
                }
            }
        }
        self.publish(kernel)
    }

    /// Subscriptions whose update interval has passed.
    pub fn due_profiles(&self, now: u64) -> Vec<String> {
        self.profiles
            .iter()
            .filter(|profile| profile.kind == ProfileKind::Subscription && profile.interval_hours > 0)
            .filter(|profile| {
                let every = u64::from(profile.interval_hours) * 3_600_000;
                match profile.updated_ms.or(profile.last_success_ms) {
                    Some(last) => now.saturating_add(REFRESH_SLACK_MS) >= last.saturating_add(every),
                    None => true,
                }
            })
            .map(|profile| profile.id.clone())
            .collect()
    }

    pub fn subscription_ids(&self) -> Vec<String> {
        self.profiles
            .iter()
            .filter(|profile| profile.kind == ProfileKind::Subscription)
            .map(|profile| profile.id.clone())
            .collect()
    }

    pub fn save_settings(
        &mut self,
        settings: KernelSettings,
        kernel: &mut dyn KernelLaunch,
        proxy: &mut dyn SystemProxy,
        tun: &mut dyn TunGrant,
        vpn: &mut dyn VpnGrant,
    ) -> ProfileSnapshot {
        let settings = settings.normalized();
        let restart = settings.kernel_part() != self.settings.kernel_part();
        self.settings = settings;
        nodes::set_probe(&self.settings.test_url, self.settings.test_timeout_ms_or_default());
        self.recompute_effective();
        self.persist();
        if !restart || self.platform != ClientPlatform::Desktop || !kernel.running() {
            return self.publish(kernel);
        }
        if self.takeover.system_proxy {
            return self.set_system_proxy(true, kernel, proxy, tun, vpn);
        }
        let tun_on = self.takeover.tun;
        if let Err(StartError::Failed(message)) | Err(StartError::Idle(message)) =
            self.reload(kernel, tun_on, None)
        {
            self.home_failure = Some(message);
            self.remember_current_failure();
        }
        self.publish(kernel)
    }

    fn record_delays(&mut self, profile_id: &str, groups: &[(String, Vec<String>)], results: Vec<NodeDelay>) {
        let marks: BTreeMap<String, Option<u64>> = results
            .into_iter()
            .map(|item| (item.name, item.delay_ms))
            .collect();
        let profile_slot = self.delays.entry(profile_id.to_string()).or_default();
        for (group, members) in groups {
            let slot = profile_slot.entry(group.clone()).or_default();
            for name in members {
                let Some(delay) = marks.get(name) else {
                    continue;
                };
                slot.insert(
                    name.clone(),
                    DelayMark {
                        delay_ms: *delay,
                        failed: delay.is_none(),
                    },
                );
            }
        }
    }

    fn tested_groups(&self, index: usize) -> Option<Vec<(String, Vec<String>)>> {
        let document = document_value(&self.profiles[index])?;
        Some(
            nodes::parse_proxy_groups(&document)
                .into_iter()
                .map(|group| {
                    let mut members = group.proxies;
                    if let Some(now) = self.auto_now.get(&group.name) {
                        if !members.iter().any(|item| item == now) {
                            members.push(now.clone());
                        }
                    }
                    (group.name, members)
                })
                .collect(),
        )
    }

    /// Tests every distinct node once and writes the result into every group that lists it.
    /// Each finished node is reported with its `tested`/`total` counters for the
    /// `node-test` progress event.
    pub fn test_all_with_progress(
        &mut self,
        kernel: &mut dyn KernelLaunch,
        on_progress: &mut dyn FnMut(&str, Option<u64>, bool, usize, usize),
    ) -> ProfileSnapshot {
        self.sync_runtime(kernel);
        if !self.kernel_running {
            self.nodes_error = Some(KERNEL_DOWN.to_string());
            return self.snapshot();
        }
        let Some(index) = self.nodes_profile_index() else {
            self.nodes_error = Some(NEED_PROFILE.to_string());
            return self.snapshot();
        };
        let Some(groups) = self.tested_groups(index) else {
            self.nodes_error = Some(NO_NODES.to_string());
            return self.snapshot();
        };
        let mut unique: Vec<String> = Vec::new();
        for (_, members) in &groups {
            for name in members {
                if !unique.iter().any(|item| item == name) {
                    unique.push(name.clone());
                }
            }
        }
        let total = unique.len();
        let profile_id = self.profiles[index].id.clone();
        let mut tested = 0usize;
        match kernel.probe_delays_with_progress("", &unique, &mut |name, delay, failed| {
            tested += 1;
            on_progress(name, delay, failed, tested, total);
        }) {
            Ok(results) => {
                self.record_delays(&profile_id, &groups, results);
                self.nodes_error = None;
            }
            Err(message) => {
                self.nodes_error = Some(if message.is_empty() { KERNEL_DOWN.to_string() } else { message });
            }
        }
        self.snapshot()
    }

    pub fn test_node(&mut self, node: &str, kernel: &mut dyn KernelLaunch) -> ProfileSnapshot {
        self.sync_runtime(kernel);
        if !self.kernel_running {
            self.nodes_error = Some(KERNEL_DOWN.to_string());
            return self.snapshot();
        }
        let Some(index) = self.nodes_profile_index() else {
            self.nodes_error = Some(NEED_PROFILE.to_string());
            return self.snapshot();
        };
        let Some(groups) = self.tested_groups(index) else {
            self.nodes_error = Some(NO_NODES.to_string());
            return self.snapshot();
        };
        let node = node.trim().to_string();
        let profile_id = self.profiles[index].id.clone();
        match kernel.probe_delays("", std::slice::from_ref(&node)) {
            Ok(results) => {
                self.record_delays(&profile_id, &groups, results);
                self.nodes_error = None;
            }
            Err(message) => {
                self.nodes_error = Some(if message.is_empty() { KERNEL_DOWN.to_string() } else { message });
            }
        }
        self.snapshot()
    }

    pub fn close_connections(&mut self, id: Option<&str>, kernel: &mut dyn KernelLaunch) -> ProfileSnapshot {
        if let Some(endpoint) = kernel.controller() {
            if let Err(message) = diagnostics::close_connections(&endpoint, id) {
                self.notice = Some(message);
            }
        }
        self.publish(kernel)
    }

    /// Full rule list from the active profile, keys computed over the original order.
    fn active_config_rules(&self) -> Vec<diagnostics::ConfigRule> {
        let Some(profile) = self
            .active_id
            .as_deref()
            .and_then(|id| self.profiles.iter().find(|profile| profile.id == id))
        else {
            return Vec::new();
        };
        let Some(value) = document_value(profile) else {
            return Vec::new();
        };
        diagnostics::config_rules(&value)
    }

    pub fn rules(&mut self, kernel: &mut dyn KernelLaunch) -> RulesSnapshot {
        let disabled = self.disabled_rules.iter().cloned().collect();
        let config = self.active_config_rules();
        match kernel.controller() {
            Some(endpoint) => match diagnostics::fetch_rules(&endpoint) {
                Ok(kernel_rules) => RulesSnapshot {
                    rules: diagnostics::rule_rows(&config, &kernel_rules, &self.disabled_rules),
                    error: None,
                    disabled,
                },
                Err(message) => RulesSnapshot {
                    rules: diagnostics::rule_rows(&config, &[], &self.disabled_rules),
                    error: Some(message),
                    disabled,
                },
            },
            None => RulesSnapshot {
                rules: Vec::new(),
                error: Some(KERNEL_DOWN.to_string()),
                disabled,
            },
        }
    }

    /// Temporarily disables or re-enables one rule. The filtered runtime config is
    /// hot-reloaded; unknown keys and failed reloads leave the previous key set.
    pub fn set_rule_disabled(
        &mut self,
        command: RuleToggle,
        kernel: &mut dyn KernelLaunch,
    ) -> Result<RulesSnapshot, String> {
        self.sync_runtime(kernel);
        if !self.kernel_running {
            return Err(KERNEL_DOWN.to_string());
        }
        let key = command.key.trim().to_string();
        if !self.active_config_rules().iter().any(|rule| rule.key == key) {
            return Err("没有这条规则".to_string());
        }
        let previous = self.disabled_rules.clone();
        let changed = if command.disabled {
            self.disabled_rules.insert(key)
        } else {
            self.disabled_rules.remove(&key)
        };
        if !changed {
            return Ok(self.rules(kernel));
        }
        let tun = self.takeover.tun;
        let outcome = match self.runtime_base.clone() {
            Some(base) => diagnostics::filter_disabled_rules(&base, &self.disabled_rules)
                .and_then(|yaml| kernel.reload_config(&yaml)),
            None => match self.kernel_yaml(tun, None) {
                Ok((base, _)) => diagnostics::filter_disabled_rules(&base, &self.disabled_rules)
                    .and_then(|yaml| kernel.reload_config(&yaml)),
                Err(StartError::Idle(message)) | Err(StartError::Failed(message)) => Err(message),
            },
        };
        if let Err(message) = outcome {
            self.disabled_rules = previous;
            return Err(message);
        }
        Ok(self.rules(kernel))
    }

    pub fn providers(&mut self, kernel: &mut dyn KernelLaunch) -> ProvidersSnapshot {
        let Some(endpoint) = kernel.controller() else {
            return ProvidersSnapshot { providers: Vec::new(), error: Some(KERNEL_DOWN.to_string()) };
        };
        match diagnostics::fetch_providers(&endpoint) {
            Ok(providers) => ProvidersSnapshot { providers, error: None },
            Err(message) => ProvidersSnapshot { providers: Vec::new(), error: Some(message) },
        }
    }

    /// The controller endpoint for slow calls made without holding the session lock.
    pub fn controller_of(kernel: &mut dyn KernelLaunch) -> Option<ControllerEndpoint> {
        kernel.controller()
    }

    /// Drops the kernel's fake-ip mapping or DNS cache.
    pub fn flush_cache(&mut self, which: &str, kernel: &mut dyn KernelLaunch) -> ProfileSnapshot {
        let Some(endpoint) = kernel.controller() else {
            self.notice = Some(KERNEL_DOWN.to_string());
            return self.snapshot();
        };
        let result = match which {
            "fakeip" => diagnostics::flush_cache(&endpoint, "fakeip"),
            _ => diagnostics::flush_cache(&endpoint, "dns"),
        };
        self.notice = result.err();
        self.publish(kernel)
    }

    pub fn clear_logs(&mut self) -> ProfileSnapshot {
        self.logs.clear();
        self.snapshot()
    }
}

struct Prepared {
    yaml: String,
    mixed_port: Option<i64>,
    mode: Option<String>,
}

enum StartError {
    Idle(String),
    Failed(String),
}

enum PrepareError {
    Content,
    Override,
}

fn normalize_outbound(mode: &str) -> Option<&'static str> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "rule" | "规则" => Some("rule"),
        "global" | "全局" => Some("global"),
        "direct" | "直连" => Some("direct"),
        _ => None,
    }
}

fn force_mode(yaml: &str, mode: &str) -> Result<String, String> {
    let mut value: Value = serde_yaml::from_str(yaml).map_err(|_| CONTENT_ERROR.to_string())?;
    let Some(map) = value.as_mapping_mut() else {
        return Err(CONTENT_ERROR.to_string());
    };
    map.insert(
        Value::String("mode".to_string()),
        Value::String(mode.to_string()),
    );
    serde_yaml::to_string(&value).map_err(|_| CONTENT_ERROR.to_string())
}

fn force_tun(yaml: &str, enable: bool, fd: Option<i32>) -> Result<String, String> {
    let mut value: Value = serde_yaml::from_str(yaml).map_err(|_| CONTENT_ERROR.to_string())?;
    let Some(map) = value.as_mapping_mut() else {
        return Err(CONTENT_ERROR.to_string());
    };
    let tun_key = Value::String("tun".to_string());
    let mut tun = map
        .get(&tun_key)
        .and_then(|item| item.as_mapping())
        .cloned()
        .unwrap_or_default();
    tun.insert(Value::String("enable".to_string()), Value::Bool(enable));
    let fd_key = Value::String("file-descriptor".to_string());
    if let Some(fd) = fd {
        tun.insert(fd_key, Value::Number(i64::from(fd).into()));
    } else {
        tun.remove(&fd_key);
    }
    map.insert(tun_key, Value::Mapping(tun));
    serde_yaml::to_string(&value).map_err(|_| CONTENT_ERROR.to_string())
}

fn document_value(profile: &Profile) -> Option<Value> {
    if profile.content.trim().is_empty() {
        return None;
    }
    let prepared = match prepare(&profile.content, &profile.applied_override) {
        Ok(prepared) => prepared,
        Err(_) => prepare(&profile.content, "").ok()?,
    };
    serde_yaml::from_str(&prepared.yaml).ok()
}

fn prepare(content: &str, override_text: &str) -> Result<Prepared, PrepareError> {
    let mut base = parse_config(content).map_err(|_| PrepareError::Content)?;
    if !override_text.trim().is_empty() {
        let overlay =
            serde_yaml::from_str::<Value>(override_text).map_err(|_| PrepareError::Override)?;
        if !overlay.is_null() {
            merge(&mut base, &overlay);
        }
        if !is_config(&base) {
            return Err(PrepareError::Override);
        }
    }
    let yaml = serde_yaml::to_string(&base).map_err(|_| PrepareError::Content)?;
    Ok(Prepared {
        mixed_port: read_i64(&base, "mixed-port"),
        mode: read_string(&base, "mode"),
        yaml,
    })
}

fn parse_config(text: &str) -> Result<Value, ()> {
    let value = serde_yaml::from_str::<Value>(text).map_err(|_| ())?;
    if is_config(&value) {
        Ok(value)
    } else {
        Err(())
    }
}

fn is_config(value: &Value) -> bool {
    match value.as_mapping() {
        Some(map) => !map.is_empty(),
        None => false,
    }
}

fn merge(base: &mut Value, overlay: &Value) {
    let Some(over_map) = overlay.as_mapping() else {
        *base = overlay.clone();
        return;
    };
    if base.as_mapping().is_none() {
        *base = overlay.clone();
        return;
    }
    for (key, value) in over_map {
        let Some(base_map) = base.as_mapping_mut() else {
            return;
        };
        if let Some(existing) = base_map.get_mut(key) {
            merge(existing, value);
        } else {
            base_map.insert(key.clone(), value.clone());
        }
    }
}

fn read_i64(value: &Value, key: &str) -> Option<i64> {
    mapping_get(value, key).and_then(Value::as_i64)
}

fn read_string(value: &Value, key: &str) -> Option<String> {
    mapping_get(value, key)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn mapping_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_mapping()?
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, item)| item)
}

fn parse_userinfo(header: Option<&str>) -> Option<Usage> {
    let header = header?.trim();
    if header.is_empty() {
        return None;
    }
    let mut upload = None;
    let mut download = None;
    let mut total = None;
    let mut expire = None;
    for part in header.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let Ok(number) = value.trim().parse::<u64>() else {
            continue;
        };
        match key {
            "upload" => upload = Some(number),
            "download" => download = Some(number),
            "total" => total = Some(number),
            "expire" => expire = Some(number),
            _ => {}
        }
    }
    usage_from_parts(
        total
            .filter(|value| *value > 0)
            .map(|_| upload.unwrap_or(0).saturating_add(download.unwrap_or(0))),
        total.filter(|value| *value > 0),
        expire.filter(|value| *value > 0),
    )
}

fn usage_from_parts(used: Option<u64>, total: Option<u64>, expire: Option<u64>) -> Option<Usage> {
    let total = total.filter(|value| *value > 0);
    let used = if total.is_some() {
        used.or(Some(0))
    } else {
        None
    };
    let expire = expire.filter(|value| *value > 0);
    if used.is_none() && total.is_none() && expire.is_none() {
        None
    } else {
        Some(Usage {
            used,
            total,
            expire,
        })
    }
}

fn parse_install_link(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.to_ascii_lowercase().starts_with("clash://") {
        return Err(LINK_ERROR.to_string());
    }
    let Some(rest) = strip_prefix_ignore_ascii_case(raw, "billow://") else {
        return Err(LINK_ERROR.to_string());
    };
    let Some((host, query)) = rest.split_once('?') else {
        return Err(ONE_LINK_ERROR.to_string());
    };
    if !host
        .trim_end_matches('/')
        .eq_ignore_ascii_case("install-config")
    {
        return Err(LINK_ERROR.to_string());
    }
    let mut urls = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key.eq_ignore_ascii_case("url") {
            urls.push(percent_decode(value));
        }
    }
    if urls.len() != 1 {
        return Err(ONE_LINK_ERROR.to_string());
    }
    validate_subscription_url(&urls[0])
}

fn validate_subscription_url(url: &str) -> Result<String, String> {
    let url = url.trim();
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err(URL_ERROR.to_string());
    }
    if url.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(URL_ERROR.to_string());
    }
    let host = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or("")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() || !host.contains('.') && host != "localhost" {
        return Err(URL_ERROR.to_string());
    }
    Ok(url.to_string())
}

fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    if value.len() < prefix.len() {
        return None;
    }
    let (head, tail) = value.split_at(prefix.len());
    if head.eq_ignore_ascii_case(prefix) {
        Some(tail)
    } else {
        None
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[index + 1..index + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    out.push(value);
                    index += 3;
                    continue;
                }
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn subscription_name(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        "订阅".to_string()
    } else {
        host.to_string()
    }
}

fn clean_name(name: &str, fallback: &str) -> String {
    let name: String = name
        .trim()
        .chars()
        .filter(|ch| *ch != '/' && *ch != '\\' && *ch != '\n' && *ch != '\r')
        .take(80)
        .collect();
    if name.is_empty() {
        fallback.to_string()
    } else {
        name
    }
}

fn normalize_subscription_content(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches('\u{feff}');
    if parse_config(trimmed).is_ok() {
        return trimmed.to_string();
    }
    let compact: String = trimmed.chars().filter(|ch| !ch.is_whitespace()).collect();
    if let Some(text) = decode_base64_text(&compact) {
        let text = text.trim().trim_start_matches('\u{feff}').to_string();
        if parse_config(&text).is_ok() {
            return text;
        }
    }
    trimmed.to_string()
}

fn decode_base64_text(text: &str) -> Option<String> {
    let attempts = [
        base64::engine::general_purpose::STANDARD.decode(text),
        base64::engine::general_purpose::STANDARD_NO_PAD.decode(text),
        base64::engine::general_purpose::URL_SAFE.decode(text),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text),
    ];
    for result in attempts {
        if let Ok(bytes) = result
            && let Ok(text) = String::from_utf8(bytes)
        {
            return Some(text);
        }
    }
    None
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::nodes::{KERNEL_DOWN, NEED_PROFILE, NO_MATCH, NO_NODES, NOT_MANUAL, NodeDelay};
    use crate::takeover::{MemoryProxy, MemoryTun, MemoryVpn};

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(name: &str) -> TempDir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "billow-profile-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    struct MapSource {
        items: HashMap<String, Result<FetchedSubscription, String>>,
    }

    impl SubscriptionSource for MapSource {
        fn fetch(&self, url: &str) -> Result<FetchedSubscription, String> {
            self.items
                .get(url)
                .cloned()
                .unwrap_or(Err(FETCH_ERROR.to_string()))
        }
    }

    struct RejectSource;

    impl SubscriptionSource for RejectSource {
        fn fetch(&self, _url: &str) -> Result<FetchedSubscription, String> {
            Err(FETCH_ERROR.to_string())
        }
    }

    struct FakeKernel {
        running: Option<String>,
        fail: bool,
        calls: u32,
    }

    impl KernelLaunch for FakeKernel {
        fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
            self.calls += 1;
            if self.fail {
                return Err(KERNEL_ERROR.to_string());
            }
            self.running = Some(config_yaml.to_string());
            Ok(())
        }
    }

    fn config(port: i64) -> String {
        format!("mixed-port: {port}\nmode: rule\nproxies: []\n")
    }

    #[test]
    fn delete_rename_and_edit_manage_saved_profiles() {
        let dir = temp_dir("manage");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        book.add_local("b.yaml", &config(7891));
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        book.enable("p1", &RejectSource, &mut kernel);

        let renamed = book.rename_profile("p2", "  办公  ");
        assert_eq!(renamed.profiles[1].name, "办公");

        let bad = book.save_profile_content("p2", "- not a map", &mut kernel);
        assert!(bad.input_error.is_some());
        assert_eq!(book.profile_content("p2").unwrap(), config(7891));
        book.save_profile_content("p2", "mixed-port: 7000\nproxies:\n  - {name: a, type: ss}\n", &mut kernel);
        let listed = book.snapshot();
        assert_eq!(listed.profiles[1].proxy_count, 1);

        let removed = book.delete_profile("p2");
        assert_eq!(removed.profiles.len(), 1);
        let reopened = ProfileBook::open(&dir.0).snapshot();
        assert_eq!(reopened.profiles.len(), 1);
        assert_eq!(reopened.profiles[0].id, "p1");
    }

    #[test]
    fn kernel_settings_overwrite_the_profile_and_a_missing_port_gets_a_default() {
        let dir = temp_dir("settings");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", "mode: rule\nproxies: []\n");
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        let enabled = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(enabled.mixed_port, Some(7890));

        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let settings = KernelSettings {
            mixed_port: Some(7999),
            allow_lan: Some(true),
            log_level: Some("WARNING".to_string()),
            test_url: "ftp://nope".to_string(),
            ..Default::default()
        };
        let saved = book.save_settings(settings, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert_eq!(saved.settings.log_level.as_deref(), Some("warning"));
        assert!(saved.settings.test_url.is_empty());
        let again = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(again.mixed_port, Some(7999));
        let running: Value = serde_yaml::from_str(kernel.running.as_deref().unwrap()).unwrap();
        assert_eq!(read_i64(&running, "mixed-port"), Some(7999));
        assert_eq!(mapping_get(&running, "allow-lan").and_then(Value::as_bool), Some(true));
        assert_eq!(ProfileBook::open(&dir.0).snapshot().settings.mixed_port, Some(7999));
    }

    #[test]
    fn geo_settings_override_auto_update_interval_and_source() {
        let base = "mixed-port: 7890\ngeox-url:\n  geoip: https://mine/geoip.dat\n";
        let (kept, _) = apply_settings(base, &KernelSettings::default(), true).unwrap();
        let kept: Value = serde_yaml::from_str(&kept).unwrap();
        assert_eq!(read_string(mapping_get(&kept, "geox-url").unwrap(), "geoip").as_deref(), Some("https://mine/geoip.dat"));
        assert!(mapping_get(&kept, "geo-auto-update").is_none());

        let settings = KernelSettings {
            geo_auto_update: Some(true),
            geo_update_interval: Some(72),
            geo_source: "jsdelivr".to_string(),
            ..Default::default()
        };
        let (yaml, _) = apply_settings(base, &settings, true).unwrap();
        let value: Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(mapping_get(&value, "geo-auto-update").and_then(Value::as_bool), Some(true));
        assert_eq!(read_i64(&value, "geo-update-interval"), Some(72));
        let geox = mapping_get(&value, "geox-url").unwrap();
        assert_eq!(
            read_string(geox, "geosite").as_deref(),
            Some("https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat")
        );
        assert!(read_string(geox, "asn").unwrap().ends_with("GeoLite2-ASN.mmdb"));
    }

    #[test]
    fn tun_gets_routing_and_dns_and_dns_override_replaces_the_profile_block() {
        let dir = temp_dir("tun-dns");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\nproxies: []\ndns:\n  enable: false\n  nameserver: [1.1.1.1]\n");
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        book.enable("p1", &RejectSource, &mut kernel);
        let (yaml, _) = book.kernel_yaml(true, None).ok().unwrap();
        let running: Value = serde_yaml::from_str(&yaml).unwrap();
        let tun = mapping_get(&running, "tun").unwrap();
        assert_eq!(mapping_get(tun, "enable").and_then(Value::as_bool), Some(true));
        assert_eq!(mapping_get(tun, "auto-route").and_then(Value::as_bool), Some(true));
        assert_eq!(read_string(tun, "stack").as_deref(), Some("mixed"));
        let dns = mapping_get(&running, "dns").unwrap();
        assert_eq!(mapping_get(dns, "enable").and_then(Value::as_bool), Some(true), "TUN turns DNS on");

        let (plain, _) = book.kernel_yaml(false, None).ok().unwrap();
        let plain: Value = serde_yaml::from_str(&plain).unwrap();
        assert_eq!(
            mapping_get(mapping_get(&plain, "dns").unwrap(), "enable").and_then(Value::as_bool),
            Some(false),
            "without TUN the profile's DNS stays as written"
        );

        let mut proxy = MemoryProxy::default();
        let mut tun_grant = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let mut settings = KernelSettings { dns_override: true, sniffer: Some(true), ..Default::default() };
        settings.dns.enhanced_mode = "redir-host".to_string();
        settings.dns.nameserver = vec![" https://1.1.1.1/dns-query ".to_string(), String::new()];
        settings.tun.stack = "GVISOR".to_string();
        let saved = book.save_settings(settings, &mut kernel, &mut proxy, &mut tun_grant, &mut vpn);
        assert_eq!(saved.settings.tun.stack, "gvisor");
        assert_eq!(saved.settings.dns.nameserver, ["https://1.1.1.1/dns-query"]);
        let (yaml, _) = book.kernel_yaml(false, None).ok().unwrap();
        let running: Value = serde_yaml::from_str(&yaml).unwrap();
        let dns = mapping_get(&running, "dns").unwrap();
        assert_eq!(read_string(dns, "enhanced-mode").as_deref(), Some("redir-host"));
        assert!(mapping_get(dns, "fake-ip-range").is_none());
        assert_eq!(mapping_get(mapping_get(&running, "sniffer").unwrap(), "enable").and_then(Value::as_bool), Some(true));
        assert_eq!(read_string(mapping_get(&running, "tun").unwrap(), "stack").as_deref(), Some("gvisor"));
    }

    #[test]
    fn subscriptions_with_an_interval_become_due_after_it_passes() {
        let dir = temp_dir("due");
        let mut book = ProfileBook::open(&dir.0);
        book.add_subscription("https://example.com/sub");
        book.add_local("a.yaml", &config(7890));
        assert!(book.due_profiles(now_ms()).is_empty());
        book.set_profile_interval("p1", 6);
        assert_eq!(book.due_profiles(now_ms()), ["p1"]);
        let mut kernel = FakeKernel { running: None, fail: false, calls: 0 };
        let failed = book.refresh_profile("p1", &RejectSource, &mut kernel);
        assert_eq!(failed.profiles[0].failure.as_deref(), Some(FETCH_ERROR));
        assert!(book.due_profiles(now_ms()).is_empty());
        assert_eq!(book.due_profiles(now_ms() + 6 * 3_600_000), ["p1"]);
        assert_eq!(book.subscription_ids(), ["p1"]);
    }

    fn current_ids(snapshot: &ProfileSnapshot) -> Vec<&str> {
        snapshot
            .profiles
            .iter()
            .filter(|profile| profile.current)
            .map(|profile| profile.id.as_str())
            .collect()
    }

    fn port_of(yaml: &str) -> i64 {
        let value: Value = serde_yaml::from_str(yaml).unwrap();
        read_i64(&value, "mixed-port").unwrap()
    }

    #[test]
    fn enabling_two_profiles_keeps_one_current_mark() {
        let dir = temp_dir("two");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        book.add_local("b.yaml", &config(7891));
        let mut kernel = FakeKernel {
            running: None,
            fail: false,
            calls: 0,
        };
        let first = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(current_ids(&first), ["p1"]);
        assert_eq!(first.active_id.as_deref(), Some("p1"));
        assert_eq!(first.mixed_port, Some(7890));
        assert!(
            first
                .profiles
                .iter()
                .all(|profile| profile.failure.is_none())
        );

        let second = book.enable("p2", &RejectSource, &mut kernel);
        assert_eq!(current_ids(&second), ["p2"]);
        assert_eq!(second.active_id.as_deref(), Some("p2"));
        assert_eq!(second.mixed_port, Some(7891));
        assert_eq!(port_of(kernel.running.as_deref().unwrap()), 7891);
        assert_eq!(kernel.calls, 2);

        let reopened = ProfileBook::open(&dir.0);
        let snapshot = reopened.snapshot();
        assert_eq!(current_ids(&snapshot), ["p2"]);
        assert_eq!(snapshot.mixed_port, Some(7891));
    }

    #[test]
    fn userinfo_records_usage_only_when_total_is_positive_and_skips_zero_expiry() {
        assert!(parse_userinfo(None).is_none());
        assert!(parse_userinfo(Some("")).is_none());
        assert!(parse_userinfo(Some("not a header")).is_none());
        assert!(parse_userinfo(Some("upload=1; download=2; total=0; expire=0")).is_none());

        let usage = parse_userinfo(Some(
            " upload = 10 ; download = 20 ; total = 100 ; expire = 0 ",
        ))
        .unwrap();
        assert_eq!(usage.used, Some(30));
        assert_eq!(usage.total, Some(100));
        assert_eq!(usage.expire, None);

        let expire_only = parse_userinfo(Some("total=0; expire=1700000000")).unwrap();
        assert_eq!(expire_only.used, None);
        assert_eq!(expire_only.total, None);
        assert_eq!(expire_only.expire, Some(1700000000));

        let dir = temp_dir("userinfo");
        let mut book = ProfileBook::open(&dir.0);
        book.add_subscription("https://example.com/sub");
        let mut source = MapSource {
            items: HashMap::new(),
        };
        source.items.insert(
            "https://example.com/sub".to_string(),
            Ok(FetchedSubscription {
                content: config(7890),
                userinfo: Some("upload=10; download=20; total=100; expire=0".to_string()),
            }),
        );
        let mut kernel = FakeKernel {
            running: None,
            fail: false,
            calls: 0,
        };
        let snapshot = book.enable("p1", &source, &mut kernel);
        let profile = &snapshot.profiles[0];
        assert_eq!(profile.used, Some(30));
        assert_eq!(profile.total, Some(100));
        assert_eq!(profile.expire, None);
        assert!(profile.current);

        source.items.insert(
            "https://example.com/plain".to_string(),
            Ok(FetchedSubscription {
                content: config(7892),
                userinfo: None,
            }),
        );
        book.add_subscription("https://example.com/plain");
        let snapshot = book.enable("p2", &source, &mut kernel);
        let plain = snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "p2")
            .unwrap();
        assert!(plain.used.is_none() && plain.total.is_none() && plain.expire.is_none());
        let encoded = base64::engine::general_purpose::STANDARD.encode(config(7001));
        source.items.insert(
            "https://example.com/b64".to_string(),
            Ok(FetchedSubscription {
                content: encoded,
                userinfo: Some("total=5; expire=9".to_string()),
            }),
        );
        book.add_subscription("https://example.com/b64");
        let snapshot = book.update("p3", &source, &mut kernel);
        assert_eq!(snapshot.mixed_port, Some(7001));
        let encoded_profile = snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "p3")
            .unwrap();
        assert_eq!(encoded_profile.used, Some(0));
        assert_eq!(encoded_profile.total, Some(5));
        assert_eq!(encoded_profile.expire, Some(9));
    }

    #[test]
    fn install_link_adds_only_after_confirm_and_does_not_enable() {
        let dir = temp_dir("link");
        let mut book = ProfileBook::open(&dir.0);
        let link = "billow://install-config?url=https%3A%2F%2Fexample.com%2Fsub";
        let staged = book.stage_install_link(link);
        assert_eq!(
            staged.pending_url.as_deref(),
            Some("https://example.com/sub")
        );
        assert!(staged.profiles.is_empty());
        assert!(staged.active_id.is_none());

        let cancelled = book.cancel_pending();
        assert!(cancelled.pending_url.is_none());
        assert!(cancelled.profiles.is_empty());

        book.stage_install_link(link);
        let confirmed = book.confirm_pending();
        assert!(confirmed.pending_url.is_none());
        assert_eq!(confirmed.profiles.len(), 1);
        assert_eq!(confirmed.profiles[0].kind, "subscription");
        assert_eq!(confirmed.profiles[0].source, "https://example.com/sub");
        assert!(!confirmed.profiles[0].current);
        assert!(confirmed.active_id.is_none());
        assert!(book.confirm_pending().profiles.len() == 1);

        let before = book.snapshot();
        let rejected =
            book.stage_install_link("clash://install-config?url=https://example.com/other");
        assert_eq!(rejected.input_error.as_deref(), Some(LINK_ERROR));
        assert_eq!(rejected.profiles.len(), before.profiles.len());
        assert!(rejected.pending_url.is_none());

        let doubled = book.stage_install_link(
            "billow://install-config?url=https://a.example/x&url=https://b.example/y",
        );
        assert_eq!(doubled.input_error.as_deref(), Some(ONE_LINK_ERROR));
        assert_eq!(doubled.profiles.len(), 1);
        assert!(
            book.stage_install_link("billow://install-config?url=ftp://example.com/a")
                .input_error
                .is_some()
        );
        assert_eq!(book.snapshot().profiles.len(), 1);

        let manual = book.add_subscription("https://manual.example/a");
        assert_eq!(manual.profiles.len(), 2);
        assert!(manual.profiles.iter().all(|profile| !profile.current));
        let local = book.add_local("home.yaml", &config(1));
        assert_eq!(local.profiles.len(), 3);
        assert_eq!(local.profiles[2].kind, "local");
    }

    #[test]
    fn duplicate_subscription_urls_are_rejected_without_adding() {
        let dir = temp_dir("duplicate");
        let mut book = ProfileBook::open(&dir.0);
        let first = book.add_subscription(" https://example.com/sub ");
        assert_eq!(first.profiles.len(), 1);
        assert_eq!(first.profiles[0].source, "https://example.com/sub");
        assert_eq!(first.input_error, None);

        let doubled = book.add_subscription("https://example.com/sub");
        assert_eq!(doubled.profiles.len(), 1);
        assert_eq!(doubled.input_error.as_deref(), Some(DUPLICATE_ERROR));

        let spaced = book.add_subscription("  https://example.com/sub  ");
        assert_eq!(spaced.profiles.len(), 1);
        assert_eq!(spaced.input_error.as_deref(), Some(DUPLICATE_ERROR));

        let other = book.add_subscription("https://example.com/other");
        assert_eq!(other.profiles.len(), 2);
        assert_eq!(other.input_error, None);

        // A deep link reaches the same guard and keeps the pending link for a retry.
        book.stage_install_link(
            "billow://install-config?url=https%3A%2F%2Fexample.com%2Fsub",
        );
        let confirmed = book.confirm_pending();
        assert_eq!(confirmed.profiles.len(), 2);
        assert_eq!(confirmed.input_error.as_deref(), Some(DUPLICATE_ERROR));
        assert_eq!(
            confirmed.pending_url.as_deref(),
            Some("https://example.com/sub")
        );
    }

    #[test]
    fn unreachable_subscription_enable_closes_takeover_and_keeps_the_reason() {
        let dir = temp_dir("unreachable");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("ok.yaml", &config(7890));
        let mut kernel = FakeKernel {
            running: None,
            fail: false,
            calls: 0,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        book.set_takeover(true, true, true);
        book.add_subscription("https://down.example/sub");
        let mut missing = MapSource {
            items: HashMap::new(),
        };
        missing.items.insert(
            "https://down.example/sub".to_string(),
            Err(FETCH_ERROR.to_string()),
        );
        let snapshot = book.enable("p2", &missing, &mut kernel);
        assert_eq!(snapshot.active_id.as_deref(), Some("p1"));
        assert_eq!(current_ids(&snapshot), ["p1"]);
        assert!(!snapshot.system_proxy && !snapshot.tun && !snapshot.vpn);
        let failed = snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "p2")
            .unwrap();
        assert_eq!(failed.failure.as_deref(), Some(FETCH_ERROR));
        assert!(!failed.current);
        assert_eq!(kernel.calls, 1);
        assert_eq!(snapshot.mixed_port, Some(7890));
        assert_eq!(snapshot.failure.as_deref(), Some(FETCH_ERROR));

        let again = book.enable("p2", &missing, &mut kernel);
        assert_eq!(
            again
                .profiles
                .iter()
                .find(|profile| profile.id == "p2")
                .unwrap()
                .failure
                .as_deref(),
            Some(FETCH_ERROR)
        );
        assert!(!again.system_proxy && !again.tun && !again.vpn);

        missing.items.insert(
            "https://down.example/sub".to_string(),
            Ok(FetchedSubscription {
                content: config(7900),
                userinfo: None,
            }),
        );
        let recovered = book.enable("p2", &missing, &mut kernel);
        assert_eq!(current_ids(&recovered), ["p2"]);
        assert!(recovered.failure.is_none());
        assert!(
            recovered
                .profiles
                .iter()
                .all(|profile| profile.id != "p2" || profile.failure.is_none())
        );
    }

    #[test]
    fn unusable_override_does_not_replace_the_active_config() {
        let dir = temp_dir("override");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local(
            "a.yaml",
            "mixed-port: 7890\nmode: rule\ndns:\n  enable: true\n  listen: 127.0.0.1:53\n",
        );
        book.add_local("b.yaml", &config(7891));
        let mut kernel = FakeKernel {
            running: None,
            fail: false,
            calls: 0,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        book.set_takeover(true, false, true);
        book.save_override("p1", ":\n  -");
        let calls_before = kernel.calls;
        let rejected = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(rejected.active_id.as_deref(), Some("p1"));
        assert_eq!(current_ids(&rejected), ["p1"]);
        assert_eq!(rejected.mixed_port, Some(7890));
        assert_eq!(rejected.mode.as_deref(), Some("rule"));
        assert!(rejected.system_proxy && !rejected.tun && rejected.vpn);
        assert_eq!(
            rejected.profiles[0].override_error.as_deref(),
            Some(OVERRIDE_ERROR)
        );
        assert!(rejected.profiles[0].failure.is_none());
        assert_eq!(kernel.calls, calls_before);
        assert_eq!(port_of(kernel.running.as_deref().unwrap()), 7890);

        book.save_override("p2", "[\n");
        let switched = book.enable("p2", &RejectSource, &mut kernel);
        assert_eq!(switched.active_id.as_deref(), Some("p1"));
        assert_eq!(switched.mixed_port, Some(7890));
        assert!(switched.system_proxy && switched.vpn && !switched.tun);
        assert_eq!(kernel.calls, calls_before);
        assert_eq!(
            switched
                .profiles
                .iter()
                .find(|profile| profile.id == "p2")
                .unwrap()
                .override_error
                .as_deref(),
            Some(OVERRIDE_ERROR)
        );

        book.save_override("p1", "mixed-port: 8000\ndns:\n  enable: false\n");
        let applied = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(applied.mixed_port, Some(8000));
        assert!(applied.profiles[0].override_error.is_none());
        assert!(applied.profiles[0].failure.is_none());
        assert!(applied.system_proxy && applied.vpn);
        let running: Value = serde_yaml::from_str(kernel.running.as_deref().unwrap()).unwrap();
        assert_eq!(read_i64(&running, "mixed-port"), Some(8000));
        // The effective-config view shows exactly what the kernel was given.
        let effective: Value = serde_yaml::from_str(&book.effective_config().unwrap()).unwrap();
        assert_eq!(read_i64(&effective, "mixed-port"), Some(8000));
        assert_eq!(
            mapping_get(mapping_get(&effective, "dns").unwrap(), "enable").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(read_string(&effective, "external-controller").as_deref(), Some("127.0.0.1:17690"));
        let dns = mapping_get(&running, "dns").unwrap();
        assert_eq!(read_string(dns, "listen").as_deref(), Some("127.0.0.1:53"));
        assert_eq!(
            mapping_get(dns, "enable").and_then(Value::as_bool),
            Some(false)
        );

        book.save_override("p2", "mixed-port: 8001\nmode: global\n");
        let other = book.enable("p2", &RejectSource, &mut kernel);
        assert_eq!(current_ids(&other), ["p2"]);
        assert_eq!(other.mixed_port, Some(8001));
        assert_eq!(other.mode.as_deref(), Some("global"));
        let back = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(current_ids(&back), ["p1"]);
        assert_eq!(back.mixed_port, Some(8000));
        assert_eq!(back.mode.as_deref(), Some("rule"));

        book.save_override("p1", "");
        assert_eq!(book.snapshot().mixed_port, Some(8000));
        // A saved but not yet applied override is not what runs.
        let effective: Value = serde_yaml::from_str(&book.effective_config().unwrap()).unwrap();
        assert_eq!(read_i64(&effective, "mixed-port"), Some(8000));
        assert_eq!(kernel.calls, 4);
        let cleared = book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(cleared.mixed_port, Some(7890));
    }

    #[test]
    fn kernel_start_failure_does_not_take_effect_and_closes_takeover() {
        let dir = temp_dir("kernel-fail");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        book.add_local("b.yaml", &config(7891));
        let mut kernel = FakeKernel {
            running: None,
            fail: false,
            calls: 0,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        book.set_takeover(true, true, false);
        kernel.fail = true;
        let failed = book.enable("p2", &RejectSource, &mut kernel);
        assert_eq!(failed.active_id.as_deref(), Some("p1"));
        assert_eq!(failed.mixed_port, Some(7890));
        assert!(!failed.system_proxy && !failed.tun && !failed.vpn);
        assert_eq!(
            failed
                .profiles
                .iter()
                .find(|profile| profile.id == "p2")
                .unwrap()
                .failure
                .as_deref(),
            Some(KERNEL_ERROR)
        );
        assert_eq!(port_of(kernel.running.as_deref().unwrap()), 7890);

        book.add_local("bad.yaml", "[]\n");
        kernel.fail = false;
        let calls = kernel.calls;
        book.set_takeover(true, false, false);
        let invalid = book.enable("p3", &RejectSource, &mut kernel);
        assert_eq!(invalid.active_id.as_deref(), Some("p1"));
        assert!(!invalid.system_proxy && !invalid.tun && !invalid.vpn);
        assert_eq!(
            invalid
                .profiles
                .iter()
                .find(|profile| profile.id == "p3")
                .unwrap()
                .failure
                .as_deref(),
            Some(CONTENT_ERROR)
        );
        assert_eq!(kernel.calls, calls);
    }

    #[test]
    fn saved_override_is_not_applied_until_enable() {
        let dir = temp_dir("draft");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = FakeKernel {
            running: None,
            fail: false,
            calls: 0,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let saved = book.save_override("p1", "mixed-port: 8010\n");
        assert_eq!(saved.mixed_port, Some(7890));
        assert_eq!(saved.profiles[0].override_text, "mixed-port: 8010\n");
        assert_eq!(kernel.calls, 1);
        assert_eq!(port_of(kernel.running.as_deref().unwrap()), 7890);
    }

    #[test]
    fn missing_kernel_binary_fails_enable_without_opening_takeover() {
        let dir = temp_dir("runtime");
        let mut runtime = ProcessRuntime::new(&dir.0);
        let error = runtime.start_or_reload("mixed-port: 1\n").unwrap_err();
        assert_eq!(error, MISSING_KERNEL);
        runtime.set_kernel_path(Some(dir.0.join("missing-core")));
        assert_eq!(
            runtime.start_or_reload("mixed-port: 1\n").unwrap_err(),
            MISSING_KERNEL
        );

        #[cfg(unix)]
        {
            runtime.set_kernel_path(Some(PathBuf::from("/usr/bin/yes")));
            runtime.start_or_reload(&config(7890)).unwrap();
            runtime.set_kernel_path(Some(PathBuf::from("/usr/bin/false")));
            assert_eq!(
                runtime.start_or_reload(&config(1)).unwrap_err(),
                KERNEL_ERROR
            );
            runtime.stop();
        }
    }

    #[test]
    fn deep_link_scheme_is_billow_only() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(
            config["plugins"]["deep-link"]["desktop"]["schemes"],
            serde_json::json!(["billow"])
        );
        assert_eq!(
            config["plugins"]["deep-link"]["mobile"][0]["scheme"],
            serde_json::json!(["billow"])
        );
        assert!(
            !include_str!("../tauri.conf.json")
                .to_ascii_lowercase()
                .contains("clash")
        );
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>();
        for permission in [
            "allow-profile-state",
            "allow-add-subscription-profile",
            "allow-add-local-profile",
            "allow-stage-install-link",
            "allow-confirm-install-link",
            "allow-cancel-install-link",
            "allow-enable-profile",
            "allow-update-profile",
            "allow-save-profile-override",
        ] {
            assert!(permissions.contains(&permission), "{permission}");
        }
    }

    struct NodeKernel {
        report_running: bool,
        yaml: Option<String>,
        calls: u32,
        applied: Vec<(String, String)>,
        delay_calls: u32,
        scripts: HashMap<String, Vec<NodeDelay>>,
        auto: BTreeMap<String, String>,
        reject_select: bool,
    }

    impl KernelLaunch for NodeKernel {
        fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
            self.calls += 1;
            self.yaml = Some(config_yaml.to_string());
            self.report_running = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.report_running
        }

        fn select_proxy(&mut self, group: &str, node: &str) -> Result<(), String> {
            if !self.report_running || self.reject_select {
                return Err("节点没有切换".to_string());
            }
            self.applied.push((group.to_string(), node.to_string()));
            Ok(())
        }

        fn probe_delays(
            &mut self,
            group: &str,
            nodes: &[String],
        ) -> Result<Vec<NodeDelay>, String> {
            self.delay_calls += 1;
            if !self.report_running {
                return Err(KERNEL_DOWN.to_string());
            }
            Ok(self
                .scripts
                .get(group)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|item| nodes.iter().any(|name| name == &item.name))
                .collect())
        }

        fn auto_now(&mut self) -> BTreeMap<String, String> {
            if self.report_running {
                self.auto.clone()
            } else {
                BTreeMap::new()
            }
        }
    }

    fn node_kernel() -> NodeKernel {
        NodeKernel {
            report_running: false,
            yaml: None,
            calls: 0,
            applied: Vec::new(),
            delay_calls: 0,
            scripts: HashMap::new(),
            auto: BTreeMap::new(),
            reject_select: false,
        }
    }

    fn grouped_config() -> String {
        r#"mixed-port: 7890
mode: rule
proxies:
  - name: z-node
    type: ss
    server: 127.0.0.1
    port: 1
  - name: m-node
    type: ss
    server: 127.0.0.1
    port: 2
  - name: a-node
    type: ss
    server: 127.0.0.1
    port: 3
proxy-groups:
  - name: manual
    type: select
    icon: https://icons.example.com/manual.png
    proxies:
      - z-node
      - m-node
      - a-node
  - name: auto
    type: url-test
    icon: file:///tmp/local.png
    proxies:
      - z-node
      - m-node
      - a-node
"#
        .to_string()
    }

    fn group<'a>(
        groups: &'a [crate::nodes::NodeGroupView],
        name: &str,
    ) -> &'a crate::nodes::NodeGroupView {
        groups.iter().find(|group| group.name == name).unwrap()
    }

    fn node_names(group: &crate::nodes::NodeGroupView) -> Vec<&str> {
        group.nodes.iter().map(|node| node.name.as_str()).collect()
    }

    fn proxies_of(yaml: &str, name: &str) -> Vec<String> {
        let value: Value = serde_yaml::from_str(yaml).unwrap();
        crate::nodes::parse_proxy_groups(&value)
            .into_iter()
            .find(|group| group.name == name)
            .unwrap()
            .proxies
    }

    #[test]
    fn saved_config_lists_groups_while_kernel_is_stopped_and_keeps_manual_choice() {
        let dir = temp_dir("nodes-saved");
        let mut book = ProfileBook::open(&dir.0);
        assert_eq!(book.snapshot().nodes_notice.as_deref(), Some(NEED_PROFILE));
        book.add_subscription("https://example.com/sub");
        let mut kernel = node_kernel();
        let missing = book.select_node("manual", "a-node", &mut kernel);
        assert_eq!(missing.nodes_error.as_deref(), Some(NEED_PROFILE));
        assert!(missing.node_groups.is_empty());
        assert!(kernel.applied.is_empty());

        book.add_local("nodes.yaml", &grouped_config());
        book.sync_runtime(&mut kernel);
        let listed = book.snapshot();
        assert!(listed.nodes_notice.is_none());
        assert!(!listed.kernel_running);
        assert_eq!(listed.nodes_profile_id.as_deref(), Some("p2"));
        assert_eq!(
            node_names(group(&listed.node_catalog, "manual")),
            ["z-node", "m-node", "a-node"]
        );
        assert!(group(&listed.node_catalog, "manual").nodes[0].selected);
        // Auto groups list their members for viewing; none is marked while the kernel is down.
        assert!(group(&listed.node_catalog, "auto").nodes.iter().all(|node| !node.selected));
        assert_eq!(group(&listed.node_catalog, "auto").kind, "auto");
        assert_eq!(
            group(&listed.node_catalog, "manual").icon.as_deref(),
            Some("https://icons.example.com/manual.png")
        );
        assert!(
            group(&listed.node_catalog, "auto").icon.is_none(),
            "a local file icon is not passed through"
        );
        assert_eq!(kernel.delay_calls, 0);
        assert!(listed.node_catalog.iter().all(|item| {
            item.nodes
                .iter()
                .all(|node| node.delay_ms.is_none() && !node.failed)
        }));

        let chosen = book.select_node("manual", "a-node", &mut kernel);
        assert!(chosen.nodes_error.is_none());
        assert!(kernel.applied.is_empty());
        assert_eq!(kernel.calls, 0);
        let manual = group(&chosen.node_groups, "manual");
        assert!(
            manual
                .nodes
                .iter()
                .any(|node| node.name == "a-node" && node.selected)
        );
        assert!(
            !manual
                .nodes
                .iter()
                .any(|node| node.name == "z-node" && node.selected)
        );
        assert_eq!(manual.now, "a-node");

        let rejected = book.select_node("auto", "m-node", &mut kernel);
        assert_eq!(rejected.nodes_error.as_deref(), Some(NOT_MANUAL));
        assert!(kernel.applied.is_empty());
        let reopened = ProfileBook::open(&dir.0);
        let stored = fs::read_to_string(dir.0.join("profiles.json")).unwrap();
        assert!(stored.contains("\"manual\""));
        assert!(stored.contains("a-node"));
        assert!(!stored.contains("\"auto\""));
        let reopened_view = reopened.snapshot();
        let manual = group(&reopened_view.node_catalog, "manual");
        assert!(
            manual
                .nodes
                .iter()
                .any(|node| node.name == "a-node" && node.selected)
        );
        assert!(
            reopened_view
                .node_groups
                .iter()
                .all(|item| { item.nodes.iter().all(|node| node.delay_ms.is_none()) })
        );
    }

    #[test]
    fn next_successful_connect_applies_the_saved_manual_choice() {
        let dir = temp_dir("nodes-connect");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("nodes.yaml", &grouped_config());
        let mut kernel = node_kernel();
        book.select_node("manual", "a-node", &mut kernel);
        assert!(kernel.applied.is_empty());
        book.enable("p1", &RejectSource, &mut kernel);
        assert_eq!(
            kernel.applied,
            [("manual".to_string(), "a-node".to_string())]
        );
        assert_eq!(
            proxies_of(kernel.yaml.as_deref().unwrap(), "manual")[0],
            "a-node"
        );
        assert_eq!(
            proxies_of(kernel.yaml.as_deref().unwrap(), "auto"),
            ["z-node", "m-node", "a-node"]
        );
        assert!(kernel.yaml.as_deref().unwrap().contains("127.0.0.1:"));

        kernel.report_running = false;
        kernel.applied.clear();
        let marked = book.select_node("manual", "m-node", &mut kernel);
        assert!(kernel.applied.is_empty());
        assert_eq!(group(&marked.node_groups, "manual").now, "m-node");
        kernel.reject_select = false;
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected);
        assert_eq!(
            kernel.applied,
            [("manual".to_string(), "m-node".to_string())]
        );
        assert_eq!(
            proxies_of(kernel.yaml.as_deref().unwrap(), "manual")[0],
            "m-node"
        );
        assert_eq!(
            proxy.http.as_ref().map(|endpoint| endpoint.host.as_str()),
            Some("127.0.0.1")
        );
        assert!(!tun.enabled && !vpn.open);

        kernel.report_running = true;
        kernel.reject_select = true;
        let kept = book.select_node("manual", "z-node", &mut kernel);
        assert_eq!(kept.nodes_error.as_deref(), Some("节点没有切换"));
        assert_eq!(group(&kept.node_groups, "manual").now, "m-node");
        kernel.auto.insert("auto".to_string(), "z-node".to_string());
        book.sync_runtime(&mut kernel);
        let current = book.snapshot();
        let auto = group(&current.node_groups, "auto");
        assert_eq!(auto.now, "z-node");
        assert!(auto.nodes.iter().any(|node| node.name == "z-node" && node.selected));
    }

    #[test]
    fn delay_results_arrive_only_after_an_explicit_test_and_a_failure_stays_local() {
        let dir = temp_dir("nodes-delay");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("nodes.yaml", &grouped_config());
        let mut kernel = node_kernel();
        book.sync_runtime(&mut kernel);
        assert_eq!(book.snapshot().nodes_notice, None);
        assert_eq!(kernel.delay_calls, 0);

        let idle = book.test_group("manual", &mut kernel);
        assert_eq!(idle.nodes_error.as_deref(), Some(KERNEL_DOWN));
        assert_eq!(kernel.delay_calls, 0);
        assert!(
            group(&idle.node_catalog, "manual")
                .nodes
                .iter()
                .all(|node| node.delay_ms.is_none() && !node.failed)
        );

        kernel.report_running = true;
        kernel.scripts.insert(
            "manual".to_string(),
            vec![
                NodeDelay {
                    name: "z-node".to_string(),
                    delay_ms: Some(20),
                },
                NodeDelay {
                    name: "m-node".to_string(),
                    delay_ms: None,
                },
                NodeDelay {
                    name: "a-node".to_string(),
                    delay_ms: Some(5),
                },
            ],
        );
        let tested = book.test_group("manual", &mut kernel);
        assert!(tested.nodes_error.is_none());
        assert_eq!(kernel.delay_calls, 1);
        let manual = group(&tested.node_groups, "manual");
        assert_eq!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "z-node")
                .unwrap()
                .delay_ms,
            Some(20)
        );
        assert!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "m-node")
                .unwrap()
                .failed
        );
        assert_eq!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "a-node")
                .unwrap()
                .delay_ms,
            Some(5)
        );

        kernel.scripts.insert(
            "manual".to_string(),
            vec![NodeDelay {
                name: "z-node".to_string(),
                delay_ms: None,
            }],
        );
        let partial = book.test_group("manual", &mut kernel);
        let manual = group(&partial.node_groups, "manual");
        assert!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "z-node")
                .unwrap()
                .failed
        );
        assert_eq!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "z-node")
                .unwrap()
                .delay_ms,
            None
        );
        assert!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "m-node")
                .unwrap()
                .failed
        );
        assert_eq!(
            manual
                .nodes
                .iter()
                .find(|node| node.name == "a-node")
                .unwrap()
                .delay_ms,
            Some(5)
        );
        assert!(
            !manual
                .nodes
                .iter()
                .find(|node| node.name == "a-node")
                .unwrap()
                .failed
        );

        let by_delay = book.set_node_sort("manual", "delay");
        assert_eq!(
            node_names(group(&by_delay.node_groups, "manual")),
            ["a-node", "z-node", "m-node"]
        );
        let by_name = book.set_node_sort("manual", "name");
        assert_eq!(
            node_names(group(&by_name.node_groups, "manual")),
            ["a-node", "m-node", "z-node"]
        );
        let original = book.set_node_sort("manual", "default");
        assert_eq!(
            node_names(group(&original.node_groups, "manual")),
            ["z-node", "m-node", "a-node"]
        );
        assert!(
            group(&original.node_groups, "manual")
                .nodes
                .iter()
                .find(|node| node.name == "a-node")
                .unwrap()
                .delay_ms
                == Some(5)
        );
    }

    #[test]
    fn name_filter_hides_rows_without_clearing_the_saved_profile() {
        let dir = temp_dir("nodes-filter");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("plain.yaml", "mixed-port: 7890\nmode: rule\n");
        assert_eq!(book.snapshot().nodes_notice.as_deref(), Some(NO_NODES));
        book.add_local("nodes.yaml", &grouped_config());
        let mut kernel = node_kernel();
        book.select_node("manual", "a-node", &mut kernel);
        let path = dir.0.join("profiles.json");
        let before = fs::read(&path).unwrap();
        let missed = book.set_node_query("missing-node");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(missed.nodes_notice.as_deref(), Some(NO_MATCH));
        assert!(missed.node_groups.is_empty());
        assert_eq!(missed.node_catalog.len(), 2);
        assert_eq!(
            node_names(group(&missed.node_catalog, "manual")),
            ["z-node", "m-node", "a-node"]
        );
        let matched = book.set_node_query("a-n");
        assert_eq!(
            node_names(group(&matched.node_groups, "manual")),
            ["a-node"]
        );
        assert!(group(&matched.node_catalog, "manual").nodes.len() == 3);
        let restored = book.set_node_query("  ");
        assert!(restored.nodes_notice.is_none());
        assert_eq!(node_names(group(&restored.node_groups, "manual")).len(), 3);
        assert_eq!(fs::read(&path).unwrap(), before);
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"].as_array().unwrap();
        for permission in [
            "allow-select-profile-node",
            "allow-test-profile-group",
            "allow-set-node-query",
            "allow-set-node-sort",
        ] {
            assert!(
                permissions
                    .iter()
                    .any(|item| item.as_str() == Some(permission)),
                "{permission}"
            );
        }
    }

    struct TrafficKernel {
        running: bool,
        fail: bool,
        connections: Vec<ConnectionView>,
        logs: Vec<LogView>,
    }

    impl KernelLaunch for TrafficKernel {
        fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
            if self.fail {
                self.running = false;
                return Err(KERNEL_ERROR.to_string());
            }
            self.running = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.running
        }

        fn connections(&mut self) -> Vec<ConnectionView> {
            if self.running {
                self.connections.clone()
            } else {
                Vec::new()
            }
        }

        fn pull_logs(&mut self) -> Vec<LogView> {
            if self.running {
                std::mem::take(&mut self.logs)
            } else {
                Vec::new()
            }
        }
    }

    #[test]
    fn injected_connections_filter_by_host_and_disappear_when_the_kernel_stops() {
        let dir = temp_dir("traffic");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = TrafficKernel {
            running: false,
            fail: false,
            connections: vec![
                ConnectionView {
                    host: "Example.COM".to_string(),
                    outbound: "香港节点".to_string(),
    ..Default::default()
},
                ConnectionView {
                    host: "other.test".to_string(),
                    outbound: "直连".to_string(),
    ..Default::default()
},
            ],
            logs: vec![
                LogView {
                    level: "info".to_string(),
                    message: "普通记录".to_string(),
    ..Default::default()
},
                LogView {
                    level: "warning".to_string(),
                    message: "注意一下".to_string(),
    ..Default::default()
},
            ],
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let live = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(live.connected);
        assert!(!live.tun);
        assert_eq!(live.connections.len(), 2);
        assert_eq!(
            proxy.http.as_ref().map(|endpoint| endpoint.host.as_str()),
            Some("127.0.0.1")
        );
        let filtered = book.set_connection_query("example", &mut kernel);
        assert_eq!(filtered.connections.len(), 1);
        assert_eq!(filtered.connections[0].host, "Example.COM");
        assert_eq!(filtered.connections[0].outbound, "香港节点");
        let encoded = serde_json::to_value(&filtered.connections[0]).unwrap();
        assert_eq!(encoded["host"], "Example.COM");
        assert!(
            book.set_connection_query("直连", &mut kernel)
                .connections
                .is_empty()
        );
        let warned = book.set_log_filter("warning", &mut kernel);
        assert_eq!(warned.logs.len(), 1);
        assert_eq!(warned.logs[0].message, "注意一下");

        kernel.running = false;
        book.sync_runtime(&mut kernel);
        let stopped = book.snapshot();
        assert!(stopped.connections.is_empty());
        assert!(!stopped.connected);
        assert!(!stopped.kernel_running);

        kernel.running = true;
        kernel.connections.push(ConnectionView {
            host: "example.com".to_string(),
            outbound: "香港节点".to_string(),
    ..Default::default()
});
        let disconnected = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!disconnected.connected);
        assert!(disconnected.connections.is_empty());
        assert!(
            disconnected
                .logs
                .iter()
                .any(|line| line.message == "注意一下")
        );
    }

    struct StatusKernel {
        running: bool,
        memory: Option<u64>,
        uptime: Option<u64>,
        total: usize,
        error: Option<String>,
        connections: Vec<ConnectionView>,
    }

    impl KernelLaunch for StatusKernel {
        fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
            self.running = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.running
        }

        fn connections(&mut self) -> Vec<ConnectionView> {
            self.connections.clone()
        }

        fn connection_total(&mut self) -> Option<usize> {
            Some(self.total)
        }

        fn connections_error(&mut self) -> Option<String> {
            self.error.clone()
        }

        fn kernel_memory(&mut self) -> Option<u64> {
            self.memory
        }

        fn kernel_uptime_secs(&mut self) -> Option<u64> {
            self.uptime
        }
    }

    #[test]
    fn snapshot_reports_kernel_memory_uptime_connection_count_and_read_errors() {
        let dir = temp_dir("status");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = StatusKernel {
            running: false,
            memory: None,
            uptime: None,
            total: 0,
            error: None,
            connections: Vec::new(),
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let idle = book.snapshot();
        assert!(idle.kernel_running);
        assert!(idle.kernel_memory.is_none());
        assert!(idle.kernel_uptime_secs.is_none());
        assert_eq!(idle.connection_total, 0);
        assert!(idle.connections_error.is_none());

        kernel.memory = Some(128 * 1024 * 1024);
        kernel.uptime = Some(90);
        kernel.total = 620;
        kernel.connections = vec![ConnectionView {
            host: "example.com".to_string(),
            outbound: "香港节点".to_string(),
            ..Default::default()
        }];
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let live = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert_eq!(live.kernel_memory, Some(128 * 1024 * 1024));
        assert_eq!(live.kernel_uptime_secs, Some(90));
        assert_eq!(live.connection_total, 620, "the count keeps the rows the view drops");
        assert_eq!(live.connections.len(), 1);
        assert!(live.connections_error.is_none());

        kernel.error = Some("连接没有读取".to_string());
        kernel.total = 0;
        kernel.connections.clear();
        kernel.memory = None;
        book.sync_runtime(&mut kernel);
        let failed = book.snapshot();
        assert!(failed.connections.is_empty());
        assert_eq!(failed.connection_total, 0);
        assert_eq!(failed.connections_error.as_deref(), Some("连接没有读取"));
        assert!(failed.kernel_memory.is_none());
        assert_eq!(failed.kernel_uptime_secs, Some(90));

        kernel.running = false;
        book.sync_runtime(&mut kernel);
        let stopped = book.snapshot();
        assert!(stopped.kernel_memory.is_none());
        assert!(stopped.kernel_uptime_secs.is_none());
        assert_eq!(stopped.connection_total, 0);
        assert!(stopped.connections_error.is_none());
    }

    #[test]
    fn a_start_failure_is_kept_in_the_log_and_level_filters_do_not_drop_it() {
        let dir = temp_dir("start-log");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = TrafficKernel {
            running: false,
            fail: true,
            connections: vec![ConnectionView {
                host: "stale.example".to_string(),
                outbound: "旧出站".to_string(),
    ..Default::default()
}],
            logs: Vec::new(),
        };
        let failed = book.enable("p1", &RejectSource, &mut kernel);
        assert!(failed.active_id.is_none());
        assert!(!failed.connected);
        assert!(!failed.system_proxy && !failed.tun && !failed.vpn);
        assert!(failed.connections.is_empty());
        assert!(
            failed
                .logs
                .iter()
                .any(|line| { line.level == "error" && line.message.contains(KERNEL_ERROR) })
        );
        kernel.fail = false;
        kernel.running = true;
        kernel.logs.push(LogView {
            level: "info".to_string(),
            message: "普通记录".to_string(),
    ..Default::default()
});
        book.sync_runtime(&mut kernel);
        let info = book.set_log_filter("info", &mut kernel);
        assert!(info.logs.iter().all(|line| line.level == "info"));
        assert!(info.logs.iter().any(|line| line.message == "普通记录"));
        let errors = book.set_log_filter("error", &mut kernel);
        assert!(
            errors
                .logs
                .iter()
                .any(|line| line.message.contains(KERNEL_ERROR))
        );
        assert!(errors.logs.iter().all(|line| line.level == "error"));
        assert!(!book.snapshot().connected);
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"].as_array().unwrap();
        for permission in ["allow-set-connection-query", "allow-set-log-filter"] {
            assert!(
                permissions
                    .iter()
                    .any(|item| item.as_str() == Some(permission)),
                "{permission}"
            );
        }
    }

    struct ReplacingKernel {
        running: bool,
        stay_up: bool,
        rows: Vec<ConnectionView>,
        pending_logs: Vec<LogView>,
    }

    impl KernelLaunch for ReplacingKernel {
        fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
            self.rows.clear();
            self.pending_logs.clear();
            self.running = self.stay_up;
            if self.stay_up {
                Ok(())
            } else {
                Err(KERNEL_ERROR.to_string())
            }
        }

        fn running(&mut self) -> bool {
            self.running
        }

        fn connections(&mut self) -> Vec<ConnectionView> {
            if self.running {
                self.rows.clone()
            } else {
                Vec::new()
            }
        }

        fn pull_logs(&mut self) -> Vec<LogView> {
            std::mem::take(&mut self.pending_logs)
        }
    }

    #[test]
    fn closing_tun_drops_the_replaced_kernels_connections_and_a_later_sample_sees_new_traffic() {
        let dir = temp_dir("tun-replace");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = ReplacingKernel {
            running: false,
            stay_up: true,
            rows: Vec::new(),
            pending_logs: Vec::new(),
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected && connected.system_proxy && !connected.tun);
        let enabled = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(enabled.tun && enabled.connected);

        kernel.rows.push(ConnectionView {
            host: "example.com".to_string(),
            outbound: "香港节点".to_string(),
    ..Default::default()
});
        let opened = book.set_log_filter("all", &mut kernel);
        assert_eq!(opened.connections.len(), 1);
        assert_eq!(opened.connections[0].host, "example.com");

        kernel.stay_up = false;
        let closed = book.set_tun(false, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!closed.tun);
        assert!(!closed.connected);
        assert!(closed.connections.is_empty());

        kernel.stay_up = true;
        let again = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(again.connected);
        kernel.rows.push(ConnectionView {
            host: "fresh.example".to_string(),
            outbound: "日本节点".to_string(),
    ..Default::default()
});
        kernel.pending_logs.push(LogView {
            level: "info".to_string(),
            message: "新的流量".to_string(),
    ..Default::default()
});
        let sampled = book.set_log_filter("info", &mut kernel);
        assert!(
            sampled
                .connections
                .iter()
                .any(|row| row.host == "fresh.example")
        );
        assert!(sampled.logs.iter().any(|line| line.message == "新的流量"));

        kernel.running = false;
        let exited = book.set_log_filter("all", &mut kernel);
        assert!(!exited.connected);
        assert!(exited.connections.is_empty());
        assert!(!exited.kernel_running);
    }

    #[test]
    fn closing_tun_after_a_sampled_exit_stays_disconnected_while_the_proxy_switch_stays_on() {
        let dir = temp_dir("tun-after-sample");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", &config(7890));
        let mut kernel = ReplacingKernel {
            running: false,
            stay_up: true,
            rows: Vec::new(),
            pending_logs: Vec::new(),
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected && connected.system_proxy);
        let enabled = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(enabled.tun && enabled.connected && enabled.kernel_running);
        kernel.rows.push(ConnectionView {
            host: "stale.example".to_string(),
            outbound: "香港节点".to_string(),
    ..Default::default()
});
        let live = book.set_log_filter("all", &mut kernel);
        assert_eq!(live.connections.len(), 1);

        kernel.running = false;
        book.sync_runtime(&mut kernel);
        let sampled = book.snapshot();
        assert!(!sampled.kernel_running);
        assert!(sampled.system_proxy);
        assert!(!sampled.connected);
        assert!(sampled.connections.is_empty());

        kernel.stay_up = false;
        let closed = book.set_tun(false, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!kernel.running);
        assert!(!closed.connected);
        assert!(!closed.kernel_running);
        assert!(closed.connections.is_empty());
        assert!(closed.system_proxy);
        assert!(!closed.tun);
        assert_eq!(
            proxy.http.as_ref().map(|endpoint| endpoint.port),
            Some(7890)
        );
    }

    struct ModeKernel {
        fail_mode: bool,
        alive: bool,
        last: String,
        up: u64,
        down: u64,
    }

    impl KernelLaunch for ModeKernel {
        fn start_or_reload(&mut self, config_yaml: &str) -> Result<(), String> {
            self.last = config_yaml.to_string();
            self.alive = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.alive
        }

        fn set_mode(&mut self, _mode: &str) -> Result<(), String> {
            if self.fail_mode {
                Err("模式没有切换".to_string())
            } else {
                Ok(())
            }
        }

        fn traffic(&mut self) -> Option<(u64, u64)> {
            Some((self.up, self.down))
        }
    }

    fn yaml_mode(yaml: &str) -> Option<String> {
        let value: Value = serde_yaml::from_str(yaml).ok()?;
        value
            .get("mode")
            .and_then(|item| item.as_str())
            .map(str::to_string)
    }

    #[test]
    fn direct_mode_keeps_the_system_proxy_and_a_failed_switch_keeps_the_mode() {
        let dir = temp_dir("mode");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = ModeKernel {
            fail_mode: false,
            alive: false,
            last: String::new(),
            up: 11,
            down: 22,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.system_proxy);
        assert!(!connected.tun);
        assert!(!connected.vpn);
        assert_eq!(connected.mode.as_deref(), Some("rule"));
        assert_eq!(connected.upload, Some(11));
        assert_eq!(connected.download, Some(22));
        assert_eq!(
            proxy.http.as_ref().map(|endpoint| endpoint.port),
            Some(7890)
        );
        let sets = proxy.sets;

        let switched = book.set_outbound_mode("direct", &mut kernel);
        assert_eq!(switched.mode.as_deref(), Some("direct"));
        assert!(switched.failure.is_none());
        assert!(switched.system_proxy);
        assert!(!switched.tun);
        assert_eq!(proxy.sets, sets);
        assert_eq!(
            proxy.http.as_ref().map(|endpoint| endpoint.port),
            Some(7890)
        );

        let again = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert_eq!(yaml_mode(&kernel.last).as_deref(), Some("direct"));
        assert!(again.system_proxy);
        assert!(!again.tun);
        let sets_after = proxy.sets;

        kernel.fail_mode = true;
        let failed = book.set_outbound_mode("global", &mut kernel);
        assert_eq!(failed.mode.as_deref(), Some("direct"));
        assert_eq!(failed.failure.as_deref(), Some("模式没有切换"));
        assert!(failed.system_proxy);
        assert_eq!(proxy.sets, sets_after);

        let disconnected = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!disconnected.system_proxy && !disconnected.tun && !disconnected.vpn);
        assert!(disconnected.upload.is_none() && disconnected.download.is_none());
    }

    struct SampleKernel {
        alive: bool,
        sample: Option<(u64, u64)>,
    }

    impl KernelLaunch for SampleKernel {
        fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
            self.alive = true;
            Ok(())
        }

        fn running(&mut self) -> bool {
            self.alive
        }

        fn traffic(&mut self) -> Option<(u64, u64)> {
            self.sample
        }
    }

    #[test]
    fn connected_rates_follow_samples_and_a_missing_sample_is_not_stuck_at_zero() {
        let dir = temp_dir("rates");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = SampleKernel {
            alive: false,
            sample: None,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected);
        assert!(connected.upload.is_none() && connected.download.is_none());

        kernel.sample = Some((7, 8));
        book.sync_runtime(&mut kernel);
        let sampled = book.snapshot();
        assert_eq!(sampled.upload, Some(7));
        assert_eq!(sampled.download, Some(8));

        kernel.sample = None;
        book.sync_runtime(&mut kernel);
        let held = book.snapshot();
        assert_eq!(held.upload, Some(7));
        assert_eq!(held.download, Some(8));

        kernel.sample = Some((1, 2));
        book.sync_runtime(&mut kernel);
        let replaced = book.snapshot();
        assert_eq!(replaced.upload, Some(1));
        assert_eq!(replaced.download, Some(2));

        let disconnected = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!disconnected.connected);
        assert!(disconnected.upload.is_none() && disconnected.download.is_none());
    }

    #[test]
    fn outbound_mode_keeps_the_previous_failure_until_the_next_connect() {
        let dir = temp_dir("mode-keeps-failure");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = ModeKernel {
            fail_mode: false,
            alive: false,
            last: String::new(),
            up: 11,
            down: 22,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected && connected.failure.is_none());
        assert!(connected.system_proxy);
        let sets = proxy.sets;

        kernel.fail_mode = true;
        let denied = book.set_outbound_mode("global", &mut kernel);
        assert_eq!(denied.mode.as_deref(), Some("rule"));
        assert_eq!(denied.failure.as_deref(), Some("模式没有切换"));
        assert_eq!(proxy.sets, sets);
        assert!(denied.system_proxy);

        kernel.fail_mode = false;
        let switched = book.set_outbound_mode("direct", &mut kernel);
        assert_eq!(switched.mode.as_deref(), Some("direct"));
        assert_eq!(switched.failure.as_deref(), Some("模式没有切换"));
        assert!(switched.system_proxy && !switched.tun);
        assert_eq!(proxy.sets, sets);

        kernel.alive = false;
        let recorded = book.set_outbound_mode("global", &mut kernel);
        assert_eq!(recorded.mode.as_deref(), Some("global"));
        assert_eq!(recorded.failure.as_deref(), Some("模式没有切换"));
        assert_eq!(recorded.system_proxy, switched.system_proxy);
        assert_eq!(proxy.sets, sets);

        kernel.alive = true;
        let again = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(again.connected);
        assert!(again.failure.is_none());
        assert!(again.system_proxy);
        assert_eq!(yaml_mode(&kernel.last).as_deref(), Some("global"));
        assert_eq!(
            proxy.http.as_ref().map(|endpoint| endpoint.port),
            Some(7890)
        );
    }

    #[test]
    fn home_failure_survives_disconnect_proxy_close_and_tun_until_connect() {
        let dir = temp_dir("keep-home-failure");
        let mut book = ProfileBook::open(&dir.0);
        book.set_platform(ClientPlatform::Desktop);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\n");
        let mut kernel = ModeKernel {
            fail_mode: false,
            alive: false,
            last: String::new(),
            up: 1,
            down: 2,
        };
        book.enable("p1", &RejectSource, &mut kernel);
        let mut proxy = MemoryProxy::default();
        let mut tun = MemoryTun::default();
        let mut vpn = MemoryVpn::default();
        let connected = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(connected.connected && connected.failure.is_none());

        kernel.fail_mode = true;
        let denied = book.set_outbound_mode("global", &mut kernel);
        assert_eq!(denied.mode.as_deref(), Some("rule"));
        assert_eq!(denied.failure.as_deref(), Some("模式没有切换"));
        assert!(denied.system_proxy && denied.connected);
        kernel.fail_mode = false;

        let closed_proxy =
            book.set_system_proxy(false, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!closed_proxy.system_proxy);
        assert_eq!(closed_proxy.failure.as_deref(), Some("模式没有切换"));

        let opened_tun = book.set_tun(true, &mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(opened_tun.tun);
        assert_eq!(opened_tun.failure.as_deref(), Some("模式没有切换"));

        let disconnected = book.disconnect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(!disconnected.connected);
        assert!(!disconnected.system_proxy && !disconnected.tun && !disconnected.vpn);
        assert_eq!(disconnected.failure.as_deref(), Some("模式没有切换"));

        let again = book.connect(&mut kernel, &mut proxy, &mut tun, &mut vpn);
        assert!(again.connected);
        assert!(again.failure.is_none());
        assert!(again.system_proxy);
    }

    #[cfg(unix)]
    #[test]
    fn process_runtime_reads_injected_controller_traffic_without_touching_system_proxy() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::mpsc;
        use std::thread;

        let dir = temp_dir("runtime-traffic");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        let server = thread::spawn(move || {
            fn accept_for(listener: &std::net::TcpListener) -> std::net::TcpStream {
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => return stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                panic!("controller client did not connect");
                            }
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => panic!("{error}"),
                    }
                }
            }
            fn read_headers(stream: &mut std::net::TcpStream) -> String {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 2048];
                loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(count) => {
                            buf.extend_from_slice(&tmp[..count]);
                            if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                String::from_utf8_lossy(&buf).into_owned()
            }
            fn write_json(stream: &mut std::net::TcpStream, body: &str) {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
            listener.set_nonblocking(true).unwrap();
            let mut first_stream = accept_for(&listener);
            first_stream.set_nonblocking(false).unwrap();
            let first_seen = read_headers(&mut first_stream);
            write_json(&mut first_stream, "{\"up\":4,\"down\":5}");
            drop(first_stream);
            let mut second_stream = accept_for(&listener);
            second_stream.set_nonblocking(false).unwrap();
            let second_seen = read_headers(&mut second_stream);
            let _ = gate_rx.recv_timeout(Duration::from_secs(3));
            write_json(&mut second_stream, "{\"up\":8,\"down\":9}");
            format!("{first_seen}\n{second_seen}")
        });
        let script = dir.0.join("stand-in.sh");
        fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let mut runtime = ProcessRuntime::new(&dir.0);
        runtime.set_kernel_path(Some(script));
        runtime
            .start_or_reload(&format!(
                "mixed-port: 1\nexternal-controller: 127.0.0.1:{port}\nsecret: billow-local\n"
            ))
            .unwrap();
        let first = wait_traffic(&mut runtime, Some((4, 5)));
        assert_eq!(first, Some((4, 5)));
        gate_tx.send(()).unwrap();
        let second = wait_traffic(&mut runtime, Some((8, 9)));
        assert_eq!(second, Some((8, 9)));
        runtime.stop();
        assert!(runtime.traffic().is_none());
        let seen = server.join().unwrap();
        assert!(seen.contains("GET /traffic"), "{seen}");
        assert!(seen.contains("Bearer billow-local"), "{seen}");
        assert!(!seen.contains("networksetup"), "{seen}");
    }

    #[cfg(unix)]
    fn wait_traffic(runtime: &mut ProcessRuntime, want: Option<(u64, u64)>) -> Option<(u64, u64)> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut last = None;
        while Instant::now() < deadline {
            last = runtime.traffic();
            if last == want {
                return last;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        last
    }

    #[test]
    fn rule_toggle_filters_the_runtime_config_and_rolls_back_a_failed_reload() {
        struct RuleKernel {
            running: bool,
            reloaded: Vec<String>,
            fail: bool,
        }

        impl KernelLaunch for RuleKernel {
            fn start_or_reload(&mut self, _config_yaml: &str) -> Result<(), String> {
                self.running = true;
                Ok(())
            }

            fn running(&mut self) -> bool {
                self.running
            }

            fn reload_config(&mut self, config_yaml: &str) -> Result<(), String> {
                if self.fail {
                    return Err("规则没有切换".to_string());
                }
                self.reloaded.push(config_yaml.to_string());
                Ok(())
            }
        }

        let dir = temp_dir("rule-toggle");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local(
            "rules.yaml",
            "mixed-port: 7890\nmode: rule\nproxies: []\nrules:\n  - DOMAIN-SUFFIX,google.com,PROXY\n  - DOMAIN-SUFFIX,google.com,PROXY\n  - MATCH,DIRECT\n",
        );
        let mut kernel = RuleKernel {
            running: false,
            reloaded: Vec::new(),
            fail: false,
        };
        book.enable("p1", &RejectSource, &mut kernel);

        let disabled_key = diagnostics::rule_key("DomainSuffix", "google.com", "PROXY", 0);
        let second_key = diagnostics::rule_key("DomainSuffix", "google.com", "PROXY", 1);
        let other = diagnostics::rule_key("Match", "", "DIRECT", 0);

        // An unknown identity is rejected without changing the set.
        let unknown = book
            .set_rule_disabled(
                RuleToggle {
                    key: "domainsuffix|missing.example|PROXY|0".to_string(),
                    disabled: true,
                },
                &mut kernel,
            )
            .unwrap_err();
        assert_eq!(unknown, "没有这条规则");
        assert!(book.rules(&mut kernel).disabled.is_empty());
        assert!(kernel.reloaded.is_empty());

        let snapshot = book
            .set_rule_disabled(
                RuleToggle {
                    key: disabled_key.clone(),
                    disabled: true,
                },
                &mut kernel,
            )
            .unwrap();
        assert_eq!(snapshot.disabled, vec![disabled_key.clone()]);
        assert_eq!(kernel.reloaded.len(), 1);
        assert_eq!(
            kernel.reloaded[0].matches("google.com,PROXY").count(),
            1,
            "one of two identical rules is hidden"
        );
        assert!(kernel.reloaded[0].contains("MATCH,DIRECT"));

        // The second identical rule keeps its own identity even though the kernel
        // now only returns the remaining occurrence.
        let both = book
            .set_rule_disabled(
                RuleToggle {
                    key: second_key.clone(),
                    disabled: true,
                },
                &mut kernel,
            )
            .unwrap();
        assert_eq!(both.disabled, vec![disabled_key.clone(), second_key.clone()]);
        assert_eq!(kernel.reloaded.len(), 2);
        assert_eq!(
            kernel.reloaded[1].matches("google.com,PROXY").count(),
            0,
            "the second occurrence is removed from the full config, not the filtered one"
        );

        let first_back = book
            .set_rule_disabled(
                RuleToggle {
                    key: disabled_key.clone(),
                    disabled: false,
                },
                &mut kernel,
            )
            .unwrap();
        assert_eq!(first_back.disabled, vec![second_key.clone()]);
        assert_eq!(
            kernel.reloaded[2].matches("google.com,PROXY").count(),
            1,
            "re-enabling the first occurrence restores exactly one"
        );

        kernel.fail = true;
        let error = book
            .set_rule_disabled(
                RuleToggle {
                    key: other.clone(),
                    disabled: true,
                },
                &mut kernel,
            )
            .unwrap_err();
        assert_eq!(error, "规则没有切换");
        let after_failure = book.rules(&mut kernel);
        assert_eq!(after_failure.disabled, vec![second_key.clone()]);
        assert!(!after_failure.disabled.contains(&other));
        assert_eq!(kernel.reloaded.len(), 3, "a failed reload does not push a config");

        kernel.fail = false;
        let enabled = book
            .set_rule_disabled(
                RuleToggle {
                    key: second_key.clone(),
                    disabled: false,
                },
                &mut kernel,
            )
            .unwrap();
        assert!(enabled.disabled.is_empty());
        assert_eq!(
            kernel.reloaded.last().unwrap().matches("google.com,PROXY").count(),
            2,
            "re-enabling restores every occurrence"
        );

        // Activating a config starts from a clean runtime rule set.
        book.set_rule_disabled(
            RuleToggle {
                key: disabled_key.clone(),
                disabled: true,
            },
            &mut kernel,
        )
        .unwrap();
        book.enable("p1", &RejectSource, &mut kernel);
        assert!(book.rules(&mut kernel).disabled.is_empty());

        // The set lives only in memory, so reopening the app starts with no disabled rules.
        book.set_rule_disabled(
            RuleToggle {
                key: disabled_key.clone(),
                disabled: true,
            },
            &mut kernel,
        )
        .unwrap();
        let mut reopened = ProfileBook::open(&dir.0);
        let mut idle = RuleKernel {
            running: true,
            reloaded: Vec::new(),
            fail: false,
        };
        assert!(reopened.rules(&mut idle).disabled.is_empty());
    }

    #[test]
    fn test_all_reports_each_node_with_tested_and_total() {
        let dir = temp_dir("test-all-progress");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("nodes.yaml", &grouped_config());
        let mut kernel = node_kernel();
        kernel.report_running = true;
        kernel.scripts.insert(
            String::new(),
            vec![
                NodeDelay {
                    name: "z-node".to_string(),
                    delay_ms: Some(20),
                },
                NodeDelay {
                    name: "m-node".to_string(),
                    delay_ms: None,
                },
                NodeDelay {
                    name: "a-node".to_string(),
                    delay_ms: Some(5),
                },
            ],
        );
        let mut events: Vec<(String, Option<u64>, bool, usize, usize)> = Vec::new();
        let snapshot = book.test_all_with_progress(&mut kernel, &mut |node, delay, failed, tested, total| {
            events.push((node.to_string(), delay, failed, tested, total));
        });
        assert!(snapshot.nodes_error.is_none());
        assert_eq!(events.len(), 3);
        assert_eq!(
            events.iter().map(|event| event.3).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert!(events.iter().all(|event| event.4 == 3));
        assert!(events.iter().any(|event| event.0 == "m-node" && event.2 && event.1.is_none()));
        assert!(events.iter().any(|event| event.0 == "a-node" && !event.2 && event.1 == Some(5)));
    }
}
