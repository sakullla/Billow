use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

const BODY_LIMIT: u64 = 2_000_000;
const CONTENT_ERROR: &str = "配置无法应用";
const OVERRIDE_ERROR: &str = "覆写无法应用";
const FETCH_ERROR: &str = "订阅没有取回";
const KERNEL_ERROR: &str = "内核没有启动";
const MISSING_KERNEL: &str = "没有本地内核";
const LINK_ERROR: &str = "不支持这个导入链接";
const ONE_LINK_ERROR: &str = "需要一条订阅链接";
const URL_ERROR: &str = "订阅链接不可用";
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

#[derive(Debug, Clone, PartialEq, Serialize)]
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
}

#[derive(Debug, Clone, PartialEq, Serialize)]
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
}

impl ProcessRuntime {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            kernel_path: None,
            work_dir: work_dir.into(),
            child: None,
            config_path: None,
        }
    }

    pub fn set_kernel_path(&mut self, path: Option<PathBuf>) {
        self.kernel_path = path;
    }

    fn stop(&mut self) {
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
    }
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
        let mut command = Command::new(&path);
        command
            .arg("-f")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
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
        self.stop();
        self.child = Some(child);
        self.config_path = Some(config_path);
        Ok(())
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
    profiles: Vec<DiskProfile>,
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
        };
        book.load();
        book
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
            })
            .collect();
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
        }
    }

    pub fn add_subscription(&mut self, url: &str) -> ProfileSnapshot {
        match validate_subscription_url(url.trim()) {
            Ok(url) => {
                self.push_profile(ProfileKind::Subscription, subscription_name(&url), url, String::new());
                self.input_error = None;
                self.persist();
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
                    return self.snapshot();
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
                return self.snapshot();
            }
            Err(PrepareError::Override) => {
                // Judged before the running config changes, so takeover and the active id stay.
                self.profiles[index].override_error = Some(OVERRIDE_ERROR.to_string());
                self.persist();
                return self.snapshot();
            }
        };
        if let Err(message) = kernel.start_or_reload(&prepared.yaml) {
            let message = if message.is_empty() {
                KERNEL_ERROR.to_string()
            } else {
                message
            };
            self.fail_activation(index, message);
            return self.snapshot();
        }
        let now = now_ms();
        {
            let profile = &mut self.profiles[index];
            if let Some(fetched) = fetched {
                profile.content = fetched.content;
                profile.usage = parse_userinfo(fetched.userinfo.as_deref());
            }
            profile.applied_override = profile.override_text.clone();
            profile.override_error = None;
            profile.failure = None;
            profile.last_success_ms = Some(now);
            self.active_id = Some(profile.id.clone());
        }
        self.mixed_port = prepared.mixed_port;
        self.mode = prepared.mode;
        self.home_failure = None;
        self.input_error = None;
        self.persist();
        self.snapshot()
    }

    fn fail_activation(&mut self, index: usize, message: String) {
        self.profiles[index].failure = Some(message.clone());
        self.home_failure = Some(message);
        self.takeover = Takeover::default();
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
        });
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
                    selected: profile.selected,
                }
            })
            .collect();
        let known = self
            .profiles
            .iter()
            .any(|profile| disk.active_id.as_deref() == Some(profile.id.as_str()));
        self.active_id = if known { disk.active_id } else { None };
        self.next_id = self.next_id.max(
            self.profiles
                .iter()
                .filter_map(|profile| profile.id.strip_prefix('p')?.parse::<u64>().ok())
                .max()
                .unwrap_or(0)
                + 1,
        );
        self.recompute_effective();
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

    #[cfg(test)]
    fn set_takeover(&mut self, system_proxy: bool, tun: bool, vpn: bool) {
        self.takeover = Takeover {
            system_proxy,
            tun,
            vpn,
        };
    }
}

struct Prepared {
    yaml: String,
    mixed_port: Option<i64>,
    mode: Option<String>,
}

enum PrepareError {
    Content,
    Override,
}

fn prepare(content: &str, override_text: &str) -> Result<Prepared, PrepareError> {
    let mut base = parse_config(content).map_err(|_| PrepareError::Content)?;
    if !override_text.trim().is_empty() {
        let overlay = serde_yaml::from_str::<Value>(override_text).map_err(|_| PrepareError::Override)?;
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
    if is_config(&value) { Ok(value) } else { Err(()) }
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
    mapping_get(value, key).and_then(Value::as_str).map(str::to_string)
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
        total.filter(|value| *value > 0).map(|_| upload.unwrap_or(0).saturating_add(download.unwrap_or(0))),
        total.filter(|value| *value > 0),
        expire.filter(|value| *value > 0),
    )
}

fn usage_from_parts(used: Option<u64>, total: Option<u64>, expire: Option<u64>) -> Option<Usage> {
    let total = total.filter(|value| *value > 0);
    let used = if total.is_some() { used.or(Some(0)) } else { None };
    let expire = expire.filter(|value| *value > 0);
    if used.is_none() && total.is_none() && expire.is_none() {
        None
    } else {
        Some(Usage { used, total, expire })
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
    if !host.trim_end_matches('/').eq_ignore_ascii_case("install-config") {
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
    if head.eq_ignore_ascii_case(prefix) { Some(tail) } else { None }
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
    if name.is_empty() { fallback.to_string() } else { name }
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

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(name: &str) -> TempDir {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("billow-profile-{name}-{}-{nanos}", std::process::id()));
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
        assert!(first.profiles.iter().all(|profile| profile.failure.is_none()));

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

        let usage = parse_userinfo(Some(" upload = 10 ; download = 20 ; total = 100 ; expire = 0 ")).unwrap();
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
        let plain = snapshot.profiles.iter().find(|profile| profile.id == "p2").unwrap();
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
        let encoded_profile = snapshot.profiles.iter().find(|profile| profile.id == "p3").unwrap();
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
        assert_eq!(staged.pending_url.as_deref(), Some("https://example.com/sub"));
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
        let rejected = book.stage_install_link("clash://install-config?url=https://example.com/other");
        assert_eq!(rejected.input_error.as_deref(), Some(LINK_ERROR));
        assert_eq!(rejected.profiles.len(), before.profiles.len());
        assert!(rejected.pending_url.is_none());

        let doubled = book.stage_install_link(
            "billow://install-config?url=https://a.example/x&url=https://b.example/y",
        );
        assert_eq!(doubled.input_error.as_deref(), Some(ONE_LINK_ERROR));
        assert_eq!(doubled.profiles.len(), 1);
        assert!(book.stage_install_link("billow://install-config?url=ftp://example.com/a").input_error.is_some());
        assert_eq!(book.snapshot().profiles.len(), 1);

        let manual = book.add_subscription("https://manual.example/a");
        assert_eq!(manual.profiles.len(), 2);
        assert!(manual.profiles.iter().all(|profile| !profile.current));
        let local = book.add_local("home.yaml", &config(1));
        assert_eq!(local.profiles.len(), 3);
        assert_eq!(local.profiles[2].kind, "local");
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
        let failed = snapshot.profiles.iter().find(|profile| profile.id == "p2").unwrap();
        assert_eq!(failed.failure.as_deref(), Some(FETCH_ERROR));
        assert!(!failed.current);
        assert_eq!(kernel.calls, 1);
        assert_eq!(snapshot.mixed_port, Some(7890));
        assert_eq!(snapshot.failure.as_deref(), Some(FETCH_ERROR));

        let again = book.enable("p2", &missing, &mut kernel);
        assert_eq!(
            again.profiles.iter().find(|profile| profile.id == "p2").unwrap().failure.as_deref(),
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
        assert!(recovered.profiles.iter().all(|profile| profile.id != "p2" || profile.failure.is_none()));
    }

    #[test]
    fn unusable_override_does_not_replace_the_active_config() {
        let dir = temp_dir("override");
        let mut book = ProfileBook::open(&dir.0);
        book.add_local("a.yaml", "mixed-port: 7890\nmode: rule\ndns:\n  enable: true\n  listen: 127.0.0.1:53\n");
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
            switched.profiles.iter().find(|profile| profile.id == "p2").unwrap().override_error.as_deref(),
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
            failed.profiles.iter().find(|profile| profile.id == "p2").unwrap().failure.as_deref(),
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
            invalid.profiles.iter().find(|profile| profile.id == "p3").unwrap().failure.as_deref(),
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
        assert_eq!(runtime.start_or_reload("mixed-port: 1\n").unwrap_err(), MISSING_KERNEL);

        #[cfg(unix)]
        {
            runtime.set_kernel_path(Some(PathBuf::from("/usr/bin/yes")));
            runtime.start_or_reload(&config(7890)).unwrap();
            runtime.set_kernel_path(Some(PathBuf::from("/usr/bin/false")));
            assert_eq!(runtime.start_or_reload(&config(1)).unwrap_err(), KERNEL_ERROR);
            runtime.stop();
        }
    }

    #[test]
    fn deep_link_scheme_is_billow_only() {
        let config: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(config["plugins"]["deep-link"]["desktop"]["schemes"], serde_json::json!(["billow"]));
        assert_eq!(
            config["plugins"]["deep-link"]["mobile"][0]["scheme"],
            serde_json::json!(["billow"])
        );
        assert!(!include_str!("../tauri.conf.json").to_ascii_lowercase().contains("clash"));
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
}
