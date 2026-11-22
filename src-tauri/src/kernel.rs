use std::fs;
use std::io::{self, Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

/// Release index for the MetaCubeX mihomo releases page.
pub const RELEASES_PAGE: &str = "https://github.com/MetaCubeX/mihomo/releases";
pub const PREVIEW_TAG: &str = "Prerelease-Alpha";

fn release_api(channel: Channel) -> String {
    let repo = RELEASES_PAGE.trim_end_matches("/releases");
    let api_repo = repo.replacen("https://github.com/", "https://api.github.com/repos/", 1);
    match channel {
        Channel::Stable => format!("{api_repo}/releases/latest"),
        Channel::Preview => format!("{api_repo}/releases/tags/{PREVIEW_TAG}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Stable,
    Preview,
}

impl Default for Channel {
    fn default() -> Self {
        Self::Stable
    }
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Preview => "preview",
        }
    }
}

pub fn parse_channel(value: &str) -> Result<Channel, String> {
    match value {
        "stable" => Ok(Channel::Stable),
        "preview" => Ok(Channel::Preview),
        _ => Err("没有这个内核渠道".to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopOs {
    Darwin,
    Windows,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuArch {
    Amd64,
    Arm64,
    I386,
    Armv7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidAbi {
    Arm64V8a,
    ArmeabiV7a,
    X86,
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformTarget {
    Desktop { os: DesktopOs, arch: CpuArch },
    Android { abi: AndroidAbi },
}

impl PlatformTarget {
    pub fn current() -> Self {
        #[cfg(target_os = "android")]
        {
            PlatformTarget::Android {
                abi: current_android_abi(),
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            PlatformTarget::Desktop {
                os: current_desktop_os(),
                arch: current_cpu_arch(),
            }
        }
    }

    fn asset_prefix(self) -> Option<&'static str> {
        Some(match self {
            Self::Desktop {
                os: DesktopOs::Darwin,
                arch: CpuArch::Arm64,
            } => "mihomo-darwin-arm64-",
            Self::Desktop {
                os: DesktopOs::Darwin,
                arch: CpuArch::Amd64,
            } => "mihomo-darwin-amd64-",
            Self::Desktop {
                os: DesktopOs::Windows,
                arch: CpuArch::Arm64,
            } => "mihomo-windows-arm64-",
            Self::Desktop {
                os: DesktopOs::Windows,
                arch: CpuArch::Amd64,
            } => "mihomo-windows-amd64-",
            Self::Desktop {
                os: DesktopOs::Windows,
                arch: CpuArch::I386,
            } => "mihomo-windows-386-",
            Self::Desktop {
                os: DesktopOs::Linux,
                arch: CpuArch::Amd64,
            } => "mihomo-linux-amd64-",
            Self::Desktop {
                os: DesktopOs::Linux,
                arch: CpuArch::Arm64,
            } => "mihomo-linux-arm64-",
            Self::Desktop {
                os: DesktopOs::Linux,
                arch: CpuArch::I386,
            } => "mihomo-linux-386-",
            Self::Desktop {
                os: DesktopOs::Linux,
                arch: CpuArch::Armv7,
            } => "mihomo-linux-armv7-",
            Self::Android {
                abi: AndroidAbi::Arm64V8a,
            } => "mihomo-android-arm64-v8-",
            Self::Android {
                abi: AndroidAbi::ArmeabiV7a,
            } => "mihomo-android-armv7-",
            Self::Android { abi: AndroidAbi::X86 } => "mihomo-android-386-",
            Self::Android {
                abi: AndroidAbi::X86_64,
            } => "mihomo-android-amd64-",
            _ => return None,
        })
    }

    fn archive_ext(self) -> &'static str {
        match self {
            Self::Desktop {
                os: DesktopOs::Windows,
                ..
            } => "zip",
            _ => "gz",
        }
    }

    fn binary_file_name(self) -> &'static str {
        match self {
            Self::Desktop {
                os: DesktopOs::Windows,
                ..
            } => "core.exe",
            _ => "core",
        }
    }
}

const SUPPORTED_TARGETS: &[PlatformTarget] = &[
    PlatformTarget::Desktop {
        os: DesktopOs::Darwin,
        arch: CpuArch::Arm64,
    },
    PlatformTarget::Desktop {
        os: DesktopOs::Darwin,
        arch: CpuArch::Amd64,
    },
    PlatformTarget::Desktop {
        os: DesktopOs::Windows,
        arch: CpuArch::Arm64,
    },
    PlatformTarget::Desktop {
        os: DesktopOs::Windows,
        arch: CpuArch::Amd64,
    },
    PlatformTarget::Desktop {
        os: DesktopOs::Windows,
        arch: CpuArch::I386,
    },
    PlatformTarget::Desktop {
        os: DesktopOs::Linux,
        arch: CpuArch::Amd64,
    },
    PlatformTarget::Desktop {
        os: DesktopOs::Linux,
        arch: CpuArch::Arm64,
    },
    PlatformTarget::Desktop {
        os: DesktopOs::Linux,
        arch: CpuArch::I386,
    },
    PlatformTarget::Desktop {
        os: DesktopOs::Linux,
        arch: CpuArch::Armv7,
    },
    PlatformTarget::Android {
        abi: AndroidAbi::Arm64V8a,
    },
    PlatformTarget::Android {
        abi: AndroidAbi::ArmeabiV7a,
    },
    PlatformTarget::Android { abi: AndroidAbi::X86 },
    PlatformTarget::Android {
        abi: AndroidAbi::X86_64,
    },
];

#[cfg(target_os = "android")]
fn current_android_abi() -> AndroidAbi {
    #[cfg(target_arch = "aarch64")]
    {
        AndroidAbi::Arm64V8a
    }
    #[cfg(target_arch = "arm")]
    {
        AndroidAbi::ArmeabiV7a
    }
    #[cfg(target_arch = "x86_64")]
    {
        AndroidAbi::X86_64
    }
    #[cfg(target_arch = "x86")]
    {
        AndroidAbi::X86
    }
}

#[cfg(not(target_os = "android"))]
fn current_desktop_os() -> DesktopOs {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        DesktopOs::Darwin
    }
    #[cfg(target_os = "windows")]
    {
        DesktopOs::Windows
    }
    #[cfg(target_os = "linux")]
    {
        DesktopOs::Linux
    }
}

#[cfg(not(target_os = "android"))]
fn current_cpu_arch() -> CpuArch {
    #[cfg(target_arch = "aarch64")]
    {
        CpuArch::Arm64
    }
    #[cfg(target_arch = "x86_64")]
    {
        CpuArch::Amd64
    }
    #[cfg(target_arch = "x86")]
    {
        CpuArch::I386
    }
    #[cfg(target_arch = "arm")]
    {
        CpuArch::Armv7
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAsset {
    pub name: String,
    pub url: String,
    /// GitHub asset digest, such as `sha256:<hex>`. Ignored when checksums.txt exists.
    pub digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseIndex {
    pub tag: String,
    pub prerelease: bool,
    pub assets: Vec<ReleaseAsset>,
}

pub trait ReleaseSource {
    fn fetch_release(&self, channel: Channel) -> Result<ReleaseIndex, String>;
    fn download(&self, url: &str) -> Result<Box<dyn Read>, String>;
}

pub struct GithubReleaseClient {
    agent: ureq::Agent,
}

impl GithubReleaseClient {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(20))
            .timeout_read(Duration::from_secs(120))
            .build();
        Self { agent }
    }
}

impl Default for GithubReleaseClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ReleaseSource for GithubReleaseClient {
    fn fetch_release(&self, channel: Channel) -> Result<ReleaseIndex, String> {
        let url = release_api(channel);
        let mut text = String::new();
        http_get(&self.agent, &url, "application/vnd.github+json")?
            .read_to_string(&mut text).map_err(|_| "发布索引无法读取".to_string())?;
        parse_github_release(&text)
    }

    fn download(&self, url: &str) -> Result<Box<dyn Read>, String> {
        http_get(&self.agent, url, "application/octet-stream")
    }
}

fn http_get(agent: &ureq::Agent, url: &str, accept: &str) -> Result<Box<dyn Read>, String> {
    if !url.starts_with("https://") {
        return Err("内核地址不可用".to_string());
    }
    let response = agent
        .get(url)
        .set("User-Agent", "Billow")
        .set("Accept", accept)
        .call()
        .map_err(|_| "内核下载失败".to_string())?;
    Ok(response.into_reader())
}

fn parse_github_release(body: &str) -> Result<ReleaseIndex, String> {
    let value: serde_json::Value = serde_json::from_str(body).map_err(|_| "发布索引无法读取".to_string())?;
    let tag = value
        .get("tag_name")
        .and_then(|item| item.as_str())
        .unwrap_or("")
        .to_string();
    if tag.is_empty() {
        return Err("发布标签缺失".to_string());
    }
    let prerelease = value.get("prerelease").and_then(|item| item.as_bool()).unwrap_or(false);
    let mut assets = Vec::new();
    for asset in value.get("assets").and_then(|item| item.as_array()).into_iter().flatten() {
        let name = asset.get("name").and_then(|item| item.as_str()).unwrap_or("");
        let url = asset
            .get("browser_download_url")
            .and_then(|item| item.as_str())
            .unwrap_or("");
        if name.is_empty() || url.is_empty() {
            continue;
        }
        let digest = asset
            .get("digest")
            .and_then(|item| item.as_str())
            .filter(|item| !item.is_empty())
            .map(str::to_string);
        assets.push(ReleaseAsset {
            name: name.to_string(),
            url: url.to_string(),
            digest,
        });
    }
    Ok(ReleaseIndex { tag, prerelease, assets })
}

fn validate_release(channel: Channel, release: &ReleaseIndex) -> Result<(), String> {
    match channel {
        Channel::Stable => {
            if release.prerelease || !is_version(&release.tag) {
                return Err("稳定版标签不可用".to_string());
            }
        }
        Channel::Preview => {
            if release.tag != PREVIEW_TAG {
                return Err("预览版标签不可用".to_string());
            }
        }
    }
    Ok(())
}

/// Plain build only. Variant names (`compatible`, `go*`, `v1`/`v2`/`v3`, packages)
/// and the other platform family are left unmatched.
fn is_plain_asset(name: &str, prefix: &str, ext: &str) -> bool {
    let Some(rest) = name.strip_prefix(prefix) else {
        return false;
    };
    let Some(stem) = rest.strip_suffix(&format!(".{ext}")) else {
        return false;
    };
    is_version(stem) || is_alpha(stem)
}

fn is_version(stem: &str) -> bool {
    let Some(digits) = stem.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = digits.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

fn is_alpha(stem: &str) -> bool {
    let Some(hex) = stem.strip_prefix("alpha-") else {
        return false;
    };
    !hex.is_empty() && hex.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub fn select_asset(release: &ReleaseIndex, target: PlatformTarget) -> Result<ReleaseAsset, String> {
    let prefix = target.asset_prefix().ok_or("没有适用于当前系统的内核")?;
    let ext = target.archive_ext();
    let matches: Vec<ReleaseAsset> = release
        .assets
        .iter()
        .filter(|asset| is_plain_asset(&asset.name, prefix, ext))
        .cloned()
        .collect();
    match matches.len() {
        1 => Ok(matches.into_iter().next().unwrap()),
        0 => Err("没有适用于当前系统的内核".to_string()),
        _ => Err("内核产物不唯一".to_string()),
    }
}

fn sha256_from_digest(digest: Option<&str>) -> Option<String> {
    let (algo, hex) = digest?.split_once(':')?;
    if !algo.eq_ignore_ascii_case("sha256") {
        return None;
    }
    if hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Some(hex.to_ascii_lowercase())
    } else {
        None
    }
}

fn lookup_checksum(checksums: &str, asset_name: &str) -> Result<String, String> {
    for line in checksums.lines() {
        let mut parts = line.split_whitespace();
        let Some(hash) = parts.next() else {
            continue;
        };
        let Some(file_name) = parts.next() else {
            continue;
        };
        if parts.next().is_some() {
            continue;
        }
        let file_name = file_name.trim_start_matches("./").trim_start_matches('*');
        let file_name = file_name.rsplit(['/', '\\']).next().unwrap_or(file_name);
        if file_name != asset_name {
            continue;
        }
        if hash.len() == 64 && hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Ok(hash.to_ascii_lowercase());
        }
        return Err("校验和无法读取".to_string());
    }
    Err("校验和里没有这个文件".to_string())
}

#[cfg(test)]
fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn extract_kernel(asset_name: &str, archive: fs::File, output: &mut fs::File) -> Result<u64, String> {
    let decode_error = |_| "内核文件无法解压".to_string();
    if asset_name.ends_with(".gz") {
        return io::copy(&mut GzDecoder::new(archive), output).map_err(decode_error);
    }
    if !asset_name.ends_with(".zip") { return Err("内核文件无法解压".into()); }
    let mut archive = ZipArchive::new(archive).map_err(|_| "内核文件无法解压".to_string())?;
    let count = archive.len();
    let mut chosen: Option<usize> = None;
    for index in 0..count {
        let name = {
            let file = archive
                .by_index(index)
                .map_err(|_| "内核文件无法解压".to_string())?;
            if !file.is_file() {
                continue;
            }
            file.name().replace('\\', "/")
        };
        let base = name.rsplit('/').next().unwrap_or("");
        if base.eq_ignore_ascii_case("mihomo.exe") || base.ends_with(".exe") {
            chosen = Some(index);
            if base.eq_ignore_ascii_case("mihomo.exe") {
                break;
            }
        } else if chosen.is_none() && count == 1 {
            chosen = Some(index);
        }
    }
    let index = chosen.ok_or("内核文件无法解压")?;
    let mut file = archive
        .by_index(index)
        .map_err(|_| "内核文件无法解压".to_string())?;
    io::copy(&mut file, output).map_err(decode_error)
}

/// Hash as bytes arrive, then extract only a verified archive. Both temporary
/// files are on the install volume and are removed on every error path.
fn install_archive(
    mut source: impl Read,
    root: &Path,
    asset: &str,
    expected: &str,
    binary_name: &str,
) -> Result<String, String> {
    let files = root.join("files");
    let io_error = |error: io::Error| error.to_string();
    fs::create_dir_all(&files).map_err(io_error)?;
    let mut archive = tempfile::tempfile_in(&files).map_err(io_error)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 32 * 1024];
    loop {
        let count = match source.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result.map_err(|_| "内核下载失败".to_string())?,
        };
        if count == 0 { break; }
        archive.write_all(&buffer[..count]).map_err(io_error)?;
        hash.update(&buffer[..count]);
    }
    if format!("{:x}", hash.finalize()) != expected {
        return Err("内核校验和不一致".into());
    }
    archive.rewind().map_err(io_error)?;
    let mut image = tempfile::NamedTempFile::new_in(&files).map_err(io_error)?;
    let size = extract_kernel(asset, archive, image.as_file_mut())?;
    if size == 0 { return Err("内核文件无法解压".into()); }

    let mut relative = format!("files/{expected}/{binary_name}");
    let destination = root.join(&relative);
    if destination.exists() {
        // Preserve the mode and identity of a matching (possibly running) image.
        if executable_matches(&destination, image.as_file_mut(), size) { return Ok(relative); }
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        relative = format!("files/{expected}-{}-{nonce}/{binary_name}", std::process::id());
    }
    let destination = root.join(&relative);
    fs::create_dir_all(destination.parent().unwrap()).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        image.as_file().set_permissions(fs::Permissions::from_mode(0o755)).map_err(io_error)?;
    }
    image.persist_noclobber(destination).map_err(|error| error.to_string())?;
    Ok(relative)
}

fn executable_matches(path: &Path, expected: &mut fs::File, size: u64) -> bool {
    let Ok(mut file) = fs::File::open(path) else { return false };
    if !file.metadata().is_ok_and(|meta| meta.is_file() && meta.len() == size) || expected.rewind().is_err() {
        return false;
    }
    let mut actual = [0; 32 * 1024];
    let mut reference = [0; 32 * 1024];
    let mut left = size;
    while left > 0 {
        let count = left.min(actual.len() as u64) as usize;
        if file.read_exact(&mut actual[..count]).is_err() || expected.read_exact(&mut reference[..count]).is_err()
            || actual[..count] != reference[..count] {
            return false;
        }
        left -= count as u64;
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstalledKernel {
    channel: Channel,
    identity: String,
    relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KernelState {
    channel: Channel,
    installed: Option<InstalledKernel>,
    failure: Option<String>,
}

impl Default for KernelState {
    fn default() -> Self {
        Self {
            channel: Channel::Stable,
            installed: None,
            failure: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedKernel {
    #[serde(default)]
    channel: Channel,
    #[serde(default)]
    installed: Option<PersistedInstall>,
    #[serde(default)]
    failure: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedInstall {
    channel: Channel,
    identity: String,
    relative_path: String,
}

fn safe_relative(path: &str) -> bool {
    let path = Path::new(path);
    !path.as_os_str().is_empty()
        && path.is_relative()
        && path.components().all(|component| matches!(component, Component::Normal(_)))
}

fn read_state(path: &Path) -> KernelState {
    let Ok(text) = fs::read_to_string(path) else {
        return KernelState::default();
    };
    let Ok(persisted) = serde_json::from_str::<PersistedKernel>(&text) else {
        return KernelState::default();
    };
    let installed = persisted.installed.and_then(|item| {
        if item.identity.is_empty() || !safe_relative(&item.relative_path) {
            None
        } else {
            Some(InstalledKernel {
                channel: item.channel,
                identity: item.identity,
                relative_path: item.relative_path,
            })
        }
    });
    KernelState {
        channel: persisted.channel,
        installed,
        failure: persisted.failure,
    }
}

fn write_state(path: &Path, state: &KernelState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
    }
    let persisted = PersistedKernel {
        channel: state.channel,
        installed: state.installed.as_ref().map(|item| PersistedInstall {
            channel: item.channel,
            identity: item.identity.clone(),
            relative_path: item.relative_path.clone(),
        }),
        failure: state.failure.clone(),
    };
    let data = serde_json::to_vec_pretty(&persisted).map_err(|err| err.to_string())?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, data).map_err(|err| err.to_string())?;
    fs::rename(&temporary, path).map_err(|err| err.to_string())?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KernelStatus {
    pub channel: String,
    pub failure: Option<String>,
    pub ready: bool,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResult {
    pub failed: bool,
    pub failure: Option<String>,
    pub system_proxy: bool,
    pub tun: bool,
    pub vpn: bool,
    pub kernel_path: Option<PathBuf>,
}

#[cfg(target_os = "android")]
pub fn android_app_dir(field: &str) -> Option<PathBuf> {
    let ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }.ok()?;
    let mut env = vm.attach_current_thread().ok()?;
    let activity = unsafe { jni::objects::JObject::from_raw(ctx.context().cast()) };
    let info = env.call_method(&activity, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;", &[]).ok()?.l().ok()?;
    let directory = env.get_field(&info, field, "Ljava/lang/String;").ok()?.l().ok()?;
    let directory: String = env.get_string(&jni::objects::JString::from(directory)).ok()?.into();
    Some(PathBuf::from(directory))
}

#[cfg(target_os = "android")]
fn bundled_android_kernel() -> Option<(PathBuf, String)> {
    let manifest: serde_json::Value = serde_json::from_str(include_str!("../android-kernel.json")).ok()?;
    Some((android_app_dir("nativeLibraryDir")?.join("libmihomo.so"), manifest["version"].as_str()?.to_string()))
}

pub struct KernelManager {
    root: PathBuf,
    target: PlatformTarget,
    state: KernelState,
    running: Option<InstalledKernel>,
    protected_path: Option<PathBuf>,
    bundled: Option<(PathBuf, String)>,
}

impl KernelManager {
    pub fn open(root: impl Into<PathBuf>, target: PlatformTarget) -> Self {
        let root = root.into();
        assert!(SUPPORTED_TARGETS.iter().all(|item| item.asset_prefix().is_some()));
        let state = read_state(&root.join("state.json"));
        Self {
            root,
            target,
            state,
            running: None,
            protected_path: None,
            #[cfg(target_os = "android")]
            bundled: bundled_android_kernel(),
            #[cfg(not(target_os = "android"))]
            bundled: None,
        }
    }

    pub fn channel(&self) -> Channel {
        self.state.channel
    }

    /// The profile runtime owns the real process; staging must preserve its file
    /// even when the legacy `connect_kernel` command was never called.
    pub fn protect_running_path(&mut self, path: Option<PathBuf>) {
        self.protected_path = path;
    }

    /// Bootstrap desktop installations offline, preserving independently updated kernels.
    pub fn seed_desktop(&mut self, resources: &Path) -> Result<(), String> {
        if self.installed_path().is_some_and(|path| fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() > 0)) {
            return Ok(());
        }
        #[derive(Deserialize)]
        struct Bundle {
            version: String,
            asset: String,
            sha256: String,
            #[serde(default)]
            packed: Option<crate::packed::PackedResource>,
        }
        let install = || -> Result<InstalledKernel, String> {
            let bundle: Bundle = serde_json::from_slice(&fs::read(resources.join("kernel.json")).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            let expected_asset = format!("{}{}.{}", self.target.asset_prefix().ok_or("不支持的内核平台")?, bundle.version, self.target.archive_ext());
            if bundle.asset != expected_asset || bundle.sha256.len() != 64 || !bundle.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("安装包内核与当前平台不匹配".to_string());
            }
            let mut relative_path = format!("files/{}/{}", bundle.sha256, self.target.binary_file_name());
            let destination = self.root.join(&relative_path);
            if let Some(packed) = &bundle.packed {
                if packed.file != "kernel.br" { return Err("安装包内核资源路径无效".into()); }
                fs::create_dir_all(destination.parent().unwrap()).map_err(|error| error.to_string())?;
                let source = fs::File::open(resources.join(&packed.file)).map_err(|error| error.to_string())?;
                crate::packed::unpack(source, &destination, packed, |_| true).map_err(|error| error.to_string())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
                }
            } else {
                // Older runtime bundles remain readable.
                let archive = fs::File::open(resources.join(format!("kernel.{}", self.target.archive_ext())))
                    .map_err(|error| error.to_string())?;
                relative_path = install_archive(archive, &self.root, &bundle.asset, &bundle.sha256, self.target.binary_file_name())?;
            }
            Ok(InstalledKernel {
                channel: Channel::Stable,
                identity: format!("{}:{}:{}", bundle.version, bundle.asset, bundle.sha256),
                relative_path,
            })
        };
        let installed = install().map_err(|error| format!("内置内核初始化失败：{error}"))?;
        let previous = self.state.clone();
        self.state = KernelState { channel: Channel::Stable, installed: Some(installed), failure: None };
        if let Err(error) = self.persist() {
            self.state = previous;
            return Err(format!("内置内核状态保存失败：{error}"));
        }
        Ok(())
    }

    #[cfg(test)]
    fn failure(&self) -> Option<&str> {
        self.state.failure.as_deref()
    }

    pub fn installed_path(&self) -> Option<PathBuf> {
        if let Some((path, _)) = &self.bundled { return Some(path.clone()); }
        #[cfg(target_os = "android")]
        return None;
        #[cfg(not(target_os = "android"))]
        self.state
            .installed
            .as_ref()
            .map(|item| self.root.join(&item.relative_path))
    }

    #[cfg(test)]
    fn running_path(&self) -> Option<PathBuf> {
        self.running
            .as_ref()
            .map(|item| self.root.join(&item.relative_path))
    }

    pub fn status(&self) -> KernelStatus {
        if let Some((path, version)) = &self.bundled {
            return KernelStatus { channel: "stable".to_string(), failure: if path.is_file() { self.state.failure.clone() } else { Some("安装包缺少内核，请更新或重新安装 Billow".to_string()) }, ready: path.is_file(), version: Some(version.clone()) };
        }
        let ready = self
            .installed_path()
            .map(|path| path.is_file())
            .unwrap_or(false);
        let version = self
            .state
            .installed
            .as_ref()
            .and_then(|item| item.identity.split(':').next())
            .map(str::to_string)
            .filter(|tag| !tag.is_empty());
        KernelStatus {
            channel: self.state.channel.as_str().to_string(),
            failure: self.state.failure.clone(),
            ready,
            version,
        }
    }

    pub fn fail_without_change(&mut self, message: String) -> KernelStatus {
        self.state.failure = Some(message);
        let _ = self.persist();
        self.status()
    }

    pub fn sync(&mut self, requested: Channel, source: &dyn ReleaseSource) -> KernelStatus {
        if self.bundled.is_some() || cfg!(target_os = "android") {
            self.state.failure = if requested == Channel::Preview { Some("Android 内核随应用更新，暂不提供独立预览渠道".to_string()) } else { None };
            return self.status();
        }
        let previous = self.state.clone();
        match self.stage(requested, source) {
            Ok(installed) => {
                self.state.channel = requested;
                self.state.installed = Some(installed);
                self.state.failure = None;
                if let Err(message) = self.persist() {
                    self.state = previous;
                    self.state.failure = Some(message);
                    let _ = self.persist();
                } else if let Some(old) = previous.installed {
                    let replaced = self
                        .state
                        .installed
                        .as_ref()
                        .map(|item| item.relative_path != old.relative_path)
                        .unwrap_or(false);
                    let running_old = self
                        .running
                        .as_ref()
                        .map(|item| item.relative_path == old.relative_path)
                        .unwrap_or(false);
                    let protected = self.protected_path.as_ref() == Some(&self.root.join(&old.relative_path));
                    if replaced && !running_old && !protected {
                        let _ = fs::remove_file(self.root.join(&old.relative_path));
                    }
                }
            }
            Err(message) => {
                self.state = previous;
                self.state.failure = Some(message);
                let _ = self.persist();
            }
        }
        self.status()
    }

    /// Select the staged kernel for the next launch.
    /// Without a local file the result is a failure and takeover stays off.
    pub fn connect(&mut self) -> ConnectResult {
        if let Some((path, _)) = &self.bundled {
            return if path.is_file() { ConnectResult { failed: false, failure: None, system_proxy: false, tun: false, vpn: false, kernel_path: Some(path.clone()) } } else { no_kernel() };
        }
        let Some(installed) = self.state.installed.clone() else {
            self.running = None;
            return no_kernel();
        };
        let path = self.root.join(&installed.relative_path);
        if !path.is_file() {
            self.running = None;
            return no_kernel();
        }
        self.running = Some(installed);
        ConnectResult {
            failed: false,
            failure: None,
            system_proxy: false,
            tun: false,
            vpn: false,
            kernel_path: Some(path),
        }
    }

    fn persist(&self) -> Result<(), String> {
        write_state(&self.root.join("state.json"), &self.state)
    }

    fn stage(&self, requested: Channel, source: &dyn ReleaseSource) -> Result<InstalledKernel, String> {
        let release = source.fetch_release(requested)?;
        validate_release(requested, &release)?;
        let asset = select_asset(&release, self.target)?;
        let expected = expected_checksum(&release, &asset, source)?;
        let identity = format!("{}:{}:{expected}", release.tag, asset.name);
        if let Some(current) = &self.state.installed {
            if current.channel == requested && current.identity == identity {
                let path = self.root.join(&current.relative_path);
                if fs::metadata(&path).is_ok_and(|meta| meta.is_file() && meta.len() > 0) {
                    return Ok(current.clone());
                }
            }
        }
        let relative = install_archive(source.download(&asset.url)?, &self.root, &asset.name, &expected, self.target.binary_file_name())?;
        Ok(InstalledKernel {
            channel: requested,
            identity,
            relative_path: relative,
        })
    }
}

fn expected_checksum(
    release: &ReleaseIndex,
    asset: &ReleaseAsset,
    source: &dyn ReleaseSource,
) -> Result<String, String> {
    if let Some(checksum_asset) = release.assets.iter().find(|item| item.name == "checksums.txt") {
        let mut checksum_text = String::new();
        source.download(&checksum_asset.url)?.read_to_string(&mut checksum_text)
            .map_err(|_| "校验和无法读取".to_string())?;
        return lookup_checksum(&checksum_text, &asset.name);
    }
    sha256_from_digest(asset.digest.as_deref()).ok_or_else(|| "发布页没有校验和".to_string())
}

fn no_kernel() -> ConnectResult {
    ConnectResult {
        failed: true,
        failure: Some("没有本地内核".to_string()),
        system_proxy: false,
        tun: false,
        vpn: false,
        kernel_path: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Cursor, Write};

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
        let path = std::env::temp_dir().join(format!("billow-kernel-{name}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    struct MapSource {
        releases: HashMap<Channel, ReleaseIndex>,
        files: HashMap<String, Vec<u8>>,
    }

    impl ReleaseSource for MapSource {
        fn fetch_release(&self, channel: Channel) -> Result<ReleaseIndex, String> {
            self.releases
                .get(&channel)
                .cloned()
                .ok_or_else(|| "内核下载失败".to_string())
        }

        fn download(&self, url: &str) -> Result<Box<dyn Read>, String> {
            self.files
                .get(url)
                .cloned()
                .map(|bytes| Box::new(Cursor::new(bytes)) as Box<dyn Read>)
                .ok_or_else(|| "内核下载失败".to_string())
        }
    }

    fn gzip_bytes(plain: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(plain).unwrap();
        encoder.finish().unwrap()
    }

    fn zip_bytes(file_name: &str, plain: &[u8]) -> Vec<u8> {
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(file_name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(plain).unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn archive_for(name: &str, plain: &[u8]) -> Vec<u8> {
        if name.ends_with(".zip") {
            zip_bytes("mihomo.exe", plain)
        } else {
            gzip_bytes(plain)
        }
    }

    fn source_with(channel: Channel, tag: &str, files: &[(&str, Vec<u8>)]) -> MapSource {
        let mut assets = Vec::new();
        let mut stored = HashMap::new();
        let mut lines = String::new();
        for (name, bytes) in files {
            let url = format!("mem://{tag}/{name}");
            lines.push_str(&format!("{}  ./{name}\n", sha256_hex(bytes)));
            assets.push(ReleaseAsset {
                name: (*name).to_string(),
                url: url.clone(),
                digest: None,
            });
            stored.insert(url, bytes.clone());
        }
        let checksum_url = format!("mem://{tag}/checksums.txt");
        assets.push(ReleaseAsset {
            name: "checksums.txt".to_string(),
            url: checksum_url.clone(),
            digest: None,
        });
        stored.insert(checksum_url, lines.into_bytes());
        let mut releases = HashMap::new();
        releases.insert(
            channel,
            ReleaseIndex {
                tag: tag.to_string(),
                prerelease: channel == Channel::Preview,
                assets,
            },
        );
        MapSource {
            releases,
            files: stored,
        }
    }

    fn linux_amd64() -> PlatformTarget {
        PlatformTarget::Desktop {
            os: DesktopOs::Linux,
            arch: CpuArch::Amd64,
        }
    }

    fn release_of(names: &[&str]) -> ReleaseIndex {
        ReleaseIndex {
            tag: "v1.19.34".to_string(),
            prerelease: false,
            assets: names
                .iter()
                .map(|name| ReleaseAsset {
                    name: (*name).to_string(),
                    url: format!("mem://{name}"),
                    digest: None,
                })
                .collect(),
        }
    }

    #[test]
    fn bundled_kernel_is_ready_offline_and_never_replaced_by_a_download() {
        let dir = temp_dir("bundled");
        let path = dir.0.join("libmihomo.so");
        fs::write(&path, b"bundled").unwrap();
        let mut manager = KernelManager::open(&dir.0, linux_amd64());
        manager.bundled = Some((path.clone(), "v1.19.34".to_string()));
        let unavailable = MapSource { releases: HashMap::new(), files: HashMap::new() };
        assert!(manager.sync(Channel::Stable, &unavailable).ready);
        assert_eq!(manager.connect().kernel_path, Some(path.clone()));
        assert!(manager.sync(Channel::Preview, &unavailable).failure.is_some());
        assert_eq!(manager.status().channel, "stable");
        assert_eq!(fs::read(&path).unwrap(), b"bundled");
        fs::remove_file(path).unwrap();
        assert!(!manager.status().ready);
        assert!(manager.connect().failed);
        assert!(manager.status().failure.unwrap().contains("安装包缺少内核"));
    }

    fn desktop_bundle(dir: &Path, target: PlatformTarget) -> Vec<u8> {
        fs::create_dir_all(dir).unwrap();
        let asset = format!("{}v1.19.34.{}", target.asset_prefix().unwrap(), target.archive_ext());
        let bytes = archive_for(&asset, b"packaged-kernel");
        fs::write(dir.join(format!("kernel.{}", target.archive_ext())), &bytes).unwrap();
        fs::write(dir.join("kernel.json"), serde_json::to_vec(&serde_json::json!({
            "version": "v1.19.34", "asset": asset, "sha256": sha256_hex(&bytes),
        })).unwrap()).unwrap();
        bytes
    }

    #[test]
    fn desktop_first_launch_and_missing_kernel_repair_work_without_network() {
        for target in [linux_amd64(), PlatformTarget::Desktop { os: DesktopOs::Windows, arch: CpuArch::Amd64 }] {
            let dir = temp_dir("desktop-bootstrap");
            let resources = dir.0.join("package");
            desktop_bundle(&resources, target);
            let home = dir.0.join("kernels");
            let mut manager = KernelManager::open(&home, target);
            assert!(!manager.status().ready);
            manager.seed_desktop(&resources).unwrap();
            assert!(manager.status().ready);
            assert_eq!(manager.status().version.as_deref(), Some("v1.19.34"));
            let path = manager.connect().kernel_path.unwrap();
            assert!(path.starts_with(&home));
            assert_eq!(fs::read(&path).unwrap(), b"packaged-kernel");
            fs::remove_file(&path).unwrap();
            let mut reopened = KernelManager::open(&home, target);
            assert!(!reopened.status().ready);
            reopened.seed_desktop(&resources).unwrap();
            assert_eq!(fs::read(reopened.installed_path().unwrap()).unwrap(), b"packaged-kernel");
            fs::write(&path, b"independent-update").unwrap();
            reopened.state.channel = Channel::Preview;
            fs::remove_dir_all(resources.clone()).unwrap();
            reopened.seed_desktop(&resources).unwrap();
            assert_eq!(reopened.channel(), Channel::Preview);
            assert_eq!(fs::read(&path).unwrap(), b"independent-update");
        }
    }

    #[test]
    fn compressed_kernel_bootstrap_preserves_bytes_permissions_and_rejects_damage() {
        let root = std::env::temp_dir().join(format!("billow-kernel-packed-{}", std::process::id()));
        let resources = root.join("resources");
        fs::create_dir_all(&resources).unwrap();
        let target = PlatformTarget::current();
        let version = "v1.19.34";
        let asset = format!("{}{}.{}", target.asset_prefix().unwrap(), version, target.archive_ext());
        let data = b"signed upstream executable bytes";
        let (bytes, metadata) = crate::packed::tests::fixture(data, "kernel.br");
        fs::write(resources.join("kernel.br"), &bytes).unwrap();
        fs::write(resources.join("kernel.json"), serde_json::to_vec(&serde_json::json!({
            "version": version, "asset": asset, "sha256": "a".repeat(64), "packed": metadata
        })).unwrap()).unwrap();
        let mut manager = KernelManager::open(root.join("kernels"), target);
        manager.seed_desktop(&resources).unwrap();
        let installed = manager.installed_path().unwrap();
        assert_eq!(fs::read(&installed).unwrap(), data);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&installed).unwrap().permissions().mode() & 0o777, 0o755);
        }
        fs::write(resources.join("kernel.br"), b"damaged").unwrap();
        manager.seed_desktop(&resources).unwrap(); // An independently installed core stays usable.
        let mut fresh = KernelManager::open(root.join("fresh"), target);
        assert!(fresh.seed_desktop(&resources).is_err());
        assert!(!fresh.status().ready);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn desktop_bootstrap_rejects_corrupt_and_wrong_platform_packages() {
        let dir = temp_dir("desktop-corrupt-bundle");
        let resources = dir.0.join("package");
        desktop_bundle(&resources, linux_amd64());
        let mut manager = KernelManager::open(dir.0.join("kernels"), linux_amd64());
        fs::write(resources.join("kernel.gz"), b"truncated").unwrap();
        assert!(manager.seed_desktop(&resources).unwrap_err().contains("校验和"));
        assert!(!manager.status().ready);
        desktop_bundle(&resources, PlatformTarget::Desktop { os: DesktopOs::Darwin, arch: CpuArch::Arm64 });
        assert!(manager.seed_desktop(&resources).unwrap_err().contains("平台"));
        assert!(!manager.status().ready);
    }

    #[test]
    fn default_channel_is_stable_and_has_no_third_channel() {
        let dir = temp_dir("default");
        let manager = KernelManager::open(&dir.0, linux_amd64());
        assert_eq!(manager.channel(), Channel::Stable);
        assert!(manager.installed_path().is_none());
        assert!(manager.failure().is_none());
        assert_eq!(parse_channel("stable").unwrap(), Channel::Stable);
        assert_eq!(parse_channel("preview").unwrap(), Channel::Preview);
        assert!(parse_channel("beta").is_err());
        assert!(parse_channel("commit").is_err());
        assert!(parse_channel("deadbeef").is_err());
        assert!(parse_channel("v1.19.34").is_err());
        assert!(parse_channel("Prerelease-Alpha").is_err());
        assert!(parse_channel("").is_err());

        fs::write(dir.0.join("state.json"), b"{not json").unwrap();
        let reopened = KernelManager::open(&dir.0, linux_amd64());
        assert_eq!(reopened.channel(), Channel::Stable);
        assert!(reopened.installed_path().is_none());

        assert_eq!(RELEASES_PAGE, "https://github.com/MetaCubeX/mihomo/releases");
        assert_eq!(
            release_api(Channel::Stable),
            "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
        );
        assert_eq!(
            release_api(Channel::Preview),
            "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/Prerelease-Alpha"
        );
        assert!(SUPPORTED_TARGETS.contains(&linux_amd64()));
    }

    #[test]
    fn desktop_and_android_assets_do_not_mix() {
        let names = [
            "mihomo-darwin-arm64-v1.19.34.gz",
            "mihomo-darwin-arm64-go120-v1.19.34.gz",
            "mihomo-darwin-amd64-v1.19.34.gz",
            "mihomo-darwin-amd64-compatible-v1.19.34.gz",
            "mihomo-darwin-amd64-v3-v1.19.34.gz",
            "mihomo-windows-amd64-v1.19.34.zip",
            "mihomo-windows-amd64-v1-go120-v1.19.34.zip",
            "mihomo-linux-amd64-v1.19.34.gz",
            "mihomo-linux-amd64-v1.19.34.deb",
            "mihomo-linux-amd64-compatible-v1.19.34.gz",
            "mihomo-linux-arm64-v1.19.34.gz",
            "mihomo-android-arm64-v8-v1.19.34.gz",
            "mihomo-android-armv7-v1.19.34.gz",
            "mihomo-android-amd64-v1.19.34.gz",
            "mihomo-android-386-v1.19.34.gz",
            "mihomo-freebsd-amd64-v1.19.34.gz",
            "checksums.txt",
        ];
        let release = release_of(&names);
        assert_eq!(
            select_asset(
                &release,
                PlatformTarget::Desktop {
                    os: DesktopOs::Darwin,
                    arch: CpuArch::Arm64,
                },
            )
            .unwrap()
            .name,
            "mihomo-darwin-arm64-v1.19.34.gz"
        );
        assert_eq!(
            select_asset(
                &release,
                PlatformTarget::Desktop {
                    os: DesktopOs::Windows,
                    arch: CpuArch::Amd64,
                },
            )
            .unwrap()
            .name,
            "mihomo-windows-amd64-v1.19.34.zip"
        );
        assert_eq!(
            select_asset(&release, linux_amd64()).unwrap().name,
            "mihomo-linux-amd64-v1.19.34.gz"
        );
        assert_eq!(
            select_asset(
                &release,
                PlatformTarget::Android {
                    abi: AndroidAbi::Arm64V8a,
                },
            )
            .unwrap()
            .name,
            "mihomo-android-arm64-v8-v1.19.34.gz"
        );
        assert!(select_asset(
            &release,
            PlatformTarget::Desktop {
                os: DesktopOs::Darwin,
                arch: CpuArch::Armv7,
            },
        )
        .is_err());

        let preview = ReleaseIndex {
            tag: PREVIEW_TAG.to_string(),
            prerelease: true,
            assets: vec![
                ReleaseAsset {
                    name: "mihomo-android-arm64-v8-alpha-4c57a4a.gz".to_string(),
                    url: "mem://android".to_string(),
                    digest: None,
                },
                ReleaseAsset {
                    name: "mihomo-darwin-arm64-alpha-4c57a4a.gz".to_string(),
                    url: "mem://darwin".to_string(),
                    digest: None,
                },
                ReleaseAsset {
                    name: "mihomo-darwin-arm64-go120-alpha-4c57a4a.gz".to_string(),
                    url: "mem://variant".to_string(),
                    digest: None,
                },
            ],
        };
        assert_eq!(
            select_asset(
                &preview,
                PlatformTarget::Android {
                    abi: AndroidAbi::Arm64V8a,
                },
            )
            .unwrap()
            .name,
            "mihomo-android-arm64-v8-alpha-4c57a4a.gz"
        );
        assert_eq!(
            select_asset(
                &preview,
                PlatformTarget::Desktop {
                    os: DesktopOs::Darwin,
                    arch: CpuArch::Arm64,
                },
            )
            .unwrap()
            .name,
            "mihomo-darwin-arm64-alpha-4c57a4a.gz"
        );

        let dir = temp_dir("install-family");
        let linux_name = "mihomo-linux-amd64-v1.19.34.gz";
        let android_name = "mihomo-android-arm64-v8-v1.19.34.gz";
        let mut files = HashMap::new();
        let linux_archive = archive_for(linux_name, b"linux-kernel");
        let android_archive = archive_for(android_name, b"android-kernel");
        files.insert(linux_name, linux_archive);
        files.insert(android_name, android_archive);
        files.insert(
            "mihomo-linux-amd64-compatible-v1.19.34.gz",
            archive_for("mihomo-linux-amd64-compatible-v1.19.34.gz", b"variant"),
        );
        let listed: Vec<(&str, Vec<u8>)> = files.iter().map(|(name, bytes)| (*name, bytes.clone())).collect();
        let source = source_with(Channel::Stable, "v1.19.34", &listed);
        let mut desktop = KernelManager::open(&dir.0, linux_amd64());
        let status = desktop.sync(Channel::Stable, &source);
        assert!(status.failure.is_none());
        assert_eq!(fs::read(desktop.installed_path().unwrap()).unwrap(), b"linux-kernel");

        let android_dir = temp_dir("install-android");
        let mut android = KernelManager::open(
            &android_dir.0,
            PlatformTarget::Android {
                abi: AndroidAbi::Arm64V8a,
            },
        );
        let status = android.sync(Channel::Stable, &source);
        assert!(status.failure.is_none());
        assert_eq!(fs::read(android.installed_path().unwrap()).unwrap(), b"android-kernel");

        let windows_dir = temp_dir("install-windows");
        let windows_name = "mihomo-windows-amd64-v1.19.34.zip";
        let windows = source_with(
            Channel::Stable,
            "v1.19.34",
            &[(windows_name, archive_for(windows_name, b"windows-kernel"))],
        );
        let mut windows_manager = KernelManager::open(
            &windows_dir.0,
            PlatformTarget::Desktop {
                os: DesktopOs::Windows,
                arch: CpuArch::Amd64,
            },
        );
        assert!(windows_manager.sync(Channel::Stable, &windows).failure.is_none());
        assert_eq!(
            fs::read(windows_manager.installed_path().unwrap()).unwrap(),
            b"windows-kernel"
        );
        assert!(windows_manager
            .installed_path()
            .unwrap()
            .ends_with("core.exe"));
    }

    #[test]
    fn update_uses_new_file_on_next_launch_and_keeps_channel() {
        let dir = temp_dir("update");
        let mut manager = KernelManager::open(&dir.0, linux_amd64());
        let first_name = "mihomo-linux-amd64-v1.19.34.gz";
        let first = source_with(
            Channel::Stable,
            "v1.19.34",
            &[(first_name, archive_for(first_name, b"kernel-v1"))],
        );
        assert!(manager.sync(Channel::Stable, &first).failure.is_none());
        let started = manager.connect();
        assert!(!started.failed);
        let first_path = started.kernel_path.clone().unwrap();
        assert_eq!(fs::read(&first_path).unwrap(), b"kernel-v1");
        assert!(!started.system_proxy && !started.tun && !started.vpn);

        let second_name = "mihomo-linux-amd64-v1.19.35.gz";
        let second = source_with(
            Channel::Stable,
            "v1.19.35",
            &[(second_name, archive_for(second_name, b"kernel-v2"))],
        );
        let status = manager.sync(Channel::Stable, &second);
        assert_eq!(status.channel, "stable");
        assert!(status.failure.is_none());
        assert_eq!(manager.channel(), Channel::Stable);
        assert_eq!(manager.running_path().unwrap(), first_path);
        assert_eq!(fs::read(&first_path).unwrap(), b"kernel-v1");

        let next = manager.connect();
        assert!(!next.failed);
        assert_ne!(next.kernel_path.as_ref(), Some(&first_path));
        assert_eq!(fs::read(next.kernel_path.unwrap()).unwrap(), b"kernel-v2");
        assert_eq!(manager.channel(), Channel::Stable);
        assert!(!next.system_proxy && !next.tun && !next.vpn);

        let mut reopened = KernelManager::open(&dir.0, linux_amd64());
        assert_eq!(reopened.channel(), Channel::Stable);
        assert_eq!(fs::read(reopened.installed_path().unwrap()).unwrap(), b"kernel-v2");
        assert!(reopened.running_path().is_none());

        let preview_name = "mihomo-linux-amd64-alpha-abc123.gz";
        let preview = source_with(
            Channel::Preview,
            PREVIEW_TAG,
            &[(preview_name, archive_for(preview_name, b"preview-kernel"))],
        );
        let status = reopened.sync(Channel::Preview, &preview);
        assert_eq!(status.channel, "preview");
        assert!(status.failure.is_none());
        let launched = reopened.connect();
        assert!(!launched.failed);
        assert_eq!(fs::read(launched.kernel_path.unwrap()).unwrap(), b"preview-kernel");
        assert_eq!(reopened.channel(), Channel::Preview);
    }

    #[test]
    fn switching_channels_back_reuses_the_running_executable_without_rewriting_it() {
        let dir = temp_dir("channel-roundtrip");
        let target = PlatformTarget::Desktop { os: DesktopOs::Windows, arch: CpuArch::Amd64 };
        let stable_name = "mihomo-windows-amd64-v1.19.34.zip";
        let preview_name = "mihomo-windows-amd64-alpha-abc123.zip";
        let stable = source_with(Channel::Stable, "v1.19.34", &[(stable_name, archive_for(stable_name, b"stable-core"))]);
        let preview = source_with(Channel::Preview, PREVIEW_TAG, &[(preview_name, archive_for(preview_name, b"preview-core"))]);
        let mut manager = KernelManager::open(&dir.0, target);
        assert!(manager.sync(Channel::Stable, &stable).failure.is_none());
        let path = manager.installed_path().unwrap();
        // Model the actual profile runtime, which does not call manager.connect().
        manager.protect_running_path(Some(path.clone()));
        let saved_time = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        fs::File::options().write(true).open(&path).unwrap()
            .set_times(fs::FileTimes::new().set_modified(saved_time)).unwrap();
        let saved_time = fs::metadata(&path).unwrap().modified().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o4755)).unwrap();
        }
        #[cfg(windows)]
        let _locked = {
            use std::os::windows::fs::OpenOptionsExt;
            // Allow reads but deny writes/deletion, like a running Windows image.
            fs::OpenOptions::new().read(true).share_mode(1).open(&path).unwrap()
        };
        for _ in 0..3 {
            assert!(manager.sync(Channel::Preview, &preview).failure.is_none());
            assert_eq!(fs::read(&path).unwrap(), b"stable-core");
            let status = manager.sync(Channel::Stable, &stable);
            assert!(status.failure.is_none(), "{:?}", status.failure);
            assert_eq!(status.channel, "stable");
            assert_eq!(manager.installed_path().unwrap(), path);
            assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), saved_time);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o4755);
        }
    }

    #[test]
    fn a_different_cached_image_is_repaired_at_a_new_path() {
        let dir = temp_dir("kernel-repair");
        let name = "mihomo-linux-amd64-v1.19.34.gz";
        let archive = archive_for(name, b"verified-kernel");
        let source = source_with(Channel::Stable, "v1.19.34", &[(name, archive.clone())]);
        let old_path = dir.0.join(format!("files/{}/core", sha256_hex(&archive)));
        fs::create_dir_all(old_path.parent().unwrap()).unwrap();
        fs::write(&old_path, b"existing-image").unwrap();
        let mut manager = KernelManager::open(&dir.0, linux_amd64());
        manager.protect_running_path(Some(old_path.clone()));
        assert!(manager.sync(Channel::Stable, &source).failure.is_none());
        let next = manager.installed_path().unwrap();
        assert_ne!(next, old_path);
        assert_eq!(fs::read(&old_path).unwrap(), b"existing-image");
        assert_eq!(fs::read(&next).unwrap(), b"verified-kernel");
        assert_eq!(manager.connect().kernel_path.as_ref(), Some(&next));
    }

    #[test]
    fn failed_kernel_state_save_keeps_the_previous_selection_and_image() {
        let dir = temp_dir("kernel-state-failure");
        let name = "mihomo-linux-amd64-v1.19.34.gz";
        let stable = source_with(Channel::Stable, "v1.19.34", &[(name, archive_for(name, b"stable"))]);
        let next = "mihomo-linux-amd64-alpha-abc123.gz";
        let preview = source_with(Channel::Preview, PREVIEW_TAG, &[(next, archive_for(next, b"preview"))]);
        let mut manager = KernelManager::open(&dir.0, linux_amd64());
        manager.sync(Channel::Stable, &stable);
        let original = manager.installed_path().unwrap();
        let state = fs::read(dir.0.join("state.json")).unwrap();
        fs::create_dir(dir.0.join("state.json.tmp")).unwrap();
        let failed = manager.sync(Channel::Preview, &preview);
        assert!(failed.failure.is_some());
        assert_eq!(failed.channel, "stable");
        assert_eq!(manager.installed_path().unwrap(), original);
        assert_eq!(fs::read(original).unwrap(), b"stable");
        assert_eq!(fs::read(dir.0.join("state.json")).unwrap(), state);
    }

    #[test]
    fn interrupted_download_and_truncated_gzip_leave_no_staging_files() {
        struct InterruptedDownload;
        impl Read for InterruptedDownload {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::UnexpectedEof))
            }
        }
        let dir = temp_dir("stage-interrupted");
        let gz = gzip_bytes(&vec![42; 140_000]);
        let truncated = &gz[..gz.len() - 4];
        let interrupted = truncated.chain(InterruptedDownload);
        assert!(install_archive(interrupted, &dir.0, "kernel.gz", &sha256_hex(&gz), "core").is_err());
        assert!(install_archive(truncated, &dir.0, "kernel.gz", &sha256_hex(truncated), "core").is_err());
        assert_eq!(fs::read_dir(dir.0.join("files")).unwrap().count(), 0);
    }

    #[test]
    fn download_failure_keeps_channel_and_file() {
        let dir = temp_dir("failure");
        let mut manager = KernelManager::open(&dir.0, linux_amd64());
        let name = "mihomo-linux-amd64-v1.19.34.gz";
        let original = source_with(Channel::Stable, "v1.19.34", &[(name, archive_for(name, b"kernel-v1"))]);
        assert!(manager.sync(Channel::Stable, &original).failure.is_none());
        let path = manager.installed_path().unwrap();
        let bytes = fs::read(&path).unwrap();

        let broken = source_with(Channel::Stable, "v1.19.35", &[]);
        let status = manager.sync(Channel::Stable, &broken);
        assert_eq!(status.channel, "stable");
        assert!(status.failure.is_some());
        assert_eq!(manager.channel(), Channel::Stable);
        assert_eq!(manager.installed_path().unwrap(), path);
        assert_eq!(fs::read(&path).unwrap(), bytes);

        let mut mismatched = source_with(
            Channel::Stable,
            "v1.19.35",
            &[(
                "mihomo-linux-amd64-v1.19.35.gz",
                archive_for("mihomo-linux-amd64-v1.19.35.gz", b"kernel-v2"),
            )],
        );
        let asset_url = mismatched.releases[&Channel::Stable]
            .assets
            .iter()
            .find(|asset| asset.name.ends_with(".gz"))
            .unwrap()
            .url
            .clone();
        mismatched.files.insert(asset_url, b"not-the-archive".to_vec());
        let status = manager.sync(Channel::Stable, &mismatched);
        assert_eq!(status.failure.as_deref(), Some("内核校验和不一致"));
        assert_eq!(manager.channel(), Channel::Stable);
        assert_eq!(fs::read(&path).unwrap(), bytes);

        let preview_name = "mihomo-linux-amd64-alpha-4c57a4a.gz";
        let mut preview = source_with(
            Channel::Preview,
            PREVIEW_TAG,
            &[(preview_name, archive_for(preview_name, b"preview-kernel"))],
        );
        let preview_url = preview.releases[&Channel::Preview]
            .assets
            .iter()
            .find(|asset| asset.name == preview_name)
            .unwrap()
            .url
            .clone();
        preview.files.remove(&preview_url);
        let status = manager.sync(Channel::Preview, &preview);
        assert_eq!(status.channel, "stable");
        assert!(status.failure.is_some());
        assert_eq!(manager.channel(), Channel::Stable);
        assert_eq!(fs::read(manager.installed_path().unwrap()).unwrap(), bytes);

        let mut prerelease = source_with(
            Channel::Stable,
            "v1.19.36",
            &[(
                "mihomo-linux-amd64-v1.19.36.gz",
                archive_for("mihomo-linux-amd64-v1.19.36.gz", b"nope"),
            )],
        );
        prerelease.releases.get_mut(&Channel::Stable).unwrap().prerelease = true;
        let status = manager.sync(Channel::Stable, &prerelease);
        assert!(status.failure.is_some());
        assert_eq!(manager.channel(), Channel::Stable);
        assert_eq!(fs::read(&path).unwrap(), bytes);

        let bare_name = "mihomo-linux-amd64-v1.19.37.gz";
        let bare_url = format!("mem://v1.19.37/{bare_name}");
        let mut bare_releases = HashMap::new();
        bare_releases.insert(
            Channel::Stable,
            ReleaseIndex {
                tag: "v1.19.37".to_string(),
                prerelease: false,
                assets: vec![ReleaseAsset {
                    name: bare_name.to_string(),
                    url: bare_url.clone(),
                    digest: None,
                }],
            },
        );
        let mut bare_files = HashMap::new();
        bare_files.insert(bare_url, archive_for(bare_name, b"bare"));
        let status = manager.sync(
            Channel::Stable,
            &MapSource {
                releases: bare_releases,
                files: bare_files,
            },
        );
        assert_eq!(status.failure.as_deref(), Some("发布页没有校验和"));
        assert_eq!(manager.channel(), Channel::Stable);
        assert_eq!(manager.installed_path().unwrap(), path);
        assert_eq!(fs::read(&path).unwrap(), bytes);

        let other_name = "mihomo-linux-amd64-v1.19.38.gz";
        let other_url = format!("mem://v1.19.38/{other_name}");
        let mut other_releases = HashMap::new();
        other_releases.insert(
            Channel::Stable,
            ReleaseIndex {
                tag: "v1.19.38".to_string(),
                prerelease: false,
                assets: vec![ReleaseAsset {
                    name: other_name.to_string(),
                    url: other_url.clone(),
                    digest: Some(format!("sha512:{}", "ab".repeat(32))),
                }],
            },
        );
        let mut other_files = HashMap::new();
        other_files.insert(other_url, archive_for(other_name, b"other"));
        let status = manager.sync(
            Channel::Stable,
            &MapSource {
                releases: other_releases,
                files: other_files,
            },
        );
        assert_eq!(status.failure.as_deref(), Some("发布页没有校验和"));
        assert_eq!(manager.channel(), Channel::Stable);
        assert_eq!(fs::read(&path).unwrap(), bytes);

        let reopened = KernelManager::open(&dir.0, linux_amd64());
        assert_eq!(reopened.channel(), Channel::Stable);
        assert_eq!(fs::read(reopened.installed_path().unwrap()).unwrap(), bytes);
        assert!(reopened.failure().is_some());
    }

    #[test]
    fn stable_release_without_checksums_uses_asset_digest() {
        let dir = temp_dir("digest");
        let mut manager = KernelManager::open(&dir.0, linux_amd64());
        let name = "mihomo-linux-amd64-v1.19.34.gz";
        let archive = archive_for(name, b"stable-kernel");
        let url = format!("mem://v1.19.34/{name}");
        let mut releases = HashMap::new();
        releases.insert(
            Channel::Stable,
            ReleaseIndex {
                tag: "v1.19.34".to_string(),
                prerelease: false,
                assets: vec![ReleaseAsset {
                    name: name.to_string(),
                    url: url.clone(),
                    digest: Some(format!("sha256:{}", sha256_hex(&archive))),
                }],
            },
        );
        let mut files = HashMap::new();
        files.insert(url, archive);
        let status = manager.sync(
            Channel::Stable,
            &MapSource {
                releases,
                files,
            },
        );
        assert!(status.failure.is_none(), "{status:?}");
        assert_eq!(status.channel, "stable");
        assert_eq!(manager.channel(), Channel::Stable);
        assert_eq!(fs::read(manager.installed_path().unwrap()).unwrap(), b"stable-kernel");

        let checked_name = "mihomo-linux-amd64-v1.19.35.gz";
        let checked = archive_for(checked_name, b"from-checksums");
        let mut preferred = source_with(Channel::Stable, "v1.19.35", &[(checked_name, checked)]);
        preferred
            .releases
            .get_mut(&Channel::Stable)
            .unwrap()
            .assets
            .iter_mut()
            .find(|item| item.name == checked_name)
            .unwrap()
            .digest = Some(format!("sha256:{}", "0".repeat(64)));
        let status = manager.sync(Channel::Stable, &preferred);
        assert!(status.failure.is_none(), "{status:?}");
        assert_eq!(manager.channel(), Channel::Stable);
        assert_eq!(fs::read(manager.installed_path().unwrap()).unwrap(), b"from-checksums");
    }

    #[test]
    fn missing_kernel_connect_fails_and_takeover_stays_off() {
        let dir = temp_dir("missing");
        let mut manager = KernelManager::open(&dir.0, linux_amd64());
        let result = manager.connect();
        assert!(result.failed);
        assert_eq!(result.failure.as_deref(), Some("没有本地内核"));
        assert!(!result.system_proxy);
        assert!(!result.tun);
        assert!(!result.vpn);
        assert!(result.kernel_path.is_none());
        assert_eq!(manager.channel(), Channel::Stable);

        let name = "mihomo-linux-amd64-v1.19.34.gz";
        let source = source_with(Channel::Stable, "v1.19.34", &[(name, archive_for(name, b"kernel-v1"))]);
        assert!(manager.sync(Channel::Stable, &source).failure.is_none());
        let path = manager.installed_path().unwrap();
        fs::remove_file(&path).unwrap();
        let result = manager.connect();
        assert!(result.failed);
        assert_eq!(result.failure.as_deref(), Some("没有本地内核"));
        assert!(!result.system_proxy && !result.tun && !result.vpn);
        assert!(result.kernel_path.is_none());
        assert_eq!(manager.channel(), Channel::Stable);
    }

    #[test]
    fn commands_are_exposed_to_the_window() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>();
        assert!(permissions.contains(&"allow-kernel-state"));
        assert!(permissions.contains(&"allow-set-kernel-channel"));
        assert!(permissions.contains(&"allow-connect-kernel"));
        assert!(permissions.contains(&"allow-shell-state"));
    }

    #[test]
    fn github_release_json_keeps_checksum_asset() {
        let body = r#"{
            "tag_name": "v1.19.34",
            "prerelease": false,
            "assets": [
                {"name": "mihomo-linux-amd64-v1.19.34.gz", "browser_download_url": "https://example.test/core.gz", "digest": "sha256:1a7a20eca63fbbaec90137717465bfde488d0db2a3a79b8fadebf9b2545b6e4c"},
                {"name": "checksums.txt", "browser_download_url": "https://example.test/checksums.txt"},
                {"name": "", "browser_download_url": "https://example.test/skip"}
            ]
        }"#;
        let release = parse_github_release(body).unwrap();
        assert_eq!(release.tag, "v1.19.34");
        assert!(!release.prerelease);
        assert_eq!(release.assets.len(), 2);
        assert_eq!(
            release.assets[0].digest.as_deref(),
            Some("sha256:1a7a20eca63fbbaec90137717465bfde488d0db2a3a79b8fadebf9b2545b6e4c")
        );
        assert_eq!(
            sha256_from_digest(release.assets[0].digest.as_deref()).as_deref(),
            Some("1a7a20eca63fbbaec90137717465bfde488d0db2a3a79b8fadebf9b2545b6e4c")
        );
        assert!(sha256_from_digest(Some("sha512:abcd")).is_none());
        assert_eq!(
            lookup_checksum(
                "abc  ./other.gz\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  ./mihomo-linux-amd64-v1.19.34.gz\n",
                "mihomo-linux-amd64-v1.19.34.gz"
            )
            .unwrap(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }
}
