//! Backup files and manual WebDAV storage (R38).
//!
//! A backup is one versioned UTF-8 JSON document. Restoring it is a whole-state
//! replacement with rollback (see `ProfileBook::restore_backup`). WebDAV is only
//! touched when the user presses a button: nothing uploads or downloads on its
//! own, and there is no automatic-sync setting anywhere (R45).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use quick_xml::Reader;
use quick_xml::events::Event;
use serde::{Deserialize, Serialize};

use crate::i18n::{self, Key};
use crate::profile::ProfileBackup;
use crate::shell::{ShellBackup, ShellState};

pub const FORMAT: &str = "billow-backup";
pub const VERSION: u32 = 1;
/// Remote folder inside the user's WebDAV space; created on demand.
pub const REMOTE_DIR: &str = "billow";
/// Refuse a listing or download larger than this; a real backup stays far below.
const MAX_BODY: u64 = 64 * 1024 * 1024;
const NAME_PREFIX: &str = "billow-backup-";

/// The whole backup document. Missing required fields make `serde` fail, which
/// the restore path reports as a damaged file instead of a partial restore.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupFile {
    pub format: String,
    pub version: u32,
    pub app_version: String,
    pub platform: String,
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub created_ms: u64,
    pub profiles: ProfileBackup,
    pub shell: ShellBackup,
}

/// Build the document from live state.
pub fn compose(
    profiles: ProfileBackup,
    shell: &ShellState,
    app_version: &str,
    platform: &str,
    device: &str,
    now_ms: u64,
) -> BackupFile {
    BackupFile {
        format: FORMAT.to_string(),
        version: VERSION,
        app_version: app_version.to_string(),
        platform: platform.to_string(),
        device: device.to_string(),
        created_ms: now_ms,
        profiles,
        shell: ShellBackup::of(shell),
    }
}

pub fn to_text(file: &BackupFile) -> Result<String, String> {
    serde_json::to_string_pretty(file).map_err(|_| i18n::tr(Key::BackupExportFailed).to_string())
}

/// Read and validate a backup. Every rejection happens before any state
/// changes, and the message names the cause: unrecognised format, a file from a
/// newer version, or a damaged file.
pub fn parse(text: &str, current_app_version: &str) -> Result<BackupFile, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| i18n::tr(Key::BackupUnknown))?;
    let Some(object) = value.as_object() else {
        return Err(i18n::tr(Key::BackupUnknown).to_string());
    };
    if object.get("format").and_then(|format| format.as_str()) != Some(FORMAT) {
        return Err(i18n::tr(Key::BackupUnknown).to_string());
    }
    let version = object.get("version").and_then(|version| version.as_u64()).unwrap_or(0);
    let app_version = object
        .get("app_version")
        .and_then(|version| version.as_str())
        .unwrap_or_default();
    if version > u64::from(VERSION) {
        let reported = if app_version.is_empty() {
            version.to_string()
        } else {
            app_version.to_string()
        };
        return Err(newer_version(&reported));
    }
    if version < u64::from(VERSION) {
        return Err(i18n::tr(Key::BackupDamaged).to_string());
    }
    if newer_app_version(app_version, current_app_version) {
        return Err(newer_version(app_version));
    }
    serde_json::from_value::<BackupFile>(value).map_err(|_| i18n::tr(Key::BackupDamaged).to_string())
}

fn newer_version(version: &str) -> String {
    i18n::tr_args(Key::BackupNewer, &[("version", version)])
}

/// `true` only when both versions parse and the file's one is ahead. An
/// unreadable app version never blocks a restore the format version accepts.
fn newer_app_version(file: &str, current: &str) -> bool {
    let parse = |raw: &str| semver::Version::parse(raw.trim().trim_start_matches('v')).ok();
    match (parse(file), parse(current)) {
        (Some(file), Some(current)) => file > current,
        _ => false,
    }
}

/// Write a backup next to the other exports and return its full path.
pub fn export(directory: &Path, file: &BackupFile, now_ms: u64) -> Result<PathBuf, String> {
    fs::create_dir_all(directory).map_err(|_| i18n::tr(Key::BackupExportFailed).to_string())?;
    let path = directory.join(local_file_name(now_ms));
    fs::write(&path, to_text(file)?).map_err(|_| i18n::tr(Key::BackupExportFailed).to_string())?;
    Ok(path)
}

/// `billow-backup-20261120-153000.json` (UTC, like the log exports).
pub fn local_file_name(now_ms: u64) -> String {
    format!("{NAME_PREFIX}{}.json", stamp(now_ms))
}

/// `billow-backup-<device>-20261120-153000.json`, so the cloud list can name the
/// device that uploaded each file.
pub fn remote_file_name(device: &str, now_ms: u64) -> String {
    format!("{NAME_PREFIX}{}-{}.json", sanitize_device(device), stamp(now_ms))
}

/// `YYYYMMDD-HHMMSS` in UTC.
fn stamp(now_ms: u64) -> String {
    let seconds = now_ms / 1000;
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u64, u64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// File names stay inside a conservative ASCII set so no XML escaping or URL
/// encoding is needed anywhere in the WebDAV path.
pub fn sanitize_device(raw: &str) -> String {
    let mut name: String = raw
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while name.contains("--") {
        name = name.replace("--", "-");
    }
    let name = name.trim_matches('-').chars().take(32).collect::<String>();
    if name.is_empty() { "billow".to_string() } else { name }
}

/// This machine's name, used in the uploaded file name.
pub fn device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .map(|name| sanitize_device(&name))
        .unwrap_or_else(|_| sanitize_device(std::env::consts::OS))
}

/// Keep this machine's platform-only settings when the backup came from the
/// other platform (R38): desktop TUN / system proxy / tray settings and Android
/// app rules do not travel, and the restore must still succeed without error.
pub fn merge_platform(
    backup: &mut BackupFile,
    current_platform: &str,
    local_profiles: &ProfileBackup,
    local_shell: &ShellState,
) -> bool {
    if backup.platform == current_platform {
        return false;
    }
    backup.profiles.settings.tun = local_profiles.settings.tun.clone();
    backup.profiles.settings.system_proxy = local_profiles.settings.system_proxy.clone();
    backup.profiles.tun_wanted = local_profiles.tun_wanted;
    backup.profiles.excluded_packages = local_profiles.excluded_packages.clone();
    backup.profiles.included_packages = local_profiles.included_packages.clone();
    backup.profiles.app_mode = local_profiles.app_mode.clone();
    backup.shell.close_to_tray = local_shell.close_to_tray;
    backup.shell.silent_start = local_shell.silent_start;
    // Lightweight mode is a desktop window behaviour like the tray flags, so an
    // Android backup must not switch it on or off here (R44).
    backup.shell.release_ui_on_close = local_shell.release_ui_on_close;
    // Global shortcuts belong to this keyboard and this desktop's other apps,
    // so a restore from the other platform keeps the local bindings (R39).
    backup.shell.hotkeys = local_shell.hotkeys.clone();
    backup.platform = current_platform.to_string();
    true
}

// ─────────────────────────── WebDAV ───────────────────────────

/// WebDAV account. Stored in `shell-state.json` and never written to a backup.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebDavAccount {
    pub url: String,
    pub username: String,
    pub password: String,
}

impl WebDavAccount {
    pub fn from_state(state: &ShellState) -> Self {
        Self {
            url: state.webdav_url.clone(),
            username: state.webdav_user.clone(),
            password: state.webdav_password.clone(),
        }
    }

    /// `<server>/billow/`; the folder is created on demand by
    /// [`test_connection`] and [`upload`].
    pub fn directory(&self) -> Result<String, String> {
        let raw = self.url.trim();
        if raw.is_empty() {
            return Err(i18n::tr(Key::WebdavNoServer).to_string());
        }
        let lower = raw.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            return Err(i18n::tr(Key::WebdavInvalidServer).to_string());
        }
        let mut base = raw.trim_end_matches('/').to_string();
        if !base.to_ascii_lowercase().ends_with(&format!("/{REMOTE_DIR}")) {
            base.push('/');
            base.push_str(REMOTE_DIR);
        }
        base.push('/');
        Ok(base)
    }

    fn authorization(&self) -> Option<String> {
        if self.username.is_empty() && self.password.is_empty() {
            return None;
        }
        let raw = format!("{}:{}", self.username, self.password);
        Some(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        ))
    }
}

/// One backup file found in the cloud folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteBackup {
    /// File name inside the folder, used to fetch it again.
    pub name: String,
    /// Device name recovered from the file name.
    pub device: String,
    /// Server `getlastmodified` text, shown as is.
    pub modified: Option<String>,
    pub size: Option<u64>,
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(30))
        .timeout_write(Duration::from_secs(30))
        .redirects(3)
        // A WebDAV server is reached directly; an environment proxy would hide
        // the real authentication failure behind a local error.
        .try_proxy_from_env(false)
        // A handful of calls per user action: a fresh connection each time is
        // cheaper than handling servers that close idle sockets between them.
        .max_idle_connections(0)
        .max_idle_connections_per_host(0)
        .build()
}

fn request(agent: &ureq::Agent, method: &str, url: &str, account: &WebDavAccount) -> ureq::Request {
    let request = agent.request(method, url).set("User-Agent", "Billow");
    match account.authorization() {
        Some(value) => request.set("Authorization", &value),
        None => request,
    }
}

fn status_error(status: u16) -> String {
    if status == 401 || status == 403 {
        i18n::tr_args(Key::WebdavAuthFailed, &[("status", &status.to_string())])
    } else {
        i18n::tr_args(Key::WebdavRequestFailed, &[("status", &status.to_string())])
    }
}

fn network_error(error: ureq::Transport) -> String {
    i18n::tr_args(Key::WebdavUnreachable, &[("reason", &error.to_string())])
}

fn transport(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(status, _) => status_error(status),
        ureq::Error::Transport(error) => network_error(error),
    }
}

fn drain(response: ureq::Response) {
    let mut reader = response.into_reader().take(MAX_BODY);
    let mut sink = Vec::new();
    let _ = reader.read_to_end(&mut sink);
}

/// Make sure the folder exists. A server that refuses MKCOL because the folder
/// is already there (405) or because it is not allowed to create it is fine: the
/// PROPFIND that follows decides whether the folder is usable.
fn ensure_directory(agent: &ureq::Agent, directory: &str, account: &WebDavAccount) -> Result<(), String> {
    match request(agent, "MKCOL", directory, account).call() {
        Ok(response) => {
            drain(response);
            Ok(())
        }
        Err(ureq::Error::Status(status, _)) if status == 401 || status == 403 => {
            Err(status_error(status))
        }
        Err(ureq::Error::Transport(error)) => Err(network_error(error)),
        // 404 / 409: the parent path does not exist, so the folder cannot be made.
        Err(ureq::Error::Status(status, _)) if status == 404 || status == 409 => Err(
            i18n::tr_args(Key::WebdavDirectoryFailed, &[("status", &status.to_string())]),
        ),
        // 405 means it is already there; any other refusal is left to PROPFIND.
        Err(ureq::Error::Status(_, _)) => Ok(()),
    }
}

/// "Test connection": create the folder when needed, then read it with
/// PROPFIND. Only a success here marks WebDAV as usable in the UI.
pub fn test_connection(account: &WebDavAccount) -> Result<(), String> {
    let directory = account.directory()?;
    let agent = agent();
    ensure_directory(&agent, &directory, account)?;
    let response = request(&agent, "PROPFIND", &directory, account)
        .set("Depth", "0")
        .set("Content-Type", "application/xml; charset=utf-8")
        .send_string(PROPFIND_BODY)
        .map_err(transport)?;
    drain(response);
    Ok(())
}

/// Upload one backup file. Returns the file name now in the folder.
pub fn upload(account: &WebDavAccount, text: &str, now_ms: u64) -> Result<String, String> {
    let directory = account.directory()?;
    let agent = agent();
    ensure_directory(&agent, &directory, account)?;
    let name = remote_file_name(&device_name(), now_ms);
    let url = format!("{directory}{name}");
    let response = request(&agent, "PUT", &url, account)
        .set("Content-Type", "application/json; charset=utf-8")
        .send_string(text)
        .map_err(transport)?;
    drain(response);
    Ok(name)
}

const PROPFIND_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:getlastmodified/><d:getcontentlength/></d:prop></d:propfind>"#;

/// List the backups in the folder, newest first.
pub fn list(account: &WebDavAccount) -> Result<Vec<RemoteBackup>, String> {
    let directory = account.directory()?;
    let agent = agent();
    ensure_directory(&agent, &directory, account)?;
    let response = request(&agent, "PROPFIND", &directory, account)
        .set("Depth", "1")
        .set("Content-Type", "application/xml; charset=utf-8")
        .send_string(PROPFIND_BODY)
        .map_err(transport)?;
    let mut body = String::new();
    response
        .into_reader()
        .take(MAX_BODY)
        .read_to_string(&mut body)
        .map_err(|_| i18n::tr(Key::WebdavRequestFailed))?;
    let mut items = parse_listing(&body);
    // Newest first: the name ends with `-YYYYMMDD-HHMMSS.json`, so its tail
    // compares chronologically even across devices.
    items.sort_by(|a, b| stamp_of(&b.name).cmp(stamp_of(&a.name)).then_with(|| a.name.cmp(&b.name)));
    Ok(items)
}

/// The `YYYYMMDD-HHMMSS` tail of a backup file name, byte-safe.
fn stamp_of(name: &str) -> &str {
    let cut = name.len().saturating_sub(20);
    name.get(cut..).unwrap_or(name)
}

/// Download one backup by the file name the listing returned.
pub fn download(account: &WebDavAccount, name: &str) -> Result<String, String> {
    let directory = account.directory()?;
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(i18n::tr(Key::WebdavUnknownBackup).to_string());
    }
    let agent = agent();
    let url = format!("{directory}{name}");
    match request(&agent, "GET", &url, account).call() {
        Ok(response) => {
            let mut text = String::new();
            response
                .into_reader()
                .take(MAX_BODY)
                .read_to_string(&mut text)
                .map_err(|_| i18n::tr(Key::WebdavRequestFailed))?;
            Ok(text)
        }
        Err(ureq::Error::Status(404, _)) => Err(i18n::tr(Key::WebdavUnknownBackup).to_string()),
        Err(error) => Err(transport(error)),
    }
}

/// Collect `response` blocks from a `multistatus` answer, keeping only Billow
/// backup file names. `local_name` ignores the server's namespace prefixes.
pub fn parse_listing(body: &str) -> Vec<RemoteBackup> {
    struct Block {
        href: String,
        modified: Option<String>,
        size: Option<u64>,
    }
    let mut reader = Reader::from_str(body);
    let mut blocks: Vec<Block> = Vec::new();
    let mut current: Option<Block> = None;
    let mut capture: Option<&'static str> = None;
    let mut text = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => match event.local_name().as_ref() {
                "response" => current = Some(Block { href: String::new(), modified: None, size: None }),
                "href" => {
                    capture = Some("href");
                    text.clear();
                }
                "getlastmodified" => {
                    capture = Some("modified");
                    text.clear();
                }
                "getcontentlength" => {
                    capture = Some("size");
                    text.clear();
                }
                _ => {}
            },
            Ok(Event::Text(event)) => {
                if capture.is_some() {
                    text.push_str(event.as_ref());
                }
            }
            Ok(Event::End(event)) => match event.local_name().as_ref() {
                "href" | "getlastmodified" | "getcontentlength" => {
                    if let (Some(field), Some(block)) = (capture.take(), current.as_mut()) {
                        let value = quick_xml::escape::unescape(&text)
                            .map(|text| text.into_owned())
                            .unwrap_or_else(|_| text.clone());
                        match field {
                            "href" => block.href = value,
                            "modified" => block.modified = Some(value.trim().to_string()),
                            _ => block.size = value.trim().parse().ok(),
                        }
                    }
                    text.clear();
                }
                "response" => {
                    if let Some(block) = current.take()
                        && let Some(name) = file_name_of(&block.href)
                    {
                        blocks.push(Block { href: name, ..block });
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    blocks
        .into_iter()
        .map(|block| RemoteBackup {
            device: device_of(&block.href),
            name: block.href,
            modified: block.modified,
            size: block.size,
        })
        .collect()
}

/// Keep the last path segment of an `href` and undo percent-encoding.
fn file_name_of(href: &str) -> Option<String> {
    let path = href.split(['?', '#']).next().unwrap_or(href);
    let segment = path.trim_end_matches('/').rsplit('/').next()?;
    let name = percent_decode(segment);
    let name = name.trim();
    if !name.starts_with(NAME_PREFIX) || !name.ends_with(".json") || name.len() <= NAME_PREFIX.len() {
        return None;
    }
    Some(name.to_string())
}

fn device_of(name: &str) -> String {
    let tail = name
        .strip_prefix(NAME_PREFIX)
        .and_then(|tail| tail.strip_suffix(".json"))
        .unwrap_or_default();
    // `<device>-YYYYMMDD-HHMMSS`: the stamp is always the last 15 characters.
    if tail.len() <= 15 {
        return String::new();
    }
    let cut = tail.len() - 15;
    if !tail.is_char_boundary(cut) {
        return String::new();
    }
    tail[..cut].trim_end_matches('-').to_string()
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
            if let Some(byte) = hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ─────────────────────────── Tests ───────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn sample_profile_backup() -> ProfileBackup {
        let file = r#"{
          "next_id": 3,
          "active_id": "p1",
          "profiles": [
            {
              "id": "p1",
              "name": "机场 A",
              "kind": "subscription",
              "source": "https://example.com/sub",
              "user_agent": "clash.meta",
              "content": "mixed-port: 7890\nproxies: []\n",
              "override_text": "rules:\n  - MATCH,DIRECT\n",
              "applied_override": "",
              "selected": {"G": "香港 01"},
              "interval_hours": 12,
              "age_key": "AGE-SECRET-KEY-1EXAMPLE"
            }
          ],
          "settings": {"mixed_port": 7890, "test_url": "https://example.com"},
          "tun_wanted": true,
          "excluded_packages": ["com.example.app"],
          "included_packages": [],
          "app_mode": "exclude",
          "chosen_mode": "rule"
        }"#;
        serde_json::from_str(file).unwrap()
    }

    fn sample_shell() -> ShellState {
        ShellState {
            theme: "dark".to_string(),
            close_to_tray: false,
            silent_start: true,
            release_ui_on_close: true,
            language: "en".to_string(),
            auto_exit_ip: true,
            hotkeys: [("proxy".to_string(), "Ctrl+Alt+P".to_string())].into_iter().collect(),
            traffic_history: true,
            ..ShellState::default()
        }
    }

    fn sample_file() -> BackupFile {
        compose(
            sample_profile_backup(),
            &sample_shell(),
            "0.1.33",
            "desktop",
            "test-pc",
            1_700_000_000_000,
        )
    }

    #[test]
    fn a_backup_round_trips_and_leaves_sensitive_or_runtime_data_out() {
        let text = to_text(&sample_file()).unwrap();
        let parsed = parse(&text, "0.1.33").unwrap();
        assert_eq!(parsed, sample_file());
        assert_eq!(parsed.profiles.profiles[0].source, "https://example.com/sub");
        assert!(parsed.profiles.profiles[0].content.contains("mixed-port"));
        assert_eq!(parsed.profiles.profiles[0].age_key, "AGE-SECRET-KEY-1EXAMPLE");
        assert_eq!(parsed.profiles.settings.mixed_port, Some(7890));
        assert_eq!(parsed.shell.theme, "dark");
        assert!(!parsed.shell.close_to_tray);
        // Every behaviour switch travels with the file (R38, R40, R43, R44).
        assert!(parsed.shell.release_ui_on_close);
        assert!(parsed.shell.auto_exit_ip);
        assert!(parsed.shell.traffic_history, "the recording switch is an app setting (R43)");
        // Global shortcuts travel too, so a cleared restore brings them back
        // (R39); only a cross-platform restore keeps this machine's.
        assert_eq!(parsed.shell.hotkeys.get("proxy").map(String::as_str), Some("Ctrl+Alt+P"));
        // WebDAV credentials, window size, traffic history rows and the current
        // page are not part of a backup.
        let mut state = sample_shell();
        state.webdav_url = "https://dav.example.com/billow/".to_string();
        state.webdav_password = "dav-secret".to_string();
        let with_dav = compose(
            sample_profile_backup(),
            &state,
            "0.1.33",
            "desktop",
            "test-pc",
            1_700_000_000_000,
        );
        let text = to_text(&with_dav).unwrap();
        for absent in [
            "dav-secret",
            "dav.example.com",
            "\"width\"",
            "\"height\"",
            "\"last_entry\"",
            "traffic-history",
            "\"entries\"",
        ] {
            assert!(!text.contains(absent), "{absent} must not be in a backup:\n{text}");
        }
        assert_eq!(with_dav.shell, ShellBackup::of(&sample_shell()));
    }

    #[test]
    fn newer_damaged_and_unrecognised_files_are_rejected_with_a_reason() {
        let text = to_text(&sample_file()).unwrap();

        let unknown = parse("not json at all", "0.1.33").unwrap_err();
        assert!(unknown.contains("无法识别"), "{unknown}");
        let wrong_format = parse(r#"{"format":"something-else","version":1}"#, "0.1.33").unwrap_err();
        assert!(wrong_format.contains("无法识别"), "{wrong_format}");
        let array = parse("[1,2,3]", "0.1.33").unwrap_err();
        assert!(array.contains("无法识别"), "{array}");

        let newer = text.replace("\"version\": 1", "\"version\": 2");
        let reason = parse(&newer, "0.1.33").unwrap_err();
        assert!(reason.contains("更新的版本"), "{reason}");

        let newer_app = text.replace("\"app_version\": \"0.1.33\"", "\"app_version\": \"0.2.0\"");
        let reason = parse(&newer_app, "0.1.33").unwrap_err();
        assert!(reason.contains("更新的版本") && reason.contains("0.2.0"), "{reason}");

        let same_app = text.replace("\"app_version\": \"0.1.33\"", "\"app_version\": \"0.1.33-beta.1\"");
        assert!(parse(&same_app, "0.1.33").is_ok(), "a pre-release of this version is not newer");

        // A missing block or a wrong type is a damaged file, never a partial restore.
        let no_profiles = r#"{"format":"billow-backup","version":1,"app_version":"0.1.33","platform":"desktop","shell":{}}"#;
        let reason = parse(no_profiles, "0.1.33").unwrap_err();
        assert!(reason.contains("损坏"), "{reason}");
        let broken_entry = text.replace("\"kind\": \"subscription\"", "\"kind\": \"mystery\"");
        let reason = parse(&broken_entry, "0.1.33").unwrap_err();
        assert!(reason.contains("损坏"), "{reason}");
        let broken_content = text.replace(
            "\"content\": \"mixed-port: 7890\\nproxies: []\\n\",",
            "\"content\": 42,",
        );
        assert_ne!(broken_content, text, "the sample keeps content in the test");
        let reason = parse(&broken_content, "0.1.33").unwrap_err();
        assert!(reason.contains("损坏"), "{reason}");
    }

    #[test]
    fn restoring_another_platform_keeps_this_machines_platform_settings() {
        let mut file = sample_file();
        file.platform = "android".to_string();
        let mut local = sample_profile_backup();
        local.settings.tun.mtu = 1420;
        local.settings.tun.device = "BillowTest".to_string();
        local.settings.system_proxy.mode = "pac".to_string();
        local.excluded_packages = vec!["com.local.app".to_string()];
        local.included_packages = vec!["com.local.only".to_string()];
        local.app_mode = "include".to_string();
        local.tun_wanted = false;
        let local_shell = ShellState {
            close_to_tray: true,
            silent_start: false,
            release_ui_on_close: false,
            auto_exit_ip: false,
            hotkeys: [("tun".to_string(), "Ctrl+Alt+T".to_string())].into_iter().collect(),
            ..sample_shell()
        };

        assert!(merge_platform(&mut file, "desktop", &local, &local_shell));
        assert_eq!(file.profiles.settings.tun, local.settings.tun);
        assert_eq!(file.profiles.settings.system_proxy, local.settings.system_proxy);
        assert!(!file.profiles.tun_wanted);
        assert_eq!(file.profiles.excluded_packages, ["com.local.app"]);
        assert_eq!(file.profiles.included_packages, ["com.local.only"]);
        assert_eq!(file.profiles.app_mode, "include");
        assert!(file.shell.close_to_tray);
        assert!(!file.shell.silent_start);
        // Lightweight mode is a desktop window behaviour and stays this machine's.
        assert!(!file.shell.release_ui_on_close);
        // Auto-query is a plain preference, so the backup keeps its value.
        assert!(file.shell.auto_exit_ip);
        // Shortcuts are this machine's, so the file's binding is replaced (R39).
        assert_eq!(file.shell.hotkeys, local_shell.hotkeys);
        assert!(file.shell.hotkeys.get("proxy").is_none());
        // The recording switch is a plain app setting, so it still travels (R43).
        assert!(file.shell.traffic_history);
        // Configuration and 覆写 still come from the backup.
        assert_eq!(file.profiles.profiles[0].name, "机场 A");
        assert_eq!(file.platform, "desktop");

        // The same platform restores everything as written.
        let mut same = sample_file();
        let before = same.clone();
        assert!(!merge_platform(&mut same, "desktop", &local, &local_shell));
        assert_eq!(same, before);
    }

    #[test]
    fn file_names_carry_the_stamp_and_the_device() {
        let now = 1_700_000_000_000; // 2023-11-14T22:13:20Z
        assert_eq!(local_file_name(now), "billow-backup-20231114-221320.json");
        assert_eq!(remote_file_name("My PC", now), "billow-backup-my-pc-20231114-221320.json");
        assert_eq!(remote_file_name("  ", now), "billow-backup-billow-20231114-221320.json");
        assert_eq!(sanitize_device("DESKTOP-告示牌"), "desktop");
        assert_eq!(sanitize_device("a_b.c"), "a_b.c");
    }

    #[test]
    fn a_listing_keeps_backup_files_and_ignores_everything_else() {
        let body = r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response><d:href>/dav/billow/</d:href><d:propstat><d:prop><d:getlastmodified>Tue, 14 Nov 2023 22:13:20 GMT</d:getlastmodified></d:prop></d:propstat></d:response>
  <d:response><d:href>/dav/billow/billow-backup-my%20pc-20231114-221320.json</d:href>
    <d:propstat><d:prop><d:getlastmodified>Tue, 14 Nov 2023 22:13:20 GMT</d:getlastmodified>
    <d:getcontentlength>2048</d:getcontentlength></d:prop></d:propstat></d:response>
  <d:response><d:href>/dav/billow/notes.txt</d:href><d:propstat><d:prop/></d:propstat></d:response>
  <d:response><d:href>/dav/billow/billow-backup-%E8%AE%BE%E5%A4%87-20230101-000000.json</d:href>
    <d:propstat><d:prop><d:getcontentlength>10</d:getcontentlength></d:prop></d:propstat></d:response>
</d:multistatus>"#;
        let mut items = parse_listing(body);
        // Newest first, even when a device name is not ASCII.
        items.sort_by(|a, b| stamp_of(&b.name).cmp(stamp_of(&a.name)));
        assert_eq!(items.len(), 2, "{items:?}");
        assert_eq!(items[0].name, "billow-backup-my pc-20231114-221320.json");
        assert_eq!(items[0].device, "my pc");
        assert_eq!(items[0].size, Some(2048));
        assert_eq!(items[0].modified.as_deref(), Some("Tue, 14 Nov 2023 22:13:20 GMT"));
        assert_eq!(items[1].name, "billow-backup-设备-20230101-000000.json");
        assert_eq!(items[1].device, "设备");
        assert_eq!(items[1].size, Some(10));
    }

    // ── Local mock WebDAV server: MKCOL, PUT, PROPFIND and GET ──

    #[derive(Default)]
    struct DavState {
        folder: bool,
        files: BTreeMap<String, Vec<u8>>,
        require: Option<String>,
        requests: Vec<String>,
    }

    struct MockDav {
        url: String,
        state: Arc<Mutex<DavState>>,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl MockDav {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let state = Arc::new(Mutex::new(DavState::default()));
            let stop = Arc::new(AtomicBool::new(false));
            let thread_state = Arc::clone(&state);
            let thread_stop = Arc::clone(&stop);
            let handle = thread::spawn(move || {
                while !thread_stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            // Windows accepts inherit the listener's non-blocking mode; a
                            // non-blocking read here closes the socket before the client
                            // finishes sending and surfaces as a sporadic reset.
                            let _ = stream.set_nonblocking(false);
                            serve(stream, &thread_state);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self { url, state, stop, handle: Some(handle) }
        }

        fn methods(&self) -> Vec<String> {
            self.state.lock().unwrap().requests.clone()
        }
    }

    impl Drop for MockDav {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn serve(mut stream: TcpStream, state: &Arc<Mutex<DavState>>) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let mut raw = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    raw.extend_from_slice(&buffer[..count]);
                    if let Some(head) = header_end(&raw) {
                        let head_len = head;
                        let header = String::from_utf8_lossy(&raw[..head_len]).to_string();
                        let length = header
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                if name.eq_ignore_ascii_case("content-length") {
                                    value.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        if raw.len() >= head_len + 4 + length {
                            respond(&mut stream, &header, &raw[head_len + 4..], state);
                            return;
                        }
                    }
                }
                Err(_) => return,
            }
        }
    }

    fn header_end(raw: &[u8]) -> Option<usize> {
        raw.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn respond(stream: &mut TcpStream, header: &str, body: &[u8], state: &Arc<Mutex<DavState>>) {
        let mut lines = header.lines();
        let request_line = lines.next().unwrap_or_default();
        let mut parts = request_line.split(' ');
        let method = parts.next().unwrap_or_default().to_ascii_uppercase();
        let path = parts.next().unwrap_or_default().to_string();
        let authorization = lines.find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("authorization") {
                Some(value.trim().to_string())
            } else {
                None
            }
        });
        let mut state = state.lock().unwrap();
        state.requests.push(format!("{method} {path}"));
        if let Some(required) = state.require.clone()
            && authorization.as_deref() != Some(required.as_str())
        {
            let _ = write!(
                stream,
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"billow\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            return;
        }
        let name = path.rsplit('/').next().unwrap_or_default().to_string();
        let (status, reason, payload, content_type) = match method.as_str() {
            "MKCOL" => {
                if state.folder {
                    ("405", "Method Not Allowed", Vec::new(), "text/plain")
                } else {
                    state.folder = true;
                    ("201", "Created", Vec::new(), "text/plain")
                }
            }
            "PUT" => {
                if !state.folder {
                    ("409", "Conflict", Vec::new(), "text/plain")
                } else {
                    state.files.insert(name, body.to_vec());
                    ("201", "Created", Vec::new(), "text/plain")
                }
            }
            "GET" => match state.files.get(&name) {
                Some(content) => ("200", "OK", content.clone(), "application/json"),
                None => ("404", "Not Found", Vec::new(), "text/plain"),
            },
            "PROPFIND" => {
                if !state.folder {
                    ("404", "Not Found", Vec::new(), "text/plain")
                } else {
                    let mut xml = String::from(
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\">",
                    );
                    xml.push_str("<d:response><d:href>/billow/</d:href><d:propstat><d:prop><d:getlastmodified>Tue, 14 Nov 2023 22:13:20 GMT</d:getlastmodified></d:prop></d:propstat></d:response>");
                    for (file, content) in &state.files {
                        xml.push_str(&format!(
                            "<d:response><d:href>/billow/{file}</d:href><d:propstat><d:prop><d:getlastmodified>Tue, 14 Nov 2023 22:13:20 GMT</d:getlastmodified><d:getcontentlength>{}</d:getcontentlength></d:prop></d:propstat></d:response>",
                            content.len()
                        ));
                    }
                    xml.push_str("</d:multistatus>");
                    ("207", "Multi-Status", xml.into_bytes(), "application/xml")
                }
            }
            _ => ("405", "Method Not Allowed", Vec::new(), "text/plain"),
        };
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(&payload);
        let _ = stream.flush();
    }

    fn account(server: &MockDav, password: &str) -> WebDavAccount {
        WebDavAccount {
            url: server.url.clone(),
            username: "me".to_string(),
            password: password.to_string(),
        }
    }

    fn expected_auth() -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("me:pw")
        )
    }

    #[test]
    fn webdav_tests_uploads_lists_and_downloads_through_a_real_http_exchange() {
        let server = MockDav::start();
        let account = account(&server, "pw");

        test_connection(&account).unwrap();
        let methods = server.methods();
        assert!(methods.iter().any(|entry| entry.starts_with("MKCOL")), "{methods:?}");
        assert!(methods.iter().any(|entry| entry.starts_with("PROPFIND")), "{methods:?}");

        let text = to_text(&sample_file()).unwrap();
        let name = upload(&account, &text, 1_700_000_000_000).unwrap();
        assert!(name.starts_with("billow-backup-") && name.ends_with("-20231114-221320.json"), "{name}");
        assert!(server.methods().iter().any(|entry| entry.starts_with("PUT")), "{:?}", server.methods());

        let items = list(&account).unwrap();
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(items[0].name, name);
        assert_eq!(items[0].size, Some(text.len() as u64));
        assert!(items[0].modified.is_some());

        let downloaded = download(&account, &name).unwrap();
        assert_eq!(downloaded, text);
        assert_eq!(parse(&downloaded, "0.1.33").unwrap(), sample_file());
        assert!(server.methods().iter().any(|entry| entry.starts_with("GET")), "{:?}", server.methods());
    }

    #[test]
    fn a_wrong_password_reports_the_authentication_failure_with_its_status_code() {
        let server = MockDav::start();
        server.state.lock().unwrap().require = Some(expected_auth());
        let wrong = account(&server, "nope");
        let error = test_connection(&wrong).unwrap_err();
        assert!(error.contains("认证失败"), "{error}");
        assert!(error.contains("401"), "{error}");
        // The same reason reaches the upload and list paths.
        assert!(upload(&wrong, "{}", 0).unwrap_err().contains("401"));
        assert!(list(&wrong).unwrap_err().contains("401"));
        assert!(!server.methods().is_empty());

        let right = account(&server, "pw");
        test_connection(&right).unwrap();
    }

    #[test]
    fn a_missing_or_unusable_address_is_named_before_any_request() {
        let empty = WebDavAccount::default();
        assert!(test_connection(&empty).unwrap_err().contains("服务器地址"));
        let bad = WebDavAccount { url: "dav.example.com".to_string(), ..WebDavAccount::default() };
        assert!(test_connection(&bad).unwrap_err().contains("http://"));
        assert_eq!(
            WebDavAccount { url: "https://dav.example.com/remote.php/dav/files/me/".to_string(), ..WebDavAccount::default() }
                .directory()
                .unwrap(),
            "https://dav.example.com/remote.php/dav/files/me/billow/"
        );
        assert_eq!(
            WebDavAccount { url: "https://dav.example.com/billow".to_string(), ..WebDavAccount::default() }
                .directory()
                .unwrap(),
            "https://dav.example.com/billow/"
        );

        // A name outside the backup namespace is never fetched.
        let server = MockDav::start();
        let account = account(&server, "pw");
        assert!(download(&account, "../secrets.json").unwrap_err().contains("云端没有"));
        assert!(download(&account, "billow-backup-missing-20231114-221320.json")
            .unwrap_err()
            .contains("云端没有"));
    }

    #[test]
    fn an_unreachable_server_is_reported_not_silently_ignored() {
        // Bind and drop to get a port nothing listens on.
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let account = WebDavAccount {
            url: format!("http://127.0.0.1:{port}"),
            username: "me".to_string(),
            password: "pw".to_string(),
        };
        let error = test_connection(&account).unwrap_err();
        assert!(error.contains("连不上"), "{error}");
    }

    #[test]
    fn only_this_machines_settings_survive_a_cross_platform_parse() {
        // The merge runs after validation, so the file still parses as written.
        let mut file = parse(&to_text(&sample_file()).unwrap(), "0.1.33").unwrap();
        assert!(merge_platform(&mut file, "android", &sample_profile_backup(), &sample_shell()));
        let text = to_text(&file).unwrap();
        assert_eq!(parse(&text, "0.1.33").unwrap().platform, "android");
    }

    #[test]
    fn a_backup_writes_next_to_the_exports_and_reports_its_path() {
        let directory = std::env::temp_dir().join(format!(
            "billow-backup-export-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = export(&directory, &sample_file(), 1_700_000_000_000).unwrap();
        assert!(path.ends_with("billow-backup-20231114-221320.json"), "{}", path.display());
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(parse(&text, "0.1.33").unwrap().profiles.profiles.len(), 1);
        let _ = fs::remove_dir_all(&directory);
    }
}
