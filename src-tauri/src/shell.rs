use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const DEFAULT_WIDTH: f64 = 960.0;
pub const DEFAULT_HEIGHT: f64 = 680.0;
pub const MIN_WIDTH: f64 = 360.0;
pub const MIN_HEIGHT: f64 = 480.0;
const MAX_EDGE: f64 = 10000.0;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShellState {
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_entry")]
    pub last_entry: String,
    #[serde(default = "default_width")]
    pub width: f64,
    #[serde(default = "default_height")]
    pub height: f64,
    #[serde(default = "default_true")]
    pub close_to_tray: bool,
    #[serde(default)]
    pub silent_start: bool,
    /// Release the main webview when the window is closed to give its memory
    /// back (R44). Only has an effect while `close_to_tray` is on, where the
    /// window would otherwise stay hidden instead of closing; off by default.
    #[serde(default)]
    pub release_ui_on_close: bool,
    /// UI language preference: `system`, `zh-CN` or `en` (R42).
    #[serde(default = "default_language")]
    pub language: String,
    /// WebDAV backup storage (R38). Plain text like the age identities; never
    /// written to a backup file, so an imported file cannot repoint it.
    #[serde(default)]
    pub webdav_url: String,
    #[serde(default)]
    pub webdav_user: String,
    #[serde(default)]
    pub webdav_password: String,
    /// Desktop global shortcut per action id (R39). Machine specific, so it is
    /// not part of a backup; nothing is bound by default.
    #[serde(default)]
    pub hotkeys: BTreeMap<String, String>,
    /// Query the exit IP automatically after connecting or switching (R40).
    /// Off by default; the tray and background tasks never query.
    #[serde(default)]
    pub auto_exit_ip: bool,
    /// Keep a daily traffic history per profile, group and node (R43). Off by
    /// default; turning it off leaves the existing history in place.
    #[serde(default)]
    pub traffic_history: bool,
}

fn default_true() -> bool {
    true
}

fn default_theme() -> String {
    "system".to_string()
}

fn default_language() -> String {
    "system".to_string()
}

fn default_entry() -> String {
    "home".to_string()
}

fn default_width() -> f64 {
    DEFAULT_WIDTH
}

fn default_height() -> f64 {
    DEFAULT_HEIGHT
}

impl Default for ShellState {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            last_entry: default_entry(),
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            close_to_tray: true,
            silent_start: false,
            release_ui_on_close: false,
            language: default_language(),
            webdav_url: String::new(),
            webdav_user: String::new(),
            webdav_password: String::new(),
            hotkeys: BTreeMap::new(),
            auto_exit_ip: false,
            traffic_history: false,
        }
    }
}

/// The app settings a backup carries (R38). Window size, the last page, the
/// WebDAV account and the global shortcuts are machine specific and stay out of
/// the file; a restore keeps this machine's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShellBackup {
    pub theme: String,
    pub close_to_tray: bool,
    pub silent_start: bool,
    /// Lightweight mode travels with "stay in tray" (R44).
    pub release_ui_on_close: bool,
    pub language: String,
    /// Automatic exit IP queries are a behaviour preference, not a machine
    /// detail, so they travel with the theme and language (R40).
    pub auto_exit_ip: bool,
    // Traffic history is deliberately absent: importing a file must never start
    // background recording, and its rows are excluded outright (R38, R43).
}

impl Default for ShellBackup {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            close_to_tray: true,
            silent_start: false,
            release_ui_on_close: false,
            language: default_language(),
            auto_exit_ip: false,
        }
    }
}

impl ShellBackup {
    pub fn of(state: &ShellState) -> Self {
        Self {
            theme: state.theme.clone(),
            close_to_tray: state.close_to_tray,
            silent_start: state.silent_start,
            release_ui_on_close: state.release_ui_on_close,
            language: state.language.clone(),
            auto_exit_ip: state.auto_exit_ip,
        }
    }

    /// Apply these settings onto the current state. Everything a backup leaves
    /// out is taken from `current`, so a restore never moves the window or
    /// replaces the WebDAV account configured on this machine.
    pub fn apply(&self, current: &ShellState) -> ShellState {
        ShellState {
            theme: resolve_theme(&self.theme).to_string(),
            close_to_tray: self.close_to_tray,
            silent_start: self.silent_start,
            release_ui_on_close: self.release_ui_on_close,
            language: resolve_language(&self.language).to_string(),
            auto_exit_ip: self.auto_exit_ip,
            ..current.clone()
        }
    }
}

pub fn resolve_entry(value: &str) -> &'static str {
    match value {
        "home" => "home",
        "nodes" | "proxies" => "proxies",
        "profiles" => "profiles",
        "connections" => "connections",
        "rules" => "rules",
        "resources" => "resources",
        "logs" => "logs",
        "settings" => "settings",
        // Android only, but a released window or a restored page may ask for it.
        "apps" => "apps",
        _ => "home",
    }
}

/// Closing the window frees the webview only when the window would otherwise
/// stay in the tray (R44). With "stay in tray" off the option is hidden in the
/// settings and must not change what closing does.
pub fn releases_ui_on_close(state: &ShellState) -> bool {
    state.close_to_tray && state.release_ui_on_close
}

pub fn resolve_theme(value: &str) -> &'static str {
    match value {
        "system" => "system",
        "light" => "light",
        "dark" => "dark",
        _ => "system",
    }
}

/// Only two languages exist (R46): anything unknown follows the system again.
pub fn resolve_language(value: &str) -> &'static str {
    match value {
        "zh-CN" => "zh-CN",
        "en" => "en",
        _ => "system",
    }
}

pub fn usable_window_size(width: f64, height: f64) -> Option<(f64, f64)> {
    if !width.is_finite() || !height.is_finite() {
        return None;
    }
    if width < MIN_WIDTH || height < MIN_HEIGHT || width > MAX_EDGE || height > MAX_EDGE {
        return None;
    }
    Some((width, height))
}

pub fn normalize(mut state: ShellState) -> ShellState {
    state.theme = resolve_theme(&state.theme).to_string();
    state.last_entry = resolve_entry(&state.last_entry).to_string();
    state.language = resolve_language(&state.language).to_string();
    state.webdav_url = clean_field(&state.webdav_url, 500, true);
    state.webdav_user = clean_field(&state.webdav_user, 200, true);
    // A password may legitimately hold spaces, so only control characters go.
    state.webdav_password = clean_field(&state.webdav_password, 500, false);
    state.hotkeys = crate::hotkeys::clean_bindings(&state.hotkeys);
    if usable_window_size(state.width, state.height).is_none() {
        state.width = DEFAULT_WIDTH;
        state.height = DEFAULT_HEIGHT;
    }
    state
}

fn clean_field(raw: &str, limit: usize, trim: bool) -> String {
    let value: String = raw.chars().filter(|ch| !ch.is_control()).take(limit).collect();
    if trim { value.trim().to_string() } else { value }
}

pub fn read_shell_state(path: &Path) -> ShellState {
    let Ok(text) = fs::read_to_string(path) else {
        return ShellState::default();
    };
    match serde_json::from_str::<ShellState>(&text) {
        Ok(state) => normalize(state),
        Err(_) => ShellState::default(),
    }
}

pub fn write_shell_state(path: &Path, state: &ShellState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
    }
    let data = serde_json::to_vec_pretty(&normalize(state.clone())).map_err(|err| err.to_string())?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, data).map_err(|err| err.to_string())?;
    fs::rename(&temporary, path).map_err(|err| err.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_file(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("billow-{name}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        (dir.clone(), dir.join("shell-state.json"))
    }

    #[test]
    fn unknown_entry_returns_home_and_unknown_theme_follows_system() {
        assert_eq!(resolve_entry("nodes"), "proxies");
        assert_eq!(resolve_entry("settings"), "settings");
        assert_eq!(resolve_entry("logs"), "logs");
        // The tool pages keep their own page instead of falling back to home,
        // so a released window can come back where it was (R44).
        assert_eq!(resolve_entry("resources"), "resources");
        assert_eq!(resolve_entry("apps"), "apps");
        assert_eq!(resolve_entry("diagnostics"), "home");
        assert_eq!(resolve_entry("theme"), "home");
        assert_eq!(resolve_theme("dark"), "dark");
        assert_eq!(resolve_theme("light"), "light");
        assert_eq!(resolve_theme("blue"), "system");
        assert_eq!(resolve_language("zh-CN"), "zh-CN");
        assert_eq!(resolve_language("en"), "en");
        assert_eq!(resolve_language("zh-TW"), "system");
        assert_eq!(resolve_language("en-US"), "system");
    }

    #[test]
    fn an_older_state_without_a_language_follows_the_system() {
        let state: ShellState = serde_json::from_str(r#"{"theme":"dark"}"#).unwrap();
        assert_eq!(state.language, "system");
        assert_eq!(state.last_entry, "home");
        assert!(state.close_to_tray);
        // Lightweight mode is off until the user turns it on (R44).
        assert!(!state.release_ui_on_close);
        // Automatic exit IP queries are off until the user turns them on (R40).
        assert!(!state.auto_exit_ip);
        // Traffic history is recorded only after the user opts in (R43).
        assert!(!state.traffic_history);
    }

    #[test]
    fn releasing_the_ui_needs_stay_in_tray() {
        let mut state = ShellState { release_ui_on_close: true, ..ShellState::default() };
        assert!(releases_ui_on_close(&state));
        // Without "stay in tray" the option is hidden and does nothing: closing
        // still ends the app instead of leaving the kernel running alone (R44).
        state.close_to_tray = false;
        assert!(!releases_ui_on_close(&state));
        state.close_to_tray = true;
        state.release_ui_on_close = false;
        assert!(!releases_ui_on_close(&state));
    }

    #[test]
    fn unusable_window_size_is_rejected() {
        assert!(usable_window_size(800.0, 600.0).is_some());
        assert!(usable_window_size(0.0, 600.0).is_none());
        assert!(usable_window_size(800.0, f64::NAN).is_none());
        assert!(usable_window_size(10.0, 10.0).is_none());
        assert!(usable_window_size(20_000.0, 600.0).is_none());
    }

    #[test]
    fn corrupt_or_invalid_state_still_opens_with_defaults() {
        let (dir, path) = temporary_file("corrupt");
        fs::write(&path, b"{not json").unwrap();
        assert_eq!(read_shell_state(&path), ShellState::default());

        let mut state = ShellState::default();
        state.theme = "nope".to_string();
        state.last_entry = "diagnostics".to_string();
        state.language = "fr".to_string();
        state.width = 12.0;
        state.height = 12.0;
        write_shell_state(&path, &state).unwrap();
        let loaded = read_shell_state(&path);
        assert_eq!(loaded.theme, "system");
        assert_eq!(loaded.last_entry, "home");
        assert_eq!(loaded.language, "system");
        assert_eq!(loaded.width, DEFAULT_WIDTH);
        assert_eq!(loaded.height, DEFAULT_HEIGHT);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn valid_state_round_trips() {
        let (dir, path) = temporary_file("round");
        let state = ShellState {
            theme: "dark".to_string(),
            last_entry: "proxies".to_string(),
            width: 1024.0,
            height: 700.0,
            close_to_tray: false,
            silent_start: true,
            release_ui_on_close: true,
            language: "en".to_string(),
            webdav_url: " https://dav.example.com/remote.php/dav/files/me ".to_string(),
            webdav_user: "me".to_string(),
            webdav_password: "p a s s".to_string(),
            hotkeys: [("proxy".to_string(), "Ctrl+Alt+P".to_string())].into_iter().collect(),
            auto_exit_ip: true,
            traffic_history: true,
        };
        write_shell_state(&path, &state).unwrap();
        let loaded = read_shell_state(&path);
        assert_eq!(loaded.theme, "dark");
        assert_eq!(loaded.last_entry, "proxies");
        assert_eq!(loaded.width, 1024.0);
        assert_eq!(loaded.close_to_tray, false);
        assert_eq!(loaded.silent_start, true);
        assert!(loaded.release_ui_on_close);
        assert!(loaded.auto_exit_ip);
        assert!(loaded.traffic_history);
        assert_eq!(loaded.language, "en");
        assert_eq!(loaded.hotkeys.get("proxy").map(String::as_str), Some("Ctrl+Alt+P"));
        // Saved as typed, trimmed, with spaces inside the password kept.
        assert_eq!(loaded.webdav_url, "https://dav.example.com/remote.php/dav/files/me");
        assert_eq!(loaded.webdav_user, "me");
        assert_eq!(loaded.webdav_password, "p a s s");
        assert_eq!(read_shell_state(Path::new("/missing/billow-shell-state.json")).last_entry, "home");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_backup_applies_app_settings_and_keeps_what_it_leaves_out() {
        let current = ShellState {
            width: 1280.0,
            height: 800.0,
            last_entry: "logs".to_string(),
            // This machine has both switches off; the backup turns them on.
            release_ui_on_close: false,
            auto_exit_ip: false,
            webdav_url: "https://dav.example.com/billow/".to_string(),
            webdav_user: "me".to_string(),
            webdav_password: "secret".to_string(),
            ..ShellState::default()
        };
        let backup: ShellBackup = serde_json::from_str(
            r#"{"theme":"dark","close_to_tray":false,"silent_start":true,"release_ui_on_close":true,"language":"en","auto_exit_ip":true}"#,
        )
        .unwrap();
        let restored = backup.apply(&current);
        assert_eq!(restored.theme, "dark");
        assert!(!restored.close_to_tray);
        assert!(restored.silent_start);
        assert_eq!(restored.language, "en");
        // Both behaviour switches travel with the backup (R38, R40, R44).
        assert!(restored.release_ui_on_close);
        assert!(restored.auto_exit_ip);
        // Excluded from every backup: window size, current page and WebDAV credentials.
        assert_eq!(restored.width, 1280.0);
        assert_eq!(restored.height, 800.0);
        assert_eq!(restored.last_entry, "logs");
        assert_eq!(restored.webdav_url, "https://dav.example.com/billow/");
        assert_eq!(restored.webdav_password, "secret");

        // Export -> clear -> import brings the same switches back.
        let reimported = ShellBackup::of(&restored).apply(&ShellState::default());
        assert!(reimported.release_ui_on_close);
        assert!(reimported.auto_exit_ip);
        assert_eq!(reimported.theme, "dark");

        // Unknown values fall back like every other stored preference.
        let odd: ShellBackup =
            serde_json::from_str(r#"{"theme":"blue","language":"fr"}"#).unwrap();
        assert_eq!(odd.apply(&current).theme, "system");
        assert_eq!(odd.apply(&current).language, "system");
        assert!(odd.close_to_tray, "an omitted flag keeps its default");
        // A backup written before the switches existed leaves them off instead
        // of silently inheriting another machine's choice.
        let switched = ShellState {
            release_ui_on_close: true,
            auto_exit_ip: true,
            ..current.clone()
        };
        assert!(!odd.apply(&switched).release_ui_on_close);
        assert!(!odd.apply(&switched).auto_exit_ip);
        // Traffic recording is never turned on by importing a file (R38, R43).
        let recording = ShellState {
            traffic_history: true,
            ..current.clone()
        };
        assert!(odd.apply(&recording).traffic_history);
        assert!(!backup.apply(&ShellState::default()).traffic_history);
        assert_eq!(ShellBackup::of(&current).theme, "system");
    }

    #[test]
    fn package_window_is_named_billow_and_matches_default_size() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(config["productName"], "Billow");
        assert_eq!(config["app"]["windows"][0]["title"], "Billow");
        assert_eq!(config["app"]["windows"][0]["width"], DEFAULT_WIDTH);
        assert_eq!(config["app"]["windows"][0]["height"], DEFAULT_HEIGHT);
        let license = config["bundle"]["license"].as_str().unwrap();
        assert!(license.contains("GPL-3"));
        let description = config["bundle"]["longDescription"].as_str().unwrap();
        assert!(description.contains("Billow"));
        assert!(description.contains("GPL-3"));
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let permissions = capability["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>();
        assert!(permissions.contains(&"allow-shell-state"));
        assert!(permissions.contains(&"allow-set-theme"));
        assert!(permissions.contains(&"allow-set-language"));
        assert!(permissions.contains(&"allow-set-last-entry"));
        // Exit IP lookup and its opt-in (R40) must stay reachable from the window.
        assert!(permissions.contains(&"allow-exit-ip"));
        assert!(permissions.contains(&"allow-set-exit-ip-auto"));
        // Traffic history and its switch (R43) are reachable from the window too.
        assert!(permissions.contains(&"allow-traffic-history"));
        assert!(permissions.contains(&"allow-set-traffic-history"));
        assert!(permissions.contains(&"allow-clear-traffic-history"));
        // Each capability entry also needs its permission definition, or the
        // command silently drops out of the window.
        assert!(include_str!("../permissions/app.toml").contains("identifier = \"allow-exit-ip\""));
        assert!(
            include_str!("../permissions/shell.toml").contains("identifier = \"allow-set-exit-ip-auto\"")
        );
        assert!(
            include_str!("../permissions/traffic.toml").contains("identifier = \"allow-traffic-history\"")
        );
    }
}
