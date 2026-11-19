//! UI language for the Rust side (R42).
//!
//! Simplified Chinese is the base language: every message has Chinese text and
//! an optional English one, so a missing translation falls back to Chinese
//! instead of an empty string. The locale is a process-wide atomic because the
//! tray and background threads read it outside any window.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    ZhCn,
    En,
}

const ZH_CN: u8 = 0;
const EN: u8 = 1;

static LOCALE: AtomicU8 = AtomicU8::new(ZH_CN);

impl Locale {
    /// `zh`, `zh-CN`, `zh-TW`, … are all Simplified Chinese (R46).
    pub fn from_tag(tag: &str) -> Self {
        if tag.to_ascii_lowercase().starts_with("zh") {
            Self::ZhCn
        } else {
            Self::En
        }
    }

    /// BCP 47 tag handed to the webview (`document.documentElement.lang`).
    pub fn tag(self) -> &'static str {
        match self {
            Self::ZhCn => "zh-CN",
            Self::En => "en",
        }
    }
}

/// The language the operating system reports; anything but Chinese is English.
pub fn system_locale() -> Locale {
    match sys_locale::get_locale() {
        Some(tag) => Locale::from_tag(&tag),
        // Only Chinese resolves to Chinese, so an unknown system language is English.
        None => Locale::En,
    }
}

/// Map a stored preference (`system`, `zh-CN`, `en`) to the effective locale.
pub fn locale_for(preference: &str) -> Locale {
    match preference {
        "zh-CN" => Locale::ZhCn,
        "en" => Locale::En,
        _ => system_locale(),
    }
}

pub fn set_locale(locale: Locale) {
    LOCALE.store(
        match locale {
            Locale::ZhCn => ZH_CN,
            Locale::En => EN,
        },
        Ordering::SeqCst,
    );
}

pub fn locale() -> Locale {
    if LOCALE.load(Ordering::SeqCst) == EN {
        Locale::En
    } else {
        Locale::ZhCn
    }
}

/// Resolve a stored preference, remember it and return the effective locale.
pub fn apply_preference(preference: &str) -> Locale {
    let locale = locale_for(preference);
    set_locale(locale);
    locale
}

/// Chinese text with an optional English translation.
///
/// A missing English text is a normal state while messages are being migrated,
/// so it must fall back to the Chinese one rather than show a key or a blank.
fn pick_text(locale: Locale, zh: &'static str, en: Option<&'static str>) -> &'static str {
    match locale {
        Locale::En => en.unwrap_or(zh),
        Locale::ZhCn => zh,
    }
}

/// UI messages the Rust side renders itself (the tray here; views join in T8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    TrayEmpty,
    TrayNoProfile,
    TrayConnected,
    TrayDisconnected,
    TrayStateConnected,
    TrayStateDisconnected,
    TrayModeSuffix,
    TrayModeRule,
    TrayModeGlobal,
    TrayModeDirect,
    TrayTimeout,
    TrayMoreNodes,
    TrayAllGroups,
    TrayGroups,
    TrayManageProfiles,
    TrayProfile,
    TrayShow,
    TrayAddProfile,
    TrayDisconnect,
    TrayConnect,
    TrayMode,
    TraySystemProxy,
    TrayTun,
    TraySettings,
    TrayQuit,
    BackupUnknown,
    BackupNewer,
    BackupDamaged,
    BackupRestoreFailed,
    BackupExportFailed,
    BackupReactivationFailed,
    WebdavNoServer,
    WebdavInvalidServer,
    WebdavAuthFailed,
    WebdavRequestFailed,
    WebdavUnreachable,
    WebdavDirectoryFailed,
    WebdavUnknownBackup,
    WebdavNotTested,
    HotkeyUnsupported,
    HotkeyWayland,
    HotkeyInvalidCombo,
    HotkeyUnknownAction,
    HotkeyConflict,
    HotkeyFailed,
    HotkeyInactive,
    HotkeyNotifyTitle,
    HotkeyConnect,
    HotkeyWindow,
}

impl Key {
    fn texts(self) -> (&'static str, Option<&'static str>) {
        match self {
            Self::TrayEmpty => ("Billow · 还没有配置", Some("Billow · No profiles yet")),
            Self::TrayNoProfile => ("未选择配置", Some("No profile selected")),
            Self::TrayConnected => ("● 已连接 · {profile}", Some("● Connected · {profile}")),
            Self::TrayDisconnected => ("○ 未连接 · {profile}", Some("○ Disconnected · {profile}")),
            Self::TrayStateConnected => ("已连接", Some("Connected")),
            Self::TrayStateDisconnected => ("未连接", Some("Disconnected")),
            Self::TrayModeSuffix => ("{mode}模式", Some("{mode} mode")),
            Self::TrayModeRule => ("规则", Some("Rule")),
            Self::TrayModeGlobal => ("全局", Some("Global")),
            Self::TrayModeDirect => ("直连", Some("Direct")),
            Self::TrayTimeout => ("  ·  超时", Some("  ·  timeout")),
            Self::TrayMoreNodes => ("其余 {count} 个节点…", Some("{count} more nodes…")),
            Self::TrayAllGroups => ("全部代理组…", Some("All proxy groups…")),
            Self::TrayGroups => ("代理组", Some("Proxy groups")),
            Self::TrayManageProfiles => ("管理配置…", Some("Manage profiles…")),
            Self::TrayProfile => ("配置", Some("Profile")),
            Self::TrayShow => ("显示主界面", Some("Show window")),
            Self::TrayAddProfile => ("添加配置…", Some("Add profile…")),
            Self::TrayDisconnect => ("断开连接", Some("Disconnect")),
            Self::TrayConnect => ("连接", Some("Connect")),
            Self::TrayMode => ("出站模式", Some("Mode")),
            Self::TraySystemProxy => ("系统代理", Some("System proxy")),
            Self::TrayTun => ("TUN 模式", Some("TUN mode")),
            Self::TraySettings => ("设置…", Some("Settings…")),
            Self::TrayQuit => ("退出 Billow", Some("Quit Billow")),
            Self::BackupUnknown => (
                "无法识别这个备份文件，请选择 Billow 导出的备份文件",
                Some("Unrecognised backup file; choose a file exported by Billow"),
            ),
            Self::BackupNewer => (
                "备份来自更新的版本（{version}），请先更新 Billow",
                Some("The backup comes from a newer version ({version}); update Billow first"),
            ),
            Self::BackupDamaged => (
                "备份文件已损坏，无法恢复",
                Some("The backup file is damaged and cannot be restored"),
            ),
            Self::BackupRestoreFailed => (
                "恢复没有完成：{reason}",
                Some("The restore did not complete: {reason}"),
            ),
            Self::BackupExportFailed => (
                "备份没有导出，请检查存储空间",
                Some("The backup was not saved; check the available storage"),
            ),
            Self::BackupReactivationFailed => (
                "恢复后配置没有启用",
                Some("The restored profile did not start"),
            ),
            Self::WebdavNoServer => ("请填写 WebDAV 服务器地址", Some("Enter the WebDAV server address")),
            Self::WebdavInvalidServer => (
                "WebDAV 地址需要以 http:// 或 https:// 开头",
                Some("The WebDAV address must start with http:// or https://"),
            ),
            Self::WebdavAuthFailed => (
                "WebDAV 认证失败（{status}）",
                Some("WebDAV authentication failed ({status})"),
            ),
            Self::WebdavRequestFailed => (
                "WebDAV 请求失败（{status}）",
                Some("WebDAV request failed ({status})"),
            ),
            Self::WebdavUnreachable => (
                "连不上 WebDAV 服务器：{reason}",
                Some("Cannot reach the WebDAV server: {reason}"),
            ),
            Self::WebdavDirectoryFailed => (
                "无法创建 WebDAV 目录（{status}）",
                Some("Cannot create the WebDAV folder ({status})"),
            ),
            Self::WebdavUnknownBackup => (
                "云端没有这份备份，请刷新列表",
                Some("That backup is no longer in the cloud; refresh the list"),
            ),
            Self::WebdavNotTested => (
                "请先测试连接，WebDAV 还不可用",
                Some("Test the connection first; WebDAV is not usable yet"),
            ),
            Self::HotkeyUnsupported => (
                "此系统不支持全局快捷键",
                Some("Global shortcuts are not supported on this system"),
            ),
            Self::HotkeyWayland => (
                "当前 Wayland 会话不支持全局快捷键，请改用 X11 会话",
                Some("Global shortcuts are not available in a Wayland session; use an X11 session"),
            ),
            Self::HotkeyInvalidCombo => (
                "无法识别组合键「{combo}」",
                Some("The key combination “{combo}” was not recognised"),
            ),
            Self::HotkeyUnknownAction => (
                "无法识别的快捷键操作",
                Some("Unknown shortcut action"),
            ),
            Self::HotkeyConflict => (
                "组合键 {combo} 已绑定给「{action}」",
                Some("{combo} is already assigned to {action}"),
            ),
            Self::HotkeyFailed => (
                "系统不允许注册 {combo}，可能已被其他应用占用",
                Some("The system refused {combo}; another application may already use it"),
            ),
            Self::HotkeyInactive => (
                "启动时未能注册，可能已被其他应用占用",
                Some("Could not be registered at startup; another application may already use it"),
            ),
            Self::HotkeyNotifyTitle => ("快捷键操作失败", Some("Shortcut action failed")),
            Self::HotkeyConnect => ("连接 / 断开", Some("Connect / disconnect")),
            Self::HotkeyWindow => ("显示 / 隐藏主窗口", Some("Show / hide window")),
        }
    }
}

/// A message in an explicit locale; tests and background code use this so a
/// switch in one place cannot race another reader.
pub fn tr_at(locale: Locale, key: Key) -> &'static str {
    let (zh, en) = key.texts();
    pick_text(locale, zh, en)
}

/// A message in the current locale.
///
/// The tray passes its locale explicitly instead, so both languages can be
/// rendered in one process; background text added in later tasks uses this.
#[allow(dead_code)]
pub fn tr(key: Key) -> &'static str {
    tr_at(locale(), key)
}

/// A message with `{name}` placeholders replaced, in an explicit locale.
pub fn tr_args_at(locale: Locale, key: Key, args: &[(&str, &str)]) -> String {
    let mut text = tr_at(locale, key).to_string();
    for (name, value) in args {
        text = text.replace(&format!("{{{name}}}"), value);
    }
    text
}

/// A message with `{name}` placeholders replaced, in the current locale.
#[allow(dead_code)]
pub fn tr_args(key: Key, args: &[(&str, &str)]) -> String {
    tr_args_at(locale(), key, args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chinese_variants_are_simplified_and_anything_else_is_english() {
        assert_eq!(Locale::from_tag("zh"), Locale::ZhCn);
        assert_eq!(Locale::from_tag("zh-CN"), Locale::ZhCn);
        assert_eq!(Locale::from_tag("zh-Hant-TW"), Locale::ZhCn);
        assert_eq!(Locale::from_tag("en-US"), Locale::En);
        assert_eq!(Locale::from_tag("de"), Locale::En);
        assert_eq!(locale_for("zh-CN"), Locale::ZhCn);
        assert_eq!(locale_for("en"), Locale::En);
        assert_eq!(locale_for("system"), system_locale());
        assert_eq!(Locale::ZhCn.tag(), "zh-CN");
        assert_eq!(Locale::En.tag(), "en");
    }

    #[test]
    fn a_missing_english_text_falls_back_to_chinese() {
        // The same branch `tr_at(En, …)` takes for an untranslated message.
        assert_eq!(pick_text(Locale::En, "中文文案", None), "中文文案");
        assert_eq!(pick_text(Locale::En, "中文文案", Some("English text")), "English text");
        assert_eq!(pick_text(Locale::ZhCn, "中文文案", Some("English text")), "中文文案");
    }

    #[test]
    fn every_message_has_text_in_both_languages() {
        for key in [
            Key::TrayEmpty,
            Key::TrayNoProfile,
            Key::TrayConnected,
            Key::TrayDisconnected,
            Key::TrayStateConnected,
            Key::TrayStateDisconnected,
            Key::TrayModeSuffix,
            Key::TrayModeRule,
            Key::TrayModeGlobal,
            Key::TrayModeDirect,
            Key::TrayTimeout,
            Key::TrayMoreNodes,
            Key::TrayAllGroups,
            Key::TrayGroups,
            Key::TrayManageProfiles,
            Key::TrayProfile,
            Key::TrayShow,
            Key::TrayAddProfile,
            Key::TrayDisconnect,
            Key::TrayConnect,
            Key::TrayMode,
            Key::TraySystemProxy,
            Key::TrayTun,
            Key::TraySettings,
            Key::TrayQuit,
            Key::BackupUnknown,
            Key::BackupNewer,
            Key::BackupDamaged,
            Key::BackupRestoreFailed,
            Key::BackupExportFailed,
            Key::BackupReactivationFailed,
            Key::WebdavNoServer,
            Key::WebdavInvalidServer,
            Key::WebdavAuthFailed,
            Key::WebdavRequestFailed,
            Key::WebdavUnreachable,
            Key::WebdavDirectoryFailed,
            Key::WebdavUnknownBackup,
            Key::WebdavNotTested,
            Key::HotkeyUnsupported,
            Key::HotkeyWayland,
            Key::HotkeyInvalidCombo,
            Key::HotkeyUnknownAction,
            Key::HotkeyConflict,
            Key::HotkeyFailed,
            Key::HotkeyInactive,
            Key::HotkeyNotifyTitle,
            Key::HotkeyConnect,
            Key::HotkeyWindow,
        ] {
            assert!(!tr_at(Locale::ZhCn, key).trim().is_empty(), "{key:?} has no Chinese text");
            assert!(!tr_at(Locale::En, key).trim().is_empty(), "{key:?} has no English text");
            assert_ne!(tr_at(Locale::ZhCn, key), "{key:?}", "{key:?} renders as a key");
            assert_ne!(tr_at(Locale::En, key), "{key:?}", "{key:?} renders as a key");
        }
    }

    #[test]
    fn placeholders_are_replaced_and_percent_free() {
        let connected = tr_args_at(Locale::ZhCn, Key::TrayConnected, &[("profile", "星河云")]);
        assert!(connected.contains("星河云"));
        assert!(connected.contains("已连接"));
        assert!(!connected.contains("{profile}"));
        let mode = tr_args_at(
            Locale::En,
            Key::TrayModeSuffix,
            &[("mode", tr_at(Locale::En, Key::TrayModeRule))],
        );
        assert_eq!(mode, "Rule mode");
        // The tooltip state words carry no profile placeholder of their own.
        assert_eq!(tr_at(Locale::En, Key::TrayStateConnected), "Connected");
        assert_eq!(tr_at(Locale::ZhCn, Key::TrayStateDisconnected), "未连接");
    }
}
