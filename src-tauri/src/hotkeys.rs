//! Desktop global shortcuts (R39).
//!
//! Every action here is also a tray menu item: both go through the one action
//! dispatcher in `lib.rs`, so a shortcut-triggered switch refreshes the tray and
//! the window exactly like a click does. Bindings live in `shell-state.json`
//! under action ids and nothing is bound by default. A backup carries them so a
//! cleared restore brings them back, while a restore from the other platform
//! keeps this machine's (R38, see `backup::merge_platform`).

use std::collections::BTreeMap;

use serde::Serialize;

use crate::i18n::{self, Key, Locale};

/// One thing a global shortcut can do. The ids are persisted, so they never change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Connect when disconnected, disconnect when connected.
    ToggleConnection,
    SystemProxy,
    Tun,
    ModeRule,
    ModeGlobal,
    ModeDirect,
    /// Show the window, or hide it when it is already in front.
    ToggleWindow,
}

pub const ACTIONS: [Action; 7] = [
    Action::ToggleConnection,
    Action::SystemProxy,
    Action::Tun,
    Action::ModeRule,
    Action::ModeGlobal,
    Action::ModeDirect,
    Action::ToggleWindow,
];

impl Action {
    pub fn id(self) -> &'static str {
        match self {
            Self::ToggleConnection => "connect",
            Self::SystemProxy => "proxy",
            Self::Tun => "tun",
            Self::ModeRule => "mode-rule",
            Self::ModeGlobal => "mode-global",
            Self::ModeDirect => "mode-direct",
            Self::ToggleWindow => "window",
        }
    }

    pub fn parse(id: &str) -> Option<Self> {
        ACTIONS.into_iter().find(|action| action.id() == id)
    }

    /// The outbound mode this action switches to, if it is a mode action.
    pub fn mode(self) -> Option<&'static str> {
        match self {
            Self::ModeRule => Some("rule"),
            Self::ModeGlobal => Some("global"),
            Self::ModeDirect => Some("direct"),
            _ => None,
        }
    }

    pub fn label(self, locale: Locale) -> &'static str {
        let key = match self {
            Self::ToggleConnection => Key::HotkeyConnect,
            Self::SystemProxy => Key::TraySystemProxy,
            Self::Tun => Key::TrayTun,
            Self::ModeRule => Key::TrayModeRule,
            Self::ModeGlobal => Key::TrayModeGlobal,
            Self::ModeDirect => Key::TrayModeDirect,
            Self::ToggleWindow => Key::HotkeyWindow,
        };
        i18n::tr_at(locale, key)
    }
}

/// One binding as the settings page shows it. `active` is false when the system
/// refused a stored combination at startup, which `error` explains.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BindingView {
    pub action: String,
    pub combo: String,
    pub active: bool,
    pub error: Option<String>,
}

/// Everything the settings page needs to render the section.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Settings {
    pub available: bool,
    pub reason: Option<String>,
    pub platform: String,
    pub bindings: Vec<BindingView>,
}

/// Whether this platform can register global shortcuts at all.
///
/// Android and iOS have no desktop shortcut manager, and a Wayland session has
/// no protocol the plugin can use, so the section is disabled instead of
/// silently doing nothing (R39).
pub fn support(os: &str, wayland: bool) -> Result<(), Key> {
    if os == "android" || os == "ios" {
        return Err(Key::HotkeyUnsupported);
    }
    if os == "linux" && wayland {
        return Err(Key::HotkeyWayland);
    }
    Ok(())
}

pub fn wayland_session() -> bool {
    if let Ok(kind) = std::env::var("XDG_SESSION_TYPE") {
        if kind.eq_ignore_ascii_case("wayland") {
            return true;
        }
    }
    std::env::var_os("WAYLAND_DISPLAY").is_some()
}

/// A stored combo with a single spelling, so `ctrl+alt+p` and `Ctrl+Alt+P`
/// cannot both exist. An empty string means "not bound".
#[cfg(desktop)]
pub fn normalize_combo(raw: &str) -> Option<String> {
    use tauri_plugin_global_shortcut::Shortcut;

    let text = raw.trim();
    if text.is_empty() {
        return Some(String::new());
    }
    let shortcut = text.parse::<Shortcut>().ok()?;
    Some(format_shortcut(&shortcut))
}

#[cfg(not(desktop))]
pub fn normalize_combo(raw: &str) -> Option<String> {
    let text = raw.trim();
    if text.is_empty() { Some(String::new()) } else { None }
}

/// `Ctrl+Alt+Shift+Super+Key` order, which is the order the parser wants and the
/// order the settings page shows.
#[cfg(desktop)]
fn format_shortcut(shortcut: &tauri_plugin_global_shortcut::Shortcut) -> String {
    use tauri_plugin_global_shortcut::Modifiers;

    let mut parts: Vec<String> = Vec::with_capacity(5);
    for (flag, name) in [
        (Modifiers::CONTROL, "Ctrl"),
        (Modifiers::ALT, "Alt"),
        (Modifiers::SHIFT, "Shift"),
        (Modifiers::SUPER, "Super"),
    ] {
        if shortcut.mods.contains(flag) {
            parts.push(name.to_string());
        }
    }
    parts.push(key_token(shortcut.key));
    parts.join("+")
}

/// `KeyP` becomes `P` and `Digit1` becomes `1`; every other key keeps its name,
/// which the parser accepts case-insensitively (`Space`, `F5`, `ArrowUp`).
#[cfg(desktop)]
fn key_token(code: tauri_plugin_global_shortcut::Code) -> String {
    let name = format!("{code:?}");
    if let Some(letter) = name.strip_prefix("Key") {
        return letter.to_string();
    }
    if let Some(digit) = name.strip_prefix("Digit") {
        return digit.to_string();
    }
    name
}

/// A combo as the settings page shows it: `Ctrl + Alt + P`.
pub fn display_combo(combo: &str) -> String {
    combo.split('+').filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" + ")
}

fn clean_combo(raw: &str) -> String {
    let text = raw.trim();
    if text.is_empty() {
        return String::new();
    }
    normalize_combo(text).unwrap_or_else(|| text.to_string())
}

/// Keep only known actions with a non-empty, canonically spelled combination.
pub fn clean_bindings(raw: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut bindings = BTreeMap::new();
    for (id, combo) in raw {
        let Some(action) = Action::parse(id) else {
            continue;
        };
        let combo = clean_combo(combo);
        if combo.is_empty() {
            continue;
        }
        bindings.insert(action.id().to_string(), combo);
    }
    bindings
}

/// The other action that already owns `combo`, ignoring `action` itself (R39).
pub fn conflict(
    bindings: &BTreeMap<String, String>,
    action: Action,
    combo: &str,
) -> Option<Action> {
    bindings
        .iter()
        .find(|(id, bound)| id.as_str() != action.id() && bound.eq_ignore_ascii_case(combo))
        .and_then(|(id, _)| Action::parse(id))
}

#[cfg(desktop)]
use tauri::Manager;
use tauri::AppHandle;

#[cfg(desktop)]
fn bindings_of(app: &AppHandle) -> BTreeMap<String, String> {
    let store = app.state::<crate::Store>();
    crate::lock(&store.state).hotkeys.clone()
}

/// The reason global shortcuts are unavailable here, in the current language.
#[cfg(desktop)]
fn unavailable(app: &AppHandle) -> Option<String> {
    if let Err(key) = support(std::env::consts::OS, wayland_session()) {
        return Some(i18n::tr(key).to_string());
    }
    let plugin = app.try_state::<tauri_plugin_global_shortcut::GlobalShortcut<tauri::Wry>>();
    if plugin.is_none() {
        return Some(i18n::tr(Key::HotkeyUnsupported).to_string());
    }
    None
}

#[cfg(desktop)]
fn register(app: &AppHandle, action: Action, combo: &str) -> bool {
    use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};

    let handle = app.clone();
    app.global_shortcut()
        .on_shortcut(combo, move |_app, _shortcut, event| {
            if event.state == ShortcutState::Pressed {
                crate::run_hotkey(&handle, action);
            }
        })
        .is_ok()
}

#[cfg(desktop)]
fn unregister(app: &AppHandle, combo: &str) {
    use tauri_plugin_global_shortcut::GlobalShortcutExt;
    let _ = app.global_shortcut().unregister(combo);
}

#[cfg(desktop)]
fn registered(app: &AppHandle, combo: &str) -> bool {
    use tauri_plugin_global_shortcut::GlobalShortcutExt;
    app.global_shortcut().is_registered(combo)
}

#[cfg(desktop)]
pub fn settings(app: &AppHandle) -> Settings {
    let reason = unavailable(app);
    let bindings = bindings_of(app)
        .into_iter()
        .map(|(id, combo)| {
            let active = reason.is_none() && registered(app, &combo);
            BindingView {
                action: id,
                combo,
                active,
                error: if active || reason.is_some() {
                    None
                } else {
                    Some(i18n::tr(Key::HotkeyInactive).to_string())
                },
            }
        })
        .collect();
    Settings {
        available: reason.is_none(),
        reason,
        platform: std::env::consts::OS.to_string(),
        bindings,
    }
}

#[cfg(not(desktop))]
pub fn settings(app: &AppHandle) -> Settings {
    let _ = app;
    Settings {
        available: false,
        reason: Some(i18n::tr(Key::HotkeyUnsupported).to_string()),
        platform: std::env::consts::OS.to_string(),
        bindings: Vec::new(),
    }
}

/// Whether `set` can keep everything as it is: the stored combination is the
/// requested one and the system still has it registered. A binding the system
/// refused at startup (`active == false`) is not "unchanged", so recording the
/// same combination again retries the registration instead of silently
/// returning an inactive binding (R39).
#[cfg_attr(not(desktop), allow(dead_code))]
fn keep_binding(previous: &str, combo: &str, active: bool) -> bool {
    previous == combo && (combo.is_empty() || active)
}

/// Bind one action to `combo`, or clear it with an empty combo.
///
/// A clash with another action, an unreadable combination and a registration
/// the system refuses all come back as a message and leave the old binding in
/// place, so a rejected edit never disables what already worked (R39).
#[cfg(desktop)]
pub fn set(app: &AppHandle, action_id: &str, combo: &str) -> Result<Settings, String> {
    let Some(action) = Action::parse(action_id) else {
        return Err(i18n::tr(Key::HotkeyUnknownAction).to_string());
    };
    if let Some(reason) = unavailable(app) {
        return Err(reason);
    }
    let Some(combo) = normalize_combo(combo) else {
        return Err(i18n::tr_args(Key::HotkeyInvalidCombo, &[("combo", combo)]));
    };
    let current = bindings_of(app);
    if !combo.is_empty() {
        if let Some(other) = conflict(&current, action, &combo) {
            return Err(i18n::tr_args(
                Key::HotkeyConflict,
                &[("combo", &display_combo(&combo)), ("action", other.label(i18n::locale()))],
            ));
        }
    }
    let previous = current.get(action.id()).cloned().unwrap_or_default();
    let active = !previous.is_empty() && registered(app, &previous);
    if keep_binding(&previous, &combo, active) {
        return Ok(settings(app));
    }
    if !combo.is_empty() && !register(app, action, &combo) {
        return Err(i18n::tr_args(Key::HotkeyFailed, &[("combo", &display_combo(&combo))]));
    }
    // An inactive binding is registered again above, so only a different
    // previous combination is dropped here.
    if !previous.is_empty() && previous != combo {
        unregister(app, &previous);
    }
    {
        let store = app.state::<crate::Store>();
        let mut state = crate::lock(&store.state);
        if combo.is_empty() {
            state.hotkeys.remove(action.id());
        } else {
            state.hotkeys.insert(action.id().to_string(), combo.clone());
        }
        crate::persist(app, &state);
    }
    Ok(settings(app))
}

#[cfg(not(desktop))]
pub fn set(app: &AppHandle, action_id: &str, combo: &str) -> Result<Settings, String> {
    let _ = (app, action_id, combo);
    Err(i18n::tr(Key::HotkeyUnsupported).to_string())
}

/// Register the bindings a previous run saved. A combination the system no
/// longer allows stays in the file and shows as inactive in the settings page.
#[cfg(desktop)]
pub fn prepare(app: &AppHandle) {
    if unavailable(app).is_some() {
        return;
    }
    for (id, combo) in bindings_of(app) {
        if let Some(action) = Action::parse(&id) {
            register(app, action, &combo);
        }
    }
}

#[cfg(not(desktop))]
pub fn prepare(app: &AppHandle) {
    let _ = app;
}

/// Tell the user why a shortcut-triggered action failed (R39): the window may be
/// hidden, so a tray or in-app toast alone would not be seen.
pub fn notify_failure(app: &AppHandle, message: &str) {
    #[cfg(desktop)]
    {
        use tauri_plugin_notification::NotificationExt;
        let _ = app
            .notification()
            .builder()
            .title(i18n::tr(Key::HotkeyNotifyTitle))
            .body(message)
            .show();
    }
    #[cfg(not(desktop))]
    let _ = (app, message);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bindings(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(id, combo)| (id.to_string(), combo.to_string())).collect()
    }

    #[test]
    fn android_and_wayland_say_why_shortcuts_are_off() {
        assert_eq!(support("android", false), Err(Key::HotkeyUnsupported));
        assert_eq!(support("ios", false), Err(Key::HotkeyUnsupported));
        assert_eq!(support("linux", true), Err(Key::HotkeyWayland));
        assert_eq!(support("windows", false), Ok(()));
        assert_eq!(support("macos", false), Ok(()));
        assert_eq!(support("linux", false), Ok(()));
    }

    #[test]
    fn action_ids_round_trip_and_carry_their_mode() {
        for action in ACTIONS {
            assert_eq!(Action::parse(action.id()), Some(action));
        }
        assert_eq!(Action::parse("mode_rule"), None);
        assert_eq!(Action::ModeRule.mode(), Some("rule"));
        assert_eq!(Action::ModeGlobal.mode(), Some("global"));
        assert_eq!(Action::ModeDirect.mode(), Some("direct"));
        assert_eq!(Action::SystemProxy.mode(), None);
        // Labels exist in both languages and are never the key.
        for action in ACTIONS {
            assert!(!action.label(Locale::ZhCn).is_empty());
            assert!(!action.label(Locale::En).is_empty());
            assert_ne!(action.label(Locale::En), action.label(Locale::ZhCn));
        }
    }

    #[cfg(desktop)]
    #[test]
    fn a_combo_has_one_spelling_whatever_the_user_typed() {
        assert_eq!(normalize_combo("ctrl+alt+p").as_deref(), Some("Ctrl+Alt+P"));
        assert_eq!(normalize_combo(" Alt + Ctrl + KeyP ").as_deref(), Some("Ctrl+Alt+P"));
        assert_eq!(normalize_combo("Shift+f5").as_deref(), Some("Shift+F5"));
        assert_eq!(normalize_combo("CmdOrCtrl+Space").as_deref(), Some("Ctrl+Space"));
        assert_eq!(normalize_combo("ctrl+alt+1").as_deref(), Some("Ctrl+Alt+1"));
        assert_eq!(normalize_combo("").as_deref(), Some(""));
        assert_eq!(normalize_combo("   ").as_deref(), Some(""));
        assert_eq!(normalize_combo("Ctrl+Alt"), None);
        assert_eq!(normalize_combo("NotAKey"), None);
        assert_eq!(display_combo("Ctrl+Alt+P"), "Ctrl + Alt + P");
    }

    #[test]
    fn stored_bindings_keep_known_actions_and_drop_junk() {
        let cleaned = clean_bindings(&bindings(&[
            ("connect", "Ctrl+Alt+P"),
            ("mode-rule", " "),
            ("bogus-action", "Ctrl+Alt+K"),
            ("window", "Alt+Shift+D"),
        ]));
        assert_eq!(cleaned.len(), 2);
        assert_eq!(cleaned.get("connect").map(String::as_str), Some("Ctrl+Alt+P"));
        assert_eq!(cleaned.get("window").map(String::as_str), Some("Alt+Shift+D"));
        assert!(cleaned.get("mode-rule").is_none());
        assert!(cleaned.get("bogus-action").is_none());
        assert!(clean_bindings(&BTreeMap::new()).is_empty());
    }

    #[test]
    fn a_combination_two_actions_claim_names_the_one_that_owns_it() {
        let current = bindings(&[("proxy", "Ctrl+Alt+P"), ("window", "Alt+Shift+D")]);
        // The other action owns it, whichever spelling this call used.
        assert_eq!(conflict(&current, Action::ToggleConnection, "ctrl+alt+p"), Some(Action::SystemProxy));
        assert_eq!(conflict(&current, Action::Tun, "Alt+Shift+D"), Some(Action::ToggleWindow));
        // Re-saving the same action its own combination is not a conflict.
        assert_eq!(conflict(&current, Action::SystemProxy, "Ctrl+Alt+P"), None);
        assert_eq!(conflict(&current, Action::Tun, "Ctrl+Alt+F5"), None);
        // The message names the action that already has it.
        let message = crate::i18n::tr_args_at(
            Locale::ZhCn,
            Key::HotkeyConflict,
            &[("combo", &display_combo("Ctrl+Alt+P")), ("action", Action::SystemProxy.label(Locale::ZhCn))],
        );
        assert!(message.contains("Ctrl + Alt + P"));
        assert!(message.contains("系统代理"));
    }

    #[test]
    fn an_inactive_binding_is_registered_again_instead_of_being_kept() {
        // The system still has the stored combination: nothing to do.
        assert!(keep_binding("Ctrl+Alt+P", "Ctrl+Alt+P", true));
        // The combination the system refused at startup is retried, not skipped.
        assert!(!keep_binding("Ctrl+Alt+P", "Ctrl+Alt+P", false));
        // Another combination, a new one or a clear always goes through.
        assert!(!keep_binding("Ctrl+Alt+P", "Ctrl+Alt+Q", false));
        assert!(!keep_binding("", "Ctrl+Alt+P", false));
        assert!(!keep_binding("Ctrl+Alt+P", "", false));
        // Clearing an action that was never bound stays a no-op.
        assert!(keep_binding("", "", false));
    }
}
