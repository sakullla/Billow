//! Tray (Windows notification area / macOS menu bar) menu model.
//!
//! The menu is described as plain data from a profile snapshot so its shape can
//! be tested without a running Tauri app; `lib.rs` turns the entries into native
//! menu items and routes clicks back through [`parse`].

use crate::i18n::{self, Key, Locale};
use crate::profile::ProfileSnapshot;

/// Separates the parts of a structured menu id. Group, node and profile names
/// come from user configs and may contain `:` or spaces, never this control char.
const SEP: char = '\u{1f}';

/// Manual groups and nodes listed in the tray before the rest is left to the window.
pub const MAX_GROUPS: usize = 12;
pub const MAX_NODES: usize = 40;

#[derive(Debug, Clone, PartialEq)]
pub enum TrayEntry {
    /// Disabled informational line.
    Label(String),
    Action { id: String, text: String, enabled: bool },
    Check { id: String, text: String, checked: bool, enabled: bool },
    Submenu { text: String, enabled: bool, items: Vec<TrayEntry> },
    Separator,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrayCommand {
    Show,
    /// Show the window and open a page (or the add-profile dialog).
    Navigate(String),
    ToggleConnection,
    SystemProxy,
    Tun,
    /// Select the engine that carries traffic (`mihomo` / `rust`).
    Engine(String),
    Mode(String),
    Profile(String),
    Node { group: String, node: String },
    Quit,
}

fn action(id: impl Into<String>, text: impl Into<String>, enabled: bool) -> TrayEntry {
    TrayEntry::Action { id: id.into(), text: text.into(), enabled }
}

fn check(id: impl Into<String>, text: impl Into<String>, checked: bool, enabled: bool) -> TrayEntry {
    TrayEntry::Check { id: id.into(), text: text.into(), checked, enabled }
}

pub fn mode_label(mode: &str, locale: Locale) -> Option<&'static str> {
    match mode {
        "rule" => Some(i18n::tr_at(locale, Key::TrayModeRule)),
        "global" => Some(i18n::tr_at(locale, Key::TrayModeGlobal)),
        "direct" => Some(i18n::tr_at(locale, Key::TrayModeDirect)),
        _ => None,
    }
}

fn current_profile(snapshot: &ProfileSnapshot) -> Option<&str> {
    snapshot.profiles.iter().find(|profile| profile.current).map(|profile| profile.name.as_str())
}

fn message(locale: Locale, key: Key, args: &[(&str, &str)]) -> String {
    i18n::tr_args_at(locale, key, args)
}

/// One line that answers "is Billow on, with what?".
pub fn status_line(snapshot: &ProfileSnapshot, locale: Locale) -> String {
    if snapshot.profiles.is_empty() {
        return i18n::tr_at(locale, Key::TrayEmpty).to_string();
    }
    let profile = current_profile(snapshot).unwrap_or(i18n::tr_at(locale, Key::TrayNoProfile));
    let key = if snapshot.connected { Key::TrayConnected } else { Key::TrayDisconnected };
    message(locale, key, &[("profile", profile)])
}

/// Hover text: state, profile and mode, kept short for the Windows 127-char limit.
pub fn tooltip(snapshot: &ProfileSnapshot, locale: Locale) -> String {
    let mut parts = vec!["Billow".to_string()];
    parts.push(
        if snapshot.connected {
            i18n::tr_at(locale, Key::TrayStateConnected)
        } else {
            i18n::tr_at(locale, Key::TrayStateDisconnected)
        }
        .to_string(),
    );
    if let Some(profile) = current_profile(snapshot) {
        parts.push(profile.to_string());
    }
    if snapshot.connected {
        if let Some(mode) = snapshot.mode.as_deref().and_then(|mode| mode_label(mode, locale)) {
            parts.push(message(locale, Key::TrayModeSuffix, &[("mode", mode)]));
        }
        // Which engine actually carries traffic, not just the selected one.
        if let Some(engine) = snapshot.running_engine.as_deref().and_then(engine_label) {
            parts.push(engine.to_string());
        }
    }
    let text = parts.join(" · ");
    text.chars().take(120).collect()
}

fn engine_label(id: &str) -> Option<&'static str> {
    match id {
        "mihomo" => Some("Mihomo"),
        "rust" => Some("Rust"),
        _ => None,
    }
}

fn engine_menu(snapshot: &ProfileSnapshot, locale: Locale) -> TrayEntry {
    let label = i18n::tr_at(locale, Key::TrayEngine);
    let running = snapshot.running_engine.as_deref();
    let text = match (engine_label(&snapshot.engine), running.and_then(engine_label)) {
        (Some(selected), Some(actual)) if selected != actual => {
            let status = message(locale, Key::TrayEngineRunning, &[("selected", selected), ("actual", actual)]);
            format!("{label}  ·  {status}")
        }
        (Some(selected), _) => format!("{label}  ·  {selected}"),
        _ => label.to_string(),
    };
    TrayEntry::Submenu {
        text,
        enabled: true,
        items: ["mihomo", "rust"]
            .iter()
            .map(|id| {
                check(
                    format!("engine{SEP}{id}"),
                    engine_label(id).unwrap_or(id),
                    snapshot.engine == *id,
                    true,
                )
            })
            .collect(),
    }
}

fn delay_suffix(delay: Option<u64>, failed: bool, locale: Locale) -> String {
    if failed {
        i18n::tr_at(locale, Key::TrayTimeout).to_string()
    } else if let Some(ms) = delay {
        format!("  ·  {ms} ms")
    } else {
        String::new()
    }
}

fn groups_menu(snapshot: &ProfileSnapshot, locale: Locale) -> Option<TrayEntry> {
    let manual: Vec<_> = snapshot
        .node_catalog
        .iter()
        .filter(|group| group.kind == "manual" && !group.nodes.is_empty())
        .filter(|group| snapshot.mode.as_deref() == Some("global") || group.name != "GLOBAL")
        .collect();
    if manual.is_empty() {
        return None;
    }
    let mut items: Vec<TrayEntry> = manual
        .iter()
        .take(MAX_GROUPS)
        .map(|group| {
            let mut nodes: Vec<TrayEntry> = group
                .nodes
                .iter()
                .take(MAX_NODES)
                .map(|node| {
                    check(
                        format!("node{SEP}{}{SEP}{}", group.name, node.name),
                        format!("{}{}", node.name, delay_suffix(node.delay_ms, node.failed, locale)),
                        node.name == group.now,
                        true,
                    )
                })
                .collect();
            if group.nodes.len() > MAX_NODES {
                nodes.push(TrayEntry::Separator);
                nodes.push(action(
                    format!("nav{SEP}proxies"),
                    message(locale, Key::TrayMoreNodes, &[("count", &(group.nodes.len() - MAX_NODES).to_string())]),
                    true,
                ));
            }
            let now = if group.now.is_empty() { "—" } else { group.now.as_str() };
            TrayEntry::Submenu { text: format!("{}  ·  {now}", group.name), enabled: true, items: nodes }
        })
        .collect();
    if manual.len() > MAX_GROUPS {
        items.push(TrayEntry::Separator);
        items.push(action(format!("nav{SEP}proxies"), i18n::tr_at(locale, Key::TrayAllGroups), true));
    }
    Some(TrayEntry::Submenu { text: i18n::tr_at(locale, Key::TrayGroups).to_string(), enabled: true, items })
}

fn profiles_menu(snapshot: &ProfileSnapshot, locale: Locale) -> Option<TrayEntry> {
    if snapshot.profiles.is_empty() {
        return None;
    }
    let mut items: Vec<TrayEntry> = snapshot
        .profiles
        .iter()
        .map(|profile| check(format!("profile{SEP}{}", profile.id), profile.name.clone(), profile.current, true))
        .collect();
    items.push(TrayEntry::Separator);
    items.push(action(format!("nav{SEP}profiles"), i18n::tr_at(locale, Key::TrayManageProfiles), true));
    let text = match current_profile(snapshot) {
        Some(name) => format!("{}  ·  {name}", i18n::tr_at(locale, Key::TrayProfile)),
        None => i18n::tr_at(locale, Key::TrayProfile).to_string(),
    };
    Some(TrayEntry::Submenu { text, enabled: true, items })
}

/// The whole tray menu, top to bottom: state, the one primary action, quick
/// switches (mode, nodes, profile), traffic takeover, then window and quit.
pub fn model(snapshot: &ProfileSnapshot, locale: Locale) -> Vec<TrayEntry> {
    let mut entries = vec![
        TrayEntry::Label(status_line(snapshot, locale)),
        action("show", i18n::tr_at(locale, Key::TrayShow), true),
        TrayEntry::Separator,
    ];

    if snapshot.profiles.is_empty() {
        entries.push(action(format!("nav{SEP}add-profile"), i18n::tr_at(locale, Key::TrayAddProfile), true));
    } else {
        let label = if snapshot.connected { Key::TrayDisconnect } else { Key::TrayConnect };
        entries.push(action("connect", i18n::tr_at(locale, label), snapshot.active_id.is_some()));
    }
    entries.push(TrayEntry::Separator);

    if snapshot.active_id.is_some() {
        let mode = snapshot.mode.as_deref().unwrap_or("");
        let text = match mode_label(mode, locale) {
            Some(label) => format!("{}  ·  {label}", i18n::tr_at(locale, Key::TrayMode)),
            None => i18n::tr_at(locale, Key::TrayMode).to_string(),
        };
        entries.push(TrayEntry::Submenu {
            text,
            enabled: true,
            items: ["rule", "global", "direct"]
                .iter()
                .map(|id| check(format!("mode{SEP}{id}"), mode_label(id, locale).unwrap_or(id), mode == *id, true))
                .collect(),
        });
        entries.push(engine_menu(snapshot, locale));
        if let Some(groups) = groups_menu(snapshot, locale) {
            entries.push(groups);
        }
    }
    if let Some(profiles) = profiles_menu(snapshot, locale) {
        entries.push(profiles);
    }
    if !snapshot.profiles.is_empty() {
        entries.push(TrayEntry::Separator);
        entries.push(check("proxy", i18n::tr_at(locale, Key::TraySystemProxy), snapshot.system_proxy, true));
        entries.push(check("tun", i18n::tr_at(locale, Key::TrayTun), snapshot.tun, true));
    }

    entries.push(TrayEntry::Separator);
    entries.push(action(format!("nav{SEP}settings"), i18n::tr_at(locale, Key::TraySettings), true));
    entries.push(action("quit", i18n::tr_at(locale, Key::TrayQuit), true));
    entries
}

pub fn parse(id: &str) -> Option<TrayCommand> {
    match id {
        "show" => return Some(TrayCommand::Show),
        "quit" => return Some(TrayCommand::Quit),
        "connect" => return Some(TrayCommand::ToggleConnection),
        "proxy" => return Some(TrayCommand::SystemProxy),
        "tun" => return Some(TrayCommand::Tun),
        _ => {}
    }
    let mut parts = id.split(SEP);
    let kind = parts.next()?;
    let first = parts.next()?.to_string();
    match kind {
        "mode" if matches!(first.as_str(), "rule" | "global" | "direct") => Some(TrayCommand::Mode(first)),
        "engine" if engine_label(&first).is_some() => Some(TrayCommand::Engine(first)),
        "profile" => Some(TrayCommand::Profile(first)),
        "nav" => Some(TrayCommand::Navigate(first)),
        "node" => Some(TrayCommand::Node { group: first, node: parts.next()?.to_string() }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodes::{NodeGroupView, NodeItemView};
    use crate::profile::ProfileView;

    fn profile(id: &str, name: &str, current: bool) -> ProfileView {
        ProfileView { id: id.to_string(), name: name.to_string(), current, ..ProfileView::default() }
    }

    fn group(name: &str, kind: &str, now: &str, nodes: &[&str]) -> NodeGroupView {
        NodeGroupView {
            name: name.to_string(),
            kind: kind.to_string(),
            now: now.to_string(),
            nodes: nodes
                .iter()
                .map(|node| NodeItemView { name: node.to_string(), delay_ms: Some(120), ..NodeItemView::default() })
                .collect(),
            ..NodeGroupView::default()
        }
    }

    fn connected() -> ProfileSnapshot {
        ProfileSnapshot {
            profiles: vec![profile("a", "星河云", true), profile("b", "备用", false)],
            active_id: Some("a".to_string()),
            mode: Some("rule".to_string()),
            connected: true,
            system_proxy: true,
            node_catalog: vec![
                group("节点选择", "manual", "香港 01", &["香港 01", "日本 01"]),
                group("自动选择", "auto", "日本 01", &["香港 01", "日本 01"]),
                group("GLOBAL", "manual", "DIRECT", &["DIRECT"]),
            ],
            ..ProfileSnapshot::default()
        }
    }

    fn find<'a>(entries: &'a [TrayEntry], prefix: &str) -> Option<&'a TrayEntry> {
        entries.iter().find(|entry| match entry {
            TrayEntry::Submenu { text, .. } | TrayEntry::Label(text) => text.starts_with(prefix),
            TrayEntry::Action { text, .. } | TrayEntry::Check { text, .. } => text.starts_with(prefix),
            TrayEntry::Separator => false,
        })
    }

    #[test]
    fn empty_install_offers_add_profile_instead_of_a_dead_connect() {
        let entries = model(&ProfileSnapshot::default(), Locale::ZhCn);
        assert_eq!(entries[0], TrayEntry::Label("Billow · 还没有配置".to_string()));
        assert!(matches!(find(&entries, "添加配置"), Some(TrayEntry::Action { enabled: true, .. })));
        assert!(find(&entries, "连接").is_none());
        assert!(find(&entries, "系统代理").is_none());
        assert!(find(&entries, "出站模式").is_none());
        assert!(matches!(entries.last(), Some(TrayEntry::Action { id, .. }) if id == "quit"));
    }

    #[test]
    fn connected_menu_shows_state_mode_groups_and_profiles() {
        let snapshot = connected();
        let entries = model(&snapshot, Locale::ZhCn);
        assert_eq!(entries[0], TrayEntry::Label("● 已连接 · 星河云".to_string()));
        assert!(matches!(find(&entries, "断开连接"), Some(TrayEntry::Action { enabled: true, .. })));
        let Some(TrayEntry::Submenu { text, items, .. }) = find(&entries, "出站模式") else { panic!("mode menu") };
        assert_eq!(text, "出站模式  ·  规则");
        assert!(matches!(&items[0], TrayEntry::Check { checked: true, text, .. } if text == "规则"));

        // Only manual groups; GLOBAL hides outside global mode.
        let Some(TrayEntry::Submenu { items: groups, .. }) = find(&entries, "代理组") else { panic!("groups") };
        assert_eq!(groups.len(), 1);
        let TrayEntry::Submenu { text, items: nodes, .. } = &groups[0] else { panic!("group") };
        assert_eq!(text, "节点选择  ·  香港 01");
        assert!(matches!(&nodes[0], TrayEntry::Check { checked: true, text, .. } if text == "香港 01  ·  120 ms"));

        let Some(TrayEntry::Submenu { text, items, .. }) = find(&entries, "配置") else { panic!("profiles") };
        assert_eq!(text, "配置  ·  星河云");
        assert!(matches!(&items[1], TrayEntry::Check { checked: false, text, .. } if text == "备用"));
        assert!(matches!(find(&entries, "系统代理"), Some(TrayEntry::Check { checked: true, .. })));
        assert_eq!(tooltip(&snapshot, Locale::ZhCn), "Billow · 已连接 · 星河云 · 规则模式");
    }

    #[test]
    fn english_menu_translates_billow_text_but_not_user_names() {
        let snapshot = connected();
        let entries = model(&snapshot, Locale::En);
        // Profile and node names are user data: they stay exactly as configured.
        assert_eq!(entries[0], TrayEntry::Label("● Connected · 星河云".to_string()));
        assert!(matches!(find(&entries, "Disconnect"), Some(TrayEntry::Action { enabled: true, .. })));
        let Some(TrayEntry::Submenu { text, items, .. }) = find(&entries, "Mode") else { panic!("mode menu") };
        assert_eq!(text, "Mode  ·  Rule");
        assert!(matches!(&items[1], TrayEntry::Check { checked: false, text, .. } if text == "Global"));

        let Some(TrayEntry::Submenu { text, items: groups, .. }) = find(&entries, "Proxy groups") else { panic!("groups") };
        assert_eq!(text, "Proxy groups");
        let TrayEntry::Submenu { text: group_text, items: nodes, .. } = &groups[0] else { panic!("group") };
        assert_eq!(group_text, "节点选择  ·  香港 01");
        assert!(matches!(&nodes[0], TrayEntry::Check { text, .. } if text == "香港 01  ·  120 ms"));

        let Some(TrayEntry::Submenu { text, .. }) = find(&entries, "Profile") else { panic!("profiles") };
        assert_eq!(text, "Profile  ·  星河云");
        assert!(matches!(find(&entries, "System proxy"), Some(TrayEntry::Check { .. })));
        assert!(matches!(find(&entries, "TUN mode"), Some(TrayEntry::Check { .. })));
        assert!(matches!(find(&entries, "Settings"), Some(TrayEntry::Action { .. })));
        assert!(matches!(find(&entries, "Quit Billow"), Some(TrayEntry::Action { .. })));
        assert_eq!(tooltip(&snapshot, Locale::En), "Billow · Connected · 星河云 · Rule mode");

        // No Chinese-only interface string is left in the English menu.
        let english = format!("{entries:?}");
        for word in ["已连接", "未连接", "代理组", "系统代理", "设置", "退出", "断开连接", "出站模式"] {
            assert!(!english.contains(word), "{word} should be translated");
        }
    }

    #[test]
    fn english_empty_install_offers_add_profile() {
        let entries = model(&ProfileSnapshot::default(), Locale::En);
        assert_eq!(entries[0], TrayEntry::Label("Billow · No profiles yet".to_string()));
        assert!(matches!(find(&entries, "Add profile"), Some(TrayEntry::Action { enabled: true, .. })));
        assert!(find(&entries, "Connect").is_none());
    }

    #[test]
    fn long_groups_point_to_the_window_instead_of_a_huge_menu() {
        let names: Vec<String> = (0..MAX_NODES + 5).map(|index| format!("节点 {index}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut snapshot = connected();
        snapshot.node_catalog = vec![group("节点选择", "manual", "节点 0", &refs)];
        let entries = model(&snapshot, Locale::ZhCn);
        let Some(TrayEntry::Submenu { items: groups, .. }) = find(&entries, "代理组") else { panic!("groups") };
        let TrayEntry::Submenu { items: nodes, .. } = &groups[0] else { panic!("group") };
        assert_eq!(nodes.len(), MAX_NODES + 2);
        assert!(matches!(nodes.last(), Some(TrayEntry::Action { text, .. }) if text == "其余 5 个节点…"));
    }

    #[test]
    fn tray_shows_and_selects_the_running_engine() {
        let mut snapshot = connected();
        snapshot.engine = "rust".to_string();
        snapshot.running_engine = Some("mihomo".to_string());
        let entries = model(&snapshot, Locale::ZhCn);
        let Some(TrayEntry::Submenu { text, items, .. }) = find(&entries, "内核引擎") else { panic!("engine menu") };
        assert_eq!(text, "内核引擎  ·  Rust（运行中 Mihomo）");
        let TrayEntry::Check { id, checked, .. } = &items[0] else { panic!("mihomo entry") };
        assert!(!checked);
        assert_eq!(parse(id), Some(TrayCommand::Engine("mihomo".to_string())));
        let TrayEntry::Check { id, checked, .. } = &items[1] else { panic!("rust entry") };
        assert!(checked);
        assert_eq!(parse(id), Some(TrayCommand::Engine("rust".to_string())));
        assert!(tooltip(&snapshot, Locale::ZhCn).contains("Mihomo"));
        assert_eq!(parse("engine\u{1f}bogus"), None);
    }

    #[test]
    fn menu_ids_round_trip_names_with_separators_and_spaces() {
        let entries = model(&connected(), Locale::ZhCn);
        let Some(TrayEntry::Submenu { items: groups, .. }) = find(&entries, "代理组") else { panic!("groups") };
        let TrayEntry::Submenu { items: nodes, .. } = &groups[0] else { panic!("group") };
        let TrayEntry::Check { id, .. } = &nodes[1] else { panic!("node") };
        assert_eq!(
            parse(id),
            Some(TrayCommand::Node { group: "节点选择".to_string(), node: "日本 01".to_string() })
        );
        assert_eq!(parse(&format!("mode{SEP}global")), Some(TrayCommand::Mode("global".to_string())));
        assert_eq!(parse(&format!("mode{SEP}bogus")), None);
        assert_eq!(parse(&format!("profile{SEP}a:b c")), Some(TrayCommand::Profile("a:b c".to_string())));
        assert_eq!(parse(&format!("nav{SEP}settings")), Some(TrayCommand::Navigate("settings".to_string())));
        assert_eq!(parse("connect"), Some(TrayCommand::ToggleConnection));
        assert_eq!(parse("status"), None);
    }
}
