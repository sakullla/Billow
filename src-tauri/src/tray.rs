//! Tray (Windows notification area / macOS menu bar) menu model.
//!
//! The menu is described as plain data from a profile snapshot so its shape can
//! be tested without a running Tauri app; `lib.rs` turns the entries into native
//! menu items and routes clicks back through [`parse`].

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

pub fn mode_label(mode: &str) -> Option<&'static str> {
    match mode {
        "rule" => Some("规则"),
        "global" => Some("全局"),
        "direct" => Some("直连"),
        _ => None,
    }
}

fn current_profile(snapshot: &ProfileSnapshot) -> Option<&str> {
    snapshot.profiles.iter().find(|profile| profile.current).map(|profile| profile.name.as_str())
}

/// One line that answers "is Billow on, with what?".
pub fn status_line(snapshot: &ProfileSnapshot) -> String {
    if snapshot.profiles.is_empty() {
        return "Billow · 还没有配置".to_string();
    }
    let profile = current_profile(snapshot).unwrap_or("未选择配置");
    if snapshot.connected {
        format!("● 已连接 · {profile}")
    } else {
        format!("○ 未连接 · {profile}")
    }
}

/// Hover text: state, profile and mode, kept short for the Windows 127-char limit.
pub fn tooltip(snapshot: &ProfileSnapshot) -> String {
    let mut parts = vec!["Billow".to_string(), if snapshot.connected { "已连接" } else { "未连接" }.to_string()];
    if let Some(profile) = current_profile(snapshot) {
        parts.push(profile.to_string());
    }
    if snapshot.connected {
        if let Some(mode) = snapshot.mode.as_deref().and_then(mode_label) {
            parts.push(format!("{mode}模式"));
        }
    }
    let text = parts.join(" · ");
    text.chars().take(120).collect()
}

fn delay_suffix(delay: Option<u64>, failed: bool) -> String {
    if failed {
        "  ·  超时".to_string()
    } else if let Some(ms) = delay {
        format!("  ·  {ms} ms")
    } else {
        String::new()
    }
}

fn groups_menu(snapshot: &ProfileSnapshot) -> Option<TrayEntry> {
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
                        format!("{}{}", node.name, delay_suffix(node.delay_ms, node.failed)),
                        node.name == group.now,
                        true,
                    )
                })
                .collect();
            if group.nodes.len() > MAX_NODES {
                nodes.push(TrayEntry::Separator);
                nodes.push(action(
                    format!("nav{SEP}proxies"),
                    format!("其余 {} 个节点…", group.nodes.len() - MAX_NODES),
                    true,
                ));
            }
            let now = if group.now.is_empty() { "—" } else { group.now.as_str() };
            TrayEntry::Submenu { text: format!("{}  ·  {now}", group.name), enabled: true, items: nodes }
        })
        .collect();
    if manual.len() > MAX_GROUPS {
        items.push(TrayEntry::Separator);
        items.push(action(format!("nav{SEP}proxies"), "全部代理组…", true));
    }
    Some(TrayEntry::Submenu { text: "代理组".to_string(), enabled: true, items })
}

fn profiles_menu(snapshot: &ProfileSnapshot) -> Option<TrayEntry> {
    if snapshot.profiles.is_empty() {
        return None;
    }
    let mut items: Vec<TrayEntry> = snapshot
        .profiles
        .iter()
        .map(|profile| check(format!("profile{SEP}{}", profile.id), profile.name.clone(), profile.current, true))
        .collect();
    items.push(TrayEntry::Separator);
    items.push(action(format!("nav{SEP}profiles"), "管理配置…", true));
    let text = match current_profile(snapshot) {
        Some(name) => format!("配置  ·  {name}"),
        None => "配置".to_string(),
    };
    Some(TrayEntry::Submenu { text, enabled: true, items })
}

/// The whole tray menu, top to bottom: state, the one primary action, quick
/// switches (mode, nodes, profile), traffic takeover, then window and quit.
pub fn model(snapshot: &ProfileSnapshot) -> Vec<TrayEntry> {
    let mut entries = vec![TrayEntry::Label(status_line(snapshot)), action("show", "显示主界面", true), TrayEntry::Separator];

    if snapshot.profiles.is_empty() {
        entries.push(action(format!("nav{SEP}add-profile"), "添加配置…", true));
    } else {
        let label = if snapshot.connected { "断开连接" } else { "连接" };
        entries.push(action("connect", label, snapshot.active_id.is_some()));
    }
    entries.push(TrayEntry::Separator);

    if snapshot.active_id.is_some() {
        let mode = snapshot.mode.as_deref().unwrap_or("");
        let text = match mode_label(mode) {
            Some(label) => format!("出站模式  ·  {label}"),
            None => "出站模式".to_string(),
        };
        entries.push(TrayEntry::Submenu {
            text,
            enabled: true,
            items: ["rule", "global", "direct"]
                .iter()
                .map(|id| check(format!("mode{SEP}{id}"), mode_label(id).unwrap_or(id), mode == *id, true))
                .collect(),
        });
        if let Some(groups) = groups_menu(snapshot) {
            entries.push(groups);
        }
    }
    if let Some(profiles) = profiles_menu(snapshot) {
        entries.push(profiles);
    }
    if !snapshot.profiles.is_empty() {
        entries.push(TrayEntry::Separator);
        entries.push(check("proxy", "系统代理", snapshot.system_proxy, true));
        entries.push(check("tun", "TUN 模式", snapshot.tun, true));
    }

    entries.push(TrayEntry::Separator);
    entries.push(action(format!("nav{SEP}settings"), "设置…", true));
    entries.push(action("quit", "退出 Billow", true));
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
        "mode" if mode_label(&first).is_some() => Some(TrayCommand::Mode(first)),
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
        let entries = model(&ProfileSnapshot::default());
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
        let entries = model(&snapshot);
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
        assert_eq!(tooltip(&snapshot), "Billow · 已连接 · 星河云 · 规则模式");
    }

    #[test]
    fn long_groups_point_to_the_window_instead_of_a_huge_menu() {
        let names: Vec<String> = (0..MAX_NODES + 5).map(|index| format!("节点 {index}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut snapshot = connected();
        snapshot.node_catalog = vec![group("节点选择", "manual", "节点 0", &refs)];
        let entries = model(&snapshot);
        let Some(TrayEntry::Submenu { items: groups, .. }) = find(&entries, "代理组") else { panic!("groups") };
        let TrayEntry::Submenu { items: nodes, .. } = &groups[0] else { panic!("group") };
        assert_eq!(nodes.len(), MAX_NODES + 2);
        assert!(matches!(nodes.last(), Some(TrayEntry::Action { text, .. }) if text == "其余 5 个节点…"));
    }

    #[test]
    fn menu_ids_round_trip_names_with_separators_and_spaces() {
        let entries = model(&connected());
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
