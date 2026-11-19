mod age_key;
mod app_update;
mod backup;
mod bundled_geo;
mod diagnostics;
#[cfg(target_os = "windows")]
mod elevation;
mod hotkeys;
mod i18n;
mod kernel;
mod mrs;
mod nodes;
mod override_engine;
mod packed;
mod profile;
mod shell;
mod takeover;
mod tray;
mod resources;
#[cfg(target_os = "windows")]
mod win_process;

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use tauri::{AppHandle, Emitter, Manager};

use kernel::{
    ConnectResult, GithubReleaseClient, KernelManager, KernelStatus, PlatformTarget, parse_channel,
};
use profile::{
    HttpSubscriptionClient, KernelLaunch, KernelSettings, ProcessRuntime, ProfileBook,
    ProfileSnapshot, ProvidersSnapshot, RuleToggle, RulesSnapshot,
};
use shell::{ShellState, read_shell_state, resolve_entry, resolve_language, resolve_theme, write_shell_state};

struct Store {
    state: Mutex<ShellState>,
    /// Ignore the initial default-size event until the restored size is seen.
    accept_resize: AtomicBool,
    /// Set only by a successful WebDAV connection test in this session (R38), so
    /// a restart never shows a stale "usable" state.
    webdav_ok: AtomicBool,
}

struct KernelStore {
    manager: Mutex<KernelManager>,
}

struct ProfileSession {
    book: ProfileBook,
    runtime: ProcessRuntime,
    proxy: takeover::HostSystemProxy,
    tun: takeover::HostTun,
    vpn: takeover::HostVpn,
}

struct ProfileStore {
    session: Mutex<ProfileSession>,
}

fn lock(state: &Mutex<ShellState>) -> std::sync::MutexGuard<'_, ShellState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_kernel(state: &Mutex<KernelManager>) -> std::sync::MutexGuard<'_, KernelManager> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_profiles(state: &Mutex<ProfileSession>) -> std::sync::MutexGuard<'_, ProfileSession> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn shell_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let directory = app.path().app_config_dir().map_err(|err| err.to_string())?;
    std::fs::create_dir_all(&directory).map_err(|err| err.to_string())?;
    Ok(directory.join("shell-state.json"))
}

fn persist(app: &AppHandle, state: &ShellState) {
    match shell_path(app) {
        Ok(path) => {
            if let Err(err) = write_shell_state(&path, state) {
                eprintln!("Billow shell state was not saved: {err}");
            }
        }
        Err(err) => eprintln!("Billow shell state path unavailable: {err}"),
    }
}

fn load_state(app: &AppHandle) -> ShellState {
    match shell_path(app) {
        Ok(path) => read_shell_state(&path),
        Err(err) => {
            eprintln!("Billow shell state path unavailable: {err}");
            ShellState::default()
        }
    }
}

#[cfg(desktop)]
fn apply_native_theme(app: &AppHandle, theme: &str) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let native = match theme {
        "light" => Some(tauri::Theme::Light),
        "dark" => Some(tauri::Theme::Dark),
        _ => None,
    };
    if let Err(err) = window.set_theme(native) {
        eprintln!("Billow window theme was not applied: {err}");
    }
}

#[cfg(not(desktop))]
fn apply_native_theme(_app: &AppHandle, _theme: &str) {}

#[cfg(desktop)]
fn restore_window(app: &AppHandle, state: &ShellState) {
    let Some(window) = app.get_webview_window("main") else {
        eprintln!("Billow main window is missing; the default window stays open");
        return;
    };
    if let Some((width, height)) = shell::usable_window_size(state.width, state.height) {
        if let Err(err) = window.set_size(tauri::LogicalSize::new(width, height)) {
            eprintln!("Billow window size restore failed: {err}");
        }
    }
    apply_native_theme(app, &state.theme);
}

#[cfg(not(desktop))]
fn restore_window(app: &AppHandle, state: &ShellState) {
    apply_native_theme(app, &state.theme);
}

#[cfg(desktop)]
fn current_logical_size(window: &tauri::WebviewWindow) -> Option<(f64, f64)> {
    let scale = window.scale_factor().ok()?;
    let physical = window.inner_size().ok()?;
    // A minimized window reports 0×0 and must not replace the saved size.
    if physical.width == 0 || physical.height == 0 {
        return None;
    }
    let logical = physical.to_logical::<f64>(scale);
    shell::usable_window_size(logical.width, logical.height)
}

#[cfg(desktop)]
fn remember_window_size(app: &AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let Some((width, height)) = current_logical_size(&window) else {
        return;
    };
    let store = app.state::<Store>();
    let mut state = lock(&store.state);
    let matches_saved = (state.width - width).abs() < 1.0 && (state.height - height).abs() < 1.0;
    if matches_saved {
        store.accept_resize.store(true, Ordering::SeqCst);
        return;
    }
    let matches_default =
        (width - shell::DEFAULT_WIDTH).abs() < 1.0 && (height - shell::DEFAULT_HEIGHT).abs() < 1.0;
    if !store.accept_resize.load(Ordering::SeqCst) && matches_default {
        return;
    }
    store.accept_resize.store(true, Ordering::SeqCst);
    state.width = width;
    state.height = height;
    persist(app, &state);
}

#[cfg(not(desktop))]
fn remember_window_size(_app: &AppHandle) {}

fn prepare_shell(app: &tauri::App) {
    let state = load_state(app.handle());
    // The tray, the guardian and background actions read the process locale.
    i18n::apply_preference(&state.language);
    restore_window(app.handle(), &state);
    app.manage(Store {
        state: Mutex::new(state),
        accept_resize: AtomicBool::new(false),
        webdav_ok: AtomicBool::new(false),
    });
}

fn kernel_dir(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| "内核目录不可用".to_string())?
        .join("kernels");
    std::fs::create_dir_all(&directory).map_err(|_| "内核目录不可用".to_string())?;
    Ok(directory)
}

/// Use the same home for resource initialization, readers and the kernel's `-d` argument.
fn kernel_home(app: &AppHandle) -> Option<std::path::PathBuf> {
    #[cfg(target_os = "android")]
    return profiles_dir(app).ok();
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        resources::kernel_home()
    }
}

fn profiles_dir(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let directory = app
        .path()
        .app_config_dir()
        .map_err(|_| "配置目录不可用".to_string())?
        .join("profiles");
    std::fs::create_dir_all(&directory).map_err(|_| "配置目录不可用".to_string())?;
    Ok(directory)
}

fn prepare_profiles(app: &tauri::App) {
    let directory = match profiles_dir(app.handle()) {
        Ok(directory) => directory,
        Err(_) => std::env::temp_dir().join(format!(
            "billow-profiles-unavailable-{}",
            std::process::id()
        )),
    };
    let mut book = ProfileBook::open(&directory);
    let mut runtime = ProcessRuntime::new(&directory);
    #[cfg(not(target_os = "android"))]
    if let Ok(resources) = app.path().resource_dir() {
        runtime.set_bundled_resources(resources.join("runtime"));
    }
    let mut proxy = takeover::host_proxy();
    book.release_lingering_proxy(&mut proxy);
    let mut installed = takeover::HostInstalledApps;
    book.refresh_installed(&mut installed);
    let vpn = takeover::host_vpn();
    app.manage(ProfileStore {
        session: Mutex::new(ProfileSession {
            book,
            runtime,
            proxy,
            tun: takeover::host_tun(),
            vpn,
        }),
    });
    bind_install_links(app.handle());
}

fn accept_install_link(app: &AppHandle, link: &str) {
    let store = app.state::<ProfileStore>();
    let snapshot = {
        let mut session = lock_profiles(&store.session);
        session.book.stage_install_link(link)
    };
    let _ = app.emit("profile-changed", snapshot);
}

fn bind_install_links(app: &AppHandle) {
    use tauri_plugin_deep_link::DeepLinkExt;
    let handle = app.clone();
    app.deep_link().on_open_url(move |event| {
        for url in event.urls() {
            accept_install_link(&handle, url.as_str());
        }
    });
    if let Ok(Some(urls)) = app.deep_link().get_current() {
        for url in urls {
            accept_install_link(app, url.as_str());
        }
    }
    #[cfg(any(target_os = "linux", windows))]
    {
        let _ = app.deep_link().register("billow");
    }
}

fn prepare_kernel(app: &tauri::App) {
    let mut manager = match kernel_dir(app.handle()) {
        Ok(dir) => KernelManager::open(dir, PlatformTarget::current()),
        Err(message) => {
            let mut manager = KernelManager::open(
                std::env::temp_dir()
                    .join(format!("billow-kernel-unavailable-{}", std::process::id())),
                PlatformTarget::current(),
            );
            manager.fail_without_change(message);
            app.manage(KernelStore {
                manager: Mutex::new(manager),
            });
            return;
        }
    };
    #[cfg(not(target_os = "android"))]
    {
        let initialized = (|| -> Result<(), String> {
            let resources = app.path().resource_dir().map_err(|error| error.to_string())?.join("runtime");
            manager.seed_desktop(&resources)?;
            let home = kernel_home(app.handle()).ok_or("GEO 数据目录不可用")?;
            bundled_geo::seed_directory(&resources.join("geo"), &home)
        })();
        if let Err(message) = initialized { manager.fail_without_change(message); }
    }
    // First launch is ready before the UI can connect, with no network dependency.
    app.manage(KernelStore {
        manager: Mutex::new(manager),
    });
}

/// Window chrome state plus the language the UI should render in.
#[derive(serde::Serialize)]
struct ShellInfo {
    theme: String,
    last_entry: String,
    language: String,
    /// Effective locale after resolving "follow system" (R42).
    locale: &'static str,
}

impl ShellInfo {
    fn of(state: &ShellState) -> Self {
        Self {
            theme: state.theme.clone(),
            last_entry: state.last_entry.clone(),
            language: state.language.clone(),
            locale: i18n::locale().tag(),
        }
    }
}

#[tauri::command]
fn shell_state(app: AppHandle) -> ShellInfo {
    let store = app.state::<Store>();
    let state = lock(&store.state).clone();
    ShellInfo::of(&state)
}

#[tauri::command]
fn set_theme(app: AppHandle, theme: String) -> ShellInfo {
    let resolved = resolve_theme(&theme).to_string();
    let store = app.state::<Store>();
    let state = {
        let mut state = lock(&store.state);
        state.theme = resolved.clone();
        persist(&app, &state);
        state.clone()
    };
    apply_native_theme(&app, &resolved);
    ShellInfo::of(&state)
}

/// Switch the UI language now: the webview, the tray and later background text
/// all read the locale, so no restart is needed (R42).
#[tauri::command(async)]
fn set_language(app: AppHandle, language: String) -> ShellInfo {
    let resolved = resolve_language(&language).to_string();
    let state = {
        let store = app.state::<Store>();
        let mut state = lock(&store.state);
        state.language = resolved.clone();
        persist(&app, &state);
        state.clone()
    };
    i18n::apply_preference(&resolved);
    let snapshot = with_profile(&app, |session| session.book.snapshot());
    refresh_tray(&app, &snapshot);
    ShellInfo::of(&state)
}

#[tauri::command(async)]
fn set_last_entry(app: AppHandle, entry: String) -> ShellInfo {
    let store = app.state::<Store>();
    let mut state = lock(&store.state);
    let entry = resolve_entry(&entry);
    if state.last_entry != entry {
        state.last_entry = entry.to_string();
        persist(&app, &state);
    }
    ShellInfo::of(&state)
}

#[tauri::command(async)]
fn kernel_state(app: AppHandle) -> KernelStatus {
    let store = app.state::<KernelStore>();
    lock_kernel(&store.manager).status()
}

#[tauri::command(async)]
fn set_kernel_channel(app: AppHandle, channel: String) -> KernelStatus {
    let running = with_profile(&app, |session| session.runtime.running_kernel_path());
    let store = app.state::<KernelStore>();
    let mut manager = lock_kernel(&store.manager);
    manager.protect_running_path(running);
    match parse_channel(&channel) {
        Ok(channel) => manager.sync(channel, &GithubReleaseClient::new()),
        Err(message) => manager.fail_without_change(message),
    }
}

#[derive(serde::Serialize)]
struct ConnectStatus {
    failed: bool,
    failure: Option<String>,
    system_proxy: bool,
    tun: bool,
    vpn: bool,
}

impl From<ConnectResult> for ConnectStatus {
    fn from(result: ConnectResult) -> Self {
        Self {
            failed: result.failed,
            failure: result.failure,
            system_proxy: result.system_proxy,
            tun: result.tun,
            vpn: result.vpn,
        }
    }
}

#[tauri::command(async)]
fn connect_kernel(app: AppHandle) -> ConnectStatus {
    let store = app.state::<KernelStore>();
    let mut manager = lock_kernel(&store.manager);
    manager.connect().into()
}

fn profile_snapshot(app: &AppHandle) -> ProfileSnapshot {
    let kernel_path = {
        let store = app.state::<KernelStore>();
        lock_kernel(&store.manager).installed_path()
    };
    let store = app.state::<ProfileStore>();
    let mut session = lock_profiles(&store.session);
    session.runtime.set_kernel_path(kernel_path.clone());
    session.tun.set_kernel_path(kernel_path);
    let mut installed = takeover::HostInstalledApps;
    session.book.refresh_installed(&mut installed);
    let ProfileSession {
        book,
        runtime,
        proxy,
        tun,
        vpn,
    } = &mut *session;
    if !runtime.running() {
        if let Some(recovered) = book.recover_crashed_kernel(runtime, proxy, tun, vpn) {
            return recovered;
        }
    }
    book.sync_runtime(runtime);
    book.snapshot()
}

fn with_profile<T>(app: &AppHandle, change: impl FnOnce(&mut ProfileSession) -> T) -> T {
    let store = app.state::<ProfileStore>();
    let mut session = lock_profiles(&store.session);
    change(&mut session)
}

fn subscription_client(app: &AppHandle) -> HttpSubscriptionClient {
    let store = app.state::<KernelStore>();
    let version = lock_kernel(&store.manager).status().version;
    HttpSubscriptionClient::with_kernel_version(version.as_deref())
}

fn activate_profile(app: &AppHandle, id: &str, update: bool) -> ProfileSnapshot {
    let kernel_path = {
        let store = app.state::<KernelStore>();
        lock_kernel(&store.manager).installed_path()
    };
    let client = subscription_client(&app);
    let store = app.state::<ProfileStore>();
    let mut session = lock_profiles(&store.session);
    let ProfileSession {
        book,
        runtime,
        proxy,
        tun,
        vpn,
    } = &mut *session;
    runtime.set_kernel_path(kernel_path.clone());
    tun.set_kernel_path(kernel_path);
    if update {
        book.update(id, &client, runtime);
    } else {
        book.enable(id, &client, runtime);
    }
    book.apply_release(proxy, tun, vpn);
    book.reconcile_system_proxy(proxy);
    book.snapshot()
}

fn with_session(
    app: &AppHandle,
    change: impl FnOnce(&mut ProfileSession) -> ProfileSnapshot,
) -> ProfileSnapshot {
    let kernel_path = {
        let store = app.state::<KernelStore>();
        lock_kernel(&store.manager).installed_path()
    };
    let store = app.state::<ProfileStore>();
    let mut session = lock_profiles(&store.session);
    session.runtime.set_kernel_path(kernel_path.clone());
    session.tun.set_kernel_path(kernel_path);
    change(&mut session)
}

#[tauri::command(async)]
fn profile_state(app: AppHandle) -> ProfileSnapshot {
    profile_snapshot(&app)
}

#[tauri::command(async)]
fn add_subscription_profile(app: AppHandle, url: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.add_subscription(&url))
}

#[tauri::command(async)]
fn add_local_profile(app: AppHandle, name: String, content: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.add_local(&name, &content))
}

#[tauri::command(async)]
fn stage_install_link(app: AppHandle, link: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.stage_install_link(&link))
}

#[tauri::command(async)]
fn confirm_install_link(app: AppHandle) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.confirm_pending())
}

#[tauri::command(async)]
fn cancel_install_link(app: AppHandle) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.cancel_pending())
}

#[tauri::command(async)]
fn enable_profile(app: AppHandle, id: String) -> ProfileSnapshot {
    activate_profile(&app, &id, false)
}

#[tauri::command(async)]
fn update_profile(app: AppHandle, id: String) -> ProfileSnapshot {
    activate_profile(&app, &id, true)
}

#[tauri::command(async)]
fn preview_profile_override(app: AppHandle, id: String, text: String) -> Result<profile::OverridePreview, String> {
    with_profile(&app, |session| session.book.preview_override(&id, &text))
}

#[tauri::command(async)]
fn save_profile_override(app: AppHandle, id: String, text: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.save_override(&id, &text))
}

#[tauri::command(async)]
fn connect_session(app: AppHandle) -> Result<ProfileSnapshot, String> {
    Ok(with_session(&app, |session| {
        let ProfileSession {
            book,
            runtime,
            proxy,
            tun,
            vpn,
        } = session;
        book.connect(runtime, proxy, tun, vpn)
    }))
}

#[tauri::command(async)]
fn disconnect_session(app: AppHandle) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession {
            book,
            runtime,
            proxy,
            tun,
            vpn,
        } = session;
        book.disconnect(runtime, proxy, tun, vpn)
    })
}

static APP_UPDATING: AtomicBool = AtomicBool::new(false);

#[tauri::command]
async fn prepare_app_update(app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let next = disconnect_session(app.clone());
        let _ = app.emit("profile-changed", &next);
        refresh_tray(&app, &next);
        if next.system_proxy || next.tun || next.vpn || next.connected {
            return Err("代理连接未能安全关闭，请手动断开后重试更新".to_string());
        }
        // Stop the kernel and wait for any elevated helper (`billow.exe --billow-kernel-helper`)
        // to exit before the Windows NSIS installer launches, otherwise the per-user installer
        // cannot terminate an elevated Billow process and aborts with "Failed to kill Billow".
        APP_UPDATING.store(true, Ordering::SeqCst);
        release_proxy_on_exit(&app);
        #[cfg(target_os = "windows")]
        if let Some(tray) = app.remove_tray_by_id("billow") {
            drop(tray);
        }
        Ok(())
    }).await.map_err(|error| error.to_string())?
}

#[tauri::command(async)]
fn set_system_proxy(app: AppHandle, enabled: bool) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession {
            book,
            runtime,
            proxy,
            tun,
            vpn,
        } = session;
        book.set_system_proxy(enabled, runtime, proxy, tun, vpn)
    })
}

#[tauri::command(async)]
fn set_tun_enabled(app: AppHandle, enabled: bool) -> Result<ProfileSnapshot, String> {
    Ok(with_session(&app, |session| {
        let ProfileSession {
            book,
            runtime,
            proxy,
            tun,
            vpn,
        } = session;
        book.set_tun(enabled, runtime, proxy, tun, vpn)
    }))
}

#[tauri::command(async)]
fn exclude_package(app: AppHandle, package_name: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession {
            book, runtime, vpn, ..
        } = session;
        book.exclude_package(&package_name, runtime, vpn)
    })
}

#[tauri::command(async)]
fn include_package(app: AppHandle, package_name: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession {
            book, runtime, vpn, ..
        } = session;
        book.include_package(&package_name, runtime, vpn)
    })
}

/// Android app access control: `mode` is `exclude` or `include`, `packages` replaces that mode's list.
#[tauri::command(async)]
fn set_app_rules(app: AppHandle, mode: String, packages: Vec<String>) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession {
            book, runtime, vpn, ..
        } = session;
        book.set_app_rules(&mode, &packages, runtime, vpn)
    })
}

#[tauri::command(async)]
fn select_profile_node(app: AppHandle, group: String, node: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.select_node(&group, &node, runtime)
    })
}

#[tauri::command(async)]
fn unfix_profile_group(app: AppHandle, group: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.unfix_group(&group, runtime)
    })
}

#[tauri::command(async)]
fn test_profile_group(app: AppHandle, group: String) -> ProfileSnapshot {
    let events = app.clone();
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.test_group_with_progress(&group, runtime, &mut |node, delay, failed, tested, total| {
            let _ = events.emit("node-test", nodes::NodeTestEvent {
                node: node.to_string(), delay, failed, tested, total,
            });
        })
    })
}

#[tauri::command(async)]
fn set_node_query(app: AppHandle, query: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.set_node_query(&query))
}

#[tauri::command(async)]
fn set_node_sort(app: AppHandle, group: String, sort: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.set_node_sort(&group, &sort))
}

#[tauri::command(async)]
fn set_connection_query(app: AppHandle, query: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.set_connection_query(&query, runtime)
    })
}

#[tauri::command(async)]
fn set_outbound_mode(app: AppHandle, mode: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.set_outbound_mode(&mode, runtime)
    })
}

#[tauri::command(async)]
fn set_log_filter(app: AppHandle, level: String) -> ProfileSnapshot {
    with_profile(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.set_log_filter(&level, runtime)
    })
}

#[tauri::command(async)]
fn delete_profile(app: AppHandle, id: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.delete_profile(&id))
}

#[tauri::command(async)]
fn rename_profile(app: AppHandle, id: String, name: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.rename_profile(&id, &name))
}

#[tauri::command(async)]
fn set_profile_source(app: AppHandle, id: String, url: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.set_profile_source(&id, &url))
}

#[tauri::command(async)]
fn set_profile_user_agent(app: AppHandle, id: String, user_agent: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.set_profile_user_agent(&id, &user_agent))
}

#[tauri::command(async)]
fn set_profile_interval(app: AppHandle, id: String, hours: u32) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.set_profile_interval(&id, hours))
}

#[tauri::command(async)]
fn set_profile_age_key(app: AppHandle, id: String, key: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.set_profile_age_key(&id, &key))
}

#[tauri::command(async)]
fn profile_content(app: AppHandle, id: String) -> Option<String> {
    with_profile(&app, |session| session.book.profile_content(&id))
}

#[tauri::command(async)]
fn effective_config(app: AppHandle) -> Result<String, String> {
    with_profile(&app, |session| session.book.effective_config())
}

#[tauri::command(async)]
fn config_overview(app: AppHandle) -> Result<profile::ConfigOverview, String> {
    with_profile(&app, |session| session.book.config_overview())
}

/// This machine's address on the local network, for LAN clients to point at.
/// Only a private IPv4 is reported: under TUN or another VPN the route probe
/// can return a tunnel address, and a wrong hint is worse than none.
#[tauri::command(async)]
fn lan_address() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // connect() on UDP only picks a route; nothing is sent.
    socket.connect("192.168.255.255:9").or_else(|_| socket.connect("10.255.255.255:9")).ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if ip.is_private() => Some(ip.to_string()),
        _ => None,
    }
}

#[tauri::command(async)]
fn save_profile_content(app: AppHandle, id: String, content: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, proxy, .. } = session;
        book.save_profile_content(&id, &content, runtime);
        book.reconcile_system_proxy(proxy);
        book.snapshot()
    })
}

fn refresh_one(app: &AppHandle, client: &HttpSubscriptionClient, id: &str) {
    let Some(request) = with_profile(app, |session| session.book.prepare_refresh(id)) else { return };
    let fetched = request.fetch(client);
    with_session_raw(app, |session| {
        let ProfileSession { book, runtime, proxy, tun, vpn } = session;
        let reloaded = book.finish_refresh(&request, fetched, runtime);
        book.apply_release(proxy, tun, vpn);
        if reloaded {
            book.reconcile_system_proxy(proxy);
        }
    });
}

#[tauri::command]
async fn refresh_profile(app: AppHandle, id: String) -> Result<ProfileSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || {
        refresh_one(&app, &subscription_client(&app), &id);
        with_profile(&app, |session| session.book.snapshot())
    }).await.map_err(|error| error.to_string())
}

#[tauri::command]
async fn refresh_all_profiles(app: AppHandle) -> Result<ProfileSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let ids = with_profile(&app, |session| session.book.subscription_ids());
        refresh_ids(&app, &ids)
    }).await.map_err(|error| error.to_string())
}

const SUBSCRIPTION_REFRESH_CONCURRENCY: usize = 4;

fn refresh_ids(app: &AppHandle, ids: &[String]) -> ProfileSnapshot {
    if ids.is_empty() {
        return profile_snapshot(app);
    }
    let client = subscription_client(app);
    let cursor = std::sync::atomic::AtomicUsize::new(0);
    let workers = ids.len().min(SUBSCRIPTION_REFRESH_CONCURRENCY);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let client = &client;
            let cursor = &cursor;
            scope.spawn(move || loop {
                let index = cursor.fetch_add(1, Ordering::Relaxed);
                let Some(id) = ids.get(index) else { break };
                refresh_one(app, client, id);
            });
        }
    });
    profile_snapshot(app)
}

#[tauri::command(async)]
fn save_kernel_settings(app: AppHandle, settings: KernelSettings) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession {
            book,
            runtime,
            proxy,
            tun,
            vpn,
        } = session;
        book.save_settings(settings, runtime, proxy, tun, vpn)
    })
}

#[tauri::command(async)]
fn test_all_nodes(app: AppHandle) -> ProfileSnapshot {
    let events = app.clone();
    with_session_raw(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.test_all_with_progress(runtime, &mut |node, delay, failed, tested, total| {
            let _ = events.emit(
                "node-test",
                nodes::NodeTestEvent {
                    node: node.to_string(),
                    delay,
                    failed,
                    tested,
                    total,
                },
            );
        })
    })
}

#[tauri::command(async)]
fn test_node(app: AppHandle, node: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.test_node(&node, runtime)
    })
}

#[tauri::command(async)]
fn close_connection(app: AppHandle, id: Option<String>) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.close_connections(id.as_deref(), runtime)
    })
}

/// Closes every connection (`ids` absent) or only the listed ones (R30).
#[tauri::command(async)]
fn close_connections(app: AppHandle, ids: Option<Vec<String>>) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.close_connection_set(ids.as_deref(), runtime)
    })
}

/// Resolves a name through the kernel's live DNS config (R31). The query runs
/// without holding the session lock; failures come back in `error`.
#[tauri::command(async)]
fn dns_query(app: AppHandle, name: String, qtype: String) -> diagnostics::DnsQueryResult {
    let endpoint = with_session_raw(&app, |session| ProfileBook::controller_of(&mut session.runtime));
    diagnostics::dns_query(endpoint.as_ref(), &name, &qtype, std::time::Duration::from_secs(8))
}

#[tauri::command(async)]
fn kernel_rules(app: AppHandle) -> RulesSnapshot {
    with_session_raw(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.rules(runtime)
    })
}

/// Toggles one runtime rule. A failed hot reload restores the previous key set.
#[tauri::command(async)]
fn set_rule_disabled(app: AppHandle, command: RuleToggle) -> Result<RulesSnapshot, String> {
    with_session_raw(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.set_rule_disabled(command, runtime)
    })
}

#[tauri::command(async)]
fn kernel_providers(app: AppHandle) -> ProvidersSnapshot {
    with_session_raw(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.providers(runtime)
    })
}

fn controller(app: &AppHandle) -> Result<nodes::ControllerEndpoint, String> {
    with_session_raw(app, |session| ProfileBook::controller_of(&mut session.runtime))
        .ok_or_else(|| "内核没有运行".to_string())
}

const MAX_CONCURRENT_PROVIDER_ACTIONS: usize = 6;
static PROVIDER_ACTION_SLOTS: (Mutex<usize>, std::sync::Condvar) =
    (Mutex::new(0), std::sync::Condvar::new());

struct ProviderActionGuard;

impl ProviderActionGuard {
    fn acquire() -> Self {
        let (lock, cvar) = &PROVIDER_ACTION_SLOTS;
        let mut active = lock.lock().unwrap_or_else(|p| p.into_inner());
        while *active >= MAX_CONCURRENT_PROVIDER_ACTIONS {
            active = cvar.wait(active).unwrap_or_else(|p| p.into_inner());
        }
        *active += 1;
        Self
    }
}

impl Drop for ProviderActionGuard {
    fn drop(&mut self) {
        let (lock, cvar) = &PROVIDER_ACTION_SLOTS;
        let mut active = lock.lock().unwrap_or_else(|p| p.into_inner());
        *active = active.saturating_sub(1);
        cvar.notify_one();
    }
}

/// Provider downloads can take a while, so they run without the profile lock held
/// while bounded by `MAX_CONCURRENT_PROVIDER_ACTIONS` to protect kernel load.
#[tauri::command]
async fn provider_action(app: AppHandle, kind: String, name: String, action: String) -> Result<(), String> {
    let endpoint = controller(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = ProviderActionGuard::acquire();
        diagnostics::provider_action(&endpoint, &kind, &name, &action)
    })
    .await
    .map_err(|err| err.to_string())?
}

/// Nodes of a proxy provider (live from the kernel) or rules of a rule provider (from its file).
#[tauri::command]
async fn provider_detail(
    app: AppHandle,
    kind: String,
    name: String,
    query: Option<String>,
) -> Result<resources::ProviderDetail, String> {
    if kind == "rule" {
        let config = with_profile(&app, |session| session.book.effective_config())?;
        let home = kernel_home(&app);
        return tauri::async_runtime::spawn_blocking(move || {
            resources::rule_detail(&config, &name, home.as_deref(), query.as_deref().unwrap_or(""))
        })
        .await
        .map_err(|err| err.to_string());
    }
    let endpoint = controller(&app)?;
    tauri::async_runtime::spawn_blocking(move || resources::proxy_detail(&endpoint, &name))
        .await
        .map_err(|err| err.to_string())?
}

/// GEO database files in the kernel home, readable without a running kernel.
#[tauri::command(async)]
fn geo_files(app: AppHandle) -> Vec<resources::GeoFile> {
    let home = kernel_home(&app);
    #[cfg(target_os = "android")]
    if let (Some(apk), Some(dir)) = (kernel::android_app_dir("sourceDir"), home.as_deref()) {
        let _ = bundled_geo::seed(&apk, dir);
    }
    resources::geo_files(home.as_deref())
}

#[tauri::command]
async fn upgrade_geo(app: AppHandle, key: Option<String>) -> Result<Vec<resources::GeoFile>, String> {
    let home = kernel_home(&app).ok_or_else(|| "GEO 数据目录不可用".to_string())?;
    let (urls, local_proxy, controller, effective_yaml) = with_profile(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.geo_download_context(runtime)
    });
    let target = key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    tauri::async_runtime::spawn_blocking(move || {
        let files = resources::download_geo_files(
            &home,
            &urls,
            target.as_deref(),
            local_proxy.as_deref(),
        )?;
        if let (Some(endpoint), Some(yaml)) = (controller, effective_yaml) {
            let rewritten = nodes::rewrite_controller_endpoint(&yaml, &endpoint);
            let _ = nodes::put_config(&endpoint, &rewritten);
        }
        Ok(files)
    })
    .await
    .map_err(|err| err.to_string())?
}

#[tauri::command(async)]
fn open_uwp_tool() -> Result<(), String> {
    takeover::open_uwp_loopback_tool()
}

#[tauri::command(async)]
fn list_uwp_apps() -> Result<Vec<takeover::UwpApp>, String> {
    takeover::list_uwp_apps()
}

#[tauri::command(async)]
fn save_uwp_exemptions(family_names: Vec<String>) -> Result<Vec<takeover::UwpApp>, String> {
    takeover::save_uwp_exemptions(family_names)
}

/// 重启内核 (R35): Billow stops and respawns the process; mihomo's `/restart` is not used.
#[tauri::command(async)]
fn restart_kernel(app: AppHandle) -> Result<ProfileSnapshot, String> {
    with_session_raw(&app, |session| {
        let ProfileSession {
            book,
            runtime,
            proxy,
            tun,
            vpn,
        } = session;
        book.restart_kernel(runtime, proxy, tun, vpn)
    })
}

/// 回收内存 (R35): `PUT /debug/gc`, sent without holding the session lock.
#[tauri::command(async)]
fn kernel_gc(app: AppHandle) -> Result<(), String> {
    let endpoint = with_session_raw(&app, |session| ProfileBook::controller_of(&mut session.runtime));
    diagnostics::kernel_gc(endpoint.as_ref())
}

#[tauri::command(async)]
fn flush_cache(app: AppHandle, which: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.flush_cache(&which, runtime)
    })
}

#[tauri::command(async)]
fn clear_logs(app: AppHandle) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.clear_logs())
}

/// Writes the visible log text to Downloads (desktop) or the app's external
/// documents directory (Android). A write failure leaves the log buffer alone.
#[tauri::command(async)]
fn export_logs(app: AppHandle, content: String) -> Result<String, String> {
    let directory = export_directory(&app)?;
    diagnostics::export_logs(&directory, &content, diagnostics::now_ms())
        .map(|path| path.display().to_string())
}

#[cfg(target_os = "android")]
fn export_directory(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .document_dir()
        .map_err(|_| "日志没有导出".to_string())
}

#[cfg(not(target_os = "android"))]
fn export_directory(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .download_dir()
        .or_else(|_| app.path().app_data_dir())
        .map_err(|_| "日志没有导出".to_string())
}

#[tauri::command(async)]
fn clear_notice(app: AppHandle) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.clear_notice())
}

#[tauri::command(async)]
fn refresh_kernel(app: AppHandle) -> KernelStatus {
    let running = with_profile(&app, |session| session.runtime.running_kernel_path());
    let store = app.state::<KernelStore>();
    let mut manager = lock_kernel(&store.manager);
    manager.protect_running_path(running);
    let channel = manager.channel();
    manager.sync(channel, &GithubReleaseClient::new())
}

// ─────────────────────── 备份与恢复 (R38) ───────────────────────

fn backup_platform() -> String {
    takeover::ClientPlatform::current().as_str().to_string()
}

/// Build the live state as a backup document.
fn current_backup(app: &AppHandle) -> Result<backup::BackupFile, String> {
    let profiles = with_profile(app, |session| session.book.backup_state());
    let shell = {
        let store = app.state::<Store>();
        lock(&store.state).clone()
    };
    Ok(backup::compose(
        profiles,
        &shell,
        &app.package_info().version.to_string(),
        &backup_platform(),
        &backup::device_name(),
        diagnostics::now_ms(),
    ))
}

fn backup_directory(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    export_directory(app).map_err(|_| i18n::tr(i18n::Key::BackupExportFailed).to_string())
}

/// Write a backup with profiles, 覆写, age keys, kernel settings and app
/// settings. WebDAV credentials, window size, traffic history and kernel/GEO
/// files are deliberately left out.
#[tauri::command(async)]
fn export_backup(app: AppHandle) -> Result<String, String> {
    let directory = backup_directory(&app)?;
    let file = current_backup(&app)?;
    backup::export(&directory, &file, diagnostics::now_ms())
        .map(|path| path.display().to_string())
}

/// Restore a whole backup. Validation happens first; a failure partway restores
/// the state captured before the attempt, so nothing is half applied.
#[tauri::command(async)]
fn restore_backup_text(app: AppHandle, text: String) -> Result<ProfileSnapshot, String> {
    let version = app.package_info().version.to_string();
    let mut file = backup::parse(&text, &version)?;
    let shell_before = {
        let store = app.state::<Store>();
        lock(&store.state).clone()
    };
    let profiles_before = with_profile(&app, |session| session.book.backup_state());
    backup::merge_platform(&mut file, &backup_platform(), &profiles_before, &shell_before);
    let shell_after = file.shell.apply(&shell_before);

    let kernel_path = {
        let store = app.state::<KernelStore>();
        lock_kernel(&store.manager).installed_path()
    };
    let client = subscription_client(&app);
    let outcome = {
        let store = app.state::<ProfileStore>();
        let mut session = lock_profiles(&store.session);
        let ProfileSession {
            book,
            runtime,
            proxy,
            tun,
            vpn,
        } = &mut *session;
        runtime.set_kernel_path(kernel_path.clone());
        tun.set_kernel_path(kernel_path);
        match book.restore_backup(file.profiles, &client, runtime) {
            Ok(snapshot) => {
                // Restored settings can defer a takeover release or move the
                // listener port; follow the new state instead of the old one.
                book.apply_release(proxy, tun, vpn);
                book.reconcile_system_proxy(proxy);
                Ok(snapshot)
            }
            Err(reason) => Err(reason),
        }
    };
    let restored = match outcome {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            return Err(i18n::tr_args(i18n::Key::BackupRestoreFailed, &[("reason", &reason)]))
        }
    };

    let path = shell_path(&app)?;
    if let Err(error) = write_shell_state(&path, &shell_after) {
        // The profile half is already written, so undo it too.
        let _ = with_profile(&app, |session| {
            let ProfileSession { book, runtime, proxy, .. } = session;
            let undone = book.restore_backup(profiles_before, &client, runtime);
            book.reconcile_system_proxy(proxy);
            undone
        });
        return Err(i18n::tr_args(i18n::Key::BackupRestoreFailed, &[("reason", &error)]));
    }
    {
        let store = app.state::<Store>();
        let mut state = lock(&store.state);
        *state = shell_after.clone();
    }
    i18n::apply_preference(&shell_after.language);
    apply_native_theme(&app, &shell_after.theme);
    refresh_tray(&app, &restored);
    Ok(restored)
}

#[derive(serde::Serialize)]
struct WebdavInfo {
    url: String,
    username: String,
    password: String,
    /// A connection test succeeded in this session; any change resets it.
    available: bool,
}

fn webdav_info(app: &AppHandle) -> WebdavInfo {
    let store = app.state::<Store>();
    let state = lock(&store.state);
    WebdavInfo {
        url: state.webdav_url.clone(),
        username: state.webdav_user.clone(),
        password: state.webdav_password.clone(),
        available: store.webdav_ok.load(Ordering::SeqCst),
    }
}

fn webdav_account(app: &AppHandle) -> backup::WebDavAccount {
    let store = app.state::<Store>();
    backup::WebDavAccount::from_state(&lock(&store.state))
}

#[tauri::command]
fn webdav_settings(app: AppHandle) -> WebdavInfo {
    webdav_info(&app)
}

/// Save the WebDAV account. Changing it makes a previous test result stale;
/// saving the same values again (as the button flows do) keeps it.
#[tauri::command(async)]
fn set_webdav_settings(
    app: AppHandle,
    url: String,
    username: String,
    password: String,
) -> WebdavInfo {
    let changed = {
        let store = app.state::<Store>();
        let mut state = lock(&store.state);
        let changed = state.webdav_url != url
            || state.webdav_user != username
            || state.webdav_password != password;
        state.webdav_url = url;
        state.webdav_user = username;
        state.webdav_password = password;
        persist(&app, &state);
        changed
    };
    if changed {
        app.state::<Store>().webdav_ok.store(false, Ordering::SeqCst);
    }
    webdav_info(&app)
}

#[derive(serde::Serialize)]
struct WebdavTest {
    available: bool,
    error: Option<String>,
}

/// "Test connection": create the folder when needed, then read it. Only a
/// success marks WebDAV as usable.
#[tauri::command(async)]
fn test_webdav(app: AppHandle) -> WebdavTest {
    let result = backup::test_connection(&webdav_account(&app));
    let available = result.is_ok();
    app.state::<Store>().webdav_ok.store(available, Ordering::SeqCst);
    WebdavTest {
        available,
        error: result.err(),
    }
}

/// Upload the current state. Only a user action starts an upload; nothing is
/// uploaded automatically (R45).
#[tauri::command(async)]
fn upload_backup(app: AppHandle) -> Result<String, String> {
    if !app.state::<Store>().webdav_ok.load(Ordering::SeqCst) {
        return Err(i18n::tr(i18n::Key::WebdavNotTested).to_string());
    }
    let file = current_backup(&app)?;
    let text = backup::to_text(&file)?;
    backup::upload(&webdav_account(&app), &text, diagnostics::now_ms())
}

#[tauri::command(async)]
fn list_remote_backups(app: AppHandle) -> Result<Vec<backup::RemoteBackup>, String> {
    backup::list(&webdav_account(&app))
}

#[tauri::command(async)]
fn restore_remote_backup(app: AppHandle, name: String) -> Result<ProfileSnapshot, String> {
    let text = backup::download(&webdav_account(&app), &name)?;
    restore_backup_text(app, text)
}

#[derive(serde::Serialize)]
struct AppInfo {
    version: String,
    platform: String,
    autostart: Option<bool>,
    close_to_tray: bool,
    silent_start: bool,
    data_dir: Option<String>,
}

#[tauri::command]
fn app_info(app: AppHandle) -> AppInfo {
    let (close_to_tray, silent_start) = {
        let store = app.state::<Store>();
        let state = lock(&store.state);
        (state.close_to_tray, state.silent_start)
    };
    AppInfo {
        version: app.package_info().version.to_string(),
        platform: std::env::consts::OS.to_string(),
        autostart: autostart_enabled(&app),
        close_to_tray,
        silent_start,
        data_dir: app
            .path()
            .app_config_dir()
            .ok()
            .map(|path| path.display().to_string()),
    }
}

#[cfg(desktop)]
fn autostart_enabled(app: &AppHandle) -> Option<bool> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().ok()
}

#[cfg(not(desktop))]
fn autostart_enabled(_app: &AppHandle) -> Option<bool> {
    None
}

#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> AppInfo {
    #[cfg(desktop)]
    {
        use tauri_plugin_autostart::ManagerExt;
        let manager = app.autolaunch();
        let _ = if enabled {
            manager.enable()
        } else {
            manager.disable()
        };
    }
    #[cfg(not(desktop))]
    let _ = enabled;
    app_info(app)
}

#[tauri::command]
fn set_app_behavior(app: AppHandle, close_to_tray: bool, silent_start: bool) -> AppInfo {
    {
        let store = app.state::<Store>();
        let mut state = lock(&store.state);
        state.close_to_tray = close_to_tray;
        state.silent_start = silent_start;
        persist(&app, &state);
    }
    app_info(app)
}

fn with_session_raw<T>(app: &AppHandle, change: impl FnOnce(&mut ProfileSession) -> T) -> T {
    let kernel_path = {
        let store = app.state::<KernelStore>();
        lock_kernel(&store.manager).installed_path()
    };
    let store = app.state::<ProfileStore>();
    let mut session = lock_profiles(&store.session);
    session.runtime.set_kernel_path(kernel_path.clone());
    session.tun.set_kernel_path(kernel_path);
    change(&mut session)
}

/// Checks subscription update intervals once a minute.
fn spawn_auto_update(app: &AppHandle) {
    let handle = app.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            let now = diagnostics::now_ms();
            let due = with_profile(&handle, |session| session.book.due_profiles(now));
            if due.is_empty() {
                continue;
            }
            let snapshot = refresh_ids(&handle, &due);
            let _ = handle.emit("profile-changed", snapshot);
        }
    });
}

/// Runs optional launch auto-connect off the UI setup thread, clears the startup
/// crash guard once the kernel has stayed up, and watches for unexpected exits
/// even while the window is hidden in the system tray.
fn spawn_kernel_guardian(app: &AppHandle) {
    let handle = app.clone();
    std::thread::spawn(move || {
        let auto = with_session_raw(&handle, |session| {
            let ProfileSession {
                book,
                runtime,
                proxy,
                tun,
                vpn,
            } = session;
            book.auto_connect_on_launch(runtime, proxy, tun, vpn)
        });
        if let Some(snapshot) = auto {
            refresh_tray(&handle, &snapshot);
            let _ = handle.emit("profile-changed", snapshot);
        }
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let exited = with_profile(&handle, |session| {
                let ProfileSession { book, runtime, .. } = session;
                if !(book.is_connected() || book.startup_guard_pending()) {
                    return false;
                }
                if !runtime.running() {
                    return true;
                }
                if book.startup_guard_pending() {
                    book.check_startup_uptime(runtime.kernel_uptime_secs());
                }
                false
            });
            if !exited {
                continue;
            }
            let recovered = with_session_raw(&handle, |session| {
                let ProfileSession {
                    book,
                    runtime,
                    proxy,
                    tun,
                    vpn,
                } = session;
                book.recover_crashed_kernel(runtime, proxy, tun, vpn)
            });
            if let Some(snapshot) = recovered {
                refresh_tray(&handle, &snapshot);
                let _ = handle.emit("profile-changed", snapshot);
            }
        }
    });
}

#[cfg(desktop)]
fn show_main(app: &AppHandle) {
    // A hidden app on macOS must be activated before its window can take focus.
    #[cfg(target_os = "macos")]
    let _ = app.show();
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Show the window and ask the page to open a view ("settings", "profiles", "add-profile", …).
#[cfg(desktop)]
fn navigate_main(app: &AppHandle, target: &str) {
    show_main(app);
    let _ = app.emit("tray-navigate", target.to_string());
}

/// One action the tray menu or a global shortcut asks the backend to run (R39).
#[cfg(desktop)]
enum BackendAction {
    Show,
    /// Show the window and open a page (or the add-profile dialog).
    Navigate(String),
    /// Show the window, or hide it when it is already in front.
    ToggleWindow,
    Quit,
    ToggleConnection,
    SystemProxy,
    Tun,
    Mode(String),
    Profile(String),
    Node { group: String, node: String },
}

#[cfg(desktop)]
impl BackendAction {
    fn from_tray(command: tray::TrayCommand) -> Self {
        use tray::TrayCommand;
        match command {
            TrayCommand::Show => Self::Show,
            TrayCommand::Navigate(target) => Self::Navigate(target),
            TrayCommand::ToggleConnection => Self::ToggleConnection,
            TrayCommand::SystemProxy => Self::SystemProxy,
            TrayCommand::Tun => Self::Tun,
            TrayCommand::Mode(mode) => Self::Mode(mode),
            TrayCommand::Profile(id) => Self::Profile(id),
            TrayCommand::Node { group, node } => Self::Node { group, node },
            TrayCommand::Quit => Self::Quit,
        }
    }

    fn from_hotkey(action: hotkeys::Action) -> Self {
        match action {
            hotkeys::Action::ToggleConnection => Self::ToggleConnection,
            hotkeys::Action::SystemProxy => Self::SystemProxy,
            hotkeys::Action::Tun => Self::Tun,
            hotkeys::Action::ToggleWindow => Self::ToggleWindow,
            hotkeys::Action::ModeRule | hotkeys::Action::ModeGlobal | hotkeys::Action::ModeDirect => {
                Self::Mode(action.mode().unwrap_or("rule").to_string())
            }
        }
    }
}

#[cfg(desktop)]
fn toggle_main_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let visible = window.is_visible().unwrap_or(false);
    let minimized = window.is_minimized().unwrap_or(false);
    if visible && !minimized {
        let _ = window.hide();
    } else {
        show_main(app);
    }
}

/// The reason a shortcut-triggered action should announce (R39).
///
/// Most takeover failures are not an `Err`: a denied TUN authorization, a
/// refused system proxy or a kernel that will not start all come back as
/// `Ok(snapshot)` with `snapshot.failure` set, so a shortcut compares the
/// reason before and after its action. Only a reason this action raised or
/// changed is announced; an unchanged banner left over from an earlier attempt
/// is not repeated, and the tray path never notifies.
#[cfg_attr(not(desktop), allow(dead_code))]
fn shortcut_failure(
    notify_failure: bool,
    previous: Option<&str>,
    snapshot: &ProfileSnapshot,
) -> Option<String> {
    if !notify_failure {
        return None;
    }
    let current = snapshot.failure.as_deref()?;
    if previous == Some(current) {
        return None;
    }
    Some(current.to_string())
}

/// The one place a tray click and a global shortcut meet (R39): run the action,
/// refresh the tray, then tell the window what changed.
#[cfg(desktop)]
fn dispatch(app: &AppHandle, action: BackendAction, notify_failure: bool) {
    match action {
        BackendAction::Show => show_main(app),
        BackendAction::Navigate(target) => navigate_main(app, &target),
        BackendAction::ToggleWindow => toggle_main_window(app),
        BackendAction::Quit => {
            release_proxy_on_exit(app);
            app.exit(0);
        }
        action => {
            // Connecting, switching profiles (which may download) and node
            // selection talk to the kernel; keep them off the menu thread so the
            // tray never freezes.
            let app = app.clone();
            tauri::async_runtime::spawn_blocking(move || {
                // Only a shortcut pays for the "before" reading; the tray never
                // notifies, so it skips it and keeps its previous behaviour.
                let previous = if notify_failure {
                    with_profile(&app, |session| session.book.snapshot().failure)
                } else {
                    None
                };
                let snapshot = match apply_action(&app, action) {
                    Ok(snapshot) => {
                        // A shortcut can fire while the window is hidden, so a
                        // failure the action raised also goes to a system
                        // notification (R39).
                        if let Some(message) =
                            shortcut_failure(notify_failure, previous.as_deref(), &snapshot)
                        {
                            hotkeys::notify_failure(&app, &message);
                        }
                        snapshot
                    }
                    Err(message) => {
                        // A shortcut can fire while the window is hidden, so the
                        // reason also goes to a system notification (R39).
                        if notify_failure {
                            hotkeys::notify_failure(&app, &message);
                        }
                        with_profile(&app, |session| session.book.report_failure(message))
                    }
                };
                refresh_tray(&app, &snapshot);
                let _ = app.emit("profile-changed", snapshot);
            });
        }
    }
}

#[cfg(desktop)]
fn apply_action(app: &AppHandle, action: BackendAction) -> Result<ProfileSnapshot, String> {
    match action {
        BackendAction::ToggleConnection => {
            let connected = with_profile(app, |session| session.book.snapshot().connected);
            if connected {
                Ok(disconnect_session(app.clone()))
            } else {
                connect_session(app.clone())
            }
        }
        BackendAction::SystemProxy => {
            let on = with_profile(app, |session| session.book.snapshot().system_proxy);
            Ok(set_system_proxy(app.clone(), !on))
        }
        BackendAction::Tun => {
            let on = with_profile(app, |session| session.book.snapshot().tun);
            set_tun_enabled(app.clone(), !on)
        }
        BackendAction::Mode(mode) => Ok(set_outbound_mode(app.clone(), mode)),
        BackendAction::Profile(id) => Ok(enable_profile(app.clone(), id)),
        BackendAction::Node { group, node } => Ok(select_profile_node(app.clone(), group, node)),
        BackendAction::Show
        | BackendAction::Navigate(_)
        | BackendAction::ToggleWindow
        | BackendAction::Quit => unreachable!("handled synchronously"),
    }
}

#[cfg(desktop)]
fn tray_action(app: &AppHandle, id: &str) {
    let Some(command) = tray::parse(id) else {
        return;
    };
    dispatch(app, BackendAction::from_tray(command), false);
}

/// A global shortcut runs through the same dispatcher as the tray (R39).
#[cfg(desktop)]
fn run_hotkey(app: &AppHandle, action: hotkeys::Action) {
    dispatch(app, BackendAction::from_hotkey(action), true);
}

#[cfg(desktop)]
fn build_menu_items(
    app: &AppHandle,
    entries: &[tray::TrayEntry],
) -> tauri::Result<Vec<Box<dyn tauri::menu::IsMenuItem<tauri::Wry>>>> {
    use tauri::menu::{CheckMenuItem, MenuItem, PredefinedMenuItem, Submenu};
    use tray::TrayEntry;
    let mut items: Vec<Box<dyn tauri::menu::IsMenuItem<tauri::Wry>>> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        match entry {
            TrayEntry::Label(text) => {
                items.push(Box::new(MenuItem::with_id(app, format!("label-{index}"), text, false, None::<&str>)?));
            }
            TrayEntry::Action { id, text, enabled } => {
                items.push(Box::new(MenuItem::with_id(app, id.as_str(), text, *enabled, None::<&str>)?));
            }
            TrayEntry::Check { id, text, checked, enabled } => {
                items.push(Box::new(CheckMenuItem::with_id(app, id.as_str(), text, *enabled, *checked, None::<&str>)?));
            }
            TrayEntry::Submenu { text, enabled, items: children } => {
                let built = build_menu_items(app, children)?;
                let refs: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = built.iter().map(|item| item.as_ref()).collect();
                items.push(Box::new(Submenu::with_items(app, text, *enabled, &refs)?));
            }
            TrayEntry::Separator => items.push(Box::new(PredefinedMenuItem::separator(app)?)),
        }
    }
    Ok(items)
}

#[cfg(desktop)]
fn tray_menu(app: &AppHandle, snapshot: &ProfileSnapshot) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    let items = build_menu_items(app, &tray::model(snapshot, i18n::locale()))?;
    let refs: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = items.iter().map(|item| item.as_ref()).collect();
    tauri::menu::Menu::with_items(app, &refs)
}

#[cfg(desktop)]
fn refresh_tray(app: &AppHandle, snapshot: &ProfileSnapshot) {
    let Some(tray) = app.tray_by_id("billow") else {
        return;
    };
    if let Ok(menu) = tray_menu(app, snapshot) {
        let _ = tray.set_menu(Some(menu));
    }
    let _ = tray.set_tooltip(Some(tray::tooltip(snapshot, i18n::locale())));
}

#[cfg(not(desktop))]
fn refresh_tray(_app: &AppHandle, _snapshot: &ProfileSnapshot) {}

#[cfg(desktop)]
fn has_tray(app: &AppHandle) -> bool {
    app.tray_by_id("billow").is_some()
}

#[cfg(not(desktop))]
fn has_tray(_app: &AppHandle) -> bool {
    false
}

/// macOS menu bar icons are monochrome templates the system tints for light,
/// dark and highlighted bars; Windows and Linux keep the colour app icon.
#[cfg(target_os = "macos")]
fn tray_icon(_app: &tauri::App) -> Option<tauri::image::Image<'static>> {
    tauri::image::Image::from_bytes(include_bytes!("../icons/tray-template.png")).ok()
}

#[cfg(all(desktop, not(target_os = "macos")))]
fn tray_icon(app: &tauri::App) -> Option<tauri::image::Image<'static>> {
    app.default_window_icon().map(|icon| icon.clone().to_owned())
}

#[cfg(desktop)]
fn prepare_tray(app: &tauri::App) {
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    let handle = app.handle().clone();
    let snapshot = with_profile(&handle, |session| session.book.snapshot());
    let Ok(menu) = tray_menu(&handle, &snapshot) else {
        return;
    };
    let mut builder = TrayIconBuilder::with_id("billow")
        .tooltip(tray::tooltip(&snapshot, i18n::locale()))
        .menu(&menu)
        // Left click opens the window on Windows/Linux; macOS menu bar items
        // conventionally open their menu on any click.
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .on_menu_event(|app, event| tray_action(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| {
            if cfg!(target_os = "macos") {
                return;
            }
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = tray_icon(app) {
        builder = builder.icon(icon);
    }
    #[cfg(target_os = "macos")]
    {
        builder = builder.icon_as_template(true);
    }
    if let Err(err) = builder.build(app) {
        eprintln!("Billow tray was not created: {err}");
    }
}

#[tauri::command(async)]
fn sync_tray(app: AppHandle) {
    let snapshot = with_profile(&app, |session| session.book.snapshot());
    refresh_tray(&app, &snapshot);
}

/// The global shortcut bindings, whether this platform can use them and why not (R39).
#[tauri::command(async)]
fn hotkey_settings(app: AppHandle) -> hotkeys::Settings {
    hotkeys::settings(&app)
}

/// Bind one action to a combination, or clear it with an empty string. A
/// rejected edit leaves the stored binding untouched and returns its reason.
#[tauri::command(async)]
fn set_hotkey(app: AppHandle, action: String, combo: String) -> Result<hotkeys::Settings, String> {
    hotkeys::set(&app, &action, &combo)
}

fn release_proxy_on_exit(app: &AppHandle) {
    let store = app.state::<ProfileStore>();
    let mut session = lock_profiles(&store.session);
    let ProfileSession { book, runtime, proxy, .. } = &mut *session;
    book.prepare_exit();
    runtime.shutdown();
    book.release_lingering_proxy(proxy);
}

fn on_window_event(app: &AppHandle, label: &str, event: tauri::WindowEvent) {
    if label != "main" {
        return;
    }
    match event {
        tauri::WindowEvent::Resized(size) if size.width > 0 && size.height > 0 => {
            remember_window_size(app);
        }
        tauri::WindowEvent::ScaleFactorChanged { .. } => remember_window_size(app),
        tauri::WindowEvent::CloseRequested { api, .. } => {
            remember_window_size(app);
            let to_tray = {
                let store = app.state::<Store>();
                lock(&store.state).close_to_tray
            };
            if !APP_UPDATING.load(Ordering::SeqCst) && to_tray && has_tray(app) {
                api.prevent_close();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
                return;
            }
            release_proxy_on_exit(app);
        }
        _ => {}
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "windows")]
    if elevation::run_helper_if_requested() { return; }
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init());
    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        // Global shortcuts (R39) and the notification a failed action sends.
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
        tauri_plugin_autostart::MacosLauncher::LaunchAgent,
        Some(vec!["--autostart"]),
    ));
    builder
        .invoke_handler(tauri::generate_handler![
            app_update::check_android_app_update,
            prepare_app_update,
            shell_state,
            set_theme,
            set_language,
            set_last_entry,
            kernel_state,
            set_kernel_channel,
            connect_kernel,
            profile_state,
            add_subscription_profile,
            add_local_profile,
            stage_install_link,
            confirm_install_link,
            cancel_install_link,
            enable_profile,
            update_profile,
            save_profile_override,
            preview_profile_override,
            connect_session,
            disconnect_session,
            set_system_proxy,
            set_tun_enabled,
            exclude_package,
            include_package,
            set_app_rules,
            select_profile_node,
            unfix_profile_group,
            test_profile_group,
            set_node_query,
            set_node_sort,
            set_connection_query,
            set_log_filter,
            set_outbound_mode,
            delete_profile,
            rename_profile,
            set_profile_source,
            set_profile_user_agent,
            set_profile_interval,
            set_profile_age_key,
            profile_content,
            effective_config,
            config_overview,
            lan_address,
            save_profile_content,
            refresh_profile,
            refresh_all_profiles,
            save_kernel_settings,
            test_all_nodes,
            test_node,
            close_connection,
            close_connections,
            dns_query,
            kernel_rules,
            set_rule_disabled,
            clear_logs,
            export_logs,
            export_backup,
            restore_backup_text,
            webdav_settings,
            set_webdav_settings,
            test_webdav,
            upload_backup,
            list_remote_backups,
            restore_remote_backup,
            clear_notice,
            refresh_kernel,
            app_info,
            set_autostart,
            set_app_behavior,
            sync_tray,
            hotkey_settings,
            set_hotkey,
            flush_cache,
            restart_kernel,
            kernel_gc,
            kernel_providers,
            provider_action,
            upgrade_geo,
            open_uwp_tool,
            list_uwp_apps,
            save_uwp_exemptions,
            provider_detail,
            geo_files
        ])
        .setup(move |app| {
            prepare_shell(app);
            prepare_kernel(app);
            prepare_profiles(app);
            spawn_auto_update(app.handle());
            #[cfg(desktop)]
            {
                prepare_tray(app);
                // Bindings from the previous run come back before the window loads (R39).
                hotkeys::prepare(app.handle());
                let silent = {
                    let store = app.state::<Store>();
                    lock(&store.state).silent_start
                };
                let autostarted = std::env::args().any(|arg| arg == "--autostart");
                if silent && autostarted {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.hide();
                    }
                }
            }
            spawn_kernel_guardian(app.handle());
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Billow")
        .run(|app, event| match event {
            tauri::RunEvent::WindowEvent { label, event, .. } => on_window_event(app, &label, event),
            // Clicking the Dock icon (or relaunching from Finder/Launchpad) while the
            // window sits hidden in the menu bar brings it back.
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { has_visible_windows, .. } => {
                if !has_visible_windows {
                    show_main(app);
                }
            }
            // Dock "Quit", Cmd+Q and system logout skip the window close path;
            // never leave the OS proxy pointing at a kernel that is gone.
            tauri::RunEvent::Exit => release_proxy_on_exit(app),
            _ => {}
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(reason: &str) -> ProfileSnapshot {
        ProfileSnapshot {
            failure: Some(reason.to_string()),
            ..ProfileSnapshot::default()
        }
    }

    #[test]
    fn a_shortcut_announces_only_a_reason_its_own_action_raised() {
        let clean = ProfileSnapshot::default();
        // Nothing failed: nothing to announce.
        assert_eq!(shortcut_failure(true, None, &clean), None);
        // A failure that was not there before is announced.
        assert_eq!(shortcut_failure(true, None, &failed("授权被拒绝")), Some("授权被拒绝".to_string()));
        // A different reason replaces the old one, so it is announced again.
        assert_eq!(
            shortcut_failure(true, Some("授权被拒绝"), &failed("内核没有启动")),
            Some("内核没有启动".to_string())
        );
        // The same stale banner is not repeated on the next press.
        assert_eq!(shortcut_failure(true, Some("授权被拒绝"), &failed("授权被拒绝")), None);
        // The tray path never sends a notification, even when the action failed.
        assert_eq!(shortcut_failure(false, None, &failed("授权被拒绝")), None);
        assert_eq!(shortcut_failure(false, Some("授权被拒绝"), &failed("内核没有启动")), None);
    }
}
