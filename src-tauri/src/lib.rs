mod diagnostics;
mod kernel;
mod nodes;
mod profile;
mod shell;
mod takeover;

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use tauri::{AppHandle, Emitter, Manager};

use kernel::{
    ConnectResult, GithubReleaseClient, KernelManager, KernelStatus, PlatformTarget, parse_channel,
};
use profile::{
    HttpSubscriptionClient, KernelSettings, ProcessRuntime, ProfileBook, ProfileSnapshot,
    ProvidersSnapshot, RulesSnapshot,
};
use shell::{ShellState, read_shell_state, resolve_entry, resolve_theme, write_shell_state};

struct Store {
    state: Mutex<ShellState>,
    /// Ignore the initial default-size event until the restored size is seen.
    accept_resize: AtomicBool,
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
    restore_window(app.handle(), &state);
    app.manage(Store {
        state: Mutex::new(state),
        accept_resize: AtomicBool::new(false),
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
    let runtime = ProcessRuntime::new(&directory);
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
    let manager = match kernel_dir(app.handle()) {
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
    app.manage(KernelStore {
        manager: Mutex::new(manager),
    });
    let handle = app.handle().clone();
    std::thread::spawn(move || {
        let store = handle.state::<KernelStore>();
        let mut manager = lock_kernel(&store.manager);
        let channel = manager.channel();
        manager.sync(channel, &GithubReleaseClient::new());
    });
}

#[tauri::command]
fn shell_state(app: AppHandle) -> ShellState {
    let store = app.state::<Store>();
    lock(&store.state).clone()
}

#[tauri::command]
fn set_theme(app: AppHandle, theme: String) -> ShellState {
    let resolved = resolve_theme(&theme).to_string();
    let store = app.state::<Store>();
    let snapshot = {
        let mut state = lock(&store.state);
        state.theme = resolved.clone();
        persist(&app, &state);
        state.clone()
    };
    apply_native_theme(&app, &resolved);
    snapshot
}

#[tauri::command]
fn set_last_entry(app: AppHandle, entry: String) -> ShellState {
    let store = app.state::<Store>();
    let mut state = lock(&store.state);
    state.last_entry = resolve_entry(&entry).to_string();
    persist(&app, &state);
    state.clone()
}

#[tauri::command]
fn kernel_state(app: AppHandle) -> KernelStatus {
    let store = app.state::<KernelStore>();
    lock_kernel(&store.manager).status()
}

#[tauri::command]
fn set_kernel_channel(app: AppHandle, channel: String) -> KernelStatus {
    let store = app.state::<KernelStore>();
    let mut manager = lock_kernel(&store.manager);
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

#[tauri::command]
fn connect_kernel(app: AppHandle) -> ConnectStatus {
    let store = app.state::<KernelStore>();
    let mut manager = lock_kernel(&store.manager);
    manager.connect().into()
}

fn profile_snapshot(app: &AppHandle) -> ProfileSnapshot {
    let store = app.state::<ProfileStore>();
    let mut session = lock_profiles(&store.session);
    let mut installed = takeover::HostInstalledApps;
    session.book.refresh_installed(&mut installed);
    let ProfileSession { book, runtime, .. } = &mut *session;
    book.sync_runtime(runtime);
    book.snapshot()
}

fn with_profile<T>(app: &AppHandle, change: impl FnOnce(&mut ProfileSession) -> T) -> T {
    let store = app.state::<ProfileStore>();
    let mut session = lock_profiles(&store.session);
    change(&mut session)
}

fn activate_profile(app: &AppHandle, id: &str, update: bool) -> ProfileSnapshot {
    let kernel_path = {
        let store = app.state::<KernelStore>();
        lock_kernel(&store.manager).installed_path()
    };
    let client = HttpSubscriptionClient::new();
    let store = app.state::<ProfileStore>();
    let mut session = lock_profiles(&store.session);
    let ProfileSession {
        book,
        runtime,
        proxy,
        tun,
        vpn,
    } = &mut *session;
    runtime.set_kernel_path(kernel_path);
    if update {
        book.update(id, &client, runtime);
    } else {
        book.enable(id, &client, runtime);
    }
    book.apply_release(proxy, tun, vpn);
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
    session.runtime.set_kernel_path(kernel_path);
    change(&mut session)
}

#[tauri::command]
fn profile_state(app: AppHandle) -> ProfileSnapshot {
    profile_snapshot(&app)
}

#[tauri::command]
fn add_subscription_profile(app: AppHandle, url: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.add_subscription(&url))
}

#[tauri::command]
fn add_local_profile(app: AppHandle, name: String, content: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.add_local(&name, &content))
}

#[tauri::command]
fn stage_install_link(app: AppHandle, link: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.stage_install_link(&link))
}

#[tauri::command]
fn confirm_install_link(app: AppHandle) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.confirm_pending())
}

#[tauri::command]
fn cancel_install_link(app: AppHandle) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.cancel_pending())
}

#[tauri::command]
fn enable_profile(app: AppHandle, id: String) -> ProfileSnapshot {
    activate_profile(&app, &id, false)
}

#[tauri::command]
fn update_profile(app: AppHandle, id: String) -> ProfileSnapshot {
    activate_profile(&app, &id, true)
}

#[tauri::command]
fn save_profile_override(app: AppHandle, id: String, text: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.save_override(&id, &text))
}

#[tauri::command]
fn connect_session(app: AppHandle) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession {
            book,
            runtime,
            proxy,
            tun,
            vpn,
        } = session;
        book.connect(runtime, proxy, tun, vpn)
    })
}

#[tauri::command]
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

#[tauri::command]
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

#[tauri::command]
fn set_tun_enabled(app: AppHandle, enabled: bool) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession {
            book,
            runtime,
            proxy,
            tun,
            vpn,
        } = session;
        book.set_tun(enabled, runtime, proxy, tun, vpn)
    })
}

#[tauri::command]
fn exclude_package(app: AppHandle, package_name: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession {
            book, runtime, vpn, ..
        } = session;
        book.exclude_package(&package_name, runtime, vpn)
    })
}

#[tauri::command]
fn include_package(app: AppHandle, package_name: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession {
            book, runtime, vpn, ..
        } = session;
        book.include_package(&package_name, runtime, vpn)
    })
}

#[tauri::command]
fn select_profile_node(app: AppHandle, group: String, node: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.select_node(&group, &node, runtime)
    })
}

#[tauri::command]
fn test_profile_group(app: AppHandle, group: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.test_group(&group, runtime)
    })
}

#[tauri::command]
fn set_node_query(app: AppHandle, query: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.set_node_query(&query))
}

#[tauri::command]
fn set_node_sort(app: AppHandle, group: String, sort: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.set_node_sort(&group, &sort))
}

#[tauri::command]
fn set_connection_query(app: AppHandle, query: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.set_connection_query(&query, runtime)
    })
}

#[tauri::command]
fn set_outbound_mode(app: AppHandle, mode: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.set_outbound_mode(&mode, runtime)
    })
}

#[tauri::command]
fn set_log_filter(app: AppHandle, level: String) -> ProfileSnapshot {
    with_profile(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.set_log_filter(&level, runtime)
    })
}

#[tauri::command]
fn delete_profile(app: AppHandle, id: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.delete_profile(&id))
}

#[tauri::command]
fn rename_profile(app: AppHandle, id: String, name: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.rename_profile(&id, &name))
}

#[tauri::command]
fn set_profile_source(app: AppHandle, id: String, url: String) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.set_profile_source(&id, &url))
}

#[tauri::command]
fn set_profile_interval(app: AppHandle, id: String, hours: u32) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.set_profile_interval(&id, hours))
}

#[tauri::command]
fn profile_content(app: AppHandle, id: String) -> Option<String> {
    with_profile(&app, |session| session.book.profile_content(&id))
}

#[tauri::command]
fn save_profile_content(app: AppHandle, id: String, content: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.save_profile_content(&id, &content, runtime)
    })
}

#[tauri::command]
fn refresh_profile(app: AppHandle, id: String) -> ProfileSnapshot {
    let client = HttpSubscriptionClient::new();
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.refresh_profile(&id, &client, runtime)
    })
}

#[tauri::command]
fn refresh_all_profiles(app: AppHandle) -> ProfileSnapshot {
    let ids = with_profile(&app, |session| session.book.subscription_ids());
    refresh_ids(&app, &ids)
}

fn refresh_ids(app: &AppHandle, ids: &[String]) -> ProfileSnapshot {
    let client = HttpSubscriptionClient::new();
    let mut last = None;
    // One lock per profile so a slow subscription does not freeze the whole UI.
    for id in ids {
        last = Some(with_session(app, |session| {
            let ProfileSession { book, runtime, .. } = session;
            book.refresh_profile(id, &client, runtime)
        }));
    }
    last.unwrap_or_else(|| profile_snapshot(app))
}

#[tauri::command]
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

#[tauri::command]
fn test_all_nodes(app: AppHandle) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.test_all(runtime)
    })
}

#[tauri::command]
fn test_node(app: AppHandle, node: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.test_node(&node, runtime)
    })
}

#[tauri::command]
fn close_connection(app: AppHandle, id: Option<String>) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.close_connections(id.as_deref(), runtime)
    })
}

#[tauri::command]
fn kernel_rules(app: AppHandle) -> RulesSnapshot {
    with_session_raw(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.rules(runtime)
    })
}

#[tauri::command]
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

/// Provider downloads can take a while, so they run without the profile lock held.
#[tauri::command]
async fn provider_action(app: AppHandle, kind: String, name: String, action: String) -> Result<(), String> {
    let endpoint = controller(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        diagnostics::provider_action(&endpoint, &kind, &name, &action)
    })
    .await
    .map_err(|err| err.to_string())?
}

#[tauri::command]
async fn upgrade_geo(app: AppHandle) -> Result<(), String> {
    let endpoint = controller(&app)?;
    tauri::async_runtime::spawn_blocking(move || diagnostics::upgrade_geo(&endpoint))
        .await
        .map_err(|err| err.to_string())?
}

#[tauri::command]
fn flush_cache(app: AppHandle, which: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, runtime, .. } = session;
        book.flush_cache(&which, runtime)
    })
}

#[tauri::command]
fn clear_logs(app: AppHandle) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.clear_logs())
}

#[tauri::command]
fn clear_notice(app: AppHandle) -> ProfileSnapshot {
    with_profile(&app, |session| session.book.clear_notice())
}

#[tauri::command]
fn refresh_kernel(app: AppHandle) -> KernelStatus {
    let store = app.state::<KernelStore>();
    let mut manager = lock_kernel(&store.manager);
    let channel = manager.channel();
    manager.sync(channel, &GithubReleaseClient::new())
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
    session.runtime.set_kernel_path(kernel_path);
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

#[cfg(desktop)]
fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg(desktop)]
fn tray_action(app: &AppHandle, id: &str) {
    let snapshot = match id {
        "show" => {
            show_main(app);
            return;
        }
        "quit" => {
            release_proxy_on_exit(app);
            app.exit(0);
            return;
        }
        "connect" => {
            let connected = with_profile(app, |session| session.book.snapshot().connected);
            if connected {
                disconnect_session(app.clone())
            } else {
                connect_session(app.clone())
            }
        }
        "proxy" => {
            let on = with_profile(app, |session| session.book.snapshot().system_proxy);
            set_system_proxy(app.clone(), !on)
        }
        "tun" => {
            let on = with_profile(app, |session| session.book.snapshot().tun);
            set_tun_enabled(app.clone(), !on)
        }
        "rule" | "global" | "direct" => set_outbound_mode(app.clone(), id.to_string()),
        _ => return,
    };
    refresh_tray(app, &snapshot);
    let _ = app.emit("profile-changed", snapshot);
}

#[cfg(desktop)]
fn tray_menu(app: &AppHandle, snapshot: &ProfileSnapshot) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
    let status = MenuItem::with_id(
        app,
        "status",
        if snapshot.connected { "Billow · 已连接" } else { "Billow · 未连接" },
        false,
        None::<&str>,
    )?;
    let show = MenuItem::with_id(app, "show", "打开主界面", true, None::<&str>)?;
    let connect = MenuItem::with_id(
        app,
        "connect",
        if snapshot.connected { "断开" } else { "连接" },
        snapshot.active_id.is_some(),
        None::<&str>,
    )?;
    let proxy = CheckMenuItem::with_id(app, "proxy", "系统代理", true, snapshot.system_proxy, None::<&str>)?;
    let tun = CheckMenuItem::with_id(app, "tun", "TUN 模式", true, snapshot.tun, None::<&str>)?;
    let mode = snapshot.mode.as_deref().unwrap_or("");
    let rule = CheckMenuItem::with_id(app, "rule", "规则", true, mode == "rule", None::<&str>)?;
    let global = CheckMenuItem::with_id(app, "global", "全局", true, mode == "global", None::<&str>)?;
    let direct = CheckMenuItem::with_id(app, "direct", "直连", true, mode == "direct", None::<&str>)?;
    let modes = Submenu::with_items(app, "出站模式", true, &[&rule, &global, &direct])?;
    let quit = MenuItem::with_id(app, "quit", "退出 Billow", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    Menu::with_items(
        app,
        &[&status, &show, &sep, &connect, &proxy, &tun, &modes, &sep2, &quit],
    )
}

#[cfg(desktop)]
fn refresh_tray(app: &AppHandle, snapshot: &ProfileSnapshot) {
    let Some(tray) = app.tray_by_id("billow") else {
        return;
    };
    if let Ok(menu) = tray_menu(app, snapshot) {
        let _ = tray.set_menu(Some(menu));
    }
    let _ = tray.set_tooltip(Some(if snapshot.connected { "Billow · 已连接" } else { "Billow" }));
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

#[cfg(desktop)]
fn prepare_tray(app: &tauri::App) {
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    let handle = app.handle().clone();
    let snapshot = with_profile(&handle, |session| session.book.snapshot());
    let Ok(menu) = tray_menu(&handle, &snapshot) else {
        return;
    };
    let mut builder = TrayIconBuilder::with_id("billow")
        .tooltip("Billow")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| tray_action(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    if let Err(err) = builder.build(app) {
        eprintln!("Billow tray was not created: {err}");
    }
}

#[tauri::command]
fn sync_tray(app: AppHandle) {
    let snapshot = with_profile(&app, |session| session.book.snapshot());
    refresh_tray(&app, &snapshot);
}

fn release_proxy_on_exit(app: &AppHandle) {
    let store = app.state::<ProfileStore>();
    let mut session = lock_profiles(&store.session);
    let ProfileSession { book, proxy, .. } = &mut *session;
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
            if to_tray && has_tray(app) {
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
    let builder = tauri::Builder::default().plugin(tauri_plugin_deep_link::init());
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_autostart::init(
        tauri_plugin_autostart::MacosLauncher::LaunchAgent,
        Some(vec!["--autostart"]),
    ));
    builder
        .invoke_handler(tauri::generate_handler![
            shell_state,
            set_theme,
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
            connect_session,
            disconnect_session,
            set_system_proxy,
            set_tun_enabled,
            exclude_package,
            include_package,
            select_profile_node,
            test_profile_group,
            set_node_query,
            set_node_sort,
            set_connection_query,
            set_log_filter,
            set_outbound_mode,
            delete_profile,
            rename_profile,
            set_profile_source,
            set_profile_interval,
            profile_content,
            save_profile_content,
            refresh_profile,
            refresh_all_profiles,
            save_kernel_settings,
            test_all_nodes,
            test_node,
            close_connection,
            kernel_rules,
            clear_logs,
            clear_notice,
            refresh_kernel,
            app_info,
            set_autostart,
            set_app_behavior,
            sync_tray,
            flush_cache,
            kernel_providers,
            provider_action,
            upgrade_geo
        ])
        .setup(|app| {
            prepare_shell(app);
            prepare_kernel(app);
            prepare_profiles(app);
            spawn_auto_update(app.handle());
            #[cfg(desktop)]
            {
                prepare_tray(app);
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
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Billow")
        .run(|app, event| {
            if let tauri::RunEvent::WindowEvent { label, event, .. } = event {
                on_window_event(app, &label, event);
            }
        });
}
