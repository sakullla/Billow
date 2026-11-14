mod kernel;
mod profile;
mod shell;
mod takeover;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tauri::{AppHandle, Emitter, Manager};

use kernel::{
    parse_channel, ConnectResult, GithubReleaseClient, KernelManager, KernelStatus, PlatformTarget,
};
use profile::{HttpSubscriptionClient, ProcessRuntime, ProfileBook, ProfileSnapshot};
use shell::{read_shell_state, resolve_entry, resolve_theme, write_shell_state, ShellState};

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
    state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_kernel(state: &Mutex<KernelManager>) -> std::sync::MutexGuard<'_, KernelManager> {
    state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_profiles(state: &Mutex<ProfileSession>) -> std::sync::MutexGuard<'_, ProfileSession> {
    state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
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
        Err(_) => std::env::temp_dir().join(format!("billow-profiles-unavailable-{}", std::process::id())),
    };
    let mut book = ProfileBook::open(&directory);
    let runtime = ProcessRuntime::new(&directory);
    let mut proxy = takeover::host_proxy();
    book.release_lingering_proxy(&mut proxy);
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
                std::env::temp_dir().join(format!("billow-kernel-unavailable-{}", std::process::id())),
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
    lock_profiles(&store.session).book.snapshot()
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
    let snapshot = if update {
        book.update(id, &client, runtime)
    } else {
        book.enable(id, &client, runtime)
    };
    if let Some(release) = book.take_release() {
        takeover::release_platform(proxy, tun, vpn, &release);
    }
    snapshot
}

fn with_session(app: &AppHandle, change: impl FnOnce(&mut ProfileSession) -> ProfileSnapshot) -> ProfileSnapshot {
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
        let ProfileSession { book, runtime, tun, .. } = session;
        book.set_tun(enabled, runtime, tun)
    })
}

#[tauri::command]
fn exclude_package(app: AppHandle, package_name: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, vpn, .. } = session;
        book.exclude_package(&package_name, vpn)
    })
}

#[tauri::command]
fn include_package(app: AppHandle, package_name: String) -> ProfileSnapshot {
    with_session(&app, |session| {
        let ProfileSession { book, vpn, .. } = session;
        book.include_package(&package_name, vpn)
    })
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
        tauri::WindowEvent::CloseRequested { .. } => {
            remember_window_size(app);
            release_proxy_on_exit(app);
        }
        _ => {}
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
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
            include_package
        ])
        .setup(|app| {
            prepare_shell(app);
            prepare_kernel(app);
            prepare_profiles(app);
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
