mod shell;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tauri::{AppHandle, Manager};

use shell::{read_shell_state, resolve_entry, resolve_theme, write_shell_state, ShellState};

struct Store {
    state: Mutex<ShellState>,
    /// Ignore the initial default-size event until the restored size is seen.
    accept_resize: AtomicBool,
}

fn lock(state: &Mutex<ShellState>) -> std::sync::MutexGuard<'_, ShellState> {
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

fn on_window_event(app: &AppHandle, label: &str, event: tauri::WindowEvent) {
    if label != "main" {
        return;
    }
    match event {
        tauri::WindowEvent::Resized(size) if size.width > 0 && size.height > 0 => {
            remember_window_size(app);
        }
        tauri::WindowEvent::ScaleFactorChanged { .. } => remember_window_size(app),
        tauri::WindowEvent::CloseRequested { .. } => remember_window_size(app),
        _ => {}
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![shell_state, set_theme, set_last_entry])
        .setup(|app| {
            prepare_shell(app);
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
