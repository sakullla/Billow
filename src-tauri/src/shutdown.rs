//! Coordinated OS shutdown handling.
//!
//! On Windows, `tao` ignores `WM_QUERYENDSESSION` and calls `std::process::exit(0)`
//! (`ExitProcess`) inside `WM_ENDSESSION`, which unloads WebView2/COM/driver DLLs via
//! `DllMain(DLL_PROCESS_DETACH)` while background threads and out-of-process COM
//! peers (`msedgewebview2.exe`, `explorer.exe`) are already tearing down — producing
//! `0x... 该内存不能为 read/written` dialogs during shutdown when TUN is active.
//!
//! This module coordinates shutdown priority (`0x380` main UI before `0x280` kernel
//! and `0x180` elevated helper), suppresses background recovery/UI emissions as soon
//! as session teardown begins, runs TUN/kernel/proxy cleanup once under a blocking
//! lock, and terminates cleanly without triggering `DllMain` detach crashes.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) struct ShutdownCoordinator {
    querying: AtomicBool,
    terminating: AtomicBool,
    cleanup_done: Mutex<bool>,
}

impl ShutdownCoordinator {
    pub(crate) const fn new() -> Self {
        Self {
            querying: AtomicBool::new(false),
            terminating: AtomicBool::new(false),
            cleanup_done: Mutex::new(false),
        }
    }

    pub(crate) fn on_query_end_session(&self) {
        self.querying.store(true, Ordering::SeqCst);
    }

    pub(crate) fn on_end_session(&self, ending: bool) -> bool {
        if ending {
            self.querying.store(true, Ordering::SeqCst);
            self.terminating.store(true, Ordering::SeqCst);
            true
        } else {
            if !self.terminating.load(Ordering::SeqCst) {
                self.querying.store(false, Ordering::SeqCst);
            }
            false
        }
    }

    pub(crate) fn should_suppress_background_work(&self, os_shutting_down: bool) -> bool {
        self.terminating.load(Ordering::SeqCst)
            || self.querying.load(Ordering::SeqCst)
            || os_shutting_down
    }

    pub(crate) fn is_system_terminating(&self, os_shutting_down: bool) -> bool {
        self.terminating.load(Ordering::SeqCst) || os_shutting_down
    }

    /// Runs `cleanup` at most once; concurrent callers block until that single run
    /// finishes so no thread terminates the process mid-cleanup.
    pub(crate) fn run_cleanup_once(&self, cleanup: impl FnOnce()) {
        let mut done = self
            .cleanup_done
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !*done {
            cleanup();
            *done = true;
        }
    }
}

static COORDINATOR: ShutdownCoordinator = ShutdownCoordinator::new();

pub fn suppress_background_work() -> bool {
    COORDINATOR.should_suppress_background_work(os_shutting_down())
}

pub fn is_system_shutting_down() -> bool {
    COORDINATOR.is_system_terminating(os_shutting_down())
}

pub fn run_exit_cleanup_once(cleanup: impl FnOnce()) {
    COORDINATOR.run_cleanup_once(cleanup);
}

#[cfg(not(target_os = "windows"))]
fn os_shutting_down() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn os_shutting_down() -> bool {
    win::system_metrics_shutting_down()
}

#[cfg(target_os = "windows")]
pub fn configure_main_process() {
    win::configure_main_process();
}

#[cfg(target_os = "windows")]
pub fn configure_helper_process() {
    win::configure_helper_process();
}

#[cfg(target_os = "windows")]
pub fn spawn_windows_shutdown_listener(app: tauri::AppHandle) {
    win::spawn_listener(app, &COORDINATOR);
}

#[cfg(target_os = "windows")]
pub fn terminate_current_process_if_shutting_down() {
    if is_system_shutting_down() {
        win::terminate_immediately();
    }
}

#[cfg(target_os = "windows")]
mod win {
    use std::ffi::c_void;
    use std::sync::OnceLock;

    use super::ShutdownCoordinator;

    type Hwnd = *mut c_void;
    type Hinstance = *mut c_void;
    type Hicon = *mut c_void;
    type Hcursor = *mut c_void;
    type Hbrush = *mut c_void;
    type Wparam = usize;
    type Lparam = isize;
    type Lresult = isize;
    type WndProc = Option<unsafe extern "system" fn(Hwnd, u32, Wparam, Lparam) -> Lresult>;

    const SM_SHUTTINGDOWN: i32 = 0x2000;
    const WM_QUERYENDSESSION: u32 = 0x0011;
    const WM_ENDSESSION: u32 = 0x0016;
    const WS_POPUP: u32 = 0x8000_0000;
    const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
    const WS_EX_NOACTIVATE: u32 = 0x0800_0000;

    /// Shut down main Billow (`0x380`) before default (`0x280`) kernels/WebView2
    /// and before the elevated supervisor (`0x180`).
    const MAIN_SHUTDOWN_LEVEL: u32 = 0x380;
    const HELPER_SHUTDOWN_LEVEL: u32 = 0x180;
    const SHUTDOWN_NORETRY: u32 = 0x0000_0001;

    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
    const SEM_NOOPENFILEERRORBOX: u32 = 0x8000;

    #[repr(C)]
    struct WndClassExW {
        cb_size: u32,
        style: u32,
        lpfn_wnd_proc: WndProc,
        cb_cls_extra: i32,
        cb_wnd_extra: i32,
        h_instance: Hinstance,
        h_icon: Hicon,
        h_cursor: Hcursor,
        hbr_background: Hbrush,
        lpsz_menu_name: *const u16,
        lpsz_class_name: *const u16,
        h_icon_sm: Hicon,
    }

    #[repr(C)]
    struct Point {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    struct Msg {
        hwnd: Hwnd,
        message: u32,
        w_param: Wparam,
        l_param: Lparam,
        time: u32,
        pt: Point,
        l_private: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn TerminateProcess(process: *mut c_void, exit_code: u32) -> i32;
        fn GetModuleHandleW(module_name: *const u16) -> Hinstance;
        fn SetProcessShutdownParameters(level: u32, flags: u32) -> i32;
        fn SetErrorMode(mode: u32) -> u32;
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetSystemMetrics(index: i32) -> i32;
        fn RegisterClassExW(wnd_class: *const WndClassExW) -> u16;
        fn CreateWindowExW(
            ex_style: u32,
            class_name: *const u16,
            window_name: *const u16,
            style: u32,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            parent: Hwnd,
            menu: *mut c_void,
            instance: Hinstance,
            param: *mut c_void,
        ) -> Hwnd;
        fn DefWindowProcW(hwnd: Hwnd, msg: u32, w_param: Wparam, l_param: Lparam) -> Lresult;
        fn GetMessageW(
            msg: *mut Msg,
            hwnd: Hwnd,
            msg_filter_min: u32,
            msg_filter_max: u32,
        ) -> i32;
        fn TranslateMessage(msg: *const Msg) -> i32;
        fn DispatchMessageW(msg: *const Msg) -> Lresult;
    }

    static LISTENER_CONTEXT: OnceLock<(tauri::AppHandle, &'static ShutdownCoordinator)> =
        OnceLock::new();

    pub(super) fn system_metrics_shutting_down() -> bool {
        unsafe { GetSystemMetrics(SM_SHUTTINGDOWN) != 0 }
    }

    pub(super) fn suppress_crash_dialogs() {
        unsafe {
            SetErrorMode(
                SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX,
            );
        }
    }

    pub(super) fn configure_main_process() {
        unsafe {
            let _ = SetProcessShutdownParameters(MAIN_SHUTDOWN_LEVEL, SHUTDOWN_NORETRY);
        }
    }

    pub(super) fn configure_helper_process() {
        // Inherited by child `mihomo.exe`, preventing WER/GPF popups if Windows
        // forcibly tears down kernel drivers during power-off.
        suppress_crash_dialogs();
        unsafe {
            let _ = SetProcessShutdownParameters(HELPER_SHUTDOWN_LEVEL, SHUTDOWN_NORETRY);
        }
    }

    pub(super) fn terminate_immediately() -> ! {
        suppress_crash_dialogs();
        unsafe {
            let _ = TerminateProcess(GetCurrentProcess(), 0);
        }
        std::process::abort()
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: Hwnd,
        msg: u32,
        w_param: Wparam,
        l_param: Lparam,
    ) -> Lresult {
        match msg {
            WM_QUERYENDSESSION => {
                if let Some((_, coordinator)) = LISTENER_CONTEXT.get() {
                    coordinator.on_query_end_session();
                }
                suppress_crash_dialogs();
                1
            }
            WM_ENDSESSION => {
                let ending = w_param != 0;
                if let Some((app, coordinator)) = LISTENER_CONTEXT.get() {
                    if coordinator.on_end_session(ending) {
                        suppress_crash_dialogs();
                        crate::cleanup_for_exit(app);
                        terminate_immediately();
                    }
                }
                0
            }
            _ => unsafe { DefWindowProcW(hwnd, msg, w_param, l_param) },
        }
    }

    pub(super) fn spawn_listener(
        app: tauri::AppHandle,
        coordinator: &'static ShutdownCoordinator,
    ) {
        if LISTENER_CONTEXT.set((app, coordinator)).is_err() {
            return;
        }
        let _ = std::thread::Builder::new()
            .name("billow-win-shutdown".to_string())
            .spawn(|| unsafe {
                let class_name: Vec<u16> = "BillowShutdownListener\0".encode_utf16().collect();
                let title: Vec<u16> = "\0".encode_utf16().collect();
                let instance = GetModuleHandleW(std::ptr::null());
                let mut class: WndClassExW = std::mem::zeroed();
                class.cb_size = std::mem::size_of::<WndClassExW>() as u32;
                class.lpfn_wnd_proc = Some(wnd_proc);
                class.h_instance = instance;
                class.lpsz_class_name = class_name.as_ptr();
                if RegisterClassExW(&class) == 0 {
                    return;
                }
                // Unowned top-level hidden popup: receives WM_QUERYENDSESSION and
                // WM_ENDSESSION broadcasts (unlike HWND_MESSAGE) without appearing
                // on screen, in Alt-Tab, or in the taskbar.
                let hwnd = CreateWindowExW(
                    WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                    class_name.as_ptr(),
                    title.as_ptr(),
                    WS_POPUP,
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    instance,
                    std::ptr::null_mut(),
                );
                if hwnd.is_null() {
                    return;
                }
                let mut msg: Msg = std::mem::zeroed();
                while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                    let _ = TranslateMessage(&msg);
                    let _ = DispatchMessageW(&msg);
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[test]
    fn cancelled_query_end_session_resumes_background_work() {
        let coord = ShutdownCoordinator::new();
        assert!(!coord.should_suppress_background_work(false));
        assert!(!coord.is_system_terminating(false));

        coord.on_query_end_session();
        assert!(coord.should_suppress_background_work(false));
        assert!(!coord.is_system_terminating(false));

        // User clicked Cancel on the Windows shutdown screen.
        assert!(!coord.on_end_session(false));
        assert!(!coord.should_suppress_background_work(false));
        assert!(!coord.is_system_terminating(false));
    }

    #[test]
    fn confirmed_end_session_locks_terminating_state() {
        let coord = ShutdownCoordinator::new();
        coord.on_query_end_session();
        assert!(coord.on_end_session(true));
        assert!(coord.should_suppress_background_work(false));
        assert!(coord.is_system_terminating(false));

        // A late false message cannot clear a committed shutdown.
        assert!(!coord.on_end_session(false));
        assert!(coord.is_system_terminating(false));
    }

    #[test]
    fn os_shutting_down_metric_immediately_suppresses_and_marks_terminating() {
        let coord = ShutdownCoordinator::new();
        assert!(coord.should_suppress_background_work(true));
        assert!(coord.is_system_terminating(true));
    }

    #[test]
    fn cleanup_once_runs_exactly_once_and_blocks_concurrent_callers_until_done() {
        let coord = Arc::new(ShutdownCoordinator::new());
        let runs = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicBool::new(false));

        let coord_first = Arc::clone(&coord);
        let runs_first = Arc::clone(&runs);
        let finished_first = Arc::clone(&finished);
        let first = std::thread::spawn(move || {
            coord_first.run_cleanup_once(|| {
                runs_first.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(60));
                finished_first.store(true, Ordering::SeqCst);
            });
        });

        while runs.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }

        // Second caller (e.g. tao RunEvent::Exit racing WM_ENDSESSION watcher)
        // must wait until the first caller finishes before returning.
        coord.run_cleanup_once(|| {
            runs.fetch_add(1, Ordering::SeqCst);
        });
        assert!(finished.load(Ordering::SeqCst));
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        first.join().unwrap();
    }
}
