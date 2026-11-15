//! Windows TUN consent uses the OS UAC dialog; no shell or credentials are involved.
#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;

#[link(name = "shell32")]
unsafe extern "system" {
    fn IsUserAnAdmin() -> i32;
    fn ShellExecuteW(
        hwnd: *mut c_void,
        verb: *const u16,
        file: *const u16,
        args: *const u16,
        directory: *const u16,
        show: i32,
    ) -> isize;
}
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, flags: u32) -> i32;
    fn CoUninitialize();
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

pub fn relaunch_for_tun() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|_| "无法确定应用路径".to_string())?;
    let file: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let args: Vec<u16> = format!(
        "--billow-enable-tun --billow-wait-pid={}\0",
        std::process::id()
    )
    .encode_utf16()
    .collect();
    let result = unsafe {
        let initialized = CoInitializeEx(std::ptr::null_mut(), 2) >= 0;
        let result = ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            args.as_ptr(),
            std::ptr::null(),
            1,
        );
        if initialized {
            CoUninitialize();
        }
        result
    };
    if result <= 32 {
        return Err("未完成管理员授权，原有连接保持不变".to_string());
    }
    Ok(())
}

/// Wait for the old instance to release its ports before the elevated instance loads state.
pub fn startup_tun_requested() -> bool {
    let args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|arg| arg == "--billow-enable-tun") || !is_admin() {
        return false;
    }
    let Some(pid) = args
        .iter()
        .find_map(|arg| arg.strip_prefix("--billow-wait-pid=")?.parse::<u32>().ok())
    else {
        return false;
    };
    if pid == std::process::id() {
        return false;
    }
    unsafe {
        let handle = OpenProcess(0x00100000, 0, pid); // SYNCHRONIZE only
        if handle.is_null() {
            return std::io::Error::last_os_error().raw_os_error() == Some(87);
        }
        let exited = WaitForSingleObject(handle, 15_000) == 0;
        CloseHandle(handle);
        exited
    }
}
