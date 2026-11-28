//! A UAC-elevated, headless kernel supervisor. The UI stays in its original process.
//! Anonymous pipes carry one launch request and stdout; closing the control pipe
//! or losing the UI process ends the kernel. No service or public IPC endpoint.
#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

type Handle = *mut c_void;
const HELPER: &str = "--billow-kernel-helper";
const READY: &[u8] = b"READY\n";
const WAIT_TIMEOUT: u32 = 258;

#[repr(C)]
struct ShellExecuteInfo {
    size: u32,
    mask: u32,
    window: Handle,
    verb: *const u16,
    file: *const u16,
    args: *const u16,
    directory: *const u16,
    show: i32,
    instance: Handle,
    id_list: Handle,
    class: *const u16,
    class_key: Handle,
    hot_key: u32,
    icon: Handle,
    process: Handle,
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn IsUserAnAdmin() -> i32;
    fn ShellExecuteExW(info: *mut ShellExecuteInfo) -> i32;
}
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoInitializeEx(reserved: Handle, flags: u32) -> i32;
    fn CoUninitialize();
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn GetCurrentProcess() -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn CreatePipe(read: *mut Handle, write: *mut Handle, attributes: Handle, size: u32) -> i32;
    fn DuplicateHandle(
        source: Handle,
        handle: Handle,
        target: Handle,
        result: *mut Handle,
        access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
    fn PeekNamedPipe(
        pipe: Handle,
        buffer: Handle,
        size: u32,
        read: *mut u32,
        available: *mut u32,
        left: *mut u32,
    ) -> i32;
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

fn pipe() -> io::Result<(File, File)> {
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null_mut(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // Neither end is inheritable. Only the two explicitly duplicated ends reach the helper.
    Ok(unsafe { (File::from_raw_handle(read), File::from_raw_handle(write)) })
}

fn available(pipe: &File) -> io::Result<u32> {
    let mut bytes = 0;
    if unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut bytes,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(bytes)
}

#[derive(Serialize, Deserialize)]
struct Launch {
    kernel: PathBuf,
    home: PathBuf,
    config: PathBuf,
    #[serde(default = "default_engine")]
    engine: String,
    #[serde(default)]
    tun: bool,
}

fn default_engine() -> String {
    "mihomo".to_string()
}

pub struct ElevatedKernel {
    process: OwnedHandle,
    input: Option<File>,
    output: Option<File>,
}

impl ElevatedKernel {
    /// Finish UAC and the pipe handshake before the caller stops the existing kernel.
    pub fn prepare() -> Result<Self, String> {
        Self::prepare_inner().map_err(|error| {
            format!(
                "{}：{error}；原有连接保持不变",
                crate::takeover::TUN_AUTHORIZATION_FAILED
            )
        })
    }

    fn prepare_inner() -> io::Result<Self> {
        let (control_read, control_write) = pipe()?;
        let (output_read, output_write) = pipe()?;
        let exe = std::env::current_exe()?;
        let file: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
        // Paths and config never appear in the command line; the private pipe carries them.
        let args: Vec<u16> = format!(
            "{HELPER} {} {} {}\0",
            std::process::id(),
            control_read.as_raw_handle() as usize,
            output_write.as_raw_handle() as usize
        )
        .encode_utf16()
        .collect();
        let verb: Vec<u16> = "runas\0".encode_utf16().collect();
        let mut info: ShellExecuteInfo = unsafe { std::mem::zeroed() };
        info.size = std::mem::size_of::<ShellExecuteInfo>() as u32;
        info.mask = 0x00000040 | 0x00000100 | 0x00000400; // NOCLOSEPROCESS | NOASYNC | FLAG_NO_UI
        info.file = file.as_ptr();
        info.verb = verb.as_ptr();
        info.args = args.as_ptr();
        let result = unsafe {
            let initialized = CoInitializeEx(std::ptr::null_mut(), 2) >= 0;
            let ok = ShellExecuteExW(&mut info);
            let error = (ok == 0).then(io::Error::last_os_error);
            if initialized {
                CoUninitialize();
            }
            error
        };
        if let Some(error) = result {
            return Err(error);
        }
        if info.process.is_null() {
            return Err(io::Error::other("系统未返回授权进程"));
        }
        let mut helper = Self {
            process: unsafe { OwnedHandle::from_raw_handle(info.process) },
            input: Some(control_write),
            output: Some(output_read),
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if available(helper.output.as_ref().unwrap())? >= READY.len() as u32 {
                break;
            }
            if !helper.running() || Instant::now() >= deadline {
                return Err(io::Error::other("授权进程未能就绪"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut ready = [0; 6];
        helper.output.as_mut().unwrap().read_exact(&mut ready)?;
        if ready != READY {
            return Err(io::Error::other("授权进程握手失败"));
        }
        // The helper now owns duplicates; dropping these avoids keeping either pipe alive.
        drop(control_read);
        drop(output_write);
        Ok(helper)
    }

    /// Sends a launch request. While a kernel already runs under this helper, the helper
    /// stops it first and starts the new one in the same elevated process.
    pub fn start(
        &mut self,
        kernel: &Path,
        home: &Path,
        config: &Path,
        engine: &str,
        tun: bool,
    ) -> io::Result<()> {
        let launch = Launch {
            kernel: kernel.to_path_buf(),
            home: home.to_path_buf(),
            config: config.to_path_buf(),
            engine: engine.to_string(),
            tun,
        };
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| io::Error::other("授权进程已关闭"))?;
        serde_json::to_writer(&mut *input, &launch)?;
        input.write_all(b"\n")?;
        input.flush()
    }

    pub fn take_stdout(&mut self) -> Option<File> {
        self.output.take()
    }

    pub fn running(&self) -> bool {
        unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) == WAIT_TIMEOUT }
    }

    pub fn stop(&mut self) {
        self.input.take();
        // The helper checks the pipe and parent every 50 ms, then kills/waits its child.
        unsafe {
            WaitForSingleObject(self.process.as_raw_handle(), 5_000);
        }
    }
}

impl Drop for ElevatedKernel {
    fn drop(&mut self) {
        self.stop();
    }
}

fn duplicate(parent: &OwnedHandle, raw: usize) -> io::Result<File> {
    if raw == 0 || raw == usize::MAX {
        return Err(io::Error::other("无效的管道句柄"));
    }
    let mut handle = std::ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            parent.as_raw_handle(),
            raw as Handle,
            GetCurrentProcess(),
            &mut handle,
            0,
            0,
            2,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn read_launch(reader: &mut BufReader<File>) -> io::Result<Launch> {
    let mut line = String::new();
    // A launch contains only three paths. Bound allocation even on a malformed request.
    (&mut *reader).take(128 * 1024).read_line(&mut line)?;
    let launch: Launch = serde_json::from_str(&line)?;
    if !launch.kernel.is_absolute()
        || !launch.home.is_absolute()
        || !launch.config.is_absolute()
        || !launch.kernel.is_file()
        || !launch.config.is_file()
    {
        return Err(io::Error::other("内核启动路径无效"));
    }
    Ok(launch)
}

fn stop_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Runs one kernel at a time. Another launch request on the control pipe replaces the running
/// kernel inside this elevated process, so restarting with TUN does not ask for UAC again.
/// The helper still exits when its kernel exits, which is how the UI detects a kernel exit.
fn supervise(parent: &OwnedHandle, input: File, output: &mut File) -> io::Result<()> {
    output.write_all(READY)?;
    let mut reader = BufReader::new(input);
    let mut launch = read_launch(&mut reader)?;
    loop {
        let mut child = spawn_kernel(&launch, output)?;
        loop {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            let parent_alive =
                unsafe { WaitForSingleObject(parent.as_raw_handle(), 50) == WAIT_TIMEOUT };
            if !parent_alive {
                stop_child(&mut child);
                return Ok(());
            }
            match available(reader.get_ref()) {
                // Control pipe closed: the UI stopped the kernel or went away.
                Err(_) => {
                    stop_child(&mut child);
                    return Ok(());
                }
                Ok(0) if reader.buffer().is_empty() => {}
                Ok(_) => {
                    // The previous kernel must release its ports before the next one binds.
                    stop_child(&mut child);
                    launch = read_launch(&mut reader)?;
                    break;
                }
            }
        }
    }
}

fn spawn_kernel(launch: &Launch, output: &File) -> io::Result<std::process::Child> {
    let mut command = Command::new(&launch.kernel);
    if launch.engine == "rust" {
        command.arg(&launch.config).arg("--geosite-dir").arg(&launch.home);
        if launch.tun {
            command.arg("--tun");
        }
    } else {
        command.arg("-d").arg(&launch.home);
        command.arg("-f").arg(&launch.config);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(output.try_clone()?)
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn()?;
    if let Err(error) = crate::win_process::try_bind_to_app_lifetime(&child) {
        stop_child(&mut child);
        return Err(error);
    }
    Ok(child)
}

/// Called before constructing Tauri, so this process never creates a WebView/tray/updater.
pub fn run_helper_if_requested() -> bool {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some(HELPER) {
        return false;
    }
    crate::shutdown::configure_helper_process();
    let run = || -> io::Result<()> {
        if !is_admin() || args.len() != 5 {
            return Err(io::Error::other("授权参数无效"));
        }
        let pid: u32 = args[2].parse().map_err(io::Error::other)?;
        if pid == 0 || pid == std::process::id() {
            return Err(io::Error::other("父进程无效"));
        }
        let raw = unsafe { OpenProcess(0x00100000 | 0x0040, 0, pid) }; // SYNCHRONIZE | DUP_HANDLE
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let parent = unsafe { OwnedHandle::from_raw_handle(raw) };
        let input = duplicate(&parent, args[3].parse().map_err(io::Error::other)?)?;
        let mut output = duplicate(&parent, args[4].parse().map_err(io::Error::other)?)?;
        if let Err(error) = supervise(&parent, input, &mut output) {
            let message =
                serde_json::json!({"type": "error", "payload": format!("Start TUN: {error}")});
            let _ = writeln!(output, "{message}");
            return Err(error);
        }
        Ok(())
    };
    if let Err(error) = run() {
        eprintln!("Billow kernel supervisor: {error}");
    }
    crate::shutdown::terminate_current_process_if_shutting_down();
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipes_have_explicit_lifetimes_and_detect_a_closed_writer() {
        let (mut read, mut write) = pipe().unwrap();
        assert_eq!(available(&read).unwrap(), 0);
        write.write_all(READY).unwrap();
        assert_eq!(available(&read).unwrap(), 6);
        let mut bytes = [0; 6];
        read.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, READY);
        drop(write);
        assert!(available(&read).is_err());
    }
}
