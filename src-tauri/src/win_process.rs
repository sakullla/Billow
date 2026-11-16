//! Windows kernel lifetime: the kernel dies with the app, and kernels left behind
//! by an earlier app process (crash, forced exit, interrupted update) are cleared
//! before a new one binds the same ports.
#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::OnceLock;

type Handle = *mut c_void;

const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
const TH32CS_SNAPPROCESS: u32 = 0x2;
const PROCESS_TERMINATE: u32 = 0x0001;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const MAX_PATH_CHARS: usize = 32_768;

#[repr(C)]
#[derive(Default)]
struct BasicLimitInformation {
    per_process_user_time_limit: i64,
    per_job_user_time_limit: i64,
    limit_flags: u32,
    minimum_working_set_size: usize,
    maximum_working_set_size: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

#[repr(C)]
#[derive(Default)]
struct IoCounters {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

#[repr(C)]
#[derive(Default)]
struct ExtendedLimitInformation {
    basic: BasicLimitInformation,
    io: IoCounters,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

#[repr(C)]
struct ProcessEntry {
    size: u32,
    usage: u32,
    process_id: u32,
    default_heap_id: usize,
    module_id: u32,
    threads: u32,
    parent_process_id: u32,
    priority_class_base: i32,
    flags: u32,
    exe_file: [u16; 260],
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> Handle;
    fn SetInformationJobObject(job: Handle, class: i32, info: *mut c_void, length: u32) -> i32;
    fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
    fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
    fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
    fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
    fn QueryFullProcessImageNameW(process: Handle, flags: u32, name: *mut u16, size: *mut u32) -> i32;
    fn TerminateProcess(process: Handle, exit_code: u32) -> i32;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn CloseHandle(handle: Handle) -> i32;
}

/// One job per app process; closing it (normal exit, crash or kill) ends every kernel in it.
fn app_job() -> Option<Handle> {
    static JOB: OnceLock<usize> = OnceLock::new();
    let raw = *JOB.get_or_init(|| unsafe {
        let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
        if job.is_null() {
            return 0;
        }
        let mut info = ExtendedLimitInformation::default();
        info.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            (&mut info as *mut ExtendedLimitInformation).cast(),
            std::mem::size_of::<ExtendedLimitInformation>() as u32,
        );
        if ok == 0 {
            CloseHandle(job);
            return 0;
        }
        // Deliberately never closed: the OS closes it when this process ends.
        job as usize
    });
    (raw != 0).then_some(raw as Handle)
}

/// Tie the kernel to this app process so it can never outlive it and hold the ports.
pub fn bind_to_app_lifetime(child: &Child) {
    let _ = try_bind_to_app_lifetime(child);
}

/// The elevated supervisor must refuse to run an unowned privileged kernel.
pub fn try_bind_to_app_lifetime(child: &Child) -> std::io::Result<()> {
    let job = app_job().ok_or_else(|| std::io::Error::other("无法创建内核进程组"))?;
    if unsafe { AssignProcessToJobObject(job, child.as_raw_handle() as Handle) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

struct ProcessRow {
    pid: u32,
    parent: u32,
    name: String,
}

fn processes() -> Vec<ProcessRow> {
    let mut rows = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() || snapshot as isize == -1 {
            return rows;
        }
        let mut entry: ProcessEntry = std::mem::zeroed();
        entry.size = std::mem::size_of::<ProcessEntry>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            let len = entry.exe_file.iter().position(|&c| c == 0).unwrap_or(entry.exe_file.len());
            rows.push(ProcessRow {
                pid: entry.process_id,
                parent: entry.parent_process_id,
                name: String::from_utf16_lossy(&entry.exe_file[..len]),
            });
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
    }
    rows
}

fn image_path(pid: u32) -> Option<PathBuf> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let mut buffer = vec![0u16; MAX_PATH_CHARS];
        let mut size = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut size);
        CloseHandle(process);
        (ok != 0).then(|| PathBuf::from(std::ffi::OsString::from_wide(&buffer[..size as usize])))
    }
}

fn normalized(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

/// A kernel left behind by an app process that is gone (or is not Billow any more).
#[derive(Debug)]
pub struct StrayKernel {
    pub pid: u32,
}

/// Kernels started from `root` whose parent is no longer a live Billow process.
/// Another running Billow instance keeps its kernel.
fn stray_kernels(root: &Path, keep: Option<u32>) -> Vec<StrayKernel> {
    let root = format!("{}\\", normalized(root));
    let app_name = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.file_name().map(|name| name.to_string_lossy().to_lowercase()))
        .unwrap_or_else(|| "billow.exe".to_string());
    let rows = processes();
    let own = std::process::id();
    rows.iter()
        .filter(|row| row.pid != own && Some(row.pid) != keep)
        .filter(|row| row.name.to_lowercase().ends_with(".exe"))
        .filter(|row| image_path(row.pid).is_some_and(|path| normalized(&path).starts_with(&root)))
        .filter(|row| {
            let parent = rows.iter().find(|candidate| candidate.pid == row.parent);
            match parent {
                None => true,
                // Our own earlier child that we lost track of is a stray as well.
                Some(parent) if parent.pid == own => true,
                Some(parent) => parent.name.to_lowercase() != app_name,
            }
        })
        .map(|row| StrayKernel { pid: row.pid })
        .collect()
}

/// End stray kernels from `root`. Returns the ones that could not be ended
/// (typically an elevated leftover when this instance is not elevated).
pub fn end_stray_kernels(root: &Path, keep: Option<u32>) -> Vec<StrayKernel> {
    stray_kernels(root, keep)
        .into_iter()
        .filter(|stray| unsafe {
            let process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, 0, stray.pid);
            if process.is_null() {
                return true;
            }
            let ended = TerminateProcess(process, 1) != 0 && WaitForSingleObject(process, 3_000) == 0;
            CloseHandle(process);
            !ended
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn a_kernel_we_lost_track_of_is_ended_and_others_are_left_alone() {
        let root = std::env::temp_dir().join(format!("billow-stray-{}", std::process::id())).join("kernels");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("files")).unwrap();
        let system = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let kernel = root.join("files").join("core.exe");
        std::fs::copy(system.join("System32").join("ping.exe"), &kernel).unwrap();
        let mut stray = Command::new(&kernel)
            .args(["-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Outside the root: never touched.
        let mut bystander = Command::new(system.join("System32").join("ping.exe"))
            .args(["-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(200));

        // The current child is kept when asked to.
        assert!(end_stray_kernels(&root, Some(stray.id())).is_empty());
        assert!(stray.try_wait().unwrap().is_none());

        assert!(end_stray_kernels(&root, None).is_empty());
        assert!(stray.wait_timeout_ok());
        assert!(bystander.try_wait().unwrap().is_none());

        let _ = bystander.kill();
        let _ = bystander.wait();
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
    }

    trait WaitTimeout {
        fn wait_timeout_ok(&mut self) -> bool;
    }

    impl WaitTimeout for std::process::Child {
        fn wait_timeout_ok(&mut self) -> bool {
            for _ in 0..50 {
                if matches!(self.try_wait(), Ok(Some(_))) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            false
        }
    }

    #[test]
    fn job_binding_does_not_disturb_a_running_child() {
        let system = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let mut child = Command::new(system.join("System32").join("ping.exe"))
            .args(["-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        bind_to_app_lifetime(&child);
        assert!(child.try_wait().unwrap().is_none());
        let _ = child.kill();
        let _ = child.wait();
    }
}
