//! Platform TUN device creation.
//!
//! macOS opens a `utun` control socket (4-byte address-family framing), Linux
//! opens `/dev/net/tun` with `IFF_TUN | IFF_NO_PI` (raw IP), and Windows loads
//! the shipped `wintun.dll` and opens a session (raw IP). Every failure is
//! named: a missing driver, missing privileges and an unsupported host each
//! produce their own message instead of a generic OS error.

use std::io;
use std::sync::Arc;

use super::framing::{strip_utun_header, UtunError};
use crate::config::TunConfig;

/// Largest IP packet read from a device (headers included).
pub const MAX_PACKET: usize = 65_535;

/// A whole-IP-packet device shared by the reader and writer pump threads.
pub trait TunDevice: Send + Sync {
    /// Interface/adapter name reported by the platform.
    fn name(&self) -> &str;
    /// One packet, stripped of device framing. `Ok(None)` means "nothing ready
    /// right now" (the caller polls again).
    fn read_packet(&self, buf: &mut [u8]) -> io::Result<Option<usize>>;
    /// Write one whole packet, adding device framing as needed.
    fn write_packet(&self, packet: &[u8]) -> io::Result<()>;
}

/// How a descriptor frames IP packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// Raw IP (Linux `IFF_NO_PI`, Wintun, Android VpnService).
    Raw,
    /// macOS utun 4-byte big-endian address family.
    Utun,
}

impl Framing {
    fn encode(&self, packet: &[u8]) -> Result<Vec<u8>, UtunError> {
        match self {
            Framing::Raw => Ok(packet.to_vec()),
            Framing::Utun => super::framing::with_utun_header(packet),
        }
    }

    fn decode<'a>(&self, packet: &'a [u8]) -> Result<&'a [u8], UtunError> {
        match self {
            Framing::Raw => Ok(packet),
            Framing::Utun => strip_utun_header(packet),
        }
    }
}

/// Create the platform device for `tun`.
pub fn create(tun: &TunConfig) -> Result<Arc<dyn TunDevice>, String> {
    #[cfg(target_os = "macos")]
    {
        platform::open(tun)
    }
    #[cfg(target_os = "linux")]
    {
        platform::open(tun)
    }
    #[cfg(target_os = "windows")]
    {
        platform::open(tun)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = tun;
        Err("desktop-tun: TUN devices are implemented on macOS (utun), Linux (/dev/net/tun) and Windows (Wintun) only".to_string())
    }
}

// ---------------------------------------------------------------------------
// Unix file-descriptor device (macOS utun + Linux /dev/net/tun).
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub struct FdDevice {
    fd: std::os::fd::RawFd,
    name: String,
    framing: Framing,
    owns: bool,
}

#[cfg(unix)]
impl FdDevice {
    /// Take ownership of `fd`, set it non-blocking and use `framing`.
    pub fn from_owned(fd: std::os::fd::RawFd, name: impl Into<String>, framing: Framing) -> io::Result<Self> {
        set_nonblocking(fd)?;
        Ok(FdDevice {
            fd,
            name: name.into(),
            framing,
            owns: true,
        })
    }

    /// Same as [`FdDevice::from_owned`] but does not close the descriptor.
    /// Tests use this with one end of a `UnixDatagram` pair.
    pub fn borrowed(fd: std::os::fd::RawFd, name: impl Into<String>, framing: Framing) -> io::Result<Self> {
        set_nonblocking(fd)?;
        Ok(FdDevice {
            fd,
            name: name.into(),
            framing,
            owns: false,
        })
    }

    pub fn fd(&self) -> std::os::fd::RawFd {
        self.fd
    }
}

#[cfg(unix)]
impl TunDevice for FdDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn read_packet(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        if self.framing == Framing::Utun && buf.len() < super::framing::UTUN_HEADER + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "utun read buffer is smaller than the framing header",
            ));
        }
        loop {
            let read = unsafe {
                libc::read(
                    self.fd,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            };
            if read > 0 {
                let read = read as usize;
                let payload = self
                    .framing
                    .decode(&buf[..read])
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
                let length = payload.len();
                if self.framing == Framing::Utun {
                    buf.copy_within(super::framing::UTUN_HEADER..super::framing::UTUN_HEADER + length, 0);
                }
                return Ok(Some(length));
            }
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TUN descriptor closed"));
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return Ok(None),
                _ => return Err(error),
            }
        }
    }

    fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        let framed = self
            .framing
            .encode(packet)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        loop {
            let written = unsafe {
                libc::write(
                    self.fd,
                    framed.as_ptr().cast(),
                    framed.len(),
                )
            };
            if written == framed.len() as isize {
                return Ok(());
            }
            if written >= 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("short TUN write: {} of {} bytes", written, framed.len()),
                ));
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {
                    wait_writable(self.fd)?;
                    continue;
                }
                _ => return Err(error),
            }
        }
    }
}

#[cfg(unix)]
impl Drop for FdDevice {
    fn drop(&mut self) {
        if self.owns {
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(unix)]
fn set_nonblocking(fd: std::os::fd::RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn wait_writable(fd: std::os::fd::RawFd) -> io::Result<()> {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    loop {
        let ready = unsafe { libc::poll(&mut poll, 1, 200) };
        if ready > 0 {
            return Ok(());
        }
        if ready == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

// Linux /dev/net/tun
#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::{CStr, CString};
    use std::io;
    use std::sync::Arc;

    use super::{FdDevice, Framing, TunDevice};
    use crate::config::TunConfig;

    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x400454ca;

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; 16],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    pub fn open(tun: &TunConfig) -> Result<Arc<dyn TunDevice>, String> {
        let path = CString::new("/dev/net/tun").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(libc::ENOENT) | Some(libc::ENODEV) => format!(
                    "desktop-tun: /dev/net/tun is missing ({error}); load the tun module or enable it in the kernel"
                ),
                Some(libc::EPERM) | Some(libc::EACCES) => format!(
                    "desktop-tun: opening /dev/net/tun was denied ({error}); run the kernel through the TunGrant authorization"
                ),
                _ => format!("desktop-tun: open /dev/net/tun: {error}"),
            });
        }
        let mut request = IfReq {
            name: [0; 16],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        let name = tun.device.as_bytes();
        if name.len() > 15 {
            unsafe { libc::close(fd) };
            return Err("desktop-tun: tun.device is longer than 15 bytes".to_string());
        }
        for (slot, byte) in request.name.iter_mut().zip(name) {
            *slot = *byte as libc::c_char;
        }
        if unsafe { libc::ioctl(fd, TUNSETIFF, &mut request) } < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(match error.raw_os_error() {
                Some(libc::EPERM) | Some(libc::EACCES) => format!(
                    "desktop-tun: TUNSETIFF was denied ({error}); run the kernel through the TunGrant authorization"
                ),
                _ => format!("desktop-tun: TUNSETIFF: {error}"),
            });
        }
        let assigned = unsafe { CStr::from_ptr(request.name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let device = FdDevice::from_owned(fd, assigned, Framing::Raw)
            .map_err(|error| format!("desktop-tun: configure /dev/net/tun: {error}"))?;
        Ok(Arc::new(device))
    }
}

// macOS utun
#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::CStr;
    use std::io;
    use std::sync::Arc;

    use super::{FdDevice, Framing, TunDevice};
    use crate::config::TunConfig;

    const PF_SYSTEM: libc::c_int = 32;
    const SYSPROTO_CONTROL: libc::c_int = 2;
    const AF_SYS_CONTROL: u16 = 2;
    const SOCK_DGRAM: libc::c_int = 2;
    const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;
    const UTUN_OPT_IFNAME: libc::c_int = 2;
    const CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [u8; 96],
    }

    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    pub(super) fn utun_unit(device: &str) -> Option<u32> {
        if device.is_empty() {
            return None;
        }
        device.strip_prefix("utun")?.parse::<u32>().ok()
    }

    pub fn open(tun: &TunConfig) -> Result<Arc<dyn TunDevice>, String> {
        let requested_unit = utun_unit(&tun.device);
        let fd = unsafe { libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            return Err(format!("desktop-tun: utun control socket: {error}"));
        }
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        let name_len = CONTROL_NAME.len().min(info.ctl_name.len() - 1);
        info.ctl_name[..name_len].copy_from_slice(&CONTROL_NAME[..name_len]);
        if unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut info) } < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!("desktop-tun: utun CTLIOCGINFO: {error}"));
        }
        let mut address = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: PF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        let mut opened = false;
        let mut last = None;
        let units: Vec<u32> = match requested_unit {
            // Darwin `sc_unit` is one-based: `utun3` is unit 4; 0 lets the
            // kernel pick the next free unit.
            Some(unit) => vec![unit.saturating_add(1)],
            None => vec![0],
        };
        for unit in units {
            address.sc_unit = unit;
            let result = unsafe {
                libc::connect(
                    fd,
                    (&address as *const SockaddrCtl).cast(),
                    std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
                )
            };
            if result == 0 {
                opened = true;
                break;
            }
            let error = io::Error::last_os_error();
            let code = error.raw_os_error();
            last = Some(error.to_string());
            match code {
                Some(libc::EPERM) | Some(libc::EACCES) => {
                    unsafe { libc::close(fd) };
                    return Err(format!(
                        "desktop-tun: opening a utun was denied ({error}); run the kernel through the TunGrant authorization (setuid root) or as root"
                    ));
                }
                Some(libc::EADDRINUSE) | Some(libc::EBUSY) | Some(libc::EINVAL) => continue,
                _ => break,
            }
        }
        if !opened {
            unsafe { libc::close(fd) };
            return Err(format!(
                "desktop-tun: no utun unit could be opened{}",
                last.map(|error| format!(": {error}")).unwrap_or_default()
            ));
        }
        let mut name = [0u8; 64];
        let mut length = name.len() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut length,
            )
        };
        let name = if result == 0 && length > 0 {
            unsafe { CStr::from_ptr(name.as_ptr().cast()) }
                .to_string_lossy()
                .into_owned()
        } else {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!("desktop-tun: utun UTUN_OPT_IFNAME: {error}"));
        };
        let device = FdDevice::from_owned(fd, name, Framing::Utun)
            .map_err(|error| format!("desktop-tun: configure utun: {error}"))?;
        Ok(Arc::new(device))
    }
}

// Windows Wintun
#[cfg(target_os = "windows")]
mod platform {
    use std::ffi::c_void;
    use std::io;
    use std::sync::Arc;

    use super::{TunDevice, MAX_PACKET};
    use crate::config::TunConfig;

    const WINTUN_MAX_RING_CAPACITY: u32 = 0x400_0000;
    const ERROR_NO_MORE_ITEMS: u32 = 259;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    type CreateAdapter = unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> *mut c_void;
    type OpenAdapter = unsafe extern "system" fn(*const u16) -> *mut c_void;
    type StartSession = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
    type EndSession = unsafe extern "system" fn(*mut c_void);
    type CloseAdapter = unsafe extern "system" fn(*mut c_void);
    type ReceivePacket = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
    type ReleaseReceivePacket = unsafe extern "system" fn(*mut c_void, *const u8);
    type AllocateSendPacket = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
    type SendPacket = unsafe extern "system" fn(*mut c_void, *const u8);

    struct Api {
        module: *mut c_void,
        create: CreateAdapter,
        open: OpenAdapter,
        start: StartSession,
        end: EndSession,
        close: CloseAdapter,
        receive: ReceivePacket,
        release: ReleaseReceivePacket,
        allocate: AllocateSendPacket,
        send: SendPacket,
    }

    unsafe impl Send for Api {}
    unsafe impl Sync for Api {}

    impl Drop for Api {
        fn drop(&mut self) {
            unsafe { FreeLibrary(self.module) };
        }
    }

    struct WintunDevice {
        api: Api,
        adapter: *mut c_void,
        session: *mut c_void,
        name: String,
    }

    unsafe impl Send for WintunDevice {}
    unsafe impl Sync for WintunDevice {}

    impl TunDevice for WintunDevice {
        fn name(&self) -> &str {
            &self.name
        }

        fn read_packet(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
            let mut size = 0u32;
            let packet = unsafe { (self.api.receive)(self.session, &mut size) };
            if packet.is_null() {
                let error = unsafe { GetLastError() };
                if error == ERROR_NO_MORE_ITEMS {
                    return Ok(None);
                }
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            let length = size as usize;
            let result = if length > buf.len() {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Wintun packet of {length} bytes exceeds the {}-byte buffer", buf.len()),
                ))
            } else {
                unsafe { std::ptr::copy_nonoverlapping(packet, buf.as_mut_ptr(), length) };
                Ok(Some(length))
            };
            unsafe { (self.api.release)(self.session, packet) };
            result
        }

        fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
            let size = u32::try_from(packet.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet is larger than u32"))?;
            let slot = unsafe { (self.api.allocate)(self.session, size) };
            if slot.is_null() {
                let error = unsafe { GetLastError() };
                // Ring full: the packet is dropped and counted by the pump, not
                // a reason to tear the session down.
                if error == 111 || error == ERROR_NO_MORE_ITEMS {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        format!("Wintun send ring is full (OS error {error})"),
                    ));
                }
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            unsafe { std::ptr::copy_nonoverlapping(packet.as_ptr(), slot, packet.len()) };
            unsafe { (self.api.send)(self.session, slot) };
            Ok(())
        }
    }

    impl Drop for WintunDevice {
        fn drop(&mut self) {
            unsafe {
                (self.api.end)(self.session);
                (self.api.close)(self.adapter);
            }
        }
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn symbol<T>(module: *mut c_void, name: &[u8]) -> Result<T, String> {
        let address = unsafe { GetProcAddress(module, name.as_ptr()) };
        if address.is_null() {
            return Err(format!(
                "desktop-tun: wintun.dll does not export {}",
                String::from_utf8_lossy(name).trim_end_matches('\0')
            ));
        }
        Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&address) })
    }

    fn load_api() -> Result<Api, String> {
        let exe = std::env::current_exe()
            .map_err(|error| format!("desktop-tun: current_exe: {error}"))?;
        let dll = exe
            .parent()
            .ok_or_else(|| "desktop-tun: the kernel executable has no directory".to_string())?
            .join("wintun.dll");
        let path = wide(&dll.to_string_lossy());
        let module = unsafe { LoadLibraryW(path.as_ptr()) };
        if module.is_null() {
            let error = unsafe { GetLastError() };
            return Err(format!(
                "desktop-tun: wintun.dll is missing next to {} (OS error {error}); ship the DLL with the installer",
                exe.display()
            ));
        }
        let api = Api {
            module,
            create: symbol(module, b"WintunCreateAdapter\0")?,
            open: symbol(module, b"WintunOpenAdapter\0")?,
            start: symbol(module, b"WintunStartSession\0")?,
            end: symbol(module, b"WintunEndSession\0")?,
            close: symbol(module, b"WintunCloseAdapter\0")?,
            receive: symbol(module, b"WintunReceivePacket\0")?,
            release: symbol(module, b"WintunReleaseReceivePacket\0")?,
            allocate: symbol(module, b"WintunAllocateSendPacket\0")?,
            send: symbol(module, b"WintunSendPacket\0")?,
        };
        Ok(api)
    }

    pub fn open(tun: &TunConfig) -> Result<Arc<dyn TunDevice>, String> {
        let api = load_api()?;
        let name = if tun.device.is_empty() {
            "Billow".to_string()
        } else {
            tun.device.clone()
        };
        if name.len() > 128
            || name
                .chars()
                .any(|character| character.is_control() || "\\/:*?\"<>|".contains(character))
        {
            return Err(format!(
                "desktop-tun: Windows tun.device '{name}' is not a valid adapter name (max 128 characters, no control or \\ / : * ? \" < > |)"
            ));
        }
        let adapter_name = wide(&name);
        let tunnel_type = wide("Billow");
        // Reuse the adapter a previous run left behind (Created by us with the
        // same name); only create when it does not exist.
        let mut adapter = unsafe { (api.open)(adapter_name.as_ptr()) };
        if adapter.is_null() {
            adapter = unsafe { (api.create)(adapter_name.as_ptr(), tunnel_type.as_ptr(), std::ptr::null()) };
        }
        if adapter.is_null() {
            let error = unsafe { GetLastError() };
            return Err(format!(
                "desktop-tun: WintunCreateAdapter('{name}') failed (OS error {error}); run the kernel elevated and check the Wintun driver"
            ));
        }
        let session = unsafe { (api.start)(adapter, WINTUN_MAX_RING_CAPACITY) };
        if session.is_null() {
            let error = unsafe { GetLastError() };
            unsafe { (api.close)(adapter) };
            return Err(format!(
                "desktop-tun: WintunStartSession failed (OS error {error})"
            ));
        }
        let device = WintunDevice {
            api,
            adapter,
            session,
            name,
        };
        // A Wintun session packet is an IP packet; keep the buffer sizing
        // explicit so a caller cannot pass something smaller.
        let _ = MAX_PACKET;
        Ok(Arc::new(device))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::platform::utun_unit;

    #[test]
    fn utun_device_names_map_to_darwin_sc_units() {
        // Darwin sc_unit is one-based; utun0 -> 1, utun9 -> 10.
        assert_eq!(utun_unit("utun0"), Some(0));
        assert_eq!(utun_unit("utun9"), Some(9));
        // Empty or a non-utunN name lets the kernel pick (sc_unit 0 = auto).
        assert_eq!(utun_unit(""), None);
        assert_eq!(utun_unit("utun"), None);
        assert_eq!(utun_unit("billow0"), None);
    }
}
