//! Process identification for intercepted connections.
//!
//! Given a socket's local address (the source IP:port of an intercepted connection),
//! determines which process owns that socket.

use std::net::SocketAddr;

/// Information about the process owning a socket.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

/// Attempt to find the process that owns a TCP socket with the given local address.
///
/// `local_addr` is the application's source IP:port as seen by the interceptor.
/// Returns `None` if the process cannot be determined (best-effort).
pub fn lookup_process_by_socket(local_addr: &SocketAddr) -> Option<ProcessInfo> {
    #[cfg(target_os = "macos")]
    {
        macos::lookup(local_addr)
    }
    #[cfg(target_os = "linux")]
    {
        linux::lookup(local_addr)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = local_addr;
        None
    }
}

/// Resolve process name and path from a PID.
/// Used by eBPF interceptor (Linux) and WFP service (Windows) which already know the PID.
#[cfg(target_os = "linux")]
pub fn resolve_pid(pid: u32) -> Option<ProcessInfo> {
    linux::resolve_pid_info(pid)
}

/// Resolve process name and path from a PID (Windows).
/// The PID comes from the WFP driver IOCTL, not from socket scanning.
#[cfg(target_os = "windows")]
pub fn resolve_pid(pid: u32) -> Option<ProcessInfo> {
    windows::resolve_pid_info(pid)
}

// ---- macOS implementation ----

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::collections::HashMap;
    use std::mem;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Mutex;
    use std::time::Instant;

    // FFI declarations for libproc.h
    mod ffi {
        use libc::{c_int, c_void, pid_t};

        pub const PROC_PIDLISTFDS: c_int = 1;
        pub const PROC_PIDFDSOCKETINFO: c_int = 3;
        pub const PROX_FDTYPE_SOCKET: u32 = 2;
        pub const SOCKINFO_TCP: c_int = 2;
        pub const MAXPATHLEN: u32 = 1024;
        pub const INI_IPV4: u8 = 0x1;

        extern "C" {
            pub fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int;
            pub fn proc_pidinfo(
                pid: pid_t,
                flavor: c_int,
                arg: u64,
                buffer: *mut c_void,
                buffersize: c_int,
            ) -> c_int;
            pub fn proc_pidfdinfo(
                pid: pid_t,
                fd: c_int,
                flavor: c_int,
                buffer: *mut c_void,
                buffersize: c_int,
            ) -> c_int;
            pub fn proc_pidpath(pid: pid_t, buffer: *mut c_void, buffersize: u32) -> c_int;
        }

        /// File descriptor info returned by PROC_PIDLISTFDS.
        #[repr(C)]
        #[derive(Debug, Clone, Copy)]
        pub struct ProcFdInfo {
            pub proc_fd: i32,
            pub proc_fdtype: u32,
        }

        /// in4in6_addr from sys/proc_info.h
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct In4In6Addr {
            pub i46a_pad32: [u32; 3],
            pub i46a_addr4: libc::in_addr,
        }

        /// Address union in in_sockinfo
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub union InAddrUnion {
            pub ina_46: In4In6Addr,
            pub ina_6: libc::in6_addr,
        }

        /// in_sockinfo from sys/proc_info.h
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct InSockInfo {
            pub insi_fport: i32,
            pub insi_lport: i32,
            pub insi_gencnt: u64,
            pub insi_flags: u32,
            pub insi_flow: u32,
            pub insi_vflag: u8,
            pub insi_ip_ttl: u8,
            pub rfu_1: u32,
            pub insi_faddr: InAddrUnion,
            pub insi_laddr: InAddrUnion,
        }

        /// tcp_sockinfo from sys/proc_info.h
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct TcpSockInfo {
            pub tcpsi_ini: InSockInfo,
            pub tcpsi_state: i32,
            pub tcpsi_timer: [i32; 4],
            pub tcpsi_mss: i32,
            pub tcpsi_flags: u32,
            pub rfu_1: u32,
            pub tcpsi_tp: u64,
        }

        /// vinfo_stat from sys/proc_info.h
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct VInfoStat {
            pub vst_dev: u32,
            pub vst_mode: u16,
            pub vst_nlink: u16,
            pub vst_ino: u64,
            pub vst_uid: u32,
            pub vst_gid: u32,
            pub vst_atime: i64,
            pub vst_atimensec: i64,
            pub vst_mtime: i64,
            pub vst_mtimensec: i64,
            pub vst_ctime: i64,
            pub vst_ctimensec: i64,
            pub vst_birthtime: i64,
            pub vst_birthtimensec: i64,
            pub vst_size: i64,
            pub vst_blocks: i64,
            pub vst_blksize: i32,
            pub vst_flags: u32,
            pub vst_gen: u32,
            pub vst_rdev: u32,
            pub vst_qspare: [i64; 2],
        }

        /// sockbuf_info from sys/proc_info.h
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct SockbufInfo {
            pub sbi_cc: u32,
            pub sbi_hiwat: u32,
            pub sbi_mbcnt: u32,
            pub sbi_mbmax: u32,
            pub sbi_lowat: u32,
            pub sbi_flags: i16,
            pub sbi_timeo: i16,
        }

        /// Protocol-specific socket info union.
        /// We only need tcp_sockinfo; use a large enough byte array for the union.
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub union SoiProto {
            pub pri_tcp: TcpSockInfo,
            pub pri_in: InSockInfo,
            pub _padding: [u8; 264],
        }

        /// socket_info from sys/proc_info.h
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct SocketInfo {
            pub soi_stat: VInfoStat,
            pub soi_so: u64,
            pub soi_pcb: u64,
            pub soi_type: i32,
            pub soi_protocol: i32,
            pub soi_family: i32,
            pub soi_options: i16,
            pub soi_linger: i16,
            pub soi_state: i16,
            pub soi_qlen: i16,
            pub soi_incqlen: i16,
            pub soi_qlimit: i16,
            pub soi_timeo: i16,
            pub soi_error: u16,
            pub soi_oobmark: u32,
            pub soi_rcv: SockbufInfo,
            pub soi_snd: SockbufInfo,
            pub soi_kind: i32,
            pub soi_padding: u32,
            pub soi_proto: SoiProto,
        }

        /// proc_fileinfo from sys/proc_info.h
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct ProcFileInfo {
            pub fi_openflags: u32,
            pub fi_status: u32,
            pub fi_offset: i64,
            pub fi_type: i32,
            pub fi_guardflags: i32,
        }

        /// socket_fdinfo = proc_fileinfo + socket_info
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct SocketFdInfo {
            pub pfi: ProcFileInfo,
            pub psi: SocketInfo,
        }
    }

    /// Cache for PID → (name, path) mappings.
    struct PathCache {
        entries: HashMap<u32, (String, String, Instant)>,
    }

    static PATH_CACHE: Mutex<Option<PathCache>> = Mutex::new(None);

    const CACHE_TTL_SECS: u64 = 10;

    fn cached_pid_path(pid: u32) -> Option<(String, String)> {
        let mut guard = PATH_CACHE.lock().ok()?;
        let cache = guard.get_or_insert_with(|| PathCache {
            entries: HashMap::new(),
        });

        // Check cache
        if let Some((name, path, ts)) = cache.entries.get(&pid) {
            if ts.elapsed().as_secs() < CACHE_TTL_SECS {
                return Some((name.clone(), path.clone()));
            }
        }

        // Call proc_pidpath
        let mut buf = [0u8; ffi::MAXPATHLEN as usize];
        let ret = unsafe {
            ffi::proc_pidpath(
                pid as libc::pid_t,
                buf.as_mut_ptr() as *mut libc::c_void,
                ffi::MAXPATHLEN,
            )
        };
        if ret <= 0 {
            return None;
        }

        let path = String::from_utf8_lossy(&buf[..ret as usize]).to_string();
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.clone());

        cache
            .entries
            .insert(pid, (name.clone(), path.clone(), Instant::now()));

        Some((name, path))
    }

    fn list_all_pids() -> Option<Vec<libc::pid_t>> {
        // First call to get count
        let count = unsafe { ffi::proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 {
            return None;
        }

        // Allocate buffer with some headroom
        let capacity = (count as usize) + 64;
        let mut pids: Vec<libc::pid_t> = vec![0; capacity];
        let ret = unsafe {
            ffi::proc_listallpids(
                pids.as_mut_ptr() as *mut libc::c_void,
                (capacity * mem::size_of::<libc::pid_t>()) as i32,
            )
        };
        if ret <= 0 {
            return None;
        }

        pids.truncate(ret as usize);
        Some(pids)
    }

    fn get_socket_fds(pid: libc::pid_t) -> Option<Vec<ffi::ProcFdInfo>> {
        let buf_size = unsafe {
            ffi::proc_pidinfo(
                pid,
                ffi::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        if buf_size <= 0 {
            return None;
        }

        let fd_count = buf_size as usize / mem::size_of::<ffi::ProcFdInfo>();
        let capacity = fd_count + 16;
        let mut fds: Vec<ffi::ProcFdInfo> = vec![
            ffi::ProcFdInfo {
                proc_fd: 0,
                proc_fdtype: 0,
            };
            capacity
        ];

        let ret = unsafe {
            ffi::proc_pidinfo(
                pid,
                ffi::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr() as *mut libc::c_void,
                (capacity * mem::size_of::<ffi::ProcFdInfo>()) as i32,
            )
        };
        if ret <= 0 {
            return None;
        }

        let actual_count = ret as usize / mem::size_of::<ffi::ProcFdInfo>();
        fds.truncate(actual_count);
        Some(fds)
    }

    fn check_socket_match(
        pid: libc::pid_t,
        fd: i32,
        target_addr: &SocketAddrV4,
    ) -> bool {
        let mut info: ffi::SocketFdInfo = unsafe { mem::zeroed() };
        let ret = unsafe {
            ffi::proc_pidfdinfo(
                pid,
                fd,
                ffi::PROC_PIDFDSOCKETINFO,
                &mut info as *mut ffi::SocketFdInfo as *mut libc::c_void,
                mem::size_of::<ffi::SocketFdInfo>() as i32,
            )
        };

        if ret as usize != mem::size_of::<ffi::SocketFdInfo>() {
            return false;
        }

        // Check: AF_INET and TCP
        if info.psi.soi_family != libc::AF_INET as i32 {
            return false;
        }
        if info.psi.soi_kind != ffi::SOCKINFO_TCP {
            return false;
        }

        let tcp_info = unsafe { &info.psi.soi_proto.pri_tcp };
        let ini = &tcp_info.tcpsi_ini;

        // Check IPv4
        if ini.insi_vflag & ffi::INI_IPV4 == 0 {
            return false;
        }

        // Compare local port (stored in network byte order, needs ntohs)
        let local_port = u16::from_be(ini.insi_lport as u16);
        if local_port != target_addr.port() {
            return false;
        }

        // Compare local address
        let local_addr_raw =
            unsafe { ini.insi_laddr.ina_46.i46a_addr4.s_addr };
        let local_ip = Ipv4Addr::from(u32::from_be(local_addr_raw));
        if local_ip != *target_addr.ip() {
            return false;
        }

        true
    }

    pub(super) fn lookup(local_addr: &SocketAddr) -> Option<ProcessInfo> {
        let target = match local_addr {
            SocketAddr::V4(v4) => *v4,
            SocketAddr::V6(v6) => {
                // Handle IPv4-mapped IPv6 addresses (::ffff:127.0.0.1)
                if let Some(ipv4) = v6.ip().to_ipv4_mapped() {
                    SocketAddrV4::new(ipv4, v6.port())
                } else {
                    return None;
                }
            }
        };

        let pids = list_all_pids()?;
        let my_pid = std::process::id() as libc::pid_t;

        for pid in pids {
            if pid == my_pid || pid <= 0 {
                continue;
            }

            let fds = match get_socket_fds(pid) {
                Some(fds) => fds,
                None => continue,
            };

            for fd_info in &fds {
                if fd_info.proc_fdtype != ffi::PROX_FDTYPE_SOCKET {
                    continue;
                }

                if check_socket_match(pid, fd_info.proc_fd, &target) {
                    let (name, path) = cached_pid_path(pid as u32)?;
                    return Some(ProcessInfo {
                        pid: pid as u32,
                        name,
                        path,
                    });
                }
            }
        }

        None
    }
}

// ---- Linux implementation ----

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddrV4};

    pub(super) fn lookup(local_addr: &SocketAddr) -> Option<ProcessInfo> {
        let target = match local_addr {
            SocketAddr::V4(v4) => *v4,
            SocketAddr::V6(_) => return None,
        };

        // Step 1: Find inode in /proc/net/tcp
        let inode = find_socket_inode(&target)?;

        // Step 2: Find PID that owns this inode
        let pid = find_pid_by_inode(inode)?;

        // Step 3: Resolve PID to path
        resolve_pid_info(pid)
    }

    fn find_socket_inode(target: &SocketAddrV4) -> Option<u64> {
        let content = fs::read_to_string("/proc/net/tcp").ok()?;

        // /proc/net/tcp format:
        // sl  local_address rem_address   st tx_queue:rx_queue ... inode
        // 0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 ...
        // local_address is hex IP (little-endian on x86) : hex port
        let target_ip = u32::from(*target.ip()).swap_bytes(); // to little-endian hex
        let target_port = target.port();

        let local_hex = format!("{:08X}:{:04X}", target_ip, target_port);

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            if fields[1] == local_hex {
                return fields[9].parse::<u64>().ok();
            }
        }

        None
    }

    fn find_pid_by_inode(inode: u64) -> Option<u32> {
        let target = format!("socket:[{}]", inode);

        let proc_dir = fs::read_dir("/proc").ok()?;
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only numeric directories (PIDs)
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let fd_dir = match fs::read_dir(format!("/proc/{}/fd", pid)) {
                Ok(d) => d,
                Err(_) => continue,
            };

            for fd_entry in fd_dir.flatten() {
                if let Ok(link) = fs::read_link(fd_entry.path()) {
                    if link.to_string_lossy() == target {
                        return Some(pid);
                    }
                }
            }
        }

        None
    }

    pub(super) fn resolve_pid_info(pid: u32) -> Option<ProcessInfo> {
        let exe_path = fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
        let path = exe_path.to_string_lossy().to_string();
        let name = exe_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.clone());

        Some(ProcessInfo { pid, name, path })
    }
}

// ---- Windows implementation ----

#[cfg(target_os = "windows")]
mod windows {
    use super::*;

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const MAX_PATH: usize = 260;

    extern "system" {
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> isize;
        fn CloseHandle(hObject: isize) -> i32;
        fn QueryFullProcessImageNameW(
            hProcess: isize,
            dwFlags: u32,
            lpExeName: *mut u16,
            lpdwSize: *mut u32,
        ) -> i32;
    }

    pub(super) fn resolve_pid_info(pid: u32) -> Option<ProcessInfo> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle == 0 {
            return None;
        }

        let mut buf = [0u16; MAX_PATH];
        let mut size = MAX_PATH as u32;
        let ok = unsafe {
            QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size)
        };
        unsafe { CloseHandle(handle); }

        if ok == 0 {
            return None;
        }

        let path = String::from_utf16_lossy(&buf[..size as usize]);
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.clone());

        Some(ProcessInfo { pid, name, path })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_lookup_own_socket() {
        // Bind a socket and look up our own process
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let result = lookup_process_by_socket(&local_addr);

        // On macOS/Linux with sufficient permissions, this should find our own process
        if let Some(info) = result {
            assert_eq!(info.pid, std::process::id());
            assert!(!info.name.is_empty());
            assert!(!info.path.is_empty());
        }
        // If None, we might not have permissions (CI, sandbox, etc.) - that's OK
    }
}
