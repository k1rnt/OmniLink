//! Privileged pf helper for DIOCNATLOOK queries.
//!
//! macOS requires root privileges for the DIOCNATLOOK ioctl, regardless of
//! /dev/pf file permissions. This module provides:
//! - A helper server (`run_pf_helper`) launched as root via osascript, which
//!   opens /dev/pf and answers DIOCNATLOOK queries over a Unix socket.
//! - A client function (`query_original_dst`) used by the accept loop.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use super::pf_sys;

/// Unix socket path for helper IPC.
pub const SOCKET_PATH: &str = "/tmp/omnilink_pf_helper.sock";

/// PID file written by the helper process.
pub const PID_PATH: &str = "/tmp/omnilink_pf_helper.pid";

// Wire protocol (all multi-byte fields in network byte order):
//
// Request  (13 bytes): direction:u8 | peer_ip:u32 | peer_port:u16 | local_ip:u32 | local_port:u16
// Response ( 7 bytes): status:u8    | ip:u32      | port:u16
//
// status: 0 = success, 1 = not found

const REQ_LEN: usize = 13;
const RESP_LEN: usize = 7;

/// Run the privileged pf helper server.
///
/// Called when the binary is invoked with `--pf-helper`. This function blocks
/// and serves DIOCNATLOOK queries until the process is killed (SIGTERM/SIGKILL).
pub fn run_pf_helper() {
    // Install signal handler to clean up on termination
    unsafe {
        libc::signal(libc::SIGTERM, cleanup_and_exit as libc::sighandler_t);
        libc::signal(libc::SIGINT, cleanup_and_exit as libc::sighandler_t);
    }

    // Write PID file
    let pid = std::process::id();
    if let Err(e) = std::fs::write(PID_PATH, pid.to_string()) {
        eprintln!("pf-helper: failed to write PID file: {}", e);
    }

    // Open /dev/pf as root
    let pf_fd = unsafe {
        libc::open(
            b"/dev/pf\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR,
        )
    };
    if pf_fd < 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("pf-helper: failed to open /dev/pf: {}", err);
        std::process::exit(1);
    }
    eprintln!("pf-helper: opened /dev/pf (fd={})", pf_fd);

    // Remove stale socket
    let _ = std::fs::remove_file(SOCKET_PATH);

    // Bind Unix socket
    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("pf-helper: failed to bind {}: {}", SOCKET_PATH, e);
            unsafe { libc::close(pf_fd); }
            std::process::exit(1);
        }
    };

    // Make socket world-accessible so the unprivileged app can connect
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(
        SOCKET_PATH,
        std::fs::Permissions::from_mode(0o777),
    );

    eprintln!("pf-helper: listening on {} (pid={})", SOCKET_PATH, pid);

    // Serve queries (one connection per lookup)
    for stream in listener.incoming() {
        match stream {
            Ok(mut conn) => {
                handle_query(pf_fd, &mut conn);
            }
            Err(e) => {
                eprintln!("pf-helper: accept error: {}", e);
            }
        }
    }

    // Cleanup (reached if listener is closed)
    unsafe { libc::close(pf_fd); }
    let _ = std::fs::remove_file(SOCKET_PATH);
    let _ = std::fs::remove_file(PID_PATH);
}

extern "C" fn cleanup_and_exit(_sig: libc::c_int) {
    let _ = std::fs::remove_file(SOCKET_PATH);
    let _ = std::fs::remove_file(PID_PATH);
    std::process::exit(0);
}

/// Handle a single DIOCNATLOOK query from the client.
fn handle_query(pf_fd: i32, conn: &mut UnixStream) {
    use std::time::Duration;
    conn.set_read_timeout(Some(Duration::from_secs(5))).ok();
    conn.set_write_timeout(Some(Duration::from_secs(5))).ok();

    let mut req = [0u8; REQ_LEN];
    if conn.read_exact(&mut req).is_err() {
        return;
    }

    let direction = req[0];
    let peer_ip = u32::from_be_bytes([req[1], req[2], req[3], req[4]]);
    let peer_port = u16::from_be_bytes([req[5], req[6]]);
    let local_ip = u32::from_be_bytes([req[7], req[8], req[9], req[10]]);
    let local_port = u16::from_be_bytes([req[11], req[12]]);

    // Perform DIOCNATLOOK ioctl as root
    let mut pnl = pf_sys::PfiocNatlook::default();
    pnl.af = pf_sys::AF_INET;
    pnl.proto = pf_sys::IPPROTO_TCP;
    pnl.direction = direction;
    pnl.saddr.v4 = peer_ip.to_be();
    pnl.sxport.port = peer_port.to_be();
    pnl.daddr.v4 = local_ip.to_be();
    pnl.dxport.port = local_port.to_be();

    let ret = unsafe { libc::ioctl(pf_fd, pf_sys::diocnatlook_ioctl(), &mut pnl) };

    let mut resp = [0u8; RESP_LEN];
    if ret >= 0 {
        let rd_ip = u32::from_be(unsafe { pnl.rdaddr.v4 });
        let rd_port = u16::from_be(unsafe { pnl.rdxport.port });
        resp[0] = 0; // success
        resp[1..5].copy_from_slice(&rd_ip.to_be_bytes());
        resp[5..7].copy_from_slice(&rd_port.to_be_bytes());
    } else {
        resp[0] = 1; // failure
    }

    let _ = conn.write_all(&resp);
}

/// Query the privileged helper for the original destination of a NAT-redirected connection.
///
/// Connects to the helper's Unix socket, sends a DIOCNATLOOK request, and returns
/// the original destination. Returns None if the helper is unreachable or lookup fails.
pub fn query_original_dst(
    peer_addr: &SocketAddr,
    local_addr: &SocketAddr,
    direction: u8,
) -> Option<SocketAddr> {
    let (peer_v4, peer_port) = match peer_addr {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        _ => return None,
    };
    let (local_v4, local_port) = match local_addr {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        _ => return None,
    };

    let mut conn = UnixStream::connect(SOCKET_PATH).ok()?;
    conn.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok();
    conn.set_write_timeout(Some(std::time::Duration::from_secs(2))).ok();

    let mut req = [0u8; REQ_LEN];
    req[0] = direction;
    req[1..5].copy_from_slice(&u32::from(peer_v4).to_be_bytes());
    req[5..7].copy_from_slice(&peer_port.to_be_bytes());
    req[7..11].copy_from_slice(&u32::from(local_v4).to_be_bytes());
    req[11..13].copy_from_slice(&local_port.to_be_bytes());

    conn.write_all(&req).ok()?;

    let mut resp = [0u8; RESP_LEN];
    conn.read_exact(&mut resp).ok()?;

    if resp[0] != 0 {
        return None;
    }

    let ip = Ipv4Addr::from(u32::from_be_bytes([resp[1], resp[2], resp[3], resp[4]]));
    let port = u16::from_be_bytes([resp[5], resp[6]]);

    Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

/// Check whether the helper is running and responsive.
pub fn is_helper_running() -> bool {
    Path::new(SOCKET_PATH).exists()
}

/// Best-effort cleanup of socket/PID files from unprivileged context.
/// Actual process kill is done via osascript (root) in flush_pf_rules/install_pf_rules.
pub fn stop_pf_helper() {
    let _ = std::fs::remove_file(SOCKET_PATH);
    let _ = std::fs::remove_file(PID_PATH);
}
