#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_sock_addr, map, sock_ops},
    maps::{Array, HashMap},
    programs::{SockAddrContext, SockOpsContext},
};
use omnilink_ebpf_common::{InterceptConfig, OriginalDest, PortKey, SockKey};

// --- BPF Maps ---

/// Stores original destination keyed by socket cookie.
#[map]
static ORIGINAL_DESTS: HashMap<SockKey, OriginalDest> = HashMap::with_max_entries(65536, 0);

/// Maps source port to socket cookie (for original destination lookup).
#[map]
static PORT_TO_COOKIE: HashMap<PortKey, u64> = HashMap::with_max_entries(65536, 0);

/// Configuration array (single entry at index 0).
#[map]
static CONFIG: Array<InterceptConfig> = Array::with_max_entries(1, 0);

// --- Program 1: cgroup/connect4 ---
// Intercepts connect() syscall and redirects to local proxy.

#[cgroup_sock_addr(connect4)]
pub fn connect4_intercept(ctx: SockAddrContext) -> i32 {
    match try_connect4(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // Allow connection on error
    }
}

fn try_connect4(ctx: &SockAddrContext) -> Result<i32, i64> {
    let config = unsafe { CONFIG.get(0) }.ok_or(0i64)?;

    // Skip interception for our own proxy process to prevent routing loops
    let pid_tgid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    if pid == config.pid_self {
        return Ok(1); // Allow without redirect
    }

    // Get socket cookie for this connection
    let cookie =
        unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr() as *mut _) };

    // Read original destination from the sock_addr context
    let dst_addr = unsafe { (*ctx.sock_addr).user_ip4 };
    let dst_port = unsafe { (*ctx.sock_addr).user_port } as u16;

    // Skip loopback (127.0.0.1 in network byte order = 0x0100007f)
    if dst_addr == 0x0100_007f {
        return Ok(1);
    }

    // Save original destination to BPF map
    let key = SockKey { cookie };
    let value = OriginalDest {
        addr: dst_addr,
        port: dst_port,
        _pad: 0,
        pid,
        _pad2: 0,
    };
    ORIGINAL_DESTS
        .insert(&key, &value, 0)
        .map_err(|e| e as i64)?;

    // Redirect to local proxy by modifying the connect address in-place
    unsafe {
        (*ctx.sock_addr).user_ip4 = config.proxy_addr;
        (*ctx.sock_addr).user_port = config.proxy_port as u32;
    }

    Ok(1) // Allow (now redirected)
}

// --- Program 2: sockops ---
// Records source port after TCP connection is established.

#[sock_ops]
pub fn sockops_record(ctx: SockOpsContext) -> u32 {
    match try_sockops(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sockops(ctx: &SockOpsContext) -> Result<u32, i64> {
    // Only handle BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB (4)
    let op = unsafe { (*ctx.ops).op };
    if op != 4 {
        return Ok(0);
    }

    let cookie =
        unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr() as *mut _) };
    let src_port = unsafe { (*ctx.ops).local_port } as u16;

    let key = PortKey {
        src_port,
        _pad: [0; 6],
    };
    PORT_TO_COOKIE
        .insert(&key, &cookie, 0)
        .map_err(|e| e as i64)?;

    Ok(0)
}

// Note: cgroup/getsockopt program for SO_ORIGINAL_DST interception
// is omitted here because aya-ebpf does not yet have stable support
// for CgroupSockopt program types.
//
// Instead, the userspace proxy queries the ORIGINAL_DESTS BPF map
// directly using the socket cookie obtained via SO_COOKIE getsockopt.

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
