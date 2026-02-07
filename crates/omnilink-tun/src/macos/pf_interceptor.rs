//! macOS pf (Packet Filter) based transparent proxy interceptor.
//!
//! Uses pfctl to redirect outbound TCP traffic to a local listener, then
//! queries the original destination via DIOCNATLOOK ioctl on /dev/pf.
//! Requires administrator privileges for pfctl and /dev/pf access.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU16, Ordering};

use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::interceptor::{InterceptedConnection, Interceptor, InterceptorError, InterceptorEvent};

use super::pf_sys;
use super::privilege;

const ANCHOR_NAME: &str = "com.omnilink";

/// Start of the source port range used by OmniLink's outbound connections.
/// pf rules exclude this range to prevent re-interception loops.
pub const BYPASS_PORT_START: u16 = 50000;
/// End of the source port range (inclusive).
pub const BYPASS_PORT_END: u16 = 50999;

static BYPASS_PORT_COUNTER: AtomicU16 = AtomicU16::new(BYPASS_PORT_START);

/// Allocate the next source port from the bypass range (50000-50999).
/// Wraps around when the range is exhausted.
pub fn next_bypass_port() -> u16 {
    loop {
        let current = BYPASS_PORT_COUNTER.load(Ordering::Relaxed);
        let next = if current >= BYPASS_PORT_END {
            BYPASS_PORT_START
        } else {
            current + 1
        };
        if BYPASS_PORT_COUNTER
            .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return current;
        }
    }
}

/// macOS interceptor using pf (Packet Filter) for transparent TCP redirection.
pub struct PfInterceptor {
    running: bool,
    /// Proxy server addresses to exclude from interception (prevent routing loops).
    excluded_ips: Vec<Ipv4Addr>,
    /// Network interface to intercept (auto-detected if None).
    interface: Option<String>,
    /// File descriptor for /dev/pf (opened during start via privileged helper).
    pf_fd: Option<RawFd>,
    /// Handle for the spawned accept loop task.
    abort_handle: Option<tokio::task::JoinHandle<()>>,
    /// The listener port allocated during start.
    listener_port: u16,
}

impl PfInterceptor {
    pub fn new(excluded_ips: Vec<Ipv4Addr>) -> Self {
        Self {
            running: false,
            excluded_ips,
            interface: None,
            pf_fd: None,
            abort_handle: None,
            listener_port: 0,
        }
    }
}

#[async_trait]
impl Interceptor for PfInterceptor {
    async fn start(&mut self) -> Result<mpsc::Receiver<InterceptorEvent>, InterceptorError> {
        if self.running {
            return Err(InterceptorError::AlreadyRunning);
        }

        // 1. Detect active network interface
        let iface = match &self.interface {
            Some(i) => i.clone(),
            None => detect_active_interface().ok_or_else(|| {
                InterceptorError::RoutingSetup(
                    "could not detect active network interface".to_string(),
                )
            })?,
        };
        tracing::info!(interface = %iface, "detected active network interface");

        // 2. Bind TCP listener on localhost with random port
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(InterceptorError::Io)?;
        let local_addr = listener.local_addr().map_err(InterceptorError::Io)?;
        self.listener_port = local_addr.port();
        tracing::info!(port = self.listener_port, "pf TCP listener bound");

        // 3. Install pf anchor rules (also makes /dev/pf readable for DIOCNATLOOK)
        install_pf_rules(&iface, self.listener_port, &self.excluded_ips)?;

        // 4. Open /dev/pf (after install_pf_rules which chmod's it)
        let pf_fd = open_pf_dev()?;
        self.pf_fd = Some(pf_fd);

        // 5. Spawn accept loop
        let (tx, rx) = mpsc::channel(256);

        let handle = tokio::spawn(async move {
            run_pf_accept_loop(listener, pf_fd, tx).await;
        });

        self.abort_handle = Some(handle);
        self.running = true;

        Ok(rx)
    }

    async fn stop(&mut self) -> Result<(), InterceptorError> {
        // 1. Abort the accept task
        if let Some(handle) = self.abort_handle.take() {
            handle.abort();
        }

        // 2. Flush pf anchor rules
        flush_pf_rules();

        // 3. Close /dev/pf fd
        if let Some(fd) = self.pf_fd.take() {
            unsafe {
                libc::close(fd);
            }
        }

        self.running = false;
        tracing::info!("pf interceptor stopped, rules flushed");

        Ok(())
    }
}

/// Detect the active network interface by parsing `route -n get default`.
fn detect_active_interface() -> Option<String> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("interface:") {
            return Some(line.split(':').nth(1)?.trim().to_string());
        }
    }
    None
}

/// Open /dev/pf for DIOCNATLOOK ioctl.
///
/// Called AFTER `install_pf_rules` which `chmod o+rw /dev/pf` with admin privileges.
/// Returns an error if /dev/pf cannot be opened (DIOCNATLOOK is required for
/// transparent proxy to work — without it, original destinations are unknown).
fn open_pf_dev() -> Result<RawFd, InterceptorError> {
    // Try read-write first (needed for DIOCNATLOOK on some macOS versions)
    let fd = unsafe { libc::open(b"/dev/pf\0".as_ptr() as *const libc::c_char, libc::O_RDWR) };
    if fd >= 0 {
        tracing::info!("/dev/pf opened (rw)");
        return Ok(fd);
    }

    // Try read-only
    let fd =
        unsafe { libc::open(b"/dev/pf\0".as_ptr() as *const libc::c_char, libc::O_RDONLY) };
    if fd >= 0 {
        tracing::info!("/dev/pf opened (ro)");
        return Ok(fd);
    }

    let err = std::io::Error::last_os_error();
    Err(InterceptorError::RoutingSetup(format!(
        "cannot open /dev/pf: {} (chmod may have failed during setup)",
        err
    )))
}

/// Install pf anchor rules for transparent TCP redirection.
///
/// Two steps are required:
/// 1. Load rules into the named anchor (`pfctl -a <anchor> -f -`)
/// 2. Add `rdr-anchor` and `anchor` references to the **main** ruleset so that
///    pf actually evaluates our anchor. macOS's default `/etc/pf.conf` only
///    references `com.apple/*`, so without this step the anchor is loaded but
///    never evaluated.
///
/// We reload the main ruleset from `/etc/pf.conf` plus our anchor references
/// via `pfctl -f -` (in-memory only; `/etc/pf.conf` is never modified).
fn install_pf_rules(
    iface: &str,
    listener_port: u16,
    excluded_ips: &[Ipv4Addr],
) -> Result<(), InterceptorError> {
    let mut rules = String::new();

    // pf requires rules in order: translation (rdr/nat) THEN filter (pass/block).

    // --- Translation rules (rdr) ---
    // Redirect traffic arriving on lo0 (via route-to) to our listener
    rules.push_str(&format!(
        "rdr pass on lo0 proto tcp from any to any -> 127.0.0.1 port {}\n",
        listener_port
    ));

    // --- Filter rules (pass) ---
    // Exclude proxy server IPs to prevent loops
    for ip in excluded_ips {
        rules.push_str(&format!(
            "pass out quick on {} proto tcp from any to {} no state\n",
            iface, ip
        ));
    }

    // Don't redirect traffic to localhost (our own listener, Burp, etc.)
    rules.push_str(&format!(
        "pass out quick on {} proto tcp from any to 127.0.0.0/8 no state\n",
        iface
    ));

    // Exclude OmniLink's own outbound connections (source port range 50000-50999)
    // to prevent re-interception loops. OmniLink binds outbound sockets to this range.
    rules.push_str(&format!(
        "pass out quick on {} proto tcp from any port {}:{} no state\n",
        iface, BYPASS_PORT_START, BYPASS_PORT_END
    ));

    // Route ALL outbound TCP through lo0 for interception
    rules.push_str(&format!(
        "pass out on {} route-to lo0 inet proto tcp from any to any keep state\n",
        iface
    ));

    // Escape newlines for printf (osascript cannot handle literal newlines in
    // the AppleScript string — they break the `do shell script "…"` parsing).
    let rules_escaped = rules.replace('\'', "'\\''").replace('\n', "\\n");

    // The command is structured so that:
    // - pfctl commands are chained with && (fail-fast)
    // - pfctl -e uses || true (OK if pf already enabled)
    // - chmod runs last to determine the exit code
    // - temp files cleaned up via trap (doesn't affect exit code)
    let cmd = format!(
        "trap 'rm -f /tmp/omnilink_pf_anchor.conf /tmp/omnilink_pf_main.conf' EXIT; \
         printf '{}' > /tmp/omnilink_pf_anchor.conf && \
         pfctl -a {} -f /tmp/omnilink_pf_anchor.conf 2>&1 && \
         {{ grep '^scrub-anchor' /etc/pf.conf 2>/dev/null; \
         grep '^nat-anchor' /etc/pf.conf 2>/dev/null; \
         grep '^rdr-anchor' /etc/pf.conf 2>/dev/null; \
         echo 'rdr-anchor \"{}\"'; \
         grep '^dummynet-anchor' /etc/pf.conf 2>/dev/null; \
         grep '^anchor' /etc/pf.conf 2>/dev/null; \
         echo 'anchor \"{}\"'; \
         grep '^load' /etc/pf.conf 2>/dev/null; \
         true; }} > /tmp/omnilink_pf_main.conf && \
         pfctl -f /tmp/omnilink_pf_main.conf 2>&1 && \
         (pfctl -e 2>&1 || true) && \
         chmod o+rw /dev/pf 2>&1",
        rules_escaped,
        ANCHOR_NAME,
        ANCHOR_NAME,
        ANCHOR_NAME,
    );

    tracing::info!(rules = %rules, "installing pf rules");

    let output = privilege::run_with_admin_privileges(&cmd).map_err(|e| {
        InterceptorError::RoutingSetup(format!("failed to install pf rules: {}", e))
    })?;

    tracing::info!(output = %output.trim(), "pf admin command output");

    // Verify /dev/pf is now accessible (chmod worked)
    let pf_check = unsafe {
        libc::access(b"/dev/pf\0".as_ptr() as *const libc::c_char, libc::R_OK)
    };
    if pf_check != 0 {
        return Err(InterceptorError::RoutingSetup(
            "/dev/pf is not readable after setup — admin command may have failed".to_string(),
        ));
    }

    tracing::info!(anchor = ANCHOR_NAME, "pf anchor rules and references installed");

    // Verify rules are actually loaded in the anchor.
    // Note: pfctl requires root to read anchor rules, so only error if the
    // command succeeds (exit 0) but returns empty output.
    if let Ok(verify_out) = std::process::Command::new("pfctl")
        .args(["-a", ANCHOR_NAME, "-sr"])
        .output()
    {
        if verify_out.status.success() {
            let loaded_rules = String::from_utf8_lossy(&verify_out.stdout);
            if loaded_rules.trim().is_empty() {
                return Err(InterceptorError::RoutingSetup(
                    "pf anchor rules are empty after installation".to_string(),
                ));
            }
            tracing::info!(rules = %loaded_rules.trim(), "pf anchor rules verified");
        } else {
            tracing::info!("pf anchor rules installed (verification skipped — needs root)");
        }
    }

    Ok(())
}

/// Flush pf anchor rules and restore the original main ruleset (best-effort).
///
/// 1. Flush all rules inside our anchor.
/// 2. Reload `/etc/pf.conf` into the main ruleset to remove our anchor references.
fn flush_pf_rules() {
    let cmd = format!(
        "pfctl -a {} -F all 2>&1; pfctl -f /etc/pf.conf 2>&1; chmod 600 /dev/pf 2>&1 || true",
        ANCHOR_NAME,
    );
    match privilege::run_with_admin_privileges(&cmd) {
        Ok(_) => tracing::info!(anchor = ANCHOR_NAME, "pf rules flushed and main config restored"),
        Err(e) => tracing::warn!(error = %e, "failed to flush pf rules (may need manual cleanup)"),
    }
}

/// Accept loop: accepts redirected connections and emits InterceptorEvents.
async fn run_pf_accept_loop(
    listener: TcpListener,
    pf_fd: RawFd,
    tx: mpsc::Sender<InterceptorEvent>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let local_addr = match stream.local_addr() {
                    Ok(a) => a,
                    Err(_) => continue,
                };

                tracing::info!(
                    peer = %peer_addr,
                    local = %local_addr,
                    "pf: accepted connection, looking up original destination"
                );

                // Try DIOCNATLOOK with both directions (PF_IN for rdr, PF_OUT for nat)
                let original_dst =
                    lookup_original_dst_ioctl(pf_fd, &peer_addr, &local_addr, pf_sys::PF_IN)
                        .or_else(|| lookup_original_dst_ioctl(pf_fd, &peer_addr, &local_addr, pf_sys::PF_OUT))
                        .or_else(|| {
                            tracing::info!("DIOCNATLOOK failed both directions, trying pfctl -s state");
                            lookup_original_dst_pfctl(&peer_addr, local_addr.port())
                        });

                let Some(original_dst) = original_dst else {
                    tracing::warn!(
                        peer = %peer_addr,
                        local = %local_addr,
                        "could not determine original destination, dropping connection"
                    );
                    continue;
                };

                // Skip connections to our own listener (shouldn't happen, but safety check)
                if original_dst == local_addr {
                    continue;
                }

                // Look up process info (lsof is blocking, so use spawn_blocking)
                let proc_info = tokio::task::spawn_blocking(move || {
                    crate::process::lookup_process_by_socket(&peer_addr)
                }).await.ok().flatten();

                let conn = InterceptedConnection {
                    original_dst,
                    src_addr: peer_addr,
                    process_name: proc_info.as_ref().map(|p| p.name.clone()),
                    process_path: proc_info.as_ref().map(|p| p.path.clone()),
                };

                tracing::debug!(
                    src = %peer_addr,
                    dst = %original_dst,
                    process = ?conn.process_name,
                    "pf: intercepted connection"
                );

                if tx
                    .send(InterceptorEvent::NewConnection(conn, stream))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "pf TCP accept error");
            }
        }
    }
}

/// Look up the original destination using DIOCNATLOOK ioctl on /dev/pf.
fn lookup_original_dst_ioctl(
    pf_fd: RawFd,
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

    let mut pnl = pf_sys::PfiocNatlook::default();
    pnl.af = pf_sys::AF_INET;
    pnl.proto = pf_sys::IPPROTO_TCP;
    pnl.direction = direction;

    // Source: the application's address
    pnl.saddr.v4 = u32::from(peer_v4).to_be();
    pnl.sxport.port = peer_port.to_be();

    // Destination: our listener address (after rdr)
    pnl.daddr.v4 = u32::from(local_v4).to_be();
    pnl.dxport.port = local_port.to_be();

    let dir_name = if direction == pf_sys::PF_IN { "PF_IN" } else { "PF_OUT" };

    let ret = unsafe { libc::ioctl(pf_fd, pf_sys::diocnatlook_ioctl(), &mut pnl) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        tracing::info!(
            dir = dir_name,
            peer = %peer_addr,
            local = %local_addr,
            error = %err,
            "DIOCNATLOOK failed"
        );
        return None;
    }

    // Extract result: real destination
    let rd_ip = Ipv4Addr::from(u32::from_be(unsafe { pnl.rdaddr.v4 }));
    let rd_port = u16::from_be(unsafe { pnl.rdxport.port });

    tracing::info!(
        dir = dir_name,
        result_ip = %rd_ip,
        result_port = rd_port,
        "DIOCNATLOOK succeeded"
    );

    // Sanity check: result should differ from listener address
    if rd_ip == local_v4 && rd_port == local_port {
        tracing::info!("DIOCNATLOOK result matches listener address, ignoring");
        return None;
    }

    Some(SocketAddr::V4(SocketAddrV4::new(rd_ip, rd_port)))
}

/// Fallback: look up original destination by parsing `pfctl -s state` output.
///
/// Two strategies:
/// 1. Match peer_addr directly in state table
/// 2. Match source port against outbound state entries (route-to creates outbound state)
fn lookup_original_dst_pfctl(peer_addr: &SocketAddr, listener_port: u16) -> Option<SocketAddr> {
    let output = std::process::Command::new("pfctl")
        .args(["-s", "state"])
        .output()
        .ok()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::info!(stderr = %stderr, "pfctl -s state failed (may need root)");
        return None;
    }

    let state_text = String::from_utf8_lossy(&output.stdout);
    tracing::info!(lines = state_text.lines().count(), "pfctl -s state output");

    // Strategy 1: direct match on peer address
    if let Some(dst) = parse_pf_state_direct(&state_text, peer_addr) {
        tracing::info!(dst = %dst, "pfctl fallback: found via direct match");
        return Some(dst);
    }

    // Strategy 2: match source port in outbound state entries
    let src_port = peer_addr.port();
    if let Some(dst) = parse_pf_state_by_port(&state_text, src_port, listener_port) {
        tracing::info!(dst = %dst, src_port = src_port, "pfctl fallback: found via source port match");
        return Some(dst);
    }

    tracing::info!(peer = %peer_addr, "pfctl fallback: no match found in state table");
    None
}

/// Strategy 1: find the peer address directly in the state table and extract the destination.
fn parse_pf_state_direct(state_text: &str, peer_addr: &SocketAddr) -> Option<SocketAddr> {
    let peer_str = peer_addr.to_string();

    for line in state_text.lines() {
        if !line.contains("tcp") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        // Find source address match
        let src_idx = match parts.iter().position(|&p| p == peer_str || p.starts_with(&peer_str)) {
            Some(i) => i,
            None => continue,
        };

        // Find the arrow (-> or <-)
        let arrow_idx = match parts[src_idx..].iter().position(|&p| p == "->") {
            Some(i) => i,
            None => continue,
        };
        let dst_idx = src_idx + arrow_idx + 1;

        if dst_idx < parts.len() {
            if let Some(addr) = parse_addr_str(parts[dst_idx]) {
                return Some(addr);
            }
        }
    }

    None
}

/// Strategy 2: find outbound state entry matching the source port.
/// The `pass out route-to lo0 keep state` rule creates outbound state with the original
/// destination. We match on source port to find it.
fn parse_pf_state_by_port(state_text: &str, src_port: u16, listener_port: u16) -> Option<SocketAddr> {
    let port_suffix = format!(":{}", src_port);

    for line in state_text.lines() {
        if !line.contains("tcp") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        // Look for a source address ending with our port
        for (i, &part) in parts.iter().enumerate() {
            if !part.ends_with(&port_suffix) {
                continue;
            }
            // Check for "->" arrow after this part
            if i + 2 < parts.len() && parts[i + 1] == "->" {
                let dst_str = parts[i + 2];
                if let Some(addr) = parse_addr_str(dst_str) {
                    // Skip if destination is our listener (this is the rdr state, not outbound)
                    if addr.port() == listener_port && addr.ip().is_loopback() {
                        continue;
                    }
                    return Some(addr);
                }
            }
        }
    }

    None
}

/// Parse an address string like "1.2.3.4:443" from pfctl state output.
fn parse_addr_str(s: &str) -> Option<SocketAddr> {
    let clean = s.trim_end_matches(|c: char| !c.is_ascii_digit());
    if let Ok(addr) = clean.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Some((ip_str, port_str)) = clean.rsplit_once(':') {
        if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>()) {
            return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
        }
    }
    None
}
