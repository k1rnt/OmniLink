//! macOS pf (Packet Filter) based transparent proxy interceptor.
//!
//! Uses pfctl to redirect outbound TCP traffic to a local listener, then
//! queries the original destination via DIOCNATLOOK ioctl on /dev/pf.
//! Requires administrator privileges for pfctl and /dev/pf access.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::RawFd;

use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::interceptor::{InterceptedConnection, Interceptor, InterceptorError, InterceptorEvent};

use super::pf_sys;
use super::privilege;

const ANCHOR_NAME: &str = "com.omnilink";

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
    /// UID of the current process (for loop avoidance in pf rules).
    self_uid: u32,
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
            self_uid: unsafe { libc::getuid() },
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
        install_pf_rules(&iface, self.listener_port, self.self_uid, &self.excluded_ips)?;

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
/// Called AFTER `install_pf_rules` which `chmod o+r /dev/pf` with admin privileges.
/// Returns -1 as sentinel if /dev/pf cannot be opened (fallback to pfctl -s state).
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

    tracing::warn!("could not open /dev/pf, will use pfctl -s state fallback for NAT lookup");
    Ok(-1)
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
    self_uid: u32,
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

    // Route outbound TCP from non-self users through lo0
    rules.push_str(&format!(
        "pass out on {} route-to lo0 inet proto tcp from any to any user != {} keep state\n",
        iface, self_uid
    ));

    // Escape newlines for printf (osascript cannot handle literal newlines in
    // the AppleScript string — they break the `do shell script "…"` parsing).
    let rules_escaped = rules.replace('\'', "'\\''").replace('\n', "\\n");

    // Step 1: Write anchor rules to temp file via printf, load with pfctl -a
    // Step 2: Rebuild main ruleset from /etc/pf.conf with our anchor references
    //         inserted at the correct positions (pf requires strict ordering:
    //         scrub → nat → rdr → dummynet → filter → load).
    // Step 3: Enable pf
    // Step 4: Clean up temp files
    let cmd = format!(
        "printf '{}' > /tmp/omnilink_pf_anchor.conf && \
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
         pfctl -e 2>&1; \
         chmod o+rw /dev/pf 2>&1; \
         rm -f /tmp/omnilink_pf_anchor.conf /tmp/omnilink_pf_main.conf",
        rules_escaped,
        ANCHOR_NAME,
        ANCHOR_NAME,
        ANCHOR_NAME,
    );

    tracing::debug!(rules = %rules, "installing pf rules with anchor references");

    privilege::run_with_admin_privileges(&cmd).map_err(|e| {
        InterceptorError::RoutingSetup(format!("failed to install pf rules: {}", e))
    })?;

    tracing::info!(anchor = ANCHOR_NAME, "pf anchor rules and references installed");
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

                // Look up original destination via DIOCNATLOOK (primary)
                let original_dst = if pf_fd >= 0 {
                    lookup_original_dst_ioctl(pf_fd, &peer_addr, &local_addr)
                } else {
                    None
                };

                // Fallback: parse pfctl -s state
                let original_dst =
                    original_dst.or_else(|| lookup_original_dst_pfctl(&peer_addr));

                let Some(original_dst) = original_dst else {
                    tracing::warn!(
                        peer = %peer_addr,
                        "could not determine original destination, dropping connection"
                    );
                    continue;
                };

                // Skip connections to our own listener (shouldn't happen, but safety check)
                if original_dst == local_addr {
                    continue;
                }

                // Look up process info
                let proc_info = crate::process::lookup_process_by_socket(&peer_addr);

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
    pnl.direction = pf_sys::PF_OUT;

    // Source: the application's address
    pnl.saddr.v4 = u32::from(peer_v4).to_be();
    pnl.sxport.port = peer_port.to_be();

    // Destination: our listener address (after rdr)
    pnl.daddr.v4 = u32::from(local_v4).to_be();
    pnl.dxport.port = local_port.to_be();

    let ret = unsafe { libc::ioctl(pf_fd, pf_sys::diocnatlook_ioctl(), &mut pnl) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        tracing::trace!(error = %err, "DIOCNATLOOK failed");
        return None;
    }

    // Extract result: real destination
    let rd_ip = Ipv4Addr::from(u32::from_be(unsafe { pnl.rdaddr.v4 }));
    let rd_port = u16::from_be(unsafe { pnl.rdxport.port });

    // Sanity check: result should differ from listener address
    if rd_ip == local_v4 && rd_port == local_port {
        return None;
    }

    Some(SocketAddr::V4(SocketAddrV4::new(rd_ip, rd_port)))
}

/// Fallback: look up original destination by parsing `pfctl -s state` output.
///
/// Note: Does NOT use admin privilege escalation — that would trigger a password
/// dialog for every connection. If pfctl fails without root, returns None.
fn lookup_original_dst_pfctl(peer_addr: &SocketAddr) -> Option<SocketAddr> {
    let output = std::process::Command::new("pfctl")
        .args(["-s", "state"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let state_text = String::from_utf8_lossy(&output.stdout);
    parse_pf_state(&state_text, peer_addr)
}

/// Parse pfctl state table output to find the original destination for a connection.
///
/// State lines look like:
/// `ALL tcp 192.168.1.100:54321 -> 93.184.216.34:443       ESTABLISHED:ESTABLISHED`
/// After rdr, the destination in the state entry is the *original* destination.
fn parse_pf_state(state_text: &str, peer_addr: &SocketAddr) -> Option<SocketAddr> {
    let peer_str = peer_addr.to_string();

    for line in state_text.lines() {
        // Look for TCP state entries containing our peer address
        if !line.contains("tcp") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        // Format: ALL tcp <src> -> <dst> <state>
        // or: ALL tcp <src> (<rdr_dst>) -> <orig_dst> <state>
        if parts.len() < 5 {
            continue;
        }

        // Find source address match
        let src_idx = parts.iter().position(|&p| p == peer_str || p.starts_with(&peer_str))?;

        // Find the arrow
        let arrow_idx = parts[src_idx..].iter().position(|&p| p == "->")?;
        let dst_idx = src_idx + arrow_idx + 1;

        if dst_idx < parts.len() {
            let dst_str = parts[dst_idx].trim_end_matches(|c: char| !c.is_ascii_digit());
            if let Ok(addr) = dst_str.parse::<SocketAddr>() {
                return Some(addr);
            }
            // Try IP:port format parsing
            if let Some((ip_str, port_str)) = dst_str.rsplit_once(':') {
                if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>())
                {
                    return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
                }
            }
        }
    }

    None
}
