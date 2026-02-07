//! macOS pf (Packet Filter) based transparent proxy interceptor.
//!
//! Uses pfctl to redirect outbound TCP traffic to a local listener, then
//! queries the original destination via DIOCNATLOOK ioctl on /dev/pf.
//! Requires administrator privileges for pfctl and /dev/pf access.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};

use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::interceptor::{InterceptedConnection, Interceptor, InterceptorError, InterceptorEvent};

use super::pf_helper;
use super::pf_sys; // PF_IN, PF_OUT constants used in accept loop
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

        // 3. Install pf anchor rules and launch privileged DIOCNATLOOK helper
        install_pf_rules(&iface, self.listener_port, &self.excluded_ips)?;

        // 4. Spawn accept loop (queries helper via Unix socket for original dst)
        let (tx, rx) = mpsc::channel(256);

        let handle = tokio::spawn(async move {
            run_pf_accept_loop(listener, tx).await;
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

        // 2. Flush pf anchor rules and stop helper
        flush_pf_rules();

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

/// Install pf anchor rules and launch the privileged DIOCNATLOOK helper.
///
/// Everything runs in a single `osascript` admin command (one password prompt):
/// 1. Load rules into the named anchor (`pfctl -a <anchor> -f -`)
/// 2. Add `rdr-anchor` and `anchor` references to the main ruleset
/// 3. Launch the privileged helper as a background root process
fn install_pf_rules(
    iface: &str,
    listener_port: u16,
    excluded_ips: &[Ipv4Addr],
) -> Result<(), InterceptorError> {
    let mut rules = String::new();

    // pf requires rules in order: translation (rdr/nat) THEN filter (pass/block).

    // --- Translation rules (rdr) ---
    rules.push_str(&format!(
        "rdr pass on lo0 proto tcp from any to !127.0.0.0/8 -> 127.0.0.1 port {}\n",
        listener_port
    ));

    // --- Filter rules (pass) ---
    for ip in excluded_ips {
        rules.push_str(&format!(
            "pass out quick on {} proto tcp from any to {} no state\n",
            iface, ip
        ));
    }

    rules.push_str(&format!(
        "pass out quick on {} proto tcp from any to 127.0.0.0/8 no state\n",
        iface
    ));

    rules.push_str(&format!(
        "pass out quick on {} proto tcp from any port {}:{} no state\n",
        iface, BYPASS_PORT_START, BYPASS_PORT_END
    ));

    rules.push_str(&format!(
        "pass out on {} route-to lo0 inet proto tcp from any to any keep state\n",
        iface
    ));

    let rules_escaped = rules.replace('\'', "'\\''").replace('\n', "\\n");

    // Get path to current executable for launching the helper
    let exe_path = std::env::current_exe()
        .map_err(|e| {
            InterceptorError::RoutingSetup(format!("cannot determine executable path: {}", e))
        })?
        .display()
        .to_string()
        .replace('\'', "'\\''");

    // Single admin command: kill existing helper + pfctl setup + helper launch (one password prompt)
    // Uses mktemp to prevent /tmp symlink attacks (Fix #3)
    // Kills existing helper with root privileges via osascript (Fix #5)
    let cmd = format!(
        "kill $(cat {pid_path} 2>/dev/null) 2>/dev/null; \
         rm -f {sock_path} {pid_path}; \
         ANCHOR_CONF=$(mktemp /tmp/omnilink_pf.XXXXXX) && \
         MAIN_CONF=$(mktemp /tmp/omnilink_pf.XXXXXX) && \
         trap 'rm -f $ANCHOR_CONF $MAIN_CONF' EXIT && \
         printf '{rules}' > $ANCHOR_CONF && \
         pfctl -a {anchor} -f $ANCHOR_CONF 2>&1 && \
         {{ grep '^scrub-anchor' /etc/pf.conf 2>/dev/null; \
         grep '^nat-anchor' /etc/pf.conf 2>/dev/null; \
         grep '^rdr-anchor' /etc/pf.conf 2>/dev/null; \
         echo 'rdr-anchor \"{anchor}\"'; \
         grep '^dummynet-anchor' /etc/pf.conf 2>/dev/null; \
         grep '^anchor' /etc/pf.conf 2>/dev/null; \
         echo 'anchor \"{anchor}\"'; \
         grep '^load' /etc/pf.conf 2>/dev/null; \
         true; }} > $MAIN_CONF && \
         pfctl -f $MAIN_CONF 2>&1 && \
         (pfctl -e 2>&1 || true) && \
         ('{exe}' --pf-helper </dev/null >/tmp/omnilink_pf_helper.log 2>&1 &)",
        rules = rules_escaped,
        anchor = ANCHOR_NAME,
        exe = exe_path,
        pid_path = pf_helper::PID_PATH,
        sock_path = pf_helper::SOCKET_PATH,
    );

    tracing::info!(rules = %rules, "installing pf rules and launching helper");

    let output = privilege::run_with_admin_privileges(&cmd).map_err(|e| {
        InterceptorError::RoutingSetup(format!("failed to install pf rules: {}", e))
    })?;

    tracing::info!(output = %output.trim(), "pf admin command output");
    tracing::info!(anchor = ANCHOR_NAME, "pf anchor rules installed");

    // Wait for the helper socket to appear (up to 3 seconds)
    for _ in 0..30 {
        if pf_helper::is_helper_running() {
            tracing::info!("pf privileged helper is running");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Helper didn't start — flush rules to avoid network outage
    flush_pf_rules();
    Err(InterceptorError::RoutingSetup(
        "pf helper did not start within 3 seconds (rules flushed for safety)".to_string(),
    ))
}

/// Flush pf anchor rules, stop the helper, and restore the original main ruleset.
/// Helper kill is done via osascript (root) to avoid EPERM (Fix #5).
fn flush_pf_rules() {
    let cmd = format!(
        "kill $(cat {pid_path} 2>/dev/null) 2>/dev/null; \
         rm -f {sock_path} {pid_path}; \
         pfctl -a {anchor} -F all 2>&1; \
         pfctl -f /etc/pf.conf 2>&1 || true",
        anchor = ANCHOR_NAME,
        pid_path = pf_helper::PID_PATH,
        sock_path = pf_helper::SOCKET_PATH,
    );
    match privilege::run_with_admin_privileges(&cmd) {
        Ok(_) => tracing::info!(anchor = ANCHOR_NAME, "pf rules flushed and helper stopped"),
        Err(e) => tracing::warn!(error = %e, "failed to flush pf rules (may need manual cleanup)"),
    }
}

/// Accept loop: accepts redirected connections and queries the privileged helper
/// for the original destination via Unix socket IPC.
async fn run_pf_accept_loop(
    listener: TcpListener,
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

                // Query the privileged helper for DIOCNATLOOK (runs as root)
                let original_dst = tokio::task::spawn_blocking(move || {
                    pf_helper::query_original_dst(&peer_addr, &local_addr, pf_sys::PF_IN)
                        .or_else(|| {
                            pf_helper::query_original_dst(&peer_addr, &local_addr, pf_sys::PF_OUT)
                        })
                })
                .await
                .ok()
                .flatten();

                let Some(original_dst) = original_dst else {
                    tracing::warn!(
                        peer = %peer_addr,
                        local = %local_addr,
                        "could not determine original destination, dropping connection"
                    );
                    continue;
                };

                // Skip connections to our own listener
                if original_dst == local_addr {
                    continue;
                }

                tracing::info!(
                    peer = %peer_addr,
                    dst = %original_dst,
                    "pf: DIOCNATLOOK resolved original destination"
                );

                // Look up process info (lsof is blocking, so use spawn_blocking)
                let peer_for_proc = peer_addr;
                let proc_info = tokio::task::spawn_blocking(move || {
                    crate::process::lookup_process_by_socket(&peer_for_proc)
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
