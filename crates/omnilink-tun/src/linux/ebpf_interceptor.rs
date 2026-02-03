use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use async_trait::async_trait;
use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use aya::programs::{CgroupSockAddr, SockOps};
use aya::Ebpf;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use omnilink_core::dns::VirtualDns;
use omnilink_ebpf_common::{InterceptConfig, OriginalDest, SockKey};

use crate::interceptor::{InterceptedConnection, Interceptor, InterceptorError, InterceptorEvent};

const PROXY_LISTEN_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// Linux interceptor using eBPF cgroup hooks.
///
/// Hooks into the cgroup's connect4 and sockops to redirect outgoing
/// TCP connections to a local proxy listener, while recording the
/// original destination in a BPF map for later retrieval.
pub struct EbpfInterceptor {
    virtual_dns: Arc<VirtualDns>,
    running: bool,
    bpf: Option<Ebpf>,
    abort_handle: Option<tokio::task::JoinHandle<()>>,
}

impl EbpfInterceptor {
    pub fn new(virtual_dns: Arc<VirtualDns>, _excluded_ips: Vec<Ipv4Addr>) -> Self {
        Self {
            virtual_dns,
            running: false,
            bpf: None,
            abort_handle: None,
        }
    }
}

#[async_trait]
impl Interceptor for EbpfInterceptor {
    async fn start(&mut self) -> Result<mpsc::Receiver<InterceptorEvent>, InterceptorError> {
        if self.running {
            return Err(InterceptorError::AlreadyRunning);
        }

        // 1. Bind local TCP listener
        let listener = TcpListener::bind(SocketAddrV4::new(PROXY_LISTEN_ADDR, 0))
            .await
            .map_err(InterceptorError::Io)?;
        let local_addr = listener.local_addr().map_err(InterceptorError::Io)?;
        let proxy_port = local_addr.port();
        tracing::info!(port = proxy_port, "eBPF interceptor proxy listener bound");

        // 2. Load eBPF programs
        // The eBPF binary is built separately and included at compile time.
        // For development, you can also load from a file path.
        let ebpf_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/bpfel-unknown-none/release/omnilink-ebpf"
        ));

        let mut bpf = Ebpf::load(ebpf_bytes)
            .map_err(|e| InterceptorError::DeviceCreation(e.to_string()))?;

        // 3. Configure: set proxy address and our PID
        {
            let mut config_map: Array<&mut MapData, InterceptConfig> =
                Array::try_from(bpf.map_mut("CONFIG").unwrap())
                    .map_err(|e| InterceptorError::DeviceCreation(e.to_string()))?;

            let config = InterceptConfig {
                proxy_addr: u32::from(PROXY_LISTEN_ADDR).to_be(),
                proxy_port: proxy_port.to_be(),
                _pad: 0,
                pid_self: std::process::id(),
                _pad2: 0,
            };
            config_map
                .set(0, config, 0)
                .map_err(|e| InterceptorError::DeviceCreation(e.to_string()))?;
        }

        // 4. Attach programs to root cgroup
        let cgroup_path = "/sys/fs/cgroup";
        let cgroup_fd = std::fs::File::open(cgroup_path)
            .map_err(|e| InterceptorError::RoutingSetup(format!("open {}: {}", cgroup_path, e)))?;

        // Attach connect4
        let connect4: &mut CgroupSockAddr = bpf
            .program_mut("connect4_intercept")
            .ok_or_else(|| {
                InterceptorError::DeviceCreation("connect4_intercept program not found".into())
            })?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                InterceptorError::DeviceCreation(e.to_string())
            })?;
        connect4
            .load()
            .map_err(|e| InterceptorError::DeviceCreation(e.to_string()))?;
        connect4
            .attach(&cgroup_fd)
            .map_err(|e| InterceptorError::RoutingSetup(e.to_string()))?;

        // Attach sockops
        let sockops: &mut SockOps = bpf
            .program_mut("sockops_record")
            .ok_or_else(|| {
                InterceptorError::DeviceCreation("sockops_record program not found".into())
            })?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                InterceptorError::DeviceCreation(e.to_string())
            })?;
        sockops
            .load()
            .map_err(|e| InterceptorError::DeviceCreation(e.to_string()))?;
        sockops
            .attach(&cgroup_fd)
            .map_err(|e| InterceptorError::RoutingSetup(e.to_string()))?;

        tracing::info!("eBPF programs loaded and attached to cgroup");

        self.bpf = Some(bpf);

        // 5. Accept loop
        let (tx, rx) = mpsc::channel(256);

        let handle = tokio::spawn(async move {
            accept_loop(listener, tx).await;
        });

        self.abort_handle = Some(handle);
        self.running = true;

        Ok(rx)
    }

    async fn stop(&mut self) -> Result<(), InterceptorError> {
        if let Some(handle) = self.abort_handle.take() {
            handle.abort();
        }
        // Dropping the Ebpf object automatically detaches all programs
        self.bpf.take();
        self.running = false;
        tracing::info!("eBPF interceptor stopped");
        Ok(())
    }
}

/// Accept loop: for each accepted connection, query the original destination
/// from the BPF map via SO_ORIGINAL_DST or SO_COOKIE + map lookup.
async fn accept_loop(listener: TcpListener, tx: mpsc::Sender<InterceptorEvent>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let original_dst = get_original_dst(&stream);

                match original_dst {
                    Some(dst) => {
                        let conn = InterceptedConnection {
                            original_dst: dst,
                            src_addr: peer_addr,
                        };
                        if tx
                            .send(InterceptorEvent::NewConnection(conn, stream))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    None => {
                        tracing::warn!(
                            peer = %peer_addr,
                            "could not determine original destination"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "accept error");
            }
        }
    }
}

/// Query SO_ORIGINAL_DST on the accepted socket to get the original destination.
///
/// This relies on the eBPF connect4 program having redirected the connection
/// and the kernel's conntrack (or the eBPF getsockopt program) providing
/// the original address.
fn get_original_dst(stream: &tokio::net::TcpStream) -> Option<SocketAddr> {
    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    // SOL_IP = 0, SO_ORIGINAL_DST = 80
    let ret = unsafe {
        libc::getsockopt(
            fd,
            0,  // SOL_IP
            80, // SO_ORIGINAL_DST
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret == 0 {
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else {
        None
    }
}
