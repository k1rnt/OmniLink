use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::unix::AsyncFd;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use omnilink_core::dns::VirtualDns;

use crate::dns_intercept;
use crate::interceptor::{InterceptedConnection, Interceptor, InterceptorError, InterceptorEvent};
use crate::nat::NatTable;
use crate::packet::{
    self, TransportProtocol,
    recalculate_ipv4_checksum, recalculate_tcp_checksum,
    rewrite_ipv4_dst, rewrite_dst_port,
};

use super::utun::UtunDevice;

/// The local IP address assigned to the utun interface.
const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// MTU for the utun device.
const TUN_MTU: u16 = 1500;

/// macOS interceptor using utun device.
pub struct MacosInterceptor {
    virtual_dns: Arc<VirtualDns>,
    listener_port: u16,
    running: bool,
    /// Proxy server addresses to exclude from interception (prevent routing loops).
    excluded_ips: Vec<Ipv4Addr>,
    abort_handle: Option<tokio::task::JoinHandle<()>>,
}

impl MacosInterceptor {
    pub fn new(virtual_dns: Arc<VirtualDns>, excluded_ips: Vec<Ipv4Addr>) -> Self {
        Self {
            virtual_dns,
            listener_port: 0,
            running: false,
            excluded_ips,
            abort_handle: None,
        }
    }
}

#[async_trait]
impl Interceptor for MacosInterceptor {
    async fn start(&mut self) -> Result<mpsc::Receiver<InterceptorEvent>, InterceptorError> {
        if self.running {
            return Err(InterceptorError::AlreadyRunning);
        }

        // Create utun device (unit=0 for auto-assignment)
        let utun = UtunDevice::create(0)
            .map_err(|e| InterceptorError::DeviceCreation(e.to_string()))?;

        // Configure interface
        let tun_addr = TUN_ADDR.to_string();
        utun.configure(&tun_addr, &tun_addr, TUN_MTU)
            .map_err(|e| InterceptorError::RoutingSetup(e.to_string()))?;

        // Bind a local TCP listener for NAT-redirected connections
        let listener = TcpListener::bind(SocketAddrV4::new(TUN_ADDR, 0))
            .await
            .map_err(InterceptorError::Io)?;
        let local_addr = listener.local_addr().map_err(InterceptorError::Io)?;
        self.listener_port = local_addr.port();
        tracing::info!(port = self.listener_port, "NAT TCP listener bound");

        // Add routes for excluded IPs (proxy servers) BEFORE adding the default route
        // to prevent routing loops
        for ip in &self.excluded_ips {
            let route_cmd = format!(
                "route add -host {} $(route -n get default 2>/dev/null | awk '/gateway:/ {{print $2}}')",
                ip
            );
            let _ = std::process::Command::new("sh")
                .args(["-c", &route_cmd])
                .status();
        }

        // Add default route through utun for all traffic
        utun.add_route("default")
            .map_err(|e| InterceptorError::RoutingSetup(e.to_string()))?;

        // Also route the fake IP range through utun
        utun.add_route("198.18.0.0/15")
            .map_err(|e| InterceptorError::RoutingSetup(e.to_string()))?;

        // Set non-blocking for async I/O
        utun.set_nonblocking()
            .map_err(InterceptorError::Io)?;

        let nat = Arc::new(NatTable::new(Duration::from_secs(30)));
        let (tx, rx) = mpsc::channel(256);

        let virtual_dns = self.virtual_dns.clone();
        let listener_port = self.listener_port;
        let excluded_ips = self.excluded_ips.clone();

        let handle = tokio::spawn(async move {
            let result = run_interceptor_loop(
                utun,
                nat,
                listener,
                tx,
                virtual_dns,
                listener_port,
                excluded_ips,
            )
            .await;

            if let Err(e) = result {
                tracing::error!(error = %e, "interceptor loop error");
            }
        });

        self.abort_handle = Some(handle);
        self.running = true;

        Ok(rx)
    }

    async fn stop(&mut self) -> Result<(), InterceptorError> {
        if let Some(handle) = self.abort_handle.take() {
            handle.abort();
        }

        // Restore routing - remove default route through utun
        let _ = std::process::Command::new("sh")
            .args(["-c", "route delete default"])
            .status();

        // Remove fake IP range route
        let _ = std::process::Command::new("sh")
            .args(["-c", "route delete -net 198.18.0.0/15"])
            .status();

        // Remove excluded IP routes
        for ip in &self.excluded_ips {
            let cmd = format!("route delete -host {}", ip);
            let _ = std::process::Command::new("sh")
                .args(["-c", &cmd])
                .status();
        }

        self.running = false;
        tracing::info!("interceptor stopped, routing restored");

        Ok(())
    }
}

/// Main interceptor loop: reads packets from utun, performs NAT, handles DNS.
async fn run_interceptor_loop(
    utun: UtunDevice,
    nat: Arc<NatTable>,
    listener: TcpListener,
    tx: mpsc::Sender<InterceptorEvent>,
    virtual_dns: Arc<VirtualDns>,
    listener_port: u16,
    excluded_ips: Vec<Ipv4Addr>,
) -> anyhow::Result<()> {
    let fd = utun.fd();
    let async_fd = AsyncFd::new(fd)?;
    let utun = Arc::new(utun);

    // Spawn TCP accept loop
    let nat_accept = nat.clone();
    let tx_accept = tx.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    if let Some(original_dst) = nat_accept.remove(&peer_addr) {
                        let proc_info = crate::process::lookup_process_by_socket(&peer_addr);
                        let conn = InterceptedConnection {
                            original_dst,
                            src_addr: peer_addr,
                            process_name: proc_info.as_ref().map(|p| p.name.clone()),
                            process_path: proc_info.as_ref().map(|p| p.path.clone()),
                        };
                        if tx_accept.send(InterceptorEvent::NewConnection(conn, stream)).await.is_err() {
                            break;
                        }
                    } else {
                        tracing::warn!(peer = %peer_addr, "no NAT entry for accepted connection");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "TCP accept error");
                }
            }
        }
    });

    // Spawn NAT cleanup task
    let nat_cleanup = nat.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            nat_cleanup.cleanup_expired();
        }
    });

    // Packet read/rewrite loop
    let mut buf = vec![0u8; 4 + TUN_MTU as usize];
    let utun_writer = utun.clone();

    loop {
        // Wait for readable
        let mut guard = async_fd.readable().await?;

        match utun.read_packet(&mut buf) {
            Ok((len, af)) => {
                guard.clear_ready();

                // Only process IPv4 (AF_INET = 2)
                if af != 2 {
                    continue;
                }

                let packet_data = &buf[4..4 + len];
                if packet_data.is_empty() {
                    continue;
                }

                let ip_info = match packet::parse_ip_packet(packet_data) {
                    Ok(info) => info,
                    Err(_) => continue,
                };

                // Skip excluded IPs (proxy servers) to prevent routing loops
                if let std::net::IpAddr::V4(dst_v4) = ip_info.dst_addr {
                    if excluded_ips.contains(&dst_v4) {
                        continue;
                    }
                    // Skip packets to our own TUN address
                    if dst_v4 == TUN_ADDR {
                        continue;
                    }
                }

                match ip_info.protocol {
                    TransportProtocol::Tcp => {
                        let transport = match packet::parse_transport(packet_data, &ip_info) {
                            Ok(t) => t,
                            Err(_) => continue,
                        };

                        let original_dst = match ip_info.dst_addr {
                            std::net::IpAddr::V4(v4) => {
                                SocketAddr::V4(SocketAddrV4::new(v4, transport.dst_port))
                            }
                            _ => continue,
                        };

                        let src_addr = match ip_info.src_addr {
                            std::net::IpAddr::V4(v4) => {
                                SocketAddr::V4(SocketAddrV4::new(v4, transport.src_port))
                            }
                            _ => continue,
                        };

                        // Insert NAT mapping
                        nat.insert(src_addr, original_dst);

                        // Rewrite destination to local listener
                        let mut rewritten = packet_data.to_vec();
                        rewrite_ipv4_dst(&mut rewritten, TUN_ADDR);
                        rewrite_dst_port(&mut rewritten, ip_info.header_len, listener_port);
                        recalculate_ipv4_checksum(&mut rewritten);
                        recalculate_tcp_checksum(&mut rewritten);

                        let _ = utun_writer.write_packet(&rewritten);
                    }
                    TransportProtocol::Udp => {
                        let transport = match packet::parse_transport(packet_data, &ip_info) {
                            Ok(t) => t,
                            Err(_) => continue,
                        };

                        // Only intercept DNS (port 53)
                        if !dns_intercept::is_dns_packet(transport.dst_port) {
                            continue;
                        }

                        let udp_payload_offset = ip_info.header_len + 8;
                        if udp_payload_offset >= packet_data.len() {
                            continue;
                        }

                        let dns_data = &packet_data[udp_payload_offset..];
                        if let Some(query) = dns_intercept::parse_dns_query(dns_data) {
                            if let Some(response) = dns_intercept::build_dns_response(&query, &virtual_dns) {
                                let response_packet = dns_intercept::build_dns_udp_response(
                                    packet_data,
                                    ip_info.header_len,
                                    &response,
                                );
                                let _ = utun_writer.write_packet(&response_packet);
                                tracing::debug!(
                                    domain = %query.domain,
                                    "DNS query intercepted"
                                );
                            }
                        }
                    }
                    _ => {
                        // Pass through other protocols (ICMP, etc.)
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                guard.clear_ready();
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "utun read error");
                guard.clear_ready();
            }
        }
    }
}
