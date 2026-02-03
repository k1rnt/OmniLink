use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use omnilink_core::dns::VirtualDns;

use crate::device::{TunConfig, TunDevice};
use crate::dns_intercept;
use crate::interceptor::{InterceptedConnection, Interceptor, InterceptorError, InterceptorEvent};
use crate::nat::NatTable;
use crate::packet::{
    self, TransportProtocol,
    recalculate_ipv4_checksum, recalculate_tcp_checksum,
    rewrite_ipv4_dst, rewrite_dst_port,
};

const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const TUN_MTU: u16 = 1500;

/// Linux interceptor using the existing TunDevice.
pub struct LinuxInterceptor {
    virtual_dns: Arc<VirtualDns>,
    listener_port: u16,
    running: bool,
    excluded_ips: Vec<Ipv4Addr>,
    abort_handle: Option<tokio::task::JoinHandle<()>>,
    tun_name: String,
}

impl LinuxInterceptor {
    pub fn new(virtual_dns: Arc<VirtualDns>, excluded_ips: Vec<Ipv4Addr>) -> Self {
        Self {
            virtual_dns,
            listener_port: 0,
            running: false,
            excluded_ips,
            abort_handle: None,
            tun_name: "omni0".to_string(),
        }
    }
}

#[async_trait]
impl Interceptor for LinuxInterceptor {
    async fn start(&mut self) -> Result<mpsc::Receiver<InterceptorEvent>, InterceptorError> {
        if self.running {
            return Err(InterceptorError::AlreadyRunning);
        }

        let config = TunConfig {
            name: self.tun_name.clone(),
            address: TUN_ADDR,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: TUN_MTU,
        };

        let tun = TunDevice::create(config)
            .map_err(|e| InterceptorError::DeviceCreation(e.to_string()))?;

        // Bind local TCP listener
        let listener = TcpListener::bind(SocketAddrV4::new(TUN_ADDR, 0))
            .await
            .map_err(InterceptorError::Io)?;
        let local_addr = listener.local_addr().map_err(InterceptorError::Io)?;
        self.listener_port = local_addr.port();

        // Add excluded IP routes via default gateway to prevent routing loops
        for ip in &self.excluded_ips {
            let cmd = format!(
                "ip route add {}/32 $(ip route show default | awk '{{print $3, $4, $5}}')",
                ip
            );
            let _ = std::process::Command::new("sh")
                .args(["-c", &cmd])
                .status();
        }

        // Add default route through TUN
        let route_cmd = format!(
            "ip route add default dev {} metric 10",
            self.tun_name
        );
        let _ = std::process::Command::new("sh")
            .args(["-c", &route_cmd])
            .status();

        // Route fake IP range
        let fake_route_cmd = format!(
            "ip route add 198.18.0.0/15 dev {}",
            self.tun_name
        );
        let _ = std::process::Command::new("sh")
            .args(["-c", &fake_route_cmd])
            .status();

        let nat = Arc::new(NatTable::new(Duration::from_secs(30)));
        let (tx, rx) = mpsc::channel(256);

        let virtual_dns = self.virtual_dns.clone();
        let listener_port = self.listener_port;
        let excluded_ips = self.excluded_ips.clone();

        let handle = tokio::spawn(async move {
            let result = run_linux_interceptor_loop(
                tun,
                nat,
                listener,
                tx,
                virtual_dns,
                listener_port,
                excluded_ips,
            )
            .await;

            if let Err(e) = result {
                tracing::error!(error = %e, "Linux interceptor loop error");
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

        // Remove default route through TUN
        let cmd = format!("ip route delete default dev {} metric 10", self.tun_name);
        let _ = std::process::Command::new("sh")
            .args(["-c", &cmd])
            .status();

        // Remove fake IP range route
        let cmd = format!("ip route delete 198.18.0.0/15 dev {}", self.tun_name);
        let _ = std::process::Command::new("sh")
            .args(["-c", &cmd])
            .status();

        // Remove excluded IP routes
        for ip in &self.excluded_ips {
            let cmd = format!("ip route delete {}/32", ip);
            let _ = std::process::Command::new("sh")
                .args(["-c", &cmd])
                .status();
        }

        self.running = false;
        tracing::info!("Linux interceptor stopped, routing restored");

        Ok(())
    }
}

async fn run_linux_interceptor_loop(
    tun: TunDevice,
    nat: Arc<NatTable>,
    listener: TcpListener,
    tx: mpsc::Sender<InterceptorEvent>,
    virtual_dns: Arc<VirtualDns>,
    listener_port: u16,
    excluded_ips: Vec<Ipv4Addr>,
) -> anyhow::Result<()> {
    // Spawn TCP accept loop
    let nat_accept = nat.clone();
    let tx_accept = tx.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    if let Some(original_dst) = nat_accept.remove(&peer_addr) {
                        let conn = InterceptedConnection {
                            original_dst,
                            src_addr: peer_addr,
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

    // NAT cleanup
    let nat_cleanup = nat.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            nat_cleanup.cleanup_expired();
        }
    });

    // Packet loop (blocking read in a blocking task)
    let mut buf = vec![0u8; TUN_MTU as usize];
    loop {
        match tun.read_packet(&mut buf) {
            Ok(len) => {
                let packet_data = &buf[..len];
                if packet_data.is_empty() {
                    continue;
                }

                let ip_info = match packet::parse_ip_packet(packet_data) {
                    Ok(info) if info.version == 4 => info,
                    _ => continue,
                };

                if let std::net::IpAddr::V4(dst_v4) = ip_info.dst_addr {
                    if excluded_ips.contains(&dst_v4) || dst_v4 == TUN_ADDR {
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

                        nat.insert(src_addr, original_dst);

                        let mut rewritten = packet_data.to_vec();
                        rewrite_ipv4_dst(&mut rewritten, TUN_ADDR);
                        rewrite_dst_port(&mut rewritten, ip_info.header_len, listener_port);
                        recalculate_ipv4_checksum(&mut rewritten);
                        recalculate_tcp_checksum(&mut rewritten);

                        let _ = tun.write_packet(&rewritten);
                    }
                    TransportProtocol::Udp => {
                        let transport = match packet::parse_transport(packet_data, &ip_info) {
                            Ok(t) => t,
                            Err(_) => continue,
                        };

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
                                let _ = tun.write_packet(&response_packet);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    tracing::error!(error = %e, "TUN read error");
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }
}
