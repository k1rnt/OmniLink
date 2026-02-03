//! OmniLink WFP user-mode service.
//!
//! Communicates with the WFP callout driver via IOCTL to:
//! 1. Configure the driver with the local proxy address/port
//! 2. Accept redirected connections and query original destinations
//! 3. Forward traffic through the proxy chain

mod wfp_client;

use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::process;

use anyhow::{Context, Result};
use wfp_client::{DriverConfig, WfpClient};

fn main() -> Result<()> {
    let proxy_port: u16 = 10800; // TODO: read from config
    let proxy_addr = Ipv4Addr::new(127, 0, 0, 1);

    println!("[omnilink-wfp] Opening driver handle...");
    let client = WfpClient::open().context("Is the WFP driver loaded?")?;

    // Configure the driver
    let config = DriverConfig {
        proxy_addr: u32::from(proxy_addr),
        proxy_port: proxy_port,
        proxy_pid: process::id(),
        enabled: 1,
    };
    client.set_config(&config)?;
    println!("[omnilink-wfp] Driver configured: proxy={}:{}, pid={}", proxy_addr, proxy_port, process::id());

    // Bind the local proxy listener
    let listener = TcpListener::bind(SocketAddrV4::new(proxy_addr, proxy_port))
        .context("Failed to bind proxy listener")?;
    println!("[omnilink-wfp] Listening on {}:{}", proxy_addr, proxy_port);

    // Accept redirected connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer = stream.peer_addr().ok();
                if let Some(peer) = peer {
                    // Query original destination from the driver's NAT table
                    if let Ok(Some((orig_addr, orig_port))) = client.get_original_dst(
                        u32::from(match peer.ip() {
                            std::net::IpAddr::V4(v4) => v4,
                            _ => continue,
                        }),
                        peer.port(),
                    ) {
                        let orig_ip = Ipv4Addr::from(orig_addr);
                        println!(
                            "[omnilink-wfp] Connection from {} -> original dest {}:{}",
                            peer, orig_ip, orig_port
                        );
                        // TODO: Forward through proxy chain via omnilink-core
                    }
                }
            }
            Err(e) => {
                eprintln!("[omnilink-wfp] Accept error: {}", e);
            }
        }
    }

    Ok(())
}
