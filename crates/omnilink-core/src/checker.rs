use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::net::TcpStream;

use crate::proxy::{ProxyServer, ProxyProtocol};

/// Result of a proxy server connectivity/latency check.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub proxy_name: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Check if a proxy server is reachable and measure latency.
pub async fn check_proxy(server: &ProxyServer, timeout: Duration) -> CheckResult {
    let start = Instant::now();

    match tokio::time::timeout(timeout, TcpStream::connect(server.addr)).await {
        Ok(Ok(stream)) => {
            let latency = start.elapsed().as_millis() as u64;
            drop(stream);

            // For SOCKS5, try a handshake to verify it's actually a SOCKS5 server
            let verified = match server.protocol {
                ProxyProtocol::Socks5 => verify_socks5(server, timeout).await,
                ProxyProtocol::Http | ProxyProtocol::Https => Ok(()),
            };

            match verified {
                Ok(()) => CheckResult {
                    proxy_name: server.name.clone(),
                    reachable: true,
                    latency_ms: Some(latency),
                    error: None,
                },
                Err(e) => CheckResult {
                    proxy_name: server.name.clone(),
                    reachable: false,
                    latency_ms: Some(latency),
                    error: Some(format!("protocol verification failed: {}", e)),
                },
            }
        }
        Ok(Err(e)) => CheckResult {
            proxy_name: server.name.clone(),
            reachable: false,
            latency_ms: None,
            error: Some(format!("connection failed: {}", e)),
        },
        Err(_) => CheckResult {
            proxy_name: server.name.clone(),
            reachable: false,
            latency_ms: None,
            error: Some("connection timed out".to_string()),
        },
    }
}

async fn verify_socks5(server: &ProxyServer, timeout: Duration) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(server.addr))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;

    // Send SOCKS5 greeting with no-auth method
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| e.to_string())?;

    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| e.to_string())?;

    if resp[0] != 0x05 {
        return Err(format!("not a SOCKS5 server (version byte: 0x{:02x})", resp[0]));
    }

    Ok(())
}

/// Check all proxies and return results.
pub async fn check_all(
    servers: &[ProxyServer],
    timeout: Duration,
) -> Vec<CheckResult> {
    let mut handles = Vec::new();

    for server in servers {
        let server = server.clone();
        handles.push(tokio::spawn(async move {
            check_proxy(&server, timeout).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    results
}
