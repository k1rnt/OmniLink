use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::TcpStream;

use super::{connect_with_timeout, ProxyDestination, ProxyError, ProxyProtocol, ProxyServer, DEFAULT_CONNECT_TIMEOUT_SECS};
use crate::config::{ChainConfig, ChainMode};

/// Relay that connects through a proxy chain or selects a proxy based on chain mode.
pub struct ChainRelay {
    chains: HashMap<String, ChainConfig>,
    proxies: HashMap<String, ProxyServer>,
    /// Round-robin counter per chain name.
    rr_counters: HashMap<String, AtomicUsize>,
}

impl ChainRelay {
    pub fn new(
        chains: Vec<ChainConfig>,
        proxies: HashMap<String, ProxyServer>,
    ) -> Self {
        let mut rr_counters = HashMap::new();
        let mut chain_map = HashMap::new();
        for chain in chains {
            rr_counters.insert(chain.name.clone(), AtomicUsize::new(0));
            chain_map.insert(chain.name.clone(), chain);
        }
        Self {
            chains: chain_map,
            proxies,
            rr_counters,
        }
    }

    /// Check if a name refers to a chain (vs. a single proxy).
    pub fn is_chain(&self, name: &str) -> bool {
        self.chains.contains_key(name)
    }

    /// Connect to the destination through a named proxy or chain.
    pub async fn connect(
        &self,
        name: &str,
        dest: &ProxyDestination,
    ) -> Result<TcpStream, ProxyError> {
        if let Some(chain) = self.chains.get(name) {
            self.connect_chain(chain, dest).await
        } else if let Some(server) = self.proxies.get(name) {
            connect_single(server, dest).await
        } else {
            Err(ProxyError::ConnectionFailed(format!(
                "proxy or chain '{}' not found",
                name
            )))
        }
    }

    async fn connect_chain(
        &self,
        chain: &ChainConfig,
        dest: &ProxyDestination,
    ) -> Result<TcpStream, ProxyError> {
        match chain.mode {
            ChainMode::Strict => self.connect_strict(chain, dest).await,
            ChainMode::Failover => self.connect_failover(chain, dest).await,
            ChainMode::RoundRobin => self.connect_round_robin(chain, dest).await,
            ChainMode::Random => self.connect_random(chain, dest).await,
        }
    }

    /// Strict: chain all proxies in order. Each proxy connects through the previous one.
    async fn connect_strict(
        &self,
        chain: &ChainConfig,
        dest: &ProxyDestination,
    ) -> Result<TcpStream, ProxyError> {
        if chain.proxies.is_empty() {
            return Err(ProxyError::ConnectionFailed("empty chain".to_string()));
        }

        if chain.proxies.len() == 1 {
            let server = self.get_proxy(&chain.proxies[0])?;
            return connect_single(server, dest).await;
        }

        // Connect to the first proxy directly
        let first_server = self.get_proxy(&chain.proxies[0])?;
        let mut stream = connect_with_timeout(first_server.addr, DEFAULT_CONNECT_TIMEOUT_SECS).await?;

        // For each intermediate proxy, establish a tunnel through the current connection
        // to the next proxy's address
        for i in 0..chain.proxies.len() - 1 {
            let current_server = self.get_proxy(&chain.proxies[i])?;
            let next_target = if i + 1 < chain.proxies.len() - 1 {
                // Intermediate: tunnel to the next proxy's address
                let next_server = self.get_proxy(&chain.proxies[i + 1])?;
                ProxyDestination::SocketAddr(next_server.addr)
            } else {
                // Last hop: tunnel to the final destination
                dest.clone()
            };

            stream = tunnel_through(stream, current_server, &next_target).await?;
        }

        Ok(stream)
    }

    /// Failover: try each proxy in order, use the first one that works.
    async fn connect_failover(
        &self,
        chain: &ChainConfig,
        dest: &ProxyDestination,
    ) -> Result<TcpStream, ProxyError> {
        let mut last_error = None;

        for proxy_name in &chain.proxies {
            let server = match self.get_proxy(proxy_name) {
                Ok(s) => s,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };

            match connect_single(server, dest).await {
                Ok(stream) => {
                    tracing::info!(proxy = %proxy_name, "failover: connected via proxy");
                    return Ok(stream);
                }
                Err(e) => {
                    tracing::warn!(proxy = %proxy_name, error = %e, "failover: proxy failed, trying next");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            ProxyError::ConnectionFailed("all proxies in failover chain failed".to_string())
        }))
    }

    /// Round-robin: distribute connections across proxies.
    async fn connect_round_robin(
        &self,
        chain: &ChainConfig,
        dest: &ProxyDestination,
    ) -> Result<TcpStream, ProxyError> {
        if chain.proxies.is_empty() {
            return Err(ProxyError::ConnectionFailed("empty chain".to_string()));
        }

        let counter = self
            .rr_counters
            .get(&chain.name)
            .expect("rr_counter missing");
        let idx = counter.fetch_add(1, Ordering::Relaxed) % chain.proxies.len();
        let proxy_name = &chain.proxies[idx];
        let server = self.get_proxy(proxy_name)?;

        tracing::debug!(proxy = %proxy_name, index = idx, "round-robin: selected proxy");
        connect_single(server, dest).await
    }

    /// Random: randomly select a proxy.
    async fn connect_random(
        &self,
        chain: &ChainConfig,
        dest: &ProxyDestination,
    ) -> Result<TcpStream, ProxyError> {
        if chain.proxies.is_empty() {
            return Err(ProxyError::ConnectionFailed("empty chain".to_string()));
        }

        // Simple pseudo-random using current time nanos
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as usize;
        let idx = nanos % chain.proxies.len();
        let proxy_name = &chain.proxies[idx];
        let server = self.get_proxy(proxy_name)?;

        tracing::debug!(proxy = %proxy_name, index = idx, "random: selected proxy");
        connect_single(server, dest).await
    }

    fn get_proxy(&self, name: &str) -> Result<&ProxyServer, ProxyError> {
        self.proxies
            .get(name)
            .ok_or_else(|| ProxyError::ConnectionFailed(format!("proxy '{}' not found", name)))
    }
}

/// Connect through a single proxy to the destination.
pub async fn connect_single(
    server: &ProxyServer,
    dest: &ProxyDestination,
) -> Result<TcpStream, ProxyError> {
    match server.protocol {
        ProxyProtocol::Socks4 => super::socks4::connect(server, dest).await,
        ProxyProtocol::Socks4a => super::socks4::connect_4a(server, dest).await,
        ProxyProtocol::Socks5 => super::socks5::connect(server, dest).await,
        ProxyProtocol::Http | ProxyProtocol::Https => super::http::connect(server, dest).await,
        ProxyProtocol::SshTunnel => super::ssh::connect(server, dest).await,
    }
}

/// Establish a tunnel through an already-connected proxy stream.
/// This performs the proxy handshake on an existing connection.
async fn tunnel_through(
    mut stream: TcpStream,
    server: &ProxyServer,
    dest: &ProxyDestination,
) -> Result<TcpStream, ProxyError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    match server.protocol {
        ProxyProtocol::Socks4 | ProxyProtocol::Socks4a => {
            return Err(ProxyError::ProtocolError(
                "SOCKS4/4a cannot be used as intermediate proxy in strict chains".to_string(),
            ));
        }
        ProxyProtocol::SshTunnel => {
            return Err(ProxyError::ProtocolError(
                "SSH tunnel cannot be used as intermediate proxy in strict chains".to_string(),
            ));
        }
        ProxyProtocol::Socks5 => {
            // SOCKS5 handshake on existing stream
            let methods: Vec<u8> = if server.auth.is_some() {
                vec![0x00, 0x02]
            } else {
                vec![0x00]
            };
            let mut buf = vec![0x05, methods.len() as u8];
            buf.extend_from_slice(&methods);
            stream.write_all(&buf).await?;

            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp[0] != 0x05 {
                return Err(ProxyError::ProtocolError("bad SOCKS5 version".to_string()));
            }

            if resp[1] == 0x02 {
                if let Some(auth) = &server.auth {
                    let mut auth_buf = vec![0x01];
                    auth_buf.push(auth.username.len() as u8);
                    auth_buf.extend_from_slice(auth.username.as_bytes());
                    auth_buf.push(auth.password.len() as u8);
                    auth_buf.extend_from_slice(auth.password.as_bytes());
                    stream.write_all(&auth_buf).await?;

                    let mut auth_resp = [0u8; 2];
                    stream.read_exact(&mut auth_resp).await?;
                    if auth_resp[1] != 0x00 {
                        return Err(ProxyError::AuthenticationFailed);
                    }
                } else {
                    return Err(ProxyError::AuthenticationFailed);
                }
            }

            // Connect request
            let mut connect_buf = vec![0x05, 0x01, 0x00];
            match dest {
                ProxyDestination::SocketAddr(addr) => match addr {
                    std::net::SocketAddr::V4(v4) => {
                        connect_buf.push(0x01);
                        connect_buf.extend_from_slice(&v4.ip().octets());
                        connect_buf.extend_from_slice(&v4.port().to_be_bytes());
                    }
                    std::net::SocketAddr::V6(v6) => {
                        connect_buf.push(0x04);
                        connect_buf.extend_from_slice(&v6.ip().octets());
                        connect_buf.extend_from_slice(&v6.port().to_be_bytes());
                    }
                },
                ProxyDestination::Domain(domain, port) => {
                    connect_buf.push(0x03);
                    connect_buf.push(domain.len() as u8);
                    connect_buf.extend_from_slice(domain.as_bytes());
                    connect_buf.extend_from_slice(&port.to_be_bytes());
                }
            }
            stream.write_all(&connect_buf).await?;

            let mut header = [0u8; 4];
            stream.read_exact(&mut header).await?;
            if header[1] != 0x00 {
                return Err(ProxyError::ConnectionFailed(format!(
                    "SOCKS5 reply: 0x{:02x}",
                    header[1]
                )));
            }

            // Consume bound address
            match header[3] {
                0x01 => {
                    let mut addr = [0u8; 6];
                    stream.read_exact(&mut addr).await?;
                }
                0x04 => {
                    let mut addr = [0u8; 18];
                    stream.read_exact(&mut addr).await?;
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    stream.read_exact(&mut len).await?;
                    let mut domain = vec![0u8; len[0] as usize + 2];
                    stream.read_exact(&mut domain).await?;
                }
                _ => return Err(ProxyError::AddressTypeNotSupported),
            }

            Ok(stream)
        }
        ProxyProtocol::Http | ProxyProtocol::Https => {
            let target = match dest {
                ProxyDestination::SocketAddr(addr) => addr.to_string(),
                ProxyDestination::Domain(domain, port) => format!("{}:{}", domain, port),
            };

            let mut request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", target, target);
            if let Some(auth) = &server.auth {
                let credentials =
                    super::http::base64_encode(&format!("{}:{}", auth.username, auth.password));
                request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", credentials));
            }
            request.push_str("\r\n");

            stream.write_all(request.as_bytes()).await?;

            // Read response
            use tokio::io::AsyncBufReadExt;
            let mut reader = tokio::io::BufReader::new(&mut stream);
            let mut status_line = String::new();
            reader.read_line(&mut status_line).await?;

            let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
            if parts.len() < 2 {
                return Err(ProxyError::ProtocolError("bad HTTP response".to_string()));
            }
            let code: u16 = parts[1]
                .parse()
                .map_err(|_| ProxyError::ProtocolError("bad status code".to_string()))?;
            if !(200..300).contains(&code) {
                return Err(ProxyError::ConnectionFailed(format!("HTTP {}", code)));
            }

            // Consume headers
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).await?;
                if line.trim().is_empty() {
                    break;
                }
            }
            drop(reader);

            Ok(stream)
        }
    }
}
