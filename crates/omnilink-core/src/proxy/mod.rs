pub mod chain;
pub mod http;
pub mod socks4;
pub mod socks5;

use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("protocol error: {0}")]
    ProtocolError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported command: {0}")]
    UnsupportedCommand(u8),
    #[error("address type not supported")]
    AddressTypeNotSupported,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProxyProtocol {
    Socks4,
    Socks4a,
    Socks5,
    Http,
    Https,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyServer {
    pub name: String,
    pub protocol: ProxyProtocol,
    pub addr: SocketAddr,
    pub auth: Option<ProxyAuth>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// Target address for proxy connections.
#[derive(Debug, Clone)]
pub enum ProxyDestination {
    /// IP address and port.
    SocketAddr(SocketAddr),
    /// Domain name and port (for remote DNS resolution).
    Domain(String, u16),
}

impl std::fmt::Display for ProxyDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyDestination::SocketAddr(addr) => write!(f, "{}", addr),
            ProxyDestination::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}
