use std::net::SocketAddr;

use async_trait::async_trait;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

#[derive(Debug, Error)]
pub enum InterceptorError {
    #[error("interceptor not supported on this platform")]
    NotSupported,
    #[error("failed to create TUN/utun device: {0}")]
    DeviceCreation(String),
    #[error("failed to configure routing: {0}")]
    RoutingSetup(String),
    #[error("interceptor already running")]
    AlreadyRunning,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Information about an intercepted connection.
#[derive(Debug, Clone)]
pub struct InterceptedConnection {
    /// The original destination address the application was trying to reach.
    pub original_dst: SocketAddr,
    /// The source address of the connecting application.
    pub src_addr: SocketAddr,
}

/// Events emitted by the interceptor.
pub enum InterceptorEvent {
    /// A new TCP connection was intercepted.
    NewConnection(InterceptedConnection, TcpStream),
}

/// Trait for OS-level traffic interception.
#[async_trait]
pub trait Interceptor: Send + Sync {
    /// Start intercepting traffic.
    /// Returns a receiver for intercepted connection events.
    async fn start(&mut self) -> Result<mpsc::Receiver<InterceptorEvent>, InterceptorError>;

    /// Stop intercepting and restore network state.
    async fn stop(&mut self) -> Result<(), InterceptorError>;
}
