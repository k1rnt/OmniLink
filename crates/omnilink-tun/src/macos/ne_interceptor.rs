//! Network Extension interceptor for macOS.
//!
//! This interceptor communicates with the NETransparentProxyProvider system extension
//! via a Unix domain socket. The extension intercepts network traffic at the kernel level
//! and forwards flow metadata to this Rust backend for routing decisions.

use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use omnilink_core::dns::VirtualDns;
use omnilink_core::proxy::chain::ChainRelay;
use omnilink_core::proxy::ProxyDestination;
use omnilink_core::rule::{Action, MatchContext, RuleEngine};
use omnilink_core::session::SessionManager;

use crate::interceptor::{Interceptor, InterceptorError, InterceptorEvent};

/// Default socket path for IPC with the Network Extension.
const SOCKET_PATH: &str = "/tmp/omnilink.sock";

/// Request messages from the Network Extension (Swift) to the Rust backend.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NERequest {
    /// Request routing decision for a new flow.
    Routing {
        flow_id: String,
        app_id: String,
        host: String,
        port: u16,
        protocol: String,
    },
    /// Request to establish outbound connection for a flow.
    Connect {
        flow_id: String,
        host: String,
        port: u16,
        proxy_name: Option<String>,
    },
    /// Relay data from the intercepted flow.
    Data {
        flow_id: String,
        direction: String,
        data: String, // base64 encoded
    },
    /// Notify that a flow has been closed.
    Close { flow_id: String },
}

/// Response messages from the Rust backend to the Network Extension.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NEResponse {
    /// Routing decision response.
    Routing {
        flow_id: String,
        action: String,
        proxy_name: Option<String>,
    },
    /// Connection establishment response.
    Connect {
        flow_id: String,
        success: bool,
        error: Option<String>,
    },
    /// Data relay response (with inbound data if any).
    Data {
        flow_id: String,
        direction: String,
        data: String, // base64 encoded
    },
}

/// State for an active flow being handled by the backend.
struct FlowState {
    /// Channel to send outbound data to the proxy connection.
    outbound_tx: mpsc::Sender<Vec<u8>>,
    /// Channel to receive inbound data from the proxy connection.
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    /// Cancellation token to stop the flow relay task.
    cancel: CancellationToken,
}

/// Network Extension interceptor that communicates via Unix domain socket.
pub struct NEInterceptor {
    rule_engine: Arc<RuleEngine>,
    chain_relay: Arc<ChainRelay>,
    virtual_dns: Arc<VirtualDns>,
    session_manager: Arc<SessionManager>,
    cancel_token: CancellationToken,
    flows: Arc<DashMap<String, FlowState>>,
    socket_path: String,
}

impl NEInterceptor {
    /// Create a new Network Extension interceptor.
    pub fn new(
        rule_engine: Arc<RuleEngine>,
        chain_relay: Arc<ChainRelay>,
        virtual_dns: Arc<VirtualDns>,
        session_manager: Arc<SessionManager>,
    ) -> Self {
        Self {
            rule_engine,
            chain_relay,
            virtual_dns,
            session_manager,
            cancel_token: CancellationToken::new(),
            flows: Arc::new(DashMap::new()),
            socket_path: SOCKET_PATH.to_string(),
        }
    }

    /// Create with a custom socket path (for testing).
    pub fn with_socket_path(mut self, path: &str) -> Self {
        self.socket_path = path.to_string();
        self
    }
}

#[async_trait]
impl Interceptor for NEInterceptor {
    async fn start(&mut self) -> Result<mpsc::Receiver<InterceptorEvent>, InterceptorError> {
        // Remove existing socket file
        let _ = std::fs::remove_file(&self.socket_path);

        // Create Unix socket listener
        let listener = UnixListener::bind(&self.socket_path)
            .map_err(|e| InterceptorError::DeviceCreation(format!("failed to bind socket: {}", e)))?;

        // Set socket permissions so the Network Extension can connect
        std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o666))
            .map_err(|e| InterceptorError::DeviceCreation(format!("failed to set socket permissions: {}", e)))?;

        tracing::info!(path = %self.socket_path, "NE socket server started");

        let (event_tx, event_rx) = mpsc::channel(256);
        let cancel = self.cancel_token.clone();
        let rule_engine = self.rule_engine.clone();
        let chain_relay = self.chain_relay.clone();
        let virtual_dns = self.virtual_dns.clone();
        let session_manager = self.session_manager.clone();
        let flows = self.flows.clone();

        // Spawn the accept loop
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::info!("NE socket server shutting down");
                        break;
                    }
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _addr)) => {
                                tracing::debug!("NE extension connected");
                                let re = rule_engine.clone();
                                let cr = chain_relay.clone();
                                let vd = virtual_dns.clone();
                                let sm = session_manager.clone();
                                let fl = flows.clone();
                                let tx = event_tx.clone();

                                tokio::spawn(async move {
                                    if let Err(e) = handle_client(stream, re, cr, vd, sm, fl, tx).await {
                                        tracing::warn!(error = %e, "NE client handler error");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "NE accept error");
                            }
                        }
                    }
                }
            }
        });

        Ok(event_rx)
    }

    async fn stop(&mut self) -> Result<(), InterceptorError> {
        self.cancel_token.cancel();

        // Cancel all active flows
        for entry in self.flows.iter() {
            entry.value().cancel.cancel();
        }
        self.flows.clear();

        // Remove socket file
        let _ = std::fs::remove_file(&self.socket_path);

        tracing::info!("NE interceptor stopped");
        Ok(())
    }
}

/// Handle a connected NE extension client.
async fn handle_client(
    mut stream: UnixStream,
    rule_engine: Arc<RuleEngine>,
    chain_relay: Arc<ChainRelay>,
    virtual_dns: Arc<VirtualDns>,
    session_manager: Arc<SessionManager>,
    flows: Arc<DashMap<String, FlowState>>,
    event_tx: mpsc::Sender<InterceptorEvent>,
) -> anyhow::Result<()> {
    loop {
        // Read length prefix (4 bytes big-endian)
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            // Connection closed
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;

        if len == 0 || len > 1024 * 1024 {
            // Invalid length
            tracing::warn!(len, "invalid message length");
            break;
        }

        // Read JSON payload
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await?;

        let request: NERequest = match serde_json::from_slice(&payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse NE request");
                continue;
            }
        };

        let response = match request {
            NERequest::Routing {
                flow_id,
                app_id,
                host,
                port,
                protocol: _,
            } => {
                handle_routing(&rule_engine, &virtual_dns, flow_id, app_id, host, port)
            }
            NERequest::Connect {
                flow_id,
                host,
                port,
                proxy_name,
            } => {
                handle_connect(
                    &chain_relay,
                    &session_manager,
                    &flows,
                    &event_tx,
                    flow_id,
                    host,
                    port,
                    proxy_name,
                )
                .await
            }
            NERequest::Data {
                flow_id,
                direction: _,
                data,
            } => handle_data(&flows, flow_id, data).await,
            NERequest::Close { flow_id } => {
                handle_close(&flows, flow_id);
                // No response needed for close
                continue;
            }
        };

        // Send response
        let json = serde_json::to_vec(&response)?;
        let len_bytes = (json.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&json).await?;
    }

    Ok(())
}

/// Handle a routing decision request.
fn handle_routing(
    rule_engine: &RuleEngine,
    virtual_dns: &VirtualDns,
    flow_id: String,
    app_id: String,
    host: String,
    port: u16,
) -> NEResponse {
    // Resolve fake IP to domain if applicable
    let (dest_domain, dest_ip) = if let Ok(ip) = host.parse::<IpAddr>() {
        // Check if this is a fake IP from our virtual DNS
        if let Some(domain) = virtual_dns.lookup(ip) {
            (Some(domain), Some(ip))
        } else {
            (None, Some(ip))
        }
    } else {
        (Some(host.clone()), None)
    };

    let ctx = MatchContext {
        process_name: Some(app_id.clone()),
        process_path: None,
        process_user: None,
        dest_domain,
        dest_ip,
        dest_port: port,
    };

    let action = rule_engine.evaluate(&ctx);

    tracing::debug!(
        flow_id = %flow_id,
        app = %app_id,
        host = %host,
        port = port,
        action = ?action,
        "routing decision"
    );

    NEResponse::Routing {
        flow_id,
        action: match &action {
            Action::Direct => "direct".to_string(),
            Action::Proxy(_) => "proxy".to_string(),
            Action::Block => "block".to_string(),
        },
        proxy_name: match action {
            Action::Proxy(name) => Some(name),
            _ => None,
        },
    }
}

/// Handle a connect request - establish outbound connection.
async fn handle_connect(
    chain_relay: &ChainRelay,
    session_manager: &SessionManager,
    flows: &DashMap<String, FlowState>,
    _event_tx: &mpsc::Sender<InterceptorEvent>,
    flow_id: String,
    host: String,
    port: u16,
    proxy_name: Option<String>,
) -> NEResponse {
    let dest = if let Ok(ip) = host.parse::<IpAddr>() {
        ProxyDestination::SocketAddr(SocketAddr::new(ip, port))
    } else {
        ProxyDestination::Domain(host.clone(), port)
    };

    let result: Result<TcpStream, String> = match &proxy_name {
        Some(chain_name) => {
            match chain_relay.connect(chain_name, &dest).await {
                Ok(stream) => Ok(stream),
                Err(e) => Err(e.to_string()),
            }
        }
        None => {
            // Direct connection
            let addr = format!("{}:{}", host, port);
            TcpStream::connect(&addr)
                .await
                .map_err(|e| e.to_string())
        }
    };

    // Get destination string for session tracking
    let dest_str = match &dest {
        ProxyDestination::SocketAddr(addr) => addr.to_string(),
        ProxyDestination::Domain(domain, port) => format!("{}:{}", domain, port),
    };

    // Determine action for session
    let action = if proxy_name.is_some() {
        Action::Proxy(proxy_name.clone().unwrap())
    } else {
        Action::Direct
    };

    match result {
        Ok(stream) => {
            // Create bidirectional channels for data relay
            let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(256);
            let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(256);
            let cancel = CancellationToken::new();

            // Store flow state
            flows.insert(
                flow_id.clone(),
                FlowState {
                    outbound_tx,
                    inbound_rx,
                    cancel: cancel.clone(),
                },
            );

            // Register session
            let session_id = session_manager.create_session(
                dest_str,
                &action,
                proxy_name.clone(),
            );

            // Spawn relay task
            let flow_id_clone = flow_id.clone();
            let cancel_clone = cancel.clone();
            tokio::spawn(async move {
                relay_flow(
                    stream,
                    &mut outbound_rx,
                    inbound_tx,
                    cancel_clone,
                )
                .await;
                tracing::debug!(flow_id = %flow_id_clone, "flow relay ended");
            });

            tracing::debug!(flow_id = %flow_id, session_id = session_id, "flow connected");

            NEResponse::Connect {
                flow_id,
                success: true,
                error: None,
            }
        }
        Err(e) => {
            tracing::warn!(flow_id = %flow_id, error = %e, "connect failed");
            NEResponse::Connect {
                flow_id,
                success: false,
                error: Some(e),
            }
        }
    }
}

/// Handle a data relay request.
async fn handle_data(
    flows: &DashMap<String, FlowState>,
    flow_id: String,
    data: String,
) -> NEResponse {
    let bytes = match BASE64.decode(&data) {
        Ok(b) => b,
        Err(e) => {
            return NEResponse::Data {
                flow_id,
                direction: "error".to_string(),
                data: format!("decode error: {}", e),
            };
        }
    };

    if let Some(flow) = flows.get(&flow_id) {
        // Send outbound data
        if flow.outbound_tx.send(bytes).await.is_err() {
            return NEResponse::Data {
                flow_id,
                direction: "error".to_string(),
                data: "flow closed".to_string(),
            };
        }
    } else {
        return NEResponse::Data {
            flow_id,
            direction: "error".to_string(),
            data: "unknown flow".to_string(),
        };
    }

    // Try to receive inbound data
    if let Some(mut flow) = flows.get_mut(&flow_id) {
        match flow.inbound_rx.try_recv() {
            Ok(inbound_data) => {
                return NEResponse::Data {
                    flow_id,
                    direction: "inbound".to_string(),
                    data: BASE64.encode(&inbound_data),
                };
            }
            Err(_) => {
                // No data available yet
            }
        }
    }

    NEResponse::Data {
        flow_id,
        direction: "ok".to_string(),
        data: String::new(),
    }
}

/// Handle a flow close notification.
fn handle_close(flows: &DashMap<String, FlowState>, flow_id: String) {
    if let Some((_, flow)) = flows.remove(&flow_id) {
        flow.cancel.cancel();
        tracing::debug!(flow_id = %flow_id, "flow closed");
    }
}

/// Relay data between the NE extension and the outbound connection.
async fn relay_flow(
    mut stream: TcpStream,
    outbound_rx: &mut mpsc::Receiver<Vec<u8>>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
) {
    let (mut read_half, mut write_half) = stream.split();
    let mut buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            // Outbound: NE extension -> remote server
            Some(data) = outbound_rx.recv() => {
                if write_half.write_all(&data).await.is_err() {
                    break;
                }
            }
            // Inbound: remote server -> NE extension
            result = read_half.read(&mut buf) => {
                match result {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if inbound_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let req = NERequest::Routing {
            flow_id: "test-123".to_string(),
            app_id: "com.example.app".to_string(),
            host: "example.com".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"routing\""));
        assert!(json.contains("\"flow_id\":\"test-123\""));

        let parsed: NERequest = serde_json::from_str(&json).unwrap();
        match parsed {
            NERequest::Routing { flow_id, .. } => {
                assert_eq!(flow_id, "test-123");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_response_serialization() {
        let resp = NEResponse::Routing {
            flow_id: "test-123".to_string(),
            action: "proxy".to_string(),
            proxy_name: Some("my-chain".to_string()),
        };

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"routing\""));
        assert!(json.contains("\"action\":\"proxy\""));
    }
}
