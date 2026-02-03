use std::sync::Arc;

use tokio::net::TcpStream;

use super::{ProxyDestination, ProxyError, ProxyServer};

struct SshHandler;

#[async_trait::async_trait]
impl russh::client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept all server keys (equivalent to StrictHostKeyChecking=no).
        // TODO: Implement known_hosts verification for production use.
        Ok(true)
    }
}

/// Establish an SSH tunnel (direct-tcpip) through the given proxy server to the destination.
/// Returns a TcpStream bridged to the SSH channel for transparent data transfer.
pub async fn connect(
    server: &ProxyServer,
    dest: &ProxyDestination,
) -> Result<TcpStream, ProxyError> {
    let config = Arc::new(russh::client::Config::default());
    let handler = SshHandler;

    let mut session = russh::client::connect(config, server.addr, handler)
        .await
        .map_err(|e| ProxyError::ConnectionFailed(format!("SSH connection failed: {}", e)))?;

    // Authenticate with username/password
    let auth = server
        .auth
        .as_ref()
        .ok_or(ProxyError::AuthenticationFailed)?;

    let auth_result = session
        .authenticate_password(&auth.username, &auth.password)
        .await
        .map_err(|e| ProxyError::ConnectionFailed(format!("SSH auth error: {}", e)))?;

    if !auth_result {
        return Err(ProxyError::AuthenticationFailed);
    }

    // Open a direct-tcpip channel to the destination
    let (dest_host, dest_port) = match dest {
        ProxyDestination::SocketAddr(a) => (a.ip().to_string(), a.port() as u32),
        ProxyDestination::Domain(d, p) => (d.clone(), *p as u32),
    };

    let channel = session
        .channel_open_direct_tcpip(&dest_host, dest_port, "127.0.0.1", 0)
        .await
        .map_err(|e| ProxyError::ConnectionFailed(format!("SSH channel open failed: {}", e)))?;

    // Bridge the SSH channel to a TcpStream via a local socket pair.
    // This preserves TcpStream compatibility with the rest of the proxy chain architecture.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;

    let (client_result, server_result) = tokio::join!(
        TcpStream::connect(local_addr),
        listener.accept(),
    );

    let client_stream = client_result?;
    let (server_stream, _) = server_result?;
    drop(listener);

    // Convert the SSH channel into an AsyncRead+AsyncWrite stream
    let channel_stream = channel.into_stream();

    // Spawn a relay task to bridge data between the local socket and SSH channel
    tokio::spawn(async move {
        let (mut cr, mut cw) = tokio::io::split(channel_stream);
        let (mut sr, mut sw) = tokio::io::split(server_stream);
        let _ = tokio::try_join!(
            tokio::io::copy(&mut cr, &mut sw),
            tokio::io::copy(&mut sr, &mut cw),
        );
        // Keep the SSH session alive until the relay ends
        drop(session);
    });

    tracing::info!(
        dest = %dest,
        server = %server.addr,
        "SSH tunnel established"
    );

    Ok(client_stream)
}
