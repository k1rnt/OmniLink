use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::{connect_with_timeout, ProxyDestination, ProxyError, ProxyServer, DEFAULT_CONNECT_TIMEOUT_SECS};

/// Establish an HTTPS CONNECT tunnel through the given proxy server.
///
/// Connects to the proxy over TLS, then performs HTTP CONNECT to reach
/// the destination. Returns a TcpStream bridged to the TLS tunnel.
pub async fn connect(
    server: &ProxyServer,
    dest: &ProxyDestination,
) -> Result<TcpStream, ProxyError> {
    // 1. TCP connect to proxy
    let tcp_stream = connect_with_timeout(server.addr, DEFAULT_CONNECT_TIMEOUT_SECS).await?;

    // 2. TLS handshake
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_config));

    let server_name = if let Some(hostname) = &server.hostname {
        rustls::pki_types::ServerName::try_from(hostname.clone())
            .map_err(|e| ProxyError::ConnectionFailed(format!("invalid TLS server name: {}", e)))?
    } else {
        let ip = server.addr.ip();
        rustls::pki_types::ServerName::try_from(ip)
            .map_err(|e| ProxyError::ConnectionFailed(format!("invalid TLS server name from IP: {}", e)))?
    };

    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| ProxyError::ConnectionFailed(format!("TLS handshake failed: {}", e)))?;

    // 3. HTTP CONNECT over TLS
    let target = match dest {
        ProxyDestination::SocketAddr(addr) => addr.to_string(),
        ProxyDestination::Domain(domain, port) => format!("{}:{}", domain, port),
    };

    let mut request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
        target, target
    );

    if let Some(auth) = &server.auth {
        let credentials = super::http::base64_encode(&format!("{}:{}", auth.username, auth.password));
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", credentials));
    }

    request.push_str("\r\n");

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut tls_stream = tls_stream;
    tls_stream.write_all(request.as_bytes()).await?;

    // Read response status line
    let mut reader = BufReader::new(&mut tls_stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;

    let status_code = parse_status_code(&status_line)?;

    if status_code == 407 {
        return Err(ProxyError::AuthenticationFailed);
    }

    if !(200..300).contains(&status_code) {
        return Err(ProxyError::ConnectionFailed(format!(
            "HTTPS CONNECT failed with status {}",
            status_code
        )));
    }

    // Consume remaining headers
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }
    drop(reader);

    // 4. Bridge TLS stream to a TcpStream via local socket pair (same pattern as ssh.rs)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;

    let (client_result, server_result) = tokio::join!(
        TcpStream::connect(local_addr),
        listener.accept(),
    );

    let client_stream = client_result?;
    let (server_stream, _) = server_result?;
    drop(listener);

    tokio::spawn(async move {
        let (mut tr, mut tw) = tokio::io::split(tls_stream);
        let (mut sr, mut sw) = tokio::io::split(server_stream);
        let _ = tokio::try_join!(
            tokio::io::copy(&mut tr, &mut sw),
            tokio::io::copy(&mut sr, &mut tw),
        );
    });

    tracing::info!(
        dest = %dest,
        server = %server.addr,
        "HTTPS CONNECT tunnel established"
    );

    Ok(client_stream)
}

fn parse_status_code(status_line: &str) -> Result<u16, ProxyError> {
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(ProxyError::ProtocolError(
            "invalid HTTP status line".to_string(),
        ));
    }
    parts[1]
        .parse()
        .map_err(|_| ProxyError::ProtocolError("invalid status code".to_string()))
}
