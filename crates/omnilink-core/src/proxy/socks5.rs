use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{ProxyAuth, ProxyDestination, ProxyError, ProxyServer};

// SOCKS5 constants
const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USERNAME_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REPLY_SUCCEEDED: u8 = 0x00;

/// Establishes a SOCKS5 connection through the given proxy server to the destination.
/// Returns the connected TcpStream ready for data transfer.
pub async fn connect(
    server: &ProxyServer,
    dest: &ProxyDestination,
) -> Result<TcpStream, ProxyError> {
    let mut stream = TcpStream::connect(server.addr).await?;

    // --- Phase 1: Authentication negotiation ---
    negotiate_auth(&mut stream, &server.auth).await?;

    // --- Phase 2: Connection request ---
    send_connect_request(&mut stream, dest).await?;

    Ok(stream)
}

async fn negotiate_auth(
    stream: &mut TcpStream,
    auth: &Option<ProxyAuth>,
) -> Result<(), ProxyError> {
    let methods: Vec<u8> = if auth.is_some() {
        vec![AUTH_NONE, AUTH_USERNAME_PASSWORD]
    } else {
        vec![AUTH_NONE]
    };

    // Send: VER | NMETHODS | METHODS
    let mut buf = vec![SOCKS5_VERSION, methods.len() as u8];
    buf.extend_from_slice(&methods);
    stream.write_all(&buf).await?;

    // Receive: VER | METHOD
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;

    if resp[0] != SOCKS5_VERSION {
        return Err(ProxyError::ProtocolError(format!(
            "unexpected version: {}",
            resp[0]
        )));
    }

    match resp[1] {
        AUTH_NONE => Ok(()),
        AUTH_USERNAME_PASSWORD => {
            let auth = auth
                .as_ref()
                .ok_or(ProxyError::AuthenticationFailed)?;
            authenticate_username_password(stream, auth).await
        }
        AUTH_NO_ACCEPTABLE => Err(ProxyError::AuthenticationFailed),
        other => Err(ProxyError::ProtocolError(format!(
            "unsupported auth method: {}",
            other
        ))),
    }
}

async fn authenticate_username_password(
    stream: &mut TcpStream,
    auth: &ProxyAuth,
) -> Result<(), ProxyError> {
    // Sub-negotiation version 0x01
    let mut buf = vec![0x01];
    buf.push(auth.username.len() as u8);
    buf.extend_from_slice(auth.username.as_bytes());
    buf.push(auth.password.len() as u8);
    buf.extend_from_slice(auth.password.as_bytes());
    stream.write_all(&buf).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;

    if resp[1] != 0x00 {
        return Err(ProxyError::AuthenticationFailed);
    }

    Ok(())
}

async fn send_connect_request(
    stream: &mut TcpStream,
    dest: &ProxyDestination,
) -> Result<(), ProxyError> {
    let mut buf = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00]; // VER | CMD | RSV

    match dest {
        ProxyDestination::SocketAddr(addr) => match addr {
            std::net::SocketAddr::V4(v4) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(v6) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
        },
        ProxyDestination::Domain(domain, port) => {
            buf.push(ATYP_DOMAIN);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }

    stream.write_all(&buf).await?;

    // Read reply: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != SOCKS5_VERSION {
        return Err(ProxyError::ProtocolError(format!(
            "unexpected version in reply: {}",
            header[0]
        )));
    }

    if header[1] != REPLY_SUCCEEDED {
        return Err(ProxyError::ConnectionFailed(format!(
            "SOCKS5 reply code: 0x{:02x}",
            header[1]
        )));
    }

    // Consume bound address
    match header[3] {
        ATYP_IPV4 => {
            let mut addr = [0u8; 6]; // 4 bytes IP + 2 bytes port
            stream.read_exact(&mut addr).await?;
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 18]; // 16 bytes IP + 2 bytes port
            stream.read_exact(&mut addr).await?;
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize + 2]; // domain + port
            stream.read_exact(&mut domain).await?;
        }
        _ => {
            return Err(ProxyError::AddressTypeNotSupported);
        }
    }

    Ok(())
}
