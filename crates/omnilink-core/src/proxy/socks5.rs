use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{ProxyAuth, ProxyDestination, ProxyError, ProxyServer};

// SOCKS5 constants
const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USERNAME_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
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

/// Result of a SOCKS5 UDP Associate handshake.
pub struct UdpAssociation {
    /// The TCP control connection (must remain open while the association is active).
    pub control: TcpStream,
    /// The relay address where UDP packets should be sent.
    pub relay_addr: std::net::SocketAddr,
}

/// Establishes a SOCKS5 UDP ASSOCIATE through the given proxy server.
/// The returned `UdpAssociation` contains the relay address for sending
/// encapsulated UDP datagrams and the control TCP connection that must
/// be kept alive for the duration of the association.
pub async fn udp_associate(
    server: &ProxyServer,
    client_addr: std::net::SocketAddr,
) -> Result<UdpAssociation, ProxyError> {
    let mut stream = TcpStream::connect(server.addr).await?;

    negotiate_auth(&mut stream, &server.auth).await?;

    // Send UDP ASSOCIATE request with client address
    let mut buf = vec![SOCKS5_VERSION, CMD_UDP_ASSOCIATE, 0x00];
    match client_addr {
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
    }
    stream.write_all(&buf).await?;

    // Read reply
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
            "SOCKS5 UDP ASSOCIATE reply: 0x{:02x}",
            header[1]
        )));
    }

    // Parse bound address (the UDP relay endpoint)
    let relay_addr = match header[3] {
        ATYP_IPV4 => {
            let mut addr_buf = [0u8; 6];
            stream.read_exact(&mut addr_buf).await?;
            let ip = std::net::Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]);
            let port = u16::from_be_bytes([addr_buf[4], addr_buf[5]]);
            let mut relay = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port);
            // If the proxy replies with 0.0.0.0, use the proxy server's IP
            if ip.is_unspecified() {
                relay.set_ip(server.addr.ip());
            }
            relay
        }
        ATYP_IPV6 => {
            let mut addr_buf = [0u8; 18];
            stream.read_exact(&mut addr_buf).await?;
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&addr_buf[..16]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([addr_buf[16], addr_buf[17]]);
            let mut relay = std::net::SocketAddr::new(std::net::IpAddr::V6(ip), port);
            if ip.is_unspecified() {
                relay.set_ip(server.addr.ip());
            }
            relay
        }
        _ => {
            return Err(ProxyError::AddressTypeNotSupported);
        }
    };

    Ok(UdpAssociation {
        control: stream,
        relay_addr,
    })
}

/// Encapsulate a UDP payload into a SOCKS5 UDP request datagram.
/// Format: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT | DATA
pub fn encode_udp_datagram(dest: &ProxyDestination, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x00, 0x00, 0x00]; // RSV + FRAG

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

    buf.extend_from_slice(payload);
    buf
}

/// Decode a SOCKS5 UDP reply datagram.
/// Returns (source address, payload data).
pub fn decode_udp_datagram(data: &[u8]) -> Result<(ProxyDestination, &[u8]), ProxyError> {
    if data.len() < 4 {
        return Err(ProxyError::ProtocolError("UDP datagram too short".to_string()));
    }

    // data[0..2] = RSV, data[2] = FRAG
    let frag = data[2];
    if frag != 0 {
        return Err(ProxyError::UnsupportedCommand(frag));
    }

    let atyp = data[3];
    match atyp {
        ATYP_IPV4 => {
            if data.len() < 10 {
                return Err(ProxyError::ProtocolError("UDP datagram too short for IPv4".to_string()));
            }
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port);
            Ok((ProxyDestination::SocketAddr(addr), &data[10..]))
        }
        ATYP_IPV6 => {
            if data.len() < 22 {
                return Err(ProxyError::ProtocolError("UDP datagram too short for IPv6".to_string()));
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([data[20], data[21]]);
            let addr = std::net::SocketAddr::new(std::net::IpAddr::V6(ip), port);
            Ok((ProxyDestination::SocketAddr(addr), &data[22..]))
        }
        ATYP_DOMAIN => {
            if data.len() < 5 {
                return Err(ProxyError::ProtocolError("UDP datagram too short for domain".to_string()));
            }
            let domain_len = data[4] as usize;
            let header_len = 5 + domain_len + 2;
            if data.len() < header_len {
                return Err(ProxyError::ProtocolError("UDP datagram too short".to_string()));
            }
            let domain = String::from_utf8_lossy(&data[5..5 + domain_len]).to_string();
            let port = u16::from_be_bytes([data[5 + domain_len], data[6 + domain_len]]);
            Ok((ProxyDestination::Domain(domain, port), &data[header_len..]))
        }
        _ => Err(ProxyError::AddressTypeNotSupported),
    }
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
