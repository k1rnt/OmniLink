use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{connect_with_timeout, ProxyDestination, ProxyError, ProxyServer, DEFAULT_CONNECT_TIMEOUT_SECS};

const SOCKS4_VERSION: u8 = 0x04;
const CMD_CONNECT: u8 = 0x01;
const REPLY_GRANTED: u8 = 0x5A;

/// Establishes a SOCKS4 connection through the given proxy server.
/// SOCKS4 only supports IPv4 addresses; domain resolution must be done locally.
pub async fn connect(
    server: &ProxyServer,
    dest: &ProxyDestination,
) -> Result<TcpStream, ProxyError> {
    let mut stream = connect_with_timeout(server.addr, DEFAULT_CONNECT_TIMEOUT_SECS).await?;

    let (ip, port) = match dest {
        ProxyDestination::SocketAddr(addr) => match addr {
            std::net::SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
            std::net::SocketAddr::V6(_) => {
                return Err(ProxyError::AddressTypeNotSupported);
            }
        },
        ProxyDestination::Domain(_domain, _port) => {
            return Err(ProxyError::ProtocolError(
                "SOCKS4 does not support domain names; use SOCKS4a or SOCKS5".to_string(),
            ));
        }
    };

    let userid = server
        .auth
        .as_ref()
        .map(|a| a.username.as_bytes().to_vec())
        .unwrap_or_default();

    // Request: VER | CMD | DSTPORT | DSTIP | USERID | NULL
    let mut buf = vec![SOCKS4_VERSION, CMD_CONNECT];
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(&ip.octets());
    buf.extend_from_slice(&userid);
    buf.push(0x00); // null terminator

    stream.write_all(&buf).await?;

    // Reply: VN | REP | DSTPORT | DSTIP (8 bytes)
    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).await?;

    if reply[1] != REPLY_GRANTED {
        return Err(ProxyError::ConnectionFailed(format!(
            "SOCKS4 reply code: 0x{:02x}",
            reply[1]
        )));
    }

    Ok(stream)
}

/// Establishes a SOCKS4a connection through the given proxy server.
/// SOCKS4a supports domain name resolution on the proxy side.
pub async fn connect_4a(
    server: &ProxyServer,
    dest: &ProxyDestination,
) -> Result<TcpStream, ProxyError> {
    let mut stream = connect_with_timeout(server.addr, DEFAULT_CONNECT_TIMEOUT_SECS).await?;

    let (ip_bytes, port, domain_bytes) = match dest {
        ProxyDestination::SocketAddr(addr) => match addr {
            std::net::SocketAddr::V4(v4) => (v4.ip().octets(), v4.port(), None),
            std::net::SocketAddr::V6(_) => {
                return Err(ProxyError::AddressTypeNotSupported);
            }
        },
        ProxyDestination::Domain(domain, port) => {
            // SOCKS4a: use invalid IP 0.0.0.x (where x != 0) to signal domain name follows
            let fake_ip = Ipv4Addr::new(0, 0, 0, 1);
            (fake_ip.octets(), *port, Some(domain.as_bytes().to_vec()))
        }
    };

    let userid = server
        .auth
        .as_ref()
        .map(|a| a.username.as_bytes().to_vec())
        .unwrap_or_default();

    // Request: VER | CMD | DSTPORT | DSTIP | USERID | NULL | [DOMAIN | NULL]
    let mut buf = vec![SOCKS4_VERSION, CMD_CONNECT];
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(&ip_bytes);
    buf.extend_from_slice(&userid);
    buf.push(0x00);

    if let Some(domain) = domain_bytes {
        buf.extend_from_slice(&domain);
        buf.push(0x00);
    }

    stream.write_all(&buf).await?;

    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).await?;

    if reply[1] != REPLY_GRANTED {
        return Err(ProxyError::ConnectionFailed(format!(
            "SOCKS4a reply code: 0x{:02x}",
            reply[1]
        )));
    }

    Ok(stream)
}
