use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::{connect_with_timeout, ProxyDestination, ProxyError, ProxyServer, DEFAULT_CONNECT_TIMEOUT_SECS};

/// Establishes an HTTP CONNECT tunnel through the given proxy server.
/// Returns the connected TcpStream ready for data transfer.
pub async fn connect(
    server: &ProxyServer,
    dest: &ProxyDestination,
) -> Result<TcpStream, ProxyError> {
    let mut stream = connect_with_timeout(server.addr, DEFAULT_CONNECT_TIMEOUT_SECS).await?;

    let target = match dest {
        ProxyDestination::SocketAddr(addr) => addr.to_string(),
        ProxyDestination::Domain(domain, port) => format!("{}:{}", domain, port),
    };

    let mut request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
        target, target
    );

    if let Some(auth) = &server.auth {
        let credentials = base64_encode(&format!("{}:{}", auth.username, auth.password));
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", credentials));
    }

    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;

    // Read response status line
    let mut reader = BufReader::new(&mut stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;

    let status_code = parse_status_code(&status_line)?;

    if status_code == 407 {
        return Err(ProxyError::AuthenticationFailed);
    }

    if !(200..300).contains(&status_code) {
        return Err(ProxyError::ConnectionFailed(format!(
            "HTTP CONNECT failed with status {}",
            status_code
        )));
    }

    // Consume remaining headers until empty line
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // We need to drop the BufReader and return the raw stream.
    // The BufReader may have buffered data, but for CONNECT tunnels
    // the proxy should not send any extra data after headers.
    drop(reader);

    Ok(stream)
}

fn parse_status_code(status_line: &str) -> Result<u16, ProxyError> {
    // Format: "HTTP/1.1 200 Connection established\r\n"
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

pub fn base64_encode(input: &str) -> String {
    use base64_chars::*;
    let bytes = input.as_bytes();
    let mut result = String::new();
    let chunks = bytes.chunks(3);

    for chunk in chunks {
        let mut buf = [0u8; 3];
        for (i, &b) in chunk.iter().enumerate() {
            buf[i] = b;
        }

        let b0 = (buf[0] >> 2) & 0x3F;
        let b1 = ((buf[0] & 0x03) << 4) | ((buf[1] >> 4) & 0x0F);
        let b2 = ((buf[1] & 0x0F) << 2) | ((buf[2] >> 6) & 0x03);
        let b3 = buf[2] & 0x3F;

        result.push(CHARS[b0 as usize]);
        result.push(CHARS[b1 as usize]);

        if chunk.len() > 1 {
            result.push(CHARS[b2 as usize]);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(CHARS[b3 as usize]);
        } else {
            result.push('=');
        }
    }

    result
}

mod base64_chars {
    pub const CHARS: &[char] = &[
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    ];
}
