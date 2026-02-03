use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("packet too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },
    #[error("unsupported IP version: {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported transport protocol: {0}")]
    UnsupportedProtocol(u8),
}

/// Parsed IP packet header info.
#[derive(Debug, Clone)]
pub struct IpPacketInfo {
    pub version: u8,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub protocol: TransportProtocol,
    pub header_len: usize,
    pub total_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

/// Parsed transport layer info.
#[derive(Debug, Clone)]
pub struct TransportInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
}

/// Parse an IP packet and extract header information.
pub fn parse_ip_packet(data: &[u8]) -> Result<IpPacketInfo, PacketError> {
    if data.is_empty() {
        return Err(PacketError::TooShort {
            expected: 1,
            actual: 0,
        });
    }

    let version = (data[0] >> 4) & 0x0F;

    match version {
        4 => parse_ipv4(data),
        6 => parse_ipv6(data),
        v => Err(PacketError::UnsupportedVersion(v)),
    }
}

fn parse_ipv4(data: &[u8]) -> Result<IpPacketInfo, PacketError> {
    if data.len() < 20 {
        return Err(PacketError::TooShort {
            expected: 20,
            actual: data.len(),
        });
    }

    let ihl = (data[0] & 0x0F) as usize * 4;
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let proto_byte = data[9];
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let protocol = match proto_byte {
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        1 => TransportProtocol::Icmp,
        other => TransportProtocol::Other(other),
    };

    Ok(IpPacketInfo {
        version: 4,
        src_addr: IpAddr::V4(src),
        dst_addr: IpAddr::V4(dst),
        protocol,
        header_len: ihl,
        total_len,
    })
}

fn parse_ipv6(data: &[u8]) -> Result<IpPacketInfo, PacketError> {
    if data.len() < 40 {
        return Err(PacketError::TooShort {
            expected: 40,
            actual: data.len(),
        });
    }

    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let next_header = data[6];

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    dst.copy_from_slice(&data[24..40]);

    let protocol = match next_header {
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        58 => TransportProtocol::Icmp,
        other => TransportProtocol::Other(other),
    };

    Ok(IpPacketInfo {
        version: 6,
        src_addr: IpAddr::V6(Ipv6Addr::from(src)),
        dst_addr: IpAddr::V6(Ipv6Addr::from(dst)),
        protocol,
        header_len: 40,
        total_len: 40 + payload_len,
    })
}

/// Extract transport layer (TCP/UDP) port information from a packet.
pub fn parse_transport(data: &[u8], ip_info: &IpPacketInfo) -> Result<TransportInfo, PacketError> {
    let transport_data = &data[ip_info.header_len..];

    match ip_info.protocol {
        TransportProtocol::Tcp | TransportProtocol::Udp => {
            if transport_data.len() < 4 {
                return Err(PacketError::TooShort {
                    expected: ip_info.header_len + 4,
                    actual: data.len(),
                });
            }
            let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
            let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);

            Ok(TransportInfo {
                src_port,
                dst_port,
                protocol: ip_info.protocol,
            })
        }
        _ => Err(PacketError::UnsupportedProtocol(match ip_info.protocol {
            TransportProtocol::Other(p) => p,
            TransportProtocol::Icmp => 1,
            _ => unreachable!(),
        })),
    }
}

// --- Packet rewrite utilities ---

/// Rewrite the destination IPv4 address in a packet.
pub fn rewrite_ipv4_dst(packet: &mut [u8], new_dst: std::net::Ipv4Addr) {
    let octets = new_dst.octets();
    packet[16..20].copy_from_slice(&octets);
}

/// Rewrite the source IPv4 address in a packet.
pub fn rewrite_ipv4_src(packet: &mut [u8], new_src: std::net::Ipv4Addr) {
    let octets = new_src.octets();
    packet[12..16].copy_from_slice(&octets);
}

/// Rewrite the TCP/UDP destination port (offset 2-3 within transport header).
pub fn rewrite_dst_port(packet: &mut [u8], ip_header_len: usize, new_port: u16) {
    let bytes = new_port.to_be_bytes();
    packet[ip_header_len + 2] = bytes[0];
    packet[ip_header_len + 3] = bytes[1];
}

/// Rewrite the TCP/UDP source port (offset 0-1 within transport header).
pub fn rewrite_src_port(packet: &mut [u8], ip_header_len: usize, new_port: u16) {
    let bytes = new_port.to_be_bytes();
    packet[ip_header_len] = bytes[0];
    packet[ip_header_len + 1] = bytes[1];
}

/// Recalculate the IPv4 header checksum (RFC 1071).
pub fn recalculate_ipv4_checksum(packet: &mut [u8]) {
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    // Zero out existing checksum
    packet[10] = 0;
    packet[11] = 0;

    let checksum = internet_checksum(&packet[..ihl]);
    packet[10] = (checksum >> 8) as u8;
    packet[11] = (checksum & 0xFF) as u8;
}

/// Recalculate the TCP checksum.
///
/// The TCP checksum covers a pseudo-header (src IP, dst IP, zero, protocol, TCP length)
/// plus the entire TCP segment.
pub fn recalculate_tcp_checksum(packet: &mut [u8]) {
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let tcp_len = total_len - ihl;

    // Zero out existing TCP checksum (offset 16 within TCP header)
    packet[ihl + 16] = 0;
    packet[ihl + 17] = 0;

    // Build pseudo-header
    let mut pseudo = Vec::with_capacity(12 + tcp_len);
    pseudo.extend_from_slice(&packet[12..16]); // src IP
    pseudo.extend_from_slice(&packet[16..20]); // dst IP
    pseudo.push(0); // zero
    pseudo.push(packet[9]); // protocol (TCP = 6)
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes()); // TCP length
    pseudo.extend_from_slice(&packet[ihl..ihl + tcp_len]); // TCP segment

    let checksum = internet_checksum(&pseudo);
    packet[ihl + 16] = (checksum >> 8) as u8;
    packet[ihl + 17] = (checksum & 0xFF) as u8;
}

/// Recalculate the UDP checksum.
pub fn recalculate_udp_checksum(packet: &mut [u8]) {
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let udp_len = total_len - ihl;

    // Zero out existing UDP checksum (offset 6 within UDP header)
    packet[ihl + 6] = 0;
    packet[ihl + 7] = 0;

    // Build pseudo-header
    let mut pseudo = Vec::with_capacity(12 + udp_len);
    pseudo.extend_from_slice(&packet[12..16]); // src IP
    pseudo.extend_from_slice(&packet[16..20]); // dst IP
    pseudo.push(0);
    pseudo.push(packet[9]); // protocol (UDP = 17)
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&packet[ihl..ihl + udp_len]);

    let checksum = internet_checksum(&pseudo);
    // UDP checksum of 0x0000 means "no checksum"; if the computed value is 0, use 0xFFFF
    let checksum = if checksum == 0 { 0xFFFF } else { checksum };
    packet[ihl + 6] = (checksum >> 8) as u8;
    packet[ihl + 7] = (checksum & 0xFF) as u8;
}

/// RFC 1071 internet checksum.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_tcp() {
        // Minimal IPv4 TCP SYN-like packet
        #[rustfmt::skip]
        let packet: Vec<u8> = vec![
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x28, // version/ihl, dscp, total len = 40
            0x00, 0x00, 0x00, 0x00, // id, flags, fragment offset
            0x40, 0x06, 0x00, 0x00, // ttl=64, proto=TCP(6), checksum
            0xC0, 0xA8, 0x01, 0x01, // src: 192.168.1.1
            0x08, 0x08, 0x08, 0x08, // dst: 8.8.8.8
            // TCP header (first 4 bytes for ports)
            0x04, 0x00, 0x00, 0x50, // src port: 1024, dst port: 80
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let ip = parse_ip_packet(&packet).unwrap();
        assert_eq!(ip.version, 4);
        assert_eq!(ip.src_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(ip.dst_addr, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(ip.protocol, TransportProtocol::Tcp);

        let transport = parse_transport(&packet, &ip).unwrap();
        assert_eq!(transport.src_port, 1024);
        assert_eq!(transport.dst_port, 80);
    }

    #[test]
    fn test_rewrite_ipv4_dst() {
        #[rustfmt::skip]
        let mut packet: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0xC0, 0xA8, 0x01, 0x01, // src: 192.168.1.1
            0x08, 0x08, 0x08, 0x08, // dst: 8.8.8.8
            // TCP header (minimum for ports)
            0x04, 0x00, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        rewrite_ipv4_dst(&mut packet, std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip = parse_ip_packet(&packet).unwrap();
        assert_eq!(
            ip.dst_addr,
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn test_ipv4_checksum_roundtrip() {
        #[rustfmt::skip]
        let mut packet: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0xC0, 0xA8, 0x01, 0x01,
            0x08, 0x08, 0x08, 0x08,
            // TCP header
            0x04, 0x00, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        recalculate_ipv4_checksum(&mut packet);

        // Verify: computing checksum over the header including the checksum should yield 0
        let ihl = ((packet[0] & 0x0F) as usize) * 4;
        let verify = internet_checksum(&packet[..ihl]);
        assert_eq!(verify, 0, "IPv4 header checksum verification failed");
    }

    #[test]
    fn test_rewrite_ports() {
        #[rustfmt::skip]
        let mut packet: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0xC0, 0xA8, 0x01, 0x01,
            0x08, 0x08, 0x08, 0x08,
            0x04, 0x00, 0x00, 0x50, // src:1024, dst:80
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        rewrite_dst_port(&mut packet, 20, 8080);
        rewrite_src_port(&mut packet, 20, 54321);

        let ip = parse_ip_packet(&packet).unwrap();
        let transport = parse_transport(&packet, &ip).unwrap();
        assert_eq!(transport.dst_port, 8080);
        assert_eq!(transport.src_port, 54321);
    }
}
