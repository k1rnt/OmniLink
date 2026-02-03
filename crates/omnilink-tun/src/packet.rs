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
}
