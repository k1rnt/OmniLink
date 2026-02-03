use omnilink_core::dns::VirtualDns;

/// DNS record types.
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

/// DNS header flags for a standard response.
const FLAGS_RESPONSE: u16 = 0x8180; // QR=1, RD=1, RA=1

/// Parsed DNS query.
#[derive(Debug)]
pub struct DnsQuery {
    pub id: u16,
    pub domain: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Parse a minimal DNS query from raw UDP payload.
///
/// Supports simple single-question queries only.
pub fn parse_dns_query(data: &[u8]) -> Option<DnsQuery> {
    if data.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]);

    // Only handle standard queries (QR=0, OPCODE=0)
    if flags & 0x8000 != 0 || qdcount == 0 {
        return None;
    }

    // Parse the question section
    let mut offset = 12;
    let mut labels = Vec::new();

    loop {
        if offset >= data.len() {
            return None;
        }
        let label_len = data[offset] as usize;
        offset += 1;
        if label_len == 0 {
            break;
        }
        if offset + label_len > data.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&data[offset..offset + label_len])
                .ok()?
                .to_string(),
        );
        offset += label_len;
    }

    if offset + 4 > data.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

    let domain = labels.join(".");

    Some(DnsQuery {
        id,
        domain,
        qtype,
        qclass,
    })
}

/// Build a DNS response with a fake IP for an A record query.
///
/// For AAAA queries, returns an empty response (no IPv6 fake IPs).
pub fn build_dns_response(query: &DnsQuery, virtual_dns: &VirtualDns) -> Option<Vec<u8>> {
    match query.qtype {
        TYPE_A => build_a_response(query, virtual_dns),
        TYPE_AAAA => Some(build_empty_response(query)),
        _ => None,
    }
}

/// Build an A record response with a fake IP from VirtualDns.
fn build_a_response(query: &DnsQuery, virtual_dns: &VirtualDns) -> Option<Vec<u8>> {
    let fake_ip = virtual_dns.resolve(&query.domain)?;

    let mut response = Vec::with_capacity(128);

    // Header
    response.extend_from_slice(&query.id.to_be_bytes());
    response.extend_from_slice(&FLAGS_RESPONSE.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // Question section (echo back)
    encode_domain_name(&mut response, &query.domain);
    response.extend_from_slice(&query.qtype.to_be_bytes());
    response.extend_from_slice(&query.qclass.to_be_bytes());

    // Answer section
    // Name pointer to offset 12 (start of question name)
    response.extend_from_slice(&[0xC0, 0x0C]);
    response.extend_from_slice(&TYPE_A.to_be_bytes()); // TYPE
    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    response.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
    response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
    response.extend_from_slice(&fake_ip.octets()); // RDATA

    Some(response)
}

/// Build an empty response (NOERROR with no answers) for unsupported query types.
fn build_empty_response(query: &DnsQuery) -> Vec<u8> {
    let mut response = Vec::with_capacity(64);

    response.extend_from_slice(&query.id.to_be_bytes());
    response.extend_from_slice(&FLAGS_RESPONSE.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    encode_domain_name(&mut response, &query.domain);
    response.extend_from_slice(&query.qtype.to_be_bytes());
    response.extend_from_slice(&query.qclass.to_be_bytes());

    response
}

/// Encode a domain name in DNS wire format (length-prefixed labels).
fn encode_domain_name(buf: &mut Vec<u8>, domain: &str) {
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // root label
}

/// Check if a UDP packet is destined for DNS (port 53).
pub fn is_dns_packet(dst_port: u16) -> bool {
    dst_port == 53
}

/// Build a complete UDP response packet for DNS by swapping src/dst in the
/// original IP+UDP headers and replacing the UDP payload.
pub fn build_dns_udp_response(
    original_packet: &[u8],
    ip_header_len: usize,
    dns_response: &[u8],
) -> Vec<u8> {
    let udp_header_len = 8;
    let total_len = ip_header_len + udp_header_len + dns_response.len();

    let mut packet = vec![0u8; total_len];

    // Copy and modify IP header
    packet[..ip_header_len].copy_from_slice(&original_packet[..ip_header_len]);

    // Swap src and dst IP
    let orig_src: [u8; 4] = original_packet[12..16].try_into().unwrap();
    let orig_dst: [u8; 4] = original_packet[16..20].try_into().unwrap();
    packet[12..16].copy_from_slice(&orig_dst);
    packet[16..20].copy_from_slice(&orig_src);

    // Update total length
    let total_len_u16 = total_len as u16;
    packet[2..4].copy_from_slice(&total_len_u16.to_be_bytes());

    // Swap src and dst UDP ports
    let orig_src_port = &original_packet[ip_header_len..ip_header_len + 2];
    let orig_dst_port = &original_packet[ip_header_len + 2..ip_header_len + 4];
    packet[ip_header_len..ip_header_len + 2].copy_from_slice(orig_dst_port);
    packet[ip_header_len + 2..ip_header_len + 4].copy_from_slice(orig_src_port);

    // UDP length
    let udp_len = (udp_header_len + dns_response.len()) as u16;
    packet[ip_header_len + 4..ip_header_len + 6].copy_from_slice(&udp_len.to_be_bytes());

    // UDP checksum = 0 (optional for IPv4)
    packet[ip_header_len + 6] = 0;
    packet[ip_header_len + 7] = 0;

    // DNS response payload
    packet[ip_header_len + udp_header_len..].copy_from_slice(dns_response);

    // Recalculate IP checksum
    crate::packet::recalculate_ipv4_checksum(&mut packet);
    // Recalculate UDP checksum
    crate::packet::recalculate_udp_checksum(&mut packet);

    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_dns_query() {
        // A simple DNS query for "example.com" type A
        let mut query_bytes = Vec::new();
        // Header
        query_bytes.extend_from_slice(&[0x12, 0x34]); // ID
        query_bytes.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, RD=1
        query_bytes.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        query_bytes.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
        query_bytes.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        query_bytes.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
        // Question: example.com
        query_bytes.push(7);
        query_bytes.extend_from_slice(b"example");
        query_bytes.push(3);
        query_bytes.extend_from_slice(b"com");
        query_bytes.push(0);
        query_bytes.extend_from_slice(&[0x00, 0x01]); // TYPE A
        query_bytes.extend_from_slice(&[0x00, 0x01]); // CLASS IN

        let parsed = parse_dns_query(&query_bytes).unwrap();
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.qtype, TYPE_A);
        assert_eq!(parsed.qclass, 1);
    }

    #[test]
    fn test_build_a_response() {
        let dns = VirtualDns::new();
        let query = DnsQuery {
            id: 0x1234,
            domain: "test.example.com".to_string(),
            qtype: TYPE_A,
            qclass: 1,
        };

        let response = build_dns_response(&query, &dns).unwrap();

        // Verify header
        assert_eq!(u16::from_be_bytes([response[0], response[1]]), 0x1234);
        // QR=1 (response)
        assert!(response[2] & 0x80 != 0);
        // ANCOUNT=1
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);

        // The last 4 bytes should be the fake IP
        let ip_bytes: [u8; 4] = response[response.len() - 4..].try_into().unwrap();
        let fake_ip = Ipv4Addr::from(ip_bytes);
        assert!(dns.is_fake_ip(std::net::IpAddr::V4(fake_ip)));
    }
}
