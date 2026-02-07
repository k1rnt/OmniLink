use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// DNS resolution mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// Send domain name to SOCKS5 proxy for remote resolution.
    RemoteResolution,
    /// Return a fake IP from the virtual pool and map it back later.
    FakeIp,
}

/// Virtual DNS / Fake IP resolver.
///
/// When an application resolves a domain name, we return a fake IP from the
/// `198.18.0.0/15` range. When the app connects to that fake IP, we look up
/// the original domain and route through the proxy with the real domain name.
pub struct VirtualDns {
    /// Maps domain -> fake IP.
    domain_to_ip: Mutex<HashMap<String, Ipv4Addr>>,
    /// Maps fake IP -> domain.
    ip_to_domain: Mutex<HashMap<Ipv4Addr, String>>,
    /// Next IP to allocate in the pool.
    next_ip: Mutex<u32>,
    /// Start of the fake IP pool (198.18.0.0).
    pool_start: u32,
    /// End of the fake IP pool (198.19.255.255).
    pool_end: u32,
    /// Maps real IP -> domain (populated by DNS response recording for pf mode).
    real_ip_to_domain: Mutex<HashMap<IpAddr, String>>,
}

impl VirtualDns {
    pub fn new() -> Self {
        let pool_start = u32::from(Ipv4Addr::new(198, 18, 0, 1));
        let pool_end = u32::from(Ipv4Addr::new(198, 19, 255, 254));

        Self {
            domain_to_ip: Mutex::new(HashMap::new()),
            ip_to_domain: Mutex::new(HashMap::new()),
            next_ip: Mutex::new(pool_start),
            pool_start,
            pool_end,
            real_ip_to_domain: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve a domain to a fake IP. Returns the same IP for the same domain.
    pub fn resolve(&self, domain: &str) -> Option<Ipv4Addr> {
        let domain = domain.to_lowercase();

        // Check existing mapping
        {
            let map = self.domain_to_ip.lock().unwrap();
            if let Some(&ip) = map.get(&domain) {
                return Some(ip);
            }
        }

        // Allocate new fake IP
        let mut next = self.next_ip.lock().unwrap();
        if *next > self.pool_end {
            tracing::warn!("fake IP pool exhausted");
            return None;
        }

        let ip = Ipv4Addr::from(*next);
        *next += 1;

        self.domain_to_ip.lock().unwrap().insert(domain.clone(), ip);
        self.ip_to_domain.lock().unwrap().insert(ip, domain);

        Some(ip)
    }

    /// Look up the original domain for a fake IP.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        if let IpAddr::V4(v4) = ip {
            let map = self.ip_to_domain.lock().unwrap();
            map.get(&v4).cloned()
        } else {
            None
        }
    }

    /// Check if an IP address is within the fake IP range.
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        if let IpAddr::V4(v4) = ip {
            let n = u32::from(v4);
            n >= self.pool_start && n <= self.pool_end
        } else {
            false
        }
    }

    /// Get the number of allocated fake IPs.
    pub fn allocated_count(&self) -> usize {
        self.domain_to_ip.lock().unwrap().len()
    }

    /// Record a real IP -> domain mapping from an observed DNS response.
    pub fn record_dns_mapping(&self, ip: IpAddr, domain: &str) {
        let mut map = self.real_ip_to_domain.lock().unwrap();
        map.insert(ip, domain.to_lowercase());
    }

    /// Look up a domain for an IP, checking the real-IP reverse table first,
    /// then falling back to the FakeIP table.
    pub fn lookup_real_ip(&self, ip: IpAddr) -> Option<String> {
        {
            let map = self.real_ip_to_domain.lock().unwrap();
            if let Some(domain) = map.get(&ip) {
                return Some(domain.clone());
            }
        }
        self.lookup(ip)
    }
}

impl Default for VirtualDns {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_and_lookup() {
        let dns = VirtualDns::new();

        let ip1 = dns.resolve("example.com").unwrap();
        let ip2 = dns.resolve("example.com").unwrap();
        assert_eq!(ip1, ip2, "same domain should return same IP");

        let ip3 = dns.resolve("other.com").unwrap();
        assert_ne!(ip1, ip3, "different domains should get different IPs");

        assert_eq!(
            dns.lookup(IpAddr::V4(ip1)),
            Some("example.com".to_string())
        );
        assert!(dns.is_fake_ip(IpAddr::V4(ip1)));
        assert!(!dns.is_fake_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
