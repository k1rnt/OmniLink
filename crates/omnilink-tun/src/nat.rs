use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Entry in the NAT table mapping a rewritten source to the original destination.
#[derive(Debug, Clone)]
struct NatEntry {
    original_dst: SocketAddr,
    created_at: Instant,
}

/// NAT table for tracking rewritten connections.
///
/// When a packet's destination is rewritten to a local listener, we record
/// the mapping from (rewritten src:port) → (original dst:port) so that the
/// local TCP listener can look up the real destination after accepting.
pub struct NatTable {
    entries: DashMap<SocketAddr, NatEntry>,
    ttl: Duration,
}

impl NatTable {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            ttl,
        }
    }

    /// Insert a mapping from source address to the original destination.
    pub fn insert(&self, src: SocketAddr, original_dst: SocketAddr) {
        self.entries.insert(
            src,
            NatEntry {
                original_dst,
                created_at: Instant::now(),
            },
        );
    }

    /// Look up the original destination for a given source address.
    pub fn lookup(&self, src: &SocketAddr) -> Option<SocketAddr> {
        self.entries.get(src).map(|e| e.original_dst)
    }

    /// Remove an entry after the connection has been established.
    pub fn remove(&self, src: &SocketAddr) -> Option<SocketAddr> {
        self.entries.remove(src).map(|(_, e)| e.original_dst)
    }

    /// Remove entries older than the configured TTL.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| {
            now.duration_since(entry.created_at) < self.ttl
        });
    }

    /// Number of active entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_insert_and_lookup() {
        let nat = NatTable::new(Duration::from_secs(60));
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345));
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443));

        nat.insert(src, dst);
        assert_eq!(nat.lookup(&src), Some(dst));
        assert_eq!(nat.len(), 1);
    }

    #[test]
    fn test_remove() {
        let nat = NatTable::new(Duration::from_secs(60));
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345));
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443));

        nat.insert(src, dst);
        assert_eq!(nat.remove(&src), Some(dst));
        assert!(nat.is_empty());
    }

    #[test]
    fn test_cleanup_expired() {
        let nat = NatTable::new(Duration::from_millis(0));
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345));
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443));

        nat.insert(src, dst);
        // TTL is 0ms so entry is immediately expired
        nat.cleanup_expired();
        assert!(nat.is_empty());
    }
}
