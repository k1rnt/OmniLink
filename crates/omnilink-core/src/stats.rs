use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::Serialize;

/// Global traffic statistics tracker.
pub struct TrafficStats {
    /// Total bytes sent across all connections.
    total_sent: AtomicU64,
    /// Total bytes received across all connections.
    total_received: AtomicU64,
    /// Total number of connections handled.
    total_connections: AtomicU64,
    /// Active connection count.
    active_connections: AtomicU64,
    /// Per-proxy traffic counters.
    proxy_stats: Mutex<HashMap<String, ProxyTraffic>>,
    /// Per-destination domain traffic (top-N tracking).
    domain_stats: Mutex<HashMap<String, DomainTraffic>>,
}

/// Traffic counters for a single proxy.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ProxyTraffic {
    pub proxy_name: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_count: u64,
    pub error_count: u64,
}

/// Traffic counters for a single destination domain.
#[derive(Debug, Clone, Serialize, Default)]
pub struct DomainTraffic {
    pub domain: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_count: u64,
}

/// Snapshot of traffic statistics for serialization.
#[derive(Debug, Clone, Serialize)]
pub struct StatsSnapshot {
    pub total_sent: u64,
    pub total_received: u64,
    pub total_connections: u64,
    pub active_connections: u64,
    pub top_proxies: Vec<ProxyTraffic>,
    pub top_domains: Vec<DomainTraffic>,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self {
            total_sent: AtomicU64::new(0),
            total_received: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            proxy_stats: Mutex::new(HashMap::new()),
            domain_stats: Mutex::new(HashMap::new()),
        }
    }

    /// Record a new connection being established.
    pub fn record_connection_open(&self, proxy_name: Option<&str>, domain: Option<&str>) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);

        if let Some(name) = proxy_name {
            let mut stats = self.proxy_stats.lock().unwrap();
            let entry = stats
                .entry(name.to_string())
                .or_insert_with(|| ProxyTraffic {
                    proxy_name: name.to_string(),
                    ..Default::default()
                });
            entry.connection_count += 1;
        }

        if let Some(d) = domain {
            let mut stats = self.domain_stats.lock().unwrap();
            let entry = stats
                .entry(d.to_string())
                .or_insert_with(|| DomainTraffic {
                    domain: d.to_string(),
                    ..Default::default()
                });
            entry.connection_count += 1;
        }
    }

    /// Record a connection being closed.
    pub fn record_connection_close(&self) {
        self.active_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .ok();
    }

    /// Record bytes transferred on a connection.
    pub fn record_bytes(
        &self,
        sent: u64,
        received: u64,
        proxy_name: Option<&str>,
        domain: Option<&str>,
    ) {
        self.total_sent.fetch_add(sent, Ordering::Relaxed);
        self.total_received.fetch_add(received, Ordering::Relaxed);

        if let Some(name) = proxy_name {
            if let Some(entry) = self.proxy_stats.lock().unwrap().get_mut(name) {
                entry.bytes_sent += sent;
                entry.bytes_received += received;
            }
        }

        if let Some(d) = domain {
            if let Some(entry) = self.domain_stats.lock().unwrap().get_mut(d) {
                entry.bytes_sent += sent;
                entry.bytes_received += received;
            }
        }
    }

    /// Record a proxy error.
    pub fn record_proxy_error(&self, proxy_name: &str) {
        let mut stats = self.proxy_stats.lock().unwrap();
        let entry = stats
            .entry(proxy_name.to_string())
            .or_insert_with(|| ProxyTraffic {
                proxy_name: proxy_name.to_string(),
                ..Default::default()
            });
        entry.error_count += 1;
    }

    /// Get a snapshot of current traffic statistics.
    pub fn snapshot(&self, top_n: usize) -> StatsSnapshot {
        let mut top_proxies: Vec<ProxyTraffic> =
            self.proxy_stats.lock().unwrap().values().cloned().collect();
        top_proxies.sort_by(|a, b| {
            (b.bytes_sent + b.bytes_received).cmp(&(a.bytes_sent + a.bytes_received))
        });
        top_proxies.truncate(top_n);

        let mut top_domains: Vec<DomainTraffic> =
            self.domain_stats.lock().unwrap().values().cloned().collect();
        top_domains.sort_by(|a, b| {
            (b.bytes_sent + b.bytes_received).cmp(&(a.bytes_sent + a.bytes_received))
        });
        top_domains.truncate(top_n);

        StatsSnapshot {
            total_sent: self.total_sent.load(Ordering::Relaxed),
            total_received: self.total_received.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            top_proxies,
            top_domains,
        }
    }

    /// Reset all statistics.
    pub fn reset(&self) {
        self.total_sent.store(0, Ordering::Relaxed);
        self.total_received.store(0, Ordering::Relaxed);
        self.total_connections.store(0, Ordering::Relaxed);
        self.active_connections.store(0, Ordering::Relaxed);
        self.proxy_stats.lock().unwrap().clear();
        self.domain_stats.lock().unwrap().clear();
    }
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self::new()
    }
}
