use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::dns::DnsMode;
use crate::proxy::{ProxyAuth, ProxyProtocol, ProxyServer};
use crate::rule::Rule;

/// Top-level configuration for OmniLink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// General settings.
    #[serde(default)]
    pub general: GeneralConfig,

    /// Proxy server definitions.
    #[serde(default)]
    pub proxies: Vec<ProxyServerConfig>,

    /// Proxy chains (ordered list of proxy names).
    #[serde(default)]
    pub chains: Vec<ChainConfig>,

    /// Routing rules.
    #[serde(default)]
    pub rules: Vec<Rule>,

    /// DNS settings.
    #[serde(default)]
    pub dns: DnsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Local listen address for the proxy relay.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Enable logging.
    #[serde(default = "default_true")]
    pub logging: bool,

    /// Log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            logging: true,
            log_level: default_log_level(),
        }
    }
}

fn default_listen_addr() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyServerConfig {
    pub name: String,
    pub protocol: ProxyProtocol,
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub auth: Option<ProxyAuth>,
}

impl ProxyServerConfig {
    pub fn to_proxy_server(&self) -> anyhow::Result<ProxyServer> {
        let addr = format!("{}:{}", self.address, self.port).parse()?;
        Ok(ProxyServer {
            name: self.name.clone(),
            protocol: self.protocol.clone(),
            addr,
            auth: self.auth.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub name: String,
    /// Ordered list of proxy names to chain through.
    pub proxies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_dns_mode")]
    pub mode: DnsMode,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            mode: default_dns_mode(),
        }
    }
}

fn default_dns_mode() -> DnsMode {
    DnsMode::FakeIp
}

impl Config {
    /// Load configuration from a YAML file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Generate a default configuration.
    pub fn default_config() -> Self {
        Self {
            general: GeneralConfig::default(),
            proxies: vec![],
            chains: vec![],
            rules: vec![],
            dns: DnsConfig::default(),
        }
    }
}
