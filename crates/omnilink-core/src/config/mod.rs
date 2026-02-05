use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::credential::{CredentialError, CredentialManager};
use crate::dns::DnsMode;
use crate::proxy::{ProxyAuth, ProxyProtocol, ProxyServer};
use crate::rule::{Action, Rule};

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

    /// Default action when no rule matches.
    #[serde(default)]
    pub default_action: Action,
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
    /// Legacy field for backward compatibility. Use `has_auth` instead.
    /// When present, credentials will be migrated to OS keychain on load.
    #[serde(default, skip_serializing)]
    pub auth: Option<ProxyAuth>,
    /// If true, credentials are stored in OS keychain under the proxy name.
    #[serde(default)]
    pub has_auth: bool,
}

impl ProxyServerConfig {
    /// Convert to ProxyServer, retrieving credentials from keychain if needed.
    pub fn to_proxy_server(&self) -> anyhow::Result<ProxyServer> {
        let addr = format!("{}:{}", self.address, self.port).parse()?;

        // Try to get auth from keychain if has_auth is set
        let auth = if self.has_auth {
            match CredentialManager::retrieve(&self.name) {
                Ok((username, password)) => Some(ProxyAuth { username, password }),
                Err(e) => {
                    tracing::warn!(proxy = %self.name, error = %e, "failed to retrieve credentials from keychain");
                    None
                }
            }
        } else {
            // Fallback to legacy auth field (for backward compatibility during migration)
            self.auth.clone()
        };

        Ok(ProxyServer {
            name: self.name.clone(),
            protocol: self.protocol.clone(),
            addr,
            auth,
        })
    }
}

/// Proxy chain selection strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainMode {
    /// All proxies in order; fail if any is unreachable.
    Strict,
    /// Try proxies in order; use the first reachable one (failover).
    Failover,
    /// Distribute connections across proxies.
    RoundRobin,
    /// Randomly select a proxy for each connection.
    Random,
}

impl Default for ChainMode {
    fn default() -> Self {
        Self::Strict
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub name: String,
    /// Ordered list of proxy names to chain through.
    pub proxies: Vec<String>,
    /// How to select proxies from the list.
    #[serde(default)]
    pub mode: ChainMode,
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
            default_action: Action::Direct,
        }
    }

    /// Migrate legacy plaintext credentials to OS keychain.
    ///
    /// Returns the list of proxy names that were migrated.
    /// After migration, call `save()` to persist the updated config.
    pub fn migrate_credentials(&mut self) -> Result<Vec<String>, CredentialError> {
        let mut migrated = Vec::new();

        for proxy in &mut self.proxies {
            if let Some(auth) = proxy.auth.take() {
                CredentialManager::store(&proxy.name, &auth.username, &auth.password)?;
                proxy.has_auth = true;
                migrated.push(proxy.name.clone());
            }
        }

        Ok(migrated)
    }

    /// Check if any proxies have legacy plaintext credentials that need migration.
    pub fn needs_credential_migration(&self) -> bool {
        self.proxies.iter().any(|p| p.auth.is_some())
    }
}

/// Configuration for the OS-level traffic interceptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptorConfig {
    /// Enable the interceptor.
    #[serde(default)]
    pub enabled: bool,
    /// TUN device address (default: 10.0.0.1).
    #[serde(default = "default_tun_addr")]
    pub tun_addr: String,
    /// MTU for the TUN device.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

impl Default for InterceptorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tun_addr: default_tun_addr(),
            mtu: default_mtu(),
        }
    }
}

fn default_tun_addr() -> String {
    "10.0.0.1".to_string()
}

fn default_mtu() -> u16 {
    1500
}

/// Configuration profile: a named, switchable set of settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub config: Config,
}

impl Profile {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let profile: Profile = serde_yaml::from_str(&content)?;
        Ok(profile)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let yaml = serde_yaml::to_string(self)?;
        std::fs::write(path, yaml)?;
        Ok(())
    }
}
