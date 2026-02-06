use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::sync::Mutex;

use omnilink_core::config::{Config, ChainConfig, ProxyServerConfig};
use omnilink_core::dns::VirtualDns;
use omnilink_core::proxy::chain::ChainRelay;
use omnilink_core::rule::{Action, Condition, Rule, RuleEngine};
use omnilink_core::session::SessionManager;
use omnilink_core::stats::TrafficStats;
use omnilink_core::sysproxy::SysProxyConfig;

/// Write config to disk (best-effort, errors logged).
fn auto_save(state: &AppStateInner) {
    if let Some(config) = &state.config {
        match serde_yaml::to_string(config) {
            Ok(yaml) => {
                if let Err(e) = std::fs::write(&state.config_path, &yaml) {
                    tracing::warn!(path = %state.config_path.display(), error = %e, "failed to auto-save config");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize config for auto-save");
            }
        }
    }
}

/// Shared application state managed by Tauri.
pub struct AppStateInner {
    running: bool,
    config: Option<Config>,
    config_path: PathBuf,
    session_manager: Arc<SessionManager>,
    traffic_stats: Arc<TrafficStats>,
    /// Handle to the running service task (so we can abort it).
    service_handle: Option<tokio::task::JoinHandle<()>>,
    rule_engine: Option<Arc<std::sync::RwLock<RuleEngine>>>,
    virtual_dns: Arc<VirtualDns>,
    chain_relay: Option<Arc<ChainRelay>>,
    sysproxy_enabled: bool,
    /// Abort handles for individual connections, keyed by session ID.
    connection_handles: Arc<tokio::sync::Mutex<HashMap<u64, tokio_util::sync::CancellationToken>>>,
    /// Handle to the running interceptor task.
    interceptor_handle: Option<tokio::task::JoinHandle<()>>,
    interceptor_running: bool,
    /// NE interceptor instance (for stopping the socket server).
    ne_interceptor: Option<Box<dyn omnilink_tun::interceptor::Interceptor>>,
    ne_server_running: bool,
}

pub type SharedState = Mutex<AppStateInner>;

#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: u64,
    pub status: String,
    pub process_name: Option<String>,
    pub destination: String,
    pub proxy_name: Option<String>,
    pub action: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct StatusInfo {
    pub running: bool,
    pub listen_addr: String,
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_sent: u64,
    pub total_received: u64,
    pub dns_mode: String,
}

#[derive(Debug, Serialize)]
pub struct ProxyInfo {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub auth: bool,
}

#[tauri::command]
async fn get_sessions(state: State<'_, SharedState>) -> Result<Vec<SessionInfo>, String> {
    let state = state.lock().await;
    let sessions = state.session_manager.get_sessions();
    Ok(sessions
        .into_iter()
        .map(|s| {
            let status_str = match &s.status {
                omnilink_core::session::SessionStatus::Connecting => "connecting".to_string(),
                omnilink_core::session::SessionStatus::Active => "active".to_string(),
                omnilink_core::session::SessionStatus::Closed => "closed".to_string(),
                omnilink_core::session::SessionStatus::Error(e) => format!("error: {}", e),
            };
            SessionInfo {
                id: s.id,
                status: status_str,
                process_name: s.process_name,
                destination: s.destination,
                proxy_name: s.proxy_name,
                action: s.action,
                bytes_sent: s.bytes_sent,
                bytes_received: s.bytes_received,
                elapsed_ms: s.elapsed_ms,
            }
        })
        .collect())
}

#[tauri::command]
async fn clear_closed_sessions(state: State<'_, SharedState>) -> Result<String, String> {
    let state = state.lock().await;
    state.session_manager.clear_closed();
    Ok("Closed sessions cleared".to_string())
}

#[tauri::command]
async fn get_status(state: State<'_, SharedState>) -> Result<StatusInfo, String> {
    let state = state.lock().await;
    let snapshot = state.traffic_stats.snapshot(0);

    let listen_addr = state
        .config
        .as_ref()
        .map(|c| c.general.listen_addr.clone())
        .unwrap_or_else(|| "127.0.0.1:1080".to_string());

    let dns_mode = state
        .config
        .as_ref()
        .map(|c| format!("{:?}", c.dns.mode))
        .unwrap_or_else(|| "FakeIp".to_string());

    Ok(StatusInfo {
        running: state.running,
        listen_addr,
        total_connections: snapshot.total_connections,
        active_connections: snapshot.active_connections,
        total_sent: snapshot.total_sent,
        total_received: snapshot.total_received,
        dns_mode,
    })
}

#[tauri::command]
async fn get_proxies(state: State<'_, SharedState>) -> Result<Vec<ProxyInfo>, String> {
    let state = state.lock().await;
    let config = match &state.config {
        Some(c) => c,
        None => return Ok(vec![]),
    };
    Ok(config
        .proxies
        .iter()
        .map(|p| ProxyInfo {
            name: p.name.clone(),
            protocol: format!("{:?}", p.protocol),
            address: p.address.clone(),
            port: p.port,
            auth: p.auth.is_some(),
        })
        .collect())
}

#[tauri::command]
async fn load_config(
    state: State<'_, SharedState>,
    path: Option<String>,
) -> Result<String, String> {
    let mut state = state.lock().await;
    let config_path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| state.config_path.clone());

    let config = Config::load(&config_path).map_err(|e| e.to_string())?;
    state.config = Some(config);
    state.config_path = config_path;
    Ok("Configuration loaded".to_string())
}

#[tauri::command]
async fn start_service(state: State<'_, SharedState>) -> Result<String, String> {
    let mut state_guard = state.lock().await;

    if state_guard.running {
        return Err("Service is already running".to_string());
    }

    let config = state_guard
        .config
        .clone()
        .ok_or("No configuration loaded")?;

    let listen_addr = config.general.listen_addr.clone();

    // Build rule engine
    let rule_engine = Arc::new(std::sync::RwLock::new(RuleEngine::with_default_action(
        config.rules.clone(),
        config.default_action.clone(),
    )));
    state_guard.rule_engine = Some(rule_engine.clone());

    // Build proxy map and chain relay
    let mut proxy_map = HashMap::new();
    for proxy_cfg in &config.proxies {
        let server = proxy_cfg.to_proxy_server().map_err(|e| e.to_string())?;
        proxy_map.insert(proxy_cfg.name.clone(), server);
    }
    let chain_relay = Arc::new(ChainRelay::new(config.chains.clone(), proxy_map));
    state_guard.chain_relay = Some(chain_relay.clone());

    let virtual_dns = state_guard.virtual_dns.clone();
    let session_manager = state_guard.session_manager.clone();
    let traffic_stats = state_guard.traffic_stats.clone();
    let connection_handles = state_guard.connection_handles.clone();

    // Spawn bandwidth sampling task (1 sample per second)
    let bw_stats = state_guard.traffic_stats.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            bw_stats.sample_bandwidth();
        }
    });

    let (startup_tx, startup_rx) = tokio::sync::oneshot::channel();

    let listen_addr_display = config.general.listen_addr.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = run_service(
            &listen_addr,
            rule_engine,
            virtual_dns,
            chain_relay,
            session_manager,
            traffic_stats,
            connection_handles,
            startup_tx,
        )
        .await
        {
            tracing::error!(error = %e, "service error");
        }
    });

    // Drop the lock before awaiting startup, then re-acquire
    drop(state_guard);

    // Wait for listener bind result
    let bind_result = startup_rx.await.unwrap_or(Err("Service task exited unexpectedly".to_string()));
    let mut state_guard = state.lock().await;

    match bind_result {
        Ok(()) => {
            state_guard.running = true;
            state_guard.service_handle = Some(handle);
            Ok(format!("Service started on {}", listen_addr_display))
        }
        Err(e) => {
            handle.abort();
            Err(e)
        }
    }
}

#[tauri::command]
async fn stop_service(state: State<'_, SharedState>) -> Result<String, String> {
    let mut state_guard = state.lock().await;

    if !state_guard.running {
        return Err("Service is not running".to_string());
    }

    if let Some(handle) = state_guard.service_handle.take() {
        handle.abort();
    }

    // Auto-disable system proxy so traffic isn't blocked
    if state_guard.sysproxy_enabled {
        if let Some(config) = state_guard.config.as_ref() {
            let listen = &config.general.listen_addr;
            let parts: Vec<&str> = listen.split(':').collect();
            let host = parts.first().copied().unwrap_or("127.0.0.1");
            let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(1080);
            let sysproxy = SysProxyConfig::new(host, port);
            if let Err(e) = sysproxy.disable() {
                tracing::warn!(error = %e, "failed to disable system proxy on stop");
            }
            state_guard.sysproxy_enabled = false;
        }
    }

    state_guard.running = false;
    Ok("Service stopped".to_string())
}

#[tauri::command]
async fn get_traffic_stats(
    state: State<'_, SharedState>,
) -> Result<omnilink_core::stats::StatsSnapshot, String> {
    let state = state.lock().await;
    Ok(state.traffic_stats.snapshot(20))
}

#[tauri::command]
async fn reset_stats(state: State<'_, SharedState>) -> Result<String, String> {
    let state = state.lock().await;
    state.traffic_stats.reset();
    Ok("Statistics reset".to_string())
}

// --- Rules CRUD ---

#[derive(Debug, Serialize)]
pub struct RuleInfo {
    pub index: usize,
    pub name: String,
    pub conditions: Vec<String>,
    pub action: String,
    pub priority: i32,
    pub enabled: bool,
}

fn format_condition(cond: &Condition) -> String {
    match cond {
        Condition::ProcessName(p) => format!("process_name: {}", p),
        Condition::ProcessPath(p) => format!("process_path: {}", p),
        Condition::Domain(d) => format!("domain: {}", d),
        Condition::Cidr(c) => format!("cidr: {}", c),
        Condition::Port(p) => format!("port: {}", p),
        Condition::PortRange(a, b) => format!("port_range: {}-{}", a, b),
        Condition::User(u) => format!("user: {}", u),
        Condition::Loopback => "loopback".to_string(),
    }
}

fn format_action(action: &Action) -> String {
    match action {
        Action::Direct => "Direct".to_string(),
        Action::Proxy(name) => format!("Proxy: {}", name),
        Action::Block => "Block".to_string(),
    }
}

#[tauri::command]
async fn get_rules(state: State<'_, SharedState>) -> Result<Vec<RuleInfo>, String> {
    let state = state.lock().await;
    let config = match &state.config {
        Some(c) => c,
        None => return Ok(vec![]),
    };
    Ok(config
        .rules
        .iter()
        .enumerate()
        .map(|(i, r)| RuleInfo {
            index: i,
            name: r.name.clone(),
            conditions: r.conditions.iter().map(format_condition).collect(),
            action: format_action(&r.action),
            priority: r.priority,
            enabled: r.enabled,
        })
        .collect())
}

#[derive(Debug, Deserialize)]
pub struct AddRuleRequest {
    pub name: String,
    pub conditions: Vec<ConditionInput>,
    pub action: String,
    pub proxy_name: Option<String>,
    pub priority: i32,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum ConditionInput {
    #[serde(rename = "process_name")]
    ProcessName(String),
    #[serde(rename = "domain")]
    Domain(String),
    #[serde(rename = "cidr")]
    Cidr(String),
    #[serde(rename = "port")]
    Port(u16),
    #[serde(rename = "port_range")]
    PortRange([u16; 2]),
}

fn parse_condition(input: &ConditionInput) -> Condition {
    match input {
        ConditionInput::ProcessName(v) => Condition::ProcessName(v.clone()),
        ConditionInput::Domain(v) => Condition::Domain(v.clone()),
        ConditionInput::Cidr(v) => Condition::Cidr(v.clone()),
        ConditionInput::Port(v) => Condition::Port(*v),
        ConditionInput::PortRange(v) => Condition::PortRange(v[0], v[1]),
    }
}

fn parse_action(action: &str, proxy_name: Option<&str>) -> Action {
    match action {
        "block" => Action::Block,
        "proxy" => Action::Proxy(proxy_name.unwrap_or("default").to_string()),
        _ => Action::Direct,
    }
}

#[tauri::command]
async fn add_rule(state: State<'_, SharedState>, req: AddRuleRequest) -> Result<String, String> {
    if req.name.trim().is_empty() {
        return Err("Rule name cannot be empty".to_string());
    }
    if req.conditions.is_empty() {
        return Err("Rule must have at least one condition".to_string());
    }

    let mut state = state.lock().await;
    let (rules_snapshot, default_action) = {
        let config = state.config.as_mut().ok_or("No configuration loaded")?;
        let rule = Rule {
            name: req.name,
            conditions: req.conditions.iter().map(parse_condition).collect(),
            action: parse_action(&req.action, req.proxy_name.as_deref()),
            priority: req.priority,
            enabled: true,
            dns_mode: None,
        };
        config.rules.push(rule);
        (config.rules.clone(), config.default_action.clone())
    };

    // Sync to running rule engine
    if let Some(re) = &state.rule_engine {
        *re.write().unwrap_or_else(|e| e.into_inner()) = RuleEngine::with_default_action(rules_snapshot, default_action);
    }

    auto_save(&state);
    Ok("Rule added".to_string())
}

#[tauri::command]
async fn toggle_rule(state: State<'_, SharedState>, index: usize) -> Result<String, String> {
    let mut state = state.lock().await;
    let (msg, rules_snapshot, default_action) = {
        let config = state.config.as_mut().ok_or("No configuration loaded")?;
        let rule = config.rules.get_mut(index).ok_or("Rule not found")?;
        rule.enabled = !rule.enabled;
        let msg = format!("Rule '{}' {}", rule.name, if rule.enabled { "enabled" } else { "disabled" });
        (msg, config.rules.clone(), config.default_action.clone())
    };

    // Sync to running rule engine
    if let Some(re) = &state.rule_engine {
        *re.write().unwrap_or_else(|e| e.into_inner()) = RuleEngine::with_default_action(rules_snapshot, default_action);
    }

    auto_save(&state);
    Ok(msg)
}

#[tauri::command]
async fn delete_rule(state: State<'_, SharedState>, index: usize) -> Result<String, String> {
    let mut state = state.lock().await;
    let (msg, rules_snapshot, default_action) = {
        let config = state.config.as_mut().ok_or("No configuration loaded")?;
        if index >= config.rules.len() {
            return Err("Rule not found".to_string());
        }
        let removed = config.rules.remove(index);
        let msg = format!("Rule '{}' deleted", removed.name);
        (msg, config.rules.clone(), config.default_action.clone())
    };

    // Sync to running rule engine
    if let Some(re) = &state.rule_engine {
        *re.write().unwrap_or_else(|e| e.into_inner()) = RuleEngine::with_default_action(rules_snapshot, default_action);
    }

    auto_save(&state);
    Ok(msg)
}

// --- Proxy CRUD ---

#[derive(Debug, Deserialize)]
pub struct AddProxyRequest {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[tauri::command]
async fn add_proxy(state: State<'_, SharedState>, req: AddProxyRequest) -> Result<String, String> {
    if req.name.trim().is_empty() {
        return Err("Proxy name cannot be empty".to_string());
    }
    if req.address.trim().is_empty() {
        return Err("Proxy address cannot be empty".to_string());
    }
    if req.port == 0 {
        return Err("Port must be between 1 and 65535".to_string());
    }

    let mut state = state.lock().await;
    let config = state.config.as_mut().ok_or("No configuration loaded")?;

    if config.proxies.iter().any(|p| p.name == req.name) {
        return Err(format!("Proxy '{}' already exists", req.name));
    }

    let protocol = match req.protocol.to_lowercase().as_str() {
        "socks4" => omnilink_core::proxy::ProxyProtocol::Socks4,
        "socks4a" => omnilink_core::proxy::ProxyProtocol::Socks4a,
        "socks5" => omnilink_core::proxy::ProxyProtocol::Socks5,
        "http" => omnilink_core::proxy::ProxyProtocol::Http,
        "https" => omnilink_core::proxy::ProxyProtocol::Https,
        "ssh" | "ssh_tunnel" => omnilink_core::proxy::ProxyProtocol::SshTunnel,
        _ => return Err(format!("Unknown protocol: {}", req.protocol)),
    };

    // Store credentials in OS keychain if provided
    let has_auth = match (req.username, req.password) {
        (Some(u), Some(p)) if !u.is_empty() => {
            omnilink_core::credential::CredentialManager::store(&req.name, &u, &p)
                .map_err(|e| e.to_string())?;
            true
        }
        _ => false,
    };

    config.proxies.push(ProxyServerConfig {
        name: req.name.clone(),
        protocol,
        address: req.address,
        port: req.port,
        auth: None, // No longer stored in config
        has_auth,
    });

    auto_save(&state);
    Ok(format!("Proxy '{}' added", req.name))
}

#[tauri::command]
async fn delete_proxy(state: State<'_, SharedState>, name: String) -> Result<String, String> {
    let mut state = state.lock().await;
    let config = state.config.as_mut().ok_or("No configuration loaded")?;

    // Find and check if proxy has credentials
    let proxy = config.proxies.iter().find(|p| p.name == name);
    if let Some(p) = proxy {
        if p.has_auth {
            // Delete credentials from keychain (ignore errors)
            let _ = omnilink_core::credential::CredentialManager::delete(&name);
        }
    }

    let before = config.proxies.len();
    config.proxies.retain(|p| p.name != name);
    if config.proxies.len() == before {
        return Err(format!("Proxy '{}' not found", name));
    }
    auto_save(&state);
    Ok(format!("Proxy '{}' deleted", name))
}

// --- Chains ---

#[derive(Debug, Serialize)]
pub struct ChainInfo {
    pub name: String,
    pub proxies: Vec<String>,
    pub mode: String,
}

#[tauri::command]
async fn get_chains(state: State<'_, SharedState>) -> Result<Vec<ChainInfo>, String> {
    let state = state.lock().await;
    let config = match &state.config {
        Some(c) => c,
        None => return Ok(vec![]),
    };
    Ok(config
        .chains
        .iter()
        .map(|c| ChainInfo {
            name: c.name.clone(),
            proxies: c.proxies.clone(),
            mode: format!("{:?}", c.mode),
        })
        .collect())
}

#[derive(Debug, Deserialize)]
pub struct AddChainRequest {
    pub name: String,
    pub proxies: Vec<String>,
    pub mode: String,
}

#[tauri::command]
async fn add_chain(state: State<'_, SharedState>, req: AddChainRequest) -> Result<String, String> {
    if req.name.trim().is_empty() {
        return Err("Chain name cannot be empty".to_string());
    }
    if req.proxies.is_empty() {
        return Err("Chain must contain at least one proxy".to_string());
    }

    let mut state = state.lock().await;
    let config = state.config.as_mut().ok_or("No configuration loaded")?;

    // Validate that all referenced proxies exist
    for proxy_name in &req.proxies {
        if !config.proxies.iter().any(|p| &p.name == proxy_name) {
            return Err(format!("Proxy '{}' not found", proxy_name));
        }
    }

    let mode = match req.mode.to_lowercase().as_str() {
        "failover" => omnilink_core::config::ChainMode::Failover,
        "round_robin" | "roundrobin" => omnilink_core::config::ChainMode::RoundRobin,
        "random" => omnilink_core::config::ChainMode::Random,
        _ => omnilink_core::config::ChainMode::Strict,
    };

    config.chains.push(ChainConfig {
        name: req.name.clone(),
        proxies: req.proxies,
        mode,
    });

    auto_save(&state);
    Ok(format!("Chain '{}' added", req.name))
}

#[tauri::command]
async fn delete_chain(state: State<'_, SharedState>, name: String) -> Result<String, String> {
    let mut state = state.lock().await;
    let config = state.config.as_mut().ok_or("No configuration loaded")?;
    let before = config.chains.len();
    config.chains.retain(|c| c.name != name);
    if config.chains.len() == before {
        return Err(format!("Chain '{}' not found", name));
    }
    auto_save(&state);
    Ok(format!("Chain '{}' deleted", name))
}

// --- System proxy ---

#[tauri::command]
async fn toggle_sysproxy(state: State<'_, SharedState>) -> Result<String, String> {
    let mut state = state.lock().await;
    let config = state.config.as_ref().ok_or("No configuration loaded")?;
    let listen = &config.general.listen_addr;

    let parts: Vec<&str> = listen.split(':').collect();
    let host = parts.first().copied().unwrap_or("127.0.0.1");
    let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(1080);

    let sysproxy = SysProxyConfig::new(host, port);

    if state.sysproxy_enabled {
        sysproxy.disable().map_err(|e| e.to_string())?;
        state.sysproxy_enabled = false;
        Ok("System proxy disabled".to_string())
    } else {
        sysproxy.enable().map_err(|e| e.to_string())?;
        state.sysproxy_enabled = true;
        Ok("System proxy enabled".to_string())
    }
}

#[tauri::command]
async fn get_sysproxy_status(state: State<'_, SharedState>) -> Result<bool, String> {
    let state = state.lock().await;
    Ok(state.sysproxy_enabled)
}

// --- Connection termination ---

#[tauri::command]
async fn terminate_session(state: State<'_, SharedState>, session_id: u64) -> Result<String, String> {
    let state = state.lock().await;
    let handles = state.connection_handles.lock().await;
    if let Some(token) = handles.get(&session_id) {
        token.cancel();
        Ok(format!("Session {} terminated", session_id))
    } else {
        Err(format!("Session {} not found or already closed", session_id))
    }
}

// --- Profiles ---

#[derive(Debug, Serialize)]
pub struct ProfileInfo {
    pub name: String,
    pub path: String,
    pub active: bool,
}

#[tauri::command]
async fn get_profiles(state: State<'_, SharedState>) -> Result<Vec<ProfileInfo>, String> {
    let state = state.lock().await;
    let profiles_dir = state.config_path.parent().unwrap_or(std::path::Path::new(".")).join("profiles");
    let mut profiles = Vec::new();

    // Always include the current config as "default" profile
    let current_name = state.config_path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("default")
        .to_string();

    profiles.push(ProfileInfo {
        name: current_name.clone(),
        path: state.config_path.display().to_string(),
        active: true,
    });

    // Scan profiles directory for .yaml files
    if profiles_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&profiles_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                    let name = path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    if name != current_name {
                        profiles.push(ProfileInfo {
                            name,
                            path: path.display().to_string(),
                            active: false,
                        });
                    }
                }
            }
        }
    }

    Ok(profiles)
}

#[tauri::command]
async fn switch_profile(state: State<'_, SharedState>, path: String) -> Result<String, String> {
    let mut state = state.lock().await;

    if state.running {
        return Err("Stop the service before switching profiles".to_string());
    }

    let config_path = PathBuf::from(&path);
    let config = Config::load(&config_path).map_err(|e| format!("Failed to load profile: {}", e))?;
    let profile_name = config_path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    state.config = Some(config);
    state.config_path = config_path;

    Ok(format!("Switched to profile '{}'", profile_name))
}

#[tauri::command]
async fn save_profile(state: State<'_, SharedState>, name: String) -> Result<String, String> {
    let state = state.lock().await;
    let config = state.config.as_ref().ok_or("No configuration loaded")?;

    let profiles_dir = state.config_path.parent().unwrap_or(std::path::Path::new(".")).join("profiles");
    std::fs::create_dir_all(&profiles_dir).map_err(|e| e.to_string())?;

    let profile_path = profiles_dir.join(format!("{}.yaml", name));
    let yaml = serde_yaml::to_string(config).map_err(|e| e.to_string())?;
    std::fs::write(&profile_path, yaml).map_err(|e| e.to_string())?;

    Ok(format!("Profile '{}' saved to {}", name, profile_path.display()))
}

// --- Save config ---

#[tauri::command]
async fn save_config(state: State<'_, SharedState>) -> Result<String, String> {
    let state = state.lock().await;
    let config = state.config.as_ref().ok_or("No configuration loaded")?;
    let yaml = serde_yaml::to_string(config).map_err(|e| e.to_string())?;
    std::fs::write(&state.config_path, yaml).map_err(|e| e.to_string())?;
    Ok(format!("Configuration saved to {}", state.config_path.display()))
}

#[tauri::command]
async fn save_config_to(state: State<'_, SharedState>, path: String) -> Result<String, String> {
    let state = state.lock().await;
    let config = state.config.as_ref().ok_or("No configuration loaded")?;
    let yaml = serde_yaml::to_string(config).map_err(|e| e.to_string())?;
    std::fs::write(&path, yaml).map_err(|e| e.to_string())?;
    Ok(format!("Configuration saved to {}", path))
}

// --- Interceptor ---

#[tauri::command]
async fn start_interceptor(state: State<'_, SharedState>) -> Result<String, String> {
    let mut state_guard = state.lock().await;

    if state_guard.interceptor_running {
        return Err("Interceptor is already running".to_string());
    }

    let config = state_guard
        .config
        .clone()
        .ok_or("No configuration loaded")?;

    // Build rule engine
    let rule_engine = Arc::new(RuleEngine::with_default_action(
        config.rules.clone(),
        config.default_action.clone(),
    ));

    // Build proxy map and chain relay
    let mut proxy_map = HashMap::new();
    for proxy_cfg in &config.proxies {
        let server = proxy_cfg.to_proxy_server().map_err(|e| e.to_string())?;
        proxy_map.insert(proxy_cfg.name.clone(), server);
    }
    let chain_relay = Arc::new(ChainRelay::new(config.chains.clone(), proxy_map));

    // Collect excluded IPs
    let mut excluded_ips = Vec::new();
    for proxy_cfg in &config.proxies {
        if let Ok(ip) = proxy_cfg.address.parse::<std::net::Ipv4Addr>() {
            excluded_ips.push(ip);
        }
    }

    let virtual_dns = state_guard.virtual_dns.clone();
    let mut interceptor = omnilink_tun::create_interceptor(virtual_dns.clone(), excluded_ips);

    let mut event_rx = interceptor
        .start()
        .await
        .map_err(|e| e.to_string())?;

    let handle = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match event {
                omnilink_tun::interceptor::InterceptorEvent::NewConnection(conn, mut inbound) => {
                    let rule_engine = rule_engine.clone();
                    let virtual_dns = virtual_dns.clone();
                    let chain_relay = chain_relay.clone();

                    tokio::spawn(async move {
                        use omnilink_core::proxy::ProxyDestination;
                        use omnilink_core::rule::MatchContext;

                        let dst_ip = conn.original_dst.ip();
                        let dst_port = conn.original_dst.port();
                        let domain = virtual_dns.lookup(dst_ip);

                        let dest = if let Some(ref d) = domain {
                            ProxyDestination::Domain(d.clone(), dst_port)
                        } else {
                            ProxyDestination::SocketAddr(conn.original_dst)
                        };

                        let ctx = MatchContext {
                            process_name: conn.process_name.clone(),
                            process_path: conn.process_path.clone(),
                            process_user: None,
                            dest_domain: domain,
                            dest_ip: Some(dst_ip),
                            dest_port: dst_port,
                        };

                        let action = rule_engine.evaluate(&ctx);

                        match action {
                            Action::Block => {}
                            Action::Direct => {
                                let target = match &dest {
                                    ProxyDestination::SocketAddr(a) => a.to_string(),
                                    ProxyDestination::Domain(d, p) => format!("{}:{}", d, p),
                                };
                                if let Ok(mut outbound) =
                                    tokio::net::TcpStream::connect(&target).await
                                {
                                    let (mut ri, mut wi) = inbound.split();
                                    let (mut ro, mut wo) = outbound.split();
                                    let _ = tokio::try_join!(
                                        tokio::io::copy(&mut ri, &mut wo),
                                        tokio::io::copy(&mut ro, &mut wi),
                                    );
                                }
                            }
                            Action::Proxy(ref pname) => {
                                if let Ok(mut outbound) =
                                    chain_relay.connect(pname, &dest).await
                                {
                                    let (mut ri, mut wi) = inbound.split();
                                    let (mut ro, mut wo) = outbound.split();
                                    let _ = tokio::try_join!(
                                        tokio::io::copy(&mut ri, &mut wo),
                                        tokio::io::copy(&mut ro, &mut wi),
                                    );
                                }
                            }
                        }
                    });
                }
                omnilink_tun::interceptor::InterceptorEvent::NewUdpPacket(packet) => {
                    // TODO: Handle UDP packets through proxy chain
                    tracing::debug!(
                        src = %packet.src_addr,
                        dst = %packet.original_dst,
                        len = packet.data.len(),
                        process = ?packet.process_name,
                        "intercepted UDP packet"
                    );
                }
            }
        }
    });

    state_guard.interceptor_handle = Some(handle);
    state_guard.interceptor_running = true;

    Ok("Interceptor started".to_string())
}

#[tauri::command]
async fn stop_interceptor(state: State<'_, SharedState>) -> Result<String, String> {
    let mut state_guard = state.lock().await;

    if !state_guard.interceptor_running {
        return Err("Interceptor is not running".to_string());
    }

    if let Some(handle) = state_guard.interceptor_handle.take() {
        handle.abort();
    }

    state_guard.interceptor_running = false;
    Ok("Interceptor stopped".to_string())
}

#[tauri::command]
async fn get_interceptor_status(state: State<'_, SharedState>) -> Result<bool, String> {
    let state = state.lock().await;
    Ok(state.interceptor_running)
}

// --- Credential Management ---

#[tauri::command]
async fn set_proxy_credentials(
    proxy_name: String,
    username: String,
    password: String,
) -> Result<(), String> {
    omnilink_core::credential::CredentialManager::store(&proxy_name, &username, &password)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_proxy_credentials(proxy_name: String) -> Result<(), String> {
    omnilink_core::credential::CredentialManager::delete(&proxy_name)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn has_proxy_credentials(proxy_name: String) -> Result<bool, String> {
    Ok(omnilink_core::credential::CredentialManager::exists(&proxy_name))
}

#[tauri::command]
async fn migrate_credentials(state: State<'_, SharedState>) -> Result<Vec<String>, String> {
    let mut state_guard = state.lock().await;
    let config = state_guard
        .config
        .as_mut()
        .ok_or("No configuration loaded")?;

    config.migrate_credentials().map_err(|e| e.to_string())
}

async fn run_service(
    listen_addr: &str,
    rule_engine: Arc<std::sync::RwLock<RuleEngine>>,
    virtual_dns: Arc<VirtualDns>,
    chain_relay: Arc<ChainRelay>,
    session_manager: Arc<SessionManager>,
    traffic_stats: Arc<TrafficStats>,
    connection_handles: Arc<tokio::sync::Mutex<HashMap<u64, tokio_util::sync::CancellationToken>>>,
    startup_tx: tokio::sync::oneshot::Sender<Result<(), String>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(l) => {
            let _ = startup_tx.send(Ok(()));
            l
        }
        Err(e) => {
            let _ = startup_tx.send(Err(format!("Failed to bind {}: {}", listen_addr, e)));
            return Err(e.into());
        }
    };
    tracing::info!(addr = %listen_addr, "tauri service listening");

    loop {
        let (mut inbound, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed, retrying");
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                continue;
            }
        };
        tracing::debug!(peer = %peer_addr, "accepted connection");

        let rule_engine = rule_engine.clone();
        let virtual_dns = virtual_dns.clone();
        let chain_relay = chain_relay.clone();
        let session_manager = session_manager.clone();
        let traffic_stats = traffic_stats.clone();
        let connection_handles = connection_handles.clone();

        tokio::spawn(async move {
            let result = handle_connection(
                &mut inbound,
                peer_addr,
                &rule_engine,
                &virtual_dns,
                &chain_relay,
                &session_manager,
                &traffic_stats,
                &connection_handles,
            )
            .await;

            if let Err(e) = result {
                tracing::error!(peer = %peer_addr, error = %e, "connection error");
            }
        });
    }
}

async fn handle_connection(
    inbound: &mut tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    rule_engine: &std::sync::RwLock<RuleEngine>,
    virtual_dns: &VirtualDns,
    chain_relay: &ChainRelay,
    session_manager: &SessionManager,
    traffic_stats: &TrafficStats,
    connection_handles: &Arc<tokio::sync::Mutex<HashMap<u64, tokio_util::sync::CancellationToken>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use omnilink_core::proxy::ProxyDestination;
    use omnilink_core::rule::{Action, MatchContext};
    use omnilink_core::session::SessionStatus;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // SOCKS5 handshake
    let mut buf = [0u8; 2];
    inbound.read_exact(&mut buf).await?;

    if buf[0] != 0x05 {
        return Err("not a SOCKS5 request".into());
    }

    let n_methods = buf[1] as usize;
    let mut methods = vec![0u8; n_methods];
    inbound.read_exact(&mut methods).await?;
    inbound.write_all(&[0x05, 0x00]).await?;

    // Read connect request
    let mut header = [0u8; 4];
    inbound.read_exact(&mut header).await?;

    if header[1] != 0x01 {
        inbound
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(format!("unsupported SOCKS5 command: {}", header[1]).into());
    }

    let (dest, dest_ip, dest_domain) = match header[3] {
        0x01 => {
            let mut addr = [0u8; 6];
            inbound.read_exact(&mut addr).await?;
            let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            let port = u16::from_be_bytes([addr[4], addr[5]]);
            let ip_addr = std::net::IpAddr::V4(ip);
            let domain = virtual_dns.lookup(ip_addr);
            let dest = if let Some(ref d) = domain {
                ProxyDestination::Domain(d.clone(), port)
            } else {
                ProxyDestination::SocketAddr(std::net::SocketAddr::new(ip_addr, port))
            };
            (dest, Some(ip_addr), domain)
        }
        0x03 => {
            let mut len = [0u8; 1];
            inbound.read_exact(&mut len).await?;
            let mut domain_bytes = vec![0u8; len[0] as usize];
            inbound.read_exact(&mut domain_bytes).await?;
            let mut port_bytes = [0u8; 2];
            inbound.read_exact(&mut port_bytes).await?;
            let domain = String::from_utf8_lossy(&domain_bytes).to_string();
            let port = u16::from_be_bytes(port_bytes);
            (
                ProxyDestination::Domain(domain.clone(), port),
                None,
                Some(domain),
            )
        }
        0x04 => {
            let mut addr = [0u8; 18];
            inbound.read_exact(&mut addr).await?;
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&addr[..16]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([addr[16], addr[17]]);
            let ip_addr = std::net::IpAddr::V6(ip);
            (
                ProxyDestination::SocketAddr(std::net::SocketAddr::new(ip_addr, port)),
                Some(ip_addr),
                None,
            )
        }
        _ => {
            inbound
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err("unsupported address type".into());
        }
    };

    let port = match &dest {
        ProxyDestination::SocketAddr(a) => a.port(),
        ProxyDestination::Domain(_, p) => *p,
    };

    // Look up the originating process from the SOCKS5 client's source port.
    let proc_info = match tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        tokio::task::spawn_blocking(move || {
            omnilink_tun::process::lookup_process_by_socket(&peer_addr)
        }),
    )
    .await
    {
        Ok(Ok(info)) => info,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "process lookup task failed");
            None
        }
        Err(_) => {
            tracing::warn!(peer = %peer_addr, "process lookup timed out (2s)");
            None
        }
    };

    let process_name = proc_info.as_ref().map(|p| p.name.clone());
    let process_path = proc_info.as_ref().map(|p| p.path.clone());

    let ctx = MatchContext {
        process_name: process_name.clone(),
        process_path: process_path.clone(),
        process_user: None,
        dest_domain: dest_domain.clone(),
        dest_ip,
        dest_port: port,
    };

    let action = rule_engine.read().unwrap_or_else(|e| e.into_inner()).evaluate(&ctx);
    tracing::info!(dest = %dest, process = ?process_name, action = ?action, "routing decision");

    let proxy_name = match &action {
        Action::Proxy(name) => Some(name.clone()),
        _ => None,
    };

    let session_id =
        session_manager.create_session(dest.to_string(), &action, proxy_name.clone());
    session_manager.set_process_name(session_id, process_name, process_path);
    traffic_stats.record_connection_open(
        proxy_name.as_deref(),
        dest_domain.as_deref(),
    );

    // Register a cancellation token for this session
    let cancel_token = tokio_util::sync::CancellationToken::new();
    connection_handles
        .lock()
        .await
        .insert(session_id, cancel_token.clone());

    let result = match action {
        Action::Block => {
            inbound
                .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            session_manager.update_status(session_id, SessionStatus::Closed);
            traffic_stats.record_connection_close();
            Ok(())
        }
        Action::Direct => {
            let target_addr = match &dest {
                ProxyDestination::SocketAddr(a) => a.to_string(),
                ProxyDestination::Domain(d, p) => format!("{}:{}", d, p),
            };

            match tokio::net::TcpStream::connect(&target_addr).await {
                Ok(mut outbound) => {
                    inbound
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;
                    session_manager.update_status(session_id, SessionStatus::Active);

                    let (mut ri, mut wi) = inbound.split();
                    let (mut ro, mut wo) = outbound.split();
                    tokio::select! {
                        result = async {
                            tokio::try_join!(
                                tokio::io::copy(&mut ri, &mut wo),
                                tokio::io::copy(&mut ro, &mut wi),
                            )
                        } => { let _ = result; }
                        _ = cancel_token.cancelled() => {
                            tracing::info!(session_id, "connection terminated by user");
                        }
                    }

                    session_manager.update_status(session_id, SessionStatus::Closed);
                    traffic_stats.record_connection_close();
                    Ok(())
                }
                Err(e) => {
                    inbound
                        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;
                    session_manager.update_status(
                        session_id,
                        SessionStatus::Error(e.to_string()),
                    );
                    traffic_stats.record_connection_close();
                    Err(e.into())
                }
            }
        }
        Action::Proxy(ref pname) => {
            let outbound_result = chain_relay.connect(pname, &dest).await;

            match outbound_result {
                Ok(mut outbound) => {
                    inbound
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;
                    session_manager.update_status(session_id, SessionStatus::Active);

                    let (mut ri, mut wi) = inbound.split();
                    let (mut ro, mut wo) = outbound.split();
                    tokio::select! {
                        result = async {
                            tokio::try_join!(
                                tokio::io::copy(&mut ri, &mut wo),
                                tokio::io::copy(&mut ro, &mut wi),
                            )
                        } => { let _ = result; }
                        _ = cancel_token.cancelled() => {
                            tracing::info!(session_id, "connection terminated by user");
                        }
                    }

                    session_manager.update_status(session_id, SessionStatus::Closed);
                    traffic_stats.record_connection_close();
                    Ok(())
                }
                Err(e) => {
                    inbound
                        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;
                    traffic_stats.record_proxy_error(pname);
                    session_manager.update_status(
                        session_id,
                        SessionStatus::Error(e.to_string()),
                    );
                    traffic_stats.record_connection_close();
                    Err(e.into())
                }
            }
        }
    };

    // Remove the cancellation token after the connection ends
    connection_handles.lock().await.remove(&session_id);

    result
}

// --- Network Extension (macOS) ---

/// Status of the macOS Network Extension.
#[derive(Debug, Serialize, Deserialize)]
pub struct NEStatusInfo {
    pub installed: bool,
    pub enabled: bool,
    pub running: bool,
    #[serde(default)]
    pub server_running: bool,
}

/// Start the NE socket server (Rust backend for Network Extension).
#[cfg(target_os = "macos")]
#[tauri::command]
async fn start_ne_server(state: State<'_, SharedState>) -> Result<String, String> {
    let mut state_guard = state.lock().await;

    if state_guard.ne_server_running {
        return Err("NE server is already running".to_string());
    }

    let config = state_guard.config.clone().ok_or("No configuration loaded")?;

    // Build rule engine using rules from config
    let rule_engine = Arc::new(RuleEngine::with_default_action(
        config.rules.clone(),
        config.default_action.clone(),
    ));

    // Build proxy map
    let mut proxy_map = HashMap::new();
    for proxy_cfg in &config.proxies {
        let server = proxy_cfg
            .to_proxy_server()
            .map_err(|e| format!("Failed to create proxy server: {}", e))?;
        proxy_map.insert(proxy_cfg.name.clone(), server);
    }

    let chain_relay = Arc::new(ChainRelay::new(config.chains.clone(), proxy_map));
    let virtual_dns = state_guard.virtual_dns.clone();
    let session_manager = state_guard.session_manager.clone();

    // Use app data dir for socket path to avoid permission issues
    let socket_path = state_guard.config_path.parent()
        .unwrap_or(std::path::Path::new("/tmp"))
        .join("omnilink.sock");
    let socket_path_str = socket_path.display().to_string();

    // Create and start the NE interceptor
    let mut ne_interceptor = omnilink_tun::create_ne_interceptor(
        rule_engine,
        chain_relay,
        virtual_dns,
        session_manager,
        Some(&socket_path_str),
    );

    let _event_rx = ne_interceptor
        .start()
        .await
        .map_err(|e| format!("Failed to start NE server: {}", e))?;

    // Store interceptor for stopping later
    state_guard.ne_interceptor = Some(ne_interceptor);
    state_guard.ne_server_running = true;

    tracing::info!(path = %socket_path_str, "NE socket server started");

    Ok(format!("NE socket server started at {}", socket_path_str))
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn start_ne_server(_state: State<'_, SharedState>) -> Result<String, String> {
    Err("Network Extension is only supported on macOS".to_string())
}

/// Stop the NE socket server.
#[cfg(target_os = "macos")]
#[tauri::command]
async fn stop_ne_server(state: State<'_, SharedState>) -> Result<String, String> {
    let mut state_guard = state.lock().await;

    if !state_guard.ne_server_running {
        return Err("NE server is not running".to_string());
    }

    if let Some(mut interceptor) = state_guard.ne_interceptor.take() {
        interceptor.stop().await.map_err(|e| format!("Failed to stop NE server: {}", e))?;
    }

    state_guard.ne_server_running = false;
    tracing::info!("NE socket server stopped");

    Ok("NE socket server stopped".to_string())
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn stop_ne_server(_state: State<'_, SharedState>) -> Result<String, String> {
    Err("Network Extension is only supported on macOS".to_string())
}

/// Get Network Extension status by calling the helper CLI.
#[cfg(target_os = "macos")]
#[tauri::command]
async fn get_ne_status(state: State<'_, SharedState>) -> Result<NEStatusInfo, String> {
    let state_guard = state.lock().await;
    let server_running = state_guard.ne_server_running;
    drop(state_guard);

    // Try to call the NE helper
    let helper_path = std::env::current_exe()
        .map(|p| p.parent().unwrap_or(std::path::Path::new(".")).join("omnilink-ne-helper"))
        .unwrap_or_else(|_| std::path::PathBuf::from("omnilink-ne-helper"));

    if helper_path.exists() {
        match std::process::Command::new(&helper_path)
            .arg("status")
            .output()
        {
            Ok(output) if output.status.success() => {
                let json = String::from_utf8_lossy(&output.stdout);
                let mut info: NEStatusInfo = serde_json::from_str(&json).map_err(|e| e.to_string())?;
                info.server_running = server_running;
                Ok(info)
            }
            Ok(output) => Err(String::from_utf8_lossy(&output.stderr).to_string()),
            Err(e) => Err(format!("Failed to execute NE helper: {}", e)),
        }
    } else {
        // Helper not found, return default status
        Ok(NEStatusInfo {
            installed: false,
            enabled: false,
            running: false,
            server_running,
        })
    }
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn get_ne_status(_state: State<'_, SharedState>) -> Result<NEStatusInfo, String> {
    Err("Network Extension is only supported on macOS".to_string())
}

// ============================================================================
// Application Discovery Commands
// ============================================================================

#[derive(Debug, Serialize)]
pub struct AppInfo {
    pub name: String,
    pub bundle_id: Option<String>,
    pub executable_name: String,
    pub executable_path: String,
    pub icon_base64: Option<String>,
    pub version: Option<String>,
}

/// List installed applications on the system.
#[tauri::command]
async fn list_installed_apps() -> Result<Vec<AppInfo>, String> {
    let apps = omnilink_core::app_discovery::discover_apps();
    Ok(apps
        .into_iter()
        .map(|a| AppInfo {
            name: a.name,
            bundle_id: a.bundle_id,
            executable_name: a.executable_name,
            executable_path: a.executable_path,
            icon_base64: a.icon_base64,
            version: a.version,
        })
        .collect())
}

/// Export current rules as YAML string.
#[tauri::command]
async fn export_rules_yaml(state: State<'_, SharedState>) -> Result<String, String> {
    let state = state.lock().await;
    let config = state.config.as_ref().ok_or("No config loaded")?;

    // Build a rules-only config for export
    #[derive(serde::Serialize)]
    struct RulesExport {
        rules: Vec<Rule>,
        default_action: Action,
    }

    let export = RulesExport {
        rules: config.rules.clone(),
        default_action: config.default_action.clone(),
    };

    serde_yaml::to_string(&export).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let initial_state = AppStateInner {
        running: false,
        config: Some(Config::default_config()),
        config_path: PathBuf::from("config.yaml"),
        session_manager: Arc::new(SessionManager::new(500)),
        traffic_stats: Arc::new(TrafficStats::new()),
        service_handle: None,
        rule_engine: None,
        virtual_dns: Arc::new(VirtualDns::new()),
        chain_relay: None,
        sysproxy_enabled: false,
        connection_handles: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        interceptor_handle: None,
        interceptor_running: false,
        ne_interceptor: None,
        ne_server_running: false,
    };

    let mut builder = tauri::Builder::default();

    // Register updater and process plugins (desktop only)
    #[cfg(desktop)]
    {
        builder = builder
            .plugin(tauri_plugin_dialog::init())
            .plugin(tauri_plugin_updater::Builder::new().build())
            .plugin(tauri_plugin_process::init());
    }

    builder
        .manage(Mutex::new(initial_state))
        .invoke_handler(tauri::generate_handler![
            get_sessions,
            clear_closed_sessions,
            get_status,
            get_proxies,
            load_config,
            start_service,
            stop_service,
            get_traffic_stats,
            reset_stats,
            get_rules,
            add_rule,
            toggle_rule,
            delete_rule,
            add_proxy,
            delete_proxy,
            get_chains,
            add_chain,
            delete_chain,
            toggle_sysproxy,
            get_sysproxy_status,
            terminate_session,
            get_profiles,
            switch_profile,
            save_profile,
            save_config,
            save_config_to,
            start_interceptor,
            stop_interceptor,
            get_interceptor_status,
            set_proxy_credentials,
            delete_proxy_credentials,
            has_proxy_credentials,
            migrate_credentials,
            start_ne_server,
            stop_ne_server,
            get_ne_status,
            list_installed_apps,
            export_rules_yaml,
        ])
        .setup(|app| {
            use tauri::Manager;
            let data_dir = app.path().app_data_dir().expect("failed to resolve app data dir");
            std::fs::create_dir_all(&data_dir).ok();
            let config_path = data_dir.join("config.yaml");
            let state = app.state::<SharedState>();
            let mut s = tauri::async_runtime::block_on(state.lock());
            s.config_path = config_path.clone();
            if config_path.exists() {
                match Config::load(&config_path) {
                    Ok(config) => {
                        tracing::info!("Loaded config from {}", config_path.display());
                        s.config = Some(config);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load config from {}: {}", config_path.display(), e);
                    }
                }
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
