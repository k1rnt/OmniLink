use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use omnilink_core::config::Config;

#[derive(Parser)]
#[command(name = "omnilink")]
#[command(about = "OmniLink - Cross-platform proxy client")]
#[command(version)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the proxy service
    Run,
    /// Validate the configuration file
    Validate,
    /// Generate a default configuration file
    Init,
    /// Check proxy server connectivity and latency
    CheckProxies {
        /// Timeout in seconds for each proxy check
        #[arg(short, long, default_value = "5")]
        timeout: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("omnilink=info".parse()?))
        .init();

    match cli.command {
        Commands::Run => cmd_run(&cli.config).await,
        Commands::Validate => cmd_validate(&cli.config),
        Commands::Init => cmd_init(&cli.config),
        Commands::CheckProxies { timeout } => {
            cmd_check_proxies(&cli.config, timeout).await
        }
    }
}

async fn cmd_run(config_path: &PathBuf) -> Result<()> {
    let config = Config::load(config_path)?;

    tracing::info!(
        listen = %config.general.listen_addr,
        proxies = config.proxies.len(),
        rules = config.rules.len(),
        "starting OmniLink"
    );

    let listener = tokio::net::TcpListener::bind(&config.general.listen_addr).await?;
    tracing::info!(addr = %config.general.listen_addr, "listening for connections");

    // Build rule engine with configurable default action
    let rule_engine = omnilink_core::rule::RuleEngine::with_default_action(
        config.rules.clone(),
        config.default_action.clone(),
    );
    let rule_engine = std::sync::Arc::new(rule_engine);

    // Build virtual DNS
    let virtual_dns = std::sync::Arc::new(omnilink_core::dns::VirtualDns::new());

    // Build proxy server map and chain relay
    let mut proxy_map = std::collections::HashMap::new();
    for proxy_cfg in &config.proxies {
        let server = proxy_cfg.to_proxy_server()?;
        proxy_map.insert(proxy_cfg.name.clone(), server);
    }

    let chain_relay = omnilink_core::proxy::chain::ChainRelay::new(
        config.chains.clone(),
        proxy_map,
    );
    let chain_relay = std::sync::Arc::new(chain_relay);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        tracing::debug!(peer = %peer_addr, "accepted connection");

        let rule_engine = rule_engine.clone();
        let virtual_dns = virtual_dns.clone();
        let chain_relay = chain_relay.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, &rule_engine, &virtual_dns, &chain_relay).await
            {
                tracing::error!(peer = %peer_addr, error = %e, "connection handler error");
            }
        });
    }
}

async fn handle_connection(
    mut inbound: tokio::net::TcpStream,
    rule_engine: &omnilink_core::rule::RuleEngine,
    virtual_dns: &omnilink_core::dns::VirtualDns,
    chain_relay: &omnilink_core::proxy::chain::ChainRelay,
) -> Result<()> {
    use omnilink_core::proxy::ProxyDestination;
    use omnilink_core::rule::{Action, MatchContext};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read SOCKS5 handshake from local client
    let mut buf = [0u8; 2];
    inbound.read_exact(&mut buf).await?;

    if buf[0] != 0x05 {
        anyhow::bail!("not a SOCKS5 request");
    }

    let n_methods = buf[1] as usize;
    let mut methods = vec![0u8; n_methods];
    inbound.read_exact(&mut methods).await?;

    // Accept no-auth
    inbound.write_all(&[0x05, 0x00]).await?;

    // Read connect request
    let mut header = [0u8; 4];
    inbound.read_exact(&mut header).await?;

    if header[1] != 0x01 {
        inbound
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        anyhow::bail!("unsupported SOCKS5 command: {}", header[1]);
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
            anyhow::bail!("unsupported address type");
        }
    };

    let port = match &dest {
        ProxyDestination::SocketAddr(a) => a.port(),
        ProxyDestination::Domain(_, p) => *p,
    };

    // Evaluate rules
    let ctx = MatchContext {
        process_name: None,
        process_path: None,
        process_user: None,
        dest_domain: dest_domain.clone(),
        dest_ip,
        dest_port: port,
    };

    let action = rule_engine.evaluate(&ctx);
    tracing::info!(dest = %dest, action = ?action, "routing decision");

    match action {
        Action::Block => {
            inbound
                .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            tracing::info!(dest = %dest, "connection blocked by rule");
            return Ok(());
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

                    let (mut ri, mut wi) = inbound.split();
                    let (mut ro, mut wo) = outbound.split();
                    let _ = tokio::try_join!(
                        tokio::io::copy(&mut ri, &mut wo),
                        tokio::io::copy(&mut ro, &mut wi),
                    );
                }
                Err(e) => {
                    inbound
                        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;
                    return Err(e.into());
                }
            }
        }
        Action::Proxy(proxy_name) => {
            let outbound_result = chain_relay.connect(&proxy_name, &dest).await;

            match outbound_result {
                Ok(mut outbound) => {
                    inbound
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;

                    let (mut ri, mut wi) = inbound.split();
                    let (mut ro, mut wo) = outbound.split();
                    let _ = tokio::try_join!(
                        tokio::io::copy(&mut ri, &mut wo),
                        tokio::io::copy(&mut ro, &mut wi),
                    );
                }
                Err(e) => {
                    inbound
                        .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;
                    return Err(e.into());
                }
            }
        }
    }

    Ok(())
}

fn cmd_validate(config_path: &PathBuf) -> Result<()> {
    let config = Config::load(config_path)?;
    println!("Configuration is valid.");
    println!("  Listen: {}", config.general.listen_addr);
    println!("  Proxies: {}", config.proxies.len());
    println!("  Chains: {}", config.chains.len());
    println!("  Rules: {} ({} enabled)",
        config.rules.len(),
        config.rules.iter().filter(|r| r.enabled).count()
    );
    println!("  DNS mode: {:?}", config.dns.mode);
    println!("  Default action: {:?}", config.default_action);
    Ok(())
}

fn cmd_init(config_path: &PathBuf) -> Result<()> {
    if config_path.exists() {
        anyhow::bail!("config file already exists: {}", config_path.display());
    }

    let config = Config::default_config();
    let yaml = serde_yaml::to_string(&config)?;
    std::fs::write(config_path, yaml)?;
    println!("Default config written to {}", config_path.display());
    Ok(())
}

async fn cmd_check_proxies(config_path: &PathBuf, timeout_secs: u64) -> Result<()> {
    let config = Config::load(config_path)?;
    let timeout = Duration::from_secs(timeout_secs);

    if config.proxies.is_empty() {
        println!("No proxy servers configured.");
        return Ok(());
    }

    println!("Checking {} proxy server(s)...\n", config.proxies.len());

    let mut servers = Vec::new();
    for proxy_cfg in &config.proxies {
        servers.push(proxy_cfg.to_proxy_server()?);
    }

    let results = omnilink_core::checker::check_all(&servers, timeout).await;

    for result in &results {
        if result.reachable {
            println!(
                "  [OK] {} - {}ms",
                result.proxy_name,
                result.latency_ms.unwrap_or(0)
            );
        } else {
            println!(
                "  [FAIL] {} - {}",
                result.proxy_name,
                result.error.as_deref().unwrap_or("unknown error")
            );
        }
    }

    let ok_count = results.iter().filter(|r| r.reachable).count();
    println!(
        "\n{}/{} proxies reachable.",
        ok_count,
        results.len()
    );

    Ok(())
}
