# OmniLink

A cross-platform transparent proxy client built with Rust and Tauri.

OmniLink intercepts network traffic at the OS level and routes it through proxy servers based on user-defined rules. It supports Windows, macOS, and Linux with platform-native interception mechanisms.

## Features

### Proxy Protocols
- **SOCKS4 / SOCKS4a** - Legacy SOCKS protocol support
- **SOCKS5** - Full support including no-auth, username/password authentication, and UDP Associate
- **HTTP / HTTPS CONNECT** - HTTP tunnel proxy support
- **SSH Tunnel** - Direct-tcpip channel forwarding via russh

### Routing & Rules
- **Rule-Based Routing** - Route traffic based on process name, destination domain/IP (CIDR), port range, or user
- **Proxy Chains** - Chain multiple proxies with strict, failover, round-robin, or random selection modes
- **Virtual DNS (Fake IP)** - Prevents DNS leaks by mapping domains to a private IP pool (`198.18.0.0/15`)

### Management
- **Proxy Checker** - Built-in latency and connectivity checker
- **Profile System** - Save and switch between named configuration profiles
- **Connection Monitor** - Real-time connection list with filtering, search, and traffic statistics
- **Traffic Visualization** - Real-time bandwidth graph with per-proxy and per-domain statistics
- **Secure Credential Storage** - OS keychain integration (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- **System Proxy** - Automatic system-wide proxy configuration

### Desktop Application
- **Cross-Platform UI** - Tauri + React desktop application
- **Full CRUD Operations** - Create, edit, delete rules, proxies, and chains from the UI
- **Connection Control** - Terminate active connections from the UI

## Architecture

```
+----------------------------------+
|     UI Layer (Tauri + React)     |
+----------------------------------+
|    Core Engine (Rust / Tokio)    |
|  +--------+ +------+ +--------+  |
|  | Proxy  | | Rule | |  DNS   |  |
|  | Client | |Engine| |Resolver|  |
|  +--------+ +------+ +--------+  |
+----------------------------------+
|     OS Interceptor (Native)      |
|  Win: WFP  macOS: NE  Linux: eBPF|
+----------------------------------+
```

## Project Structure

```
OmniLink/
├── crates/
│   ├── omnilink-core/       # Core proxy engine
│   │   └── src/
│   │       ├── proxy/       # SOCKS4/5, HTTP, SSH proxy clients
│   │       ├── rule/        # Rule matching engine
│   │       ├── dns/         # Virtual DNS / Fake IP
│   │       ├── config/      # Configuration and profiles
│   │       ├── credential/  # OS keychain integration
│   │       ├── checker.rs   # Proxy latency checker
│   │       └── session.rs   # Connection session tracking
│   ├── omnilink-tun/        # TUN device + packet parsing
│   ├── omnilink-ebpf/       # Linux eBPF interceptor
│   └── omnilink-cli/        # CLI binary
├── omnilink-ui/             # Tauri + React frontend
│   ├── src/                 # React components
│   └── src-tauri/           # Tauri Rust backend
├── omnilink-ne/             # macOS Network Extension
├── omnilink-wfp/            # Windows WFP driver + service
├── config.example.yaml      # Example configuration
└── Cargo.toml               # Workspace root
```

## Getting Started

### Prerequisites

- Rust 1.75+
- Node.js 18+
- Platform-specific: Xcode (macOS), GTK3/WebKit (Linux)

### Build

```sh
# Build core engine and CLI
cargo build --release

# Generate a default config
cargo run --bin omnilink-cli -- init

# Validate configuration
cargo run --bin omnilink-cli -- validate -c config.yaml

# Check proxy connectivity
cargo run --bin omnilink-cli -- check-proxies -c config.yaml

# Start the proxy service
cargo run --bin omnilink-cli -- run -c config.yaml
```

### Build the Desktop App

```sh
cd omnilink-ui
npm install
npm run tauri build
```

## Configuration

OmniLink uses YAML configuration files. See `config.example.yaml` for a complete example.

### Proxy Servers

```yaml
proxies:
  - name: my-socks5
    protocol: !Socks5
    address: "proxy.example.com"
    port: 1080
    auth:
      username: user
      password: pass

  - name: my-http
    protocol: !Http
    address: "httpproxy.example.com"
    port: 8080

  - name: my-ssh
    protocol: !Ssh
    address: "ssh.example.com"
    port: 22
    auth:
      username: user
      private_key_path: ~/.ssh/id_rsa
```

### Proxy Chains

```yaml
chains:
  - name: double-hop
    proxies:
      - my-socks5
      - my-http
    mode: strict     # strict | failover | round_robin | random
```

### Routing Rules

Rules are evaluated by priority (highest first). Each rule has conditions that must all match, and an action to apply.

```yaml
rules:
  - name: skip-loopback
    conditions:
      - !loopback
    action: !direct
    priority: 1000

  - name: block-ads
    conditions:
      - !domain "*.ads.example.com;*.tracking.com"
    action: !block
    priority: 100

  - name: proxy-browsers
    conditions:
      - !process_name "chrome.exe;firefox.exe;safari"
    action:
      !proxy my-socks5
    priority: 50
    dns_mode: !remote_resolution

  - name: direct-local
    conditions:
      - !cidr "192.168.0.0/16"
    action: !direct
    priority: 50

default_action: !direct
```

### Available Conditions

| Condition | Example | Description |
|-----------|---------|-------------|
| `process_name` | `"chrome*;firefox*"` | Match process name (glob, multi) |
| `process_path` | `"/usr/bin/*"` | Match full process path |
| `domain` | `"*.example.com"` | Match destination domain (wildcard) |
| `cidr` | `"10.0.0.0/8"` | Match destination IP range |
| `port` | `443` | Match destination port |
| `port_range` | `[8000, 9000]` | Match port range (inclusive) |
| `user` | `"root"` | Match process owner |
| `loopback` | | Match 127.0.0.0/8 and localhost |

### DNS Settings

```yaml
dns:
  mode: !fake_ip           # fake_ip | remote_resolution
```

- **fake_ip** - Returns IPs from `198.18.0.0/15` pool, resolves through proxy on connect. Zero DNS leaks.
- **remote_resolution** - Sends domain name directly to SOCKS5 proxy for remote resolution.

## CLI Commands

| Command | Description |
|---------|-------------|
| `omnilink run` | Start the proxy service |
| `omnilink validate` | Validate configuration file |
| `omnilink init` | Generate default config file |
| `omnilink check-proxies` | Test proxy server connectivity and latency |
| `omnilink credential` | Manage credentials in OS keychain |

## Platform Support

| Platform | Interception Method | Status |
|----------|---------------------|--------|
| macOS | Network Extension (NETransparentProxyProvider) | Implemented |
| Linux | eBPF (connect4/sendmsg4 hooks) | Implemented |
| Windows | WFP (Windows Filtering Platform) | Implemented |

### Platform-Specific Notes

**macOS:**
- Requires System Extension approval in System Preferences
- Network Extension requires app notarization for distribution (or Gatekeeper bypass for local builds)

**Linux:**
- eBPF requires kernel 5.8+ with BPF enabled
- CAP_BPF or root privileges required

**Windows:**
- WFP driver requires kernel-mode code signing for production
- Test signing mode available for development
