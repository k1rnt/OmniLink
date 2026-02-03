# OmniLink Network Extension (macOS)

macOS System Extension using `NETransparentProxyProvider` for transparent traffic interception.

## Prerequisites

- macOS 12.0 (Monterey) or later
- Xcode 14+
- Apple Developer Program membership
- **Network Extension entitlement** (must be requested from Apple)

## Entitlement Request

1. Sign in to [Apple Developer](https://developer.apple.com/account/)
2. Go to Certificates, Identifiers & Profiles
3. Create App IDs for both the container app and the extension
4. Request the Network Extension entitlement via [Apple's request form](https://developer.apple.com/contact/request/network-extension/)
5. Wait for approval (typically 1-2 weeks)
6. Enable the entitlement in your provisioning profile

## Development Setup (Without Entitlement)

For local testing without the NE entitlement:

```bash
# Disable SIP (requires booting into Recovery Mode)
csrutil disable

# Enable developer mode for system extensions
systemextensionsctl developer on
```

**Warning**: Disabling SIP reduces system security. Only do this on development machines.

## Architecture

```
Tauri App (Rust backend)
    |
    | Unix domain socket (/var/run/omnilink.sock)
    |
NE System Extension (Swift)
    |
    | NETransparentProxyProvider
    |
macOS Network Stack (kernel)
```

### Communication

The NE extension communicates with the Rust/Tauri backend via:
- **Unix domain socket** (current): Simple, works well with Rust
- **XPC** (future): Native macOS IPC, requires Mach service registration

### Flow Handling

1. App initiates TCP connection
2. NE extension intercepts via `handleNewFlow(_:)`
3. Extension queries Rust backend for routing decision
4. Based on action (direct/proxy/block), extension either:
   - Relays data through the proxy chain
   - Allows direct connection
   - Drops the connection

## Files

| File | Purpose |
|------|---------|
| `OmniLinkExtension/TransparentProxyProvider.swift` | Core NE provider implementation |
| `OmniLinkExtension/XPCBridge.swift` | IPC client (extension side) |
| `OmniLinkApp/ExtensionManager.swift` | System extension lifecycle management |
| `OmniLinkApp/XPCClient.swift` | IPC server (app side) |
| `Shared/XPCProtocol.swift` | IPC protocol definition |
| `Shared/Messages.swift` | Shared data types |

## Building

This is currently a skeleton. To build:

1. Open in Xcode (create a project with these files)
2. Configure signing with your Developer ID
3. Add the NE entitlement to your provisioning profile
4. Build the extension target
5. Embed the extension in the container app bundle

## TODO

- [ ] Obtain NE entitlement from Apple
- [ ] Create Xcode project (.xcodeproj)
- [ ] Implement Unix socket wire protocol (JSON framing)
- [ ] Implement Rust-side socket server in omnilink-tun
- [ ] Add UDP flow handling for DNS
- [ ] Per-app filtering based on bundle ID
- [ ] Integration tests with the Rust backend
