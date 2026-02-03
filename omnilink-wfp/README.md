# OmniLink WFP Callout Driver

Windows Filtering Platform (WFP) callout driver for transparent TCP traffic interception on Windows.

## Architecture

```
App connects to 1.2.3.4:443
  → WFP ALE_CONNECT_REDIRECT_V4 callout intercepts
  → Saves original dest in kernel NAT table
  → Redirects connection to 127.0.0.1:PROXY_PORT
  → User-mode service accepts connection
  → Queries original dest via IOCTL
  → Forwards through proxy chain
```

### Components

- **`driver/`** — KMDF WFP callout driver (C, requires WDK)
- **`service/`** — User-mode Rust service that communicates with the driver via IOCTL

## Build Requirements

### Driver

- Windows Driver Kit (WDK) 10 or later
- Visual Studio 2022 with WDK integration
- EV Code Signing Certificate (for production deployment)

### Service

- Rust toolchain with `x86_64-pc-windows-msvc` target
- `cargo build --manifest-path service/Cargo.toml`

## Development Setup

### 1. Enable Test Signing

For development, enable test signing to load unsigned drivers:

```cmd
bcdedit /set testsigning on
```

Reboot after running this command.

### 2. Build the Driver

Open `driver/omnilink-wfp.vcxproj` in Visual Studio with WDK installed and build in Debug mode.

### 3. Install the Driver

```cmd
sc create OmniLinkWFP type= kernel binPath= C:\path\to\omnilink-wfp.sys
sc start OmniLinkWFP
```

Or use the INF installer:

```cmd
pnputil /add-driver driver.inf /install
```

### 4. Run the Service

```cmd
cargo run --manifest-path service/Cargo.toml
```

## Current Status

This is a **skeleton implementation**. The driver registers WFP callouts and handles IOCTLs, but the core redirect logic in `ClassifyConnectV4` is stubbed out (permits all traffic).

### TODO

- Implement `FwpsAcquireWritableLayerDataPointer0` redirect logic in `ClassifyConnectV4`
- NAT table TTL cleanup (`NatCleanupExpired`)
- IPv6 support (`ALE_CONNECT_REDIRECT_V6`)
- Integration with omnilink-core proxy chain
- Windows service registration (SCM)
- MSBuild `.vcxproj` project file for the driver
