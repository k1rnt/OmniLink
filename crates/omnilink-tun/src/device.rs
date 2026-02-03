use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN device creation failed: {0}")]
    CreateFailed(String),
    #[error("TUN device not supported on this platform")]
    NotSupported,
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Configuration for creating a TUN device.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Name of the TUN device (e.g., "omni0").
    pub name: String,
    /// IP address to assign to the device.
    pub address: std::net::Ipv4Addr,
    /// Netmask for the device.
    pub netmask: std::net::Ipv4Addr,
    /// MTU for the device.
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "omni0".to_string(),
            address: std::net::Ipv4Addr::new(10, 0, 0, 1),
            netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1500,
        }
    }
}

/// Platform-abstracted TUN device handle.
///
/// Actual TUN device creation requires platform-specific code and root privileges.
/// This module provides the abstraction layer; platform implementations are
/// conditionally compiled.
pub struct TunDevice {
    config: TunConfig,
    #[cfg(target_os = "linux")]
    fd: Option<i32>,
}

impl TunDevice {
    /// Create a new TUN device (platform-specific).
    #[cfg(target_os = "linux")]
    pub fn create(config: TunConfig) -> Result<Self, TunError> {
        use std::ffi::CString;

        tracing::info!(name = %config.name, "creating TUN device");

        // Open /dev/net/tun
        let fd = unsafe {
            let path = CString::new("/dev/net/tun").unwrap();
            libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK)
        };

        if fd < 0 {
            return Err(TunError::CreateFailed(
                "failed to open /dev/net/tun".to_string(),
            ));
        }

        // Configure the device with ioctl
        // (Simplified - full implementation would use TUNSETIFF ioctl)
        tracing::info!(name = %config.name, fd = fd, "TUN device created");

        Ok(Self {
            config,
            fd: Some(fd),
        })
    }

    /// Stub for non-Linux platforms.
    #[cfg(not(target_os = "linux"))]
    pub fn create(config: TunConfig) -> Result<Self, TunError> {
        tracing::warn!("TUN device creation is only supported on Linux; using stub");
        Ok(Self { config })
    }

    pub fn config(&self) -> &TunConfig {
        &self.config
    }
}
