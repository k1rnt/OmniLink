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
pub struct TunDevice {
    config: TunConfig,
    #[cfg(target_os = "linux")]
    fd: std::os::unix::io::RawFd,
}

impl TunDevice {
    /// Create a new TUN device (Linux implementation).
    #[cfg(target_os = "linux")]
    pub fn create(config: TunConfig) -> Result<Self, TunError> {
        use std::os::unix::io::RawFd;

        tracing::info!(name = %config.name, "creating TUN device");

        // Open /dev/net/tun
        let fd: RawFd = unsafe {
            let path = std::ffi::CString::new("/dev/net/tun").unwrap();
            libc::open(path.as_ptr(), libc::O_RDWR)
        };

        if fd < 0 {
            return Err(TunError::CreateFailed(
                format!("failed to open /dev/net/tun: {}", io::Error::last_os_error()),
            ));
        }

        // TUNSETIFF ioctl
        // struct ifreq with ifr_flags = IFF_TUN | IFF_NO_PI
        const IFF_TUN: libc::c_short = 0x0001;
        const IFF_NO_PI: libc::c_short = 0x1000;
        const TUNSETIFF: libc::c_ulong = 0x400454CA;

        let mut ifr = [0u8; 40]; // struct ifreq is 40 bytes on most platforms
        let name_bytes = config.name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let flags = (IFF_TUN | IFF_NO_PI) as u16;
        ifr[16] = (flags & 0xFF) as u8;
        ifr[17] = ((flags >> 8) & 0xFF) as u8;

        let ret = unsafe { libc::ioctl(fd, TUNSETIFF, ifr.as_ptr()) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(TunError::CreateFailed(
                format!("TUNSETIFF failed: {}", io::Error::last_os_error()),
            ));
        }

        // Configure IP address and netmask via ip command
        let ip_cmd = format!(
            "ip addr add {}/{} dev {} && ip link set {} up mtu {}",
            config.address,
            netmask_to_prefix(config.netmask),
            config.name,
            config.name,
            config.mtu,
        );

        let status = std::process::Command::new("sh")
            .args(["-c", &ip_cmd])
            .status();

        match status {
            Ok(s) if s.success() => {
                tracing::info!(name = %config.name, fd = fd, "TUN device created and configured");
            }
            Ok(s) => {
                tracing::warn!(name = %config.name, status = %s, "TUN device created but IP configuration failed");
            }
            Err(e) => {
                tracing::warn!(name = %config.name, error = %e, "failed to run ip commands");
            }
        }

        Ok(Self { config, fd })
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

    /// Read a packet from the TUN device.
    #[cfg(target_os = "linux")]
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Write a packet to the TUN device.
    #[cfg(target_os = "linux")]
    pub fn write_packet(&self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Stub read for non-Linux.
    #[cfg(not(target_os = "linux"))]
    pub fn read_packet(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "TUN not supported on this platform"))
    }

    /// Stub write for non-Linux.
    #[cfg(not(target_os = "linux"))]
    pub fn write_packet(&self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "TUN not supported on this platform"))
    }
}

#[cfg(target_os = "linux")]
impl Drop for TunDevice {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
        tracing::debug!(name = %self.config.name, "TUN device closed");
    }
}

/// Convert a netmask to CIDR prefix length.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn netmask_to_prefix(netmask: std::net::Ipv4Addr) -> u8 {
    let bits = u32::from(netmask);
    bits.count_ones() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netmask_to_prefix() {
        assert_eq!(netmask_to_prefix(std::net::Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_prefix(std::net::Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_to_prefix(std::net::Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(netmask_to_prefix(std::net::Ipv4Addr::new(255, 255, 255, 255)), 32);
    }
}
