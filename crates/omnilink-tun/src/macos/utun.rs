use std::io;
use std::os::unix::io::RawFd;

use thiserror::Error;

/// AF_INET value used in the 4-byte utun header on macOS.
const AF_INET: u32 = 2;

/// PF_SYSTEM for macOS kernel control sockets.
const PF_SYSTEM: libc::c_int = libc::AF_SYSTEM;
const SOCK_DGRAM: libc::c_int = libc::SOCK_DGRAM;
const SYSPROTO_CONTROL: libc::c_int = 2;
const AF_SYS_CONTROL: u16 = 2;

/// CTLIOCGINFO ioctl number for macOS.
/// _IOWR('N', 3, struct ctl_info) = 0xC0644E03
const CTLIOCGINFO: libc::c_ulong = 0xC0644E03;

/// UTUN_CONTROL_NAME used to find the utun kernel control.
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

#[derive(Debug, Error)]
pub enum UtunError {
    #[error("failed to create system socket: {0}")]
    SocketCreation(io::Error),
    #[error("CTLIOCGINFO ioctl failed: {0}")]
    CtlInfo(io::Error),
    #[error("failed to connect utun: {0}")]
    Connect(io::Error),
    #[error("failed to get interface name: {0}")]
    GetName(io::Error),
    #[error("failed to configure interface: {0}")]
    Configure(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// ctl_info structure for CTLIOCGINFO ioctl.
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

/// sockaddr_ctl for connecting to a kernel control.
#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

/// A macOS utun device.
pub struct UtunDevice {
    fd: RawFd,
    name: String,
}

impl UtunDevice {
    /// Create a new utun device.
    ///
    /// If `unit` is 0, the kernel assigns the next available utun number.
    /// Otherwise, utun(unit-1) is created (e.g., unit=1 → utun0).
    pub fn create(unit: u32) -> Result<Self, UtunError> {
        // Create PF_SYSTEM socket
        let fd = unsafe { libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(UtunError::SocketCreation(io::Error::last_os_error()));
        }

        // Get control ID via CTLIOCGINFO
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0u8; 96],
        };
        let name_len = UTUN_CONTROL_NAME.len().min(96);
        info.ctl_name[..name_len].copy_from_slice(&UTUN_CONTROL_NAME[..name_len]);

        if unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut info as *mut CtlInfo) } < 0 {
            unsafe { libc::close(fd) };
            return Err(UtunError::CtlInfo(io::Error::last_os_error()));
        }

        // Connect to the utun control
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYS_CONTROL as u8,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };

        if unsafe {
            libc::connect(
                fd,
                &addr as *const SockaddrCtl as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
            )
        } < 0
        {
            unsafe { libc::close(fd) };
            return Err(UtunError::Connect(io::Error::last_os_error()));
        }

        // Get the assigned interface name
        let name = Self::get_ifname(fd)?;
        tracing::info!(name = %name, fd = fd, "utun device created");

        Ok(Self { fd, name })
    }

    /// Get the interface name for this utun fd.
    fn get_ifname(fd: RawFd) -> Result<String, UtunError> {
        let mut name_buf = [0u8; 64];
        let mut name_len: libc::socklen_t = name_buf.len() as libc::socklen_t;

        // UTUN_OPT_IFNAME = 2
        const UTUN_OPT_IFNAME: libc::c_int = 2;

        if unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name_buf.as_mut_ptr() as *mut libc::c_void,
                &mut name_len,
            )
        } < 0
        {
            return Err(UtunError::GetName(io::Error::last_os_error()));
        }

        let name = std::str::from_utf8(&name_buf[..name_len as usize - 1])
            .unwrap_or("utun?")
            .to_string();
        Ok(name)
    }

    /// Configure the utun interface with an IP address and bring it up.
    pub fn configure(&self, addr: &str, peer_addr: &str, mtu: u16) -> Result<(), UtunError> {
        let cmd = format!(
            "ifconfig {} inet {} {} mtu {} up",
            self.name, addr, peer_addr, mtu,
        );

        let status = std::process::Command::new("sh")
            .args(["-c", &cmd])
            .status()
            .map_err(|e| UtunError::Configure(e.to_string()))?;

        if !status.success() {
            return Err(UtunError::Configure(format!(
                "ifconfig exited with status {}",
                status
            )));
        }

        tracing::info!(
            name = %self.name,
            addr = addr,
            mtu = mtu,
            "utun interface configured"
        );

        Ok(())
    }

    /// Add a route through the utun interface.
    pub fn add_route(&self, destination: &str) -> Result<(), UtunError> {
        let cmd = format!("route add -net {} -interface {}", destination, self.name);
        let status = std::process::Command::new("sh")
            .args(["-c", &cmd])
            .status()
            .map_err(|e| UtunError::Configure(e.to_string()))?;

        if !status.success() {
            tracing::warn!(dest = destination, "route add failed (may already exist)");
        }
        Ok(())
    }

    /// Remove a route.
    pub fn remove_route(&self, destination: &str) -> Result<(), UtunError> {
        let cmd = format!("route delete -net {}", destination);
        let _ = std::process::Command::new("sh")
            .args(["-c", &cmd])
            .status();
        Ok(())
    }

    /// Read a packet from the utun device.
    ///
    /// The first 4 bytes are the AF header (AF_INET=2 for IPv4).
    /// Returns the packet data without the AF header.
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<(usize, u32)> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if (n as usize) < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet too short for AF header",
            ));
        }
        let af = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Ok(((n as usize) - 4, af))
    }

    /// Write a packet to the utun device.
    ///
    /// Prepends the 4-byte AF header (AF_INET for IPv4).
    pub fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
        let mut buf = Vec::with_capacity(4 + packet.len());
        buf.extend_from_slice(&AF_INET.to_be_bytes());
        buf.extend_from_slice(packet);

        let n = unsafe {
            libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len())
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Set the socket to non-blocking mode.
    pub fn set_nonblocking(&self) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(self.fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for UtunDevice {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
        tracing::debug!(name = %self.name, "utun device closed");
    }
}
