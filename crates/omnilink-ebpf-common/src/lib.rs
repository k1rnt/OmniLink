#![cfg_attr(not(feature = "user"), no_std)]

/// Key for the original destination map.
/// Uses the socket cookie as a unique identifier.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SockKey {
    pub cookie: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SockKey {}

/// Value stored in the original destination map.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OriginalDest {
    /// IPv4 address in network byte order.
    pub addr: u32,
    /// Port in network byte order.
    pub port: u16,
    pub _pad: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OriginalDest {}

/// Key for the port-to-cookie map.
/// Used by getsockopt to find the cookie from the source port.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PortKey {
    pub src_port: u16,
    pub _pad: [u8; 6],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PortKey {}

/// Configuration passed to eBPF programs via a BPF array map.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InterceptConfig {
    /// Local proxy address in network byte order (typically 127.0.0.1 = 0x0100007f).
    pub proxy_addr: u32,
    /// Local proxy port in network byte order.
    pub proxy_port: u16,
    pub _pad: u16,
    /// PID of the proxy process itself (excluded from interception to prevent loops).
    pub pid_self: u32,
    pub _pad2: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for InterceptConfig {}
