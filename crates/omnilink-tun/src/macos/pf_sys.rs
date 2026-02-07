//! FFI definitions for macOS Packet Filter (pf) kernel interface.
//!
//! These structures match Apple's XNU `net/pfvar.h` layout and are used
//! to query the original destination of NAT-redirected connections via
//! the `DIOCNATLOOK` ioctl on `/dev/pf`.

/// PF direction: inbound (used for rdr rules).
pub const PF_IN: u8 = 1;
/// PF direction: outbound (used for nat rules).
pub const PF_OUT: u8 = 2;

/// IPv4 address family.
pub const AF_INET: u8 = 2;

/// TCP protocol number.
pub const IPPROTO_TCP: u8 = 6;

/// pf_addr: 16-byte address union (IPv4 or IPv6).
#[repr(C)]
#[derive(Copy, Clone)]
pub union PfAddr {
    pub v4: u32,          // network byte order
    pub v6: [u32; 4],     // network byte order
    pub addr8: [u8; 16],
    pub addr16: [u16; 8],
    pub addr32: [u32; 4],
}

impl Default for PfAddr {
    fn default() -> Self {
        PfAddr { addr8: [0u8; 16] }
    }
}

/// pf_state_xport: 4-byte port/SPI union (Darwin-specific).
#[repr(C)]
#[derive(Copy, Clone)]
pub union PfStateXport {
    pub port: u16,     // network byte order
    pub call_id: u16,
    pub spi: u32,
}

impl Default for PfStateXport {
    fn default() -> Self {
        PfStateXport { spi: 0 }
    }
}

/// pfioc_natlook: the main structure for `DIOCNATLOOK` ioctl.
///
/// Darwin layout: 4 * PfAddr (16) + 4 * PfStateXport (4) + 4 * u8 = 84 bytes.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PfiocNatlook {
    pub saddr: PfAddr,           // source address
    pub daddr: PfAddr,           // destination address
    pub rsaddr: PfAddr,          // result: real source address
    pub rdaddr: PfAddr,          // result: real destination address
    pub sxport: PfStateXport,    // source port
    pub dxport: PfStateXport,    // destination port
    pub rsxport: PfStateXport,   // result: real source port
    pub rdxport: PfStateXport,   // result: real destination port
    pub af: u8,                  // address family (AF_INET = 2)
    pub proto: u8,               // protocol (IPPROTO_TCP = 6)
    pub proto_variant: u8,
    pub direction: u8,           // PF_OUT = 2
}

impl Default for PfiocNatlook {
    fn default() -> Self {
        // Safety: all-zero is valid for this repr(C) struct
        unsafe { std::mem::zeroed() }
    }
}

/// Calculate the `DIOCNATLOOK` ioctl request number.
///
/// Formula: `_IOWR('D', 23, struct pfioc_natlook)`
/// = `IOC_INOUT | ((size & IOCPARM_MASK) << 16) | ('D' << 8) | 23`
pub fn diocnatlook_ioctl() -> libc::c_ulong {
    let size = std::mem::size_of::<PfiocNatlook>() as libc::c_ulong;
    // IOC_INOUT = 0xC0000000, IOCPARM_MASK = 0x1FFF
    0xC000_0000 | ((size & 0x1FFF) << 16) | ((b'D' as libc::c_ulong) << 8) | 23
}

// Compile-time size assertions to catch layout mismatches.
const _: () = {
    assert!(std::mem::size_of::<PfAddr>() == 16);
    assert!(std::mem::size_of::<PfStateXport>() == 4);
    assert!(std::mem::size_of::<PfiocNatlook>() == 84);
};
