//! IOCTL client for communicating with the OmniLink WFP callout driver.
//!
//! Opens a handle to `\\.\OmniLinkWFP` and issues DeviceIoControl calls
//! to configure the driver and query NAT entries.

use std::mem;
use std::ptr;

use anyhow::{Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

const FILE_DEVICE_NETWORK: u32 = 0x00000012;

fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const METHOD_BUFFERED: u32 = 0;
const FILE_READ_ACCESS: u32 = 1;
const FILE_WRITE_ACCESS: u32 = 2;

const IOCTL_OMNILINK_GET_ORIGINAL_DST: u32 =
    ctl_code(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS);
const IOCTL_OMNILINK_SET_CONFIG: u32 =
    ctl_code(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS);
const IOCTL_OMNILINK_GET_STATS: u32 =
    ctl_code(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS);

/// Driver configuration sent via IOCTL.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DriverConfig {
    pub proxy_addr: u32,
    pub proxy_port: u16,
    pub proxy_pid: u32,
    pub enabled: u8,
}

/// Query for original destination lookup.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OriginalDstQuery {
    pub src_addr: u32,
    pub src_port: u16,
}

/// Result of original destination lookup (field order matches C driver).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OriginalDstResult {
    pub original_addr: u32,
    pub process_id: u32,
    pub original_port: u16,
    pub found: u8,
}

/// Driver statistics.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DriverStats {
    pub total_intercepted: u64,
    pub total_passed: u64,
    pub active_nat_entries: u64,
}

/// Client for the OmniLink WFP callout driver.
pub struct WfpClient {
    handle: HANDLE,
}

impl WfpClient {
    /// Open a handle to the WFP driver device.
    pub fn open() -> Result<Self> {
        let device_path: Vec<u16> = "\\\\.\\OmniLinkWFP\0".encode_utf16().collect();

        let handle = unsafe {
            CreateFileW(
                PCWSTR(device_path.as_ptr()),
                (FILE_READ_ACCESS | FILE_WRITE_ACCESS).into(),
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .context("Failed to open WFP driver device")?
        };

        Ok(Self { handle })
    }

    /// Send configuration to the driver.
    pub fn set_config(&self, config: &DriverConfig) -> Result<()> {
        let mut bytes_returned: u32 = 0;

        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_OMNILINK_SET_CONFIG,
                Some(config as *const DriverConfig as *const _),
                mem::size_of::<DriverConfig>() as u32,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
            .context("IOCTL_OMNILINK_SET_CONFIG failed")?;
        }

        Ok(())
    }

    /// Query the original destination for a redirected connection.
    pub fn get_original_dst(
        &self,
        src_addr: u32,
        src_port: u16,
    ) -> Result<Option<(u32, u16, u32)>> {
        let query = OriginalDstQuery { src_addr, src_port };
        let mut result = OriginalDstResult {
            original_addr: 0,
            process_id: 0,
            original_port: 0,
            found: 0,
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_OMNILINK_GET_ORIGINAL_DST,
                Some(&query as *const OriginalDstQuery as *const _),
                mem::size_of::<OriginalDstQuery>() as u32,
                Some(&mut result as *mut OriginalDstResult as *mut _),
                mem::size_of::<OriginalDstResult>() as u32,
                Some(&mut bytes_returned),
                None,
            )
            .context("IOCTL_OMNILINK_GET_ORIGINAL_DST failed")?;
        }

        if result.found != 0 {
            Ok(Some((result.original_addr, result.original_port, result.process_id)))
        } else {
            Ok(None)
        }
    }

    /// Get driver statistics.
    pub fn get_stats(&self) -> Result<DriverStats> {
        let mut stats = DriverStats {
            total_intercepted: 0,
            total_passed: 0,
            active_nat_entries: 0,
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_OMNILINK_GET_STATS,
                None,
                0,
                Some(&mut stats as *mut DriverStats as *mut _),
                mem::size_of::<DriverStats>() as u32,
                Some(&mut bytes_returned),
                None,
            )
            .context("IOCTL_OMNILINK_GET_STATS failed")?;
        }

        Ok(stats)
    }
}

impl Drop for WfpClient {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
