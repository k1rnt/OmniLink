pub mod packet;
pub mod device;
pub mod interceptor;
pub mod nat;
pub mod dns_intercept;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

/// Create a platform-appropriate interceptor.
///
/// Returns `None` on unsupported platforms.
#[cfg(target_os = "macos")]
pub fn create_interceptor(
    virtual_dns: std::sync::Arc<omnilink_core::dns::VirtualDns>,
    excluded_ips: Vec<std::net::Ipv4Addr>,
) -> Box<dyn interceptor::Interceptor> {
    Box::new(macos::interceptor::MacosInterceptor::new(virtual_dns, excluded_ips))
}

#[cfg(target_os = "linux")]
pub fn create_interceptor(
    virtual_dns: std::sync::Arc<omnilink_core::dns::VirtualDns>,
    excluded_ips: Vec<std::net::Ipv4Addr>,
) -> Box<dyn interceptor::Interceptor> {
    Box::new(linux::interceptor::LinuxInterceptor::new(virtual_dns, excluded_ips))
}

#[cfg(target_os = "windows")]
pub fn create_interceptor(
    _virtual_dns: std::sync::Arc<omnilink_core::dns::VirtualDns>,
    _excluded_ips: Vec<std::net::Ipv4Addr>,
) -> Box<dyn interceptor::Interceptor> {
    Box::new(windows::interceptor::WindowsInterceptor::new())
}
