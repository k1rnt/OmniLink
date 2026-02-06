pub mod packet;
pub mod device;
pub mod interceptor;
pub mod nat;
pub mod dns_intercept;
pub mod process;

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

/// Create a Network Extension interceptor for macOS.
///
/// This interceptor communicates with the NETransparentProxyProvider system extension
/// via a Unix domain socket. If `socket_path` is provided, it overrides the default path.
#[cfg(target_os = "macos")]
pub fn create_ne_interceptor(
    rule_engine: std::sync::Arc<omnilink_core::rule::RuleEngine>,
    chain_relay: std::sync::Arc<omnilink_core::proxy::chain::ChainRelay>,
    virtual_dns: std::sync::Arc<omnilink_core::dns::VirtualDns>,
    session_manager: std::sync::Arc<omnilink_core::session::SessionManager>,
    socket_path: Option<&str>,
) -> Box<dyn interceptor::Interceptor> {
    let mut interceptor = macos::ne_interceptor::NEInterceptor::new(
        rule_engine,
        chain_relay,
        virtual_dns,
        session_manager,
    );
    if let Some(path) = socket_path {
        interceptor = interceptor.with_socket_path(path);
    }
    Box::new(interceptor)
}

#[cfg(target_os = "linux")]
pub fn create_interceptor(
    virtual_dns: std::sync::Arc<omnilink_core::dns::VirtualDns>,
    excluded_ips: Vec<std::net::Ipv4Addr>,
) -> Box<dyn interceptor::Interceptor> {
    #[cfg(feature = "ebpf")]
    {
        Box::new(linux::ebpf_interceptor::EbpfInterceptor::new(virtual_dns, excluded_ips))
    }
    #[cfg(not(feature = "ebpf"))]
    {
        Box::new(linux::interceptor::LinuxInterceptor::new(virtual_dns, excluded_ips))
    }
}

#[cfg(target_os = "windows")]
pub fn create_interceptor(
    _virtual_dns: std::sync::Arc<omnilink_core::dns::VirtualDns>,
    _excluded_ips: Vec<std::net::Ipv4Addr>,
) -> Box<dyn interceptor::Interceptor> {
    Box::new(windows::interceptor::WindowsInterceptor::new())
}
