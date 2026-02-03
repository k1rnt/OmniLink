use std::process::Command;

/// System proxy configuration helper.
/// Sets and unsets the OS-level SOCKS proxy so that applications
/// following system proxy settings are routed through OmniLink.

#[derive(Debug, Clone)]
pub struct SysProxyConfig {
    pub host: String,
    pub port: u16,
}

impl SysProxyConfig {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
        }
    }

    /// Enable system SOCKS proxy.
    pub fn enable(&self) -> Result<(), SysProxyError> {
        #[cfg(target_os = "macos")]
        return self.enable_macos();

        #[cfg(target_os = "linux")]
        return self.enable_linux();

        #[cfg(target_os = "windows")]
        return self.enable_windows();

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        Err(SysProxyError::Unsupported)
    }

    /// Disable system SOCKS proxy.
    pub fn disable(&self) -> Result<(), SysProxyError> {
        #[cfg(target_os = "macos")]
        return self.disable_macos();

        #[cfg(target_os = "linux")]
        return self.disable_linux();

        #[cfg(target_os = "windows")]
        return self.disable_windows();

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        Err(SysProxyError::Unsupported)
    }

    #[cfg(target_os = "macos")]
    fn enable_macos(&self) -> Result<(), SysProxyError> {
        let services = list_macos_network_services()?;

        for service in &services {
            // Enable SOCKS proxy
            run_cmd(
                "networksetup",
                &["-setsocksfirewallproxy", service, &self.host, &self.port.to_string()],
            )?;
            run_cmd(
                "networksetup",
                &["-setsocksfirewallproxystate", service, "on"],
            )?;
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn disable_macos(&self) -> Result<(), SysProxyError> {
        let services = list_macos_network_services()?;

        for service in &services {
            run_cmd(
                "networksetup",
                &["-setsocksfirewallproxystate", service, "off"],
            )?;
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn enable_linux(&self) -> Result<(), SysProxyError> {
        // GNOME / gsettings
        if which_exists("gsettings") {
            run_cmd("gsettings", &[
                "set", "org.gnome.system.proxy", "mode", "manual",
            ])?;
            run_cmd("gsettings", &[
                "set", "org.gnome.system.proxy.socks", "host", &self.host,
            ])?;
            run_cmd("gsettings", &[
                "set", "org.gnome.system.proxy.socks", "port", &self.port.to_string(),
            ])?;
            return Ok(());
        }

        // KDE / kwriteconfig5
        if which_exists("kwriteconfig5") {
            run_cmd("kwriteconfig5", &[
                "--file", "kioslaverc",
                "--group", "Proxy Settings",
                "--key", "ProxyType", "1",
            ])?;
            run_cmd("kwriteconfig5", &[
                "--file", "kioslaverc",
                "--group", "Proxy Settings",
                "--key", "socksProxy",
                &format!("socks://{}:{}", self.host, self.port),
            ])?;
            return Ok(());
        }

        Err(SysProxyError::Unsupported)
    }

    #[cfg(target_os = "linux")]
    fn disable_linux(&self) -> Result<(), SysProxyError> {
        if which_exists("gsettings") {
            run_cmd("gsettings", &[
                "set", "org.gnome.system.proxy", "mode", "none",
            ])?;
            return Ok(());
        }

        if which_exists("kwriteconfig5") {
            run_cmd("kwriteconfig5", &[
                "--file", "kioslaverc",
                "--group", "Proxy Settings",
                "--key", "ProxyType", "0",
            ])?;
            return Ok(());
        }

        Err(SysProxyError::Unsupported)
    }

    #[cfg(target_os = "windows")]
    fn enable_windows(&self) -> Result<(), SysProxyError> {
        let proxy_value = format!("socks={}:{}", self.host, self.port);
        run_cmd("reg", &[
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f",
        ])?;
        run_cmd("reg", &[
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v", "ProxyServer", "/t", "REG_SZ", "/d", &proxy_value, "/f",
        ])?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn disable_windows(&self) -> Result<(), SysProxyError> {
        run_cmd("reg", &[
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f",
        ])?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SysProxyError {
    #[error("command failed: {0}")]
    CommandFailed(String),
    #[error("platform not supported for system proxy configuration")]
    Unsupported,
}

fn run_cmd(program: &str, args: &[&str]) -> Result<(), SysProxyError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| SysProxyError::CommandFailed(format!("{}: {}", program, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SysProxyError::CommandFailed(format!(
            "{} exited with {}: {}",
            program,
            output.status,
            stderr.trim()
        )));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn list_macos_network_services() -> Result<Vec<String>, SysProxyError> {
    let output = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .map_err(|e| SysProxyError::CommandFailed(format!("networksetup: {}", e)))?;

    if !output.status.success() {
        return Err(SysProxyError::CommandFailed(
            "failed to list network services".to_string(),
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let services: Vec<String> = text
        .lines()
        .skip(1) // skip the header line
        .filter(|line| !line.starts_with('*')) // skip disabled services
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Ok(services)
}

#[cfg(target_os = "linux")]
fn which_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
