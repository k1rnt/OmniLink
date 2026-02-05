//! Application discovery for installed apps on the system.
//!
//! Platform-specific implementations:
//! - macOS: Scans /Applications and ~/Applications for .app bundles
//! - Windows: Reads registry and scans Program Files (TODO)
//! - Linux: Parses .desktop files (TODO)

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Information about an installed application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationInfo {
    /// Display name of the application (e.g., "Google Chrome")
    pub name: String,
    /// Bundle identifier (macOS) or package name
    pub bundle_id: Option<String>,
    /// Executable name that appears as process_name at runtime
    pub executable_name: String,
    /// Full path to the main executable
    pub executable_path: String,
    /// Base64-encoded icon (PNG format, 48x48)
    pub icon_base64: Option<String>,
    /// Application version string
    pub version: Option<String>,
}

/// Discover installed applications on the system.
pub fn discover_apps() -> Vec<ApplicationInfo> {
    #[cfg(target_os = "macos")]
    {
        discover_macos_apps()
    }
    #[cfg(target_os = "windows")]
    {
        discover_windows_apps()
    }
    #[cfg(target_os = "linux")]
    {
        discover_linux_apps()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "macos")]
fn discover_macos_apps() -> Vec<ApplicationInfo> {
    use std::fs;

    let mut apps = Vec::new();
    let mut paths_to_scan = vec![PathBuf::from("/Applications")];

    // Add ~/Applications if it exists
    if let Some(home) = dirs::home_dir() {
        let user_apps = home.join("Applications");
        if user_apps.exists() {
            paths_to_scan.push(user_apps);
        }
    }

    for base_path in paths_to_scan {
        if let Ok(entries) = fs::read_dir(&base_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "app").unwrap_or(false) {
                    if let Some(app_info) = parse_macos_app(&path) {
                        apps.push(app_info);
                    }
                }
            }
        }
    }

    // Sort by name
    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    apps
}

#[cfg(target_os = "macos")]
fn parse_macos_app(app_path: &Path) -> Option<ApplicationInfo> {
    let info_plist_path = app_path.join("Contents/Info.plist");
    if !info_plist_path.exists() {
        return None;
    }

    let plist = plist::Value::from_file(&info_plist_path).ok()?;
    let dict = plist.as_dictionary()?;

    // Get bundle name (display name)
    let name = dict
        .get("CFBundleName")
        .or_else(|| dict.get("CFBundleDisplayName"))
        .and_then(|v| v.as_string())
        .map(String::from)
        .or_else(|| {
            // Fallback to filename without .app
            app_path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(String::from)
        })?;

    // Get bundle identifier
    let bundle_id = dict
        .get("CFBundleIdentifier")
        .and_then(|v| v.as_string())
        .map(String::from);

    // Get executable name
    let executable_name = dict
        .get("CFBundleExecutable")
        .and_then(|v| v.as_string())
        .map(String::from)
        .or_else(|| {
            // Fallback to bundle name
            Some(name.clone())
        })?;

    // Build executable path
    let executable_path = app_path
        .join("Contents/MacOS")
        .join(&executable_name)
        .to_string_lossy()
        .to_string();

    // Get version
    let version = dict
        .get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .map(String::from);

    Some(ApplicationInfo {
        name,
        bundle_id,
        executable_name,
        executable_path,
        icon_base64: None, // Icons loaded lazily to improve performance
        version,
    })
}

#[cfg(target_os = "windows")]
fn discover_windows_apps() -> Vec<ApplicationInfo> {
    // TODO: Implement Windows app discovery
    // - Read HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
    // - Scan C:\Program Files and C:\Program Files (x86)
    Vec::new()
}

#[cfg(target_os = "linux")]
fn discover_linux_apps() -> Vec<ApplicationInfo> {
    use std::fs;

    let mut apps = Vec::new();
    let desktop_dirs = [
        PathBuf::from("/usr/share/applications"),
        dirs::home_dir()
            .map(|h| h.join(".local/share/applications"))
            .unwrap_or_default(),
    ];

    for dir in desktop_dirs.iter().filter(|p| p.exists()) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "desktop").unwrap_or(false) {
                    if let Some(app_info) = parse_linux_desktop_file(&path) {
                        apps.push(app_info);
                    }
                }
            }
        }
    }

    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    apps
}

#[cfg(target_os = "linux")]
fn parse_linux_desktop_file(path: &Path) -> Option<ApplicationInfo> {
    use std::fs;
    use std::io::{BufRead, BufReader};

    let file = fs::File::open(path).ok()?;
    let reader = BufReader::new(file);

    let mut name = None;
    let mut exec = None;
    let mut in_desktop_entry = false;

    for line in reader.lines().flatten() {
        let line = line.trim();
        if line == "[Desktop Entry]" {
            in_desktop_entry = true;
            continue;
        }
        if line.starts_with('[') {
            in_desktop_entry = false;
            continue;
        }
        if !in_desktop_entry {
            continue;
        }

        if let Some(value) = line.strip_prefix("Name=") {
            if name.is_none() {
                name = Some(value.to_string());
            }
        } else if let Some(value) = line.strip_prefix("Exec=") {
            // Extract executable name from Exec line
            // e.g., "/usr/bin/firefox %u" -> "firefox"
            let exec_path = value.split_whitespace().next()?;
            exec = Some(exec_path.to_string());
        }
    }

    let name = name?;
    let exec_path = exec?;
    let executable_name = Path::new(&exec_path)
        .file_name()
        .and_then(|s| s.to_str())
        .map(String::from)
        .unwrap_or_else(|| exec_path.clone());

    Some(ApplicationInfo {
        name,
        bundle_id: None,
        executable_name,
        executable_path: exec_path,
        icon_base64: None,
        version: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_apps() {
        let apps = discover_apps();
        // Should find at least some apps on any system
        println!("Found {} apps", apps.len());
        for app in apps.iter().take(5) {
            println!("  - {} ({})", app.name, app.executable_name);
        }
    }
}
