//! macOS privilege escalation via native admin password dialog.
//!
//! Uses `osascript` to invoke `do shell script ... with administrator privileges`,
//! which presents the standard macOS authentication dialog.

use crate::interceptor::InterceptorError;

/// Execute a shell command with administrator privileges.
///
/// This triggers macOS's native admin password dialog via `osascript`.
/// Returns the stdout of the command on success.
pub fn run_with_admin_privileges(command: &str) -> Result<String, InterceptorError> {
    let escaped = command.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        r#"do shell script "{}" with administrator privileges"#,
        escaped
    );

    let output = std::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| {
            InterceptorError::PrivilegeRequired(format!("failed to run osascript: {}", e))
        })?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("User canceled") || stderr.contains("-128") {
            Err(InterceptorError::PrivilegeRequired(
                "user cancelled admin authorization".to_string(),
            ))
        } else {
            Err(InterceptorError::PrivilegeRequired(format!(
                "admin command failed: {}",
                stderr.trim()
            )))
        }
    }
}
