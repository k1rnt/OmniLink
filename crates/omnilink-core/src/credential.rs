//! OS Keychain/Credential Manager integration for secure credential storage.
//!
//! Stores proxy authentication credentials in the OS-native secure storage:
//! - macOS: Keychain
//! - Windows: Credential Manager
//! - Linux: Secret Service (via libsecret/GNOME Keyring)

use keyring::Entry;
use thiserror::Error;

const SERVICE_NAME: &str = "omnilink";

/// Errors that can occur during credential operations.
#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("credential not found: {0}")]
    NotFound(String),
    #[error("keyring error: {0}")]
    Keyring(String),
}

/// Manager for storing and retrieving proxy credentials from OS keychain.
pub struct CredentialManager;

impl CredentialManager {
    /// Store credentials in OS keychain.
    ///
    /// Credentials are stored under the service name "omnilink" with the proxy name as the key.
    /// The username and password are combined as "username:password" format.
    pub fn store(proxy_name: &str, username: &str, password: &str) -> Result<(), CredentialError> {
        let entry = Entry::new(SERVICE_NAME, proxy_name)
            .map_err(|e| CredentialError::Keyring(e.to_string()))?;

        // Store as "username:password" format
        let secret = format!("{}:{}", username, password);
        entry
            .set_password(&secret)
            .map_err(|e| CredentialError::Keyring(e.to_string()))?;

        Ok(())
    }

    /// Retrieve credentials from OS keychain.
    ///
    /// Returns (username, password) tuple if found.
    pub fn retrieve(proxy_name: &str) -> Result<(String, String), CredentialError> {
        let entry = Entry::new(SERVICE_NAME, proxy_name)
            .map_err(|e| CredentialError::Keyring(e.to_string()))?;

        let secret = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => CredentialError::NotFound(proxy_name.to_string()),
            _ => CredentialError::Keyring(e.to_string()),
        })?;

        // Parse "username:password" format
        let parts: Vec<&str> = secret.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(CredentialError::Keyring(
                "invalid credential format".to_string(),
            ));
        }

        Ok((parts[0].to_string(), parts[1].to_string()))
    }

    /// Delete credentials from OS keychain.
    pub fn delete(proxy_name: &str) -> Result<(), CredentialError> {
        let entry = Entry::new(SERVICE_NAME, proxy_name)
            .map_err(|e| CredentialError::Keyring(e.to_string()))?;

        entry
            .delete_credential()
            .map_err(|e| CredentialError::Keyring(e.to_string()))?;

        Ok(())
    }

    /// Check if credentials exist for a proxy.
    pub fn exists(proxy_name: &str) -> bool {
        Self::retrieve(proxy_name).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // This test requires access to OS keychain which may not be available in CI.
    // Run manually with: cargo test -p omnilink-core credential -- --ignored
    #[test]
    #[ignore]
    fn test_credential_roundtrip() {
        let proxy_name = "omnilink-test-proxy";
        let username = "testuser";
        let password = "testpass:with:colons";

        // Clean up any existing entry
        let _ = CredentialManager::delete(proxy_name);

        // Store
        CredentialManager::store(proxy_name, username, password).unwrap();

        // Check exists
        assert!(CredentialManager::exists(proxy_name));

        // Retrieve
        let (u, p) = CredentialManager::retrieve(proxy_name).unwrap();
        assert_eq!(u, username);
        assert_eq!(p, password);

        // Delete
        CredentialManager::delete(proxy_name).unwrap();

        // Check not exists
        assert!(!CredentialManager::exists(proxy_name));
    }
}
