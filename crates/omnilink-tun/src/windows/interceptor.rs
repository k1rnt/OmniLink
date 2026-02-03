use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::interceptor::{Interceptor, InterceptorError, InterceptorEvent};

// TODO: Implement WFP (Windows Filtering Platform) driver-based interceptor.
//   - FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6 hooking
//   - Kernel Mode Callout Driver (.sys)
//   - EV certificate + Microsoft Attestation Signing required
//   - UWP / AppContainer loopback exemption handling

/// Windows interceptor stub (WFP-based, not yet implemented).
pub struct WindowsInterceptor;

impl WindowsInterceptor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Interceptor for WindowsInterceptor {
    async fn start(&mut self) -> Result<mpsc::Receiver<InterceptorEvent>, InterceptorError> {
        Err(InterceptorError::NotSupported)
    }

    async fn stop(&mut self) -> Result<(), InterceptorError> {
        Err(InterceptorError::NotSupported)
    }
}
