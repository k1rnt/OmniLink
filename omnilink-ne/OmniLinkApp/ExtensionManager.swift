import Foundation
import SystemExtensions
import NetworkExtension
import os.log

/// Manages the OmniLink Network Extension system extension lifecycle.
///
/// Handles installation, activation, and removal of the system extension,
/// as well as enabling/disabling the transparent proxy via NETransparentProxyManager.
class ExtensionManager: NSObject, OSSystemExtensionRequestDelegate {

    private let log = OSLog(subsystem: "com.omnilink.app", category: "extension")
    private let extensionBundleId = "com.omnilink.ne-extension"

    /// Install and activate the system extension.
    func install() {
        os_log("Requesting system extension activation", log: log, type: .info)

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionBundleId,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Uninstall the system extension.
    func uninstall() {
        os_log("Requesting system extension deactivation", log: log, type: .info)

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: extensionBundleId,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Enable the transparent proxy after the extension is installed.
    func enableProxy() {
        NETransparentProxyManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }

            if let error = error {
                os_log("Failed to load proxy preferences: %{public}@",
                       log: self.log, type: .error, error.localizedDescription)
                return
            }

            let manager = managers?.first ?? NETransparentProxyManager()

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = self.extensionBundleId
            proto.serverAddress = "OmniLink"

            manager.providerProtocol = proto
            manager.isEnabled = true
            manager.localizedDescription = "OmniLink Transparent Proxy"

            manager.saveToPreferences { error in
                if let error = error {
                    os_log("Failed to save proxy preferences: %{public}@",
                           log: self.log, type: .error, error.localizedDescription)
                    return
                }

                os_log("Proxy preferences saved, starting tunnel", log: self.log, type: .info)

                do {
                    try manager.connection.startVPNTunnel()
                    os_log("Transparent proxy started", log: self.log, type: .info)
                } catch {
                    os_log("Failed to start tunnel: %{public}@",
                           log: self.log, type: .error, error.localizedDescription)
                }
            }
        }
    }

    /// Disable the transparent proxy.
    func disableProxy() {
        NETransparentProxyManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }

            if let error = error {
                os_log("Failed to load proxy preferences: %{public}@",
                       log: self.log, type: .error, error.localizedDescription)
                return
            }

            guard let manager = managers?.first else {
                os_log("No proxy manager found", log: self.log, type: .info)
                return
            }

            manager.connection.stopVPNTunnel()
            manager.isEnabled = false

            manager.saveToPreferences { error in
                if let error = error {
                    os_log("Failed to disable proxy: %{public}@",
                           log: self.log, type: .error, error.localizedDescription)
                } else {
                    os_log("Transparent proxy disabled", log: self.log, type: .info)
                }
            }
        }
    }

    // MARK: - OSSystemExtensionRequestDelegate

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        os_log("Replacing existing extension (v%{public}@ -> v%{public}@)",
               log: log, type: .info,
               existing.bundleShortVersion, ext.bundleShortVersion)
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        os_log("System extension requires user approval (System Preferences > Security & Privacy)",
               log: log, type: .info)
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            os_log("System extension request completed successfully", log: log, type: .info)
        case .willCompleteAfterReboot:
            os_log("System extension will be activated after reboot", log: log, type: .info)
        @unknown default:
            os_log("System extension request finished with unknown result", log: log, type: .info)
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        os_log("System extension request failed: %{public}@",
               log: log, type: .error, error.localizedDescription)
    }
}
