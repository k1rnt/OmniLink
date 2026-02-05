import Foundation
import SystemExtensions
import NetworkExtension
import os.log

/// Manages the OmniLink Network Extension system extension lifecycle.
///
/// Handles installation, activation, and removal of the system extension,
/// as well as enabling/disabling the transparent proxy via NETransparentProxyManager.
public class ExtensionManager: NSObject, OSSystemExtensionRequestDelegate {

    public static let shared = ExtensionManager()

    private let log = OSLog(subsystem: "com.omnilink.app", category: "extension")
    private let extensionBundleId = "com.omnilink.ne-extension"

    private var installCompletion: ((Bool, String?) -> Void)?
    private var uninstallCompletion: ((Bool, String?) -> Void)?

    private override init() {
        super.init()
    }

    // MARK: - Install/Uninstall

    /// Install and activate the system extension.
    public func install(completion: @escaping (Bool, String?) -> Void) {
        os_log("Requesting system extension activation", log: log, type: .info)

        installCompletion = completion

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionBundleId,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Uninstall the system extension.
    public func uninstall(completion: @escaping (Bool, String?) -> Void) {
        os_log("Requesting system extension deactivation", log: log, type: .info)

        uninstallCompletion = completion

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: extensionBundleId,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: - Proxy Enable/Disable

    /// Enable the transparent proxy after the extension is installed.
    public func enableProxy(completion: @escaping (Bool, String?) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }

            if let error = error {
                os_log("Failed to load proxy preferences: %{public}@",
                       log: self.log, type: .error, error.localizedDescription)
                completion(false, error.localizedDescription)
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
                    completion(false, error.localizedDescription)
                    return
                }

                os_log("Proxy preferences saved, starting tunnel", log: self.log, type: .info)

                do {
                    try manager.connection.startVPNTunnel()
                    os_log("Transparent proxy started", log: self.log, type: .info)
                    completion(true, nil)
                } catch {
                    os_log("Failed to start tunnel: %{public}@",
                           log: self.log, type: .error, error.localizedDescription)
                    completion(false, error.localizedDescription)
                }
            }
        }
    }

    /// Disable the transparent proxy.
    public func disableProxy(completion: @escaping (Bool, String?) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }

            if let error = error {
                os_log("Failed to load proxy preferences: %{public}@",
                       log: self.log, type: .error, error.localizedDescription)
                completion(false, error.localizedDescription)
                return
            }

            guard let manager = managers?.first else {
                os_log("No proxy manager found", log: self.log, type: .info)
                completion(true, nil)
                return
            }

            manager.connection.stopVPNTunnel()
            manager.isEnabled = false

            manager.saveToPreferences { error in
                if let error = error {
                    os_log("Failed to disable proxy: %{public}@",
                           log: self.log, type: .error, error.localizedDescription)
                    completion(false, error.localizedDescription)
                } else {
                    os_log("Transparent proxy disabled", log: self.log, type: .info)
                    completion(true, nil)
                }
            }
        }
    }

    // MARK: - Status

    /// Get the current status of the Network Extension.
    public func getStatus(completion: @escaping (NEStatus) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { managers, _ in
            let manager = managers?.first
            let status = NEStatus(
                installed: manager != nil,
                enabled: manager?.isEnabled ?? false,
                running: manager?.connection.status == .connected
            )
            completion(status)
        }
    }

    // MARK: - OSSystemExtensionRequestDelegate

    public func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        os_log("Replacing existing extension (v%{public}@ -> v%{public}@)",
               log: log, type: .info,
               existing.bundleShortVersion, ext.bundleShortVersion)
        return .replace
    }

    public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        os_log("System extension requires user approval (System Preferences > Security & Privacy)",
               log: log, type: .info)
    }

    public func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            os_log("System extension request completed successfully", log: log, type: .info)
            installCompletion?(true, nil)
            uninstallCompletion?(true, nil)
        case .willCompleteAfterReboot:
            os_log("System extension will be activated after reboot", log: log, type: .info)
            installCompletion?(true, "Will complete after reboot")
            uninstallCompletion?(true, "Will complete after reboot")
        @unknown default:
            os_log("System extension request finished with unknown result", log: log, type: .info)
            installCompletion?(true, nil)
            uninstallCompletion?(true, nil)
        }

        installCompletion = nil
        uninstallCompletion = nil
    }

    public func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        os_log("System extension request failed: %{public}@",
               log: log, type: .error, error.localizedDescription)

        installCompletion?(false, error.localizedDescription)
        uninstallCompletion?(false, error.localizedDescription)

        installCompletion = nil
        uninstallCompletion = nil
    }
}

/// Status of the Network Extension.
public struct NEStatus: Codable {
    public let installed: Bool
    public let enabled: Bool
    public let running: Bool

    public init(installed: Bool, enabled: Bool, running: Bool) {
        self.installed = installed
        self.enabled = enabled
        self.running = running
    }
}
