import Foundation
import SystemExtensions
import NetworkExtension

/// CLI helper for managing the OmniLink Network Extension.
/// This is called from the Rust/Tauri backend to install, enable, and manage the extension.

let args = CommandLine.arguments

guard args.count >= 2 else {
    printUsage()
    exit(1)
}

let command = args[1]

switch command {
case "install":
    installExtension()
case "uninstall":
    uninstallExtension()
case "enable":
    enableProxy()
case "disable":
    disableProxy()
case "status":
    printStatus()
case "help", "-h", "--help":
    printUsage()
    exit(0)
default:
    print("Unknown command: \(command)")
    printUsage()
    exit(1)
}

// Run the run loop to allow async operations to complete
RunLoop.main.run(until: Date(timeIntervalSinceNow: 10))

// MARK: - Commands

func printUsage() {
    print("""
    Usage: omnilink-ne-helper <command>

    Commands:
      install    Request system extension activation
      uninstall  Request system extension deactivation
      enable     Enable the transparent proxy
      disable    Disable the transparent proxy
      status     Print current status as JSON
      help       Show this help message
    """)
}

func installExtension() {
    print("Requesting system extension activation...")
    let manager = ExtensionManager.shared
    manager.install { success, error in
        if success {
            print("Extension activation requested successfully")
            print("Note: User may need to approve in System Preferences > Security & Privacy")
        } else {
            print("Failed to request activation: \(error ?? "unknown error")")
        }
        exit(success ? 0 : 1)
    }
}

func uninstallExtension() {
    print("Requesting system extension deactivation...")
    let manager = ExtensionManager.shared
    manager.uninstall { success, error in
        if success {
            print("Extension deactivation requested successfully")
        } else {
            print("Failed to request deactivation: \(error ?? "unknown error")")
        }
        exit(success ? 0 : 1)
    }
}

func enableProxy() {
    print("Enabling transparent proxy...")
    let manager = ExtensionManager.shared
    manager.enableProxy { success, error in
        if success {
            print("Transparent proxy enabled")
        } else {
            print("Failed to enable proxy: \(error ?? "unknown error")")
        }
        exit(success ? 0 : 1)
    }
}

func disableProxy() {
    print("Disabling transparent proxy...")
    let manager = ExtensionManager.shared
    manager.disableProxy { success, error in
        if success {
            print("Transparent proxy disabled")
        } else {
            print("Failed to disable proxy: \(error ?? "unknown error")")
        }
        exit(success ? 0 : 1)
    }
}

func printStatus() {
    let manager = ExtensionManager.shared
    manager.getStatus { status in
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        if let data = try? encoder.encode(status),
           let json = String(data: data, encoding: .utf8) {
            print(json)
        } else {
            print("{\"error\": \"Failed to encode status\"}")
        }
        exit(0)
    }
}

// MARK: - Extension Manager (Singleton wrapper)

class ExtensionManager: NSObject, OSSystemExtensionRequestDelegate {
    static let shared = ExtensionManager()

    private let extensionBundleId = "com.omnilink.ne-extension"
    private var installCompletion: ((Bool, String?) -> Void)?
    private var uninstallCompletion: ((Bool, String?) -> Void)?

    override private init() {
        super.init()
    }

    // MARK: - Install/Uninstall

    func install(completion: @escaping (Bool, String?) -> Void) {
        installCompletion = completion

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionBundleId,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func uninstall(completion: @escaping (Bool, String?) -> Void) {
        uninstallCompletion = completion

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: extensionBundleId,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: - Proxy Enable/Disable

    func enableProxy(completion: @escaping (Bool, String?) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error = error {
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
                    completion(false, error.localizedDescription)
                    return
                }

                do {
                    try manager.connection.startVPNTunnel()
                    completion(true, nil)
                } catch {
                    completion(false, error.localizedDescription)
                }
            }
        }
    }

    func disableProxy(completion: @escaping (Bool, String?) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error = error {
                completion(false, error.localizedDescription)
                return
            }

            guard let manager = managers?.first else {
                completion(true, nil) // No manager = already disabled
                return
            }

            manager.connection.stopVPNTunnel()
            manager.isEnabled = false

            manager.saveToPreferences { error in
                if let error = error {
                    completion(false, error.localizedDescription)
                } else {
                    completion(true, nil)
                }
            }
        }
    }

    // MARK: - Status

    func getStatus(completion: @escaping (NEStatus) -> Void) {
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

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("System extension requires user approval in System Preferences")
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            if request.identifier.contains("activation") {
                installCompletion?(true, nil)
            } else {
                uninstallCompletion?(true, nil)
            }
        case .willCompleteAfterReboot:
            let completion = installCompletion ?? uninstallCompletion
            completion?(true, "Will complete after reboot")
        @unknown default:
            let completion = installCompletion ?? uninstallCompletion
            completion?(true, nil)
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        if request.identifier.contains("activation") {
            installCompletion?(false, error.localizedDescription)
        } else {
            uninstallCompletion?(false, error.localizedDescription)
        }
    }
}

// MARK: - Status Struct

struct NEStatus: Codable {
    let installed: Bool
    let enabled: Bool
    let running: Bool
}
