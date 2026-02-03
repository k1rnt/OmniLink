import Foundation
import os.log

/// XPC server running in the main app process.
///
/// Listens for connections from the NE extension and dispatches
/// routing decisions and data relay requests to the Rust backend.
class XPCServer: NSObject, NSXPCListenerDelegate, OmniLinkXPCProtocol {

    private let log = OSLog(subsystem: "com.omnilink.app", category: "xpc-server")
    private var listener: NSXPCListener?

    /// Start the XPC listener.
    func start() {
        listener = NSXPCListener(machServiceName: kOmniLinkXPCServiceName)
        listener?.delegate = self
        listener?.resume()
        os_log("XPC server started on %{public}@", log: log, type: .info, kOmniLinkXPCServiceName)
    }

    /// Stop the XPC listener.
    func stop() {
        listener?.invalidate()
        listener = nil
        os_log("XPC server stopped", log: log, type: .info)
    }

    // MARK: - NSXPCListenerDelegate

    func listener(_ listener: NSXPCListener,
                  shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        let interface = NSXPCInterface(with: OmniLinkXPCProtocol.self)
        newConnection.exportedInterface = interface
        newConnection.exportedObject = self
        newConnection.resume()

        os_log("Accepted XPC connection from extension", log: log, type: .info)
        return true
    }

    // MARK: - OmniLinkXPCProtocol

    func getRoutingDecision(sourceAppIdentifier: String,
                            destinationHost: String,
                            destinationPort: Int,
                            reply: @escaping (String, String) -> Void) {
        // TODO: Call into Rust backend (omnilink-core rule engine) via FFI
        // For now, return direct for all connections
        os_log("Routing decision requested: %{public}@ -> %{public}@:%d",
               log: log, type: .debug, sourceAppIdentifier, destinationHost, destinationPort)
        reply("direct", "")
    }

    func relayData(flowId: String, data: Data, direction: String,
                   reply: @escaping (Bool) -> Void) {
        // TODO: Forward data to/from the Rust proxy relay
        reply(true)
    }

    func flowClosed(flowId: String) {
        // TODO: Notify Rust backend to clean up flow state
        os_log("Flow closed: %{public}@", log: log, type: .debug, flowId)
    }

    func connectFlow(flowId: String, destinationHost: String, destinationPort: Int,
                     proxyName: String, reply: @escaping (Bool, String) -> Void) {
        // TODO: Call Rust backend to establish outbound connection
        os_log("Connect flow %{public}@ -> %{public}@:%d via %{public}@",
               log: log, type: .debug, flowId, destinationHost, destinationPort,
               proxyName.isEmpty ? "direct" : proxyName)
        reply(true, "")
    }
}
