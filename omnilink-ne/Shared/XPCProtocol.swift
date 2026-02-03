import Foundation

/// XPC protocol for communication between the NE extension and the main app.
///
/// The main app (Tauri/Rust) acts as the XPC server, providing routing
/// decisions and data relay services. The NE extension connects as a client.
@objc protocol OmniLinkXPCProtocol {
    /// Request a routing decision for a new flow.
    ///
    /// - Parameters:
    ///   - sourceAppIdentifier: Bundle ID of the originating app (e.g., "com.google.Chrome")
    ///   - destinationHost: The destination hostname or IP
    ///   - destinationPort: The destination port
    ///   - reply: Callback with (action, proxyName). Action is "direct", "proxy", or "block".
    func getRoutingDecision(
        sourceAppIdentifier: String,
        destinationHost: String,
        destinationPort: Int,
        reply: @escaping (_ action: String, _ proxyName: String) -> Void
    )

    /// Relay data from an intercepted flow to the proxy backend.
    ///
    /// - Parameters:
    ///   - flowId: Unique identifier for this flow
    ///   - data: The data to relay
    ///   - direction: "inbound" or "outbound"
    ///   - reply: Callback indicating success
    func relayData(
        flowId: String,
        data: Data,
        direction: String,
        reply: @escaping (_ success: Bool) -> Void
    )

    /// Notify the backend that a flow has been closed.
    ///
    /// - Parameter flowId: Unique identifier for the closed flow
    func flowClosed(flowId: String)

    /// Request proxy connection for a flow.
    ///
    /// The backend establishes the outbound connection (direct or via proxy)
    /// and returns a file descriptor or connection identifier.
    ///
    /// - Parameters:
    ///   - flowId: Unique identifier for this flow
    ///   - destinationHost: Original destination host
    ///   - destinationPort: Original destination port
    ///   - proxyName: Name of the proxy chain to use (empty for direct)
    ///   - reply: Callback with (success, errorMessage)
    func connectFlow(
        flowId: String,
        destinationHost: String,
        destinationPort: Int,
        proxyName: String,
        reply: @escaping (_ success: Bool, _ error: String) -> Void
    )
}
