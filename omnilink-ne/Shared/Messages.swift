import Foundation

/// Routing action returned by the backend.
enum RoutingAction: String {
    case direct = "direct"
    case proxy = "proxy"
    case block = "block"
}

/// Flow metadata sent from the NE extension to the backend.
struct FlowMetadata: Codable {
    let flowId: String
    let sourceAppIdentifier: String
    let sourceAddress: String
    let sourcePort: Int
    let destinationHost: String
    let destinationPort: Int
    let transportProtocol: String  // "tcp" or "udp"
    let timestamp: Date
}

/// Status of the NE extension, queried by the app.
struct ExtensionStatus: Codable {
    let running: Bool
    let activeFlows: Int
    let totalIntercepted: UInt64
    let uptime: TimeInterval
}

/// Configuration pushed from the app to the NE extension.
struct InterceptorConfiguration: Codable {
    /// Whether to intercept all traffic or only specific apps.
    let interceptAll: Bool
    /// Bundle IDs of apps to intercept (when interceptAll is false).
    let targetApps: [String]
    /// Bundle IDs of apps to exclude from interception.
    let excludedApps: [String]
    /// Domains to exclude from interception (e.g., Apple services).
    let excludedDomains: [String]
}

/// Mach service name for XPC communication.
let kOmniLinkXPCServiceName = "com.omnilink.xpc-service"

/// App Group identifier for shared container access.
let kOmniLinkAppGroup = "group.com.omnilink"

/// Unix domain socket path (alternative to XPC, recommended for Rust interop).
let kOmniLinkSocketPath = "/var/run/omnilink.sock"
