import Foundation
import os.log

/// Manages the XPC / Unix socket connection from the NE extension to the main app.
///
/// Currently uses Unix domain socket for communication with the Rust backend,
/// as Rust XPC bindings are not mature enough for production use.
/// Can be switched to XPC (NSXPCConnection) in the future.
class XPCBridge {

    private let log = OSLog(subsystem: "com.omnilink.ne-extension", category: "xpc")
    private var connection: NSXPCConnection?
    private var socketFd: Int32 = -1

    // MARK: - Connection Management

    func connect() {
        // Option 1: Unix domain socket (recommended for Rust interop)
        connectViaSocket()

        // Option 2: XPC (uncomment when Rust XPC support is ready)
        // connectViaXPC()
    }

    func disconnect() {
        if socketFd >= 0 {
            close(socketFd)
            socketFd = -1
        }

        connection?.invalidate()
        connection = nil

        os_log("XPC bridge disconnected", log: log, type: .info)
    }

    // MARK: - Unix Socket Connection

    private func connectViaSocket() {
        socketFd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFd >= 0 else {
            os_log("Failed to create Unix socket", log: log, type: .error)
            return
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        let path = kOmniLinkSocketPath
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let pathPtr = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            path.withCString { cStr in
                strncpy(pathPtr, cStr, MemoryLayout.size(ofValue: addr.sun_path) - 1)
            }
        }

        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                Darwin.connect(socketFd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        if connectResult < 0 {
            os_log("Failed to connect to Unix socket at %{public}@: %{public}@",
                   log: log, type: .error, path, String(cString: strerror(errno)))
            Darwin.close(socketFd)
            socketFd = -1
        } else {
            os_log("Connected to Rust backend via Unix socket", log: log, type: .info)
        }
    }

    // MARK: - XPC Connection (Future)

    private func connectViaXPC() {
        connection = NSXPCConnection(machServiceName: kOmniLinkXPCServiceName,
                                     options: .privileged)
        connection?.remoteObjectInterface = NSXPCInterface(with: OmniLinkXPCProtocol.self)
        connection?.interruptionHandler = { [weak self] in
            os_log("XPC connection interrupted", log: self?.log ?? .default, type: .error)
        }
        connection?.invalidationHandler = { [weak self] in
            os_log("XPC connection invalidated", log: self?.log ?? .default, type: .error)
        }
        connection?.resume()

        os_log("XPC connection established", log: log, type: .info)
    }

    // MARK: - Protocol Methods

    func getRoutingDecision(sourceApp: String, host: String, port: Int,
                            completion: @escaping (String, String) -> Void) {
        if socketFd >= 0 {
            // TODO: Send JSON-encoded request over socket, read response
            // For now, default to direct
            completion("direct", "")
            return
        }

        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ error in
            os_log("XPC error: %{public}@", type: .error, error.localizedDescription)
            completion("direct", "")
        }) as? OmniLinkXPCProtocol else {
            completion("direct", "")
            return
        }

        proxy.getRoutingDecision(
            sourceAppIdentifier: sourceApp,
            destinationHost: host,
            destinationPort: port,
            reply: completion
        )
    }

    func relayData(flowId: String, data: Data, direction: String,
                   completion: @escaping (Bool) -> Void) {
        if socketFd >= 0 {
            // TODO: Send data frame over socket
            completion(true)
            return
        }

        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ _ in
            completion(false)
        }) as? OmniLinkXPCProtocol else {
            completion(false)
            return
        }

        proxy.relayData(flowId: flowId, data: data, direction: direction, reply: completion)
    }

    func connectFlow(flowId: String, host: String, port: Int, proxyName: String,
                     completion: @escaping (Bool, String) -> Void) {
        if socketFd >= 0 {
            // TODO: Send connect request over socket
            completion(true, "")
            return
        }

        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ error in
            completion(false, error.localizedDescription)
        }) as? OmniLinkXPCProtocol else {
            completion(false, "No XPC connection")
            return
        }

        proxy.connectFlow(
            flowId: flowId,
            destinationHost: host,
            destinationPort: port,
            proxyName: proxyName,
            reply: completion
        )
    }

    func flowClosed(flowId: String) {
        if socketFd >= 0 {
            // TODO: Send close notification over socket
            return
        }

        guard let proxy = connection?.remoteObjectProxy as? OmniLinkXPCProtocol else { return }
        proxy.flowClosed(flowId: flowId)
    }
}
