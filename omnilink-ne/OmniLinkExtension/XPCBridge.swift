import Foundation
import os.log

/// Manages the Unix socket connection from the NE extension to the Rust backend.
///
/// Uses length-prefixed JSON framing for wire protocol:
/// +----------------+-------------------+
/// | length (4 BE)  | JSON payload      |
/// +----------------+-------------------+
class XPCBridge {

    private let log = OSLog(subsystem: "com.omnilink.ne-extension", category: "xpc")
    private var socketFd: Int32 = -1
    private let socketQueue = DispatchQueue(label: "com.omnilink.xpc.socket", qos: .userInitiated)
    private let lock = NSLock()

    // MARK: - Connection Management

    func connect() {
        connectViaSocket()
    }

    func disconnect() {
        lock.lock()
        defer { lock.unlock() }

        if socketFd >= 0 {
            Darwin.close(socketFd)
            socketFd = -1
        }

        os_log("XPC bridge disconnected", log: log, type: .info)
    }

    var isConnected: Bool {
        lock.lock()
        defer { lock.unlock() }
        return socketFd >= 0
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

    // MARK: - Wire Protocol

    /// Write a length-prefixed JSON frame to the socket.
    private func writeFrame(_ message: [String: Any]) throws {
        let jsonData = try JSONSerialization.data(withJSONObject: message, options: [])

        // Write 4-byte big-endian length prefix
        var length = UInt32(jsonData.count).bigEndian
        let lengthData = Data(bytes: &length, count: 4)

        lock.lock()
        let fd = socketFd
        lock.unlock()

        guard fd >= 0 else {
            throw XPCError.notConnected
        }

        // Write length prefix
        try lengthData.withUnsafeBytes { ptr in
            let written = Darwin.write(fd, ptr.baseAddress!, 4)
            if written != 4 {
                throw XPCError.writeError(errno)
            }
        }

        // Write JSON payload
        try jsonData.withUnsafeBytes { ptr in
            var totalWritten = 0
            while totalWritten < jsonData.count {
                let written = Darwin.write(fd, ptr.baseAddress!.advanced(by: totalWritten),
                                          jsonData.count - totalWritten)
                if written <= 0 {
                    throw XPCError.writeError(errno)
                }
                totalWritten += written
            }
        }
    }

    /// Read a length-prefixed JSON frame from the socket.
    private func readFrame() throws -> [String: Any] {
        lock.lock()
        let fd = socketFd
        lock.unlock()

        guard fd >= 0 else {
            throw XPCError.notConnected
        }

        // Read 4-byte big-endian length prefix
        var lengthBytes = [UInt8](repeating: 0, count: 4)
        var totalRead = 0
        while totalRead < 4 {
            let n = Darwin.read(fd, &lengthBytes[totalRead], 4 - totalRead)
            if n <= 0 {
                throw XPCError.readError(errno)
            }
            totalRead += n
        }

        let length = UInt32(bigEndian: Data(lengthBytes).withUnsafeBytes { $0.load(as: UInt32.self) })

        guard length > 0 && length < 1024 * 1024 else {
            throw XPCError.invalidLength(Int(length))
        }

        // Read JSON payload
        var payload = [UInt8](repeating: 0, count: Int(length))
        totalRead = 0
        while totalRead < Int(length) {
            let n = Darwin.read(fd, &payload[totalRead], Int(length) - totalRead)
            if n <= 0 {
                throw XPCError.readError(errno)
            }
            totalRead += n
        }

        let data = Data(payload)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw XPCError.invalidJSON
        }

        return json
    }

    /// Send a request and receive a response synchronously.
    private func sendRequest(_ request: [String: Any]) -> [String: Any]? {
        do {
            try writeFrame(request)
            return try readFrame()
        } catch {
            os_log("Socket communication error: %{public}@", log: log, type: .error, "\(error)")
            return nil
        }
    }

    // MARK: - Protocol Methods

    func getRoutingDecision(sourceApp: String, host: String, port: Int,
                            completion: @escaping (String, String) -> Void) {
        socketQueue.async { [weak self] in
            guard let self = self, self.isConnected else {
                DispatchQueue.main.async { completion("direct", "") }
                return
            }

            let flowId = UUID().uuidString
            let request: [String: Any] = [
                "type": "routing",
                "flow_id": flowId,
                "app_id": sourceApp,
                "host": host,
                "port": port,
                "protocol": "tcp"
            ]

            if let response = self.sendRequest(request),
               let action = response["action"] as? String {
                let proxyName = response["proxy_name"] as? String ?? ""
                DispatchQueue.main.async { completion(action, proxyName) }
            } else {
                DispatchQueue.main.async { completion("direct", "") }
            }
        }
    }

    func connectFlow(flowId: String, host: String, port: Int, proxyName: String,
                     completion: @escaping (Bool, String) -> Void) {
        socketQueue.async { [weak self] in
            guard let self = self, self.isConnected else {
                DispatchQueue.main.async { completion(false, "Not connected") }
                return
            }

            let request: [String: Any] = [
                "type": "connect",
                "flow_id": flowId,
                "host": host,
                "port": port,
                "proxy_name": proxyName.isEmpty ? NSNull() : proxyName
            ]

            if let response = self.sendRequest(request),
               let success = response["success"] as? Bool {
                let error = response["error"] as? String ?? ""
                DispatchQueue.main.async { completion(success, error) }
            } else {
                DispatchQueue.main.async { completion(false, "No response") }
            }
        }
    }

    func relayData(flowId: String, data: Data, direction: String,
                   completion: @escaping (Bool) -> Void) {
        socketQueue.async { [weak self] in
            guard let self = self, self.isConnected else {
                DispatchQueue.main.async { completion(false) }
                return
            }

            let request: [String: Any] = [
                "type": "data",
                "flow_id": flowId,
                "direction": direction,
                "data": data.base64EncodedString()
            ]

            if let response = self.sendRequest(request) {
                let responseDirection = response["direction"] as? String ?? ""
                let success = responseDirection != "error"
                DispatchQueue.main.async { completion(success) }
            } else {
                DispatchQueue.main.async { completion(false) }
            }
        }
    }

    /// Receive inbound data for a flow (polling).
    func receiveData(flowId: String, completion: @escaping (Data?) -> Void) {
        socketQueue.async { [weak self] in
            guard let self = self, self.isConnected else {
                DispatchQueue.main.async { completion(nil) }
                return
            }

            // Send empty data request to poll for inbound data
            let request: [String: Any] = [
                "type": "data",
                "flow_id": flowId,
                "direction": "poll",
                "data": ""
            ]

            if let response = self.sendRequest(request),
               let direction = response["direction"] as? String,
               direction == "inbound",
               let dataStr = response["data"] as? String,
               !dataStr.isEmpty,
               let data = Data(base64Encoded: dataStr) {
                DispatchQueue.main.async { completion(data) }
            } else {
                DispatchQueue.main.async { completion(nil) }
            }
        }
    }

    func flowClosed(flowId: String) {
        socketQueue.async { [weak self] in
            guard let self = self, self.isConnected else { return }

            let request: [String: Any] = [
                "type": "close",
                "flow_id": flowId
            ]

            // Fire and forget - no response expected
            do {
                try self.writeFrame(request)
            } catch {
                os_log("Failed to send close notification: %{public}@",
                       log: self.log, type: .error, "\(error)")
            }
        }
    }
}

// MARK: - Error Types

enum XPCError: Error {
    case notConnected
    case writeError(Int32)
    case readError(Int32)
    case invalidLength(Int)
    case invalidJSON

    var localizedDescription: String {
        switch self {
        case .notConnected:
            return "Socket not connected"
        case .writeError(let errno):
            return "Write error: \(String(cString: strerror(errno)))"
        case .readError(let errno):
            return "Read error: \(String(cString: strerror(errno)))"
        case .invalidLength(let len):
            return "Invalid message length: \(len)"
        case .invalidJSON:
            return "Invalid JSON response"
        }
    }
}
