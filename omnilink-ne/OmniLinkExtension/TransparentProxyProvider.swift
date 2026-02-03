import NetworkExtension
import os.log

/// NETransparentProxyProvider implementation for OmniLink.
///
/// This system extension intercepts all outbound TCP (and DNS UDP) traffic,
/// sends flow metadata to the Rust backend via Unix domain socket / XPC,
/// and relays data through the configured proxy chain.
class TransparentProxyProvider: NETransparentProxyProvider {

    private let log = OSLog(subsystem: "com.omnilink.ne-extension", category: "proxy")
    private var xpcBridge: XPCBridge?
    private var activeFlows: [String: NEAppProxyFlow] = [:]
    private var flowCounter: UInt64 = 0

    // MARK: - Lifecycle

    override func startProxy(options: [String: Any]? = nil,
                              completionHandler: @escaping (Error?) -> Void) {
        os_log("Starting transparent proxy extension", log: log, type: .info)

        // Establish IPC connection to the main app (Rust backend)
        xpcBridge = XPCBridge()
        xpcBridge?.connect()

        // Configure network settings
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        // Intercept all outbound TCP traffic
        let tcpRule = NENetworkRule(
            remoteNetwork: nil,       // all destinations
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .TCP,
            direction: .outbound
        )

        // Intercept DNS (UDP port 53)
        let dnsEndpoint = NWHostEndpoint(hostname: "0.0.0.0", port: "53")
        let dnsRule = NENetworkRule(
            remoteNetwork: dnsEndpoint,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .UDP,
            direction: .outbound
        )

        settings.includedNetworkRules = [tcpRule, dnsRule]

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                os_log("Failed to set tunnel settings: %{public}@",
                       log: self?.log ?? .default, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }
            os_log("Tunnel settings applied successfully", log: self?.log ?? .default, type: .info)
            completionHandler(nil)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        os_log("Stopping transparent proxy, reason: %d", log: log, type: .info, reason.rawValue)

        // Close all active flows
        for (flowId, flow) in activeFlows {
            xpcBridge?.flowClosed(flowId: flowId)
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
        activeFlows.removeAll()

        // Disconnect IPC
        xpcBridge?.disconnect()
        xpcBridge = nil

        completionHandler()
    }

    // MARK: - Flow Handling

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcpFlow = flow as? NEAppProxyTCPFlow else {
            os_log("Non-TCP flow received, ignoring", log: log, type: .debug)
            return false
        }

        let flowId = generateFlowId()
        let appId = flow.metaData.sourceAppSigningIdentifier

        guard let remoteEndpoint = tcpFlow.remoteEndpoint as? NWHostEndpoint else {
            return false
        }

        let host = remoteEndpoint.hostname
        let port = Int(remoteEndpoint.port) ?? 0

        os_log("New TCP flow: %{public}@ -> %{public}@:%d from %{public}@",
               log: log, type: .info, flowId, host, port, appId)

        activeFlows[flowId] = tcpFlow

        // Ask the backend for a routing decision
        xpcBridge?.getRoutingDecision(
            sourceApp: appId,
            host: host,
            port: port
        ) { [weak self] action, proxyName in
            guard let self = self else { return }

            switch action {
            case "block":
                os_log("Flow %{public}@ blocked by rule", log: self.log, type: .info, flowId)
                tcpFlow.closeReadWithError(nil)
                tcpFlow.closeWriteWithError(nil)
                self.activeFlows.removeValue(forKey: flowId)

            case "direct", "proxy":
                // Open the flow and start relaying
                tcpFlow.open(withLocalEndpoint: nil) { error in
                    if let error = error {
                        os_log("Failed to open flow %{public}@: %{public}@",
                               log: self.log, type: .error, flowId, error.localizedDescription)
                        self.activeFlows.removeValue(forKey: flowId)
                        return
                    }

                    // Request the backend to establish the outbound connection
                    self.xpcBridge?.connectFlow(
                        flowId: flowId,
                        host: host,
                        port: port,
                        proxyName: proxyName
                    ) { success, errorMsg in
                        if success {
                            self.startRelay(flowId: flowId, flow: tcpFlow)
                        } else {
                            os_log("Backend connect failed for %{public}@: %{public}@",
                                   log: self.log, type: .error, flowId, errorMsg)
                            tcpFlow.closeReadWithError(nil)
                            tcpFlow.closeWriteWithError(nil)
                            self.activeFlows.removeValue(forKey: flowId)
                        }
                    }
                }

            default:
                os_log("Unknown action for flow %{public}@: %{public}@",
                       log: self.log, type: .error, flowId, action)
                tcpFlow.closeReadWithError(nil)
                tcpFlow.closeWriteWithError(nil)
                self.activeFlows.removeValue(forKey: flowId)
            }
        }

        return true
    }

    override func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow,
                                    initialRemoteEndpoint remoteEndpoint: NWEndpoint) -> Bool {
        // DNS interception: the Rust backend handles DNS via VirtualDns
        // For now, pass through UDP flows
        os_log("UDP flow received, passing through", log: log, type: .debug)
        return false
    }

    // MARK: - Data Relay

    private func startRelay(flowId: String, flow: NEAppProxyTCPFlow) {
        readLoop(flowId: flowId, flow: flow)
    }

    private func readLoop(flowId: String, flow: NEAppProxyTCPFlow) {
        flow.readData { [weak self] data, error in
            guard let self = self else { return }

            if let error = error {
                os_log("Read error on flow %{public}@: %{public}@",
                       log: self.log, type: .error, flowId, error.localizedDescription)
                self.cleanupFlow(flowId: flowId)
                return
            }

            guard let data = data, !data.isEmpty else {
                // EOF
                self.cleanupFlow(flowId: flowId)
                return
            }

            // Send data to Rust backend for proxying
            self.xpcBridge?.relayData(flowId: flowId, data: data, direction: "outbound") { success in
                if success {
                    // Continue reading
                    self.readLoop(flowId: flowId, flow: flow)
                } else {
                    self.cleanupFlow(flowId: flowId)
                }
            }
        }
    }

    private func cleanupFlow(flowId: String) {
        if let flow = activeFlows.removeValue(forKey: flowId) {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            xpcBridge?.flowClosed(flowId: flowId)
        }
    }

    // MARK: - Helpers

    private func generateFlowId() -> String {
        flowCounter += 1
        return "flow-\(flowCounter)"
    }
}
