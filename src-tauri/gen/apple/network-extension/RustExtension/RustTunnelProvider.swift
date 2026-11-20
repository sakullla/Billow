import Foundation
import NetworkExtension

/// Packet Tunnel extension for the Billow Rust kernel.
///
/// Start order follows Network Extension semantics: validate resources and
/// start libapp.a first, then apply settings, then the packet pump, and call
/// `completionHandler` exactly once. A start failure (missing App Group,
/// missing libapp.a -> code 4, config rejected by Rust -> code 2) is reported
/// to the host through the completion error and the App Group status file, so
/// the host's engine selector can show a stable state for each engine.
final class RustTunnelProvider: NEPacketTunnelProvider {
    private let log = BillowLog("rust")
    private var engine: BillowRustEngine?
    private var groupId: String?
    private var pathMonitor: NWPathMonitor?
    private var stopping = false
    private var startCompleted = false
    private let commandQueue = DispatchQueue(label: "billow.rust.commands")

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        stopping = false
        startCompleted = false
        let proto = protocolConfiguration as? NETunnelProviderProtocol
        groupId = BillowEngineIdentity.appGroup(from: proto)
        guard let group = groupId, let store = AppGroupStore(groupId: group) else {
            completeStart(error: BillowVPNError.make(.resourceInvalid,
                                                     "App Group \(groupId ?? "?") unavailable (entitlement missing?)"),
                          completionHandler: completionHandler)
            return
        }
        let eng = BillowRustEngine(provider: self)
        engine = eng
        BillowRustTunnelProvider.current = eng
        eng.failedHandler = { [weak self] error in
            self?.handleRuntimeFailure(error)
        }
        do {
            try eng.start(store: store, requestedVersion: proto?.requestedVersion)
        } catch {
            let ns = error as NSError
            let mapped = ns.domain == BillowVPNError.domain
                ? ns
                : BillowVPNError.make(BillowVPNError.classify(error), "\(error)", underlying: error)
            eng.shutdown()
            engine = nil
            BillowRustTunnelProvider.current = nil
            completeStart(error: mapped, completionHandler: completionHandler)
            return
        }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: ProviderSupport.mtu)
        let ipv4 = NEIPv4Settings(addresses: [ProviderSupport.tunnelIPv4], subnetMasks: ["255.255.0.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        settings.dnsSettings = NEDNSSettings(servers: [ProviderSupport.tunnelIPv4])
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else {
                completionHandler(BillowVPNError.make(.tunnelSetupFailed, "provider deallocated"))
                return
            }
            if let error {
                eng.shutdown()
                self.engine = nil
                BillowRustTunnelProvider.current = nil
                self.completeStart(error: BillowVPNError.make(.tunnelSetupFailed,
                                                              "setTunnelNetworkSettings: \(error)",
                                                              underlying: error),
                                   completionHandler: completionHandler)
                return
            }
            eng.startMainPump()
            self.startPathMonitor()
            self.completeStart(error: nil, completionHandler: completionHandler)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue)")
        teardown()
        publishStatus()
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        commandQueue.async { [weak self] in
            guard let self else {
                completionHandler?(nil)
                return
            }
            guard let object = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
                  let raw = object[ProviderMessageKey.command] as? String,
                  let command = ProviderCommand(rawValue: raw)
            else {
                completionHandler?(self.reply(error: BillowVPNError.make(.unsupportedCommand,
                                                                         "unparsable provider message")))
                return
            }
            switch command {
            case .status:
                let status = self.engine?.status
                var body: [String: Any] = [
                    ProviderMessageKey.ok: true,
                    ProviderMessageKey.running: status?.running ?? false,
                    ProviderMessageKey.embedded: status?.embeddedVersion ?? NSNull(),
                    ProviderMessageKey.version: status?.version ?? NSNull(),
                    ProviderMessageKey.engineId: BillowEngineIdentity.bundleId,
                ]
                body[ProviderMessageKey.error] = status?.lastError ?? NSNull()
                body[ProviderMessageKey.errorCode] = status?.errorCode ?? NSNull()
                completionHandler?(try? JSONSerialization.data(withJSONObject: body))
            default:
                completionHandler?(self.reply(error: BillowVPNError.make(.unsupportedCommand,
                                                                         "\(command.rawValue) is applied by the host or libapp.a")))
            }
        }
    }

    // MARK: - Path changes

    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, !self.stopping else { return }
            self.log.info("path update satisfied=\(path.status == .satisfied)")
            self.commandQueue.async {
                // The Rust kernel follows the system route after a path
                // change; a failure it reports arrives through
                // recordFailure -> handleRuntimeFailure.
                if path.status == .unsatisfied {
                    self.log.info("network path unsatisfied; waiting for the kernel")
                }
            }
        }
        monitor.start(queue: commandQueue)
        pathMonitor = monitor
    }

    // MARK: - Completion and failure

    private func completeStart(error: Error?, completionHandler: (Error?) -> Void) {
        guard !startCompleted else {
            log.warning("startTunnel completed twice; ignoring \(error.map { "\($0)" } ?? "success")")
            return
        }
        startCompleted = true
        if let error {
            log.error("startTunnel failed: \(error.localizedDescription)")
        }
        publishStatus(lastError: error as NSError?)
        completionHandler(error)
    }

    /// Unrecoverable runtime failure after a successful start: stop the
    /// engine, publish the status and cancel the tunnel with the error (the
    /// host sees NEVPNConnection.lastDisconnectError). Start was already
    /// completed, so no completion handler is called here.
    private func handleRuntimeFailure(_ error: NSError) {
        guard !stopping else { return }
        log.error("runtime failure: \(error.localizedDescription)")
        teardown()
        publishStatus(lastError: error)
        cancelTunnelWithError(error)
    }

    private func teardown() {
        stopping = true
        pathMonitor?.cancel()
        pathMonitor = nil
        engine?.shutdown()
        engine = nil
        BillowRustTunnelProvider.current = nil
    }

    private func reply(error: Error?) -> Data? {
        var body: [String: Any] = [ProviderMessageKey.ok: error == nil, ProviderMessageKey.running: engine != nil]
        if let error = error as NSError? {
            body[ProviderMessageKey.error] = error.localizedDescription
            body[ProviderMessageKey.errorCode] = error.code
        }
        return try? JSONSerialization.data(withJSONObject: body)
    }

    private func publishStatus(lastError: NSError? = nil) {
        var status = engine?.status ?? ProviderStatus(
            extensionId: BillowEngineIdentity.bundleId,
            engine: BillowEngineIdentity.engine,
            embeddedVersion: BillowRustEngine.rustEngineVersion(),
            running: false,
            version: nil,
            loopbackPort: nil,
            loopbackListen: nil,
            lastError: nil,
            errorCode: nil,
            startedAt: nil
        )
        if let lastError {
            status.lastError = lastError.localizedDescription
            status.errorCode = lastError.code
        }
        ProviderSupport.writeStatus(status, groupId: groupId)
    }
}
