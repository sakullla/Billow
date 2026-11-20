import Foundation
import NetworkExtension

/// Packet Tunnel extension embedding MetaCubeX/mihomo v1.19.34
/// (src-tauri/gen/apple/mihomo-ios -> libmihomo_ios.a).
///
/// Swift owns the read side (PacketPump + readPackets), Go owns routing and
/// egress (gVisor stack -> GoMihomoWritePackets -> mihomoWriteCallback ->
/// packetFlow.writePackets). DNS is hijacked inside the stack (:53 goes to the
/// DNS configured in config.yaml).
final class MihomoTunnelProvider: NEPacketTunnelProvider {
    private let log = BillowLog("mihomo")
    private var engine: BillowMihomoEngine?
    private var pump: PacketPump?
    private var pathMonitor: NWPathMonitor?
    private var groupId: String?
    private var stopping = false
    private let commandQueue = DispatchQueue(label: "billow.mihomo.commands")

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        stopping = false
        let proto = protocolConfiguration as? NETunnelProviderProtocol
        groupId = BillowEngineIdentity.appGroup(from: proto)
        guard let group = groupId, let store = AppGroupStore(groupId: group) else {
            finishStart(error: BillowVPNError.make(.resourceInvalid,
                                                   "App Group \(groupId ?? "?") unavailable (entitlement missing?)"),
                        completionHandler: completionHandler)
            return
        }
        let eng = BillowMihomoEngine(provider: self)
        engine = eng
        eng.start(store: store, requestedVersion: proto?.requestedVersion) { [weak self] error in
            guard let self else {
                completionHandler(BillowVPNError.make(.tunnelSetupFailed, "provider deallocated"))
                return
            }
            if let error {
                self.fail(error, completionHandler: completionHandler)
                return
            }
            if let version = eng.version, let (manifest, _) = try? store.validatedResources(version, expectedEngine: BillowEngineIdentity.engine) {
                eng.startLoopback(manifest: manifest)
            }
            self.configureNetwork { [weak self] settingsError in
                guard let self else { return }
                if let settingsError {
                    eng.shutdown()
                    self.engine = nil
                    self.fail(BillowVPNError.make(.tunnelSetupFailed, "setTunnelNetworkSettings: \(settingsError)",
                                                  underlying: settingsError), completionHandler: completionHandler)
                    return
                }
                let pump = PacketPump(flow: self.packetFlow, ingest: mihomoIngest) { [weak self] failure in
                    self?.handlePumpFailure(failure)
                }
                self.pump = pump
                pump.start()
                eng.markRunning()
                self.startPathMonitor()
                self.publishStatus()
                completionHandler(nil)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue)")
        stopping = true
        pathMonitor?.cancel()
        pathMonitor = nil
        pump?.stop()
        pump = nil
        engine?.shutdown()
        engine = nil
        publishStatus()
        completionHandler()
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        // The stack keeps its NAT state; iOS suspends the extension anyway.
        completionHandler()
    }

    override func wake() {}

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        commandQueue.async { [weak self] in
            completionHandler?(self?.handle(messageData))
        }
    }

    // MARK: - Network settings and path

    private func configureNetwork(completion: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: ProviderSupport.mtu)
        let ipv4 = NEIPv4Settings(addresses: [ProviderSupport.tunnelIPv4], subnetMasks: ["255.255.0.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        let ipv6 = NEIPv6Settings(addresses: [ProviderSupport.tunnelIPv6],
                                  networkPrefixLengths: [NSNumber(value: ProviderSupport.tunnelIPv6Prefix)])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6
        // The stack answers DNS on the tunnel address; queries never leak.
        settings.dnsSettings = NEDNSSettings(servers: [ProviderSupport.tunnelIPv4])
        setTunnelNetworkSettings(settings, completionHandler: completion)
    }

    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, !self.stopping, let eng = self.engine else { return }
            self.log.info("path update satisfied=\(path.status == .satisfied) expensive=\(path.isExpensive)")
            // NETunnelProvider must re-apply settings after a path change.
            self.configureNetwork { [weak self] error in
                guard let self else { return }
                if let error {
                    self.log.error("re-applying network settings failed: \(error.localizedDescription)")
                }
                if eng.networkChanged() {
                    // Restarting the tunnel is how Network Extension expects a
                    // path change the engine cannot follow to be handled.
                    self.restartTunnel(error: BillowVPNError.make(.networkUnavailable,
                                                                  "engine could not follow the new network path"))
                }
            }
        }
        monitor.start(queue: commandQueue)
        pathMonitor = monitor
    }

    // MARK: - Commands from the host

    private func handle(_ data: Data) -> Data? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let raw = object[ProviderMessageKey.command] as? String,
              let command = ProviderCommand(rawValue: raw)
        else {
            return reply(error: BillowVPNError.make(.unsupportedCommand, "unparsable provider message"))
        }
        switch command {
        case .status:
            var body = replyBody()
            let status = engine?.status()
            body[ProviderMessageKey.embedded] = status?.embeddedVersion
            body[ProviderMessageKey.version] = status?.version
            body[ProviderMessageKey.loopbackPort] = status?.loopbackPort
            body[ProviderMessageKey.loopbackListen] = status?.loopbackListen
            return encode(body)
        case .reload:
            guard let engine else {
                return reply(error: BillowVPNError.make(.engineStopped, "engine not running"))
            }
            do {
                try engine.reload()
                return reply()
            } catch {
                return reply(error: error)
            }
        case .setMode:
            // Mode changes are applied through config.yaml + reload by the host.
            return reply(error: BillowVPNError.make(.unsupportedCommand, "setMode: patch config and send reload"))
        case .loopback:
            return reply(error: BillowVPNError.make(.unsupportedCommand, "loopback is configured by the manifest"))
        }
    }

    private func replyBody() -> [String: Any] {
        [
            ProviderMessageKey.ok: true,
            ProviderMessageKey.running: engine?.isRunning == true,
        ]
    }

    private func reply(error: Error? = nil) -> Data? {
        guard let error else {
            return encode(replyBody())
        }
        let ns = error as NSError
        return encode([
            ProviderMessageKey.ok: false,
            ProviderMessageKey.error: ns.localizedDescription,
            ProviderMessageKey.errorCode: ns.code,
            ProviderMessageKey.domain: ns.domain,
        ])
    }

    private func encode(_ body: [String: Any]) -> Data? {
        try? JSONSerialization.data(withJSONObject: body)
    }

    // MARK: - Failure paths

    private func fail(_ error: Error, completionHandler: @escaping (Error?) -> Void) {
        let ns = error as NSError
        let mapped = ns.domain == BillowVPNError.domain
            ? ns
            : BillowVPNError.make(BillowVPNError.classify(error), "\(error)", underlying: error)
        log.error("startTunnel failed: \(mapped.localizedDescription)")
        engine?.shutdown()
        engine = nil
        publishStatus(lastError: mapped)
        completionHandler(mapped)
    }

    /// The pump saw an unrecoverable read/ingest failure.
    private func handlePumpFailure(_ failure: NSError?) {
        guard !stopping else { return }
        let error = failure ?? BillowVPNError.make(.engineStopped, "packet pump stopped")
        restartTunnel(error: error)
    }

    /// The engine cannot continue on a path change, or the pump failed: stop
    /// the engine, report the error and ask the system to restart the tunnel by
    /// asserting the reasserting state then cancelling settings. Network
    /// Extension shows the error through NEVPNConnection.lastDisconnectError
    /// only for provider-initiated stops, so the status file is refreshed too.
    private func restartTunnel(error: NSError) {
        guard !stopping else { return }
        log.error("restarting tunnel: \(error.localizedDescription)")
        stopping = true
        pathMonitor?.cancel()
        pathMonitor = nil
        pump?.stop()
        pump = nil
        engine?.shutdown()
        engine = nil
        publishStatus(lastError: error)
        reasserting = true
        let restart = { (completion: @escaping (Error?) -> Void) in
            completion(BillowVPNError.make(.engineStopped, error.localizedDescription, underlying: error))
        }
        setTunnelNetworkSettings(nil) { _ in
            restart { [weak self] failure in
                guard let self else { return }
                self.reasserting = false
                self.stopping = false
                self.fail(failure ?? error, completionHandler: { _ in })
            }
        }
    }

    private func finishStart(error: Error, completionHandler: @escaping (Error?) -> Void) {
        publishStatus(lastError: error as NSError)
        completionHandler(error)
    }

    private func publishStatus(lastError: NSError? = nil) {
        let status = engine?.status() ?? ProviderStatus(
            extensionId: BillowEngineIdentity.bundleId,
            engine: BillowEngineIdentity.engine,
            embeddedVersion: nil,
            running: false,
            version: nil,
            loopbackPort: nil,
            loopbackListen: nil,
            lastError: nil,
            errorCode: nil,
            startedAt: nil
        )
        var merged = status
        if let lastError {
            merged.lastError = lastError.localizedDescription
            merged.errorCode = lastError.code
        }
        ProviderSupport.writeStatus(merged, groupId: groupId)
    }
}
