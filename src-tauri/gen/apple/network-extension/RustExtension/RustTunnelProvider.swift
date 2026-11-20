import Foundation
import NetworkExtension

/// Packet Tunnel extension for the Billow Rust kernel (T7 owns the data
/// plane). It shares the App Group layout with the Mihomo extension but keeps
/// network settings out of the Rust binary's way: the Rust engine receives
/// the home directory and installs its own routes through the port table.
final class RustTunnelProvider: NEPacketTunnelProvider {
    private let log = BillowLog("rust")
    private var engine: BillowRustEngine?
    private var groupId: String?

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        do {
            let proto = protocolConfiguration as? NETunnelProviderProtocol
            groupId = BillowEngineIdentity.appGroup(from: proto)
            guard let group = groupId, let store = AppGroupStore(groupId: group) else {
                throw BillowVPNError.make(.resourceInvalid, "App Group \(groupId ?? "?") unavailable (entitlement?)")
            }
            let eng = BillowRustEngine(provider: self)
            try eng.start(store: store, requestedVersion: proto?.requestedVersion)
            engine = eng
            let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
            settings.mtu = NSNumber(value: ProviderSupport.mtu)
            let ipv4 = NEIPv4Settings(addresses: [ProviderSupport.tunnelIPv4], subnetMasks: ["255.255.0.0"])
            ipv4.includedRoutes = [NEIPv4Route.default()]
            settings.ipv4Settings = ipv4
            setTunnelNetworkSettings(settings) { [weak self] error in
                if let error {
                    self?.engine?.shutdown()
                    self?.engine = nil
                    self?.publishStatus()
                    completionHandler(BillowVPNError.make(.tunnelSetupFailed, "setTunnelNetworkSettings: \(error)",
                                                          underlying: error))
                    return
                }
                self?.publishStatus()
                completionHandler(nil)
            }
        } catch {
            let ns = error as NSError
            let mapped = ns.domain == BillowVPNError.domain ? ns : BillowVPNError.make(BillowVPNError.classify(error), "\(error)", underlying: error)
            log.error("startTunnel failed: \(mapped.localizedDescription)")
            publishStatus(lastError: mapped)
            completionHandler(mapped)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue)")
        engine?.shutdown()
        engine = nil
        publishStatus()
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let object = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
              let raw = object[ProviderMessageKey.command] as? String,
              let command = ProviderCommand(rawValue: raw)
        else {
            completionHandler?(reply(error: BillowVPNError.make(.unsupportedCommand, "unparsable provider message")))
            return
        }
        switch command {
        case .status:
            let body: [String: Any] = [
                ProviderMessageKey.ok: true,
                ProviderMessageKey.running: engine != nil,
                ProviderMessageKey.embedded: engine?.embeddedVersion ?? NSNull(),
                ProviderMessageKey.version: engine?.version ?? NSNull(),
            ]
            completionHandler?(try? JSONSerialization.data(withJSONObject: body))
        default:
            completionHandler?(reply(error: BillowVPNError.make(.unsupportedCommand, "\(command.rawValue) not available in the Rust placeholder")))
        }
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
        let status = ProviderStatus(
            extensionId: BillowEngineIdentity.bundleId,
            engine: BillowEngineIdentity.engine,
            embeddedVersion: engine?.embeddedVersion,
            running: engine != nil,
            version: engine?.version,
            loopbackPort: nil,
            loopbackListen: nil,
            lastError: lastError?.localizedDescription ?? engine?.lastError?.localizedDescription,
            errorCode: lastError?.code ?? engine?.lastError?.code,
            startedAt: engine?.startedAt
        )
        ProviderSupport.writeStatus(status, groupId: groupId)
    }
}
