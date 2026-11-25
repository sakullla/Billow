import Foundation
import NetworkExtension

/// Host entry point for the iOS dual-tunnel feature. T6/T7 call this from the
/// Rust side (commands suggested in tool/ios/README.md); it is deliberately
/// free of UI code.
///
/// Two NETunnelProviderManager configurations coexist, one per extension
/// bundle id. The active one is stored in the shared defaults/App Group so the
/// UI can show the selected engine and Tauri can mirror it.
final class BillowVPNManager {
    static let shared = BillowVPNManager()

    enum Engine: String, CaseIterable {
        case mihomo
        case rust

        var bundleId: String { "\(Bundle.main.bundleIdentifier ?? "app.billow.client").\(rawValue)" }
        /// Directory name under the host's PlugIns (xcodegen PRODUCT_NAME).
        var bundleName: String { self == .mihomo ? "BillowMihomo" : "BillowRust" }
        var displayName: String { self == .mihomo ? "Mihomo" : "Rust" }
    }

    enum SelectedEngineKey {
        static let appGroup = "selectedEngine"
    }

    private let groupId: String
    private let log = BillowLog("host")

    init(groupId: String = "group.app.billow.client") {
        self.groupId = groupId
    }

    var appGroupId: String { groupId }

    // MARK: - Packaging

    /// Whether the appex ships in this build. `manager.status(of:)` only proves
    /// that an extension answered, so a not-yet-started or failing extension
    /// must not be reported as missing.
    func isInstalled(_ engine: Engine) -> Bool {
        guard let plugins = Bundle.main.builtInPlugInsURL else { return false }
        let url = plugins.appendingPathComponent("\(engine.bundleName).appex", isDirectory: true)
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            return false
        }
        return Bundle(url: url)?.bundleIdentifier == engine.bundleId
    }

    // MARK: - Configuration management

    func manager(for engine: Engine) async throws -> NETunnelProviderManager {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        if let existing = managers.first(where: { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == engine.bundleId }) {
            return existing
        }
        let manager = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = engine.bundleId
        proto.serverAddress = "Billow"
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Billow \(engine.displayName)"
        manager.isEnabled = true
        try await manager.saveToPreferences()
        return manager
    }

    /// Creates/updates the stored resources and starts the selected extension.
    /// `requestedVersion` names the App Group version prepared by
    /// ResourcesInstaller; the extension validates it again.
    func connect(engine: Engine, requestedVersion: String) async throws {
        let manager = try await manager(for: engine)
        guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
            throw BillowVPNError.make(.configurationMissing, "protocol lost")
        }
        var config = proto.providerConfiguration ?? [:]
        config[AppGroupLayout.groupKey] = groupId
        config[AppGroupLayout.versionKey] = requestedVersion
        config[AppGroupLayout.extensionKey] = engine.bundleId
        proto.providerConfiguration = config
        manager.protocolConfiguration = proto
        manager.isEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        try manager.connection.startVPNTunnel()
        setSelected(engine)
    }

    func disconnect() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        for manager in managers {
            manager.connection.stopVPNTunnel()
        }
    }

    func status(of engine: Engine) async throws -> ProviderStatus? {
        let manager = try await manager(for: engine)
        guard let session = manager.connection as? NETunnelProviderSession else {
            return nil
        }
        let data = try await send(.status, to: session)
        return ProviderSupport.decodeStatus(data)
    }

    func reload(engine: Engine) async throws {
        let manager = try await manager(for: engine)
        guard let session = manager.connection as? NETunnelProviderSession else {
            throw BillowVPNError.make(.configurationMissing, "no session for \(engine.bundleId)")
        }
        _ = try await send(.reload, to: session)
    }

    /// Polls the connection until it reaches `target` or 30 s pass; returns
    /// the last observed state so callers can tell "timed out" apart.
    func waitForState(_ target: NEVPNStatus, engine: Engine, timeout: TimeInterval = 30) async throws -> NEVPNStatus {
        let manager = try await manager(for: engine)
        let deadline = Date().addingTimeInterval(timeout)
        var state = manager.connection.status
        while state != target && Date() < deadline {
            if state == .disconnected, target != .disconnected {
                break
            }
            try await Task.sleep(nanoseconds: 250_000_000)
            state = manager.connection.status
        }
        return state
    }

    /// Explains the last start failure using the provider's own status file.
    func describeLastError(engine: Engine) -> String? {
        guard let status = AppGroupStore(groupId: groupId)?.readStatus(engine: engine.rawValue),
              status.lastError != nil else {
            return nil
        }
        return "\(status.lastError ?? "") (code \(status.errorCode ?? -1))"
    }

    // MARK: - Selection

    func isConnected(engine: Engine) async -> Bool {
        guard let manager = try? await manager(for: engine) else { return false }
        return manager.connection.status == .connected
    }

    func setSelected(_ engine: Engine) {
        UserDefaults(suiteName: groupId)?.set(engine.rawValue, forKey: SelectedEngineKey.appGroup)
        // The Rust extension reads the selection from the App Group file system
        // (it has no UserDefaults bridge into libapp.a):
        // <AppGroup>/engine.json = {"selected": "rust" | "mihomo"}.
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: groupId
        ) else { return }
        let url = container.appendingPathComponent("engine.json")
        let body: [String: Any] = [
            "selected": engine.rawValue,
            "updatedAt": ISO8601DateFormatter().string(from: Date()),
        ]
        if let data = try? JSONSerialization.data(withJSONObject: body) {
            try? data.write(to: url, options: .atomic)
        }
    }

    func selected() -> Engine {
        let raw = UserDefaults(suiteName: groupId)?.string(forKey: SelectedEngineKey.appGroup) ?? Engine.mihomo.rawValue
        return Engine(rawValue: raw) ?? .mihomo
    }

    // MARK: - Sessions

    private func send(_ command: ProviderCommand, to session: NETunnelProviderSession) async throws -> Data? {
        let message = try JSONSerialization.data(withJSONObject: [ProviderMessageKey.command: command.rawValue])
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(message) { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: BillowVPNError.make(.providerFailed, "sendProviderMessage: \(error)", underlying: error))
            }
        }
    }
}

// Status encoding/decoding lives on ProviderSupport (Shared/ProviderSupport.swift);
// the host compiles the same file, so it must not be redeclared here. Status
// reading lives on AppGroupStore (Shared/AppGroupStore.swift).
