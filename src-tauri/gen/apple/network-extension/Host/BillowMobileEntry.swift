import Foundation

/// Compiled into billow_iOS and called by the Tauri commands in
/// `src-tauri/src/ios_vpn.rs` through `BillowMobileBridge.swift`.
enum BillowMobileEntry {
    struct EngineState: Codable {
        var engine: String
        var installed: Bool
        var connected: Bool
        var version: String?
        var engineVersion: String?
        var lastError: String?
    }

    static func activeVersion(groupId: String = BillowVPNManager.shared.appGroupId) -> String? {
        (try? AppGroupStore(groupId: groupId)?.activeVersion()) ?? nil
    }

    static func engineStates() async -> [EngineState] {
        let manager = BillowVPNManager.shared
        let version = activeVersion()
        var states: [EngineState] = []
        for engine in BillowVPNManager.Engine.allCases {
            // Packaging presence and runtime state are different facts: an
            // extension that is installed but not started answers no status.
            let installed = manager.isInstalled(engine)
            let status = installed ? try? await manager.status(of: engine) : nil
            let connected = installed ? await manager.isConnected(engine: engine) : false
            states.append(EngineState(
                engine: engine.rawValue,
                installed: installed,
                connected: connected,
                version: installed ? (status?.version ?? version) : nil,
                engineVersion: status?.embeddedVersion,
                lastError: installed ? (status?.lastError ?? manager.describeLastError(engine: engine)) : nil
            ))
        }
        return states
    }
}
