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
            let status = try? await manager.status(of: engine)
            states.append(EngineState(
                engine: engine.rawValue,
                installed: status != nil,
                connected: await manager.isConnected(engine: engine),
                version: status?.version ?? version,
                engineVersion: status?.embeddedVersion,
                lastError: status?.lastError ?? manager.describeLastError(engine: engine)
            ))
        }
        return states
    }
}
