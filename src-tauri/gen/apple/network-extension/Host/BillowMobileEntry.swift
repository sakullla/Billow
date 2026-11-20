import Foundation

/// Compiled into billow_iOS. T6 replaces the stubs with Tauri commands that
/// call BillowVPNManager / ResourcesInstaller (suggested command names and
/// payloads are listed in tool/ios/README.md).
enum BillowMobileEntry {
    struct EngineState: Codable {
        var engine: String
        var installed: Bool
        var connected: Bool
        var version: String?
        var engineVersion: String?
        var lastError: String?
    }

    static func engineStates() async -> [EngineState] {
        let manager = BillowVPNManager.shared
        let installer = try? ResourcesInstaller()
        let version = try? installer?.activeVersion()
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
