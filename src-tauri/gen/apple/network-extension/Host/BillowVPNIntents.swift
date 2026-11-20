import AppIntents
import Foundation

/// App Intents the system shows in Settings > VPN. They reuse
/// BillowVPNManager, which T6 can also expose to Tauri.
struct ToggleBillowVPNIntent: AppIntent {
    static let title: LocalizedStringResource = "Toggle Billow VPN"
    static let description = IntentDescription("Connect or disconnect the selected Billow engine.")
    static let openAppWhenRun = false

    func perform() async throws -> some IntentResult {
        let manager = BillowVPNManager.shared
        let engine = manager.selected()
        if await manager.isConnected(engine: engine) {
            try await manager.disconnect()
        } else {
            let installer = try ResourcesInstaller()
            let version = try installer.activeVersion()
            try await manager.connect(engine: engine, requestedVersion: version)
        }
        return .result()
    }
}

struct SelectBillowEngineIntent: AppIntent {
    static let title: LocalizedStringResource = "Select Billow engine"
    static let description = IntentDescription("Choose which engine Billow connects with.")
    static let openAppWhenRun = false

    @Parameter(title: "Engine")
    var engine: String

    static var parameterSummary: some ParameterSummary {
        Summary("Use \(\.$engine)")
    }

    func perform() async throws -> some IntentResult {
        let selected = BillowVPNManager.Engine(rawValue: engine) ?? .mihomo
        BillowVPNManager.shared.setSelected(selected)
        return .result()
    }
}
