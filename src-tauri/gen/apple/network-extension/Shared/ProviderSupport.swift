import Foundation
import NetworkExtension

/// Per-target identity. The Swift sources in network-extension/Shared are
/// compiled into both extensions; each target defines exactly one of
/// BILLOW_ENGINE_MIHOMO / BILLOW_ENGINE_RUST (see project.yml).
enum BillowEngineIdentity {
    static var engine: String {
        #if BILLOW_ENGINE_MIHOMO
        return "mihomo"
        #elseif BILLOW_ENGINE_RUST
        return "rust"
        #else
        #error("Define BILLOW_ENGINE_MIHOMO or BILLOW_ENGINE_RUST for this target")
        #endif
    }

    static var bundleId: String {
        Bundle.main.bundleIdentifier ?? "unknown"
    }

    /// The App Group from the entitlements (all three targets share
    /// billow_iOS/BillowMihomo/BillowRust entitlements). Host fallback when
    /// NETunnelProviderProtocol carries no App Group.
    static var defaultAppGroup: String {
        "group.app.billow.client"
    }

    static func appGroup(from protocolConfiguration: NETunnelProviderProtocol?) -> String {
        let value = protocolConfiguration?.providerConfiguration?[AppGroupLayout.groupKey] as? String
        return (value?.isEmpty == false) ? value! : defaultAppGroup
    }
}

enum ProviderSupport {
    static func statusURL(groupId: String?) -> URL? {
        guard let groupId, let root = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupId) else {
            return nil
        }
        let dir = root.appendingPathComponent("status", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("\(BillowEngineIdentity.engine).json")
    }

    static func writeStatus(_ status: ProviderStatus, groupId: String?) {
        guard let url = statusURL(groupId: groupId) else { return }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        if let data = try? encoder.encode(status) {
            try? data.write(to: url, options: .atomic)
        }
    }

    /// Tunnel addresses must match mihomo's sing-tun Inet4/Inet6Address
    /// (mihomo-ios/bridge.go) so the gVisor stack answers on them.
    static let tunnelIPv4 = "198.18.0.1"
    static let tunnelIPv6 = "fdfe:dcba:9876::1"
    static let tunnelIPv4Prefix = 16
    static let tunnelIPv6Prefix = 126
    static let mtu = 9000
}

extension NETunnelProviderProtocol {
    var appGroupId: String? {
        providerConfiguration?[AppGroupLayout.groupKey] as? String
    }

    var requestedVersion: String? {
        providerConfiguration?[AppGroupLayout.versionKey] as? String
    }
}
