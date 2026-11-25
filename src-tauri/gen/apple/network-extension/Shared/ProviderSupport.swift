import Foundation
import NetworkExtension

/// Per-target identity. The Swift sources in network-extension/Shared are
/// compiled into both extensions and the host; each target defines exactly one
/// of BILLOW_ENGINE_MIHOMO / BILLOW_ENGINE_RUST / BILLOW_ENGINE_HOST (see
/// project.yml).
enum BillowEngineIdentity {
    static var engine: String {
        #if BILLOW_ENGINE_MIHOMO
        return "mihomo"
        #elseif BILLOW_ENGINE_RUST
        return "rust"
        #elseif BILLOW_ENGINE_HOST
        // The host never writes a provider status file; it reads both engines
        // by name through AppGroupStore/BillowVPNManager. A distinct value keeps
        // an accidental write from overwriting either extension's status.
        return "host"
        #else
        #error("Define BILLOW_ENGINE_MIHOMO, BILLOW_ENGINE_RUST or BILLOW_ENGINE_HOST for this target")
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
        guard let url = statusURL(groupId: groupId), let data = encodeStatus(status) else { return }
        try? data.write(to: url, options: .atomic)
    }

    /// One encoding for the App Group status file, the provider `status` reply
    /// and the bridge: ISO-8601 dates and the camelCase `ProviderStatus` keys
    /// (including `stats`) stay identical across all three paths.
    static func encodeStatus(_ status: ProviderStatus) -> Data? {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try? encoder.encode(status)
    }

    /// Decodes the provider `status` reply or a `status/<engine>.json` file.
    /// Unknown `stats` counters are ignored, so a newer kernel stays readable.
    static func decodeStatus(_ data: Data?) -> ProviderStatus? {
        guard let data else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(ProviderStatus.self, from: data)
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
