import Foundation

/// Error codes surfaced to the host. `NETunnelProviderSession` reports the
/// provider error through `NEVPNConnectionError` / `lastDisconnectError`:
/// the NSError domain is `NEVPNConnectionErrorDomain` and the code is
/// `NEVPNConnectionError.providerFailed` for a start failure; the underlying
/// reason is the provider's `cancelTunnel(with:)` error.
enum BillowVPNError {
    static let domain = "app.billow.client.vpn"

    enum Code: Int {
        case providerFailed = 0
        case resourceInvalid = 1
        case engineStartFailed = 2
        case configurationMissing = 3
        case engineNotAvailable = 4
        case networkUnavailable = 5
        case engineStopped = 6
        case loopbackFailed = 7
        case unsupportedCommand = 8
        case tunnelSetupFailed = 9
        case hostNotReady = 10
    }

    static func make(_ code: Code, _ detail: String, underlying: Error? = nil) -> NSError {
        var info: [String: Any] = [NSLocalizedDescriptionKey: detail]
        if let underlying {
            info[NSUnderlyingErrorKey] = underlying
        }
        return NSError(domain: domain, code: code.rawValue, userInfo: info)
    }

    /// Classifies failures so the host can tell "resources not ready" apart
    /// from "engine failed" or "entitlement/permission missing".
    static func classify(_ error: Error) -> Code {
        let ns = error as NSError
        if ns.domain == domain, let code = Code(rawValue: ns.code) {
            return code
        }
        switch ns.code {
        case 1, 4, 5: // NEVPNError.configurationInvalid / configurationReadWriteFailed / configurationUnknown
            return .configurationMissing
        case NSURLErrorNotConnectedToInternet, NSURLErrorNetworkConnectionLost:
            return .networkUnavailable
        default:
            if let posix = error as? POSIXError, posix.code == .EPERM {
                // Saving or starting a tunnel without the Network Extension
                // entitlement or user permission fails with EPERM.
                return .providerFailed
            }
            return .engineStartFailed
        }
    }
}

/// Messages exchanged between host and extension through
/// `NETunnelProviderSession.sendProviderMessage` and
/// `NEPacketTunnelProvider.handleAppMessage`.
enum ProviderCommand: String {
    case status
    case reload
    case setMode
    case loopback
}

enum ProviderMessageKey {
    static let command = "command"
    static let mode = "mode"
    static let listen = "listen"
    static let fraction = "fraction"
    static let version = "version"
    static let engine = "engine"
    static let running = "running"
    static let loopbackPort = "loopbackPort"
    static let loopbackListen = "loopbackListen"
    static let embedded = "embedded"
    static let error = "error"
    static let errorCode = "code"
    static let ok = "ok"
    static let provider = "provider"
    static let engineId = "engineId"
    static let message = "message"
    static let domain = "domain"
    /// JSON counters + peak RSS (`billow_ios_vpn_stats`); present on the Rust
    /// engine only.
    static let stats = "stats"
}

/// What `status` answers; also stored at "status/<extensionId>.json" inside
/// the App Group so the host can show it without starting a session.
struct ProviderStatus: Codable {
    var extensionId: String
    var engine: String
    var embeddedVersion: String?
    var running: Bool
    var version: String?
    var loopbackPort: Int?
    var loopbackListen: String?
    var lastError: String?
    var errorCode: Int?
    var startedAt: Date?
    /// Live tunnel counters + process peak RSS reported by the Rust extension
    /// (`billow_ios_vpn_stats`); nil for Mihomo and older extensions. The key
    /// names below match that JSON object verbatim so the host, the App Group
    /// status file and `ios_vpn_status` all carry the same numbers (R4).
    var stats: ProviderStats? = nil
}

/// The `stats` object of a Rust extension status reply. Every field is
/// optional: a counter added by a newer kernel still decodes, and a reply
/// without it (Mihomo) leaves `ProviderStatus.stats` nil. Property names are
/// the JSON keys from `billow_ios_vpn_stats` (camelCase).
struct ProviderStats: Codable {
    var running: Bool?
    var version: String?
    var generation: UInt64?
    var reloads: UInt64?
    var peakRssBytes: UInt64?
    var inPackets: UInt64?
    var inBytes: UInt64?
    var outPackets: UInt64?
    var outBytes: UInt64?
    var tcpOpened: UInt64?
    var tcpClosed: UInt64?
    var tcpRejected: UInt64?
    var tcpFlows: UInt64?
    var tcpFlowHigh: UInt64?
    var udpDatagrams: UInt64?
    var udpReplies: UInt64?
    var udpFlows: UInt64?
    var udpFlowHigh: UInt64?
    var dnsQueries: UInt64?
    var dnsFailures: UInt64?
    var invalidPackets: UInt64?
    var fragments: UInt64?
    var unsupportedProtocols: UInt64?
    var icmpDropped: UInt64?
    var droppedInbound: UInt64?
    var droppedEgress: UInt64?
    var queueHigh: UInt64?
    var queuedPackets: UInt64?

    /// The object `BillowMobileBridge` embeds under `stats`; only counters the
    /// extension actually sent are present, so a new kernel counter is not
    /// invented as null by the host.
    var dictionary: [String: Any] {
        guard let data = try? JSONEncoder().encode(self),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return [:]
        }
        return object
    }
}
