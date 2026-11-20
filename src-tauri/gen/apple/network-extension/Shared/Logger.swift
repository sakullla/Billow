import OSLog

/// Unified-log wrapper. Messages never include subscription credentials (the
/// host keeps those out of App Group files and providerConfiguration).
struct BillowLog {
    private let vpn: Logger
    private let engineLogger: Logger

    init(_ component: String) {
        let subsystem = "app.billow.client.\(component)"
        vpn = Logger(subsystem: subsystem, category: "packet-tunnel")
        engineLogger = Logger(subsystem: subsystem, category: "engine")
    }

    func info(_ message: String) {
        vpn.info("\(message, privacy: .public)")
    }

    func warning(_ message: String) {
        vpn.warning("\(message, privacy: .public)")
    }

    func error(_ message: String) {
        vpn.error("\(message, privacy: .public)")
    }

    /// Engine diagnostics; the embedded logger applies mihomo's log-level.
    func engine(_ message: String) {
        engineLogger.debug("\(message, privacy: .public)")
    }
}
