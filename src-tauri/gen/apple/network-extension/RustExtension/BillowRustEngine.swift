import Foundation
import NetworkExtension

#if BILLOW_RUST_PLACEHOLDER
/// Placeholder data plane for T7: the target builds, signs and starts, reads
/// the same App Group resources as the Mihomo extension and refuses traffic
/// with a distinguishable error until `rust_tunnel_port_t` is provided by the
/// Rust kernel. Setting rustPort from T7 is the only wiring step required.
final class BillowRustEngine {
    private weak var provider: NEPacketTunnelProvider?
    private(set) var version: String?
    private(set) var embeddedVersion: String?
    private(set) var lastError: NSError?
    private(set) var startedAt: Date?

    init(provider: NEPacketTunnelProvider) {
        self.provider = provider
    }

    var isAvailable: Bool { rustPort != nil }

    func start(store: AppGroupStore, requestedVersion: String?) throws {
        let active = try store.activeVersion()
        let (manifest, dir) = try store.validatedResources(active, expectedEngine: BillowEngineIdentity.engine)
        version = active
        guard let provider else {
            throw BillowVPNError.make(.tunnelSetupFailed, "provider deallocated")
        }
        guard let port = rustPort else {
            throw BillowVPNError.make(.engineNotAvailable,
                                      "Rust data plane not linked (T7 placeholder, resources \(manifest.version))")
        }
        _ = requestedVersion
        var error: UnsafeMutableRawPointer?
        let home = strdup(dir.path)!
        let rc = billow_rust_start(home, port, Unmanaged.passUnretained(provider).toOpaque(), &error)
        free(home)
        guard rc == 0 else {
            let text = error.map { String(cString: $0.assumingMemoryBound(to: CChar.self)) } ?? "rust start failed"
            if let error {
                billow_rust_free(error)
            }
            throw BillowVPNError.make(.engineStartFailed, text)
        }
        embeddedVersion = "billow-rust-placeholder"
        startedAt = Date()
    }

    func shutdown() {
        guard let provider else { return }
        billow_rust_stop(Unmanaged.passUnretained(provider).toOpaque())
    }
}

// Declared in include/billow_rust_bridge.h (C declarations come from the
// bridging header BillowRust-Bridging-Header.h).
/// T7 installs the Rust kernel's table here (for example from a Swift shim
/// over the exported C functions of native-kernel/).
var rustPort: UnsafeMutablePointer<rust_tunnel_port_t>?
#endif
