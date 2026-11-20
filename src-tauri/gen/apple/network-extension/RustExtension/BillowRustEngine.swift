import Foundation
import NetworkExtension

// libapp.a (src-tauri/src/ios_vpn.rs) is reached only through C shims
// (RustKernelBridge.c, declared in billow_rust_bridge.h and visible via the
// bridging header); Swift calls them directly and never names a Rust symbol
// with @_silgen_name, which the linker would reject. billow_rust_free is an
// ordinary C function (BillowRustBridge.c) seen through the bridging header.

/// Kernel gate: libapp.a only provides the billow_ios_vpn_* entry points,
/// reached through RustKernelBridge.c.
enum RustKernel {
    private static let lock = NSLock()
    private static var cached: Bool?

    /// Whether libapp.a was found and linked (RustKernelBridge.c compiled
    /// with BILLOW_RUST_KERNEL_LINKED by the "Resolve Rust kernel" phase).
    static var linked: Bool {
        lock.lock()
        defer { lock.unlock() }
        if let cached {
            return cached
        }
        var buf = [CChar](repeating: 0, count: 32)
        let length = buf.withUnsafeMutableBufferPointer { billow_rust_kernel_version($0.baseAddress, Int32($0.count)) }
        let linked = length > 0 && billow_rust_kernel_image_present() == 1
        cached = linked
        return linked
    }

    static var version: String {
        guard linked else { return "billow-rust (unlinked)" }
        var buf = [CChar](repeating: 0, count: 32)
        _ = buf.withUnsafeMutableBufferPointer { billow_rust_kernel_version($0.baseAddress, Int32($0.count)) }
        return String(cString: buf)
    }
}

/// Data plane of the Rust extension. Swift owns readPackets and the tunnel
/// settings; the Rust kernel (libapp.a) owns routing, DNS and egress. Each
/// readPackets batch is replayed into the Rust tunnel through
/// billow_ios_vpn_drain; duplicates and re-injected packets are rejected by
/// libapp.a.
final class BillowRustEngine {
    private weak var provider: NEPacketTunnelProvider?
    private var pump: PacketPump?
    private var stateLock = NSLock()
    private var failed = false
    private var stopping = false
    private(set) var version: String?
    private(set) var embeddedVersion: String?
    private(set) var lastError: NSError?
    private(set) var startedAt: Date?
    private let log = BillowLog("rust")

    init(provider: NEPacketTunnelProvider) {
        self.provider = provider
    }

    static var kernelLinked: Bool { RustKernel.linked }
    static func rustEngineVersion() -> String { RustKernel.version }

    /// Successful starts in this process (diagnostics only).
    static var startCount = 0

    /// Validates the App Group version for this engine and starts libapp.a.
    func start(store: AppGroupStore, requestedVersion: String?) throws {
        let active = try store.activeVersion()
        let (_, dir) = try store.validatedResources(active, expectedEngine: BillowEngineIdentity.engine)
        version = active
        _ = requestedVersion
        guard let provider else {
            throw BillowVPNError.make(.tunnelSetupFailed, "provider deallocated")
        }
        guard Self.kernelLinked else {
            throw BillowVPNError.make(.engineNotAvailable,
                                      "libapp.a not linked into BillowRust (run tool/ios/build.sh)")
        }
        // 1 = the app state selects the Rust kernel; the host only starts this
        // extension when it is selected, so 0 is allowed too (the extension is
        // still startable and reportable). -1 means the app never wrote its
        // state: Billow must be launched once (code 10, hostNotReady).
        if billow_rust_kernel_selected() == -1 {
            throw BillowVPNError.make(.hostNotReady, "app state not loaded; start Billow once")
        }
        embeddedVersion = Self.rustEngineVersion()
        let ctx = Unmanaged.passUnretained(provider).toOpaque()
        let home = strdup(dir.path)!
        var error: UnsafeMutablePointer<CChar>?
        let rc = billow_rust_kernel_start(ctx, home, rustKernelWrite, &error)
        free(home)
        guard rc == 0 else {
            let text = error.map { String(cString: $0) } ?? "billow_ios_vpn_start failed (\(rc))"
            if let error {
                free(error)
            }
            throw BillowVPNError.make(.engineStartFailed, text)
        }
        Self.startCount += 1
        startedAt = Date()
        log.info("rust engine \(self.embeddedVersion ?? "?") started")
    }

    /// Starts the readPackets pump (Swift side of the data path).
    func startMainPump() {
        guard let provider, pump == nil else { return }
        let pump = PacketPump(flow: provider.packetFlow, ingest: rustIngest) { [weak self] error in
            self?.recordFailure(error ?? BillowVPNError.make(.engineStopped, "rust packet pump stopped"))
        }
        self.pump = pump
        pump.start()
    }

    func recordFailure(_ error: NSError) {
        stateLock.lock()
        let first = !failed
        failed = true
        stateLock.unlock()
        if first {
            lastError = error
            log.error("rust engine failure: \(error.localizedDescription)")
            failedHandler?(error)
        }
    }

    /// Called once with the first unrecoverable error.
    var failedHandler: ((NSError) -> Void)?

    func shutdown() {
        stateLock.lock()
        stopping = true
        stateLock.unlock()
        pump?.stop()
        pump = nil
        if Self.kernelLinked {
            billow_rust_kernel_stop()
        }
    }

    var status: ProviderStatus {
        ProviderStatus(
            extensionId: BillowEngineIdentity.bundleId,
            engine: BillowEngineIdentity.engine,
            embeddedVersion: embeddedVersion,
            running: !failed && startedAt != nil && !stopping,
            version: version,
            loopbackPort: nil,
            loopbackListen: nil,
            lastError: lastError?.localizedDescription,
            errorCode: lastError?.code,
            startedAt: startedAt
        )
    }
}

/// Egress callback registered with libapp.a (billow_ios_vpn_start(port, ctx)):
/// Rust hands each packet back here and it is written to packetFlow. It is a
/// global C function so Rust never holds a Swift closure.
let rustKernelWrite: @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, UInt32) -> Int64 = { ctx, packet, length in
    guard let ctx, let packet else { return -1 }
    let provider = Unmanaged<NEPacketTunnelProvider>.fromOpaque(ctx).takeUnretainedValue()
    let family: sa_family_t = (packet.assumingMemoryBound(to: UInt8.self).pointee >> 4) == 6
        ? sa_family_t(AF_INET6) : sa_family_t(AF_INET)
    let data = Data(bytesNoCopy: packet, count: Int(length), deallocator: .none)
    provider.packetFlow.writePackets([data], withProtocols: [NSNumber(value: family)])
    return 0
}

/// Packet pump ingest: packs [length][packet] records and replays them into
/// the Rust tunnel one at a time through billow_ios_vpn_drain.
func rustIngest(_ flow: NEPacketTunnelFlow, _ packets: [Data]) -> Int32 {
    guard let engine = BillowRustTunnelProvider.current else { return 0 }
    let capacity = 4 + ProviderSupport.mtu
    var record = [UInt8](repeating: 0, count: capacity)
    var produced: UInt32 = 0
    for packet in packets {
        let n = min(packet.count, capacity - 4)
        guard n >= 20 else { continue }
        record[0] = UInt8((n >> 24) & 0xff)
        record[1] = UInt8((n >> 16) & 0xff)
        record[2] = UInt8((n >> 8) & 0xff)
        record[3] = UInt8(n & 0xff)
        let result: Int32 = packet.withUnsafeBytes { raw in
            guard let src = raw.baseAddress else { return 0 }
            return record.withUnsafeMutableBufferPointer { buffer in
                guard let dst = buffer.baseAddress else { return 0 }
                (dst + 4).update(from: src.assumingMemoryBound(to: UInt8.self), count: n)
                return billow_rust_kernel_drain(dst, UInt32(n + 4), &produced)
            }
        }
        if result < 0 {
            engine.recordFailure(BillowVPNError.make(.engineStopped, "billow_ios_vpn_drain returned \(result)"))
            return result
        }
    }
    return 0
}

/// Strong reference for the global ingest function.
enum BillowRustTunnelProvider {
    static weak var current: BillowRustEngine?
}
