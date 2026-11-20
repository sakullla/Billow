import Foundation
import NetworkExtension

// Go exports (include/billow_mihomo_bridge.h). Kept in the global namespace so
// Swift never emits a $s-prefixed symbol for them.
@_silgen_name("GoMihomoStart")
func GoMihomoStart(_ home: UnsafeMutablePointer<CChar>, _ writeCB: UInt, _ checkCB: UInt,
                   _ ctx: UnsafeMutableRawPointer?, _ errOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32
@_silgen_name("GoMihomoVersion")
func GoMihomoVersion(_ buf: UnsafeMutablePointer<CChar>, _ size: Int32) -> Int32
@_silgen_name("GoMihomoReload")
func GoMihomoReload(_ errOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32
@_silgen_name("GoMihomoNetworkChanged")
func GoMihomoNetworkChanged() -> Int32
@_silgen_name("GoMihomoShutdown")
func GoMihomoShutdown()
@_silgen_name("GoMihomoReadPacket")
func GoMihomoReadPacket(_ record: UnsafeMutableRawPointer?, _ size: UInt32) -> Int32
@_silgen_name("GoMihomoWritePackets")
func GoMihomoWritePackets(_ packet: UnsafeMutableRawPointer?, _ length: UInt32) -> Int32
@_silgen_name("GoMihomoLoopbackStart")
func GoMihomoLoopbackStart(_ listen: UnsafeMutablePointer<CChar>, _ fraction: Double) -> Int32
@_silgen_name("GoMihomoLoopbackStop")
func GoMihomoLoopbackStop()
@_silgen_name("billow_mihomo_free")
func billowMihomoFree(_ p: UnsafeMutablePointer<CChar>)

typealias MihomoWriteCallback = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, UInt32) -> Int64
typealias MihomoCheckCallback = @convention(c) (UnsafeMutableRawPointer?) -> Int64

/// Glue between the Packet Tunnel provider and libmihomo_ios.a (Go).
///
/// Read side: PacketPump calls packetFlow.readPackets and injects each packet
/// through GoMihomoReadPacket. Write side: the gVisor stack calls
/// mihomoWriteCallback (a Swift C function, not a closure over self) which
/// resolves the provider from the Go-owned context pointer.
final class BillowMihomoEngine {
    private weak var provider: NEPacketTunnelProvider?
    private(set) var version: String?
    private(set) var embeddedVersion: String?
    private(set) var loopbackPort: Int?
    private(set) var loopbackListen: String?
    private(set) var lastError: NSError?
    private(set) var startedAt: Date?
    private let log = BillowLog("mihomo-engine")
    private var loopbackPointer: UnsafeMutablePointer<CChar>?
    private var running = false

    init(provider: NEPacketTunnelProvider) {
        self.provider = provider
    }

    var isRunning: Bool { running }

    /// Validates the active App Group resources, registers the packet port and
    /// starts the engine on a background queue (mihomo parses the config and
    /// builds the gVisor stack synchronously).
    func start(store: AppGroupStore, requestedVersion: String?, completion: @escaping (Error?) -> Void) {
        let active: String
        do {
            active = try store.activeVersion()
            _ = try store.validatedResources(active, expectedEngine: BillowEngineIdentity.engine)
        } catch {
            let mapped = error as NSError
            lastError = mapped.domain == BillowVPNError.domain
                ? mapped
                : BillowVPNError.make(.resourceInvalid, "\(error)", underlying: error)
            completion(lastError)
            return
        }
        if let requestedVersion, requestedVersion != active {
            self.log.error("requested resources \(requestedVersion) are not active; using \(active)")
        }
        version = active
        let dir = store.versionURL(active).path
        guard let provider else {
            completion(BillowVPNError.make(.tunnelSetupFailed, "provider deallocated"))
            return
        }
        let ctx = Unmanaged.passUnretained(provider).toOpaque()
        let writeCB = unsafeBitCast(mihomoWriteCallback as MihomoWriteCallback, to: UInt.self)
        let checkCB = unsafeBitCast(mihomoCheckCallback as MihomoCheckCallback, to: UInt.self)
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            var errOut: UnsafeMutablePointer<CChar>?
            var versionBuf = [CChar](repeating: 0, count: 32)
            let home = strdup(dir)!
            let rc = versionBuf.withUnsafeMutableBufferPointer { buf in
                GoMihomoStart(home, writeCB, checkCB, ctx, &errOut)
            }
            free(home)
            if rc != 0 {
                let text = errOut.map { String(cString: $0) } ?? "mihomo start failed"
                if let errOut {
                    billowMihomoFree(errOut)
                }
                lastError = BillowVPNError.make(.engineStartFailed, text)
                completion(lastError)
                return
            }
            embeddedVersion = String(cString: versionBuf)
            DispatchQueue.main.async {
                completion(nil)
            }
        }
    }

    /// Starts the optional loopback for the Rust data plane (manifest
    /// options.loopbackListen). Failure is reported but does not stop the
    /// engine: loopback is only used by T7.
    func startLoopback(manifest: SharedManifest) {
        let listen = manifest.options?.loopbackListen ?? ""
        guard !listen.isEmpty else { return }
        let pointer = strdup(listen)!
        let port = GoMihomoLoopbackStart(pointer, manifest.options?.loopbackFraction ?? 1)
        if port < 0 {
            free(pointer)
            lastError = BillowVPNError.make(.loopbackFailed, "loopback listen \(listen) failed")
            log.error("loopback listen \(listen) failed")
            return
        }
        loopbackPointer = pointer
        loopbackPort = Int(port)
        loopbackListen = listen.replacingOccurrences(of: ":0", with: ":\(port)")
    }

    func markRunning() {
        running = true
        startedAt = Date()
        log.info("mihomo \(self.embeddedVersion ?? "?") started with resources \(self.version ?? "?")")
    }

    func reload() throws {
        var errOut: UnsafeMutablePointer<CChar>?
        let rc = GoMihomoReload(&errOut)
        if rc != 0 {
            let text = errOut.map { String(cString: $0) } ?? "reload failed"
            if let errOut {
                billowMihomoFree(errOut)
            }
            throw BillowVPNError.make(.engineStartFailed, text)
        }
    }

    /// Reports a path change; returns true when the extension has to restart
    /// the tunnel (Network Extension contract after NWPathMonitor updates).
    func networkChanged() -> Bool {
        GoMihomoNetworkChanged() != 0
    }

    func shutdown() {
        if loopbackPointer != nil {
            GoMihomoLoopbackStop()
            free(loopbackPointer)
            loopbackPointer = nil
            loopbackPort = nil
        }
        running = false
        GoMihomoShutdown()
    }

    func status() -> ProviderStatus {
        ProviderStatus(
            extensionId: BillowEngineIdentity.bundleId,
            engine: BillowEngineIdentity.engine,
            embeddedVersion: embeddedVersion,
            running: running,
            version: version,
            loopbackPort: loopbackPort,
            loopbackListen: loopbackListen,
            lastError: lastError?.localizedDescription,
            errorCode: lastError?.code,
            startedAt: startedAt
        )
    }
}

// MARK: - Packet port callbacks (Go -> Swift)

/// Egress: one IP packet produced by the gVisor stack.
let mihomoWriteCallback: MihomoWriteCallback = { ctx, packet, length in
    guard let ctx, let packet else { return -1 }
    let provider = Unmanaged<NEPacketTunnelProvider>.fromOpaque(ctx).takeUnretainedValue()
    return provider.writeIPPacket(packet.assumingMemoryBound(to: UInt8.self), Int(length))
}

/// Path check used by GoMihomoNetworkChanged; the extension keeps the tunnel
/// up (mihomo's dialer follows the system default route).
let mihomoCheckCallback: MihomoCheckCallback = { _ in 0 }

extension NEPacketTunnelProvider {
    /// Writes one IP packet; Go keeps the memory valid until writePackets
    /// returns (it calls this synchronously from the stack).
    fileprivate func writeIPPacket(_ bytes: UnsafeMutablePointer<UInt8>, _ length: Int) -> Int64 {
        let family: sa_family_t = (bytes.pointee >> 4) == 6 ? sa_family_t(AF_INET6) : sa_family_t(AF_INET)
        // Go keeps the memory valid until writePackets returns (synchronous).
        let buffer = Data(bytesNoCopy: bytes, count: length, deallocator: .none)
        packetFlow.writePackets([buffer], withProtocols: [NSNumber(value: family)])
        return 0
    }
}
