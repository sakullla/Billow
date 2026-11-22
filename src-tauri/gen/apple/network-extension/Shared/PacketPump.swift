import Foundation
import NetworkExtension

// Extension-only file: the host target also compiles network-extension/Shared
// (for AppGroupStore/ProviderSupport), but it neither reads packetFlow nor
// links an engine, so compiling this file there would surface an undefined
// engine symbol. Each extension target defines exactly one of the two guards.
#if BILLOW_ENGINE_MIHOMO || BILLOW_ENGINE_RUST

/// Reads IP packets from NEPacketTunnelFlow and hands each one to `ingest`.
///
/// Only one readPackets call is outstanding at a time. readPackets (SDK 27)
/// hands out [Data] copies; every packet is forwarded synchronously and then
/// released when the handler returns.
final class PacketPump {
    typealias Ingest = (NEPacketTunnelFlow, [Data]) -> Int32

    private let flow: NEPacketTunnelFlow
    private let ingest: (NEPacketTunnelFlow, [Data]) -> Int32
    private let onStop: (NSError?) -> Void
    private var running = false
    private(set) var lastError: NSError?

    init(flow: NEPacketTunnelFlow, ingest: @escaping (NEPacketTunnelFlow, [Data]) -> Int32,
         onStop: @escaping (NSError?) -> Void) {
        self.flow = flow
        self.ingest = ingest
        self.onStop = onStop
    }

    func start() {
        running = true
        readNext()
    }

    func stop() {
        running = false
    }

    private func readNext() {
        guard running else { return }
        flow.readPackets { [weak self] packets, _ in
            guard let self, self.running else { return }
            if !packets.isEmpty {
                let rc = self.ingest(self.flow, packets)
                if rc < 0 {
                    let error = BillowVPNError.make(.engineStopped, "engine rejected the packet batch")
                    self.running = false
                    self.lastError = error
                    self.onStop(error)
                    return
                }
            }
            self.readNext()
        }
    }
}

/// Packs a readPackets batch as [4-byte big-endian length][IP packet] records
/// and injects every record through GoMihomoReadPacket.
#if BILLOW_ENGINE_MIHOMO
func mihomoIngest(_ flow: NEPacketTunnelFlow, _ packets: [Data]) -> Int32 {
    let capacity = 4 + ProviderSupport.mtu
    var record = [UInt8](repeating: 0, count: capacity)
    var rejected = false
    for packet in packets {
        let n = min(packet.count, capacity - 4)
        guard n >= 20 else { continue }
        record[0] = UInt8((n >> 24) & 0xff)
        record[1] = UInt8((n >> 16) & 0xff)
        record[2] = UInt8((n >> 8) & 0xff)
        record[3] = UInt8(n & 0xff)
        packet.withUnsafeBytes { raw in
            guard let src = raw.baseAddress else { return }
            record.withUnsafeMutableBufferPointer { buffer in
                guard let dst = buffer.baseAddress else { return }
                (dst + 4).update(from: src.assumingMemoryBound(to: UInt8.self), count: n)
                if GoMihomoReadPacket(dst, UInt32(n + 4)) < 0 {
                    rejected = true
                }
            }
        }
        if rejected {
            return -1
        }
    }
    return 0
}

#endif // BILLOW_ENGINE_MIHOMO

#endif // BILLOW_ENGINE_MIHOMO || BILLOW_ENGINE_RUST
