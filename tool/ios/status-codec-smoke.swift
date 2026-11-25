// Canonical `ProviderStatus` codec smoke, run with the real shared source:
//
//   cat src-tauri/gen/apple/network-extension/Shared/BillowVPNError.swift \
//       tool/ios/status-codec-smoke.swift | xcrun swift -
//
// It proves the host-visible contract added for R4: a provider `status` reply
// that carries the Rust extension's `stats` object decodes into
// `ProviderStatus`, keeps the counters, and re-encodes with the camelCase keys
// `BillowMobileBridge.statusDictionary` / `status/<engine>.json` publish.
// App Group writes and the iOS target itself are covered by
// `tool/ios/verify-host-sources.sh` type-checks and still need a device.

import Darwin
import Foundation

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("status-codec-smoke: \(message)\n".utf8))
    exit(1)
}

let reply = """
{
  "extensionId": "app.billow.client.rust",
  "engine": "rust",
  "embeddedVersion": "billow-rust 0.1.0",
  "running": true,
  "version": "v7",
  "loopbackPort": null,
  "loopbackListen": null,
  "lastError": null,
  "errorCode": null,
  "startedAt": "2026-11-24T00:00:00Z",
  "stats": {
    "running": true,
    "version": "billow-rust 0.1.0",
    "generation": 3,
    "reloads": 2,
    "peakRssBytes": 28491776,
    "tcpFlows": 8,
    "tcpOpened": 12,
    "tcpClosed": 4,
    "queuedPackets": 0,
    "queueHigh": 7,
    "udpFlows": 2,
    "dnsQueries": 5,
    "futureCounter": 99
  }
}
"""

let decoder = JSONDecoder()
decoder.dateDecodingStrategy = .iso8601
guard let status = try? decoder.decode(ProviderStatus.self, from: Data(reply.utf8)) else {
    fail("a provider status reply with stats did not decode")
}
guard status.extensionId == "app.billow.client.rust", status.engine == "rust", status.running else {
    fail("identity fields were not preserved")
}
guard let stats = status.stats else {
    fail("stats was dropped by ProviderStatus")
}
guard stats.generation == 3, stats.reloads == 2, stats.peakRssBytes == 28_491_776,
      stats.tcpFlows == 8, stats.tcpOpened == 12, stats.queuedPackets == 0,
      stats.queueHigh == 7, stats.dnsQueries == 5 else {
    fail("stats counters changed during decoding")
}

// Same encoder configuration as ProviderSupport.encodeStatus, used for both the
// provider reply and status/<engine>.json.
let encoder = JSONEncoder()
encoder.dateEncodingStrategy = .iso8601
guard let encoded = try? encoder.encode(status),
      let object = try? JSONSerialization.jsonObject(with: encoded) as? [String: Any] else {
    fail("ProviderStatus did not re-encode")
}
guard object["extensionId"] as? String == "app.billow.client.rust",
      object["startedAt"] as? String == "2026-11-24T00:00:00Z" else {
    fail("status file keys/dates changed")
}
guard let encodedStats = object["stats"] as? [String: Any],
      encodedStats["peakRssBytes"] as? Int == 28_491_776,
      encodedStats["generation"] as? Int == 3 else {
    fail("stats did not survive the status-file encoding")
}
guard encodedStats["futureCounter"] == nil else {
    fail("unknown counters must stay out of the typed status model")
}

// The dictionary BillowMobileBridge.statusDictionary embeds under "stats".
let bridgeStats = stats.dictionary
guard bridgeStats["queueHigh"] as? Int == 7,
      bridgeStats["dnsQueries"] as? Int == 5 else {
    fail("bridge stats dictionary lost counters")
}

// Mihomo / older replies have no stats and must stay decodable.
let legacy = """
{"extensionId":"app.billow.client.mihomo","engine":"mihomo","running":false}
"""
guard let legacyStatus = try? decoder.decode(ProviderStatus.self, from: Data(legacy.utf8)) else {
    fail("a status reply without stats no longer decodes")
}
guard legacyStatus.stats == nil else {
    fail("missing stats must decode as nil")
}

print("ok: ProviderStatus decodes/re-encodes stats (bridge dictionary carries counters)")
