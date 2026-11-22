import Foundation

/// C ABI between the Tauri host commands (`src-tauri/src/ios_vpn.rs`) and the
/// NetworkExtension management code in this target.
///
/// One synchronous request/response call is enough for every command: the
/// Rust side runs the call from `spawn_blocking`, while the Swift side wraps
/// the async `NETunnelProviderManager` APIs in a semaphore. Strings are UTF-8
/// JSON; the returned pointer is `malloc`'d and released by
/// `billow_mobile_free`.
///
/// Requests (keys in camelCase):
///   { "command": "engines" }
///   { "command": "prepare", "version": "v1", "engine": "rust"?, "stagedDir": "/…" }
///   { "command": "select", "engine": "mihomo" | "rust" }
///   { "command": "connect", "engine": "rust", "version": "v1" }
///   { "command": "disconnect" }
///   { "command": "status", "engine": "rust" }
///   { "command": "reload", "engine": "rust" }
///   { "command": "prune", "keeping": ["v1", "v2"] }
///   { "command": "selected" }
///
/// Responses: `{ "ok": true, "data": … }` or
/// `{ "ok": false, "error": { "code", "message", "domain" } }`. Codes are the
/// stable `BillowVPNError.Code` values (0…10); a malformed request uses 8
/// (`unsupportedCommand`) and a host timeout uses 0 (`providerFailed`).
@_cdecl("billow_mobile_request")
public func billowMobileRequest(_ request: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let request else {
        return nil
    }
    let reply = BillowMobileHost.handle(String(cString: request))
    return strdup(reply)
}

@_cdecl("billow_mobile_free")
public func billowMobileFree(_ pointer: UnsafeMutablePointer<CChar>?) {
    if let pointer {
        free(pointer)
    }
}

enum BillowMobileHost {
    static let timeout: TimeInterval = 40

    static func handle(_ json: String) -> String {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let command = object["command"] as? String else {
            return encode(errorResponse(BillowVPNError.make(.unsupportedCommand,
                                                            "request is not a JSON object with a command")))
        }
        let semaphore = DispatchSemaphore(value: 0)
        var response: [String: Any] = [:]
        Task {
            response = await perform(command: command, object: object)
            semaphore.signal()
        }
        if semaphore.wait(timeout: .now() + timeout) == .timedOut {
            return encode(errorResponse(BillowVPNError.make(.providerFailed,
                                                            "\(command) timed out after \(Int(timeout)) s")))
        }
        return encode(response)
    }

    private static func perform(command: String,
                                object: [String: Any]) async -> [String: Any] {
        do {
            switch command {
            case "engines":
                let states = await BillowMobileEntry.engineStates()
                return success(states.map { state in
                    [
                        "engine": state.engine,
                        "installed": state.installed,
                        "connected": state.connected,
                        "version": state.version.map { $0 as Any } ?? NSNull(),
                        "engineVersion": state.engineVersion.map { $0 as Any } ?? NSNull(),
                        "lastError": state.lastError.map { $0 as Any } ?? NSNull(),
                    ]
                })

            case "activeVersion":
                return success(BillowMobileEntry.activeVersion() ?? NSNull())

            case "prepare":
                let version = try string(object, "version")
                let staged = try string(object, "stagedDir")
                guard FileManager.default.containerURL(
                    forSecurityApplicationGroupIdentifier: BillowVPNManager.shared.appGroupId
                ) != nil else {
                    throw BillowVPNError.make(.resourceInvalid,
                                              "App Group unavailable (entitlement missing?)")
                }
                let installer = ResourcesInstaller()
                let engines: [BillowVPNManager.Engine]
                if let raw = object["engine"] as? String, let one = BillowVPNManager.Engine(rawValue: raw) {
                    engines = [one]
                } else {
                    engines = BillowVPNManager.Engine.allCases
                }
                let manifest = try installer.prepare(version: version,
                                                     engines: engines,
                                                     stagedDir: URL(fileURLWithPath: staged))
                return success([
                    "version": manifest.version,
                    "engines": manifest.engines,
                    "files": manifest.files.count,
                ])

            case "select":
                let engine = try engine(object)
                BillowVPNManager.shared.setSelected(engine)
                return success(["selected": engine.rawValue])

            case "selected":
                return success(["selected": BillowVPNManager.shared.selected().rawValue])

            case "connect":
                let engine = try engine(object)
                let version = try string(object, "version")
                let manager = BillowVPNManager.shared
                try await manager.connect(engine: engine, requestedVersion: version)
                let state = try await manager.waitForState(.connected, engine: engine)
                guard state == .connected else {
                    let detail = manager.describeLastError(engine: engine)
                        ?? "\(engine.rawValue) did not reach connected (status \(state.rawValue))"
                    throw BillowVPNError.make(.engineStartFailed, detail)
                }
                return success(["engine": engine.rawValue, "version": version, "connected": true])

            case "disconnect":
                try await BillowVPNManager.shared.disconnect()
                return success([:])

            case "status":
                let engine = try engine(object)
                let status = try await BillowVPNManager.shared.status(of: engine)
                return success(status.map(statusDictionary) ?? NSNull())

            case "reload":
                try await BillowVPNManager.shared.reload(engine: try engine(object))
                return success([:])

            case "prune":
                guard FileManager.default.containerURL(
                    forSecurityApplicationGroupIdentifier: BillowVPNManager.shared.appGroupId
                ) != nil else {
                    throw BillowVPNError.make(.resourceInvalid,
                                              "App Group unavailable (entitlement missing?)")
                }
                let keeping = object["keeping"] as? [String] ?? []
                ResourcesInstaller().prune(keeping: keeping)
                return success(["keeping": keeping])

            default:
                throw BillowVPNError.make(.unsupportedCommand, "unknown host command '\(command)'")
            }
        } catch {
            return errorResponse(error)
        }
    }

    private static func engine(_ object: [String: Any]) throws -> BillowVPNManager.Engine {
        guard let raw = object["engine"] as? String,
              let engine = BillowVPNManager.Engine(rawValue: raw) else {
            throw BillowVPNError.make(.configurationMissing,
                                      "engine must be 'mihomo' or 'rust'")
        }
        return engine
    }

    private static func string(_ object: [String: Any], _ key: String) throws -> String {
        guard let value = object[key] as? String, !value.isEmpty else {
            throw BillowVPNError.make(.configurationMissing, "\(key) is required")
        }
        return value
    }

    private static func statusDictionary(_ status: ProviderStatus) -> [String: Any] {
        [
            "extensionId": status.extensionId,
            "engine": status.engine,
            "embeddedVersion": status.embeddedVersion.map { $0 as Any } ?? NSNull(),
            "running": status.running,
            "version": status.version.map { $0 as Any } ?? NSNull(),
            "loopbackPort": status.loopbackPort.map { $0 as Any } ?? NSNull(),
            "loopbackListen": status.loopbackListen.map { $0 as Any } ?? NSNull(),
            "lastError": status.lastError.map { $0 as Any } ?? NSNull(),
            "errorCode": status.errorCode.map { $0 as Any } ?? NSNull(),
            "startedAt": status.startedAt.map { ISO8601DateFormatter().string(from: $0) as Any } ?? NSNull(),
        ]
    }

    private static func success(_ data: Any) -> [String: Any] {
        ["ok": true, "data": data]
    }

    private static func errorResponse(_ error: Error) -> [String: Any] {
        let ns = error as NSError
        let code = ns.domain == BillowVPNError.domain
            ? ns.code
            : BillowVPNError.classify(error).rawValue
        return [
            "ok": false,
            "error": [
                "code": code,
                "message": ns.localizedDescription,
                "domain": ns.domain,
            ],
        ]
    }

    private static func encode(_ object: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: object),
              let text = String(data: data, encoding: .utf8) else {
            return #"{"ok":false,"error":{"code":0,"message":"response encoding failed","domain":"app.billow.client.vpn"}}"#
        }
        return text
    }
}
