import CryptoKit
import Foundation

/// Versioned resources shared by the host and both extensions.
///
///   <AppGroup>/
///     current.json                        { "active": "<version>" }
///     versions/<version>/manifest.json    see SharedManifest
///     versions/<version>/config.yaml      patched engine config (no secrets)
///     versions/<version>/<assets...>      geo (mmdb/mrs/dat) and any file the
///                                         config references by relative path
///     status/<engine>.json                last start/stop result per extension
///
/// The host copies a staging directory, writes manifest.json with the size and
/// SHA-256 of every file, validates everything and only then switches
/// current.json. An extension validates the active version before it starts
/// and never deletes the version it is running.
enum AppGroupLayout {
    static let currentFile = "current.json"
    static let manifestFile = "manifest.json"
    static let versionsDir = "versions"
    static let configFile = "config.yaml"

    /// NETunnelProviderProtocol.providerConfiguration keys.
    static let groupKey = "appGroup"
    static let versionKey = "configVersion"
    static let extensionKey = "extensionId"
}

struct SharedManifest: Codable {
    struct FileEntry: Codable {
        let sha256: String
        let size: Int
    }

    struct Options: Codable {
        var logLevel: String?
        var loopbackListen: String?
        var loopbackFraction: Double?
        /// Recorded geo asset names (informational).
        var geo: [String: String]?
    }

    var version: String
    /// Engines able to consume this resource set ("mihomo", "rust").
    var engines: [String]
    var appVersion: String?
    var createdAt: String?
    var files: [String: FileEntry]
    var options: Options?
}

struct ActiveVersionRecord: Codable {
    var active: String
}

enum AppGroupError: Int, Error, CustomStringConvertible {
    case missingGroup = 1
    case missingVersion = 2
    case corruptManifest = 3
    case fileMismatch = 4
    case engineMismatch = 5
    case hostNotReady = 6

    var description: String {
        switch self {
        case .missingGroup: return "App Group container is not available (entitlement missing?)"
        case .missingVersion: return "No prepared resource version (current.json missing)"
        case .corruptManifest: return "manifest.json is missing or invalid"
        case .fileMismatch: return "A resource file failed size or SHA-256 validation"
        case .engineMismatch: return "The resource set was not prepared for this engine"
        case .hostNotReady: return "The host did not provide a configuration"
        }
    }

    var nsError: NSError {
        NSError(domain: BillowVPNError.domain, code: rawValue, userInfo: [NSLocalizedDescriptionKey: description])
    }
}

final class AppGroupStore {
    let groupId: String
    let rootURL: URL
    private let fm = FileManager.default

    init?(groupId: String) {
        guard let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupId) else {
            return nil
        }
        self.groupId = groupId
        self.rootURL = url
    }

    var currentURL: URL { rootURL.appendingPathComponent(AppGroupLayout.currentFile) }
    var versionsURL: URL { rootURL.appendingPathComponent(AppGroupLayout.versionsDir) }

    func versionURL(_ version: String) -> URL {
        versionsURL.appendingPathComponent(version, isDirectory: true)
    }

    func activeVersion() throws -> String {
        guard let data = try? Data(contentsOf: currentURL),
              let record = try? JSONDecoder().decode(ActiveVersionRecord.self, from: data),
              !record.active.isEmpty,
              fm.fileExists(atPath: versionURL(record.active).path)
        else {
            throw AppGroupError.missingVersion
        }
        return record.active
    }

    /// Validates manifest.json and every listed file. Returns the manifest and
    /// the version directory.
    func validatedResources(_ version: String, expectedEngine: String) throws -> (SharedManifest, URL) {
        let dir = versionURL(version)
        let manifestURL = dir.appendingPathComponent(AppGroupLayout.manifestFile)
        guard let data = try? Data(contentsOf: manifestURL),
              let manifest = try? JSONDecoder().decode(SharedManifest.self, from: data)
        else {
            throw AppGroupError.corruptManifest
        }
        guard manifest.version == version else { throw AppGroupError.corruptManifest }
        guard manifest.engines.contains(expectedEngine) else { throw AppGroupError.engineMismatch }
        for (path, entry) in manifest.files {
            let fileURL = dir.appendingPathComponent(path)
            guard let attrs = try? fm.attributesOfItem(atPath: fileURL.path),
                  let size = attrs[.size] as? Int, size == entry.size,
                  let digest = try? FileDigest.sha256Hex(fileURL),
                  digest.caseInsensitiveCompare(entry.sha256) == .orderedSame
            else {
                throw AppGroupError.fileMismatch
            }
        }
        return (manifest, dir)
    }

    /// Copies `stagedDir` to versions/<version>, writes and validates the
    /// manifest, then activates it. Everything is written before current.json
    /// changes, so a failure leaves the previous version active.
    @discardableResult
    func prepareVersion(version: String, stagedDir: URL, engines: [String], options: SharedManifest.Options?,
                        appVersion: String?) throws -> SharedManifest {
        guard !version.isEmpty, !version.contains("/"), !version.contains("..") else {
            throw AppGroupError.corruptManifest
        }
        let files = try listedFiles(stagedDir)
        guard files[AppGroupLayout.configFile] != nil else {
            throw AppGroupError.corruptManifest
        }
        let manifest = SharedManifest(
            version: version,
            engines: engines,
            appVersion: appVersion,
            createdAt: ISO8601DateFormatter().string(from: Date()),
            files: files,
            options: options
        )
        let target = versionURL(version)
        try? fm.removeItem(at: target)
        try fm.createDirectory(at: versionsURL, withIntermediateDirectories: true)
        try fm.copyItem(at: stagedDir, to: target)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(manifest).write(to: target.appendingPathComponent(AppGroupLayout.manifestFile),
                                           options: .atomic)
        for engine in engines {
            _ = try validatedResources(version, expectedEngine: engine)
        }
        try JSONEncoder().encode(ActiveVersionRecord(active: version)).write(to: currentURL, options: .atomic)
        return manifest
    }

    /// Removes every version except the active one and those listed in
    /// `keeping` (for example a version a running tunnel still reports).
    func prune(keeping: [String]) {
        let active = (try? activeVersion()) ?? ""
        let keep = Set(keeping + [active])
        guard let entries = try? fm.contentsOfDirectory(at: versionsURL, includingPropertiesForKeys: nil) else {
            return
        }
        for entry in entries where !keep.contains(entry.lastPathComponent) {
            try? fm.removeItem(at: entry)
        }
    }

    /// Status file written by an extension at start/stop.
    func readStatus(engine: String) -> ProviderStatus? {
        let url = rootURL.appendingPathComponent("status/\(engine).json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(ProviderStatus.self, from: data)
    }

    private func listedFiles(_ stagedDir: URL) throws -> [String: SharedManifest.FileEntry] {
        var result: [String: SharedManifest.FileEntry] = [:]
        let base = stagedDir.standardizedFileURL.path
        guard let walker = fm.enumerator(at: stagedDir,
                                         includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey]) else {
            return result
        }
        for case let url as URL in walker {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
            guard values.isRegularFile == true else { continue }
            let path = url.standardizedFileURL.path
            guard path.hasPrefix(base + "/") else { continue }
            let relative = String(path.dropFirst(base.count + 1))
            if relative == AppGroupLayout.manifestFile { continue }
            result[relative] = SharedManifest.FileEntry(sha256: try FileDigest.sha256Hex(url),
                                                        size: values.fileSize ?? 0)
        }
        return result
    }
}

enum FileDigest {
    static func sha256Hex(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1 << 20) ?? Data()
            if chunk.isEmpty {
                break
            }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
