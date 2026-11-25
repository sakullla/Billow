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

    convenience init?(groupId: String) {
        guard let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupId) else {
            return nil
        }
        self.init(rootURL: url, groupId: groupId)
    }

    /// Testable root: the packaging smoke (`tool/ios/verify-app-group.sh`)
    /// validates the manifest merge without a signed App Group entitlement.
    init(rootURL: URL, groupId: String) {
        self.groupId = groupId
        self.rootURL = rootURL
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

    /// Copies `stagedDir` over versions/<version>, merges the engine list with
    /// the existing manifest, writes and validates the manifest, then
    /// activates it. Everything is written before current.json changes, so a
    /// failure leaves the previous version active.
    ///
    /// The directory is merged instead of removed: the host prepares one
    /// version and both packet-tunnel extensions must validate the same
    /// `versions/<version>` tree. Preparing for the second engine therefore
    /// keeps the first engine in `manifest.engines` and keeps any file the
    /// other engine needs.
    @discardableResult
    func prepareVersion(version: String, stagedDir: URL, engines: [String], options: SharedManifest.Options?,
                        appVersion: String?) throws -> SharedManifest {
        guard !version.isEmpty, !version.contains("/"), !version.contains("..") else {
            throw AppGroupError.corruptManifest
        }
        let stagedFiles = try listedFiles(stagedDir)
        guard stagedFiles[AppGroupLayout.configFile] != nil else {
            throw AppGroupError.corruptManifest
        }
        let target = versionURL(version)
        try fm.createDirectory(at: versionsURL, withIntermediateDirectories: true)
        try fm.createDirectory(at: target, withIntermediateDirectories: true)
        try mergeContents(of: stagedDir, into: target)
        // Re-hash whatever is now in the version directory: the merged tree
        // may contain files from an earlier prepare for the other engine.
        let files = try listedFiles(target)
        var merged = engines
        if let data = try? Data(contentsOf: target.appendingPathComponent(AppGroupLayout.manifestFile)),
           let existing = try? JSONDecoder().decode(SharedManifest.self, from: data) {
            for engine in existing.engines where !merged.contains(engine) {
                merged.append(engine)
            }
        }
        let manifest = SharedManifest(
            version: version,
            engines: merged,
            appVersion: appVersion,
            createdAt: ISO8601DateFormatter().string(from: Date()),
            files: files,
            options: options
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(manifest).write(to: target.appendingPathComponent(AppGroupLayout.manifestFile),
                                           options: .atomic)
        for engine in merged {
            _ = try validatedResources(version, expectedEngine: engine)
        }
        try JSONEncoder().encode(ActiveVersionRecord(active: version)).write(to: currentURL, options: .atomic)
        return manifest
    }

    /// Copies every file from `source` into `destination`, replacing files but
    /// leaving destination-only files in place (they belong to the other
    /// engine's view of the same version).
    private func mergeContents(of source: URL, into destination: URL) throws {
        let keys: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey]
        guard let walker = fm.enumerator(at: source, includingPropertiesForKeys: keys) else {
            return
        }
        let base = source.standardizedFileURL.path
        for case let url as URL in walker {
            let values = try url.resourceValues(forKeys: Set(keys))
            let path = url.standardizedFileURL.path
            guard path.hasPrefix(base + "/") else { continue }
            let relative = String(path.dropFirst(base.count + 1))
            if relative == AppGroupLayout.manifestFile { continue }
            let target = destination.appendingPathComponent(relative)
            if values.isDirectory == true {
                try fm.createDirectory(at: target, withIntermediateDirectories: true)
                continue
            }
            guard values.isRegularFile == true else { continue }
            try fm.createDirectory(at: target.deletingLastPathComponent(),
                                   withIntermediateDirectories: true)
            if fm.fileExists(atPath: target.path) {
                try fm.removeItem(at: target)
            }
            try fm.copyItem(at: url, to: target)
        }
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
        return ProviderSupport.decodeStatus(data)
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
