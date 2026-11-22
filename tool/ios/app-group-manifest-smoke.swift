// Smoke for the shared App Group resource layout: one version must be
// prepared and validated for both extensions, and a later prepare for one
// engine must not revoke the other engine's manifest entry.
//
// Built and run by tool/ios/verify-app-group.sh with the real
// Shared/AppGroupStore.swift and Shared/ProviderSupport.swift sources.

import Foundation

func check(_ condition: @autoclosure () -> Bool, _ message: String) {
    guard condition() else {
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
        exit(1)
    }
}

@main
enum ManifestSmoke {
    static func main() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("billow-app-group-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = AppGroupStore(rootURL: root, groupId: "group.test")

        func stage(_ name: String, files: [String: Data]) throws -> URL {
            let dir = root.appendingPathComponent(name, isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            for (path, data) in files {
                let url = dir.appendingPathComponent(path)
                try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                        withIntermediateDirectories: true)
                try data.write(to: url)
            }
            return dir
        }

        let config = "mixed-port: 17890\ntun:\n  enable: true\nrules:\n  - MATCH,DIRECT\n".data(using: .utf8)!
        let geo = Data(repeating: 7, count: 128)

        let first = try stage("stage-mihomo", files: ["config.yaml": config, "Country.mmdb": geo])
        let second = try stage("stage-rust", files: ["config.yaml": config, "rules/ads.mrs": Data("mrs".utf8)])

        let one = try store.prepareVersion(version: "v1", stagedDir: first, engines: ["mihomo"],
                                           options: nil, appVersion: "smoke")
        check(one.engines == ["mihomo"], "first prepare names mihomo")
        let two = try store.prepareVersion(version: "v1", stagedDir: second, engines: ["rust"],
                                           options: nil, appVersion: "smoke")
        check(two.engines.sorted() == ["mihomo", "rust"], "second prepare keeps both engines: \(two.engines)")

        // Each engine validates the same tree, and files from the first prepare stay.
        _ = try store.validatedResources("v1", expectedEngine: "mihomo")
        _ = try store.validatedResources("v1", expectedEngine: "rust")
        let versionDir = store.versionURL("v1")
        check(FileManager.default.fileExists(atPath: versionDir.appendingPathComponent("Country.mmdb").path),
              "first engine's asset survives the second prepare")
        let active = try store.activeVersion()
        check(active == "v1", "v1 is active")

        // A third prepare for mihomo must still keep rust in the manifest.
        let third = try store.prepareVersion(version: "v1", stagedDir: first, engines: ["mihomo"],
                                             options: nil, appVersion: "smoke")
        check(third.engines.sorted() == ["mihomo", "rust"], "repeat prepare keeps both engines")
        _ = try store.validatedResources("v1", expectedEngine: "rust")

        // A missing file is still a named validation failure.
        try Data("broken".utf8).write(to: versionDir.appendingPathComponent("Country.mmdb"))
        do {
            _ = try store.validatedResources("v1", expectedEngine: "mihomo")
            check(false, "corrupted file must fail validation")
        } catch let error as AppGroupError {
            if case .fileMismatch = error {
                // expected
            } else {
                check(false, "corruption is fileMismatch, got \(error)")
            }
        }

        print("ok: one version validates for mihomo and rust; later prepares preserve both")
    }
}
