import Foundation

/// Prepares a versioned resource set in the App Group, validates it with the
/// same code the extensions use and switches current.json atomically.
///
/// Flow used by the host (settings "offline prepare"):
///  1. write config.yaml + geo/rule assets into a staging directory (outside
///     the App Group, e.g. the app's caches), rewriting external paths to
///     files that will be copied alongside;
///  2. `prepare(version:engines:stagedDir:)` merges the staging directory into
///     versions/<version>, hashes every file into manifest.json, validates every
///     engine and activates it. The previous version stays until `prune`, and a
///     later prepare keeps the union of engines so both extensions can validate
///     the same tree.
///  3. connect with `requestedVersion:`; the extension validates again before
///     it starts the engine.
final class ResourcesInstaller {
    let store: AppGroupStore
    private let log = BillowLog("host-resources")

    init(groupId: String = "group.app.billow.client") {
        guard let store = AppGroupStore(groupId: groupId) else {
            // Without the App Group entitlement (unsigned builds) resources
            // cannot be shared; fail on first use instead of crashing.
            fatalError("App Group \(groupId) unavailable: check the App Group entitlement")
        }
        self.store = store
    }

    @discardableResult
    func prepare(version: String, engine: BillowVPNManager.Engine, stagedDir: URL,
                 appVersion: String? = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) throws -> SharedManifest {
        try prepare(version: version, engines: [engine], stagedDir: stagedDir, appVersion: appVersion)
    }

    /// Prepares one version for every supplied engine. The manifest keeps the
    /// union of the engines seen for that version, so a later prepare for a
    /// single engine never revokes the other engine's `validatedResources`.
    @discardableResult
    func prepare(version: String, engines: [BillowVPNManager.Engine], stagedDir: URL,
                 appVersion: String? = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) throws -> SharedManifest {
        let names = engines.map(\.rawValue)
        let manifest = try store.prepareVersion(version: version,
                                                stagedDir: stagedDir,
                                                engines: names,
                                                options: nil,
                                                appVersion: appVersion)
        log.info("prepared \(names.joined(separator: ",")) resources \(version) (\(manifest.files.count) files, engines \(manifest.engines.joined(separator: ",")))")
        return manifest
    }

    func activeVersion() throws -> String {
        try store.activeVersion()
    }

    /// Removes versions other than the active one and those the caller still
    /// needs (for example a running tunnel's version).
    func prune(keeping: [String]) {
        store.prune(keeping: keeping)
    }
}
