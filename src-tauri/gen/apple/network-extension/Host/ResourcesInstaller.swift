import Foundation

/// Prepares a versioned resource set in the App Group, validates it with the
/// same code the extensions use and switches current.json atomically.
///
/// Flow used by the host (settings "offline prepare"):
///  1. write config.yaml + geo/rule assets into a staging directory (outside
///     the App Group, e.g. the app's caches), rewriting external paths to
///     files that will be copied alongside;
///  2. `prepare(version:engine:stagedDir:)` copies the staging directory to
///     versions/<version>, hashes every file into manifest.json, validates and
///     activates it. The previous version stays until `prune`.
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
        let manifest = try store.prepareVersion(version: version,
                                                stagedDir: stagedDir,
                                                engine: engine.rawValue,
                                                appVersion: appVersion)
        log.info("prepared \(engine.rawValue) resources \(version) (\(manifest.files.count) files)")
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
