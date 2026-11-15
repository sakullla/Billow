// One writer assembles the updater manifest after every platform has uploaded.
// Exported separately so release completeness and URL checks run in ordinary CI.
export function createManifest(release, signatures, repo, version) {
  if (!release.draft || release.tag_name !== `v${version}`) throw new Error('Expected this version’s draft release')
  const assets = release.assets
  const select = (pattern) => {
    const found = assets.filter((asset) => pattern.test(asset.name))
    if (found.length !== 1 || found[0].size <= 0) throw new Error(`Expected one nonempty asset matching ${pattern}`)
    const asset = found[0]
    const expected = `https://github.com/${repo}/releases/download/v${version}/${asset.name}`
    if (asset.browser_download_url !== expected) throw new Error(`Unexpected asset URL: ${asset.name}`)
    return asset
  }
  select(/_aarch64\.dmg$/)
  select(/_amd64\.deb$/)
  select(/_arm64\.apk$/)
  const platforms = {}
  for (const [targets, pattern] of [
    [['windows-x86_64', 'windows-x86_64-nsis'], /_x64-setup\.exe$/],
    [['linux-x86_64', 'linux-x86_64-appimage'], /_amd64\.AppImage$/],
    [['linux-x86_64-deb'], /_amd64\.deb$/],
    [['darwin-aarch64', 'darwin-aarch64-app'], /_aarch64\.app\.tar\.gz$/],
  ]) {
    const asset = select(pattern)
    const signatureAsset = assets.find((item) => item.name === `${asset.name}.sig`)
    const signature = signatures[signatureAsset?.name]?.trim()
    if (!signatureAsset?.size || !signature || !/^[A-Za-z0-9+/=]+$/.test(signature)) {
      throw new Error(`Missing or invalid update signature: ${asset.name}`)
    }
    for (const target of targets) platforms[target] = { url: asset.browser_download_url, signature }
  }
  return { version, notes: release.body ?? '', pub_date: new Date().toISOString(), platforms }
}
