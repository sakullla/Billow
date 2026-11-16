const { createHash } = require('node:crypto')

function verifyMacosManifest(bytes, { expectedHash, version, commit }) {
  if (!/^[a-f0-9]{64}$/.test(expectedHash) || createHash('sha256').update(bytes).digest('hex') !== expectedHash) throw new Error('macOS build manifest checksum mismatch')
  const manifest = JSON.parse(bytes)
  if (manifest.version !== version || manifest.sourceCommit !== commit || manifest.architecture !== 'aarch64') throw new Error('macOS build source, version or architecture mismatch')
  if (manifest.nativeChecks?.sourceClean !== true || manifest.nativeChecks?.codesign !== true || manifest.nativeChecks?.offlineKernel !== true) throw new Error('Native macOS verification is incomplete')
  const files = [`Billow_${version}_aarch64.app.tar.gz`, `Billow_${version}_aarch64.dmg`]
  if (Object.keys(manifest.files ?? {}).length !== files.length || files.some(name => !/^[a-f0-9]{64}$/.test(manifest.files[name] ?? ''))) throw new Error('Invalid macOS artifact checksums')
  return files.map(name => ({ name, sha256: manifest.files[name] }))
}

module.exports = { verifyMacosManifest }
