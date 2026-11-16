const { execFileSync } = require('node:child_process')
const { readFileSync, mkdtempSync, createReadStream } = require('node:fs')
const { join } = require('node:path')
const { createHash } = require('node:crypto')
const { verifyMacosManifest } = require('./prebuilt-macos.cjs')

async function main() {
  const version = process.env.RELEASE_VERSION
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('Invalid release version')
  const tag = `v${version}`
  const repo = process.env.GITHUB_REPOSITORY
  const release = JSON.parse(execFileSync('gh', ['api', `repos/${repo}/releases/${process.env.RELEASE_ID}`], { encoding: 'utf8' }))
  if (!release.draft || release.tag_name !== tag || release.target_commitish !== process.env.RELEASE_SHA) throw new Error('Recovery only signs the matching verified draft')
  const directory = mkdtempSync(join(process.env.RUNNER_TEMP, 'billow-macos-sign-'))
  const manifestName = `Billow_${version}_macos-build.json`
  const download = name => execFileSync('gh', ['release', 'download', tag, '--repo', repo, '--pattern', name, '--dir', directory], { stdio: 'inherit' })
  download(manifestName)
  const files = verifyMacosManifest(readFileSync(join(directory, manifestName)), {
    version, commit: process.env.RELEASE_SHA, expectedHash: process.env.MACOS_MANIFEST_SHA256,
  })
  for (const file of files) {
    download(file.name)
    const hash = createHash('sha256')
    for await (const chunk of createReadStream(join(directory, file.name))) hash.update(chunk)
    if (hash.digest('hex') !== file.sha256) throw new Error(`macOS artifact checksum mismatch: ${file.name}`)
  }
  const archive = join(directory, files[0].name)
  // The key remains in GitHub Secrets; only the version-bound signature is uploaded.
  execFileSync('npx', ['tauri', 'signer', 'sign', '--app-version', version, archive], { stdio: 'inherit' })
  execFileSync('gh', ['release', 'upload', tag, `${archive}.sig`, '--repo', repo, '--clobber'], { stdio: 'inherit' })
}
main().catch(error => { console.error(error.message); process.exitCode = 1 })
