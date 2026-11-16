import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { downloadBytes } from './build_download.mjs'

// First launch must not need a working proxy to download its routing databases.
const root = fileURLToPath(new URL('../', import.meta.url))

export async function prepareGeo(target) {
  const manifest = JSON.parse(await readFile(resolve(root, 'src-tauri/android-geo.json'), 'utf8'))
  const headers = { 'User-Agent': 'Billow-build' }
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN
  if (token) headers.Authorization = `Bearer ${token}`
  const revision = await downloadBytes(`https://api.github.com/repos/${manifest.repository}/commits/${manifest.ref}`, { headers, timeout: 30000 })
  const commit = JSON.parse(revision).sha
  if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error('Invalid GEO revision')
  const provenance = { repository: manifest.repository, commit, fetchedAt: new Date().toISOString(), files: [] }
  await mkdir(target, { recursive: true })
  const sha = bytes => createHash('sha256').update(bytes).digest('hex')
  for (const entry of manifest.files) {
    // Resolve the latest revision on every build, then use one immutable snapshot.
    const url = `https://raw.githubusercontent.com/${manifest.repository}/${commit}/${entry.source}`
    const checksum = await downloadBytes(`${url}.sha256sum`, { timeout: 30000 })
    const expected = checksum.toString().trim().split(/\s+/)[0]
    if (!/^[a-f0-9]{64}$/.test(expected)) throw new Error(`Invalid GEO checksum: ${entry.name}`)
    const path = resolve(target, entry.name)
    let bytes = await readFile(path).catch(() => null)
    if (!bytes || sha(bytes) !== expected) {
      console.log(`Downloading bundled ${entry.name}`)
      bytes = await downloadBytes(url)
      if (sha(bytes) !== expected) throw new Error(`GEO checksum mismatch: ${entry.name}`)
      await writeFile(path, bytes)
    }
    provenance.files.push({ ...entry, sha256: expected })
    console.log(`Verified bundled ${entry.name}`)
  }
  await writeFile(resolve(target, 'build.json'), JSON.stringify(provenance, null, 2))
}
