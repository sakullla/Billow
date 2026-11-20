// Reads the shipped-kernel manifests. The desktop manifest pins release binaries per target and
// the Android manifest pins the source commit, archive checksum, Go toolchain and build tags.
import { readFile, mkdir, writeFile, rename } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

export const repoRoot = fileURLToPath(new URL('../../', import.meta.url))
export const desktopManifestPath = resolve(repoRoot, 'src-tauri/desktop-kernel.json')
export const androidManifestPath = resolve(repoRoot, 'src-tauri/android-kernel.json')

const sha256Pattern = /^[0-9a-f]{64}$/
const assetVersionPattern = /-v(\d+\.\d+\.\d+)\.(gz|zip)$/

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

export async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'))
}

export function platformKey() {
  return {
    darwin: 'darwin',
    win32: 'windows',
    linux: 'linux',
  }[process.platform] ?? process.platform
}

export function architectureKey() {
  return {
    arm64: 'aarch64',
    x64: 'x86_64',
    ia32: 'i686',
    arm: 'armv7',
  }[process.arch] ?? process.arch
}

export function currentTarget() {
  return `${platformKey()}-${architectureKey()}`
}

// Lists targets that ship a binary for a platform, so callers can distinguish "not packaged"
// from "packaged but unverified on this machine".
export function platformTargets(desktop, platform) {
  return Object.entries(desktop.targets ?? {})
    .filter(([target]) => target.startsWith(`${platform}-`))
    .map(([target, entry]) => ({ target, ...entry }))
}

// Validates the two manifests against each other: the versions must agree, every desktop
// asset name must carry the pinned version, checksums must be full SHA-256 digests, and
// Android build tags must be non-empty. Unresolved facts are returned instead of thrown.
export function checkManifests(desktop, android) {
  const errors = []
  const notes = []
  if (!/^v\d+\.\d+\.\d+$/.test(desktop.version ?? '')) errors.push('desktop manifest version is not a release tag')
  if (desktop.version !== android.version) errors.push(`desktop version ${desktop.version} differs from Android version ${android.version}`)
  const targets = Object.entries(desktop.targets ?? {})
  if (targets.length === 0) errors.push('desktop manifest declares no targets')
  for (const [target, entry] of targets) {
    if (!sha256Pattern.test(entry.sha256 ?? '')) errors.push(`desktop target ${target} has an invalid sha256`)
    const match = assetVersionPattern.exec(entry.asset ?? '')
    if (!match) errors.push(`desktop target ${target} asset name carries no version`)
    else if (match[1] !== desktop.version.slice(1)) errors.push(`desktop target ${target} asset version ${match[1]} differs from ${desktop.version}`)
  }
  if (!sha256Pattern.test(android.sha256 ?? '')) errors.push('android manifest has an invalid source sha256')
  if (!/^[0-9a-f]{40}$/.test(android.commit ?? '')) errors.push('android manifest commit is not a full revision')
  if (!/^go\d+\.\d+(\.\d+)?$/.test(android.goVersion ?? '')) errors.push('android manifest goVersion is missing')
  if (!Array.isArray(android.tags) || android.tags.length === 0) errors.push('android manifest declares no build tags')
  notes.push('desktop manifest pins only binary assets; the source commit and source checksum for the desktop release are undeclared and are recorded from the first verified download')
  notes.push('desktop manifest lists targets beyond the current release matrix; only packaged targets are compatibility claims')
  return {
    ok: errors.length === 0,
    errors,
    notes,
    versions: { desktop: desktop.version, android: android.version },
    sharedVersion: desktop.version === android.version ? desktop.version : null,
    androidTags: android.tags ?? [],
    desktopSourceCommit: null,
    targets: targets.map(([target, entry]) => ({ target, asset: entry.asset, sha256: entry.sha256 })),
  }
}

export async function readManifests() {
  const desktop = await readJson(desktopManifestPath)
  const android = await readJson(androidManifestPath)
  return { desktop, android, check: checkManifests(desktop, android) }
}

export async function ensureDir(path) {
  await mkdir(path, { recursive: true })
  return path
}

// Writes atomically so an interrupted run never leaves a truncated cached archive behind.
export async function writeAtomic(path, bytes) {
  const temp = `${path}.${process.pid}.tmp`
  await ensureDir(dirname(path))
  await writeFile(temp, bytes)
  await rename(temp, path)
  return path
}

// Downloads one URL into a cache path and returns the observed checksum. A cached file is
// re-hashed first; a mismatching cache is replaced rather than trusted.
export async function fetchVerified(url, cachePath, expectedSha256, { timeoutMs = 300000 } = {}) {
  const existing = await readFile(cachePath).catch(() => null)
  if (existing && sha256(existing) === expectedSha256) {
    return { path: cachePath, sha256: expectedSha256, cached: true, bytes: existing.length }
  }
  const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
  if (!response.ok) throw new Error(`download failed for ${url}: HTTP ${response.status}`)
  const bytes = Buffer.from(await response.arrayBuffer())
  const digest = sha256(bytes)
  if (expectedSha256 && digest !== expectedSha256) throw new Error(`checksum mismatch for ${url}: expected ${expectedSha256}, got ${digest}`)
  await writeAtomic(cachePath, bytes)
  return { path: cachePath, sha256: digest, cached: false, bytes: bytes.length }
}

export const defaultCacheDir = resolve(repoRoot, 'tool/kernel-compat/.cache')
