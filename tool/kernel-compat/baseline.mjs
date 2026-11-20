#!/usr/bin/env node
// Resolves the locked Mihomo baseline for this machine from the repository manifests:
// downloads the desktop release asset named by the manifest, verifies its pinned checksum,
// extracts the executable to a content-addressed cache path, and checks that the binary
// reports the manifest version. The cache holds only release artifacts, never source trees.
import { gunzipSync, inflateRawSync } from 'node:zlib'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { chmod, readFile, stat } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { defaultCacheDir, currentTarget, ensureDir, fetchVerified, readManifests, sha256, writeAtomic } from './manifest.mjs'

const run = promisify(execFile)

function parseArgs(argv) {
  const options = { cacheDir: defaultCacheDir, json: false }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--json') options.json = true
    else if (arg === '--cache') options.cacheDir = resolve(argv[++index])
    else if (arg === '--target') options.target = argv[++index]
    else throw new Error(`unknown argument ${arg}`)
  }
  return options
}

// Extracts the executable payload of a release archive (.gz or .zip). Zip entries are located
// through the central directory rather than guessed filenames.
export function extractBinary(asset, bytes) {
  if (asset.endsWith('.gz')) return gunzipSync(bytes)
  if (!asset.endsWith('.zip')) throw new Error(`${asset}: unsupported archive format`)
  const end = bytes.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]))
  if (end < 0) throw new Error(`${asset}: zip end record missing`)
  const count = bytes.readUInt16LE(end + 10)
  let offset = bytes.readUInt32LE(end + 16)
  let binary = null
  for (let entry = 0; entry < count; entry += 1) {
    if (bytes.readUInt32LE(offset) !== 0x02014b50) throw new Error(`${asset}: zip central directory corrupt`)
    const method = bytes.readUInt16LE(offset + 10)
    const compressed = bytes.readUInt32LE(offset + 20)
    const nameLength = bytes.readUInt16LE(offset + 28)
    const extraLength = bytes.readUInt16LE(offset + 30)
    const commentLength = bytes.readUInt16LE(offset + 32)
    const localOffset = bytes.readUInt32LE(offset + 42)
    const name = bytes.subarray(offset + 46, offset + 46 + nameLength).toString('utf8')
    const payloadStart = localOffset + 30 + bytes.readUInt16LE(localOffset + 26) + bytes.readUInt16LE(localOffset + 28)
    const payload = bytes.subarray(payloadStart, payloadStart + compressed)
    if (/(^|\/)(mihomo|mihomo\.exe)$/.test(name)) {
      if (method === 0) binary = payload
      else if (method === 8) binary = inflateRawSync(payload)
      else throw new Error(`${asset}: unsupported compression method ${method}`)
    }
    offset += 46 + nameLength + extraLength + commentLength
  }
  if (!binary) throw new Error(`${asset}: mihomo executable not found`)
  return binary
}

// Materializes the executable next to the cache under a content-addressed name so repeated
// runs reuse the same path and the binary can never be confused with the archive digest.
async function materialize(cacheDir, binary) {
  const path = resolve(cacheDir, 'baseline', `mihomo-${sha256(binary).slice(0, 12)}`)
  const existing = await readFile(path).catch(() => null)
  if (!existing || sha256(existing) !== sha256(binary)) {
    await writeAtomic(path, binary)
    await chmod(path, 0o755)
  }
  return path
}

export async function resolveBaseline({ cacheDir = defaultCacheDir, target = currentTarget() } = {}) {
  await ensureDir(resolve(cacheDir, 'baseline'))
  const { desktop, check } = await readManifests()
  if (!check.ok) throw new Error(`kernel manifests are inconsistent: ${check.errors.join('; ')}`)
  const entry = desktop.targets[target]
  if (!entry) {
    const platform = target.split('-')[0]
    return {
      status: 'unavailable',
      target,
      reason: `desktop manifest packages no baseline binary for ${target}`,
      platformTargets: Object.keys(desktop.targets).filter((name) => name.startsWith(`${platform}-`)),
    }
  }
  const archive = await fetchVerified(`https://github.com/${desktop.repository}/releases/download/${desktop.version}/${entry.asset}`,
    resolve(cacheDir, 'baseline', desktop.version, entry.asset), entry.sha256)
  const binary = extractBinary(entry.asset, await readFile(archive.path))
  const path = await materialize(cacheDir, binary)
  let reported = null
  try {
    reported = /^Mihomo Meta (\S+) (\S+ \S+)?/.exec((await run(path, ['-v'], { timeout: 30000 })).stdout) ?? null
  } catch (error) {
    return {
      status: 'unusable',
      target,
      asset: entry.asset,
      archiveSha256: archive.sha256,
      reason: `baseline binary did not start: ${error.message}`,
    }
  }
  const version = reported?.[1] ?? null
  const platform = (reported?.[2] ?? '').trim()
  if (version !== desktop.version) {
    return { status: 'mismatch', target, asset: entry.asset, archiveSha256: archive.sha256, binaryVersion: version, reason: 'pinned binary reports a different version' }
  }
  return {
    status: 'locked',
    engine: 'mihomo',
    target,
    version,
    reportedPlatform: platform,
    asset: entry.asset,
    repository: desktop.repository,
    archiveSha256: archive.sha256,
    manifestSha256: entry.sha256,
    cached: archive.cached,
    binary: path,
    binarySha256: sha256(binary),
    binaryBytes: (await stat(path)).size,
  }
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv)
  const result = await resolveBaseline(options)
  if (options.json) console.log(JSON.stringify(result, null, 2))
  else if (result.status === 'locked') console.log(`Mihomo ${result.version} ${result.target}: ${result.binary}`)
  else console.log(`${result.status}: ${result.reason}`)
  if (result.status !== 'locked') process.exitCode = 2
  return result
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.message)
    process.exitCode = 1
  })
}
