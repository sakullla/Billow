import { createHash, randomUUID } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { writeFile, mkdir, stat, copyFile, rename, rm } from 'node:fs/promises'
import { resolve } from 'node:path'
import { Transform, Writable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { promisify } from 'node:util'
import { brotliCompress, createBrotliDecompress, constants, gunzipSync } from 'node:zlib'
import { unzipSync } from 'fflate'

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')
const compress = promisify(brotliCompress)

// Repack the verified executable bytes, preserving platform signatures exactly.
export function kernelBytes(asset, archive) {
  if (asset.endsWith('.gz')) return gunzipSync(archive)
  if (asset.endsWith('.zip')) {
    const files = unzipSync(archive, { filter: file => file.name.toLowerCase().endsWith('.exe') })
    const entries = Object.entries(files)
    if (entries.length !== 1) throw new Error('Expected exactly one executable in bundled kernel archive')
    const bytes = entries[0][1]
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  }
  throw new Error('Unsupported bundled kernel archive')
}

async function verifiedCache(path, expectedSize, expectedHash) {
  const packedHash = createHash('sha256')
  const rawHash = createHash('sha256')
  let size = 0
  let rawSize = 0
  try {
    await pipeline(
      createReadStream(path),
      new Transform({ transform(chunk, _encoding, done) {
        size += chunk.length
        packedHash.update(chunk)
        done(null, chunk)
      } }),
      createBrotliDecompress({ chunkSize: 64 * 1024 }),
      new Writable({ write(chunk, _encoding, done) {
        rawSize += chunk.length
        if (rawSize > expectedSize) return done(new Error('Cached resource exceeds expected size'))
        rawHash.update(chunk)
        done()
      } }),
    )
    if (rawSize !== expectedSize || rawHash.digest('hex') !== expectedHash) return null
    return { size, sha256: packedHash.digest('hex') }
  } catch { return null }
}

async function matchesFile(path, expected) {
  try {
    if ((await stat(path)).size !== expected.size) return false
    const hash = createHash('sha256')
    for await (const chunk of createReadStream(path)) hash.update(chunk)
    return hash.digest('hex') === expected.sha256
  } catch { return false }
}

async function replaceFile(path, write) {
  const temporary = `${path}.${randomUUID()}.tmp`
  try {
    await write(temporary)
    await rename(temporary, path)
  } finally {
    await rm(temporary, { force: true })
  }
}

export async function packResource(bytes, name, target, cache) {
  if (!bytes.length) throw new Error(`Empty bundled resource: ${name}`)
  const rawSha = sha256(bytes)
  await mkdir(cache, { recursive: true })
  await mkdir(target, { recursive: true })
  const cached = resolve(cache, `${rawSha}.br`)
  // Hash decoded chunks rather than allocating another entire executable on cache hits.
  let packed = await verifiedCache(cached, bytes.length, rawSha)
  if (!packed) {
    console.log(`Compressing ${name} (${(bytes.length / 1048576).toFixed(1)} MiB)`)
    const encoded = await compress(bytes, { params: {
      [constants.BROTLI_PARAM_QUALITY]: 11,
      [constants.BROTLI_PARAM_SIZE_HINT]: bytes.length,
    } })
    packed = { size: encoded.length, sha256: sha256(encoded) }
    await replaceFile(cached, path => writeFile(path, encoded))
  }
  const file = `${name}.br`
  const destination = resolve(target, file)
  // Keep unchanged outputs (and their mtimes); repair damage atomically.
  if (!await matchesFile(destination, packed)) {
    await replaceFile(destination, path => copyFile(cached, path))
  }
  return { file, sha256: packed.sha256, size: packed.size, unpacked_sha256: rawSha, unpacked_size: bytes.length }
}
