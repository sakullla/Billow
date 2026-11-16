import { createHash } from 'node:crypto'
import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'
import { brotliCompressSync, brotliDecompressSync, constants, gunzipSync } from 'node:zlib'
import { unzipSync } from 'fflate'

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')

// Repack the verified executable bytes, preserving platform signatures exactly.
export function kernelBytes(asset, archive) {
  if (asset.endsWith('.gz')) return gunzipSync(archive)
  if (asset.endsWith('.zip')) {
    const files = unzipSync(archive, { filter: file => file.name.toLowerCase().endsWith('.exe') })
    const entries = Object.entries(files)
    if (entries.length !== 1) throw new Error('Expected exactly one executable in bundled kernel archive')
    return Buffer.from(entries[0][1])
  }
  throw new Error('Unsupported bundled kernel archive')
}

export async function packResource(bytes, name, target, cache) {
  if (!bytes.length) throw new Error(`Empty bundled resource: ${name}`)
  const rawSha = sha256(bytes)
  await mkdir(cache, { recursive: true })
  await mkdir(target, { recursive: true })
  const cached = resolve(cache, `${rawSha}.br`)
  let packed = await readFile(cached).catch(() => null)
  if (packed) {
    try {
      if (!brotliDecompressSync(packed, { maxOutputLength: bytes.length }).equals(bytes)) packed = null
    } catch { packed = null }
  }
  if (!packed) {
    console.log(`Compressing ${name} (${(bytes.length / 1048576).toFixed(1)} MiB)`)
    packed = brotliCompressSync(bytes, { params: {
      [constants.BROTLI_PARAM_QUALITY]: 11,
      [constants.BROTLI_PARAM_SIZE_HINT]: bytes.length,
    } })
    await writeFile(cached, packed)
  }
  const file = `${name}.br`
  await writeFile(resolve(target, file), packed)
  return { file, sha256: sha256(packed), size: packed.length, unpacked_sha256: rawSha, unpacked_size: bytes.length }
}
