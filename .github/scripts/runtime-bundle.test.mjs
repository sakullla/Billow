import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, writeFile, rm, stat, utimes } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'
import { createHash } from 'node:crypto'
import { desktopTarget, prepareDesktop, RUST_TARGETS } from '../../tool/prepare_desktop_runtime.mjs'
import { downloadBytes } from '../../tool/build_download.mjs'
import { zipSync } from 'fflate'
import { brotliDecompressSync } from 'node:zlib'
import { kernelBytes, packResource } from '../../tool/pack_resource.mjs'

test('interrupted response bodies retry before any artifact is accepted', async () => {
  let calls = 0
  const result = await downloadBytes('https://example.com/archive.gz', {
    retryDelay: 0,
    fetchImpl: async () => ({ ok: true, arrayBuffer: async () => {
      if (++calls < 3) throw new Error('truncated response')
      return Buffer.from('complete')
    } }),
  })
  assert.equal(calls, 3)
  assert.equal(result.toString(), 'complete')
})

test('native target selection does not silently use the build host architecture', () => {
  assert.equal(desktopTarget('darwin', 'aarch64'), 'darwin-aarch64')
  assert.equal(desktopTarget('windows', 'x86_64'), 'windows-x86_64')
  assert.equal(desktopTarget('linux', 'aarch64'), 'linux-aarch64')
  assert.throws(() => desktopTarget('darwin', undefined), /Unsupported/)
  assert.throws(() => desktopTarget('android', 'aarch64'), /Unsupported/)
  assert.equal(RUST_TARGETS['darwin-aarch64'], 'aarch64-apple-darwin')
  assert.equal(RUST_TARGETS['windows-x86_64'], 'x86_64-pc-windows-msvc')
  assert.equal(RUST_TARGETS['linux-x86_64'], 'x86_64-unknown-linux-gnu')
})

test('desktop bundle contains a verified kernel, GEO data and license; corrupt downloads fail the build', async () => {
  const root = await mkdtemp(resolve(tmpdir(), 'billow-runtime-build-'))
  try {
    await mkdir(resolve(root, 'src-tauri'), { recursive: true })
    await mkdir(resolve(root, 'assets/mihomo'), { recursive: true })
    await writeFile(resolve(root, 'assets/mihomo/LICENSE'), 'license')
    const executable = Buffer.from('verified executable fixture')
    const bytes = Buffer.from(zipSync({ 'mihomo.exe': executable, 'LICENSE': Buffer.from('license') }))
    const asset = 'mihomo-windows-amd64-v1.19.34.zip'
    const sha256 = createHash('sha256').update(bytes).digest('hex')
    await writeFile(resolve(root, 'src-tauri/desktop-kernel.json'), JSON.stringify({
      version: 'v1.19.34', repository: 'MetaCubeX/mihomo', targets: { 'windows-x86_64': { asset, sha256 } },
    }))
    let downloads = 0
    const options = {
      root, platform: 'windows', arch: 'x86_64',
      fetchImpl: async url => {
        downloads++
        assert.equal(url, `https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/${asset}`)
        return { ok: true, arrayBuffer: async () => bytes }
      },
      prepareGeoImpl: async dir => {
        await mkdir(dir, { recursive: true })
        await writeFile(resolve(dir, 'GeoSite.dat'), 'geo fixture')
      },
      prepareRustKernelImpl: async ({ bundle: dir, target: name }) => {
        await mkdir(dir, { recursive: true })
        await writeFile(resolve(dir, 'billow-kernel.exe'), 'native fixture')
        await writeFile(resolve(dir, 'rust-kernel.json'), JSON.stringify({ version: '0.1.0', target: name }))
      },
    }
    await prepareDesktop(options)
    const bundle = resolve(root, 'src-tauri/resources/runtime')
    const packed = JSON.parse(await readFile(resolve(bundle, 'kernel.json')))
    assert.equal(packed.asset, asset)
    assert.equal(packed.sha256, sha256)
    assert.equal(packed.packed.unpacked_sha256, createHash('sha256').update(executable).digest('hex'))
    assert.deepEqual(brotliDecompressSync(await readFile(resolve(bundle, 'kernel.br'))), executable)
    await assert.rejects(readFile(resolve(bundle, 'kernel.zip')))
    await assert.rejects(readFile(resolve(bundle, 'kernel.gz')))
    assert.equal(await readFile(resolve(bundle, 'mihomo-LICENSE'), 'utf8'), 'license')
    assert.equal(await readFile(resolve(bundle, 'geo/GeoSite.dat'), 'utf8'), 'geo fixture')
    assert.equal(await readFile(resolve(bundle, 'billow-kernel.exe'), 'utf8'), 'native fixture')
    assert.equal(JSON.parse(await readFile(resolve(bundle, 'rust-kernel.json'))).version, '0.1.0')
    await writeFile(resolve(bundle, 'kernel.br'), 'damaged output')
    await writeFile(resolve(bundle, 'kernel.gz'), 'stale architecture')
    await prepareDesktop(options)
    assert.equal(downloads, 1)
    assert.deepEqual(brotliDecompressSync(await readFile(resolve(bundle, 'kernel.br'))), executable)
    await assert.rejects(readFile(resolve(bundle, 'kernel.gz')))
    await writeFile(resolve(root, 'src-tauri/.runtime-cache', asset), 'damaged cache')
    await assert.rejects(prepareDesktop({ ...options, fetchImpl: async () => ({ ok: true, arrayBuffer: async () => Buffer.from('bad download') }) }), /checksum mismatch/)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('every desktop installer includes runtime resources while Android keeps its APK integration', async () => {
  for (const platform of ['macos', 'windows', 'linux']) {
    const config = JSON.parse(await readFile(new URL(`../../src-tauri/tauri.${platform}.conf.json`, import.meta.url)))
    assert.equal(config.bundle.resources['resources/runtime/'], 'runtime/')
    if (platform === 'windows') assert.equal(config.bundle.resources['../assets/wintun/wintun.dll'], 'wintun.dll')
  }
  const config = JSON.parse(await readFile(new URL('../../src-tauri/tauri.conf.json', import.meta.url)))
  assert.equal(config.bundle.resources, undefined)
})

test('packed resources round trip exactly and repair a corrupted compression cache', async () => {
  const root = await mkdtemp(resolve(tmpdir(), 'billow-packed-build-'))
  try {
    const raw = Buffer.alloc(100_000, 42)
    const output = resolve(root, 'output')
    const cache = resolve(root, 'cache')
    const first = await packResource(raw, 'GeoIP.dat', output, cache)
    assert.ok(first.size < raw.length / 10)
    assert.equal(first.unpacked_size, raw.length)
    assert.deepEqual(brotliDecompressSync(await readFile(resolve(output, first.file))), raw)
    const outputPath = resolve(output, first.file)
    const cachedPath = resolve(cache, `${first.unpacked_sha256}.br`)
    const stamp = new Date('2001-01-01T00:00:00Z')
    await utimes(outputPath, stamp, stamp)
    await utimes(cachedPath, stamp, stamp)
    await packResource(raw, 'GeoIP.dat', output, cache)
    assert.equal((await stat(outputPath)).mtimeMs, stamp.getTime(), 'unchanged outputs must not be rewritten')
    assert.equal((await stat(cachedPath)).mtimeMs, stamp.getTime(), 'verified cache must not be rewritten')
    await writeFile(outputPath, 'damaged output')
    await packResource(raw, 'GeoIP.dat', output, cache)
    assert.deepEqual(brotliDecompressSync(await readFile(outputPath)), raw)
    await writeFile(resolve(cache, `${first.unpacked_sha256}.br`), 'corrupt')
    const repaired = await packResource(raw, 'GeoIP.dat', output, cache)
    assert.deepEqual(repaired, first)
    await assert.rejects(packResource(Buffer.alloc(0), 'empty', output, cache), /Empty/)
    assert.throws(() => kernelBytes('kernel.zip', zipSync({ 'one.exe': raw, 'two.exe': raw })), /exactly one/)
  } finally { await rm(root, { recursive: true, force: true }) }
})
