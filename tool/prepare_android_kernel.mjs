// The upstream cmfa build uses VpnService's fd instead of root-only Android routing.
// Android also requires executable code to be installed inside the APK.
import { readFile, writeFile, mkdir, copyFile, mkdtemp } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'

if (['android', 'androideabi'].includes(process.env.TAURI_ENV_PLATFORM) || process.argv.includes('--force')) {
  await import('./prepare_android_geo.mjs')
  const root = fileURLToPath(new URL('../', import.meta.url))
  const manifest = JSON.parse(await readFile(resolve(root, 'src-tauri/android-kernel.json'), 'utf8'))
  const arch = process.env.TAURI_ENV_ARCH
  if (arch && arch !== 'aarch64' && arch !== 'arm64') throw new Error('Billow Android packages currently support ARM64')
  const cache = resolve(root, 'src-tauri/gen/android/.tauri/kernel-cache')
  const target = resolve(root, 'src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/libmihomo.so')
  const stamp = resolve(cache, 'build.json')
  const sha = (bytes) => createHash('sha256').update(bytes).digest('hex')
  const modePatch = (await readFile(resolve(root, 'tool/android-kernel-mode.patch'), 'utf8')).replaceAll('\r\n', '\n')
  const key = JSON.stringify({ manifest, modePatch: sha(modePatch) })
  const previous = JSON.parse(await readFile(stamp, 'utf8').catch(() => '{}'))
  const existing = await readFile(target).catch(() => null)
  if (previous.key === key && existing && sha(existing) === previous.sha256) {
    console.log(`Using verified Mihomo ${manifest.version} (Android VpnService)`)
  } else {
    await mkdir(cache, { recursive: true })
    const archivePath = resolve(cache, `mihomo-${manifest.commit.slice(0, 7)}.tar.gz`)
    let archive = await readFile(archivePath).catch(() => null)
    if (!archive || sha(archive) !== manifest.sha256) {
      const response = await fetch(`https://codeload.github.com/MetaCubeX/mihomo/tar.gz/${manifest.commit}`, { signal: AbortSignal.timeout(120000) })
      if (!response.ok) throw new Error(`Kernel source download failed: HTTP ${response.status}`)
      archive = Buffer.from(await response.arrayBuffer())
      if (sha(archive) !== manifest.sha256) throw new Error('Kernel source checksum mismatch')
      await writeFile(archivePath, archive)
    }
    const extraction = await mkdtemp(resolve(cache, 'source-'))
    const source = resolve(extraction, `mihomo-${manifest.commit}`)
    // Compile a fresh extraction, so leftover Go files cannot enter the build.
    execFileSync('tar', ['-xzf', archivePath, '-C', extraction], { stdio: 'inherit' })
    // The extraction is inside Billow's checkout. Apply relative to the Mihomo source root.
    execFileSync('git', ['apply', '--no-index', '-'], {
      cwd: source, input: modePatch, env: { ...process.env, GIT_CEILING_DIRECTORIES: extraction },
    })
    await mkdir(resolve(target, '..'), { recursive: true })
    execFileSync('go', ['build', '-mod=readonly', '-trimpath', '-tags', manifest.tags.join(','), '-ldflags',
      `-s -w -X github.com/metacubex/mihomo/constant.Version=${manifest.version}-billow`, '-o', target, '.'], {
      cwd: source, stdio: 'inherit', env: { ...process.env, GOTOOLCHAIN: manifest.goVersion, GOOS: 'android', GOARCH: 'arm64', CGO_ENABLED: '0' },
    })
    const binary = await readFile(target)
    if (binary.subarray(0, 4).toString('hex') !== '7f454c46') throw new Error('Kernel is not ELF')
    await writeFile(stamp, JSON.stringify({ key, sha256: sha(binary) }))
    const assets = resolve(root, 'src-tauri/gen/android/app/src/main/assets')
    await mkdir(assets, { recursive: true })
    await copyFile(resolve(source, 'LICENSE'), resolve(assets, 'mihomo-LICENSE'))
    console.log(`Built Mihomo ${manifest.version} with Android VpnService integration`)
  }
}
