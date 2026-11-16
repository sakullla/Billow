import { readFile, writeFile, mkdir, copyFile, rm } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { prepareGeo } from './prepare_geo.mjs'
import { downloadBytes } from './build_download.mjs'

export function desktopTarget(platform, arch) {
  const os = { darwin: 'darwin', macos: 'darwin', win32: 'windows', windows: 'windows', linux: 'linux' }[platform]
  const cpu = { arm64: 'aarch64', aarch64: 'aarch64', x64: 'x86_64', x86_64: 'x86_64', ia32: 'i686', i686: 'i686', armv7: 'armv7' }[arch]
  if (!os || !cpu) throw new Error(`Unsupported desktop runtime target: ${platform}/${arch}`)
  return `${os}-${cpu}`
}

export async function prepareDesktop({ platform, arch, root = fileURLToPath(new URL('../', import.meta.url)), fetchImpl = fetch, prepareGeoImpl = prepareGeo }) {
  const manifest = JSON.parse(await readFile(resolve(root, 'src-tauri/desktop-kernel.json'), 'utf8'))
  const target = desktopTarget(platform, arch)
  const entry = manifest.targets[target]
  if (!entry) throw new Error(`No bundled Mihomo for ${target}`)
  const sha = bytes => createHash('sha256').update(bytes).digest('hex')
  const cache = resolve(root, 'src-tauri/.runtime-cache')
  const bundle = resolve(root, 'src-tauri/resources/runtime')
  await mkdir(cache, { recursive: true })
  await mkdir(bundle, { recursive: true })
  const archivePath = resolve(cache, entry.asset)
  let bytes = await readFile(archivePath).catch(() => null)
  if (!bytes || sha(bytes) !== entry.sha256) {
    const url = `https://github.com/${manifest.repository}/releases/download/${manifest.version}/${entry.asset}`
    console.log(`Downloading bundled Mihomo for ${target}`)
    bytes = await downloadBytes(url, { fetchImpl })
    if (sha(bytes) !== entry.sha256) throw new Error('Bundled kernel checksum mismatch')
    await writeFile(archivePath, bytes)
  }
  // Ship the verified archive; Rust extracts it into writable app data at startup.
  // macOS TUN authorization must never modify a signed application bundle.
  const archiveName = entry.asset.endsWith('.zip') ? 'kernel.zip' : 'kernel.gz'
  await writeFile(resolve(bundle, archiveName), bytes)
  await rm(resolve(bundle, archiveName === 'kernel.zip' ? 'kernel.gz' : 'kernel.zip'), { force: true })
  await copyFile(resolve(root, 'assets/mihomo/LICENSE'), resolve(bundle, 'mihomo-LICENSE'))
  await prepareGeoImpl(resolve(bundle, 'geo'))
  await writeFile(resolve(bundle, 'kernel.json'), JSON.stringify({ version: manifest.version, ...entry }, null, 2))
  console.log(`Bundled verified Mihomo ${manifest.version} for ${target}`)
}
