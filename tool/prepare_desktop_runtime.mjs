import { readFile, writeFile, mkdir, copyFile, rm, chmod } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { prepareGeo } from './prepare_geo.mjs'
import { downloadBytes } from './build_download.mjs'
import { kernelBytes, packResource } from './pack_resource.mjs'

export function desktopTarget(platform, arch) {
  const os = { darwin: 'darwin', macos: 'darwin', win32: 'windows', windows: 'windows', linux: 'linux' }[platform]
  const cpu = { arm64: 'aarch64', aarch64: 'aarch64', x64: 'x86_64', x86_64: 'x86_64', ia32: 'i686', i686: 'i686', armv7: 'armv7' }[arch]
  if (!os || !cpu) throw new Error(`Unsupported desktop runtime target: ${platform}/${arch}`)
  return `${os}-${cpu}`
}

/** Rust triples that match the packaged desktop targets. */
export const RUST_TARGETS = {
  'darwin-aarch64': 'aarch64-apple-darwin',
  'darwin-x86_64': 'x86_64-apple-darwin',
  'windows-aarch64': 'aarch64-pc-windows-msvc',
  'windows-x86_64': 'x86_64-pc-windows-msvc',
  'windows-i686': 'i686-pc-windows-msvc',
  'linux-aarch64': 'aarch64-unknown-linux-gnu',
  'linux-x86_64': 'x86_64-unknown-linux-gnu',
  'linux-i686': 'i686-unknown-linux-gnu',
  'linux-armv7': 'armv7-unknown-linux-gnueabihf',
}

async function rustWorkspaceVersion(root) {
  const manifest = await readFile(resolve(root, 'native-kernel/Cargo.toml'), 'utf8')
  const block = manifest.match(/\[workspace\.package\]([\s\S]*?)(?:\n\[|$)/)
  const version = block?.[1].match(/version\s*=\s*"([^"]+)"/)?.[1]
  if (!version) throw new Error('native-kernel workspace version is missing')
  return version
}

/**
 * Builds (or reuses) the native Rust kernel and copies it next to the bundled
 * Mihomo, so every desktop installer ships both engines. `BILLOW_RUST_KERNEL_BIN`
 * points at a prebuilt binary; `BILLOW_RUST_KERNEL_TARGET` overrides the triple.
 */
export async function prepareRustKernel({ root, target, bundle }) {
  const triple = process.env.BILLOW_RUST_KERNEL_TARGET || RUST_TARGETS[target]
  if (!triple) throw new Error(`No native Rust kernel target for ${target}`)
  const executable = triple.includes('windows') ? 'billow-kernel.exe' : 'billow-kernel'
  let source = process.env.BILLOW_RUST_KERNEL_BIN
  const targetDir = process.env.CARGO_TARGET_DIR
    ? resolve(process.env.CARGO_TARGET_DIR)
    : resolve(root, 'native-kernel/target')
  if (!source) {
    execFileSync('cargo', [
      'build', '--release', '--locked',
      '--manifest-path', resolve(root, 'native-kernel/Cargo.toml'),
      '-p', 'billow-kernel-cli', '--features', 'desktop-tun',
      '--target', triple, '--target-dir', targetDir,
    ], { cwd: root, stdio: 'inherit' })
    source = resolve(targetDir, triple, 'release', executable)
  }
  const bytes = await readFile(source)
  if (bytes.length === 0) throw new Error('Native Rust kernel is empty')
  const destination = resolve(bundle, executable)
  await copyFile(source, destination)
  await chmod(destination, 0o755)
  // Wintun is loaded from the kernel executable's own directory. The Windows
  // bundle also ships wintun.dll next to Billow.exe for the takeover probe, but
  // the Rust kernel lives under runtime/, so it needs its own copy.
  if (target.startsWith('windows')) {
    await copyFile(resolve(root, 'assets/wintun/wintun.dll'), resolve(bundle, 'wintun.dll'))
  }
  const version = await rustWorkspaceVersion(root)
  await writeFile(resolve(bundle, 'rust-kernel.json'), JSON.stringify({
    version,
    target,
    triple,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  }, null, 2))
  console.log(`Bundled native Rust kernel ${version} for ${target}`)
  return destination
}

export async function prepareDesktop({
  platform,
  arch,
  root = fileURLToPath(new URL('../', import.meta.url)),
  fetchImpl = fetch,
  prepareGeoImpl = prepareGeo,
  prepareRustKernelImpl = prepareRustKernel,
}) {
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
  const packed = await packResource(kernelBytes(entry.asset, bytes), 'kernel', bundle, resolve(cache, 'packed'))
  // An architecture switch or a build from an older checkout must not ship duplicate cores.
  await rm(resolve(bundle, 'kernel.gz'), { force: true })
  await rm(resolve(bundle, 'kernel.zip'), { force: true })
  await copyFile(resolve(root, 'assets/mihomo/LICENSE'), resolve(bundle, 'mihomo-LICENSE'))
  await prepareGeoImpl(resolve(bundle, 'geo'))
  await writeFile(resolve(bundle, 'kernel.json'), JSON.stringify({ version: manifest.version, ...entry, packed }, null, 2))
  console.log(`Bundled verified Mihomo ${manifest.version} for ${target}`)
  await prepareRustKernelImpl({ root, target, bundle })
}
