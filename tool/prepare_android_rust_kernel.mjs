// Builds the native Rust kernel as an Android PIE executable named
// `libbillow_kernel.so`, matching the existing `libmihomo.so` packaging so the
// app can start either engine as a process from nativeLibraryDir.
import { readFile, writeFile, mkdir, copyFile, chmod } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'

const triple = 'aarch64-linux-android'
const root = fileURLToPath(new URL('../', import.meta.url))
const target = resolve(root, 'src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/libbillow_kernel.so')
const cache = resolve(root, 'src-tauri/gen/android/.tauri/rust-kernel-cache')
const stamp = resolve(cache, 'build.json')
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex')

async function workspaceVersion() {
  const manifest = await readFile(resolve(root, 'native-kernel/Cargo.toml'), 'utf8')
  const block = manifest.match(/\[workspace\.package\]([\s\S]*?)(?:\n\[|$)/)
  const version = block?.[1].match(/version\s*=\s*"([^"]+)"/)?.[1]
  if (!version) throw new Error('native-kernel workspace version is missing')
  return version
}

export async function prepareAndroidRustKernel() {
  const version = await workspaceVersion()
  const key = JSON.stringify({ version, triple, features: ['android-vpn'] })
  const previous = JSON.parse(await readFile(stamp, 'utf8').catch(() => '{}'))
  const existing = await readFile(target).catch(() => null)
  if (previous.key === key && existing && sha(existing) === previous.sha256) {
    console.log(`Using verified native Rust kernel ${version} (Android VpnService)`)
    return
  }
  const ndk = process.env.NDK_HOME || process.env.ANDROID_NDK_HOME || process.env.ANDROID_NDK_ROOT
  if (!ndk) throw new Error('Android NDK is required to build the native Rust kernel')
  const host = process.platform === 'darwin' ? 'darwin-x86_64' : process.platform === 'win32' ? 'windows-x86_64' : 'linux-x86_64'
  const toolchain = resolve(ndk, 'toolchains/llvm/prebuilt', host, 'bin')
  const linker = resolve(toolchain, 'aarch64-linux-android21-clang')
  const ar = resolve(toolchain, 'llvm-ar')
  const targetDir = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : resolve(root, 'native-kernel/target')
  execFileSync('cargo', [
    'build', '--release', '--locked',
    '--manifest-path', resolve(root, 'native-kernel/Cargo.toml'),
    '-p', 'billow-kernel-cli', '--features', 'android-vpn',
    '--target', triple, '--target-dir', targetDir,
  ], {
    cwd: root,
    stdio: 'inherit',
    env: {
      ...process.env,
      CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER: linker,
      CARGO_TARGET_AARCH64_LINUX_ANDROID_AR: ar,
      CC_aarch64_linux_android: linker,
      AR_aarch64_linux_android: ar,
    },
  })
  const source = resolve(targetDir, triple, 'release', 'billow-kernel')
  const binary = await readFile(source)
  if (binary.subarray(0, 4).toString('hex') !== '7f454c46') throw new Error('Native Rust kernel is not ELF')
  await mkdir(resolve(target, '..'), { recursive: true })
  await copyFile(source, target)
  await chmod(target, 0o755)
  await mkdir(cache, { recursive: true })
  await writeFile(stamp, JSON.stringify({ key, sha256: sha(binary) }))
  const assets = resolve(root, 'src-tauri/gen/android/app/src/main/assets')
  await mkdir(assets, { recursive: true })
  await writeFile(resolve(assets, 'billow-kernel.json'), JSON.stringify({ version, triple, sha256: sha(binary) }, null, 2))
  console.log(`Built native Rust kernel ${version} for Android (${triple})`)
}

if (['android', 'androideabi'].includes(process.env.TAURI_ENV_PLATFORM) || process.argv.includes('--force')) {
  await prepareAndroidRustKernel()
}
