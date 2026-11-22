#!/usr/bin/env node
// Builds the Rust kernel staticlib for the iOS Packet Tunnel extension
// (T7) and copies it where the BillowRust "Resolve Rust kernel" phase looks
// for it:
//
//   src-tauri/gen/apple/Externals/arm64/<device|simulator>/rust/libapp.a
//
// Usage:
//   node tool/ios/build-rust-kernel.mjs --platform device|simulator|all
//   [--profile release|debug] [--out path/to/libapp.a]
//   [--target aarch64-apple-ios|aarch64-apple-ios-sim|x86_64-apple-ios]
//
// The archive is the `billow-kernel` staticlib built with `--features
// ios-vpn`, which is the only configuration that compiles the userspace IP
// stack and exports the billow_ios_vpn_* C ABI. Nothing is downloaded: the
// workspace's Cargo.lock is the source of truth, so this works offline.
//
// The script verifies the archive really exports billow_ios_vpn_start and
// fails loudly instead of letting the extension build an unlinked binary.

import { execFileSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const workspace = join(root, 'native-kernel')

const platforms = {
  device: { target: 'aarch64-apple-ios', dir: 'device' },
  simulator: { target: 'aarch64-apple-ios-sim', dir: 'simulator' },
}

function parseArgs(argv) {
  const options = { platform: 'device', profile: 'release', out: null, target: null }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    switch (arg) {
      case '--platform':
        options.platform = argv[++index]
        break
      case '--profile':
        options.profile = argv[++index]
        break
      case '--out':
        options.out = resolve(argv[++index])
        break
      case '--target':
        options.target = argv[++index]
        break
      default:
        throw new Error(`unknown argument ${arg}`)
    }
  }
  if (!['device', 'simulator', 'all'].includes(options.platform)) {
    throw new Error(`unknown platform ${options.platform}`)
  }
  if (!['release', 'debug'].includes(options.profile)) {
    throw new Error(`unknown profile ${options.profile}`)
  }
  return options
}

/** Whether the archive exports the data-plane entry point. */
function exportsKernel(archive) {
  // `nm` from a newer LLVM often cannot read the archive's index; a grep over
  // the symbol table is enough for this presence check (same approach as
  // resolve-mihomo.sh).
  const text = readFileSync(archive).toString('latin1')
  return text.includes('billow_ios_vpn_start') && text.includes('billow_ios_vpn_drain')
}

function build(target, profile, out) {
  const args = [
    'build',
    '--manifest-path',
    join(workspace, 'Cargo.toml'),
    '--package',
    'billow-kernel',
    '--features',
    'ios-vpn',
    '--target',
    target,
  ]
  if (profile === 'release') {
    args.push('--release')
  }
  console.log(`== cargo ${args.join(' ')}`)
  execFileSync('cargo', args, { stdio: 'inherit', cwd: workspace })

  const metadata = JSON.parse(
    execFileSync('cargo', ['metadata', '--no-deps', '--format-version', '1', '--manifest-path', join(workspace, 'Cargo.toml')], {
      cwd: workspace,
      encoding: 'utf8',
    }),
  )
  const archive = join(metadata.target_directory, target, profile, 'libbillow_kernel.a')
  if (!existsSync(archive)) {
    throw new Error(`archive not found: ${archive}`)
  }
  if (!exportsKernel(archive)) {
    throw new Error(
      `archive ${archive} does not export billow_ios_vpn_*: build with --features ios-vpn`,
    )
  }
  mkdirSync(dirname(out), { recursive: true })
  copyFileSync(archive, out)
  const size = readFileSync(out).length
  console.log(`rust kernel: ${out} (${(size / 1024 / 1024).toFixed(1)} MiB, ${target}, ${profile})`)
  return out
}

const options = parseArgs(process.argv.slice(2))
const targets =
  options.platform === 'all'
    ? [
        { target: platforms.device.target, out: join(root, 'src-tauri/gen/apple/Externals/arm64/device/rust/libapp.a') },
        { target: platforms.simulator.target, out: join(root, 'src-tauri/gen/apple/Externals/arm64/simulator/rust/libapp.a') },
      ]
    : [
        {
          target: options.target || platforms[options.platform].target,
          out: options.out || join(root, `src-tauri/gen/apple/Externals/arm64/${platforms[options.platform].dir}/rust/libapp.a`),
        },
      ]

for (const { target, out } of targets) {
  build(target, options.profile, out)
}
