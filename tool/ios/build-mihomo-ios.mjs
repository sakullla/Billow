// Builds the pinned Mihomo source (tool/ios/mihomo-ios.json) into the static
// archive linked by the Billow Mihomo Packet Tunnel extension.
//
//   node tool/ios/build-mihomo-ios.mjs [--platform device|simulator] [--clean]
//
// Output (git-ignored):
//   src-tauri/gen/apple/Externals/arm64/<platform>/libmihomo_ios.a
//     <platform>: device    | GOOS=ios GOARCH=arm64, iphoneos SDK, iOS 15
//                 simulator | GOOS=ios GOARCH=arm64, iphonesimulator SDK
//
// Steps: verify the pinned tar.gz sha256 -> extract into a private temp dir ->
// copy src-tauri/gen/apple/mihomo-ios (Go bridge + go.mod/go.sum) -> `go vet`
// -> `go build -buildmode=c-archive -tags with_gvisor,cmfa`.
//
// Go requires a main package for c-archive and links host code with the GOOS
// linker; on ios/arm64 the result therefore carries host-linked runtime
// objects. tool/ios/verify-mihomo-archive.sh links the archive into a probe
// binary for the selected SDK and must pass on the build Mac.

import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, copyFileSync, statSync, writeFileSync } from 'node:fs'
import { writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const toolDir = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(toolDir, '..', '..')
const pin = JSON.parse(readFileSync(path.join(toolDir, 'mihomo-ios.json'), 'utf8'))
const bridgeDir = path.join(repoRoot, 'src-tauri', 'gen', 'apple', 'mihomo-ios')
const externals = path.join(repoRoot, 'src-tauri', 'gen', 'apple', 'Externals')

function args(argv) {
  const out = { platform: 'device', clean: false }
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--platform') out.platform = argv[++i]
    else if (argv[i] === '--clean') out.clean = true
  }
  if (out.platform === 'ios') out.platform = 'device'
  if (!['device', 'simulator'].includes(out.platform)) {
    throw new Error(`unknown --platform ${out.platform} (device|simulator)`)
  }
  return out
}

function run(cmd, cmdArgs, options = {}) {
  return execFileSync(cmd, cmdArgs, { stdio: 'inherit', ...options })
}

function xcrun(...cmdArgs) {
  return execFileSync('xcrun', cmdArgs, { encoding: 'utf8' }).trim()
}

function goVersionAtLeast(current, minimum) {
  const parse = (v) => v.replace(/^go/, '').split('.').map((n) => Number.parseInt(n, 10) || 0)
  const a = parse(current)
  const b = parse(minimum)
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0)
  }
  return true
}

async function download(url, file) {
  if (existsSync(file)) return
  const res = await fetch(url, { redirect: 'follow' })
  if (!res.ok) throw new Error(`download ${url}: HTTP ${res.status}`)
  await writeFile(file, Buffer.from(await res.arrayBuffer()))
}

// The c-archive header is used as a Swift module: SwiftPM-compatible layout
//   Externals/arm64/<platform>/include/<module>/<module>.h
// with `#include "<module>.h"` resolving to the generated header.
async function installModule(archive, platform) {
  const header = archive.replace(/\.a$/, '.h')
  if (!existsSync(header)) {
    throw new Error(`go build did not produce ${header}`)
  }
  const name = pin.moduleName
  const modDir = path.join(path.dirname(archive), 'include', name)
  mkdirSync(modDir, { recursive: true })
  copyFileSync(header, path.join(modDir, `${name}.h`))
  rmSync(header)
  console.log(`module ${name}: ${path.join(modDir, `${name}.h`)}`)
}

function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex')
}

async function main() {
  const opts = args(process.argv.slice(2))
  const go = execFileSync('go', ['version'], { encoding: 'utf8' }).split(' ')[2]
  if (!goVersionAtLeast(go, pin.minimumGoVersion)) {
    throw new Error(`go ${go} is older than required ${pin.minimumGoVersion} (GOOS=ios needs Go 1.26+)`)
  }

  const outDir = path.join(externals, 'arm64', opts.platform)
  const archive = path.join(outDir, 'libmihomo_ios.a')
  if (opts.clean) rmSync(outDir, { recursive: true, force: true })
  mkdirSync(outDir, { recursive: true })

  const work = mkdtempSync(path.join(tmpdir(), 'billow-mihomo-'))
  try {
    const tar = path.join(work, `${pin.commit}.tar.gz`)
    await download(pin.archiveUrl, tar)
    const digest = sha256(tar)
    if (digest !== pin.sha256) {
      throw new Error(`mihomo archive sha256 ${digest} != pinned ${pin.sha256}`)
    }
    console.log(`mihomo ${pin.version} ${pin.commit.slice(0, 12)} archive verified`)

    const srcRoot = path.join(work, 'src')
    mkdirSync(srcRoot)
    run('tar', ['-xzf', tar, '-C', srcRoot])
    const upstream = path.join(srcRoot, `mihomo-${pin.commit}`)
    if (!existsSync(path.join(upstream, 'go.mod'))) {
      throw new Error(`unexpected archive layout: ${upstream}`)
    }

    const module = path.join(work, 'module')
    mkdirSync(module)
    for (const file of ['bridge.go', 'go.mod', 'go.sum']) {
      copyFileSync(path.join(bridgeDir, file), path.join(module, file))
    }
    // Point the bridge module at the verified checkout; go.sum stays pinned.
    const gomod = path.join(module, 'go.mod')
    const pinned = readFileSync(gomod, 'utf8').replace(/^replace .*$/gm, '').trimEnd()
    writeFileSync(gomod, `${pinned}\n\nreplace github.com/metacubex/mihomo => ${upstream}\n`)

    const sdk = opts.platform === 'device' ? 'iphoneos' : 'iphonesimulator'
    const sdkPath = xcrun('--sdk', sdk, '--show-sdk-path')
    const clang = xcrun('--sdk', sdk, '-f', 'clang')
    const minFlag = opts.platform === 'device' ? '-miphoneos-version-min=15.0' : '-mios-simulator-version-min=15.0'
    const env = {
      ...process.env,
      GOOS: 'ios',
      GOARCH: 'arm64',
      CGO_ENABLED: '1',
      CC: clang,
      CGO_CFLAGS: `-isysroot ${sdkPath} ${minFlag}`,
      CGO_LDFLAGS: `-isysroot ${sdkPath} ${minFlag}`,
      GOFLAGS: '-trimpath',
    }
    const ldflags = Object.entries(pin.ldflags)
      .map(([key, value]) => `-X "${key}=${value}"`)
      .join(' ')
    const tags = pin.tags.join(',')
    console.log(`go vet (${tags}, ${opts.platform})`)
    run('go', ['vet', `-tags=${tags}`, '.'], { cwd: module, env })
    console.log(`go build -buildmode=c-archive -> ${archive}`)
    run(
      'go',
      ['build', `-tags=${tags}`, '-buildmode=c-archive', '-ldflags', `${ldflags} -buildid=`, '-o', archive, '.'],
      { cwd: module, env }
    )
    await installModule(archive, opts.platform)
    const size = statSync(archive).size
    const mach = xcrun('lipo', '-info', archive)
    console.log(`ok ${archive} (${size} bytes, ${mach})`)
  } finally {
    rmSync(work, { recursive: true, force: true })
  }
}

main().catch((error) => {
  console.error(`build-mihomo-ios: ${error.message}`)
  process.exit(1)
})
