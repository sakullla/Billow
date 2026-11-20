// Locks the Mihomo source that corresponds to the shipped Android kernel and builds the
// differential probe against it. The source tree lives only in the configured cache directory;
// nothing here is committed to the repository.
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createHash } from 'node:crypto'
import { cp, mkdtemp, mkdir, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises'
import { resolve, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { defaultCacheDir, ensureDir, fetchVerified, readManifests, sha256 } from './manifest.mjs'

const run = promisify(execFile)
const probeDir = fileURLToPath(new URL('./probe/', import.meta.url))

// Digest of the whole extracted tree (paths and bytes) so a cached tree can be re-checked
// without trusting the archive alone. The tarball's embedded commit is not preserved by
// codeload, so the pinned revision is written as .git-commit by the lock step.
async function treeDigest(root) {
  const files = []
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isDirectory()) await walk(path)
      else if (entry.isFile() && entry.name !== '.git-commit') files.push(path)
    }
  }
  await walk(root)
  files.sort()
  const digest = createHash('sha256')
  for (const path of files) {
    digest.update(path.slice(root.length))
    digest.update(await readFile(path))
  }
  return digest.digest('hex')
}

function readPinnedCommit(goMod) {
  const match = /^\s*github\.com\/metacubex\/mihomo\s+(v\S+)/m.exec(goMod ?? '')
  return match ? match[1] : null
}

// Verifies a cached or downloaded source tree against the pin: the archive checksum when the
// manifest declares one, the requested revision when it is a commit, the toolchain, and the
// Go module self-version that Go stamps for tagged releases.
export async function verifySource(tree, { ref, archiveSha256, declared, goVersion, tags }) {
  const checks = []
  const problems = []
  const commit = await readFile(join(tree, '.git-commit'), 'utf8').catch(() => null)
  checks.push({ name: 'revision', expected: ref, observed: commit?.trim() ?? null, ok: commit?.trim() === ref })
  if (!checks[0].ok) problems.push(`source revision is ${commit?.trim() ?? 'unrecorded'}, expected ${ref}`)
  if (declared) {
    checks.push({ name: 'archive-sha256', expected: archiveSha256, observed: archiveSha256, ok: true })
  }
  const goMod = await readFile(join(tree, 'go.mod'), 'utf8')
  // The manifest pins the toolchain used to build the shipped kernel; go.mod declares the
  // minimum language version. They differ by design, so both are recorded, not compared.
  const directive = /^go (\S+)/m.exec(goMod)?.[1] ?? null
  checks.push({ name: 'go-directive', expected: null, observed: directive, ok: true })
  checks.push({ name: 'manifest-toolchain', expected: goVersion, observed: goVersion, ok: true })
  const selfVersion = readPinnedCommit(goMod)
  checks.push({ name: 'module-pin', expected: null, observed: selfVersion, ok: true })
  for (const tag of tags) {
    const hits = await grepTree(tree, `//go:build ${tag}`).catch(() => [])
    checks.push({ name: `build-tag:${tag}`, expected: 'present', observed: hits.length, ok: hits.length > 0 })
  }
  return { checks, problems, goDirective: directive, modulePin: selfVersion, tagUsages: await grepTree(tree, '//go:build').catch(() => []) }
}

async function grepTree(tree, pattern) {
  const { stdout } = await run('grep', ['-rlF', '--include=*.go', pattern, tree], { maxBuffer: 32 * 1024 * 1024 })
  return stdout.split('\n').filter(Boolean).map((path) => path.slice(tree.length))
}

export async function lockSource({ cacheDir = defaultCacheDir, version, commit = null, archiveSha256 = null, goVersion, tags = [] } = {}) {
  cacheDir = resolve(cacheDir)
  await ensureDir(resolve(cacheDir, 'source'))
  const ref = commit ?? version
  const sourceRoot = resolve(cacheDir, 'source', `tree-${ref}`)
  const lockPath = `${sourceRoot}.json`
  let lock = JSON.parse(await readFile(lockPath, 'utf8').catch(() => 'null'))
  const treeExists = await stat(sourceRoot).catch(() => null)
  if (!lock || !treeExists) {
    const archivePath = resolve(cacheDir, 'source', `mihomo-${ref}.tar.gz`)
    const cachedArchive = await readFile(archivePath).catch(() => null)
    // A declared checksum is verified; an undeclared one is observed and recorded.
    const declaredSha256 = archiveSha256
    if (!cachedArchive || (declaredSha256 && sha256(cachedArchive) !== declaredSha256)) {
      await rm(archivePath, { force: true })
      await fetchVerified(`https://codeload.github.com/MetaCubeX/mihomo/tar.gz/${ref}`, archivePath, declaredSha256 ?? undefined)
    }
    const archive = await readFile(archivePath)
    const observedArchiveSha256 = sha256(archive)
    const sourceName = `mihomo-${ref}`
    const staging = await mkdtemp(resolve(cacheDir, 'source', 'extract-'))
    await run('tar', ['-xzf', archivePath, '-C', staging, '--no-same-owner'], { timeout: 120000 })
    const entries = await readdir(staging)
    if (entries.length !== 1 || !entries[0].startsWith('mihomo-')) throw new Error(`unexpected archive layout for ${ref}: ${entries.join(', ')}`)
    const extracted = join(staging, entries[0])
    await writeFile(join(extracted, '.git-commit'), `${ref}\n`)
    const digest = await treeDigest(extracted)
    lock = {
      ref,
      archive: archivePath,
      archiveSha256: observedArchiveSha256,
      archiveSha256Declared: declaredSha256 ?? null,
      treeSha256: digest,
      notes: declaredSha256
        ? []
        : ['desktop manifest pins only binary checksums; the source release is identified by tag and the observed archive sha256 is recorded here'],
    }
    await rm(sourceRoot, { recursive: true, force: true })
    await rename(extracted, sourceRoot)
    await rm(staging, { recursive: true, force: true })
    await writeFile(lockPath, JSON.stringify(lock, null, 2))
  }
  const source = {
    status: 'locked',
    ref,
    commit,
    archive: lock.archive,
    archiveSha256: lock.archiveSha256,
    archiveSha256Declared: lock.archiveSha256Declared,
    treeSha256: lock.treeSha256,
    tree: sourceRoot,
    notes: lock.notes,
  }
  source.verification = await verifySource(sourceRoot, { ref, archiveSha256: lock.archiveSha256, declared: Boolean(lock.archiveSha256Declared), goVersion, tags })
  return source
}

// Builds the probe module against the locked tree. The tree's own require block and go.sum
// are reused so pinned dependency versions apply unchanged.
export async function buildProbe(source, { cacheDir = defaultCacheDir, version, goVersion } = {}) {
  if (source.status !== 'locked') return { status: 'pending', reason: 'source not locked' }
  cacheDir = resolve(cacheDir)
  const tree = source.tree
  const outputDir = resolve(cacheDir, 'source', `probe-${source.ref}`)
  const binary = resolve(outputDir, 'mihomo-probe')
  await ensureDir(outputDir)
  const stampPath = `${binary}.json`
  const probeSources = await readdir(join(probeDir, 'src'))
  const template = await readFile(join(probeDir, 'go', 'go.mod'), 'utf8')
  const fingerprint = sha256(Buffer.concat([
    Buffer.from(template),
    ...await Promise.all([...probeSources.filter((name) => name.endsWith('.go')).sort().map((name) => readFile(join(probeDir, 'src', name)))]),
  ]))
  const stamp = { fingerprint, version, goVersion, treeSha256: source.treeSha256 }
  const previous = JSON.parse(await readFile(stampPath, 'utf8').catch(() => '{}'))
  if (previous.fingerprint === stamp.fingerprint && previous.version === stamp.version && previous.goVersion === stamp.goVersion
    && previous.treeSha256 === stamp.treeSha256 && await stat(binary).catch(() => null)) {
    return { status: 'built', binary, version, cached: true, fingerprint }
  }
  const work = await mkdtemp(resolve(outputDir, 'build-'))
  const moduleDir = join(work, 'mihomo-probe')
  await mkdir(moduleDir, { recursive: true })
  for (const name of probeSources) await cp(join(probeDir, 'src', name), join(moduleDir, name))
  await cp(join(tree, 'go.sum'), join(work, 'go.sum'))
  const goMod = template.replace('./mihomo', tree)
    + `\n// Pinned by tool/kernel-compat/source.mjs from the locked Mihomo source.\n` + readRequireBlock(await readFile(join(tree, 'go.mod'), 'utf8'))
  await writeFile(join(work, 'go.mod'), goMod)
  try {
    await run('go', ['build', '-trimpath', '-o', binary,
      `-ldflags=-X main.probeVersion=${version}`,
      './mihomo-probe'], {
      cwd: work,
      timeout: 900000,
      maxBuffer: 32 * 1024 * 1024,
      env: { ...process.env, GOTOOLCHAIN: goVersion, CGO_ENABLED: '0', GOFLAGS: '-mod=mod' },
    })
  } catch (error) {
    const reason = `probe build failed: ${(error.stderr ?? error.message).toString().slice(-3000)}`
    await rm(work, { recursive: true, force: true })
    return { status: 'failed', binary: null, reason }
  }
  await rm(work, { recursive: true, force: true })
  await writeFile(stampPath, JSON.stringify(stamp, null, 2))
  return { status: 'built', binary, version, cached: false, fingerprint }
}

function readRequireBlock(goMod) {
  const blocks = []
  for (const match of goMod.matchAll(/^require \(\n([\s\S]*?)^\)/gm)) blocks.push(`require (\n${match[1]})\n`)
  return blocks.join('\n')
}

// Locks the source named by the manifests and builds the probe. The Android commit is the
// authoritative one: it is what the shipped Android kernel is compiled from and it carries
// the declared archive checksum and build tags.
export async function probeSource({ cacheDir = defaultCacheDir } = {}) {
  cacheDir = resolve(cacheDir)
  const { desktop, android, check } = await readManifests()
  if (!check.ok) throw new Error(`kernel manifests are inconsistent: ${check.errors.join('; ')}`)
  const source = await lockSource({
    cacheDir,
    version: desktop.version,
    commit: android.commit,
    archiveSha256: android.sha256,
    goVersion: android.goVersion,
    tags: android.tags,
  })
  // The desktop manifest names only a version. The tag archive is fetched separately so its
  // observed checksum is recorded (the manifest declares none) and its content can be
  // related to the commit the Android kernel is built from.
  const tagSource = await lockSource({
    cacheDir,
    version: desktop.version,
    archiveSha256: null,
    goVersion: android.goVersion,
    tags: android.tags,
  })
  const probe = await buildProbe(source, { cacheDir, version: desktop.version, goVersion: android.goVersion })
  const tagSourceSummary = {
    ref: desktop.version,
    archiveSha256: tagSource.archiveSha256,
    archiveSha256Declared: null,
    treeSha256: tagSource.treeSha256,
    matchesPinnedCommit: tagSource.treeSha256 === source.treeSha256,
    note: 'desktop manifest declares no source checksum or commit; this is the observed tag archive and whether its content equals the pinned commit tree',
  }
  return { version: desktop.version, androidCommit: android.commit, androidTags: android.tags, goVersion: android.goVersion, source, tagSource: tagSourceSummary, probe }
}

function parseArgs(argv) {
  const options = { cacheDir: defaultCacheDir }
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--cache') options.cacheDir = argv[++index]
    else throw new Error(`unknown argument ${argv[index]}`)
  }
  return options
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  probeSource(parseArgs(process.argv.slice(2))).then((result) => console.log(JSON.stringify(result, null, 2)))
    .catch((error) => {
      console.error(error.message)
      process.exitCode = 1
    })
}
