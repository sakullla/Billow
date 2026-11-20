#!/usr/bin/env node
// Builds a reviewable capability index from the locked Mihomo source tree. Everything is
// extracted statically from the pinned files, with a source location for each entry; entries
// whose shape cannot be mapped statically (free-form maps, platform-only code) are kept in an
// unmapped list rather than dropped. Every entry is marked as unmapped to the Rust engine:
// T1 establishes the baseline, later tasks record their implementation against it.
import { readFileSync } from 'node:fs'
import { readdir, readFile, writeFile } from 'node:fs/promises'
import { join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'
import { defaultCacheDir, ensureDir } from './manifest.mjs'
import { probeSource } from './source.mjs'

const read = (tree, path) => readFile(join(tree, path), 'utf8')

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length
}

// Reads a Go struct block by name and returns its fields with tags.
export function goStructFields(source, structName) {
  const start = source.search(new RegExp(`type ${structName} struct \\{`))
  if (start < 0) return []
  const open = source.indexOf('{', start)
  let depth = 0
  let end = open
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === '{') depth += 1
    else if (source[index] === '}') {
      depth -= 1
      if (depth === 0) {
        end = index
        break
      }
    }
  }
  const body = source.slice(open + 1, end)
  const fields = []
  let offset = open + 1
  for (const line of body.split('\n')) {
    const parsed = /^\s*([A-Z]\w*)\s+([^\s`]+)(?:\s+`([^`]*)`)?/.exec(line)
    if (parsed) {
      const tags = {}
      for (const tag of (parsed[3] ?? '').split(/\s+/)) {
        const match = /^(\w+):"([^"]*)"/.exec(tag)
        if (match) tags[match[1]] = match[2].split(',')[0]
      }
      fields.push({ name: parsed[1], goType: parsed[2], yaml: tags.yaml ?? null, json: tags.json ?? null, line: lineOf(source, offset) })
    }
    offset += line.length + 1
  }
  return fields
}

// Case labels of a Go switch, with the constructor called in the same case.
export function goSwitchCases(source, switchPattern) {
  const start = source.search(switchPattern)
  if (start < 0) return []
  const cases = []
  const pattern = /case ((?:"[^"]+"(?:,\s*)?)+):\n([\s\S]*?)(?=\n\tcase |\n\tdefault:|\n\t\}\n)/g
  const chunk = source.slice(start)
  for (const match of chunk.matchAll(pattern)) {
    const labels = [...match[1].matchAll(/"([^"]+)"/g)].map((label) => label[1])
    const constructor = /(?:outbound|outboundgroup|IN|inbound|RC)\.[A-Z]\w+\(/.exec(match[2])?.[0]?.replace('(', '') ?? null
    for (const label of labels) {
      cases.push({ value: label, constructor, line: lineOf(source, start + match.index) })
    }
  }
  return cases
}

async function walk(root, filter = () => true) {
  const files = []
  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name)
      if (entry.isDirectory()) await visit(path)
      else if (filter(path)) files.push(path)
    }
  }
  await visit(root)
  return files.sort()
}

// Platform evidence: build constraint lines and file-name suffixes that the pinned tree uses
// to compile a feature only on some targets. Both are recorded because a tag alone does not
// say which platform a file belongs to, and a file suffix does not say why it exists.
export function platformEvidence(files, root) {
  const tags = new Map()
  const suffixes = new Map()
  for (const file of files) {
    const name = relative(root, file)
    const match = /_(windows|darwin|linux|android|ios|freebsd|openbsd|netbsd|unix|other|posix|mips|arm64|amd64|386)\.go$/.exec(name)
    if (match) {
      const list = suffixes.get(match[1]) ?? []
      list.push(name)
      suffixes.set(match[1], list)
    }
  }
  return { byFileSuffix: Object.fromEntries([...suffixes].sort()), note: 'derived from file names; build tags are listed separately' }
}

export function buildTags(files, root) {
  const found = new Map()
  for (const file of files) {
    const text = readFileSyncSafe(file)
    if (text === null) continue
    const lines = text.split('\n').slice(0, 12)
    for (const line of lines) {
      const match = /^\/\/go:build (.+)$/.exec(line)
      if (match) {
        const value = match[1].trim()
        const list = found.get(value) ?? []
        list.push(relative(root, file))
        found.set(value, list)
      }
    }
  }
  return [...found].map(([expression, locations]) => ({ expression, locations })).sort((left, right) => left.expression.localeCompare(right.expression))
}

function readFileSyncSafe(path) {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    return null
  }
}

export async function generateCapabilities(tree, { version, commit, archiveSha256, treeSha256, androidTags = [] } = {}) {
  const config = await read(tree, 'config/config.go')
  const parser = await read(tree, 'adapter/parser.go')
  const listeners = await read(tree, 'listener/parse.go')
  const groups = await read(tree, 'adapter/outboundgroup/parser.go')
  const rules = await read(tree, 'rules/parser.go')
  const goMod = await read(tree, 'go.mod')
  const files = await walk(tree, (path) => path.endsWith('.go'))
  const rawConfig = goStructFields(config, 'RawConfig')
  const nestedStructs = [...new Set(rawConfig.map((field) => field.goType).filter((type) => /^Raw\w+$/.test(type)))]
  const nested = {}
  for (const name of nestedStructs) nested[name] = goStructFields(config, name)
  const freeFormTypes = new Set(['map[string]map[string]any', '[]map[string]any', 'map[string]any', '[]LC.Tunnel'])
  const unmapped = []
  for (const field of rawConfig) {
    if (freeFormTypes.has(field.goType)) {
      unmapped.push({ kind: 'config-field', name: field.yaml ?? field.name, goType: field.goType, source: `config/config.go:${field.line}`, reason: 'free-form shape; keys are defined by another parser and are indexed there' })
    }
  }
  const protocols = goSwitchCases(parser, /switch proxyType \{/)
  const inboundTypes = goSwitchCases(listeners, /switch proxyType \{/)
  const groupTypes = goSwitchCases(groups, /switch groupOption\.Type \{/)
  const ruleTypes = [...rules.matchAll(/case ((?:"[^"]+"(?:,\s*)??)+):/g)].flatMap((match) =>
    [...match[1].matchAll(/"([^"]+)"/g)].map((label) => ({ value: label[1], line: lineOf(rules, match.index) })))
  // A handler that is only constructed under a build tag (for example gvisor-backed TUN) is
  // reported with that tag instead of being assumed available everywhere.
  const gated = []
  for (const protocol of protocols) {
    const hit = buildTags(files, tree).find((tag) => tag.locations.some((path) => path.includes(protocol.value)))
    if (hit) gated.push({ kind: 'protocol', name: protocol.value, tag: hit.expression })
  }
  return {
    format: 'kernel-capability-index',
    version: 1,
    generatedFrom: 'locked Mihomo source tree (static extraction)',
    engine: 'mihomo',
    upstream: {
      repository: 'MetaCubeX/mihomo',
      version,
      commit: commit ?? null,
      archiveSha256: archiveSha256 ?? null,
      treeSha256: treeSha256 ?? null,
      goDirective: /^go (\S+)/m.exec(goMod)?.[1] ?? null,
      androidBuildTags: androidTags,
      notes: [
        'the desktop manifest pins only release binaries; the source identity here comes from the Android manifest and the observed archive checksum',
        'static extraction reads declarations; it cannot prove runtime behaviour of a field, which is what the differential fixtures are for',
      ],
    },
    configFields: rawConfig.map((field) => ({
      name: field.yaml ?? field.name,
      goName: field.name,
      goType: field.goType,
      source: `config/config.go:${field.line}`,
      nested: /^Raw\w+$/.test(field.goType) ? { struct: field.goType, fields: nested[field.goType] } : null,
      rustMapping: null,
    })),
    proxies: protocols.map((entry) => ({ type: entry.value, constructor: entry.constructor, source: `adapter/parser.go:${entry.line}`, rustMapping: null })),
    listeners: inboundTypes.map((entry) => ({ type: entry.value, constructor: entry.constructor, source: `listener/parse.go:${entry.line}`, rustMapping: null })),
    groups: groupTypes.map((entry) => ({ type: entry.value, constructor: entry.constructor, source: `adapter/outboundgroup/parser.go:${entry.line}`, rustMapping: null })),
    rules: ruleTypes.map((entry) => ({ type: entry.value, source: `rules/parser.go:${entry.line}`, rustMapping: null })),
    platforms: {
      desktopTargets: [],
      androidBuildTags: androidTags,
      buildTags: buildTags(files, tree),
      byFileSuffix: platformEvidence(files, tree).byFileSuffix,
      gated,
    },
    unmapped: [
      ...unmapped,
      ...protocols.filter((entry) => !entry.constructor).map((entry) => ({ kind: 'protocol', name: entry.value, source: `adapter/parser.go:${entry.line}`, reason: 'no constructor recognised; needs manual review' })),
      { kind: 'mapping', name: '*', reason: 'no Rust implementation exists at T1; every entry is unmapped until a later task records its coverage' },
    ],
    coverage: {
      mapped: 0,
      total: rawConfig.length + protocols.length + inboundTypes.length + groupTypes.length + ruleTypes.length,
      note: 'T1 records the baseline only. A later task must fill rustMapping and update this count; unmapped entries must not be reported as compatible.',
    },
  }
}

export async function generateFromCache({ cacheDir = defaultCacheDir } = {}) {
  const locked = await probeSource({ cacheDir })
  const { readManifests } = await import('./manifest.mjs')
  const { desktop, android } = await readManifests()
  const index = await generateCapabilities(locked.source.tree, {
    version: desktop.version,
    commit: locked.source.commit,
    archiveSha256: locked.source.archiveSha256,
    treeSha256: locked.source.treeSha256,
    androidTags: android.tags,
  })
  index.platforms.desktopTargets = Object.keys(desktop.targets)
  index.upstream.desktopVersion = desktop.version
  index.upstream.androidCommit = android.commit
  return { index, locked }
}

function parseArgs(argv) {
  const options = { cacheDir: defaultCacheDir, out: null }
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--cache') options.cacheDir = argv[++index]
    else if (argv[index] === '--out') options.out = argv[++index]
    else throw new Error(`unknown argument ${argv[index]}`)
  }
  return options
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const options = parseArgs(process.argv.slice(2))
  generateFromCache(options).then(async ({ index }) => {
    if (options.out) {
      await ensureDir(options.out.replace(/\/[^/]+$/, ''))
      await writeFile(options.out, JSON.stringify(index, null, 2))
    }
    console.log(JSON.stringify({
      entries: { configFields: index.configFields.length, proxies: index.proxies.length, listeners: index.listeners.length, groups: index.groups.length, rules: index.rules.length },
      unmapped: index.unmapped.length,
      out: options.out,
    }))
  }).catch((error) => {
    console.error(error.message)
    process.exitCode = 1
  })
}
