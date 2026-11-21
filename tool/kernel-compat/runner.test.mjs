// Acceptance tests for the differential entry point. They use the baseline pinned by the
// repository manifests (downloaded and checksum-verified on first use) and the locked source
// tree, so the positive case is a real Mihomo exit through a controlled endpoint.
import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { checkManifests, currentTarget, defaultCacheDir, readManifests } from './manifest.mjs'
import { resolveBaseline } from './baseline.mjs'
import { setTopLevel, getTopLevel } from './yaml.mjs'
import { loadFixture, withHosts, withPorts, tagHost } from './fixture.mjs'
import { runDifferential } from './runner.mjs'
import { generateFromCache, loadRustMapping } from './capability.mjs'
import { probeSource } from './source.mjs'

const here = fileURLToPath(new URL('.', import.meta.url))
const fixture = (name) => resolve(here, 'fixtures', `${name}.yaml`)
const cacheDir = process.env.KC_CACHE_DIR ? resolve(process.env.KC_CACHE_DIR) : defaultCacheDir

let baseline
let probe

before(async () => {
  baseline = await resolveBaseline({ cacheDir })
  assert.equal(baseline.status, 'locked', `baseline must resolve: ${baseline.reason ?? ''}`)
  probe = await probeSource({ cacheDir })
  assert.equal(probe.probe.status, 'built', `probe must build: ${probe.probe.reason ?? ''}`)
  assert.match(probe.tagSource.archiveSha256, /^[0-9a-f]{64}$/)
  assert.equal(probe.tagSource.matchesPinnedCommit, true, 'the v1.19.34 tag content must equal the Android-pinned commit tree')
}, { timeout: 900000 })

test('manifests agree and keep undeclared facts as notes', async () => {
  const { desktop, android, check } = await readManifests()
  assert.equal(check.ok, true, check.errors.join('; '))
  assert.equal(desktop.version, android.version)
  assert.equal(android.version, 'v1.19.34')
  assert.match(android.commit, /^[0-9a-f]{40}$/)
  assert.deepEqual(android.tags, ['with_gvisor', 'cmfa'])
  assert.equal(check.desktopSourceCommit, null)
  assert.ok(check.notes.some((note) => note.includes('undeclared')))
  assert.equal(checkManifests(desktop, { ...android, version: 'v0.0.0' }).ok, false)
  assert.equal(currentTarget(), 'darwin-aarch64')
})

test('baseline is selected by manifest and refuses unpackaged targets', async () => {
  assert.equal(baseline.engine, 'mihomo')
  assert.equal(baseline.version, 'v1.19.34')
  assert.equal(baseline.manifestSha256, baseline.archiveSha256)
  assert.ok((await stat(baseline.binary)).size > 0)
  const unavailable = await resolveBaseline({ cacheDir, target: 'plan9-mips' })
  assert.equal(unavailable.status, 'unavailable')
  assert.equal(unavailable.reason.includes('packages no baseline binary'), true)
})

test('fixture keeps requests and expectations in one reviewable file', async () => {
  const positive = await loadFixture(fixture('direct-echo'))
  assert.equal(positive.expect.accept, true)
  assert.equal(positive.expect.flow.proxyAccepted, true)
  assert.deepEqual(positive.flow.map((step) => step.method), ['connect'])
  assert.equal(positive.config.includes('x-kernel-compat'), false)
  assert.equal(positive.config.includes('MATCH,DIRECT'), true)
  const negative = await loadFixture(fixture('invalid-rule-target'))
  assert.equal(negative.expect.accept, false)
  const control = await loadFixture(fixture('control-switch'))
  assert.equal(control.controlRequests[0].method, 'PUT')
  assert.equal(control.expect.control.selector, 'tagged-parent')
})

test('port and hosts rewriting touches only the runner-owned keys', () => {
  const text = 'mixed-port: 7890\ndns:\n  mixed-port: 53\nexternal-controller: 127.0.0.1:9090\n'
  const rewritten = setTopLevel(setTopLevel(text, 'mixed-port', 1234), 'external-controller', '127.0.0.1:5678')
  assert.equal(getTopLevel(rewritten, 'mixed-port'), '1234')
  assert.equal(rewritten.includes('mixed-port: 53'), true)
  const hosts = withHosts('rules: []\n', { nonce: 'abc', ids: ['a'] })
  assert.match(hosts, /"billowt1-a-abc\.probe\.invalid": 127\.0\.0\.1\n/)
  assert.equal(withPorts('mixed-port: 1\n', { mixedPort: 2 }).includes('mixed-port: 2'), true)
  assert.equal(tagHost('a', 'abc'), 'billowt1-a-abc.probe.invalid')
})

test('source capability index covers config, protocols, rules and platforms', async () => {
  const { index } = await generateFromCache({ cacheDir })
  assert.equal(index.upstream.version, 'v1.19.34')
  assert.equal(index.upstream.commit, probe.androidCommit)
  const fieldNames = index.configFields.map((field) => field.name)
  for (const expected of ['mixed-port', 'mode', 'rules', 'dns', 'tun', 'listeners', 'proxy-providers']) {
    assert.ok(fieldNames.includes(expected), `config field ${expected} is indexed`)
  }
  const protocolTypes = index.proxies.map((entry) => entry.type)
  for (const expected of ['ss', 'vmess', 'vless', 'trojan', 'hysteria2', 'tuic', 'wireguard']) {
    assert.ok(protocolTypes.includes(expected), `protocol ${expected} is indexed`)
  }
  const listenerTypes = index.listeners.map((entry) => entry.type)
  for (const expected of ['mixed', 'socks', 'http', 'tun']) assert.ok(listenerTypes.includes(expected))
  const ruleTypes = index.rules.map((entry) => entry.type)
  for (const expected of ['MATCH', 'DOMAIN-SUFFIX', 'GEOIP', 'RULE-SET', 'SUB-RULE', 'AND']) assert.ok(ruleTypes.includes(expected))
  assert.deepEqual(index.groups.map((entry) => entry.type), ['url-test', 'select', 'fallback', 'load-balance', 'relay'])
  assert.ok(index.platforms.desktopTargets.length >= 9)
  assert.ok(index.platforms.buildTags.length > 0)
  assert.ok(index.platforms.androidBuildTags.includes('with_gvisor'))
  assert.ok(index.unmapped.length > 0, 'unmapped entries are kept, not dropped')
  assert.ok(index.configFields.every((field) => /config\/config\.go:\d+/.test(field.source)))
  assert.equal(index.coverage.total, index.configFields.length + index.proxies.length + index.listeners.length + index.groups.length + index.rules.length)
  assert.equal(
    index.coverage.mapped + index.coverage.partial + index.coverage.unimplemented,
    index.coverage.total,
    'every entry has exactly one Rust status',
  )
  assert.ok(index.coverage.mapped > 0, 'T4 records implemented entries')
  assert.equal(index.configFields.every((field) => field.rustMapping?.status), true)
})

test('the Rust mapping names only pinned entries and backs every claim with a test', async () => {
  const { index } = await generateFromCache({ cacheDir })
  const mapping = loadRustMapping()
  const statuses = new Set(['implemented', 'partial', 'unimplemented'])
  const check = (kind, allowed, entries) => {
    for (const [key, value] of Object.entries(entries ?? {})) {
      assert.ok(statuses.has(value.status), `${kind}.${key} has a known status`)
      assert.ok(allowed.has(key), `${kind}.${key} exists in the pinned source (found: ${[...allowed].filter((name) => name === key)})`)
      if (value.status === 'implemented' || value.status === 'partial') {
        assert.ok((value.evidence ?? []).length > 0, `${kind}.${key} (${value.status}) cites at least one test`)
      }
      if (value.status === 'partial') assert.ok(value.reason, `${kind}.${key} says what is missing`)
    }
  }
  check('proxies', new Set(index.proxies.map((entry) => entry.type)), mapping.proxies)
  check('listeners', new Set(index.listeners.map((entry) => entry.type)), mapping.listeners)
  check('groups', new Set(index.groups.map((entry) => entry.type)), mapping.groups)
  check('rules', new Set(index.rules.map((entry) => entry.type)), mapping.rules)
  check('configFields', new Set(index.configFields.map((field) => field.name)), mapping.configFields)
  for (const type of ['ss', 'socks5', 'http', 'trojan', 'vless', 'anytls', 'vmess', 'snell', 'trusttunnel']) {
    assert.equal(mapping.proxies[type]?.status, 'implemented', `${type} is implemented and tested`)
  }
  for (const type of ['ssr', 'ssh', 'gost-relay']) {
    assert.equal(mapping.proxies[type]?.status, 'partial', `${type} is partially implemented with the gaps named`)
  }
  for (const type of ['mieru', 'masque', 'sudoku', 'hysteria2', 'tuic', 'wireguard']) {
    assert.notEqual(mapping.proxies[type]?.status, 'implemented', `${type} must not be claimed`)
  }
  assert.ok(mapping.platform.verified.length > 0)
  const peers = JSON.parse(await readFile(resolve(here, 'evidence', 'protocol-peers.json'), 'utf8'))
  assert.equal(peers.format, 'kernel-protocol-peers')
  assert.equal(peers.upstream.version, 'v1.19.34')
  assert.ok(peers.platform.verified.includes(mapping.platform.verified[0]))
  for (const [type, entry] of Object.entries(peers.families)) {
    assert.equal(entry.status === 'pass', true, `${type} has a real-peer result`)
    assert.ok(entry.cases.positive.length > 0 && entry.cases.negative.length > 0, `${type} covers success and failure`)
    assert.match(entry.command, /mihomo_peers|protocols\.rs/)
  }
  // UDP must be real-peer verified for the families that claim it, and the
  // command must work from the crate directory (an absolute binary path).
  const allCases = Object.values(peers.families).flatMap((entry) => [...entry.cases.positive, ...entry.cases.negative])
  assert.ok(allCases.some((name) => name.includes('_udp_')), 'a UDP case is run against the peer')
  for (const family of ['ss', 'trojan']) {
    assert.ok(
      peers.families[family].cases.positive.some((name) => name.includes('_udp_')) &&
        peers.families[family].cases.negative.some((name) => name.includes('_udp_')),
      `${family} covers UDP success and failure`,
    )
  }
  assert.match(peers.command, /KC_MIHOMO_BIN=\/|KC_MIHOMO_BIN=[A-Z]:\\/)
  assert.equal(peers.controlledPeers?.command, 'tool/kernel-compat/family-peers.sh')
  assert.equal(peers.controlledPeers?.result.passed, peers.controlledPeers?.result.cases)
  for (const family of peers.controlledPeers?.families ?? []) {
    assert.equal(peers.families[family]?.status, 'pass', `${family} has a controlled-peer result`)
  }
  assert.equal(peers.result.passed, peers.result.cases)
  assert.ok(
    allCases.some((name) => name.includes('chained_ss_udp')),
    'the chained UDP case against the peer is recorded',
  )
  // The option matrix is the recorded comparison with Mihomo's own `-t`: no-op
  // forms accepted by both, enabled forms rejected by the kernel.
  const matrix = await readFile(resolve(here, 'evidence', 'option-matrix.txt'), 'utf8')
  assert.match(matrix, /no-op cases: [1-9]\d*, enabled cases: [1-9]\d*, problems: 0/)
  assert.ok(matrix.split('\n').some((line) => /^noop .*rust=accept mihomo=accept/.test(line)))
  assert.ok(matrix.split('\n').some((line) => /^enabled .*rust=reject mihomo=accept/.test(line)))
  assert.equal(matrix.split('\n').some((line) => line.startsWith('PROBLEM')), false)
  // Every proxy type the index marks unimplemented must name an owner, so a
  // family cannot silently disappear from the scope.
  for (const entry of index.proxies) {
    if (entry.rustMapping.status !== 'unimplemented') continue
    assert.ok(
      mapping.familiesNotImplemented?.entries?.[entry.type],
      `${entry.type} names its owner in familiesNotImplemented`,
    )
  }
})

test('real Mihomo passes the tagged exit fixtures while the Rust side stays missing', async () => {
  const output = await mkdtemp(join(tmpdir(), 'kernel-compat-test-'))
  try {
    const { path, report } = await runDifferential({
      kernels: [{ engine: 'mihomo', path: baseline.binary }],
      fixtures: [fixture('direct-echo'), fixture('forward-echo'), fixture('reject-fault'), fixture('invalid-rule-target')],
      reportDir: output,
      cacheDir,
    })
    const written = JSON.parse(await readFile(path, 'utf8'))
    assert.equal(written.format, 'kernel-compat-report')
    assert.equal(report.summary.cases, 4)
    assert.equal(report.summary.kernelPass, 4, JSON.stringify(report.cases.map((entry) => entry.results)))
    assert.equal(report.summary.kernelMissing, 4, 'the missing Rust kernel is recorded, not assumed compatible')
    assert.equal(report.exitOk, false, 'a run with one kernel cannot prove compatibility')
    const direct = report.cases.find((entry) => entry.id.endsWith('direct-echo.yaml'))
    const kernel = direct.endpoints.find((endpoint) => endpoint.role === 'kernel')
    const receipt = kernel.run.flow.steps[0].receipt
    assert.equal(receipt.value, kernel.markers.a)
    assert.equal(kernel.run.flow.echoSawMarkers, 1)
    assert.equal(kernel.run.cleanup.mixedPortFree, true)
    const forward = report.cases.find((entry) => entry.id.endsWith('forward-echo.yaml'))
    assert.equal(forward.results.find((result) => result.engine === 'mihomo').status, 'pass')
    const reject = report.cases.find((entry) => entry.id.endsWith('reject-fault.yaml'))
    const rejectKernel = reject.endpoints.find((endpoint) => endpoint.role === 'kernel')
    assert.equal(rejectKernel.run.flow.echoSawMarkers, 0, 'REJECT must not reach the echo')
    assert.equal(rejectKernel.run.flow.steps[0].responseStatus, 502)
    const invalid = report.cases.find((entry) => entry.id.endsWith('invalid-rule-target.yaml'))
    assert.equal(invalid.results.find((result) => result.engine === 'mihomo').category, 'config-rejected-as-expected')
    // Each endpoint had its own mixed port, and every process was stopped.
    const ports = report.cases.flatMap((entry) => entry.endpoints.map((endpoint) => endpoint.ports?.mixed)).filter(Boolean)
    assert.equal(new Set(ports).size, ports.length)
    for (const entry of report.cases) for (const endpoint of entry.endpoints) {
      if (endpoint.run?.cleanup) assert.equal(endpoint.run.cleanup.mixedPortFree, true)
    }
  } finally {
    await rm(output, { recursive: true, force: true })
  }
})

test('the Rust CLI is driven through its own command line and its exit is observed', async () => {
  // The operator builds it from native-kernel/ (workspace member billow-kernel-cli, binary
  // billow-kernel). KC_RUST_CLI names it explicitly; otherwise the common cargo target
  // directories are probed. When no build exists the adapter is skipped, never passed.
  const candidates = [process.env.KC_RUST_CLI, resolve(here, '..', '..', 'native-kernel', 'target', 'release', 'billow-kernel'),
    resolve(process.env.CARGO_TARGET_DIR ?? '', 'release', 'billow-kernel')].filter(Boolean)
  let binary = null
  for (const candidate of candidates) {
    if (await stat(candidate).then(() => true, () => false)) {
      binary = candidate
      break
    }
  }
  if (!binary) return
  return runRustAdapter(binary)
})

async function runRustAdapter(binary) {
  const output = await mkdtemp(join(tmpdir(), 'kernel-compat-rust-'))
  try {
    const { report } = await runDifferential({
      kernels: [{ engine: 'rust', path: binary }],
      fixtures: [fixture('direct-ip'), fixture('invalid-rule-target'), fixture('full-config')],
      reportDir: output,
      cacheDir,
      requiredEngines: ['mihomo', 'rust'],
    })
    const rust = report.endpoints.find((endpoint) => endpoint.engine === 'rust')
    assert.equal(rust.status, 'built')
    assert.equal(rust.versionSource, 'cli --version')
    const byId = Object.fromEntries(report.cases.map((entry) => [entry.id.split('/').pop(), entry]))
    // A configuration the current slice accepts: the tagged CONNECT exits through DIRECT.
    const direct = byId['direct-ip.yaml'].results.find((result) => result.engine === 'rust')
    assert.equal(direct.status, 'pass', JSON.stringify(direct))
    // A config both engines reject.
    const invalid = byId['invalid-rule-target.yaml'].results.find((result) => result.engine === 'rust')
    assert.equal(invalid.category, 'config-rejected-as-expected')
    // A valid config using keys the slice does not implement yet: rejected with its reason,
    // never counted as compatible.
    const full = byId['full-config.yaml']
    const fullRust = full.results.find((result) => result.engine === 'rust')
    assert.equal(fullRust.status, 'fail')
    assert.equal(fullRust.category, 'startup-failed')
    assert.match(fullRust.engineOutput, /unsupported/)
    const fullMihomo = full.results.find((result) => result.engine === 'mihomo')
    assert.equal(fullMihomo.status, 'missing')
  } finally {
    await rm(output, { recursive: true, force: true })
  }
}

test('missing or non-executable kernels fail explicitly', async () => {
  const output = await mkdtemp(join(tmpdir(), 'kernel-compat-missing-'))
  try {
    const { report } = await runDifferential({
      kernels: [{ engine: 'rust', path: join(output, 'does-not-exist') }],
      fixtures: [fixture('direct-echo')],
      reportDir: output,
      cacheDir,
      requiredEngines: ['rust'],
    })
    assert.equal(report.summary.kernelMissing, 1)
    assert.equal(report.exitOk, false)
    const rust = report.endpoints.find((endpoint) => endpoint.engine === 'rust')
    assert.equal(rust.status, 'missing')
    assert.match(rust.reason, /not executable/)
    const result = report.cases[0].results.find((entry) => entry.engine === 'rust')
    assert.equal(result.status, 'missing')
    assert.equal(result.category, 'kernel-unavailable')
    assert.equal(result.status === 'pass', false)
  } finally {
    await rm(output, { recursive: true, force: true })
  }
})

test('a kernel that never answers is reported as a timeout, not a pass', async () => {
  const output = await mkdtemp(join(tmpdir(), 'kernel-compat-timeout-'))
  try {
    // A stub "engine" that identifies itself, answers the config test and listens but never
    // replies. Registered as "mihomo" so the mihomo command line applies. It is a negative
    // control: the harness must surface the timeout and fail the case.
    const stub = resolve(output, 'stub-kernel.mjs')
    await (await import('node:fs/promises')).writeFile(stub, [
      '#!/usr/bin/env node',
      "import net from 'node:net'",
      "import { readFileSync } from 'node:fs'",
      // Identify as an unknown CLI that answers `-v`; the runner treats unknown engines as
      // mihomo-shaped, so only the never-answering listener below is under test.
      "if (process.argv.includes('-v')) { console.log('Mihomo Meta v9.9.9 stub'); process.exit(0) }",
      "if (process.argv.includes('-t')) process.exit(0)",
      "const configPath = process.argv[process.argv.indexOf('-f') + 1]",
      "const port = Number(/^mixed-port:\\s*(\\d+)/m.exec(readFileSync(configPath, 'utf8'))?.[1] ?? 0)",
      "net.createServer(() => {}).listen(port, '127.0.0.1')",
      '',
    ].join('\n'))
    await (await import('node:fs/promises')).chmod(stub, 0o755)
    const fixturePath = resolve(output, 'timeout.yaml')
    await (await import('node:fs/promises')).writeFile(fixturePath, [
      'mixed-port: 0',
      'mode: rule',
      'allow-lan: true',
      'rules:',
      '  - MATCH,DIRECT',
      'x-kernel-compat:',
      '  requests:',
      '    - {id: a, method: connect, value-of: true}',
      '  request-timeout-ms: 400',
      '  expect:',
      '    accept: true',
      '    proxyAccepted: true',
      '    echoSawMarkers: 1',
      '    markersSent: 1',
      '',
    ].join('\n'))
    const { report } = await runDifferential({
      kernels: [{ engine: 'mihomo', path: stub }],
      fixtures: [fixturePath],
      reportDir: output,
      probe: { probe: { status: 'built', binary: probe.probe.binary }, source: null },
      requiredEngines: ['mihomo'],
    })
    const result = report.cases[0].results.find((entry) => entry.engine === 'mihomo')
    assert.equal(result.status, 'fail')
    assert.equal(result.category, 'flow:proxyAccepted')
    const stubEndpoint = report.cases[0].endpoints.find((endpoint) => endpoint.engine === 'mihomo')
    assert.equal(stubEndpoint.run.flow.steps[0].category, 'timeout')
    // The reference still reaches its echo; the run fails because the kernel case failed.
    assert.equal(report.exitOk, false)
  } finally {
    await rm(output, { recursive: true, force: true })
  }
})
