#!/usr/bin/env node
// T24 differential probe: runs the same rule/provider/geodata configuration
// against the pinned Mihomo v1.19.34 binary and the Rust kernel, records what
// each CONNECT attempt actually did, and fails when the two engines disagree.
//
// Offline resources: every provider URL is served by a loopback HTTP server
// started here; GeoSite.dat/GeoIP.dat are generated from the protobuf shapes in
// the pinned source; MRS uses the checked-in `src-tauri/testdata/domain.mrs`.
// Optional `--mmdb-dir` adds the Country.mmdb/ASN.mmdb cases (decompress the
// bundled `src-tauri/resources/runtime/geo/*.mmdb.br` first, see README T24).
//
// Command:
//   node tool/kernel-compat/t24-differential.mjs \
//     --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
//     --rust native-kernel/target/debug/billow-kernel \
//     --out tool/kernel-compat/evidence/t24-differential.json
import { spawn } from 'node:child_process'
import { mkdtemp, copyFile, mkdir, rm, writeFile } from 'node:fs/promises'
import http from 'node:http'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { reservePort } from './ports.mjs'
import { openTunnel } from './process.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '../..')

// ---------------------------------------------------------------------------
// Protobuf fixtures
// ---------------------------------------------------------------------------

function varint(value) {
  const out = []
  let current = value
  do {
    let byte = current & 0x7f
    current >>>= 7
    if (current) byte |= 0x80
    out.push(byte)
  } while (current)
  return Buffer.from(out)
}

const fieldBytes = (field, bytes) => Buffer.concat([varint((field << 3) | 2), varint(bytes.length), bytes])
const fieldVarint = (field, value) => Buffer.concat([varint(field << 3), varint(value)])
const text = (value) => Buffer.from(value)

function domain(type, value, attrs = []) {
  let out = Buffer.concat([fieldVarint(1, type), fieldBytes(2, text(value))])
  if (attrs.length) out = Buffer.concat([out, ...attrs.map((attr) => fieldBytes(3, fieldBytes(1, text(attr))))])
  return out
}

function geositeDat(lists) {
  return Buffer.concat(lists.map((list) => fieldBytes(1, Buffer.concat([
    fieldBytes(1, text(list.code)),
    ...list.domains.map((entry) => fieldBytes(2, entry)),
  ]))))
}

function geoipDat(countries) {
  return Buffer.concat(countries.map((country) => {
    const entry = Buffer.concat([
      fieldBytes(1, text(country.code)),
      ...country.cidrs.map(({ bytes, prefix }) => fieldBytes(2, Buffer.concat([
        fieldBytes(1, Buffer.from(bytes)),
        fieldVarint(2, prefix),
      ]))),
    ])
    return fieldBytes(1, entry)
  }))
}

const ipv4 = (a, b, c, d) => [a, b, c, d]

// An HTTP echo with a fixed Content-Length. The shared `startEcho` uses
// chunked responses, which `openTunnel.write` (Content-Length based) cannot
// delimit; this endpoint is what the CONNECT client actually reads through.
function startEchoServer() {
  const server = net.createServer((socket) => {
    let buffered = Buffer.alloc(0)
    socket.on('data', (chunk) => {
      buffered = Buffer.concat([buffered, chunk])
      const headEnd = buffered.indexOf('\r\n\r\n')
      if (headEnd < 0) return
      const head = buffered.slice(0, headEnd).toString('utf8')
      const length = Number(/content-length: *(\d+)/i.exec(head)?.[1] ?? 0)
      const body = buffered.slice(headEnd + 4)
      if (body.length < length) return
      let marker = null
      try { marker = JSON.parse(body.slice(0, length).toString('utf8')).marker ?? null } catch { marker = null }
      const reply = Buffer.from(JSON.stringify({ marker, receivedBytes: body.length }))
      socket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${reply.length}\r\nConnection: close\r\n\r\n`)
      socket.write(reply)
      socket.end()
    })
    socket.on('error', () => socket.destroy())
  })
  return new Promise((resolveServer) => {
    server.listen(0, '0.0.0.0', () => {
      const { port } = server.address()
      resolveServer({ host: '0.0.0.0', port, close: () => new Promise((done) => server.close(done)) })
    })
  })
}

// ---------------------------------------------------------------------------
// Local provider HTTP server
// ---------------------------------------------------------------------------

function startProviderServer(routes) {
  const state = new Map(Object.entries(routes).map(([path, value]) => [path, { ...value }]))
  const server = http.createServer((request, response) => {
    const route = state.get(request.url)
    if (!route) {
      response.writeHead(404).end('not found')
      return
    }
    response.writeHead(route.status ?? 200, { 'content-type': 'application/octet-stream' })
    response.end(route.body)
  })
  return new Promise((resolveServer, rejectServer) => {
    server.once('error', rejectServer)
    server.listen(0, '127.0.0.1', () => {
      resolveServer({
        port: server.address().port,
        set(path, value) { state.set(path, { ...value }) },
        close: () => new Promise((done) => server.close(done)),
      })
    })
  })
}

// ---------------------------------------------------------------------------
// Child processes and one CONNECT attempt
// ---------------------------------------------------------------------------

function startProcess(command, args, cwd) {
  const logs = { stdout: '', stderr: '' }
  const child = spawn(command, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] })
  child.stdout.on('data', (chunk) => { logs.stdout = (logs.stdout + chunk).slice(-8000) })
  child.stderr.on('data', (chunk) => { logs.stderr = (logs.stderr + chunk).slice(-8000) })
  const exited = new Promise((done) => child.once('exit', (code, signal) => done({ code, signal })))
  return { child, logs, exited }
}

async function waitPort(port, timeoutMs = 15000) {
  const started = performance.now()
  while (performance.now() - started < timeoutMs) {
    const ok = await new Promise((resolveProbe) => {
      const socket = new net.Socket()
      socket.setTimeout(300)
      socket.once('connect', () => { socket.destroy(); resolveProbe(true) })
      socket.once('timeout', () => { socket.destroy(); resolveProbe(false) })
      socket.once('error', () => resolveProbe(false))
      socket.connect(port, '127.0.0.1')
    })
    if (ok) return true
    await new Promise((done) => setTimeout(done, 100))
  }
  return false
}

async function stopProcess(handle) {
  if (!handle) return
  handle.child.kill('SIGTERM')
  const result = await Promise.race([handle.exited, new Promise((done) => setTimeout(() => done({ timeout: true }), 4000))])
  if (result.timeout) {
    handle.child.kill('SIGKILL')
    await handle.exited
  }
}

async function attempt(mixedPort, host, targetPort) {
  const exchange = await openTunnel({
    host: '127.0.0.1',
    port: mixedPort,
    target: { host, port: targetPort },
    connectTimeoutMs: 3000,
  })
  if (exchange.error) {
    return { category: exchange.error.name === 'TimeoutError' ? 'timeout' : 'closed', connectStatus: 0, error: exchange.error.message }
  }
  const status = exchange.response.status
  if (status !== 200) {
    await exchange.close()
    return { category: 'blocked', connectStatus: status }
  }
  try {
    const payload = 'POST /probe HTTP/1.1\r\nHost: probe\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{"marker":"t24ok"}'
    const reply = await exchange.write(payload, 3000)
    return {
      category: reply.includes('t24ok') ? 'echoed' : 'empty',
      connectStatus: status,
      replyBytes: reply.length,
      reply: reply.includes('t24ok') ? null : reply.slice(0, 240),
    }
  } catch (error) {
    return { category: 'timeout', connectStatus: status, error: error.message }
  } finally {
    await exchange.close()
  }
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

const domainRules = (rule, target = 'localhost') => ({
  rules: [`${rule},REJECT`, 'MATCH,DIRECT'],
  target: { host: target, port: 'echo' },
})

const cases = [
  { id: 'domain-exact-hit', expect: 'blocked', ...domainRules('DOMAIN,localhost') },
  { id: 'domain-suffix-hit', expect: 'blocked', ...domainRules('DOMAIN-SUFFIX,localhost') },
  { id: 'domain-keyword-hit', expect: 'blocked', ...domainRules('DOMAIN-KEYWORD,local') },
  { id: 'domain-wildcard-hit', expect: 'blocked', ...domainRules('DOMAIN-WILDCARD,local*') },
  { id: 'domain-regex-hit', expect: 'blocked', ...domainRules('DOMAIN-REGEX,^localho.*$') },
  { id: 'domain-exact-miss', expect: 'echoed', ...domainRules('DOMAIN,not-localhost', 'localhost') },
  { id: 'dst-port-hit', expect: 'blocked', rules: ['DST-PORT,{{echo}},REJECT', 'MATCH,DIRECT'], target: { host: '127.0.0.1', port: 'echo' } },
  { id: 'dst-port-miss', expect: 'echoed', rules: ['DST-PORT,{{echo+1}},REJECT', 'MATCH,DIRECT'], target: { host: '127.0.0.1', port: 'echo' } },
  { id: 'network-tcp-hit', expect: 'blocked', rules: ['NETWORK,TCP,REJECT', 'MATCH,DIRECT'], target: { host: '127.0.0.1', port: 'echo' } },
  { id: 'in-type-https-hit', expect: 'blocked', rules: ['IN-TYPE,HTTPS,REJECT', 'MATCH,DIRECT'], target: { host: '127.0.0.1', port: 'echo' } },
  { id: 'in-type-socks-miss', expect: 'echoed', rules: ['IN-TYPE,SOCKS5,REJECT', 'MATCH,DIRECT'], target: { host: '127.0.0.1', port: 'echo' } },
  { id: 'in-type-http-miss', expect: 'echoed', rules: ['IN-TYPE,HTTP,REJECT', 'MATCH,DIRECT'], target: { host: '127.0.0.1', port: 'echo' } },
  { id: 'in-port-hit', expect: 'blocked', rules: ['IN-PORT,{{mixed}},REJECT', 'MATCH,DIRECT'], target: { host: '127.0.0.1', port: 'echo' } },
  { id: 'src-ip-cidr-hit', expect: 'blocked', rules: ['SRC-IP-CIDR,127.0.0.0/8,REJECT', 'MATCH,DIRECT'], target: { host: '127.0.0.1', port: 'echo' } },
  { id: 'ip-cidr-hit', expect: 'blocked', rules: ['IP-CIDR,127.0.0.1/32,REJECT', 'MATCH,DIRECT'], target: { host: '127.0.0.1', port: 'echo' } },
  { id: 'ip-cidr-miss', expect: 'echoed', rules: ['IP-CIDR,10.0.0.0/8,REJECT', 'MATCH,DIRECT'], target: { host: '127.0.0.1', port: 'echo' } },
  { id: 'first-match-wins', expect: 'echoed', rules: ['DOMAIN,localhost,DIRECT', 'DOMAIN-SUFFIX,localhost,REJECT', 'MATCH,REJECT'], target: { host: 'localhost', port: 'echo' } },
  {
    id: 'rule-set-inline',
    expect: 'blocked',
    ruleProviders: { inline: '  inline:\n    type: inline\n    behavior: domain\n    payload: [\'+.localhost\']\n' },
    rules: ['RULE-SET,inline,REJECT', 'MATCH,DIRECT'],
    target: { host: 'localhost', port: 'echo' },
  },
  {
    id: 'rule-set-file-text',
    expect: 'blocked',
    files: { 'providers/domain.txt': '+.localhost\n' },
    ruleProviders: { text: "  text:\n    type: file\n    behavior: domain\n    format: text\n    path: providers/domain.txt\n" },
    rules: ['RULE-SET,text,REJECT', 'MATCH,DIRECT'],
    target: { host: 'localhost', port: 'echo' },
  },
  {
    id: 'rule-set-file-yaml-ip',
    expect: 'blocked',
    files: { 'providers/ip.yaml': 'payload:\n  - 127.0.0.1/32\n' },
    ruleProviders: { yamlip: "  yamlip:\n    type: file\n    behavior: ipcidr\n    format: yaml\n    path: providers/ip.yaml\n" },
    rules: ['RULE-SET,yamlip,REJECT', 'MATCH,DIRECT'],
    target: { host: '127.0.0.1', port: 'echo' },
  },
  {
    id: 'rule-set-file-mrs',
    expect: 'blocked',
    mrs: true,
    ruleProviders: { mrs: "  mrs:\n    type: file\n    behavior: domain\n    format: mrs\n    path: providers/rules.mrs\n" },
    rules: ['RULE-SET,mrs,REJECT', 'MATCH,DIRECT'],
    target: { host: 'www.google.com', port: 'echo' },
  },
  {
    id: 'rule-set-http',
    expect: 'blocked',
    httpProvider: '/rules.yaml',
    ruleProviders: { remote: "  remote:\n    type: http\n    behavior: domain\n    format: yaml\n    url: http://127.0.0.1:{{provider}}/rules.yaml\n" },
    rules: ['RULE-SET,remote,REJECT', 'MATCH,DIRECT'],
    target: { host: 'localhost', port: 'echo' },
  },
  {
    id: 'logic-and-hit',
    expect: 'blocked',
    rules: ['AND,((NETWORK,TCP),(DOMAIN,localhost)),REJECT', 'MATCH,DIRECT'],
    target: { host: 'localhost', port: 'echo' },
  },
  {
    id: 'logic-not-miss',
    expect: 'echoed',
    rules: ['NOT,((DOMAIN,localhost)),REJECT', 'MATCH,DIRECT'],
    target: { host: 'localhost', port: 'echo' },
  },
  {
    id: 'sub-rule-hit',
    expect: 'blocked',
    subRules: "sub-rules:\n  branch:\n    - DOMAIN,localhost,REJECT\n    - MATCH,DIRECT\n",
    rules: ['SUB-RULE,(NETWORK,TCP),branch', 'MATCH,DIRECT'],
    target: { host: 'localhost', port: 'echo' },
  },
  {
    id: 'geosite-dat-hit',
    expect: 'blocked',
    geodata: 'dat',
    rules: ['GEOSITE,test,REJECT', 'MATCH,DIRECT'],
    target: { host: 'localhost', port: 'echo' },
  },
  {
    id: 'geoip-dat-hit',
    expect: 'blocked',
    geodata: 'dat',
    rules: ['GEOIP,zz,REJECT', 'MATCH,DIRECT'],
    target: { host: '127.0.0.1', port: 'echo' },
  },
  {
    id: 'geoip-lan-direct',
    expect: 'echoed',
    geodata: 'dat',
    rules: ['GEOIP,lan,DIRECT', 'MATCH,REJECT'],
    target: { host: '127.0.0.1', port: 'echo' },
  },
  {
    id: 'geoip-mmdb-hit',
    expect: 'blocked',
    geodata: 'mmdb',
    rules: ['GEOIP,au,REJECT', 'MATCH,DIRECT'],
    target: { host: '1.1.1.1', port: 'echo' },
  },
  {
    id: 'ip-asn-mmdb-hit',
    expect: 'blocked',
    geodata: 'mmdb',
    rules: ['IP-ASN,13335,REJECT', 'MATCH,DIRECT'],
    target: { host: '1.1.1.1', port: 'echo' },
  },
]

const formatRule = (rule, context) => rule
  .replace('{{echo}}', String(context.echoPort))
  .replace('{{echo+1}}', String(context.echoPort + 1))
  .replace('{{mixed}}', String(context.mixedPort))
  .replace('{{provider}}', String(context.providerPort))

function buildConfig(item, context, extra = {}) {
  const format = (value) => value
    .replaceAll('{{echo}}', String(context.echoPort))
    .replaceAll('{{echo+1}}', String(context.echoPort + 1))
    .replaceAll('{{mixed}}', String(context.mixedPort))
    .replaceAll('{{provider}}', String(context.providerPort))
  const lines = ['mixed-port: ' + context.mixedPort, 'mode: rule', 'log-level: info']
  if (item.geodata === 'dat') lines.push('geodata-mode: true')
  if (item.geodata === 'mmdb') lines.push('geodata-mode: false')
  if (item.ruleProviders) {
    lines.push('rule-providers:')
    for (const fragment of Object.values(item.ruleProviders)) lines.push(format(fragment).trimEnd())
  }
  if (item.subRules) lines.push(format(item.subRules).trimEnd())
  lines.push('rules:')
  for (const rule of item.rules) lines.push('  - ' + format(rule))
  if (extra.controllerPort) lines.push(`external-controller: 127.0.0.1:${extra.controllerPort}`)
  return lines.join('\n') + '\n'
}

async function prepareCase(item, dir, server) {
  if (item.files) {
    for (const [name, body] of Object.entries(item.files)) {
      const path = join(dir, name)
      await mkdir(dirname(path), { recursive: true })
      await writeFile(path, body)
    }
  }
  if (item.mrs) {
    await mkdir(join(dir, 'providers'), { recursive: true })
    await copyFile(join(repoRoot, 'src-tauri/testdata/domain.mrs'), join(dir, 'providers/rules.mrs'))
  }
  if (server && item.httpProvider) server.set(item.httpProvider, { status: 200, body: "payload:\n  - '+.localhost'\n" })
  if (item.geodata === 'dat') {
    await writeFile(join(dir, 'GeoSite.dat'), geositeDat([
      { code: 'CN', domains: [domain(3, 'localhost')] },
      { code: 'test', domains: [domain(3, 'localhost'), domain(2, 'example.test'), domain(0, 'keyword'), domain(3, 'attr.test', ['ads'])] },
    ]))
    await writeFile(join(dir, 'GeoIP.dat'), geoipDat([
      { code: 'CN', cidrs: [{ bytes: ipv4(10, 0, 0, 0), prefix: 8 }] },
      { code: 'zz', cidrs: [{ bytes: ipv4(127, 0, 0, 1), prefix: 32 }] },
    ]))
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = { mihomo: null, rust: null, out: null, mmdbDir: null }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--mihomo') args.mihomo = resolve(argv[++index])
    else if (arg === '--rust') args.rust = resolve(argv[++index])
    else if (arg === '--out') args.out = resolve(argv[++index])
    else if (arg === '--mmdb-dir') args.mmdbDir = resolve(argv[++index])
    else throw new Error(`unknown argument ${arg}`)
  }
  if (!args.mihomo || !args.rust || !args.out) throw new Error('usage: --mihomo <binary> --rust <binary> --out <json> [--mmdb-dir <dir>]')
  return args
}

async function runKernel(engine, binary, item, dir, context, controllerPort) {
  const config = buildConfig(item, context, { controllerPort })
  await writeFile(join(dir, 'config.yaml'), config)
  const args = engine === 'mihomo'
    ? ['-d', dir, '-f', join(dir, 'config.yaml')]
    : [join(dir, 'config.yaml'), '--port', String(context.mixedPort), '--geosite-dir', dir]
  const handle = startProcess(binary, args, dir)
  const ready = await waitPort(context.mixedPort)
  const result = { engine, ready, config, logs: handle.logs }
  if (!ready) {
    await stopProcess(handle)
    return result
  }
  result.observation = await attempt(context.mixedPort, item.target.host, context.echoPort)
  await stopProcess(handle)
  return result
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  const echo = await startEchoServer()
  const server = await startProviderServer({})
  const sandbox = await mkdtemp(join(tmpdir(), 'billow-t24-diff-'))
  const results = []
  try {
    for (const item of cases) {
      if (item.geodata === 'mmdb' && !args.mmdbDir) {
        results.push({ id: item.id, status: 'skipped', reason: 'pass --mmdb-dir with decompressed Country.mmdb/ASN.mmdb' })
        continue
      }
      const mixedByEngine = {}
      const dir = join(sandbox, item.id)
      await mkdir(dir, { recursive: true })
      await prepareCase(item, dir, server)
      if (item.geodata === 'mmdb') {
        await copyFile(join(args.mmdbDir, 'Country.mmdb'), join(dir, 'Country.mmdb'))
        await copyFile(join(args.mmdbDir, 'ASN.mmdb'), join(dir, 'ASN.mmdb'))
        await writeFile(join(dir, 'GeoSite.dat'), geositeDat([{ code: 'CN', domains: [domain(3, 'localhost')] }]))
      }
      const entry = { id: item.id, expect: item.expect, engines: {} }
      for (const engine of ['mihomo', 'rust']) {
        const context = {
          echoPort: echo.port,
          mixedPort: await reservePort(),
          providerPort: server.port,
        }
        mixedByEngine[engine] = context.mixedPort
        entry.engines[engine] = await runKernel(engine, engine === 'mihomo' ? args.mihomo : args.rust, item, dir, context)
      }
      const mihomo = entry.engines.mihomo
      const rust = entry.engines.rust
      const mihomoCategory = mihomo.observation?.category ?? 'startup-failed'
      const rustCategory = rust.observation?.category ?? 'startup-failed'
      const normalize = (category) => ['blocked', 'closed', 'timeout'].includes(category) ? 'blocked' : category
      const normalized = { mihomo: normalize(mihomoCategory), rust: normalize(rustCategory) }
      entry.observed = { mihomo: mihomoCategory, rust: rustCategory, normalized }
      const matchesExpect = (category) => item.expect === 'blocked'
        ? category === 'blocked'
        : category === item.expect
      entry.status = normalized.mihomo === normalized.rust && matchesExpect(normalized.rust) ? 'pass'
        : normalized.mihomo !== normalized.rust ? 'differ'
          : 'unexpected'
      results.push(entry)
    }

    // Update semantics against Mihomo's control API. Rust's equivalent is
    // covered by tests/resources.rs (no control endpoint until T25).
    const updateDir = join(sandbox, 'provider-update')
    await mkdir(updateDir, { recursive: true })
    server.set('/update.yaml', { status: 200, body: "payload:\n  - '+.localhost'\n" })
    const providerPort = server.port
    const controllerPort = await reservePort()
    const context = { echoPort: echo.port, mixedPort: await reservePort(), providerPort }
    const updateItem = {
      rules: ['RULE-SET,remote,REJECT', 'MATCH,DIRECT'],
      ruleProviders: { remote: "  remote:\n    type: http\n    behavior: domain\n    format: yaml\n    url: http://127.0.0.1:{{provider}}/update.yaml\n" },
      target: { host: 'localhost', port: 'echo' },
    }
    const binary = args.mihomo
    const config = buildConfig(updateItem, context, { controllerPort })
    await writeFile(join(updateDir, 'config.yaml'), config)
    const handle = startProcess(binary, ['-d', updateDir, '-f', join(updateDir, 'config.yaml')], updateDir)
    const ready = await waitPort(context.mixedPort)
    const update = { id: 'mihomo-provider-update', ready, attempts: [] }
    if (ready) {
      update.attempts.push({ phase: 'initial', ...(await attempt(context.mixedPort, 'localhost', echo.port)) })
      server.set('/update.yaml', { status: 200, body: "payload:\n  - '+.other.invalid'\n" })
      update.putAfterChange = await fetch(`http://127.0.0.1:${controllerPort}/providers/rules/remote`, { method: 'PUT' }).then((r) => r.status).catch((e) => e.message)
      update.attempts.push({ phase: 'after-success', ...(await attempt(context.mixedPort, 'localhost', echo.port)) })
      server.set('/update.yaml', { status: 500, body: '' })
      update.putAfterFailure = await fetch(`http://127.0.0.1:${controllerPort}/providers/rules/remote`, { method: 'PUT' }).then((r) => r.status).catch((e) => e.message)
      update.attempts.push({ phase: 'after-failure', ...(await attempt(context.mixedPort, 'localhost', echo.port)) })
      update.status = update.putAfterChange === 204
        && update.putAfterFailure === 503
        && ['blocked', 'closed', 'timeout'].includes(update.attempts[0].category)
        && update.attempts[1].category === 'echoed'
        && update.attempts[2].category === 'echoed'
        ? 'pass' : 'unexpected'
    } else {
      update.status = 'startup-failed'
    }
    await stopProcess(handle)
    results.push(update)

    const framingDifferences = results.filter((entry) => entry.observed
      && entry.observed.mihomo !== entry.observed.rust
      && entry.observed.normalized?.mihomo === entry.observed.normalized?.rust).length
    const summary = {
      cases: results.length,
      framingDifferences,
      pass: results.filter((entry) => entry.status === 'pass').length,
      differ: results.filter((entry) => entry.status === 'differ').length,
      unexpected: results.filter((entry) => entry.status === 'unexpected').length,
      skipped: results.filter((entry) => entry.status === 'skipped').length,
      startupFailed: results.filter((entry) => entry.status === 'startup-failed').length,
    }
    const report = {
      format: 't24-differential',
      version: 1,
      startedAt: new Date().toISOString(),
      mihomo: args.mihomo,
      rust: args.rust,
      mmdbDir: args.mmdbDir,
      echo: { host: echo.host, port: echo.port },
      summary,
      framingNote: 'Mihomo answers HTTP CONNECT with 200 before rule evaluation and then closes a REJECT tunnel; the Rust mixed inbound answers REJECT with 403/502. The normalized rule outcome is compared (blocked vs echoed); inbound reply framing is not a T24 claim.',
      results: results.map((entry) => ({
        ...entry,
        engines: entry.engines && Object.fromEntries(Object.entries(entry.engines).map(([engine, value]) => [engine, {
          ready: value.ready,
          observation: value.observation ?? null,
          config: value.config ?? null,
          stderr: value.logs?.stderr?.slice(-1200) ?? null,
        }])),
      })),
      exitOk: summary.differ === 0 && summary.unexpected === 0 && summary.startupFailed === 0,
    }
    await writeFile(args.out, JSON.stringify(report, null, 2))
    console.log(JSON.stringify(summary))
    process.exitCode = report.exitOk ? 0 : 1
  } finally {
    await echo.close()
    await server.close()
    await rm(sandbox, { recursive: true, force: true }).catch(() => null)
  }
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 2
})
