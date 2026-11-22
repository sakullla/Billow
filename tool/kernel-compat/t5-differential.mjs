#!/usr/bin/env node
// T5 combined differential: one configuration that uses DNS (fake-ip), hosts,
// rule-providers (yaml/text/mrs/http), a proxy-provider, rule types
// (RULE-SET/GEOSITE/GEOIP/AND), select/url-test/fallback groups, the control
// API and three real outbounds (ss, trojan, ssr) at once.
//
// Peers are controlled local servers:
//   - ss/trojan: the pinned Mihomo binary itself as a `listeners:` server with a
//     fixed password (one process per protocol so a stop test is possible);
//   - ssr: the independent Go server in `peers/ssr-server` built from the locked
//     `transport/shadowsocks` packages (origin/plain, aes-256-cfb).
// Both engines run the same YAML (only their own listener ports differ), answer
// DNS on `dns.listen`, take controller calls with the same secret, and send the
// same CONNECT sequence; the report compares DNS answers, matched-rule outcome,
// group selection, provider update/reload semantics and the bytes the echo
// receiver got back.
//
// Effective Billow YAML: `t5-effective.mjs` mirrors
// `src-tauri/src/profile.rs::kernel_yaml_for(Engine::Rust, false)` and the four
// call steps around it. The generated desktop/Android artifacts are written next
// to the report, then loaded with `--check`/`-t` so the keys the kernel still
// rejects are named instead of claimed as supported.
//
// Command:
//   node tool/kernel-compat/t5-differential.mjs \
//     --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
//     --rust native-kernel/target/debug/billow-kernel \
//     --out tool/kernel-compat/evidence/t5-integration.json \
//     --effective-dir tool/kernel-compat/evidence/t5-effective
import { spawn } from 'node:child_process'
import dgram from 'node:dgram'
import { copyFile, cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import http from 'node:http'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { reservePort } from './ports.mjs'
import { openTunnel } from './process.mjs'
import { effectiveConfig, emitYaml, T5_SETTINGS } from './t5-effective.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '../..')
const SECRET = 't5-secret'
const TYPE_A = 1
const TYPE_CNAME = 5

// ---------------------------------------------------------------------------
// DNS wire helpers (same subset as t22-differential)
// ---------------------------------------------------------------------------

function encodeName(name) {
  const parts = []
  for (const label of name.replace(/\.$/, '').split('.')) {
    const bytes = Buffer.from(label)
    parts.push(Buffer.from([bytes.length]), bytes)
  }
  parts.push(Buffer.from([0]))
  return Buffer.concat(parts)
}

function buildQuery(name, qtype, id = 0x5151) {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(id, 0)
  header.writeUInt16BE(0x0100, 2)
  header.writeUInt16BE(1, 4)
  const question = Buffer.concat([
    encodeName(name),
    Buffer.from([qtype >> 8, qtype & 0xff, 0, 1]),
  ])
  return Buffer.concat([header, question])
}

function readName(message, offset) {
  const labels = []
  let cursor = offset
  let end = offset
  let jumped = false
  for (let guard = 0; guard < 32; guard += 1) {
    const len = message[cursor]
    if (len === 0) {
      if (!jumped) end = cursor + 1
      return { name: labels.join('.'), end }
    }
    if ((len & 0xc0) === 0xc0) {
      if (!jumped) end = cursor + 2
      jumped = true
      cursor = ((len & 0x3f) << 8) | message[cursor + 1]
      continue
    }
    labels.push(message.subarray(cursor + 1, cursor + 1 + len).toString('latin1'))
    cursor += 1 + len
  }
  throw new Error('compression loop')
}

function parseDns(message) {
  const rcode = message[3] & 0x0f
  const qcount = message.readUInt16BE(4)
  let offset = 12
  let name = ''
  for (let index = 0; index < qcount; index += 1) {
    const parsed = readName(message, offset)
    name = parsed.name
    offset = parsed.end + 4
  }
  const ancount = message.readUInt16BE(6)
  const answers = []
  for (let index = 0; index < ancount; index += 1) {
    const owner = readName(message, offset)
    offset = owner.end
    const header = message.subarray(offset, offset + 10)
    const rtype = header.readUInt16BE(0)
    const ttl = header.readUInt32BE(4)
    const rdlength = header.readUInt16BE(8)
    offset += 10
    const data = message.subarray(offset, offset + rdlength)
    if (rtype === TYPE_A) {
      answers.push({ type: 'A', ip: [...data].join('.'), ttl })
    } else if (rtype === TYPE_CNAME) {
      answers.push({ type: 'CNAME', ip: readName(message, offset).name, ttl })
    } else {
      answers.push({ type: String(rtype), ip: data.toString('hex'), ttl })
    }
    offset += rdlength
  }
  return { name, rcode, answers }
}

function queryDns(port, name, qtype = TYPE_A, timeoutMs = 8000) {
  return new Promise((done) => {
    const socket = dgram.createSocket('udp4')
    let settled = false
    const finish = (result) => {
      if (settled) return
      settled = true
      socket.close()
      done(result)
    }
    socket.on('message', (message) => {
      try {
        finish({ ...parseDns(message), timeout: false })
      } catch (error) {
        finish({ error: error.message, timeout: false })
      }
    })
    socket.on('error', (error) => finish({ error: error.message, timeout: false }))
    socket.send(buildQuery(name, qtype), port, '127.0.0.1', (error) => {
      if (error) finish({ error: error.message, timeout: false })
    })
    setTimeout(() => finish({ timeout: true, rcode: null, answers: [] }), timeoutMs)
  })
}

// ---------------------------------------------------------------------------
// Local fixtures
// ---------------------------------------------------------------------------

function startDnsFixture(answers) {
  const queries = []
  const socket = dgram.createSocket('udp4')
  socket.on('message', (message, peer) => {
    let offset = 12
    let name = ''
    try {
      const parsed = readName(message, offset)
      name = parsed.name.toLowerCase()
      offset = parsed.end
    } catch {
      return
    }
    const qtype = message.readUInt16BE(offset)
    queries.push(`${name}/${qtype}`)
    const qtypeName = qtype === TYPE_A ? 'A' : qtype === TYPE_CNAME ? 'CNAME' : String(qtype)
    const entry = answers[`${name}/${qtypeName}`] ?? answers[`${name}/A`]
    const reply = Buffer.from(message.subarray(0, offset + 4))
    reply.writeUInt16BE(0x8180, 2)
    if (!entry) {
      reply.writeUInt16BE(0, 6)
      reply.writeUInt16BE(0, 8)
      reply.writeUInt16BE(0, 10)
      reply[3] = 0x83
      socket.send(reply, peer.port, peer.address)
      return
    }
    const rdata = qtype === TYPE_CNAME
      ? encodeName(entry.cname)
      : Buffer.from(entry.ip.split('.').map(Number))
    const answer = Buffer.concat([
      Buffer.from([0xc0, 0x0c]),
      Buffer.from([0, qtype, 0, 1]),
      Buffer.from([0, 0, 0, entry.ttl ?? 60]),
      Buffer.from([0, rdata.length]),
      rdata,
    ])
    reply.writeUInt16BE(1, 6)
    reply.writeUInt16BE(0, 8)
    reply.writeUInt16BE(0, 10)
    socket.send(Buffer.concat([reply, answer]), peer.port, peer.address)
  })
  return new Promise((done) => {
    socket.bind(0, '127.0.0.1', () => {
      done({
        port: socket.address().port,
        queries,
        close: () => socket.close(),
      })
    })
  })
}

// HTTP echo with an explicit Content-Length so `openTunnel.write` can delimit.
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
  return new Promise((done) => {
    server.listen(0, '0.0.0.0', () => {
      done({
        port: server.address().port,
        close: () => new Promise((closed) => server.close(closed)),
      })
    })
  })
}

function startHealthServer() {
  const server = http.createServer((request, response) => {
    request.resume()
    request.on('end', () => {
      response.writeHead(204)
      response.end()
    })
  })
  return new Promise((done) => {
    server.listen(0, '127.0.0.1', () => {
      done({
        port: server.address().port,
        close: () => new Promise((closed) => server.close(closed)),
      })
    })
  })
}

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
  return new Promise((done) => {
    server.listen(0, '127.0.0.1', () => {
      done({
        port: server.address().port,
        set(path, value) { state.set(path, { ...value }) },
        close: () => new Promise((closed) => server.close(closed)),
      })
    })
  })
}

// ---------------------------------------------------------------------------
// Child processes
// ---------------------------------------------------------------------------

function startProcess(command, args, cwd) {
  const logs = { stdout: '', stderr: '' }
  const child = spawn(command, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] })
  child.stdout.on('data', (chunk) => { logs.stdout = (logs.stdout + chunk).slice(-16000) })
  child.stderr.on('data', (chunk) => { logs.stderr = (logs.stderr + chunk).slice(-16000) })
  const exited = new Promise((done) => child.once('exit', (code, signal) => done({ code, signal })))
  return { child, logs, exited }
}

async function waitPort(port, timeoutMs = 20000) {
  const started = performance.now()
  while (performance.now() - started < timeoutMs) {
    const ok = await new Promise((probe) => {
      const socket = new net.Socket()
      socket.setTimeout(400)
      socket.once('connect', () => { socket.destroy(); probe(true) })
      socket.once('timeout', () => { socket.destroy(); probe(false) })
      socket.once('error', () => probe(false))
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
  const result = await Promise.race([
    handle.exited,
    new Promise((done) => setTimeout(() => done({ timeout: true }), 5000)),
  ])
  if (result.timeout) {
    handle.child.kill('SIGKILL')
    await handle.exited
  }
}

async function runToExit(command, args, cwd, timeoutMs = 30000) {
  const handle = startProcess(command, args, cwd)
  const result = await Promise.race([
    handle.exited,
    new Promise((done) => setTimeout(() => done({ timeout: true }), timeoutMs)),
  ])
  if (result.timeout) {
    handle.child.kill('SIGKILL')
    await handle.exited
  }
  return { ...result, stdout: handle.logs.stdout, stderr: handle.logs.stderr }
}

function resolveBinary(path, flag) {
  if (!path) throw new Error(`${flag} is required`)
  return resolve(path)
}

// ---------------------------------------------------------------------------
// Peers: pinned Mihomo listeners for ss/trojan, Go SSR server
// ---------------------------------------------------------------------------

async function startMihomoListenerPeer(mihomo, dir, kind) {
  const port = await reservePort()
  const reservedPort = await reservePort()
  const lines = [
    `mixed-port: ${reservedPort}`,
    'mode: rule',
    'log-level: warning',
    'listeners:',
    `  - name: ${kind}-in`,
    `    type: ${kind === 'ss' ? 'shadowsocks' : 'trojan'}`,
    '    listen: 127.0.0.1',
    `    port: ${port}`,
  ]
  if (kind === 'ss') {
    lines.push('    cipher: aes-256-gcm', '    password: t5-ss-pass', '    udp: false')
  } else {
    lines.push(
      '    users:',
      '      - password: t5-trojan-pass',
      "    certificate: 'cert.pem'",
      "    private-key: 'key.pem'",
    )
  }
  lines.push('rules:', '  - MATCH,DIRECT')
  await writeFile(join(dir, 'peer.yaml'), lines.join('\n') + '\n')
  const handle = startProcess(mihomo, ['-d', dir, '-f', join(dir, 'peer.yaml')], dir)
  const ready = await waitPort(port)
  return { kind, port, ready, handle, dir }
}

async function buildSsrPeer(sandbox) {
  if (process.env.KC_SSR_PEER_BIN) return resolve(process.env.KC_SSR_PEER_BIN)
  const cacheDir = join(here, '.cache', 'peers')
  const binary = join(cacheDir, 'ssr-server')
  try {
    await readFile(binary)
    return binary
  } catch {
    await mkdir(cacheDir, { recursive: true })
  }
  const build = await runToExit('go', ['build', '-o', binary, '.'], join(here, 'peers/ssr-server'), 240000)
  if (build.code !== 0) throw new Error(`go build peers/ssr-server failed: ${build.stderr.slice(-800)}`)
  return binary
}

async function startSsrPeer(binary) {
  const port = await reservePort()
  const child = spawn(binary, ['-listen', `127.0.0.1:${port}`, '-cipher', 'aes-256-cfb', '-password', 't5-ssr-pass'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const logs = { stdout: '', stderr: '' }
  child.stdout.on('data', (chunk) => { logs.stdout += chunk })
  child.stderr.on('data', (chunk) => { logs.stderr += chunk })
  const exited = new Promise((done) => child.once('exit', (code, signal) => done({ code, signal })))
  const ready = await waitPort(port)
  return { port, ready, handle: { child, logs, exited } }
}

// ---------------------------------------------------------------------------
// Effective configuration artifacts
// ---------------------------------------------------------------------------

function geoipDat(countries) {
  const varint = (value) => {
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
  return Buffer.concat(countries.map((country) => fieldBytes(1, Buffer.concat([
    fieldBytes(1, text(country.code)),
    ...country.cidrs.map(({ bytes, prefix }) => fieldBytes(2, Buffer.concat([
      fieldBytes(1, Buffer.from(bytes)),
      fieldVarint(2, prefix),
    ]))),
  ]))))
}

function geositeDat(lists) {
  const varint = (value) => {
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
  const domain = (type, value) => Buffer.concat([fieldVarint(1, type), fieldBytes(2, text(value))])
  return Buffer.concat(lists.map((list) => fieldBytes(1, Buffer.concat([
    fieldBytes(1, text(list.code)),
    ...list.domains.map((entry) => fieldBytes(2, entry)),
  ]))))
}

async function writeProviderFiles(dir) {
  await mkdir(join(dir, 'providers'), { recursive: true })
  await writeFile(join(dir, 'providers/rp.yaml'), "payload:\n  - '+.localhost'\n")
  await writeFile(join(dir, 'providers/rp.txt'), '+.text-probe.test\n')
  await writeFile(join(dir, 'providers/nodes.yaml'), [
    'proxies:',
    '  - {name: sub-a, type: ss, server: 127.0.0.1, port: 18388, cipher: aes-256-gcm, password: sub-pass}',
    '',
  ].join('\n'))
  await copyFile(join(repoRoot, 'src-tauri/testdata/domain.mrs'), join(dir, 'providers/rp.mrs'))
  await writeFile(join(dir, 'GeoIP.dat'), geoipDat([
    { code: 'CN', cidrs: [{ bytes: [10, 0, 0, 0], prefix: 8 }] },
    { code: 'zz', cidrs: [{ bytes: [127, 0, 0, 1], prefix: 32 }] },
  ]))
  await writeFile(join(dir, 'GeoSite.dat'), geositeDat([
    { code: 'CN', domains: [domainPattern(3, 'localhost')] },
    { code: 't5site', domains: [domainPattern(3, 'geo.test')] },
  ]))
}

function domainPattern(type, value) {
  const varint = (valueIn) => {
    const out = []
    let current = valueIn
    do {
      let byte = current & 0x7f
      current >>>= 7
      if (current) byte |= 0x80
      out.push(byte)
    } while (current)
    return Buffer.from(out)
  }
  const fieldBytes = (field, bytes) => Buffer.concat([varint((field << 3) | 2), varint(bytes.length), bytes])
  const fieldVarint = (field, valueIn) => Buffer.concat([varint(field << 3), varint(valueIn)])
  return Buffer.concat([fieldVarint(1, type), fieldBytes(2, Buffer.from(value))])
}

// ---------------------------------------------------------------------------
// Combined configuration
// ---------------------------------------------------------------------------

function combinedConfig({ mixed, dns, controller, providerPort, healthPort, ports, ssPeer, trojanPeer, ssrPeer, rules }) {
  const rulesBlock = rules ?? [
    'RULE-SET,rp-http,REJECT',
    'RULE-SET,rp-yaml,PROXY',
    'GEOSITE,t5site,REJECT',
    'RULE-SET,rp-text,REJECT',
    'RULE-SET,rp-mrs,REJECT',
    'DOMAIN,bad.localhost,BAD',
    `DST-PORT,${ports?.trojan ?? '{{trojanEcho}}'},trojan-node`,
    'GEOIP,zz,ss-node',
    'MATCH,ssr-node',
  ]
  return [
    `mixed-port: ${mixed}`,
    'mode: rule',
    'log-level: warning',
    `external-controller: 127.0.0.1:${controller}`,
    `secret: ${SECRET}`,
    'profile:',
    '  store-selected: false',
    '  store-fake-ip: false',
    'geodata-mode: true',
    'hosts:',
    "  host-only.test: '127.0.0.1'",
    "  alias.test: 'alias-target.test'",
    'dns:',
    '  enable: true',
    `  listen: 127.0.0.1:${dns}`,
    '  enhanced-mode: fake-ip',
    '  fake-ip-range: 198.18.0.1/16',
    "  fake-ip-filter: ['+.real.test', 'alias-target.test', 'absent.test']",
    '  use-hosts: true',
    '  ipv6: false',
    `  nameserver: ['udp://127.0.0.1:{{dnsUpstream}}']`,
    'rule-providers:',
    '  rp-yaml:',
    '    type: file',
    '    behavior: domain',
    '    format: yaml',
    '    path: providers/rp.yaml',
    '  rp-text:',
    '    type: file',
    '    behavior: domain',
    '    format: text',
    '    path: providers/rp.txt',
    '  rp-mrs:',
    '    type: file',
    '    behavior: domain',
    '    format: mrs',
    '    path: providers/rp.mrs',
    '  rp-http:',
    '    type: http',
    '    behavior: domain',
    '    format: yaml',
    `    url: http://127.0.0.1:${providerPort}/rules.yaml`,
    'proxy-providers:',
    '  pp-sub:',
    '    type: file',
    '    path: providers/nodes.yaml',
    '    health-check:',
    '      enable: true',
    `      url: 'http://127.0.0.1:${healthPort}/generate_204'`,
    '      interval: 60',
    'proxies:',
    `  - {name: ss-node, type: ss, server: 127.0.0.1, port: ${ssPeer}, cipher: aes-256-gcm, password: t5-ss-pass, udp: true}`,
    `  - {name: trojan-node, type: trojan, server: 127.0.0.1, port: ${trojanPeer}, password: t5-trojan-pass, sni: 'localhost', skip-cert-verify: true}`,
    `  - {name: ssr-node, type: ssr, server: 127.0.0.1, port: ${ssrPeer}, cipher: aes-256-cfb, password: t5-ssr-pass, protocol: origin, obfs: plain}`,
    `  - {name: bad-ss, type: ss, server: 127.0.0.1, port: ${ssPeer}, cipher: aes-256-gcm, password: wrong-pass}`,
    'proxy-groups:',
    '  - {name: PROXY, type: select, proxies: [ss-node, trojan-node, ssr-node]}',
    `  - {name: AUTO, type: url-test, proxies: [ss-node, trojan-node], url: 'http://127.0.0.1:${healthPort}/generate_204', interval: 60, tolerance: 50, lazy: false}`,
    `  - {name: FALLBACK, type: fallback, proxies: [ss-node, trojan-node], url: 'http://127.0.0.1:${healthPort}/generate_204', interval: 60, lazy: false}`,
    '  - {name: BAD, type: select, proxies: [bad-ss]}',
    '  - {name: SUB, type: select, use: [pp-sub]}',
    'rules:',
    ...rulesBlock.map((rule) => `  - ${rule}`),
    '',
  ].join('\n')
}

// ---------------------------------------------------------------------------
// One CONNECT attempt
// ---------------------------------------------------------------------------

async function attempt(mixedPort, host, targetPort, marker) {
  const exchange = await openTunnel({
    host: '127.0.0.1',
    port: mixedPort,
    target: { host, port: targetPort },
    connectTimeoutMs: 4000,
  })
  if (exchange.error) {
    return {
      category: exchange.error.name === 'TimeoutError' ? 'timeout' : 'closed',
      connectStatus: 0,
      error: exchange.error.message,
    }
  }
  const status = exchange.response.status
  if (status !== 200) {
    await exchange.close()
    return { category: 'blocked', connectStatus: status }
  }
  try {
    const payload = `POST /probe HTTP/1.1\r\nHost: probe\r\nContent-Length: ${Buffer.byteLength(JSON.stringify({ marker }))}\r\nConnection: close\r\n\r\n${JSON.stringify({ marker })}`
    const reply = await exchange.write(payload, 5000)
    let echoed = null
    try { echoed = JSON.parse(reply.slice(reply.indexOf('{'))).marker } catch { echoed = null }
    return {
      category: echoed === marker ? 'echoed' : 'empty',
      connectStatus: status,
      echoed,
      replyBytes: reply.length,
    }
  } catch (error) {
    return { category: 'timeout', connectStatus: status, error: error.message }
  } finally {
    await exchange.close()
  }
}

function normalize(engine, observation) {
  if (!observation) return null
  if (observation.category === 'closed') return 'blocked'
  if (observation.category === 'timeout' && engine === 'mihomo') return 'blocked'
  return observation.category
}

// ---------------------------------------------------------------------------
// Controller client
// ---------------------------------------------------------------------------

async function api(port, method, path, body) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 8000)
  try {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      body: body ?? undefined,
      headers: {
        Authorization: `Bearer ${SECRET}`,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      signal: controller.signal,
    })
    const text = await response.text()
    return { status: response.status, body: text }
  } catch (error) {
    return { status: 0, error: String(error) }
  } finally {
    clearTimeout(timer)
  }
}

function jsonOf(response) {
  try { return JSON.parse(response.body) } catch { return null }
}

function groupShapeOf(body) {
  if (!body) return null
  const members = (body.all ?? []).map((member) => (typeof member === 'string' ? member : member.name))
  const health = body.members ?? []
  return {
    now: body.now ?? null,
    members,
    // Rust exposes health on `members`; pinned embeds it in `all` entries.
    alive: health.length
      ? health.filter((member) => member.alive).map((member) => member.name)
      : (body.all ?? []).filter((member) => typeof member === 'object' && member.alive).map((member) => member.name),
  }
}

async function waitGroupShape(controller, group, timeoutMs = 10000) {
  const deadline = performance.now() + timeoutMs
  let shape = null
  while (performance.now() < deadline) {
    const body = jsonOf(await api(controller, 'GET', `/proxies/${group}`))
    shape = groupShapeOf(body)
    if (!shape) return null
    // Auto groups probe every member; wait until the health rows are visible so
    // the two engines are compared after the same startup work.
    if (group === 'AUTO' || group === 'FALLBACK') {
      const expected = shape.members.length
      if (shape.alive.length < expected) {
        await new Promise((done) => setTimeout(done, 100))
        continue
      }
    }
    return shape
  }
  return shape
}

async function waitController(port, timeoutMs = 15000) {
  const started = performance.now()
  while (performance.now() - started < timeoutMs) {
    const response = await api(port, 'GET', '/version')
    if (response.status === 200) return true
    await new Promise((done) => setTimeout(done, 100))
  }
  return false
}

// ---------------------------------------------------------------------------
// One engine run
// ---------------------------------------------------------------------------

async function runEngine(engine, binary, sandbox, fixtures) {
  // Every engine starts from the initial HTTP provider payload; the update
  // sequence below leaves the fixture in a failure state on purpose.
  fixtures.provider.set('/rules.yaml', { status: 200, body: "payload:\n  - '+.http-probe.test'\n" })
  const dir = join(sandbox, engine)
  await mkdir(dir, { recursive: true })
  await writeProviderFiles(dir)
  const mixed = await reservePort()
  const dns = await reservePort()
  const controller = await reservePort()
  const config = combinedConfig({
    mixed,
    dns,
    controller,
    providerPort: fixtures.provider.port,
    healthPort: fixtures.health.port,
    ssPeer: fixtures.ss.port,
    trojanPeer: fixtures.trojan.port,
    ssrPeer: fixtures.ssr.port,
    ports: { trojan: fixtures.echoB.port },
  }).replace('{{dnsUpstream}}', String(fixtures.dns.port))
  await writeFile(join(dir, 'config.yaml'), config)
  const args = engine === 'mihomo'
    ? ['-d', dir, '-f', join(dir, 'config.yaml')]
    : [join(dir, 'config.yaml'), '--port', String(mixed), '--geosite-dir', dir]
  const handle = startProcess(binary, args, dir)
  const ready = (await waitPort(mixed)) && (await waitController(controller))
  const result = { engine, ready, mixed, dns, controller, config, logs: handle.logs }
  if (!ready) {
    await stopProcess(handle)
    return result
  }
  const run = async (host, marker, echo = fixtures.echoA.port) => attempt(mixed, host, echo, marker)
  try {
    result.dnsAnswers = {}
    for (const name of ['fake.test', 'host-only.test', 'alias.test', 'real.test', 'absent.test']) {
      result.dnsAnswers[name] = await queryDns(dns, name)
    }
    result.groupsInitial = {}
    for (const group of ['PROXY', 'AUTO', 'FALLBACK', 'SUB']) {
      result.groupsInitial[group] = await waitGroupShape(controller, group)
    }
    result.providers = jsonOf(await api(controller, 'GET', '/providers/proxies'))
    result.selection = {
      set: (await api(controller, 'PUT', '/proxies/PROXY', JSON.stringify({ name: 'trojan-node' }))).status,
      now: jsonOf(await api(controller, 'GET', '/proxies/PROXY'))?.now ?? null,
      missing: (await api(controller, 'PUT', '/proxies/PROXY', JSON.stringify({ name: 'no-such-node' }))).status,
    }
    result.egress = {
      'localhost': await run('localhost', 't5-proxy-trojan'),
      '127.0.0.1': await run('127.0.0.1', 't5-ss'),
      'trojan-port': await run('127.0.0.1', 't5-trojan', fixtures.echoB.port),
      'ssr-port': await run('127.0.0.1', 't5-ssr', fixtures.echoC.port),
      'bad.localhost': await run('bad.localhost', 't5-bad'),
      'text-probe.test': await run('text-probe.test', 't5-text'),
      'www.google.com': await run('www.google.com', 't5-mrs'),
      'geo.test': await run('geo.test', 't5-geosite'),
      'http-probe.test': await run('http-probe.test', 't5-http'),
    }
    result.selectionSwitch = {
      set: (await api(controller, 'PUT', '/proxies/PROXY', JSON.stringify({ name: 'ss-node' }))).status,
      now: jsonOf(await api(controller, 'GET', '/proxies/PROXY'))?.now ?? null,
      localhost: await run('localhost', 't5-proxy-ss'),
    }

    // Rule-provider update: the HTTP payload starts matching only
    // http-probe.test; after the update it matches localhost (which the earlier
    // RULE-SET would otherwise send to PROXY), and a failing update keeps that
    // swapped snapshot.
    result.providerUpdate = { steps: [] }
    result.providerUpdate.steps.push({
      phase: 'initial',
      localhost: normalize(engine, await run('localhost', 't5-before-update')),
      httpProbe: normalize(engine, await run('http-probe.test', 't5-http-before')),
    })
    fixtures.provider.set('/rules.yaml', { status: 200, body: "payload:\n  - '+.localhost'\n" })
    result.providerUpdate.steps.push({
      phase: 'update-ok',
      status: (await api(controller, 'PUT', '/providers/rules/rp-http')).status,
      localhost: normalize(engine, await run('localhost', 't5-after-update')),
    })
    fixtures.provider.set('/rules.yaml', { status: 500, body: '' })
    const failure = (await api(controller, 'PUT', '/providers/rules/rp-http')).status
    result.providerUpdate.steps.push({
      phase: 'update-failure',
      status: failure,
      localhost: normalize(engine, await run('localhost', 't5-after-failure')),
    })

    // Reload: a new rule set is accepted and takes effect; invalid YAML is
    // rejected and the previous (reloaded) configuration stays live.
    fixtures.provider.set('/rules.yaml', { status: 200, body: "payload:\n  - '+.http-probe.test'\n" })
    const reloadYaml = combinedConfig({
      mixed,
      dns,
      controller,
      providerPort: fixtures.provider.port,
      healthPort: fixtures.health.port,
      ssPeer: fixtures.ss.port,
      trojanPeer: fixtures.trojan.port,
      ssrPeer: fixtures.ssr.port,
      ports: { trojan: fixtures.echoB.port },
      rules: ['DOMAIN,localhost,REJECT', 'MATCH,DIRECT'],
    }).replace('{{dnsUpstream}}', String(fixtures.dns.port))
    result.reload = {
      successStatus: (await api(controller, 'PUT', '/configs?force=true', JSON.stringify({ path: '', payload: reloadYaml }))).status,
      localhostAfter: normalize(engine, await run('localhost', 't5-reloaded')),
      failureStatus: (await api(controller, 'PUT', '/configs?force=true', JSON.stringify({ path: '', payload: 'mixed-port: 1\nmode: nope\n' }))).status,
      localhostAfterFailure: normalize(engine, await run('localhost', 't5-reload-failed')),
      mixedPort: jsonOf(await api(controller, 'GET', '/configs'))?.['mixed-port'] ?? null,
      groups: jsonOf(await api(controller, 'GET', '/proxies/PROXY'))?.now ?? null,
      dnsAfter: await queryDns(dns, 'fake.test'),
    }
  } finally {
    await stopProcess(handle)
  }
  return result
}

// ---------------------------------------------------------------------------
// Configuration acceptance probes (Rust --check / Mihomo -t)
// ---------------------------------------------------------------------------

async function checkConfig(engine, binary, yaml, dir, name, assetsFrom = null) {
  const caseDir = join(dir, name)
  await mkdir(caseDir, { recursive: true })
  await writeFile(join(caseDir, 'config.yaml'), yaml)
  if (assetsFrom) {
    await cp(join(assetsFrom, 'providers'), join(caseDir, 'providers'), { recursive: true })
    for (const asset of ['GeoIP.dat', 'GeoSite.dat']) {
      await cp(join(assetsFrom, asset), join(caseDir, asset)).catch(() => null)
    }
  }
  const port = await reservePort()
  const result = engine === 'mihomo'
    ? await runToExit(binary, ['-t', '-d', caseDir, '-f', join(caseDir, 'config.yaml')], caseDir)
    : await runToExit(binary, [join(caseDir, 'config.yaml'), '--check', '--port', String(port), '--geosite-dir', caseDir], caseDir)
  return {
    exit: result.code ?? (result.timeout ? 'timeout' : null),
    accepted: result.code === 0,
    stderr: (result.stderr ?? '').slice(-1200),
    stdout: (result.stdout ?? '').slice(-600),
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = {
    mihomo: null,
    rust: null,
    out: null,
    effectiveDir: join(here, 'evidence', 't5-effective'),
  }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--mihomo') args.mihomo = resolveBinary(argv[++index], '--mihomo')
    else if (arg === '--rust') args.rust = resolveBinary(argv[++index], '--rust')
    else if (arg === '--out') args.out = resolve(argv[++index])
    else if (arg === '--effective-dir') args.effectiveDir = resolve(argv[++index])
    else throw new Error(`unknown argument ${arg}`)
  }
  if (!args.mihomo || !args.rust || !args.out) {
    throw new Error('usage: --mihomo <binary> --rust <binary> --out <json> [--effective-dir <dir>]')
  }
  return args
}

function mark(scenario, equal, detail = {}) {
  return { ...scenario, equal, status: equal ? 'pass' : 'differ', ...detail }
}

async function runEffective(args, sandbox, report) {
  const profileText = await readFile(join(here, 'fixtures/t5-billow-profile.json'), 'utf8')
  await mkdir(args.effectiveDir, { recursive: true })
  // Provider paths in the fixture are relative to the config file.
  const providerDir = join(args.effectiveDir, 'providers')
  await mkdir(providerDir, { recursive: true })
  await writeFile(join(providerDir, 'billow-corp.txt'), '+.corp.example\n')
  await writeFile(join(providerDir, 'billow-sub.yaml'), [
    'proxies:',
    '  - {name: sub-node, type: ss, server: 127.0.0.1, port: 18388, cipher: aes-256-gcm, password: sub-pass}',
    '',
  ].join('\n'))
  await writeFile(join(args.effectiveDir, 'GeoIP.dat'), geoipDat([
    { code: 'CN', cidrs: [{ bytes: [10, 0, 0, 0], prefix: 8 }] },
  ]))
  await writeFile(join(args.effectiveDir, 'GeoSite.dat'), geositeDat([
    { code: 'CN', domains: [domainPattern(3, 'localhost')] },
  ]))

  const effective = { artifacts: {}, checks: {}, reduced: {} }
  for (const platform of ['desktop', 'android']) {
    const built = effectiveConfig(profileText, T5_SETTINGS, platform)
    const path = join(args.effectiveDir, `billow-${platform}.yaml`)
    const yaml = emitYaml(built.config)
    await writeFile(path, yaml)
    effective.artifacts[platform] = {
      path,
      bytes: Buffer.byteLength(yaml),
      profileHadTun: built.profileHadTun,
      hasTun: built.config.tun !== undefined,
      hasController: built.config['external-controller'] !== undefined,
      ports: Object.fromEntries([
        'mixed-port', 'port', 'socks-port', 'redir-port', 'tproxy-port',
      ].map((name) => [name, built.config[name] ?? null])),
      sniffer: built.config.sniffer?.enable ?? null,
    }
    effective.checks[platform] = {
      rust: await checkConfig('rust', args.rust, yaml, sandbox, `effective-${platform}`, args.effectiveDir),
      mihomo: await checkConfig('mihomo', args.mihomo, yaml, sandbox, `effective-${platform}`, args.effectiveDir),
    }

    // The only key the kernel still rejects by name in this artifact is the
    // enabled sniffer (T7). Remove it and prove the rest loads and its groups
    // are registered; the launcher `tun` block was already stripped above.
    const reduced = effectiveConfig(profileText, { ...T5_SETTINGS, sniffer: false }, platform).config
    const reducedYaml = emitYaml(reduced)
    const reducedPath = join(args.effectiveDir, `billow-${platform}-reduced.yaml`)
    await writeFile(reducedPath, reducedYaml)
    const check = await checkConfig('rust', args.rust, reducedYaml, sandbox, `effective-${platform}-reduced`, args.effectiveDir)
    const groups = await runToExit(args.rust, [reducedPath, '--port', String(await reservePort()), '--geosite-dir', args.effectiveDir, '--print-groups'], args.effectiveDir, 20000)
    effective.reduced[platform] = {
      path: reducedPath,
      check,
      groups: parseGroups(groups.stdout + groups.stderr),
      stderr: groups.stderr.slice(-600),
    }
  }
  // Named-rejection list derived from the artifacts, not hand-maintained.
  const rejected = []
  for (const platform of ['desktop', 'android']) {
    const check = effective.checks[platform].rust
    if (!check.accepted) rejected.push({ platform, stderr: check.stderr })
  }
  effective.namedRejections = rejected
  effective.conclusion = rejected.length === 2
    && rejected.every((entry) => /sniffer/.test(entry.stderr))
    ? 'sniffer (T7) is the only top-level key rejected by name; removing it makes both desktop and Android artifacts load'
    : 'unexpected rejection shape; see stderr'
  report.effective = effective
}

function parseGroups(text) {
  const line = text.split('\n').find((entry) => entry.startsWith('GROUPS '))
  if (!line) return []
  try {
    const body = JSON.parse(line.slice('GROUPS '.length))
    return (body.groups ?? []).map((group) => ({
      name: group.name,
      type: group.type,
      now: group.now,
      members: (group.all ?? []).length,
    }))
  } catch {
    return []
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  const sandbox = await mkdtemp(join(tmpdir(), 'billow-t5-diff-'))
  const fixtures = {}
  const report = { format: 't5-integration', version: 1, startedAt: new Date().toISOString(), mihomo: args.mihomo, rust: args.rust }
  try {
    fixtures.echoA = await startEchoServer()
    fixtures.echoB = await startEchoServer()
    fixtures.echoC = await startEchoServer()
    fixtures.health = await startHealthServer()
    fixtures.dns = await startDnsFixture({
      'fake.test/A': { ip: '127.0.0.1', ttl: 60 },
      'real.test/A': { ip: '5.5.5.5', ttl: 60 },
      'alias-target.test/A': { ip: '9.9.9.9', ttl: 60 },
    })
    fixtures.provider = await startProviderServer({
      '/rules.yaml': { status: 200, body: "payload:\n  - '+.http-probe.test'\n" },
    })
    // Self-signed certificate for the pinned Trojan listener.
    const peerDir = join(sandbox, 'peers')
    await mkdir(peerDir, { recursive: true })
    await runToExit('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
      '-keyout', join(peerDir, 'key.pem'), '-out', join(peerDir, 'cert.pem'),
    ], peerDir)

    fixtures.ss = await startMihomoListenerPeer(args.mihomo, peerDir, 'ss')
    const trojanDir = join(sandbox, 'peers-trojan')
    await mkdir(trojanDir, { recursive: true })
    await copyFile(join(peerDir, 'cert.pem'), join(trojanDir, 'cert.pem'))
    await copyFile(join(peerDir, 'key.pem'), join(trojanDir, 'key.pem'))
    fixtures.trojan = await startMihomoListenerPeer(args.mihomo, trojanDir, 'trojan')
    const ssrBinary = await buildSsrPeer(sandbox)
    fixtures.ssr = await startSsrPeer(ssrBinary)
    report.peers = {
      ss: { port: fixtures.ss.port, ready: fixtures.ss.ready },
      trojan: { port: fixtures.trojan.port, ready: fixtures.trojan.ready },
      ssr: { binary: ssrBinary, port: fixtures.ssr.port, ready: fixtures.ssr.ready },
      dns: fixtures.dns.port,
      provider: fixtures.provider.port,
      echoA: fixtures.echoA.port,
      echoB: fixtures.echoB.port,
      echoC: fixtures.echoC.port,
      health: fixtures.health.port,
    }
    if (![fixtures.ss.ready, fixtures.trojan.ready, fixtures.ssr.ready].every(Boolean)) {
      throw new Error(`a peer did not start: ${JSON.stringify(report.peers)}`)
    }

    const engines = {}
    for (const engine of ['mihomo', 'rust']) {
      engines[engine] = await runEngine(engine, engine === 'mihomo' ? args.mihomo : args.rust, sandbox, fixtures)
    }
    report.engines = engines

    const scenarios = []
    for (const engine of ['mihomo', 'rust']) {
      scenarios.push(mark({ id: `startup-${engine}` }, engines[engine].ready, { ready: engines[engine].ready }))
    }
    const mihomo = engines.mihomo
    const rust = engines.rust
    if (!mihomo.ready || !rust.ready) {
      console.error('startup failed', JSON.stringify({
        mihomo: { ready: mihomo.ready, stderr: mihomo.logs?.stderr?.slice(-1500), stdout: mihomo.logs?.stdout?.slice(-500) },
        rust: { ready: rust.ready, stderr: rust.logs?.stderr?.slice(-1500), stdout: rust.logs?.stdout?.slice(-500) },
      }, null, 2))
    }

    // DNS: answer + TTL/CNAME shape must match.
    const dnsShape = (answers) => Object.fromEntries(Object.entries(answers ?? {}).map(([name, answer]) => [
      name,
      { rcode: answer.rcode, timeout: answer.timeout, answers: (answer.answers ?? []).map((entry) => `${entry.type}:${entry.ip}:${entry.ttl}`) },
    ]))
    scenarios.push(mark({ id: 'dns-fake-ip-hosts-alias' }, JSON.stringify(dnsShape(mihomo.dnsAnswers)) === JSON.stringify(dnsShape(rust.dnsAnswers)), {
      mihomo: dnsShape(mihomo.dnsAnswers),
      rust: dnsShape(rust.dnsAnswers),
    }))

    // Groups: selection/status shape. url-test picks by measured delay, which
    // is not compared for equality; membership and liveness are.
    const groupShape = (groups) => Object.fromEntries(Object.entries(groups ?? {}).map(([name, group]) => [
      name,
      group ? { nowMember: group.members.includes(group.now), members: group.members.length, alive: group.alive?.length ?? null } : null,
    ]))
    scenarios.push(mark({ id: 'groups-initial' }, JSON.stringify(groupShape(mihomo.groupsInitial)) === JSON.stringify(groupShape(rust.groupsInitial)), {
      mihomo: groupShape(mihomo.groupsInitial),
      rust: groupShape(rust.groupsInitial),
    }))

    const providerShape = (body) => {
      const entry = body?.providers?.['pp-sub']
      return entry ? { type: entry.vehicleType ?? entry.type, proxies: (entry.proxies ?? []).map((proxy) => proxy.name).sort() } : null
    }
    scenarios.push(mark({ id: 'proxy-provider-registered' }, JSON.stringify(providerShape(mihomo.providers)) === JSON.stringify(providerShape(rust.providers)), {
      mihomo: providerShape(mihomo.providers),
      rust: providerShape(rust.providers),
    }))

    const selectionShape = (state) => ({ set: state.set, now: state.now, missing: state.missing })
    scenarios.push(mark({ id: 'group-select', }, JSON.stringify(selectionShape(mihomo.selection)) === JSON.stringify(selectionShape(rust.selection)), {
      mihomo: selectionShape(mihomo.selection),
      rust: selectionShape(rust.selection),
    }))
    scenarios.push(mark({ id: 'group-select-switch' }, JSON.stringify({ set: mihomo.selectionSwitch.set, now: mihomo.selectionSwitch.now, localhost: normalize('mihomo', mihomo.selectionSwitch.localhost) })
      === JSON.stringify({ set: rust.selectionSwitch.set, now: rust.selectionSwitch.now, localhost: normalize('rust', rust.selectionSwitch.localhost) }), {
      mihomo: { set: mihomo.selectionSwitch.set, now: mihomo.selectionSwitch.now, localhost: normalize('mihomo', mihomo.selectionSwitch.localhost) },
      rust: { set: rust.selectionSwitch.set, now: rust.selectionSwitch.now, localhost: normalize('rust', rust.selectionSwitch.localhost) },
    }))

    const expectations = {
      'localhost': 'echoed',
      '127.0.0.1': 'echoed',
      'trojan-port': 'echoed',
      'ssr-port': 'echoed',
      'bad.localhost': 'blocked',
      'text-probe.test': 'blocked',
      'www.google.com': 'blocked',
      'geo.test': 'blocked',
      'http-probe.test': 'blocked',
    }
    // Compare "did the echo receiver answer" instead of the exact failure
    // framing: Mihomo answers 200-then-close, the Rust inbound answers 403/502
    // or leaves the relay waiting, which T24 records as a framing difference.
    const egressShape = (state) => Object.fromEntries(Object.entries(state).map(([host, observation]) => [host, {
      reached: observation?.category === 'echoed',
      category: observation?.category ?? null,
    }]))
    const left = egressShape(mihomo.egress)
    const right = egressShape(rust.egress)
    const egressOk = Object.keys(expectations).every((host) => {
      const expected = expectations[host] === 'echoed'
      return left[host].reached === expected && right[host].reached === expected
    })
    const reachedOnly = (state) => Object.fromEntries(Object.entries(state).map(([host, entry]) => [host, entry.reached]))
    scenarios.push(mark({ id: 'combined-egress-and-rules' }, JSON.stringify(reachedOnly(left)) === JSON.stringify(reachedOnly(right)) && egressOk, {
      mihomo: left,
      rust: right,
      expectations,
    }))

    const updateShape = (engine, update) => update.steps.map((step) => ({
      phase: step.phase,
      status: step.status ?? null,
      localhost: step.localhost ?? null,
      httpProbe: step.httpProbe ?? null,
    }))
    const updateLeft = updateShape('mihomo', mihomo.providerUpdate)
    const updateRight = updateShape('rust', rust.providerUpdate)
    scenarios.push(mark({ id: 'provider-update-failure-keeps-old' }, JSON.stringify(updateLeft) === JSON.stringify(updateRight), {
      mihomo: updateLeft,
      rust: updateRight,
    }))

    const reloadShape = (engine, reload) => ({
      successStatus: reload.successStatus,
      localhostAfter: normalize(engine, { category: reload.localhostAfter }),
      failureStatus: reload.failureStatus,
      localhostAfterFailure: normalize(engine, { category: reload.localhostAfterFailure }),
      mixedPort: reload.mixedPort === (engine === 'mihomo' ? mihomo.mixed : rust.mixed),
      groups: reload.groups,
      dnsAfter: (reload.dnsAfter.answers ?? []).map((entry) => `${entry.type}:${entry.ip}`),
    })
    const reloadLeft = reloadShape('mihomo', mihomo.reload)
    const reloadRight = reloadShape('rust', rust.reload)
    scenarios.push(mark({ id: 'reload-success-and-failure' }, JSON.stringify(reloadLeft) === JSON.stringify(reloadRight), {
      mihomo: reloadLeft,
      rust: reloadRight,
    }))

    // Configuration acceptance: the same rejected shapes through both config
    // testers. A pinned acceptance is recorded, not normalized away.
    const rejectDir = join(sandbox, 'reject')
    await mkdir(rejectDir, { recursive: true })
    const outOfRange = 'mixed-port: 7891\nrule-providers:\n  escape:\n    type: file\n    behavior: domain\n    path: ../escape.yaml\nrules:\n  - RULE-SET,escape,REJECT\n  - MATCH,DIRECT\n'
    const tunOn = 'mixed-port: 7891\ntun:\n  enable: true\nrules:\n  - MATCH,DIRECT\n'
    report.configAcceptance = {
      outOfRangeProviderPath: {
        mihomo: await checkConfig('mihomo', args.mihomo, outOfRange, rejectDir, 'out-of-range'),
        rust: await checkConfig('rust', args.rust, outOfRange, rejectDir, 'out-of-range'),
      },
      tunEnabled: {
        mihomo: await checkConfig('mihomo', args.mihomo, tunOn, rejectDir, 'tun-on'),
        rust: await checkConfig('rust', args.rust, tunOn, rejectDir, 'tun-on'),
      },
    }
    const rejection = report.configAcceptance
    scenarios.push(mark(
      { id: 'reject-out-of-range-provider-path' },
      rejection.outOfRangeProviderPath.rust.accepted === false
        && /escape|outside|parent|invalid/i.test(rejection.outOfRangeProviderPath.rust.stderr),
      rejection.outOfRangeProviderPath,
    ))
    scenarios.push(mark(
      { id: 'reject-unimplemented-option-tun' },
      rejection.tunEnabled.rust.accepted === false
        && /tun/.test(rejection.tunEnabled.rust.stderr)
        && rejection.tunEnabled.mihomo.accepted === true,
      { note: 'pinned accepts the TUN block at config-test time; the Rust kernel names the TUN gap (T6/T7)', ...rejection.tunEnabled },
    ))

    await runEffective(args, sandbox, report)

    report.peers.dnsQueries = fixtures.dns.queries
    report.scenarios = scenarios
    const summary = {
      scenarios: scenarios.length,
      pass: scenarios.filter((entry) => entry.status === 'pass').length,
      differ: scenarios.filter((entry) => entry.status === 'differ').length,
      startupFailed: ['mihomo', 'rust'].filter((engine) => !engines[engine].ready).length,
    }
    report.summary = summary
    report.notes = [
      'Both engines run the same combined YAML (only mixed/dns/controller ports differ); DNS answers are compared as rcode + type/address/TTL.',
      'Peers: pinned Mihomo `listeners:` processes for ss (aes-256-gcm) and trojan (self-signed cert, skip-cert-verify), plus peers/ssr-server (origin/plain, aes-256-cfb) built from the locked source.',
      'Rule outcome is compared after normalizing `closed` to `blocked` for both and Mihomo 200-then-close (`timeout`) to `blocked`; the Rust inbound answers 403/502 itself (T24 framing note).',
      'Group AUTO/FALLBACK `now` is compared by membership/liveness, not by the winning member: url-test ranks measured delays, which differ per run.',
      'The effective desktop/Android YAML is generated by t5-effective.mjs (a mirror of profile.rs::kernel_yaml_for for Engine::Rust) and loaded with --check/-t; the remaining named rejection is the enabled sniffer (T7).',
      'Old provider generations are reclaimed by Arc drop; unique generation stamping under the write lock is covered by tests/resources.rs::concurrent_provider_updates_stamp_unique_generations and the reload/provider-update scenarios here.',
      'R2 compatibility is determined by T8/Delivery on the complete candidate; this report only records the combined differential.',
    ]
    report.exitOk = summary.differ === 0 && summary.startupFailed === 0
      && report.effective.namedRejections.length === 2
      && report.effective.reduced.desktop.check.accepted
      && report.effective.reduced.android.check.accepted
    await mkdir(dirname(args.out), { recursive: true })
    await writeFile(args.out, JSON.stringify(report, null, 2))
    console.log(JSON.stringify({ summary, effective: report.effective.conclusion, exitOk: report.exitOk }))
    process.exitCode = report.exitOk ? 0 : 1
  } finally {
    for (const fixture of Object.values(fixtures)) {
      try {
        if (fixture?.close) await fixture.close()
        if (fixture?.handle) await stopProcess(fixture.handle)
      } catch { /* best effort */ }
    }
    await rm(sandbox, { recursive: true, force: true }).catch(() => null)
  }
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 2
})
