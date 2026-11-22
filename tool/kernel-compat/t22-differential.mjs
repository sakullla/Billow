#!/usr/bin/env node
// T22 differential probe: DNS, hosts and fake-ip against the pinned Mihomo
// v1.19.34 binary.
//
// Every DNS upstream is a loopback fixture started here with fixed answers:
// UDP, TCP, DoT (self-signed, `skip-cert-verify`), DoH (HTTP/1.1 over TLS) and
// a silent UDP port for the timeout case. Both engines run the same effective
// configuration, answer queries on `dns.listen`, and the answers (rcode,
// address, TTL) are compared. The last cases drive real CONNECT sessions
// through the mixed inbound so rule-time resolution and fake-ip destination
// rebuilding are compared too.
//
// Command:
//   node tool/kernel-compat/t22-differential.mjs \
//     --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
//     --rust native-kernel/target/debug/billow-kernel \
//     --out tool/kernel-compat/evidence/t22-dns.json
import { execFileSync, spawn } from 'node:child_process'
import dgram from 'node:dgram'
import { writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import tls from 'node:tls'
import { fileURLToPath } from 'node:url'
import { reservePort } from './ports.mjs'
import { openTunnel } from './process.mjs'

const here = dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// DNS wire format
// ---------------------------------------------------------------------------

const TYPE = { A: 1, CNAME: 5, AAAA: 28 }

function encodeName(name) {
  const parts = []
  for (const label of name.replace(/\.$/, '').split('.')) {
    const bytes = Buffer.from(label)
    parts.push(Buffer.from([bytes.length]), bytes)
  }
  parts.push(Buffer.from([0]))
  return Buffer.concat(parts)
}

function buildQuery(name, qtype, id = 0x2222) {
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

function parseMessage(message) {
  if (message.length < 12) throw new Error('short DNS message')
  const flags = message.readUInt16BE(2)
  const qd = message.readUInt16BE(4)
  const an = message.readUInt16BE(6)
  let offset = 12
  for (let i = 0; i < qd; i += 1) {
    offset = readName(message, offset).end + 4
  }
  const answers = []
  for (let i = 0; i < an; i += 1) {
    const named = readName(message, offset)
    offset = named.end
    const rtype = message.readUInt16BE(offset)
    const ttl = message.readUInt32BE(offset + 4)
    const rdlength = message.readUInt16BE(offset + 8)
    const rdataStart = offset + 10
    const data = message.subarray(rdataStart, rdataStart + rdlength)
    offset = rdataStart + rdlength
    if (rtype === TYPE.A && rdlength === 4) {
      answers.push({ type: 'A', ip: `${data[0]}.${data[1]}.${data[2]}.${data[3]}`, ttl })
    } else if (rtype === TYPE.AAAA && rdlength === 16) {
      const groups = []
      for (let j = 0; j < 16; j += 2) groups.push(data.readUInt16BE(j).toString(16))
      answers.push({ type: 'AAAA', ip: groups.join(':'), ttl })
    } else if (rtype === TYPE.CNAME) {
      // `ip` carries the CNAME target so `normalizedDns` compares it too.
      answers.push({ type: 'CNAME', ip: readName(message, rdataStart).name, ttl })
    }
  }
  return { rcode: flags & 0x000f, truncated: (flags & 0x0200) !== 0, answers }
}

/** Build an answer for `query`; `spec.ips` are strings. */
function buildAnswer(query, spec) {
  const question = query.subarray(12)
  // Locate the end of the question section (QNAME + type + class).
  let offset = 12
  while (query[offset] !== 0) offset += 1 + query[offset]
  const questionLength = offset + 1 + 4 - 12
  const header = Buffer.alloc(12)
  header.writeUInt16BE(query.readUInt16BE(0), 0)
  header.writeUInt16BE(0x8180 | (spec.rcode ?? 0), 2)
  header.writeUInt16BE(1, 4)
  header.writeUInt16BE((spec.ips ?? []).length, 6)
  const answerParts = []
  for (const entry of spec.ips ?? []) {
    const type = entry.includes(':') ? TYPE.AAAA : TYPE.A
    const data = type === TYPE.A
      ? Buffer.from(entry.split('.').map(Number))
      : Buffer.from(entry.split(':').flatMap((group) => {
        const value = parseInt(group || '0', 16)
        return [value >> 8, value & 0xff]
      }))
    // RR after the 2-byte name pointer: type, class, ttl, rdlength (10 bytes)
    const rr = Buffer.alloc(12)
    rr.writeUInt16BE(0xc00c, 0) // pointer to the question name
    rr.writeUInt16BE(type, 2)
    rr.writeUInt16BE(1, 4)
    rr.writeUInt32BE(spec.ttl ?? 60, 6)
    rr.writeUInt16BE(data.length, 10)
    answerParts.push(rr, data)
  }
  return Buffer.concat([header, question.subarray(0, questionLength), ...answerParts])
}

// ---------------------------------------------------------------------------
// Controlled DNS fixtures
// ---------------------------------------------------------------------------

/** A scripted resolver: `answers` maps "name/TYPE" to {ips, ttl, rcode, delayMs}. */
function resolver(answers) {
  return (name, qtype) => {
    const type = qtype === TYPE.AAAA ? 'AAAA' : qtype === TYPE.A ? 'A' : String(qtype)
    return answers[`${name.toLowerCase()}/${type}`] ?? { rcode: 3, ips: [] }
  }
}

function startUdpDns(handler) {
  const socket = dgram.createSocket('udp4')
  const counters = { queries: 0 }
  socket.on('message', (message, peer) => {
    counters.queries += 1
    let name = ''
    let qtype = 0
    try {
      const question = readName(message, 12)
      name = question.name
      qtype = message.readUInt16BE(question.end)
    } catch {
      return
    }
    const spec = handler(name, qtype)
    if (spec.silent) return
    const reply = buildAnswer(message, spec)
    const send = () => socket.send(reply, peer.port, peer.address)
    if (spec.delayMs) setTimeout(send, spec.delayMs)
    else send()
  })
  return new Promise((resolveServer) => {
    socket.bind(0, '127.0.0.1', () => {
      resolveServer({
        port: socket.address().port,
        counters,
        close: () => new Promise((done) => socket.close(done)),
      })
    })
  })
}

function startTcpDns(handler) {
  const counters = { queries: 0 }
  const server = net.createServer((socket) => {
    let buffered = Buffer.alloc(0)
    socket.on('data', (chunk) => {
      buffered = Buffer.concat([buffered, chunk])
      while (buffered.length >= 2) {
        const length = buffered.readUInt16BE(0)
        if (buffered.length < 2 + length) return
        const query = buffered.subarray(2, 2 + length)
        buffered = buffered.subarray(2 + length)
        counters.queries += 1
        const question = readName(query, 12)
        const qtype = query.readUInt16BE(question.end)
        const reply = buildAnswer(query, handler(question.name, qtype))
        const prefix = Buffer.alloc(2)
        prefix.writeUInt16BE(reply.length)
        socket.write(Buffer.concat([prefix, reply]))
      }
    })
    socket.on('error', () => socket.destroy())
  })
  return new Promise((resolveServer) => {
    server.listen(0, '127.0.0.1', () => {
      resolveServer({
        port: server.address().port,
        counters,
        close: () => new Promise((done) => server.close(done)),
      })
    })
  })
}

function startTlsDns(handler, tlsOptions) {
  const counters = { queries: 0 }
  const server = tls.createServer(tlsOptions, (socket) => {
    let buffered = Buffer.alloc(0)
    socket.on('data', (chunk) => {
      buffered = Buffer.concat([buffered, chunk])
      while (buffered.length >= 2) {
        const length = buffered.readUInt16BE(0)
        if (buffered.length < 2 + length) return
        const query = buffered.subarray(2, 2 + length)
        buffered = buffered.subarray(2 + length)
        counters.queries += 1
        const question = readName(query, 12)
        const qtype = query.readUInt16BE(question.end)
        const reply = buildAnswer(query, handler(question.name, qtype))
        const prefix = Buffer.alloc(2)
        prefix.writeUInt16BE(reply.length)
        socket.write(Buffer.concat([prefix, reply]))
      }
    })
    socket.on('error', () => socket.destroy())
  })
  return new Promise((resolveServer) => {
    server.listen(0, '127.0.0.1', () => {
      resolveServer({
        port: server.address().port,
        counters,
        close: () => new Promise((done) => server.close(done)),
      })
    })
  })
}

/** DoH over HTTP/1.1 + TLS (the pinned `DefaultHTTPVersions` starts with 1.1). */
function startDohDns(handler, tlsOptions) {
  const counters = { queries: 0 }
  const server = tls.createServer(tlsOptions, (socket) => {
    let buffered = Buffer.alloc(0)
    const onData = (chunk) => {
      buffered = Buffer.concat([buffered, chunk])
      const headEnd = buffered.indexOf('\r\n\r\n')
      if (headEnd < 0) return
      socket.off('data', onData)
      const head = buffered.subarray(0, headEnd).toString('latin1')
      const path = head.split('\r\n')[0].split(/\s+/)[1] ?? ''
      const encoded = new URL(path, 'https://example.invalid').searchParams.get('dns') ?? ''
      const query = Buffer.from(encoded.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
      counters.queries += 1
      let reply = Buffer.alloc(0)
      try {
        const question = readName(query, 12)
        const qtype = query.readUInt16BE(question.end)
        reply = buildAnswer(query, handler(question.name, qtype))
      } catch {
        reply = buildAnswer(query, { rcode: 1, ips: [] })
      }
      socket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: ${reply.length}\r\nConnection: close\r\n\r\n`)
      socket.write(reply)
      socket.end()
    }
    socket.on('data', onData)
    socket.on('error', () => socket.destroy())
  })
  return new Promise((resolveServer) => {
    server.listen(0, '127.0.0.1', () => {
      resolveServer({
        port: server.address().port,
        counters,
        close: () => new Promise((done) => server.close(done)),
      })
    })
  })
}

function startSilentUdp() {
  const socket = dgram.createSocket('udp4')
  const counters = { queries: 0 }
  socket.on('message', () => { counters.queries += 1 })
  return new Promise((resolveServer) => {
    socket.bind(0, '127.0.0.1', () => {
      resolveServer({
        port: socket.address().port,
        counters,
        close: () => new Promise((done) => socket.close(done)),
      })
    })
  })
}

/** Minimal SOCKS5 CONNECT server used by the `respect-rules` case. */
function startSocks5() {
  const counters = { connects: 0 }
  const server = net.createServer((socket) => {
    let stage = 'greeting'
    let buffered = Buffer.alloc(0)
    const onData = (chunk) => {
      buffered = Buffer.concat([buffered, chunk])
      if (stage === 'greeting') {
        if (buffered.length < 2 || buffered.length < 2 + buffered[1]) return
        buffered = buffered.subarray(2 + buffered[1])
        socket.write(Buffer.from([0x05, 0x00]))
        stage = 'request'
      }
      if (stage === 'request') {
        if (buffered.length < 5) return
        const atyp = buffered[3]
        let target = null
        let offset = 4
        if (atyp === 1) {
          target = `${buffered[4]}.${buffered[5]}.${buffered[6]}.${buffered[7]}`
          offset = 8
        } else if (atyp === 4) {
          const groups = []
          for (let i = 0; i < 8; i += 1) groups.push(buffered.readUInt16BE(4 + i * 2).toString(16))
          target = groups.join(':')
          offset = 20
        } else if (atyp === 3) {
          target = buffered.subarray(5, 5 + buffered[4]).toString('latin1')
          offset = 5 + buffered[4]
        }
        if (!target) return
        const targetPort = buffered.readUInt16BE(offset)
        const rest = buffered.subarray(offset + 2)
        stage = 'tunnel'
        socket.off('data', onData)
        counters.connects += 1
        const upstream = net.connect(targetPort, target, () => {
          socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
          if (rest.length) upstream.write(rest)
          upstream.pipe(socket)
          socket.pipe(upstream)
        })
        upstream.on('error', () => socket.destroy())
        socket.on('error', () => upstream.destroy())
      }
    }
    socket.on('data', onData)
    socket.on('error', () => socket.destroy())
  })
  return new Promise((resolveServer) => {
    server.listen(0, '127.0.0.1', () => {
      resolveServer({
        port: server.address().port,
        counters,
        close: () => new Promise((done) => { server.close(done) }),
      })
    })
  })
}

/// HTTP echo with a fixed Content-Length, matching `openTunnel.write` (which
/// delimits replies by HTTP framing).
function startEchoServer() {
  const server = net.createServer((socket) => {
    let buffered = Buffer.alloc(0)
    socket.on('data', (chunk) => {
      buffered = Buffer.concat([buffered, chunk])
      const headEnd = buffered.indexOf('\r\n\r\n')
      if (headEnd < 0) return
      const head = buffered.subarray(0, headEnd).toString('utf8')
      const length = Number(/content-length: *(\d+)/i.exec(head)?.[1] ?? 0)
      const body = buffered.subarray(headEnd + 4)
      if (body.length < length) return
      let marker = null
      try { marker = JSON.parse(body.subarray(0, length).toString('utf8')).marker ?? null } catch { marker = null }
      const reply = Buffer.from(JSON.stringify({ marker, receivedBytes: body.length }))
      socket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${reply.length}\r\nConnection: close\r\n\r\n`)
      socket.write(reply)
      socket.end()
    })
    socket.on('error', () => socket.destroy())
  })
  return new Promise((resolveServer) => {
    server.listen(0, '0.0.0.0', () => {
      resolveServer({
        port: server.address().port,
        close: () => new Promise((done) => server.close(done)),
      })
    })
  })
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

function startProcess(command, args, cwd) {
  const logs = { stdout: '', stderr: '' }
  const child = spawn(command, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] })
  child.stdout.on('data', (chunk) => { logs.stdout = (logs.stdout + chunk).slice(-6000) })
  child.stderr.on('data', (chunk) => { logs.stderr = (logs.stderr + chunk).slice(-6000) })
  const exited = new Promise((done) => child.once('exit', (code, signal) => done({ code, signal })))
  return { child, logs, exited }
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

function queryDns(port, name, qtype = TYPE.A, timeoutMs = 8000) {
  return new Promise((resolveQuery) => {
    const socket = dgram.createSocket('udp4')
    const started = performance.now()
    let settled = false
    const finish = (result) => {
      if (settled) return
      settled = true
      socket.close()
      resolveQuery({ ...result, elapsedMs: Math.round(performance.now() - started) })
    }
    socket.on('message', (message) => {
      try {
        const parsed = parseMessage(message)
        finish({ ...parsed, timeout: false })
      } catch (error) {
        finish({ error: error.message, timeout: false })
      }
    })
    socket.on('error', (error) => finish({ error: error.message, timeout: false }))
    socket.send(buildQuery(name, qtype), port, '127.0.0.1', (error) => {
      if (error) finish({ error: error.message, timeout: false })
    })
    setTimeout(() => finish({ timeout: true, answers: [], rcode: null }), timeoutMs)
  })
}

async function waitPort(port, timeoutMs = 12000) {
  const started = performance.now()
  while (performance.now() - started < timeoutMs) {
    const ok = await new Promise((resolveProbe) => {
      const socket = net.connect(port, '127.0.0.1')
      socket.once('connect', () => { socket.destroy(); resolveProbe(true) })
      socket.once('error', () => resolveProbe(false))
    })
    if (ok) return true
    await new Promise((done) => setTimeout(done, 100))
  }
  return false
}

async function attempt(mixedPort, host, targetPort, marker) {
  const exchange = await openTunnel({
    host: '127.0.0.1',
    port: mixedPort,
    target: { host, port: targetPort },
    connectTimeoutMs: 4000,
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
    const payload = `POST /probe HTTP/1.1\r\nHost: probe\r\nContent-Length: ${Buffer.byteLength(JSON.stringify({ marker }))}\r\nConnection: close\r\n\r\n${JSON.stringify({ marker })}`
    const reply = await exchange.write(payload, 4000)
    return {
      category: reply.includes(marker) ? 'echoed' : 'empty',
      connectStatus: status,
      replyLength: reply.length,
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

const A = (ip, ttl = 60) => ({ ips: [ip], ttl })
const NX = { rcode: 3, ips: [] }

const upstreamAnswers = {
  'ready.test/A': A('9.9.9.9'),
  'a.test/A': A('1.2.3.4'),
  'loop.test/A': A('127.0.0.1'),
  'filtered.test/A': A('1.1.1.1'),
  'public.test/A': A('8.8.8.8'),
  'only.test/A': A('9.9.9.9'),
  'fake.test/A': A('127.0.0.1'),
  'real.test/A': A('127.0.0.1'),
  'host-only.test/A': A('5.5.5.5'),
  'tcp.test/A': A('10.0.0.2'),
  'dot.test/A': A('10.2.0.1'),
  'doh.test/A': A('10.2.0.2'),
  'policy.test/A': A('10.0.0.1'),
  'deep.policy.test/A': A('10.0.0.1'),
  'v6.test/AAAA': { ips: ['2001:db8::1'], ttl: 60 },
  'rule.test/A': A('127.0.0.1'),
  'hosts-only.test/A': A('127.0.0.1'),
  'alias-target.test/A': A('9.9.9.9'),
  'geoip-zz.test/A': A('1.2.3.4'),
  'geoip-other.test/A': A('8.8.8.8'),
}

const policyAnswers = {
  'policy.test/A': A('10.0.0.3'),
  'deep.policy.test/A': A('10.0.0.3'),
}

const fallbackAnswers = {
  'filtered.test/A': A('7.7.7.7'),
  'only.test/A': A('6.6.6.6'),
  'geoip-zz.test/A': A('7.7.7.7'),
  'geoip-other.test/A': A('6.6.6.6'),
}

// Minimal protobuf geodata fixture: `GeoIPList { entry: GeoIP { country_code,
// cidr } }`, the same shapes T24 generates.
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

function formatDns(caseDef, fixtures) {
  const nameserver = (specs) => `[${specs.map((spec) => `'${spec}'`).join(', ')}]`
  const lines = [
    `mixed-port: {{mixed}}`,
    'mode: rule',
    'log-level: warning',
    'profile:',
    '  store-selected: false',
    '  store-fake-ip: false',
  ]
  if (caseDef.geodata) lines.push('geodata-mode: true')
  if (caseDef.hosts) {
    lines.push('hosts:')
    for (const [domain, ip] of Object.entries(caseDef.hosts)) lines.push(`  ${domain}: ${ip}`)
  }
  if (caseDef.proxies) {
    lines.push('proxies:')
    for (const line of caseDef.proxies) lines.push(`  - ${line}`)
  }
  lines.push('dns:')
  lines.push('  enable: true')
  lines.push(`  listen: 127.0.0.1:{{dns}}`)
  lines.push(`  enhanced-mode: ${caseDef.enhancedMode ?? 'normal'}`)
  if ((caseDef.enhancedMode ?? 'normal') === 'fake-ip') {
    lines.push('  fake-ip-range: 198.18.0.1/16')
    lines.push('  fake-ip-ttl: 3')
    if (caseDef.fakeIpFilter) lines.push(`  fake-ip-filter: [${caseDef.fakeIpFilter.map((name) => `'${name}'`).join(', ')}]`)
  }
  if (caseDef.ipv6 !== undefined) lines.push(`  ipv6: ${caseDef.ipv6}`)
  if (caseDef.useHosts !== undefined) lines.push(`  use-hosts: ${caseDef.useHosts}`)
  lines.push(`  nameserver: ${nameserver(caseDef.nameservers(fixtures))}`)
  if (caseDef.fallback) lines.push(`  fallback: ${nameserver(caseDef.fallback(fixtures))}`)
  if (caseDef.fallbackFilter) {
    lines.push('  fallback-filter:')
    for (const [key, value] of Object.entries(caseDef.fallbackFilter)) {
      lines.push(`    ${key}: ${JSON.stringify(value)}`)
    }
  }
  if (caseDef.policy) {
    lines.push('  nameserver-policy:')
    for (const [key, values] of Object.entries(caseDef.policy(fixtures))) {
      lines.push(`    '${key}': ${nameserver(values)}`)
    }
  }
  if (caseDef.respectRules) {
    lines.push('  respect-rules: true')
    lines.push(`  proxy-server-nameserver: ${nameserver(caseDef.proxyServerNameservers(fixtures))}`)
  }
  lines.push('rules:')
  for (const rule of caseDef.rules ?? ['MATCH,DIRECT']) lines.push(`  - ${rule}`)
  return lines.join('\n') + '\n'
}

const tcpNameserver = (fixtures) => [`tcp://127.0.0.1:${fixtures.tcp.port}`]
const udpNameserver = (fixtures) => [`udp://127.0.0.1:${fixtures.main.port}`]

const cases = [
  {
    id: 'a-record-udp',
    nameservers: udpNameserver,
    queries: ['a.test'],
    expect: (answers) => answers[0]?.rcode === 0 && answers[0]?.answers?.[0]?.ip === '1.2.3.4' && answers[0]?.answers?.[0]?.ttl === 60,
  },
  {
    id: 'nxdomain',
    nameservers: udpNameserver,
    queries: ['absent.test'],
    expect: (answers) => answers[0]?.rcode === 3 && (answers[0]?.answers?.length ?? 0) === 0,
  },
  {
    id: 'tcp-upstream',
    nameservers: tcpNameserver,
    queries: ['tcp.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '10.0.0.2',
  },
  {
    id: 'nameserver-policy',
    nameservers: udpNameserver,
    policy: (fixtures) => ({ '+.policy.test': [`udp://127.0.0.1:${fixtures.policy.port}`] }),
    queries: ['policy.test', 'deep.policy.test', 'a.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '10.0.0.3'
      && answers[1]?.answers?.[0]?.ip === '10.0.0.3'
      && answers[2]?.answers?.[0]?.ip === '1.2.3.4',
  },
  {
    id: 'fallback-ipcidr',
    nameservers: udpNameserver,
    fallback: (fixtures) => [`udp://127.0.0.1:${fixtures.fallback.port}`],
    fallbackFilter: { geoip: false, ipcidr: ['1.0.0.0/8'], domain: ['+.only.test'] },
    queries: ['filtered.test', 'public.test', 'only.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '7.7.7.7'
      && answers[1]?.answers?.[0]?.ip === '8.8.8.8'
      && answers[2]?.answers?.[0]?.ip === '6.6.6.6',
  },
  {
    // T22-A2: `!` in fallback-filter.geoip-code must not be dropped. The
    // filter is inverted by the resolver, so `zz` falls back for a non-zz
    // address and `!zz` for a zz one (pinned `LoadGeoIPMatcher` + `MatchIp`).
    id: 'fallback-geoip-code',
    geodata: true,
    nameservers: udpNameserver,
    fallback: (fixtures) => [`udp://127.0.0.1:${fixtures.fallback.port}`],
    fallbackFilter: { geoip: true, 'geoip-code': 'zz' },
    queries: ['geoip-zz.test', 'geoip-other.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '1.2.3.4'
      && answers[1]?.answers?.[0]?.ip === '6.6.6.6',
  },
  {
    id: 'fallback-geoip-code-negated',
    geodata: true,
    nameservers: udpNameserver,
    fallback: (fixtures) => [`udp://127.0.0.1:${fixtures.fallback.port}`],
    fallbackFilter: { geoip: true, 'geoip-code': '!zz' },
    queries: ['geoip-zz.test', 'geoip-other.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '7.7.7.7'
      && answers[1]?.answers?.[0]?.ip === '8.8.8.8',
  },
  {
    id: 'hosts-answer',
    hosts: { 'host-only.test': '1.2.3.4' },
    nameservers: udpNameserver,
    queries: ['host-only.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '1.2.3.4' && answers[0]?.answers?.[0]?.ttl === 10,
  },
  {
    id: 'use-hosts-false',
    hosts: { 'host-only.test': '1.2.3.4' },
    useHosts: false,
    nameservers: udpNameserver,
    queries: ['host-only.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '5.5.5.5',
  },
  {
    // T22-A2: the enhancer mutex was locked twice on this path, so a hosts
    // query in redir-host/fake-ip wedged the whole listener. All three queries
    // must answer, the last proving the listener is still serving.
    id: 'hosts-redir-host',
    enhancedMode: 'redir-host',
    hosts: { 'host-only.test': '1.2.3.4' },
    nameservers: udpNameserver,
    queries: ['localhost', 'host-only.test', 'a.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '127.0.0.1'
      && answers[0]?.answers?.[0]?.ttl === 10
      && answers[1]?.answers?.[0]?.ip === '1.2.3.4'
      && answers[2]?.answers?.[0]?.ip === '1.2.3.4',
  },
  {
    id: 'hosts-fake-ip',
    enhancedMode: 'fake-ip',
    hosts: { 'host-only.test': '1.2.3.4' },
    fakeIpFilter: ['real.test'],
    nameservers: udpNameserver,
    queries: ['localhost', 'host-only.test', 'fake.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '127.0.0.1'
      && answers[0]?.answers?.[0]?.ttl === 10
      && answers[1]?.answers?.[0]?.ip === '1.2.3.4'
      && answers[2]?.answers?.[0]?.ip === '198.18.0.4',
  },
  {
    // Domain-valued hosts: pinned replaces the question name, resolves the
    // target and prepends a CNAME (TTL 10), so the alias is not delegated.
    id: 'hosts-domain-alias',
    hosts: { 'alias.test': 'alias-target.test' },
    nameservers: udpNameserver,
    queries: ['alias.test'],
    expect: (answers) => answers[0]?.rcode === 0
      && answers[0]?.answers?.[0]?.type === 'CNAME'
      && answers[0]?.answers?.[0]?.ip === 'alias-target.test'
      && answers[0]?.answers?.[0]?.ttl === 10
      && answers[0]?.answers?.[1]?.type === 'A'
      && answers[0]?.answers?.[1]?.ip === '9.9.9.9',
  },
  {
    id: 'fake-ip',
    enhancedMode: 'fake-ip',
    fakeIpFilter: ['real.test'],
    nameservers: udpNameserver,
    queries: ['fake.test', 'fake.test', 'other.test', 'real.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '198.18.0.4'
      && answers[0]?.answers?.[0]?.ttl === 3
      && answers[1]?.answers?.[0]?.ip === '198.18.0.4'
      && answers[2]?.answers?.[0]?.ip === '198.18.0.5'
      && answers[3]?.answers?.[0]?.ip === '127.0.0.1',
  },
  {
    id: 'ipv6-disabled-aaaa',
    nameservers: udpNameserver,
    ipv6: false,
    queries: [{ name: 'v6.test', type: TYPE.AAAA }],
    expect: (answers) => answers[0]?.rcode === 0 && (answers[0]?.answers?.length ?? 0) === 0,
  },
  {
    id: 'dot-upstream',
    nameservers: (fixtures) => [`tls://127.0.0.1:${fixtures.dot.port}#skip-cert-verify=true`],
    queries: ['dot.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '10.2.0.1',
  },
  {
    id: 'doh-upstream',
    nameservers: (fixtures) => [`https://127.0.0.1:${fixtures.doh.port}/dns-query#skip-cert-verify=true`],
    queries: ['doh.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '10.2.0.2',
  },
  {
    id: 'timeout-is-servfail',
    nameservers: (fixtures) => [`udp://127.0.0.1:${fixtures.silent.port}`],
    queries: ['slow.test'],
    queryTimeoutMs: 12000,
    expect: (answers) => answers[0]?.rcode !== 0 && (answers[0]?.answers?.length ?? 0) === 0,
  },
  {
    id: 'respect-rules',
    nameservers: tcpNameserver,
    respectRules: true,
    proxyServerNameservers: () => ['223.5.5.5'],
    proxies: null,
    rules: ['IP-CIDR,127.0.0.1/32,RULES', 'MATCH,DIRECT'],
    socksTarget: '127.0.0.1',
    queries: ['tcp.test'],
    expect: (answers) => answers[0]?.answers?.[0]?.ip === '10.0.0.2',
  },
  {
    id: 'engine-ip-rule',
    nameservers: udpNameserver,
    rules: ['IP-CIDR,127.0.0.0/8,REJECT', 'MATCH,DIRECT'],
    connect: 'loop.test',
    expectConnect: 'blocked',
  },
  {
    id: 'engine-no-resolve',
    nameservers: udpNameserver,
    rules: ['IP-CIDR,127.0.0.0/8,REJECT,no-resolve', 'MATCH,DIRECT'],
    connect: 'loop.test',
    expectConnect: 'echoed',
  },
  {
    id: 'engine-fake-ip',
    enhancedMode: 'fake-ip',
    nameservers: udpNameserver,
    rules: ['MATCH,DIRECT'],
    fakeConnect: 'fake.test',
    expectConnect: 'echoed',
  },
]

function fill(template, context) {
  return template
    .replaceAll('{{mixed}}', String(context.mixedPort))
    .replaceAll('{{dns}}', String(context.dnsPort))
}

function rewriteProxies(line, context) {
  if (context.socksPort) {
    return line.replaceAll('{{socks}}', String(context.socksPort))
  }
  return line
}

async function runEngine(engine, binary, item, fixtures, dir, context) {
  let caseDef = item
  if (item.id === 'respect-rules') {
    // The upstream is reached through a SOCKS5 hop declared as the rule target.
    caseDef = {
      ...item,
      proxies: [`{name: RULES, type: socks5, server: 127.0.0.1, port: {{socks}}}`],
    }
  }
  const template = formatDns(caseDef, fixtures)
  const config = template
    .split('\n')
    .map((line) => fill(rewriteProxies(line, context), context))
    .join('\n')
  await writeFile(join(dir, 'config.yaml'), config)
  if (item.geodata) {
    // Pinned `geodata.InitGeoIP` sanity-loads CN from the file, so keep a CN
    // entry next to the zz one the fallback filter selects.
    await writeFile(join(dir, 'GeoIP.dat'), geoipDat([
      { code: 'CN', cidrs: [{ bytes: [10, 0, 0, 0], prefix: 8 }] },
      { code: 'zz', cidrs: [{ bytes: [1, 2, 3, 4], prefix: 32 }] },
    ]))
  }
  const args = engine === 'mihomo'
    ? ['-d', dir, '-f', join(dir, 'config.yaml')]
    : item.geodata
      ? [join(dir, 'config.yaml'), '--geosite-dir', dir]
      : [join(dir, 'config.yaml')]
  const handle = startProcess(binary, args, dir)
  // Readiness is a TCP/port check: a query-based probe would wait for the
  // 5s resolver timeout in the silent-upstream case.
  const readyDns = await waitPort(context.dnsPort)
  const readyMixed = await waitPort(context.mixedPort)
  const result = { engine, ready: readyDns && readyMixed, config, logs: handle.logs, dns: [], connect: null }
  if (!result.ready) {
    await stopProcess(handle)
    return result
  }
  try {
    if (item.fakeConnect) {
      const answer = await queryDns(context.dnsPort, item.fakeConnect)
      const fakeIp = answer.answers?.[0]?.ip
      result.fakeIp = fakeIp
      if (fakeIp) {
        result.connect = await attempt(context.mixedPort, fakeIp, fixtures.echo.port, 't22-fake')
      }
    } else if (item.connect) {
      result.connect = await attempt(context.mixedPort, item.connect, fixtures.echo.port, 't22-probe')
    } else {
      for (const query of item.queries) {
        const spec = typeof query === 'string' ? { name: query, type: TYPE.A } : query
        const answer = await queryDns(context.dnsPort, spec.name, spec.type, item.queryTimeoutMs ?? 8000)
        result.dns.push({ name: spec.name, type: spec.type, ...answer })
      }
    }
    result.counters = {
      main: fixtures.main.counters.queries,
      policy: fixtures.policy.counters.queries,
      fallback: fixtures.fallback.counters.queries,
      tcp: fixtures.tcp.counters.queries,
      dot: fixtures.dot.counters.queries,
      doh: fixtures.doh.counters.queries,
      socks: fixtures.socks.counters.connects,
    }
  } finally {
    await stopProcess(handle)
  }
  return result
}

function normalizedDns(answers) {
  return answers.map((answer) => ({
    rcode: answer.rcode,
    timeout: answer.timeout,
    answers: (answer.answers ?? []).map((entry) => `${entry.type}:${entry.ip}:${entry.ttl}`),
  }))
}

function normalizeConnect(engine, observation) {
  if (!observation) return null
  if (observation.category === 'closed') return 'blocked'
  if (observation.category === 'timeout' && engine === 'mihomo') return 'blocked'
  return observation.category
}

function parseArgs(argv) {
  const args = { mihomo: null, rust: null, out: null }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--mihomo') args.mihomo = resolve(argv[++index])
    else if (arg === '--rust') args.rust = resolve(argv[++index])
    else if (arg === '--out') args.out = resolve(argv[++index])
    else throw new Error(`unknown argument ${arg}`)
  }
  if (!args.mihomo || !args.rust || !args.out) throw new Error('usage: --mihomo <binary> --rust <binary> --out <json>')
  return args
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  const certDir = await mkdtemp(join(tmpdir(), 'billow-t22-cert-'))
  const keyPath = join(certDir, 'key.pem')
  const certPath = join(certDir, 'cert.pem')
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
    '-keyout', keyPath, '-out', certPath,
  ], { stdio: 'ignore' })
  const tlsOptions = {
    key: execFileSync('cat', [keyPath]),
    cert: execFileSync('cat', [certPath]),
  }

  const fixtures = {
    main: await startUdpDns(resolver(upstreamAnswers)),
    policy: await startUdpDns(resolver(policyAnswers)),
    fallback: await startUdpDns(resolver(fallbackAnswers)),
    tcp: await startTcpDns(resolver(upstreamAnswers)),
    dot: await startTlsDns(resolver(upstreamAnswers), tlsOptions),
    doh: await startDohDns(resolver(upstreamAnswers), tlsOptions),
    silent: await startSilentUdp(),
    socks: await startSocks5(),
    echo: await startEchoServer(),
  }
  const sandbox = await mkdtemp(join(tmpdir(), 'billow-t22-diff-'))
  const results = []
  try {
    for (const item of cases) {
      const entry = { id: item.id, engines: {} }
      for (const engine of ['mihomo', 'rust']) {
        const binary = engine === 'mihomo' ? args.mihomo : args.rust
        // A reserved TCP port can be taken by a UDP ephemeral socket before
        // the kernel binds `dns.listen`; retry once with fresh ports.
        let run = null
        for (let attempt = 0; attempt < 3; attempt += 1) {
          const dir = join(sandbox, `${item.id}-${engine}-${attempt}`)
          await mkdir(dir, { recursive: true })
          const context = {
            mixedPort: await reservePort(),
            dnsPort: await reservePort(),
            socksPort: fixtures.socks.port,
          }
          // Counters are per-run for the cases that depend on them.
          for (const fixture of [fixtures.main, fixtures.policy, fixtures.fallback, fixtures.tcp, fixtures.dot, fixtures.doh, fixtures.socks]) {
            for (const key of Object.keys(fixture.counters)) fixture.counters[key] = 0
          }
          run = await runEngine(engine, binary, item, fixtures, dir, context)
          run.context = context
          if (run.ready) break
          const stderr = run.logs?.stderr ?? ''
          const startupLogs = run.logs?.stdout ?? ''
          if (!/Address already in use|address already in use/.test(stderr + startupLogs)) break
        }
        entry.engines[engine] = run
      }
      const mihomo = entry.engines.mihomo
      const rust = entry.engines.rust
      let status
      if (!mihomo.ready || !rust.ready) {
        status = 'startup-failed'
      } else if (item.connect || item.fakeConnect) {
        const normalized = {
          mihomo: normalizeConnect('mihomo', mihomo.connect),
          rust: normalizeConnect('rust', rust.connect),
        }
        entry.observed = normalized
        status = normalized.mihomo === normalized.rust && normalized.rust === (item.expectConnect ?? 'echoed')
          ? 'pass'
          : normalized.mihomo !== normalized.rust ? 'differ' : 'unexpected'
        if (item.fakeConnect) {
          entry.fakeIp = { mihomo: mihomo.fakeIp, rust: rust.fakeIp }
          if (mihomo.fakeIp !== rust.fakeIp) status = 'differ'
        }
      } else {
        const left = normalizedDns(mihomo.dns)
        const right = normalizedDns(rust.dns)
        entry.observed = { mihomo: left, rust: right }
        const same = JSON.stringify(left) === JSON.stringify(right)
        const expectation = item.expect(rust.dns)
        status = same && expectation ? 'pass' : !same ? 'differ' : 'unexpected'
        if (item.id === 'respect-rules') {
          entry.socksConnects = { mihomo: mihomo.counters?.socks ?? 0, rust: rust.counters?.socks ?? 0 }
          if ((mihomo.counters?.socks ?? 0) < 1 || (rust.counters?.socks ?? 0) < 1) status = 'unexpected'
        }
      }
      entry.status = status
      results.push(entry)
    }
    const summary = {
      cases: results.length,
      pass: results.filter((entry) => entry.status === 'pass').length,
      differ: results.filter((entry) => entry.status === 'differ').length,
      unexpected: results.filter((entry) => entry.status === 'unexpected').length,
      startupFailed: results.filter((entry) => entry.status === 'startup-failed').length,
    }
    const report = {
      format: 't22-differential',
      version: 1,
      startedAt: new Date().toISOString(),
      mihomo: args.mihomo,
      rust: args.rust,
      fixtures: Object.fromEntries(Object.entries(fixtures).map(([name, value]) => [name, value.port])),
      summary,
      notes: [
        'Both engines answer on their own dns.listen with the same effective configuration; answers are compared as rcode + A/AAAA address + TTL.',
        'DoT/DoH use self-signed certificates with skip-cert-verify, as the pinned `#skip-cert-verify=true` parameter allows.',
        'The timeout case compares the failure rcode, not elapsed time: both resolvers use the pinned 5s timeout.',
        'respect-rules is compared through a loopback SOCKS5 hop: the rule IP-CIDR,127.0.0.1/32,RULES must route the TCP DNS upstream through it for both engines.',
        'CONNECT cases normalize Mihomo\'s 200-then-close rejection to `blocked`; the Rust inbound answers 403.',
        'Not covered here (named gaps, see evidence): DoQ, DHCP/system/Tailscale/EasyTier/rcode upstreams, fake-ip-filter rule mode, profile.store-fake-ip persistence, nameserver #proxy names, EDNS client subnet, name-cert-verify, and HTTP/3 DoH.',
      ],
      results,
      exitOk: summary.differ === 0 && summary.unexpected === 0 && summary.startupFailed === 0,
    }
    await writeFile(args.out, JSON.stringify(report, null, 2))
    console.log(JSON.stringify(summary))
    process.exitCode = report.exitOk ? 0 : 1
  } finally {
    for (const fixture of Object.values(fixtures)) await fixture.close()
    await rm(sandbox, { recursive: true, force: true }).catch(() => null)
    await rm(certDir, { recursive: true, force: true }).catch(() => null)
  }
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 2
})
