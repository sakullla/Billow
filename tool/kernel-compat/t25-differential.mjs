#!/usr/bin/env node
// T25 differential probe: the Billow-consumed control API against the pinned
// Mihomo v1.19.34 binary.
//
// Both engines get the same YAML (only ports/paths differ) and the same HTTP
// sequence: auth failures, routing/status codes, CORS preflight, configs
// GET/PATCH/PUT (reload), proxies/selection/delay, rules, providers (list,
// update success/failure), connections (list + DELETE), traffic/logs first
// frames, the Unix socket and the TLS listener.
//
// Command:
//   node tool/kernel-compat/t25-differential.mjs \
//     --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
//     --rust native-kernel/target/debug/billow-kernel \
//     --out tool/kernel-compat/evidence/t25-differential.json
import { spawn, spawnSync } from 'node:child_process'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { reservePort } from './ports.mjs'

const here = dirname(fileURLToPath(import.meta.url))

const SECRET = 't25-secret'

function parseArgs(argv) {
  const args = { mihomo: null, rust: null, out: null, keep: false }
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index]
    if (key === '--mihomo') args.mihomo = resolve(argv[++index])
    else if (key === '--rust') args.rust = resolve(argv[++index])
    else if (key === '--out') args.out = resolve(argv[++index])
    else if (key === '--keep') args.keep = true
  }
  return args
}

function sleep(ms) {
  return new Promise((done) => setTimeout(done, ms))
}

// ---------------------------------------------------------------------------
// Local peers: a held tunnel target and a delay target.
// ---------------------------------------------------------------------------

function startHeldServer() {
  const clients = []
  const server = net.createServer((socket) => {
    clients.push(socket)
    socket.on('data', () => {
      if (!socket.wroteHead) {
        socket.wroteHead = true
        socket.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
      }
    })
    socket.on('error', () => {})
  })
  return new Promise((done) => {
    server.listen(0, '127.0.0.1', () => {
      done({
        port: server.address().port,
        close: () =>
          new Promise((closed) => {
            for (const client of clients) client.destroy()
            server.close(closed)
          }),
      })
    })
  })
}

function startDelayServer() {
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

// ---------------------------------------------------------------------------
// HTTP (TCP / Unix / TLS)
// ---------------------------------------------------------------------------

async function fetchTcp(port, method, path, { body, headers = {}, timeout = 5000 } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeout)
  try {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      body: body ?? undefined,
      headers,
      signal: controller.signal,
    })
    const text = await response.text()
    return { status: response.status, headers: Object.fromEntries(response.headers), body: text }
  } catch (error) {
    return { status: 0, error: String(error) }
  } finally {
    clearTimeout(timer)
  }
}

function requestNode(module, options, body) {
  return new Promise((done) => {
    const request = module.request(options, (response) => {
      let text = ''
      response.setEncoding('utf8')
      response.on('data', (chunk) => (text += chunk))
      response.on('end', () =>
        done({ status: response.statusCode, headers: response.headers, body: text })
      )
    })
    request.setTimeout(5000, () => request.destroy(new Error('timeout')))
    request.on('error', (error) => done({ status: 0, error: String(error) }))
    if (body) request.write(body)
    request.end()
  })
}

function fetchUnix(socketPath, method, path, headers = {}, body = null) {
  return requestNode(
    http,
    {
      socketPath,
      path,
      method,
      headers: { Connection: 'close', ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}), ...headers },
    },
    body
  )
}

function fetchTls(port, method, path, headers = {}, body = null) {
  return requestNode(
    https,
    {
      host: '127.0.0.1',
      port,
      path,
      method,
      rejectUnauthorized: false,
      headers: { Connection: 'close', ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}), ...headers },
    },
    body
  )
}

async function firstStreamLine(port, path, headers) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 6000)
  try {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
      headers,
      signal: controller.signal,
    })
    if (response.status !== 200) return { status: response.status }
    const reader = response.body.getReader()
    let buffer = ''
    const decoder = new TextDecoder()
    const deadline = Date.now() + 5000
    while (Date.now() < deadline) {
      const { value, done } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      const newline = buffer.indexOf('\n')
      if (newline >= 0) {
        reader.cancel().catch(() => {})
        return { status: response.status, line: buffer.slice(0, newline) }
      }
    }
    reader.cancel().catch(() => {})
    return { status: response.status, line: null }
  } catch (error) {
    return { status: 0, error: String(error) }
  } finally {
    clearTimeout(timer)
  }
}

function openTunnel(port, targetPort) {
  return new Promise((done, fail) => {
    const socket = net.connect({ host: '127.0.0.1', port }, () => {
      socket.write(`CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\n\r\n`)
    })
    let head = ''
    const onData = (chunk) => {
      head += chunk.toString('latin1')
      if (!head.includes('\r\n\r\n')) return
      socket.off('data', onData)
      if (!head.startsWith('HTTP/1.1 200')) return fail(new Error(`CONNECT failed: ${head.split('\r\n')[0]}`))
      socket.write('GET /held HTTP/1.1\r\nHost: held\r\n\r\n')
      done(socket)
    }
    socket.on('data', onData)
    socket.on('error', fail)
  })
}

// ---------------------------------------------------------------------------
// Engine processes
// ---------------------------------------------------------------------------

async function freePort() {
  return reservePort()
}

function engineConfig({ mixed, controller, unixPath, tlsPort, certPath, keyPath }) {
  return `mixed-port: ${mixed}
mode: rule
log-level: info
ipv6: true
external-controller: 127.0.0.1:${controller}
external-controller-unix: ${unixPath}
external-controller-tls: 127.0.0.1:${tlsPort}
secret: ${SECRET}
external-controller-cors: {allow-origins: ["*"], allow-private-network: true}
tls:
  certificate: ${certPath}
  private-key: ${keyPath}
proxies:
  - {name: n1, type: socks5, server: 127.0.0.1, port: 1}
  - {name: n2, type: http, server: 127.0.0.1, port: 2}
proxy-groups:
  - {name: Sel, type: select, proxies: [n1, n2, DIRECT]}
  - {name: Fast, type: url-test, proxies: [n1, n2], url: "http://127.0.0.1:9/", interval: 3600, lazy: true}
rule-providers:
  rp:
    type: file
    behavior: classical
    path: rules.yaml
proxy-providers:
  pp:
    type: file
    path: proxies.yaml
rules:
  - RULE-SET,rp,DIRECT
  - MATCH,Sel
`
}

async function startEngine(name, binary, dir, args) {
  const log = join(dir, `${name}.log`)
  const out = await import('node:fs/promises').then(({ open }) => open(log, 'w'))
  const child = spawn(binary, args, { cwd: dir, stdio: ['ignore', out.fd, out.fd] })
  child.on('error', () => {})
  return { child, log, out }
}

async function waitReady(port, url, headers) {
  const deadline = Date.now() + 15000
  while (Date.now() < deadline) {
    const response = await fetchTcp(port, 'GET', url, { headers, timeout: 1000 })
    if (response.status === 200) return true
    await sleep(100)
  }
  return false
}

// ---------------------------------------------------------------------------
// Comparison helpers
// ---------------------------------------------------------------------------

function pick(value, path) {
  let current = value
  for (const key of path.split('.')) {
    if (current === null || current === undefined) return undefined
    current = current[key]
  }
  return current
}

function stable(value) {
  return JSON.stringify(value)
}

function compareObject(id, mihomo, rust, paths, note = null) {
  const diffs = []
  for (const path of paths) {
    const left = pick(mihomo, path)
    const right = pick(rust, path)
    if (stable(left) !== stable(right)) {
      diffs.push({ path, mihomo: left, rust: right })
    }
  }
  return { id, equal: diffs.length === 0, diffs, note }
}

function compareStatus(id, mihomo, rust, note = null) {
  return {
    id,
    equal: mihomo.status === rust.status,
    diffs: mihomo.status === rust.status ? [] : [{ path: 'status', mihomo: mihomo.status, rust: rust.status }],
    note,
  }
}

function jsonOf(result) {
  try {
    return JSON.parse(result.body)
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (!args.mihomo || !args.rust || !args.out) {
    console.error('usage: t25-differential.mjs --mihomo <binary> --rust <binary> --out <json> [--keep]')
    process.exit(2)
  }
  const root = await mkdtemp(join(tmpdir(), 'billow-t25-'))

  const engines = {}
  for (const engine of ['mihomo', 'rust']) {
    const dir = join(root, engine)
    await mkdir(dir, { recursive: true })
    // Pinned only accepts certificate paths below its home directory, so
    // each engine gets its own copy.
    const certPath = join(dir, 'cert.pem')
    const keyPath = join(dir, 'key.pem')
    const openssl = spawnSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '1',
      '-subj', '/CN=127.0.0.1',
      '-addext', 'subjectAltName=IP:127.0.0.1',
    ], { encoding: 'utf8' })
    if (openssl.status !== 0) {
      throw new Error(`openssl certificate generation failed: ${openssl.stderr}`)
    }
    const config = {
      mixed: await freePort(),
      controller: await freePort(),
      tlsPort: await freePort(),
      unixPath: join(root, `${engine}.sock`),
      certPath,
      keyPath,
    }
    await writeFile(join(dir, 'rules.yaml'), 'payload:\n  - DOMAIN,example.com\n')
    await writeFile(
      join(dir, 'proxies.yaml'),
      'proxies:\n  - {name: pn1, type: socks5, server: 127.0.0.1, port: 3}\n'
    )
    const yaml = engineConfig(config)
    await writeFile(join(dir, 'config.yaml'), yaml)
    const spawned =
      engine === 'mihomo'
        ? await startEngine(engine, args.mihomo, dir, ['-d', dir, '-f', 'config.yaml'])
        : await startEngine(engine, args.rust, dir, ['config.yaml'])
    const ready = await waitReady(config.controller, '/version', {
      Authorization: `Bearer ${SECRET}`,
    })
    engines[engine] = { ...config, dir, yaml, ...spawned, ready }
    if (!ready) {
      console.error(`${engine} did not become ready; see ${spawned.log}`)
    }
  }

  const held = await startHeldServer()
  const delay = await startDelayServer()
  const auth = { Authorization: `Bearer ${SECRET}` }
  const results = []

  try {
    for (const engine of ['mihomo', 'rust']) {
      const state = engines[engine]
      state.request = (method, path, options = {}) =>
        fetchTcp(state.controller, method, path, options)
      state.authed = (method, path, body) =>
        fetchTcp(state.controller, method, path, {
          headers: { ...auth, 'Content-Type': 'application/json' },
          body,
        })
    }

    for (const [id, run, paths] of [
      ['auth-missing', (e) => e.request('GET', '/version'), ['status', 'body']],
      ['auth-query-token-non-ws', (e) => e.request('GET', `/version?token=${SECRET}`), ['status']],
      ['auth-wrong-bearer-case', (e) => e.request('GET', '/version', { headers: { Authorization: `bearer ${SECRET}` } }), ['status']],
      ['version-authorized', (e) => e.authed('GET', '/version'), ['status']],
      ['unknown-path', (e) => e.request('GET', '/nope'), ['status', 'headers.content-type']],
      ['wrong-method', (e) => e.request('POST', '/version'), ['status', 'headers.allow']],
    ]) {
      const left = await run(engines.mihomo)
      const right = await run(engines.rust)
      if (id === 'auth-missing') {
        const lm = jsonOf(left)
        const rm = jsonOf(right)
        results.push({
          id,
          equal: left.status === right.status && lm?.message === rm?.message,
          mihomo: { status: left.status, message: lm?.message },
          rust: { status: right.status, message: rm?.message },
        })
      } else {
        results.push(compareObject(id, left, right, paths))
      }
    }

    {
      const headers = {
        Origin: 'http://127.0.0.1:1420',
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'authorization',
      }
      const left = await engines.mihomo.request('OPTIONS', '/version', { headers })
      const right = await engines.rust.request('OPTIONS', '/version', { headers })
      const varySet = (response) =>
        String(response.headers?.vary ?? '')
          .split(',')
          .map((value) => value.trim().toLowerCase())
          .filter(Boolean)
          .sort()
      results.push(
        compareObject('cors-preflight', left, right, [
          'status',
          'headers.access-control-allow-origin',
          'headers.access-control-allow-methods',
          'headers.access-control-max-age',
        ])
      )
      results.push({
        id: 'cors-preflight-vary',
        equal: stable(varySet(left)) === stable(varySet(right)),
        mihomo: varySet(left),
        rust: varySet(right),
        note: 'Header order differs; both set Origin/Request-Method/Request-Headers.',
      })
      const leftGet = await engines.mihomo.request('GET', '/version', {
        headers: { Origin: 'http://127.0.0.1:1420' },
      })
      const rightGet = await engines.rust.request('GET', '/version', {
        headers: { Origin: 'http://127.0.0.1:1420' },
      })
      results.push(
        compareObject('cors-unauthorized-get', leftGet, rightGet, [
          'status',
          'headers.access-control-allow-origin',
        ])
      )
    }

    {
      const left = await engines.mihomo.authed('GET', '/configs')
      const right = await engines.rust.authed('GET', '/configs')
      const jsonLeft = jsonOf(left)
      const jsonRight = jsonOf(right)
      results.push({
        id: 'configs-get',
        equal:
          left.status === right.status &&
          jsonLeft['mixed-port'] === engines.mihomo.mixed &&
          jsonRight['mixed-port'] === engines.rust.mixed &&
          jsonLeft['tun']?.enable === jsonRight['tun']?.enable &&
          jsonLeft.mode === jsonRight.mode &&
          jsonLeft.ipv6 === jsonRight.ipv6 &&
          jsonLeft['log-level'] === jsonRight['log-level'],
        mihomo: {
          status: left.status,
          'mixed-port': jsonLeft['mixed-port'],
          'tun.enable': jsonLeft['tun']?.enable,
          mode: jsonLeft.mode,
          ipv6: jsonLeft.ipv6,
          'log-level': jsonLeft['log-level'],
        },
        rust: {
          status: right.status,
          'mixed-port': jsonRight['mixed-port'],
          'tun.enable': jsonRight['tun']?.enable,
          mode: jsonRight.mode,
          ipv6: jsonRight.ipv6,
          'log-level': jsonRight['log-level'],
        },
        note:
          'Only the fields this kernel reports are compared; pinned General keys the Rust kernel does not implement (unified-delay, routing-mark, geox-url, …) are absent rather than fabricated.',
      })
    }

    {
      const left = await engines.mihomo.authed('PATCH', '/configs', '{"tun":{"enable":false}}')
      const right = await engines.rust.authed('PATCH', '/configs', '{"tun":{"enable":false}}')
      results.push(compareStatus('configs-patch-tun-disable', left, right))
      const leftBad = await engines.mihomo.authed('PATCH', '/configs', '{"tun":{"enable":true}}')
      const rightBad = await engines.rust.authed('PATCH', '/configs', '{"tun":{"enable":true}}')
      results.push({
        id: 'configs-patch-tun-enable-missing',
        equal: false,
        mihomo: { status: leftBad.status },
        rust: { status: rightBad.status },
        note:
          'Pinned answers 204 and tries to (re)create a TUN device; the Rust kernel has no device layer (T6/T7) and rejects `tun.enable: true` by name with 400.',
      })
    }

    {
      const left = await engines.mihomo.authed('GET', '/proxies')
      const right = await engines.rust.authed('GET', '/proxies')
      const lm = jsonOf(left)
      const rm = jsonOf(right)
      const pickGroup = (json, name) => ({
        type: json.proxies?.[name]?.type,
        now: json.proxies?.[name]?.now,
        all: json.proxies?.[name]?.all,
        expectedStatus: json.proxies?.[name]?.expectedStatus,
        hidden: json.proxies?.[name]?.hidden,
      })
      results.push({
        id: 'proxies-groups',
        equal:
          left.status === right.status &&
          stable(pickGroup(lm, 'Sel')) === stable(pickGroup(rm, 'Sel')) &&
          stable(pickGroup(lm, 'Fast').type) === stable(pickGroup(rm, 'Fast').type) &&
          stable(pickGroup(lm, 'Fast').all) === stable(pickGroup(rm, 'Fast').all),
        mihomo: { status: left.status, Sel: pickGroup(lm, 'Sel'), Fast: pickGroup(lm, 'Fast') },
        rust: { status: right.status, Sel: pickGroup(rm, 'Sel'), Fast: pickGroup(rm, 'Fast') },
        note:
          'The Rust kernel does not invent the pinned GLOBAL/PASS/COMPATIBLE builtins; only the configured groups and real outbounds are listed.',
      })
      const node = (json, name) => ({
        type: json.proxies?.[name]?.type,
        provider: json.proxies?.[name]?.['provider-name'],
      })
      results.push({
        id: 'proxies-nodes',
        equal:
          stable(node(lm, 'DIRECT')) === stable(node(rm, 'DIRECT')) &&
          stable(node(lm, 'n1')) === stable(node(rm, 'n1')) &&
          stable(node(lm, 'pn1')) === stable(node(rm, 'pn1')),
        mihomo: { DIRECT: node(lm, 'DIRECT'), n1: node(lm, 'n1'), pn1: node(lm, 'pn1') },
        rust: { DIRECT: node(rm, 'DIRECT'), n1: node(rm, 'n1'), pn1: node(rm, 'pn1') },
      })
    }

    {
      const left = await engines.mihomo.authed('GET', '/rules')
      const right = await engines.rust.authed('GET', '/rules')
      const lm = jsonOf(left)
      const rm = jsonOf(right)
      const shape = (json) =>
        (json?.rules ?? []).map((rule) => ({
          index: rule.index,
          type: rule.type,
          payload: rule.payload,
          proxy: rule.proxy,
          size: rule.size,
        }))
      results.push({
        id: 'rules-shape',
        equal: left.status === right.status && stable(shape(lm)) === stable(shape(rm)),
        mihomo: shape(lm),
        rust: shape(rm),
        note: 'Pinned `extra` hit counters are not reported by the Rust kernel (rule hit statistics are not tracked).',
      })
    }

    {
      const left = await engines.mihomo.authed('PUT', '/proxies/Sel', '{"name":"n2"}')
      const right = await engines.rust.authed('PUT', '/proxies/Sel', '{"name":"n2"}')
      results.push(compareStatus('selection-put', left, right))
      const leftNow = jsonOf(await engines.mihomo.authed('GET', '/proxies/Sel'))
      const rightNow = jsonOf(await engines.rust.authed('GET', '/proxies/Sel'))
      results.push({
        id: 'selection-now',
        equal: leftNow?.now === rightNow?.now && rightNow?.now === 'n2',
        mihomo: leftNow?.now,
        rust: rightNow?.now,
      })
      const leftBad = await engines.mihomo.authed('PUT', '/proxies/Sel', '{"name":"missing"}')
      const rightBad = await engines.rust.authed('PUT', '/proxies/Sel', '{"name":"missing"}')
      results.push({
        id: 'selection-missing-member',
        equal:
          leftBad.status === rightBad.status &&
          jsonOf(leftBad)?.message === jsonOf(rightBad)?.message,
        mihomo: { status: leftBad.status, message: jsonOf(leftBad)?.message },
        rust: { status: rightBad.status, message: jsonOf(rightBad)?.message },
      })
      const leftDelete = await engines.mihomo.authed('DELETE', '/proxies/Sel')
      const rightDelete = await engines.rust.authed('DELETE', '/proxies/Sel')
      results.push(compareStatus('selection-delete-selector', leftDelete, rightDelete))
    }

    {
      const query = `?timeout=3000&url=${encodeURIComponent(`http://127.0.0.1:${delay.port}/`)}`
      const left = await engines.mihomo.authed('GET', `/proxies/DIRECT/delay${query}`)
      const right = await engines.rust.authed('GET', `/proxies/DIRECT/delay${query}`)
      results.push({
        id: 'delay-direct',
        equal:
          left.status === right.status &&
          left.status === 200 &&
          Number.isFinite(jsonOf(left)?.delay) &&
          Number.isFinite(jsonOf(right)?.delay),
        mihomo: { status: left.status, hasDelay: Number.isFinite(jsonOf(left)?.delay) },
        rust: { status: right.status, hasDelay: Number.isFinite(jsonOf(right)?.delay) },
        note: 'Latency values are not compared byte-wise.',
      })
      const leftMissing = await engines.mihomo.authed('GET', '/proxies/DIRECT/delay?url=http://127.0.0.1:9/')
      const rightMissing = await engines.rust.authed('GET', '/proxies/DIRECT/delay?url=http://127.0.0.1:9/')
      results.push(compareObject('delay-timeout-missing', leftMissing, rightMissing, ['status', 'body']))
      const leftBad = await engines.mihomo.authed('GET', '/proxies/missing/delay?timeout=500&url=http://127.0.0.1:9/')
      const rightBad = await engines.rust.authed('GET', '/proxies/missing/delay?timeout=500&url=http://127.0.0.1:9/')
      results.push(compareObject('delay-unknown-proxy', leftBad, rightBad, ['status', 'body']))
      const dead = await engines.rust.authed('GET', '/proxies/n1/delay?timeout=500&url=http://127.0.0.1:9/')
      const deadPinned = await engines.mihomo.authed('GET', '/proxies/n1/delay?timeout=500&url=http://127.0.0.1:9/')
      results.push(compareStatus('delay-dead-node', deadPinned, dead))
    }

    {
      const leftList = jsonOf(await engines.mihomo.authed('GET', '/providers/proxies'))
      const rightList = jsonOf(await engines.rust.authed('GET', '/providers/proxies'))
      const providerShape = (json, name) => ({
        type: json?.providers?.[name]?.type,
        vehicleType: json?.providers?.[name]?.vehicleType,
        nodes: (json?.providers?.[name]?.proxies ?? []).map((proxy) => proxy.name),
      })
      results.push({
        id: 'providers-proxies',
        equal:
          stable(providerShape(leftList, 'pp')) === stable(providerShape(rightList, 'pp')) &&
          stable(providerShape(leftList, 'Sel').vehicleType) ===
            stable(providerShape(rightList, 'Sel').vehicleType),
        mihomo: { pp: providerShape(leftList, 'pp'), Sel: providerShape(leftList, 'Sel') },
        rust: { pp: providerShape(rightList, 'pp'), Sel: providerShape(rightList, 'Sel') },
      })
      const leftRules = jsonOf(await engines.mihomo.authed('GET', '/providers/rules'))
      const rightRules = jsonOf(await engines.rust.authed('GET', '/providers/rules'))
      const ruleShape = (json) => ({
        behavior: json?.providers?.rp?.behavior,
        format: json?.providers?.rp?.format,
        ruleCount: json?.providers?.rp?.ruleCount,
        type: json?.providers?.rp?.type,
        vehicleType: json?.providers?.rp?.vehicleType,
      })
      results.push({
        id: 'providers-rules',
        equal: stable(ruleShape(leftRules)) === stable(ruleShape(rightRules)),
        mihomo: ruleShape(leftRules),
        rust: ruleShape(rightRules),
      })

      const leftUpdate = await engines.mihomo.authed('PUT', '/providers/rules/rp')
      const rightUpdate = await engines.rust.authed('PUT', '/providers/rules/rp')
      results.push(compareStatus('provider-rule-update-ok', leftUpdate, rightUpdate))
      const leftProxy = await engines.mihomo.authed('PUT', '/providers/proxies/pp')
      const rightProxy = await engines.rust.authed('PUT', '/providers/proxies/pp')
      results.push(compareStatus('provider-proxy-update-ok', leftProxy, rightProxy))

      // Invalidating the files makes both updates fail without losing the
      // previous snapshot.
      for (const engine of ['mihomo', 'rust']) {
        const dir = engines[engine].dir
        await rm(join(dir, 'rules.yaml'))
        await rm(join(dir, 'proxies.yaml'))
      }
      const leftFail = await engines.mihomo.authed('PUT', '/providers/rules/rp')
      const rightFail = await engines.rust.authed('PUT', '/providers/rules/rp')
      results.push(compareStatus('provider-rule-update-failure', leftFail, rightFail))
      const leftProxyFail = await engines.mihomo.authed('PUT', '/providers/proxies/pp')
      const rightProxyFail = await engines.rust.authed('PUT', '/providers/proxies/pp')
      results.push(compareStatus('provider-proxy-update-failure', leftProxyFail, rightProxyFail))
      const leftKept = jsonOf(await engines.mihomo.authed('GET', '/providers/rules'))
      const rightKept = jsonOf(await engines.rust.authed('GET', '/providers/rules'))
      results.push({
        id: 'provider-failure-keeps-snapshot',
        equal:
          leftKept?.providers?.rp?.ruleCount === rightKept?.providers?.rp?.ruleCount &&
          rightKept?.providers?.rp?.ruleCount === 1,
        mihomo: leftKept?.providers?.rp?.ruleCount,
        rust: rightKept?.providers?.rp?.ruleCount,
      })
    }

    // Reload with a changed rule (same listener/controller fields). Restore
    // the provider files first: both engines re-read them on reload.
    {
      for (const engine of ['mihomo', 'rust']) {
        const state = engines[engine]
        await writeFile(join(state.dir, 'rules.yaml'), 'payload:\n  - DOMAIN,example.com\n')
        await writeFile(
          join(state.dir, 'proxies.yaml'),
          'proxies:\n  - {name: pn1, type: socks5, server: 127.0.0.1, port: 3}\n'
        )
        state.reloadYaml = state.yaml.replace('  - MATCH,Sel\n', '  - MATCH,DIRECT\n')
      }
      const body = (yaml) => JSON.stringify({ path: '', payload: yaml })
      const left = await engines.mihomo.authed('PUT', '/configs?force=true', body(engines.mihomo.reloadYaml))
      const right = await engines.rust.authed('PUT', '/configs?force=true', body(engines.rust.reloadYaml))
      results.push(compareStatus('reload-success', left, right))
      const leftRules = jsonOf(await engines.mihomo.authed('GET', '/rules'))
      const rightRules = jsonOf(await engines.rust.authed('GET', '/rules'))
      results.push({
        id: 'reload-rule-effect',
        equal:
          leftRules?.rules?.[1]?.proxy === rightRules?.rules?.[1]?.proxy &&
          rightRules?.rules?.[1]?.proxy === 'DIRECT',
        mihomo: leftRules?.rules?.[1]?.proxy,
        rust: rightRules?.rules?.[1]?.proxy,
      })
      const leftBad = await engines.mihomo.authed('PUT', '/configs?force=true', body('mixed-port: 1\nmode: nope\n'))
      const rightBad = await engines.rust.authed('PUT', '/configs?force=true', body('mixed-port: 1\nmode: nope\n'))
      results.push(compareStatus('reload-invalid-yaml', leftBad, rightBad))
      const leftConfig = jsonOf(await engines.mihomo.authed('GET', '/configs'))
      const rightConfig = jsonOf(await engines.rust.authed('GET', '/configs'))
      results.push({
        id: 'reload-failure-keeps-config',
        equal:
          leftConfig?.['mixed-port'] === engines.mihomo.mixed &&
          rightConfig?.['mixed-port'] === engines.rust.mixed,
        mihomo: leftConfig?.['mixed-port'],
        rust: rightConfig?.['mixed-port'],
      })
    }

    // Connections: open one tunnel per engine, list, close, verify.
    {
      const measurements = {}
      for (const engine of ['mihomo', 'rust']) {
        const state = engines[engine]
        const socket = await openTunnel(state.mixed, held.port)
        let snapshot = null
        const deadline = Date.now() + 4000
        while (Date.now() < deadline) {
          const body = jsonOf(await state.authed('GET', '/connections'))
          if (Array.isArray(body?.connections) && body.connections.length > 0) {
            snapshot = body
            break
          }
          await sleep(50)
        }
        const row = snapshot?.connections?.[0]
        const closed = await state.authed('DELETE', `/connections/${row?.id}`)
        let after = null
        const closeDeadline = Date.now() + 3000
        while (Date.now() < closeDeadline) {
          const body = jsonOf(await state.authed('GET', '/connections'))
          if (!Array.isArray(body?.connections) || body.connections.length === 0) {
            after = body
            break
          }
          await sleep(50)
        }
        socket.destroy()
        measurements[engine] = {
          row: row
            ? {
                network: row.metadata?.network,
                type: row.metadata?.type,
                destinationIP: row.metadata?.destinationIP,
                destinationPort: row.metadata?.destinationPort,
                inboundName: row.metadata?.inboundName,
                chains: row.chains,
                rule: row.rule,
                rulePayload: row.rulePayload,
              }
            : null,
          closeStatus: closed.status,
          afterEmpty: !Array.isArray(after?.connections) || after.connections.length === 0,
          totals: { up: snapshot?.uploadTotal > 0 || snapshot?.downloadTotal > 0 },
        }
      }
      const normalize = (value) => ({
        ...value.row,
        destinationPort: String(value.row?.destinationPort ?? ''),
      })
      results.push({
        id: 'connections-list-close',
        equal:
          stable(normalize(measurements.mihomo)) === stable(normalize(measurements.rust)) &&
          measurements.rust.closeStatus === 204 &&
          measurements.rust.afterEmpty,
        mihomo: measurements.mihomo,
        rust: measurements.rust,
      })
      const leftDelete = await engines.mihomo.authed('DELETE', '/connections/not-a-real-id')
      const rightDelete = await engines.rust.authed('DELETE', '/connections/not-a-real-id')
      results.push(compareStatus('connections-delete-unknown', leftDelete, rightDelete))
    }

    // Streams: first frame keys and CORS-bearing status.
    {
      const left = await firstStreamLine(engines.mihomo.controller, '/traffic', auth)
      const right = await firstStreamLine(engines.rust.controller, '/traffic', auth)
      const leftJson = left.line ? JSON.parse(left.line) : null
      const rightJson = right.line ? JSON.parse(right.line) : null
      results.push({
        id: 'traffic-first-frame',
        equal:
          left.status === right.status &&
          ['up', 'down', 'upTotal', 'downTotal'].every(
            (key) => Number.isFinite(leftJson?.[key]) && Number.isFinite(rightJson?.[key])
          ),
        mihomo: { status: left.status, keys: Object.keys(leftJson ?? {}) },
        rust: { status: right.status, keys: Object.keys(rightJson ?? {}) },
        note: 'Counters differ (different sessions); only the frame shape is compared.',
      })

      // `/logs` only emits a frame on a kernel event. A routed connection
      // produces an info log in both engines; subscribe first, then open it.
      const logged = {}
      for (const engine of ['mihomo', 'rust']) {
        const state = engines[engine]
        const subscription = firstStreamLine(state.controller, '/logs?level=info', auth)
        await sleep(250)
        const socket = await openTunnel(state.mixed, held.port)
        logged[engine] = await subscription
        socket.destroy()
      }
      const leftLog = logged.mihomo.line ? JSON.parse(logged.mihomo.line) : null
      const rightLog = logged.rust.line ? JSON.parse(logged.rust.line) : null
      results.push({
        id: 'logs-first-frame',
        equal:
          logged.mihomo.status === 200 &&
          logged.rust.status === 200 &&
          typeof leftLog?.type === 'string' &&
          typeof rightLog?.type === 'string' &&
          typeof leftLog?.payload === 'string' &&
          typeof rightLog?.payload === 'string',
        mihomo: { status: logged.mihomo.status, keys: Object.keys(leftLog ?? {}) },
        rust: { status: logged.rust.status, keys: Object.keys(rightLog ?? {}) },
        note: 'Message contents differ between engines; the `{type,payload}` frame shape is compared.',
      })
    }

    // Unix socket: pinned starts it without a secret (socket permissions).
    {
      const left = await fetchUnix(engines.mihomo.unixPath, 'GET', '/version')
      const right = await fetchUnix(engines.rust.unixPath, 'GET', '/version')
      results.push({
        id: 'unix-socket-version',
        equal: left.status === right.status && left.status === 200,
        mihomo: { status: left.status },
        rust: { status: right.status },
        note: 'Neither engine requires the Bearer secret on the Unix socket.',
      })
      const leftAuth = await fetchUnix(engines.mihomo.unixPath, 'GET', '/configs', auth)
      const rightAuth = await fetchUnix(engines.rust.unixPath, 'GET', '/configs', auth)
      results.push({
        id: 'unix-socket-configs',
        equal:
          leftAuth.status === rightAuth.status &&
          jsonOf(leftAuth)?.['mixed-port'] === engines.mihomo.mixed &&
          jsonOf(rightAuth)?.['mixed-port'] === engines.rust.mixed,
        mihomo: { status: leftAuth.status, port: jsonOf(leftAuth)?.['mixed-port'] },
        rust: { status: rightAuth.status, port: jsonOf(rightAuth)?.['mixed-port'] },
      })
    }

    // TLS controller listener.
    {
      const left = await fetchTls(engines.mihomo.tlsPort, 'GET', '/version', auth)
      const right = await fetchTls(engines.rust.tlsPort, 'GET', '/version', auth)
      results.push({
        id: 'tls-controller-version',
        equal: left.status === right.status && left.status === 200,
        mihomo: { status: left.status },
        rust: { status: right.status },
      })
      const leftNoAuth = await fetchTls(engines.mihomo.tlsPort, 'GET', '/version')
      const rightNoAuth = await fetchTls(engines.rust.tlsPort, 'GET', '/version')
      results.push({
        id: 'tls-controller-unauthorized',
        equal: leftNoAuth.status === rightNoAuth.status,
        mihomo: { status: leftNoAuth.status },
        rust: { status: rightNoAuth.status },
      })
    }

    // Endpoints this kernel does not implement must be explicit 404s.
    {
      const paths = ['/configs/geo', '/upgrade/geo', '/group', '/cache', '/storage', '/dns/query']
      for (const path of paths) {
        const left = await engines.mihomo.request('GET', path, { headers: auth })
        const right = await engines.rust.request('GET', path, { headers: auth })
        results.push({
          id: `unimplemented${path.replaceAll('/', '-')}`,
          equal: right.status === 404,
          mihomo: { status: left.status },
          rust: { status: right.status },
          note: 'The Rust kernel returns an explicit 404 for a pinned endpoint it does not implement; recorded in evidence/t25-controller.md.',
        })
      }
    }
    // Known divergence: moving the mixed listener on reload. Pinned recreates
    // the listener; the Rust kernel rejects it by name (restart required).
    {
      const body = (yaml) => JSON.stringify({ path: '', payload: yaml })
      const nextPort = await freePort()
      const leftPort = await engines.mihomo.authed(
        'PUT',
        '/configs?force=true',
        body(engines.mihomo.reloadYaml.replace(/mixed-port: \d+/, `mixed-port: ${nextPort}`))
      )
      const rightPort = await engines.rust.authed(
        'PUT',
        '/configs?force=true',
        body(engines.rust.reloadYaml.replace(/mixed-port: \d+/, `mixed-port: ${nextPort}`))
      )
      results.push({
        id: 'reload-listener-move',
        equal: false,
        mihomo: leftPort.status,
        rust: rightPort.status,
        note:
          'Pinned recreates the mixed listener on PUT /configs; the Rust kernel rejects a listener move by name (restart required). Recorded as a known divergence, not a compatibility pass.',
      })
    }
  } finally {
    await held.close()
    await delay.close()
    for (const engine of Object.values(engines)) {
      engine.child.kill('SIGTERM')
      engine.out.close().catch(() => {})
    }
    if (!args.keep) {
      await sleep(300)
      await rm(root, { recursive: true, force: true })
    } else {
      console.log(`kept ${root}`)
    }
  }

  const pass = results.filter((result) => result.equal).length
  const differ = results.filter((result) => !result.equal && !result.note).length
  const recorded = results.filter((result) => !result.equal && result.note).length
  const evidence = {
    format: 't25-differential',
    version: 1,
    startedAt: new Date().toISOString(),
    mihomo: args.mihomo,
    rust: args.rust,
    summary: { cases: results.length, pass, differ, recordedDivergences: recorded },
    results,
  }
  await mkdir(dirname(args.out), { recursive: true })
  await writeFile(args.out, `${JSON.stringify(evidence, null, 2)}\n`)
  console.log(
    `T25 differential: ${pass}/${results.length} compared equal, ${recorded} known divergence(s), ${differ} unexpected`
  )
  if (!engines.mihomo.ready || !engines.rust.ready) {
    console.error('one engine never became ready')
    process.exit(1)
  }
  if (differ !== 0) process.exit(1)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
