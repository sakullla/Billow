#!/usr/bin/env node
// T23 differential probe: proxy groups, selection, health checks and the
// selection cache against the pinned Mihomo v1.19.34 binary.
//
// Every outbound node is a loopback HTTP CONNECT proxy started here. A health
// node answers the probe HEAD itself with a fixed delay/status and forwards
// ordinary tunnels. Mihomo is driven through its external-controller API; the
// Rust kernel through `--print-groups`/`--select`/`--wait-ms`.
//
// Command:
//   node tool/kernel-compat/t23-differential.mjs \
//     --mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 \
//     --rust native-kernel/target/debug/billow-kernel \
//     --out tool/kernel-compat/evidence/t23-differential.json
import { spawn } from 'node:child_process'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { reservePort } from './ports.mjs'
import { openTunnel } from './process.mjs'

const here = dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// Loopback endpoints
// ---------------------------------------------------------------------------

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
      resolveServer({ host: '0.0.0.0', port: server.address().port, close: () => new Promise((done) => server.close(done)) })
    })
  })
}

/**
 * HTTP CONNECT node. `delayMs`/`status` configure the health-check HEAD reply;
 * other tunnels are forwarded to their CONNECT target.
 */
function startNode({ delayMs = 0, status = 204 } = {}) {
  const counters = { connects: 0 }
  const server = net.createServer((socket) => {
    let head = Buffer.alloc(0)
    let target = null
    const onHead = (chunk) => {
      head = Buffer.concat([head, chunk])
      const end = head.indexOf('\r\n\r\n')
      if (end < 0) return
      socket.off('data', onHead)
      const text = head.slice(0, end).toString('utf8')
      const line = text.split('\r\n')[0]
      const [method, authority] = line.split(/\s+/)
      const rest = head.slice(end + 4)
      if (!method || method.toUpperCase() !== 'CONNECT') {
        socket.end('HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n')
        return
      }
      counters.connects += 1
      target = authority
      socket.write('HTTP/1.1 200 Connection Established\r\nX-T23-Node: yes\r\n\r\n')
      if (rest.length) handleTunnel(rest)
      socket.on('data', handleTunnel)
    }
    const handleTunnel = (chunk) => {
      socket.off('data', handleTunnel)
      if (chunk.subarray(0, 5).toString('ascii') === 'HEAD ') {
        let request = chunk
        const waitForHead = (more) => {
          request = Buffer.concat([request, more])
          if (request.indexOf('\r\n\r\n') < 0) return
          socket.off('data', waitForHead)
          const respond = () => {
            const reason = status === 204 ? 'No Content' : 'OK'
            socket.write(`HTTP/1.1 ${status} ${reason}\r\nContent-Length: 0\r\n\r\n`)
            socket.end()
          }
          if (delayMs > 0) setTimeout(respond, delayMs)
          else respond()
        }
        if (request.indexOf('\r\n\r\n') >= 0) waitForHead(Buffer.alloc(0))
        else socket.on('data', waitForHead)
        return
      }
      const [host, port] = splitAuthority(target)
      const upstream = net.connect({ host, port }, () => {
        upstream.write(chunk)
        socket.pipe(upstream)
        upstream.pipe(socket)
        socket.on('error', () => upstream.destroy())
        upstream.on('error', () => socket.destroy())
      })
      upstream.on('error', () => socket.destroy())
    }
    socket.on('data', onHead)
    socket.on('error', () => socket.destroy())
  })
  return new Promise((resolveServer) => {
    server.listen(0, '127.0.0.1', () => {
      resolveServer({
        port: server.address().port,
        connects: () => counters.connects,
        close: () => new Promise((done) => server.close(done)),
      })
    })
  })
}

function splitAuthority(authority) {
  const index = authority.lastIndexOf(':')
  return [authority.slice(0, index).replace(/^\[|\]$/g, ''), Number(authority.slice(index + 1))]
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
  const result = await Promise.race([handle.exited, new Promise((done) => setTimeout(() => done({ timeout: true }), 5000))])
  if (result.timeout) {
    handle.child.kill('SIGKILL')
    await handle.exited
  }
}

const sleep = (ms) => new Promise((done) => setTimeout(done, ms))

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
    return { category: reply.includes(marker) ? 'echoed' : 'empty', connectStatus: status, replyBytes: reply.length }
  } catch (error) {
    return { category: 'timeout', connectStatus: status, error: error.message }
  } finally {
    await exchange.close()
  }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const normalizeType = (type) => ({
  Selector: 'select',
  URLTest: 'url-test',
  Fallback: 'fallback',
  LoadBalance: 'load-balance',
}[type] || type)

function buildConfig(item, context, engine) {
  const lines = ['mixed-port: ' + context.mixedPort, 'mode: rule', 'log-level: info']
  lines.push('profile: {store-selected: true}')
  // The control API is T25: only the pinned engine is configured with it.
  if (context.controllerPort && engine === 'mihomo') lines.push(`external-controller: 127.0.0.1:${context.controllerPort}`)
  lines.push('proxies:')
  for (const proxy of item.proxies) lines.push('  - ' + proxy)
  if (item.proxyProviders) {
    lines.push('proxy-providers:')
    for (const provider of item.proxyProviders) lines.push(provider.trimEnd())
  }
  lines.push('proxy-groups:')
  for (const group of item.groups) lines.push('  - ' + group)
  lines.push('rules:')
  for (const rule of item.rules) lines.push('  - ' + rule)
  return lines.join('\n') + '\n'
}

// One flat set of node definitions. `node()` returns the config line.
const nodeLine = (name, port) => `{name: ${name}, type: http, server: 127.0.0.1, port: ${port}}`

async function prepareDir(root, id, item, context, engine) {
  const dir = join(root, id)
  await mkdir(dir, { recursive: true })
  if (item.files) {
    for (const [name, body] of Object.entries(item.files)) await writeFile(join(dir, name), body)
  }
  const config = buildConfig(item, context, engine)
  await writeFile(join(dir, 'config.yaml'), config)
  return { dir, config }
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

function parseGroupsLine(stdout) {
  const line = stdout.split('\n').find((entry) => entry.startsWith('GROUPS '))
  if (!line) return null
  return JSON.parse(line.slice('GROUPS '.length))
}

async function runRust(item, dir, context) {
  const args = [join(dir, 'config.yaml'), '--port', String(context.mixedPort), '--cache-dir', dir]
  if (item.select) args.push('--select', item.select)
  args.push('--print-groups', '--wait-ms', String(item.waitMs ?? 300))
  if (item.probe) args.push('--probe-groups')
  const handle = startProcess(context.rust, args, dir)
  const { code, signal } = await Promise.race([
    handle.exited,
    sleep(30000).then(() => ({ timeout: true })),
  ])
  if (handle.child.exitCode === null && !signal && code === undefined) await stopProcess(handle)
  return { code, signal, logs: handle.logs }
}

async function queryMihomo(controllerPort, group, path = `/proxies/${encodeURIComponent(group)}`) {
  const response = await fetch(`http://127.0.0.1:${controllerPort}${path}`)
  if (!response.ok) return { status: response.status }
  return { status: response.status, body: await response.json() }
}

async function rustSnapshot(item, root, context) {
  const { dir } = await prepareDir(root, `${item.id}-rust`, item, context, 'rust')
  const result = await runRust(item, dir, context)
  const groups = parseGroupsLine(result.logs.stdout)
  if (!groups) {
    return { engine: 'rust', startupFailed: true, code: result.code, stderr: result.logs.stderr.slice(-2000), stdout: result.logs.stdout.slice(-1000) }
  }
  const status = groups.groups.find((group) => group.name === item.group)
  return {
    engine: 'rust',
    ready: true,
    group: status ? {
      type: status.type,
      now: status.now,
      all: status.all,
      members: status.members,
    } : null,
    stderr: result.logs.stderr.slice(-1500),
  }
}

async function mihomoSnapshot(item, root, context) {
  const { dir } = await prepareDir(root, `${item.id}-mihomo`, item, context, 'mihomo')
  const args = ['-d', dir, '-f', join(dir, 'config.yaml')]
  const handle = startProcess(context.mihomo, args, dir)
  const ready = await waitPort(context.mixedPort)
  if (!ready) {
    await stopProcess(handle)
    return { engine: 'mihomo', startupFailed: true, stderr: handle.logs.stderr.slice(-2000) }
  }
  if (item.select) {
    const [group, member] = item.select.split('=')
    const response = await fetch(`http://127.0.0.1:${context.controllerPort}/proxies/${encodeURIComponent(group)}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: member }),
    })
    if (!response.ok) {
      await stopProcess(handle)
      return { engine: 'mihomo', ready: true, selectStatus: response.status, stderr: handle.logs.stderr.slice(-1500) }
    }
  }
  await sleep(item.waitMs ?? 300)
  const snapshot = await queryMihomo(context.controllerPort, item.group)
  await stopProcess(handle)
  const body = snapshot.body
  return {
    engine: 'mihomo',
    ready: true,
    group: body ? { type: normalizeType(body.type), now: body.now ?? null, all: body.all ?? null } : null,
    httpStatus: snapshot.status,
    stderr: handle.logs.stderr.slice(-1500),
  }
}

async function trafficObservation(engine, item, root, context, echo) {
  const { dir } = await prepareDir(root, `${item.id}-${engine}`, item, context, engine)
  const args = engine === 'mihomo'
    ? ['-d', dir, '-f', join(dir, 'config.yaml')]
    : [join(dir, 'config.yaml'), '--port', String(context.mixedPort), '--cache-dir', dir]
  if (engine === 'rust' && item.select) args.push('--select', item.select)
  const handle = startProcess(engine === 'mihomo' ? context.mihomo : context.rust, args, dir)
  const ready = await waitPort(context.mixedPort)
  const result = { engine, ready, attempts: [] }
  if (!ready) {
    await stopProcess(handle)
    result.startupFailed = true
    result.stderr = handle.logs.stderr.slice(-2000)
    return result
  }
  if (item.waitMs) await sleep(item.waitMs)
  for (let index = 0; index < (item.requests ?? 1); index += 1) {
    const before = item.nodes.map((node) => node.connects())
    const observation = await attempt(context.mixedPort, echo.host, echo.port, item.marker ?? 't23ok')
    const served = item.nodes
      .map((node, nodeIndex) => ({ name: item.nodeNames[nodeIndex], delta: node.connects() - before[nodeIndex] }))
      .filter((entry) => entry.delta > 0)
      .map((entry) => entry.name)
    result.attempts.push({ ...observation, served })
  }
  await stopProcess(handle)
  result.stderr = handle.logs.stderr.slice(-1500)
  return result
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

async function contextFor(root, id) {
  const mixedPort = await reservePort()
  const controllerPort = await reservePort()
  return { mixedPort, controllerPort, dir: join(root, id) }
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  const echo = await startEchoServer()
  const sandbox = await mkdtemp(join(tmpdir(), 'billow-t23-diff-'))
  const results = []
  try {
    // Shared node pool. Each case rebuilds configs around these ports.
    const nodeSlow = await startNode({ delayMs: 300, status: 204 })
    const nodeFast = await startNode({ delayMs: 10, status: 204 })
    const nodeHttpError = await startNode({ delayMs: 5, status: 500 })
    const nodeMid = await startNode({ delayMs: 100, status: 204 })
    const nodeMidSlow = await startNode({ delayMs: 180, status: 204 })
    const deadPort = await reservePort()
    const nodes = [nodeSlow, nodeFast, nodeHttpError, nodeMid, nodeMidSlow]
    try {
      const base = { rust: args.rust, mihomo: args.mihomo }
      const cases = [
        {
          id: 'select-default-first',
          reason: 'selector defaults to the first member; rules may name the group',
          group: 'G',
          proxies: [nodeLine('A', nodeFast.port), nodeLine('B', nodeSlow.port)],
          groups: ['{name: G, type: select, proxies: [A, B]}'],
          rules: ['MATCH,G'],
          waitMs: 300,
          compareAll: true,
        },
        {
          id: 'select-default-selected',
          reason: '`default-selected` fixes the selector until a cached/API choice overrides it',
          group: 'G',
          proxies: [nodeLine('A', nodeFast.port), nodeLine('B', nodeSlow.port)],
          groups: ['{name: G, type: select, proxies: [A, B], default-selected: B}'],
          rules: ['MATCH,G'],
          waitMs: 300,
          compareAll: true,
        },
        {
          id: 'select-after-put',
          reason: 'PUT /proxies/{group} fixes the selector (Rust: --select)',
          group: 'G',
          proxies: [nodeLine('A', nodeFast.port), nodeLine('B', nodeSlow.port)],
          groups: ['{name: G, type: select, proxies: [A, B]}'],
          rules: ['MATCH,G'],
          select: 'G=B',
          waitMs: 300,
          compareAll: true,
        },
        {
          id: 'url-test-picks-fastest',
          reason: 'url-test selects the lowest probe delay',
          group: 'AUTO',
          proxies: [nodeLine('slow', nodeSlow.port), nodeLine('fast', nodeFast.port)],
          groups: [`{name: AUTO, type: url-test, proxies: [slow, fast], url: 'http://127.0.0.1:${echo.port}/generate_204', interval: 1, lazy: false, timeout: 1000}`],
          rules: ['MATCH,AUTO'],
          waitMs: 3200,
          compareAll: true,
        },
        {
          id: 'fallback-moves-off-dead',
          reason: 'fallback skips a member whose probe fails',
          group: 'FB',
          proxies: [nodeLine('dead', deadPort), nodeLine('backup', nodeFast.port)],
          groups: [`{name: FB, type: fallback, proxies: [dead, backup], url: 'http://127.0.0.1:${echo.port}/generate_204', interval: 1, lazy: false, timeout: 500}`],
          rules: ['MATCH,FB'],
          waitMs: 3200,
          compareAll: true,
        },
        {
          id: 'expected-status-excludes-code',
          reason: 'expected-status rejects a member whose probe answers another code',
          group: 'AUTO',
          proxies: [nodeLine('err', nodeHttpError.port), nodeLine('ok', nodeMid.port)],
          groups: [`{name: AUTO, type: url-test, proxies: [err, ok], url: 'http://127.0.0.1:${echo.port}/generate_204', interval: 1, lazy: false, timeout: 1000, expected-status: '204'}`],
          rules: ['MATCH,AUTO'],
          waitMs: 3200,
          compareAll: true,
        },
        {
          id: 'expected-status-default-accepts-any-code',
          reason: 'without expected-status any HTTP code is a live member (pinned expectedStatus == nil)',
          group: 'AUTO',
          proxies: [nodeLine('err', nodeHttpError.port), nodeLine('ok', nodeMid.port)],
          groups: [`{name: AUTO, type: url-test, proxies: [err, ok], url: 'http://127.0.0.1:${echo.port}/generate_204', interval: 1, lazy: false, timeout: 1000}`],
          rules: ['MATCH,AUTO'],
          waitMs: 3200,
          compareAll: true,
        },
        {
          id: 'tolerance-keeps-sticky',
          reason: 'url-test keeps the current member while the difference is within tolerance',
          group: 'AUTO',
          proxies: [nodeLine('first', nodeMid.port), nodeLine('second', nodeMidSlow.port)],
          groups: [`{name: AUTO, type: url-test, proxies: [first, second], url: 'http://127.0.0.1:${echo.port}/generate_204', interval: 1, lazy: false, timeout: 1000, tolerance: 200}`],
          rules: ['MATCH,AUTO'],
          waitMs: 3200,
          compareAll: true,
        },
        {
          id: 'nested-group-inner-selection',
          reason: 'a nested group reports the group name and dials its inner selection',
          group: 'OUTER',
          proxies: [nodeLine('dead', deadPort), nodeLine('backup', nodeFast.port)],
          groups: [
            `{name: INNER, type: fallback, proxies: [dead, backup], url: 'http://127.0.0.1:${echo.port}/generate_204', interval: 1, lazy: false, timeout: 500}`,
            '{name: OUTER, type: select, proxies: [INNER]}',
          ],
          rules: ['MATCH,OUTER'],
          waitMs: 3200,
          compareAll: true,
        },
        {
          id: 'nested-group-dials-inner-selection',
          reason: 'a dial through the outer selector follows the inner fallback choice',
          group: 'OUTER',
          proxies: [nodeLine('dead', deadPort), nodeLine('backup', nodeFast.port)],
          groups: [
            `{name: INNER, type: fallback, proxies: [dead, backup], url: 'http://127.0.0.1:${echo.port}/generate_204', interval: 1, lazy: false, timeout: 500}`,
            '{name: OUTER, type: select, proxies: [INNER]}',
          ],
          rules: ['MATCH,OUTER'],
          traffic: true,
          waitMs: 3200,
          requests: 1,
          nodeNames: ['backup'],
          nodeServers: [nodeFast],
        },
        {
          id: 'include-all-proxies-filter',
          reason: 'include-all-proxies expands sorted proxy names through filter',
          group: 'G',
          proxies: [nodeLine('Zebra', nodeFast.port), nodeLine('Alpha', nodeSlow.port)],
          groups: ["{name: G, type: select, include-all-proxies: true, filter: '^A'}"],
          rules: ['MATCH,G'],
          waitMs: 300,
          compareAll: true,
        },
        {
          id: 'include-all-expands-everything',
          reason: 'include-all turns on proxies and providers',
          group: 'G',
          proxies: [nodeLine('Zebra', nodeFast.port), nodeLine('Alpha', nodeSlow.port)],
          groups: ['{name: G, type: select, include-all: true}'],
          rules: ['MATCH,G'],
          waitMs: 300,
          compareAll: true,
        },
        {
          id: 'exclude-type-uses-adapter-name',
          reason: 'exclude-type compares the pinned adapter name (Http), not the YAML type',
          group: 'G',
          proxies: [nodeLine('A', nodeFast.port), `{name: S, type: socks5, server: 127.0.0.1, port: ${deadPort}}`],
          groups: ["{name: G, type: select, proxies: [A, S], exclude-type: 'Http'}"],
          rules: ['MATCH,G'],
          waitMs: 300,
          compareAll: true,
        },
        {
          id: 'provider-use-filter',
          reason: 'use providers contribute their proxies through the group filter',
          group: 'G',
          proxies: [],
          files: {
            'nodes.yaml': "proxies:\n  - {name: Node-A, type: http, server: 127.0.0.1, port: 9}\n  - {name: Node-B, type: http, server: 127.0.0.1, port: 9}\n",
          },
          proxyProviders: ['  remote:\n    type: file\n    path: nodes.yaml'],
          groups: ["{name: G, type: select, use: [remote], filter: '^Node-B'}"],
          rules: ['MATCH,G'],
          waitMs: 300,
          compareAll: true,
        },
        {
          id: 'load-balance-round-robin',
          reason: 'round-robin cycles members in order',
          group: 'LB',
          proxies: [nodeLine('A', nodeFast.port), nodeLine('B', nodeSlow.port)],
          groups: ['{name: LB, type: load-balance, proxies: [A, B], strategy: round-robin}'],
          rules: ['MATCH,LB'],
          traffic: true,
          requests: 4,
          nodeNames: ['A', 'B'],
          nodeServers: [nodeFast, nodeSlow],
        },
        {
          id: 'select-rule-target-traffic',
          reason: 'a rule naming a group dials the selected member',
          group: 'G',
          proxies: [nodeLine('A', nodeFast.port), nodeLine('B', nodeSlow.port)],
          groups: ['{name: G, type: select, proxies: [A, B]}'],
          rules: ['MATCH,G'],
          traffic: true,
          requests: 2,
          nodeNames: ['A', 'B'],
          nodeServers: [nodeFast, nodeSlow],
        },
        {
          id: 'relay-rejected',
          reason: 'pinned v1.19.34 removed the relay group type; the Rust kernel rejects it with the same reason',
          group: 'G',
          proxies: [nodeLine('A', nodeFast.port)],
          groups: ['{name: G, type: relay, proxies: [A]}'],
          rules: ['MATCH,G'],
          startFailure: true,
        },
      ]

      for (const item of cases) {
        const context = { ...base, ...(await contextFor(sandbox, item.id)) }
        const entry = { id: item.id, reason: item.reason }

        if (item.traffic) {
          const trafficItem = { ...item, nodes: item.nodeServers }
          const trafficContext = { ...context, mixedPort: context.mixedPort }
          const mixedMihomo = await reservePort()
          const mixedRust = await reservePort()
          const mihomo = await trafficObservation('mihomo', trafficItem, sandbox, { ...trafficContext, mixedPort: mixedMihomo }, echo)
          const rust = await trafficObservation('rust', trafficItem, sandbox, { ...trafficContext, mixedPort: mixedRust }, echo)
          entry.engines = { mihomo, rust }
          const sequence = (observation) => observation.attempts?.map((attempt) => attempt.served.join('+') || attempt.category).join(',')
          entry.observed = { mihomo: sequence(mihomo), rust: sequence(rust) }
          if (item.id === 'load-balance-round-robin') {
            entry.status = entry.observed.mihomo === entry.observed.rust
              && rust.attempts?.every((attempt) => attempt.category === 'echoed')
              ? 'pass'
              : 'differ'
          } else {
            entry.status = mihomo.attempts?.[0]?.category === 'echoed'
              && rust.attempts?.[0]?.category === 'echoed'
              && mihomo.attempts?.[0]?.served.join('+') === rust.attempts?.[0]?.served.join('+')
              ? 'pass'
              : 'differ'
          }
          results.push(entry)
          continue
        }

        if (item.startFailure) {
          // Mihomo must refuse the configuration; the Rust CLI must exit non-zero
          // and name the type.
          const { dir } = await prepareDir(sandbox, `${item.id}-mihomo`, item, context, 'mihomo')
          const mihomo = startProcess(args.mihomo, ['-d', dir, '-f', join(dir, 'config.yaml')], dir)
          const mihomoExit = await Promise.race([mihomo.exited, sleep(8000).then(() => ({ timeout: true }))])
          await stopProcess(mihomo)
          const rustDir = join(sandbox, `${item.id}-rust`)
          await mkdir(rustDir, { recursive: true })
          await writeFile(join(rustDir, 'config.yaml'), buildConfig(item, context, 'rust'))
          const rust = await runRust(item, rustDir, context)
          entry.engines = {
            mihomo: { exit: mihomoExit, stderr: mihomo.logs.stderr.slice(-2000) + mihomo.logs.stdout.slice(-1000) },
            rust: { exit: rust.code, stderr: rust.logs.stderr.slice(-2000) },
          }
          const mihomoRejected = mihomoExit.code !== 0 || /relay type was removed/.test(entry.engines.mihomo.stderr)
          const rustRejected = rust.code !== 0 && /relay type was removed/.test(entry.engines.rust.stderr)
          entry.observed = { mihomoRejected, rustRejected }
          entry.status = mihomoRejected && rustRejected ? 'pass' : 'differ'
          results.push(entry)
          continue
        }

        const [mihomo, rust] = await Promise.all([
          mihomoSnapshot(item, sandbox, { ...context, mixedPort: await reservePort() }),
          rustSnapshot(item, sandbox, { ...context, mixedPort: await reservePort() }),
        ])
        entry.engines = { mihomo, rust }
        const mihomoGroup = mihomo.group
        const rustGroup = rust.group
        const sameNow = mihomoGroup?.now === rustGroup?.now
        const sameAll = !item.compareAll
          || JSON.stringify(mihomoGroup?.all) === JSON.stringify(rustGroup?.all)
        entry.observed = {
          mihomo: mihomoGroup,
          rust: rustGroup,
          sameNow,
          sameAll,
        }
        entry.status = mihomoGroup && rustGroup && sameNow && sameAll ? 'pass' : 'differ'
        results.push(entry)
      }

      // Persistence: select B, stop, restart with the same directory.
      {
        const item = {
          id: 'selection-persisted-across-restart',
          group: 'G',
          proxies: [nodeLine('A', nodeFast.port), nodeLine('B', nodeSlow.port)],
          groups: ['{name: G, type: select, proxies: [A, B]}'],
          rules: ['MATCH,G'],
          waitMs: 300,
        }
        const entry = { id: item.id, reason: 'profile.store-selected keeps the choice across restarts' }
        const mihomoContext = await contextFor(sandbox, `${item.id}-mihomo`)
        const rustContext = { rust: args.rust, ...(await contextFor(sandbox, `${item.id}-rust`)) }

        // Mihomo: first run with PUT, second run without.
        const mihomoFirst = await (async () => {
          const { dir } = await prepareDir(sandbox, `${item.id}-mihomo`, item, mihomoContext, 'mihomo')
          const handle = startProcess(args.mihomo, ['-d', dir, '-f', join(dir, 'config.yaml')], dir)
          await waitPort(mihomoContext.mixedPort)
          const response = await fetch(`http://127.0.0.1:${mihomoContext.controllerPort}/proxies/G`, {
            method: 'PUT',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ name: 'B' }),
          })
          await sleep(300)
          const before = await queryMihomo(mihomoContext.controllerPort, 'G')
          await stopProcess(handle)
          const handle2 = startProcess(args.mihomo, ['-d', dir, '-f', join(dir, 'config.yaml')], dir)
          await waitPort(mihomoContext.mixedPort)
          await sleep(300)
          const after = await queryMihomo(mihomoContext.controllerPort, 'G')
          await stopProcess(handle2)
          return { put: response.status, before: before.body?.now ?? null, after: after.body?.now ?? null }
        })()

        // Rust: first run selects (writes cache.yaml), second run reads it.
        const rustFirst = await (async () => {
          const { dir } = await prepareDir(sandbox, `${item.id}-rust`, item, rustContext, 'rust')
          const first = await runRust({ ...item, select: 'G=B', waitMs: 100 }, dir, rustContext)
          const afterSelect = parseGroupsLine(first.logs.stdout)?.groups.find((group) => group.name === 'G')?.now ?? null
          const second = await runRust({ ...item, waitMs: 100 }, dir, rustContext)
          const afterRestart = parseGroupsLine(second.logs.stdout)?.groups.find((group) => group.name === 'G')?.now ?? null
          const cache = await import('node:fs/promises').then((fs) => fs.readFile(join(dir, 'cache.yaml'), 'utf8')).catch(() => null)
          return { afterSelect, afterRestart, cache }
        })()

        entry.engines = { mihomo: mihomoFirst, rust: rustFirst }
        entry.observed = {
          mihomo: `${mihomoFirst.before}->${mihomoFirst.after}`,
          rust: `${rustFirst.afterSelect}->${rustFirst.afterRestart}`,
        }
        entry.status = mihomoFirst.put === 204
          && mihomoFirst.before === 'B'
          && mihomoFirst.after === 'B'
          && rustFirst.afterSelect === 'B'
          && rustFirst.afterRestart === 'B'
          ? 'pass'
          : 'differ'
        results.push(entry)
      }

      const summary = {
        cases: results.filter((entry) => !entry.id.startsWith('selection-persisted')).length,
        persistence: results.filter((entry) => entry.id.startsWith('selection-persisted')).length,
        pass: results.filter((entry) => entry.status === 'pass').length,
        differ: results.filter((entry) => entry.status === 'differ').length,
        unexpected: results.filter((entry) => entry.status === 'unexpected').length,
      }
      const report = {
        format: 't23-differential',
        version: 1,
        startedAt: new Date().toISOString(),
        mihomo: args.mihomo,
        rust: args.rust,
        summary,
        normalizationNote: [
          'Mihomo type names are normalized (Selector->select, URLTest->url-test, Fallback->fallback, LoadBalance->load-balance).',
          'Group `now` and `all` are compared; latency values are not compared byte-wise because scheduler ticks and probe ports differ. url-test/fallback liveness is asserted through the selected member and the observed echo.',
          'Pinned load-balance consistent-hashing uses a per-process random maphash seed, so only the round-robin strategy is compared as an ordered sequence; consistent-hashing/sticky-sessions are covered by unit semantics (stable pin per key, dead-member retry).',
          'The Rust selection cache is `<cache-dir>/cache.yaml` (the selected map); pinned stores the same map in bbolt `cache.db`. Only the persistence effect is compared.',
          'Relay is rejected by both engines: pinned v1.19.34 removed the type ("please using dialer-proxy instead") and the Rust kernel reproduces that named rejection.',
        ],
        results,
        exitOk: summary.differ === 0 && summary.unexpected === 0,
      }
      await writeFile(args.out, JSON.stringify(report, null, 2))
      console.log(JSON.stringify(summary))
      process.exitCode = report.exitOk ? 0 : 1
    } finally {
      for (const node of nodes) await node.close().catch(() => null)
    }
  } finally {
    await echo.close()
    await rm(sandbox, { recursive: true, force: true }).catch(() => null)
  }
}

function parseArgs(argv) {
  const args = { mihomo: null, rust: null, out: null }
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index]
    if (value === '--mihomo') args.mihomo = resolve(argv[++index])
    else if (value === '--rust') args.rust = resolve(argv[++index])
    else if (value === '--out') args.out = resolve(argv[++index])
    else throw new Error(`unknown argument ${value}`)
  }
  if (!args.mihomo || !args.rust || !args.out) throw new Error('usage: --mihomo <binary> --rust <binary> --out <json>')
  return args
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 2
})
