// Fixture loading. A fixture is the exact YAML handed to both kernels plus an
// x-kernel-compat block (removed before the kernels see it) describing the tagged requests
// and the expected results. Not JSON: YAML permits comments that explain why each field or
// failure is chosen, which keeps the differential cases reviewable.
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { sha256 } from './manifest.mjs'
import { setTopLevel } from './yaml.mjs'

// Tag hosts must be syntactically valid domain names: the CONNECT authority and hosts keys
// are parsed as such by both kernels, and a colon in the host makes the parser reject them.
const markerPrefix = 'billowt1'

function readBlock(text) {
  const lines = text.replace(/\r\n/g, '\n').split('\n')
  const start = lines.findIndex((line) => /^x-kernel-compat\s*:/.test(line))
  if (start < 0) throw new Error('fixture needs an x-kernel-compat block')
  let end = start + 1
  while (end < lines.length && (/^[\s#]/.test(lines[end]) || lines[end] === '')) end += 1
  const block = lines.slice(start + 1, end)
  const config = [...lines.slice(0, start), ...lines.slice(end)].join('\n')
  return { block, config }
}

// Parses the small subset used by fixtures with an indentation stack: nested mappings,
// lists of mappings written on one line ({k: v}) or over several lines, and scalar lists.
export function parseCompatBlock(lines) {
  const root = {}
  const stack = [{ indent: -1, mapping: root }]
  const currentMapping = () => stack.at(-1).mapping
  for (const raw of lines) {
    const line = stripComment(raw)
    if (!line.trim()) continue
    const indent = line.length - line.trimStart().length
    let content = line.trim()
    // Close frames that ended before this line; list items at the same indent as their key
    // stay inside the list, which is why the pop happens before list handling.
    while (stack.length > 1 && indent <= stack.at(-1).indent) stack.pop()
    if (content.startsWith('- ')) {
      const frame = stack.at(-1)
      if (!frame.list) {
        frame.list = []
        frame.parent[frame.key] = frame.list
      }
      content = content.slice(2).trim()
      const inline = /^\{\s*(.*)\s*\}$/.exec(content)
      const pairs = inline ? splitInline(inline[1]) : null
      const first = /^(\w[\w-]*)\s*:\s*(.*)$/.exec(pairs ? pairs[0] : content)
      if (first) {
        const item = { [first[1]]: parseValue(first[2]) }
        frame.list.push(item)
        for (const extra of pairs ? pairs.slice(1) : []) {
          const pair = /^(\w[\w-]*)\s*:\s*(.*)$/.exec(extra)
          if (pair) item[pair[1]] = parseValue(pair[2])
        }
        stack.push({ indent, mapping: item })
      } else {
        frame.list.push(parseValue(content))
      }
      continue
    }
    const match = /^(\w[\w-]*)\s*:\s*(.*)$/.exec(content)
    if (!match) throw new Error(`unsupported compat line: ${content}`)
    const [, key, rest] = match
    const mapping = currentMapping()
    if (rest === '') {
      const child = {}
      mapping[key] = child
      stack.push({ indent, mapping: child, parent: mapping, key })
    } else {
      mapping[key] = parseValue(rest)
    }
  }
  return root
}

function stripComment(line) {
  let quote = null
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index]
    if (quote) {
      if (char === quote) quote = null
    } else if (char === '"' || char === "'") quote = char
    else if (char === '#' && (index === 0 || line[index - 1] === ' ')) return line.slice(0, index)
  }
  return line
}

function parseValue(text) {
  const value = text.trim()
  if (value.startsWith('[') && value.endsWith(']')) {
    const inner = value.slice(1, -1).trim()
    return inner ? splitInline(inner).map(parseValue) : []
  }
  if (value.startsWith('{') && value.endsWith('}')) {
    const mapping = {}
    for (const pair of splitInline(value.slice(1, -1))) {
      const index = pair.indexOf(':')
      mapping[pair.slice(0, index).trim()] = parseValue(pair.slice(index + 1))
    }
    return mapping
  }
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) return value.slice(1, -1)
  if (value === 'true') return true
  if (value === 'false') return false
  if (value === 'null' || value === '') return null
  if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value)
  return value
}

function splitInline(text) {
  const parts = []
  let depth = 0
  let quote = null
  let current = ''
  for (const char of text) {
    if (quote) {
      current += char
      if (char === quote) quote = null
    } else if (char === '"' || char === "'") {
      quote = char
      current += char
    } else if (char === '[' || char === '{') {
      depth += 1
      current += char
    } else if (char === ']' || char === '}') {
      depth -= 1
      current += char
    } else if (char === ',' && depth === 0) {
      parts.push(current.trim())
      current = ''
    } else current += char
  }
  if (current.trim()) parts.push(current.trim())
  return parts
}

const defaults = {
  // Unset: the echo binds an OS-allocated free port. A fixed port is only requested when a
  // fixture says so; a real run never shares a port with another process.
  'request-port': null,
  'ready-timeout-ms': 15000,
  'request-timeout-ms': 5000,
  'stop-timeout-ms': 5000,
  'request-host': '127.0.0.1',
  'request-port': 18080,
  'request-path': '/probe',
}

export function normalizeCompat(compat, { path, text }) {
  const merged = { ...compat }
  for (const [key, value] of Object.entries(defaults)) if (merged[key] === undefined || merged[key] === null) merged[key] = value
  const kernelFields = ['proxyAccepted', 'echoSawMarkers', 'markersSent']
  const expectBlock = merged.expect ?? { accept: true }
  const expect = { accept: expectBlock.accept !== false, flow: {}, control: {} }
  for (const key of ['proxyAccepted', 'echoSawMarkers', 'markersSent']) {
    if (expectBlock[key] === undefined || expectBlock[key] === null) continue
    // proxyAccepted is a boolean outcome; the marker counts are numbers.
    expect.flow[key] = key === 'proxyAccepted' ? expectBlock[key] === true : Number(expectBlock[key])
  }
// Expected flow outcomes default to the accepting case; a fixture states every value it
  // cares about and the report records what was observed either way.
  if (expect.accept && typeof expect.flow.proxyAccepted !== 'boolean') expect.flow.proxyAccepted = true
  if (expectBlock.control) for (const [key, value] of Object.entries(expectBlock.control)) expect.control[key] = value
  if (!Array.isArray(merged.requests) || merged.requests.length === 0) throw new Error(`${path}: needs at least one request`)
  const flow = merged.requests.map((item) => {
    const method = item.method ?? 'connect'
    // A value-of of "false" is a misspelling for "no"; only literal true enables it.
    const valueOf = item['value-of'] === true
    const protocol = item.protocol ?? 'http'
    // socks5 is the only method valid together with the socks5 protocol; any other method
    // name must say what it sends through the TCP tunnel.
    if (!['connect', 'forward'].includes(method)) throw new Error(`${path}: request ${item.id} has unknown method ${method}`)
    if (!['http', 'socks5'].includes(protocol)) throw new Error(`${path}: request ${item.id} has unknown protocol ${protocol}`)
    if (protocol === 'socks5' && method !== 'connect') throw new Error(`${path}: request ${item.id} must use method connect for socks5`)
    // connect-host: the CONNECT authority for CONNECT-only engines. Default is the tag host.
    const hostOverride = item['connect-host'] ? String(item['connect-host']) : null
    // A forward fixture that brings its own hosts table names the key it routes here.
    const forwardHost = item['forward-host'] ? String(item['forward-host']) : null
    if (method === 'forward' && hostOverride) throw new Error(`${path}: request ${item.id} cannot combine forward with connect-host`)
    // connect-port: the port placed in the CONNECT authority (default: the echo port), so a
    // fixture rule can route a reserved address to the echo on a fixed port.
    const portOverride = item['connect-port'] !== undefined ? Number(item['connect-port']) : null
    // reference-only: a request only the reference replica may send (it is not a pass claim
    // for a kernel; the kernel side skips it and the reference uses it to prove its exit).
    const referenceOnly = item['reference-only'] === true
    return { id: String(item.id), valueOf: valueOf ? String(item.id) : null, method, protocol, connectHost: hostOverride, forwardHost, connectPort: portOverride, referenceOnly }
  })
  if (!flow.some((step) => step.valueOf)) throw new Error(`${path}: one request must use value-of`)
  const controlRequests = (merged.control ?? []).map((item) => ({
    method: String(item.method ?? 'GET'),
    path: String(item.path ?? '/'),
    body: item.body ?? null,
    expectStatus: Number(item['expect-status'] ?? 200),
  }))
  return {
    path: resolve(path),
    sha256: sha256(text),
    expect,
    flow,
    controlRequests,
    requestTarget: { host: String(merged['request-host']), port: merged['request-port'] === null ? null : Number(merged['request-port']), path: String(merged['request-path']) },
    timeouts: {
      ready: Number(merged['ready-timeout-ms']),
      request: Number(merged['request-timeout-ms']),
      config: Number(merged['config-timeout-ms'] ?? 60000),
      stop: Number(merged['stop-timeout-ms']),
    },
  }
}

export async function loadFixture(fixturePath) {
  const text = await readFile(fixturePath, 'utf8')
  const { block, config } = readBlock(text)
  const fixture = normalizeCompat(parseCompatBlock(block), { path: fixturePath, text })
  // The echo endpooint port is only known once the run starts; it is injected into hosts and
  // into the CONNECT port by the runner.
  return { ...fixture, config: config.trim() + '\n' }
}

// Host the tagged requests use: a placeholder host name that points at the loopback echo and
// is never resolved by either kernel, because the rules match the domain directly.
export const tagHost = (id, nonce) => `${markerPrefix}-${id}-${nonce}.probe.invalid`

export function withPorts(config, { mixedPort, controllerPort }) {
  let text = setTopLevel(config, 'mixed-port', mixedPort)
  if (controllerPort) text = setTopLevel(text, 'external-controller', `127.0.0.1:${controllerPort}`)
  return text
}

// Maps every tag host to the loopback echo. The port is not part of the hosts value: the
// pinned kernel treats a value with a port as a host string, so only the IP is mapped and the
// request port selects the echo listener. A fixture that defines its own hosts table, or that
// routes by address instead of by host name, is handed to the engines unchanged.
export function withHosts(config, { nonce, ids, addressesOnly = false }) {
  if (addressesOnly || /^hosts\s*:/m.test(config)) return config
  const all = [...Array(36).keys()].map((index) => index.toString(36))
  const used = ids?.length ? ids : all
  const lines = [
    'hosts:',
    ...used.map((id) => `  "${tagHost(id, nonce)}": 127.0.0.1`),
  ]
  return `${lines.join('\n')}\n${config}`
}
