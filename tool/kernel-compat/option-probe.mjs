#!/usr/bin/env node
// Option matrix: how the Rust kernel classifies every proxy option the mapping
// marks as not implemented, compared with the pinned Mihomo binary.
//
//   node tool/kernel-compat/option-probe.mjs --rust <billow-kernel> \
//     [--mihomo <mihomo>] [--out tool/kernel-compat/evidence/option-matrix.txt]
//
// Two groups, because "not implemented" has two shapes:
//
// - `noop`: Mihomo accepts the value and does nothing with it (a disabled
//   boolean, an empty block, a TLS-only option without TLS). Rejecting those
//   would reject a valid configuration (R2), so the Rust kernel must accept
//   them; with `--mihomo` both verdicts are compared.
// - `enabled`: the value changes behaviour (or would, once implemented). Mihomo
//   accepts it and the Rust kernel must reject it naming the field, so no
//   unimplemented behaviour is silently skipped.
//
// The run exits 1 when a no-op form is rejected, when an enabled form is
// accepted, or (with `--mihomo`) when the two engines disagree on a no-op or
// Mihomo rejects a case this matrix calls valid.
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = fileURLToPath(new URL('.', import.meta.url))
const mapping = JSON.parse(readFileSync(join(here, 'evidence', 'rust-mapping.json'), 'utf8'))

// Bases per family: `off` has no TLS, `on` turns it on (null when the family has
// no TLS at all, which makes TLS-only options permanent no-ops there).
const bases = {
  socks5: { off: 'server: 127.0.0.1, port: 1', on: 'server: 127.0.0.1, port: 1, tls: true' },
  http: { off: 'server: 127.0.0.1, port: 1', on: 'server: 127.0.0.1, port: 1, tls: true' },
  ss: { off: 'server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p', on: null },
  trojan: { off: 'server: 127.0.0.1, port: 1, password: p', on: 'server: 127.0.0.1, port: 1, password: p' },
  vless: {
    off: 'server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68',
    on: 'server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, tls: true',
  },
  anytls: { off: 'server: 127.0.0.1, port: 1, password: p', on: 'server: 127.0.0.1, port: 1, password: p' },
  vmess: {
    off: 'server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto',
    on: 'server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, alterId: 0, cipher: auto, tls: true',
  },
  snell: { off: 'server: 127.0.0.1, port: 1, psk: p, version: 2', on: null },
  trusttunnel: {
    off: 'server: 127.0.0.1, port: 1, username: u, password: p',
    on: 'server: 127.0.0.1, port: 1, username: u, password: p',
  },
  'gost-relay': {
    off: 'server: 127.0.0.1, port: 1',
    on: 'server: 127.0.0.1, port: 1, tls: true',
  },
  ssh: { off: 'server: 127.0.0.1, port: 1, username: u', on: null },
  ssr: {
    off: 'server: 127.0.0.1, port: 1, cipher: aes-256-cfb, password: p, protocol: origin, obfs: plain',
    on: null,
  },
}

const tlsOnly = new Set([
  'sni',
  'skip-cert-verify',
  'alpn',
  'name-cert-verify',
  'fingerprint',
  'certificate',
  'private-key',
  'client-fingerprint',
  'ech-opts',
  'reality-opts',
])

const booleans = new Set(['udp', 'tfo', 'mptcp', 'smux', 'packet-addr', 'xudp', 'disable-reuse', 'udp-over-tcp'])

const pin = 'a'.repeat(64)

const valueFor = (key) => {
  if (booleans.has(key)) return 'true'
  if (key === 'ip-version') return 'ipv4'
  if (key === 'fingerprint') return pin // Mihomo validates a SHA-256 pin
  if (key === 'client-fingerprint') return 'chrome'
  if (key === 'certificate') return 'cert.pem'
  if (key === 'private-key') return 'key.pem'
  if (key === 'name-cert-verify') return 'example.org'
  if (key === 'udp-over-tcp-version') return '2'
  if (key === 'flow') return 'xtls-rprx-vision'
  if (key === 'plugin') return 'obfs'
  if (key === 'interface-name') return 'eth0'
  if (key === 'routing-mark') return '100'
  if (key === 'client-metadata') return 'm'
  if (key === 'idle-session-check-interval' || key === 'idle-session-timeout') return '30'
  if (key === 'min-idle-session') return '1'
  if (key === 'ech-opts') return '{enable: true, config: x}'
  if (key === 'packet-encoding') return 'xudp'
  if (key === 'ws-headers') return '{X-Probe: yes}'
  if (key === 'network') return 'grpc'
  if (key === 'protocol') return 'auth_chain_a'
  if (key === 'obfs') return 'tls1.2_ticket_auth'
  if (key === 'ss-opts') return '{enabled: true, password: p}'
  if (key === 'jls-opts') return '{password: p, username: u}'
  if (key === 'shadow-tls-opts' || key === 'restls-opts') return '{password: p}'
  if (key === 'reality-opts') return `{public-key: ${pin}}`
  return '{enabled: true}'
}

// Transport blocks only matter when their `network` is selected; the matrix's
// bases use the default network, so their content is a no-op for Mihomo.
const transportBlocks = new Set(['grpc-opts', 'http-opts', 'h2-opts', 'xhttp-opts'])

// Keys the pinned type declares but the kernel does not implement; every
// enabled row must name one of them for its family, so a rejection is only
// allowed for a registered gap.
const registered = (type, key) => (mapping.proxies[type]?.notImplemented ?? []).some((entry) => entry.replace(/:.*$/, '') === key)

// Enabled forms: one per (family, key) from the mapping's `notImplemented`.
const enabled = []
for (const [type, entry] of Object.entries(mapping.proxies)) {
  for (const option of entry.notImplemented ?? []) {
    const parsed = /^([a-z0-9.-]+)(?::\s*true)?$/.exec(option)
    if (!parsed) continue
    const key = parsed[1]
    // Sub-options (`ws-opts.…`) are exercised by the transport tests, and
    // `plugin-opts` is a no-op unless a plugin is configured (which is itself
    // rejected), so neither can be enabled at the proxy level.
    if (key.includes('.')) continue
    if (transportBlocks.has(key) || key === 'plugin-opts') continue
    let base = tlsOnly.has(key) ? bases[type].on : bases[type].off
    if (!base) continue // the family has no TLS, so a TLS-only key cannot be enabled
    // SSR's protocol/obfs are required fields: replace the base value instead
    // of appending a duplicate key.
    if (type === 'ssr' && key === 'protocol') {
      base = 'server: 127.0.0.1, port: 1, cipher: aes-256-cfb, password: p, obfs: plain'
    }
    if (type === 'ssr' && key === 'obfs') {
      base = 'server: 127.0.0.1, port: 1, cipher: aes-256-cfb, password: p, protocol: origin'
    }
    enabled.push({ type, key, base, option: `${key}: ${valueFor(key)}` })
  }
}
const uniqueEnabled = [...new Map(enabled.map((entry) => [`${entry.type}/${entry.key}`, entry])).values()]

// No-op forms Mihomo accepts (checked against the binary when provided).
const noops = []
const add = (type, key, value, base = bases[type].off) => noops.push({ type, key, base, option: `${key}: ${value}` })
for (const type of ['socks5', 'http']) {
  for (const key of ['skip-cert-verify', 'sni', 'alpn', 'fingerprint', 'certificate', 'private-key', 'name-cert-verify']) {
    const value = key === 'skip-cert-verify' ? 'true' : key === 'alpn' ? '[h2]' : key === 'fingerprint' ? 'chrome' : key === 'certificate' ? 'x.pem' : key === 'private-key' ? 'k.pem' : 'example.org'
    add(type, key, value)
  }
}
for (const type of ['socks5', 'http', 'trojan', 'vless', 'anytls']) {
  add(type, 'smux', '{enabled: false}')
  add(type, 'tfo', 'false')
  add(type, 'mptcp', 'false')
  add(type, 'interface-name', "''")
  add(type, 'routing-mark', '0')
}
for (const type of ['socks5', 'trojan', 'vless', 'anytls', 'vmess']) {
  add(type, 'ech-opts', '{enable: false}')
  add(type, 'ech-opts', '{enable: false, config: x}')
}
for (const type of ['socks5', 'trojan', 'vless', 'anytls', 'vmess']) add(type, 'smux', '{enabled: true, protocol: h2mux}')
for (const type of ['socks5', 'trojan', 'vless']) add(type, 'smux', '{enabled: false}')
for (const type of ['socks5', 'trojan', 'vless']) add(type, 'grpc-opts', '{}')
for (const type of ['trojan', 'vless']) {
  add(type, 'grpc-opts', '{grpc-service-name: svc}')
  add(type, 'http-opts', '{path: [/x]}')
  add(type, 'h2-opts', '{host: [h.example]}')
  add(type, 'xhttp-opts', '{path: /x}')
}
for (const type of ['trojan', 'vless']) {
  add(type, 'http-opts', '{}')
  add(type, 'h2-opts', '{}')
}
// `reality-opts` and `jls-opts` require fields, so their empty form is invalid
// in Mihomo; both engines must reject it (covered by the enabled group).
add('trojan', 'shadow-tls-opts', '{}')
add('trojan', 'restls-opts', '{}')
add('vless', 'xhttp-opts', '{}')
add('vless', 'ech-opts', '{enable: true}') // TLS is off here: Mihomo ignores it
add('trojan', 'ss-opts', '{}')
add('ss', 'plugin', "''")
add('ss', 'plugin-opts', '{}')
add('ss', 'plugin-opts', '{mode: tls}')
add('ss', 'client-fingerprint', 'chrome') // no TLS on ss, and the plugin is refused
add('ss', 'udp-over-tcp', 'false')
for (const type of ['socks5', 'vless', 'anytls']) add(type, 'udp', 'false')
add('vless', 'packet-addr', 'false')
add('vless', 'xudp', 'false')
add('anytls', 'disable-reuse', 'false')
add('anytls', 'idle-session-timeout', '0')
add('socks5', 'bogus', '1')
// Keys another proxy type declares: the pinned decoder ignores them here.
for (const type of ['socks5', 'http']) {
  add(type, 'jls-opts', '{}')
  add(type, 'shadow-tls-opts', '{password: p}')
  add(type, 'restls-opts', '{password: p}')
  add(type, 'ech-opts', '{enable: true}')
  add(type, 'udp-over-tcp', 'true')
  add(type, 'udp-over-tcp-version', '2')
  add(type, 'ss-opts', '{enabled: true, password: p}')
}
for (const type of ['ss']) {
  add(type, 'shadow-tls-opts', '{password: p}')
  add(type, 'jls-opts', '{password: p, username: u}')
  add(type, 'restls-opts', '{password: p}')
  add(type, 'ech-opts', '{enable: true}')
}
for (const type of ['trojan', 'vless', 'anytls']) add(type, 'udp-over-tcp', 'true')
add('trojan', 'bogus', '{a: b}')
add('vless', 'ss-opts', '{enabled: true, password: p}')
add('anytls', 'client-metadata', "''")
// T11 families: no-op forms accepted by both engines.
for (const type of ['gost-relay', 'ssh', 'ssr']) {
  add(type, 'tfo', 'false')
  add(type, 'mptcp', 'false')
  add(type, 'interface-name', "''")
  add(type, 'routing-mark', '0')
  add(type, 'ip-version', "''")
}
for (const type of ['gost-relay', 'ssr']) add(type, 'udp', 'false')
add('gost-relay', 'forward', 'false')
add('gost-relay', 'mux', 'false')
for (const key of ['sni', 'skip-cert-verify', 'name-cert-verify', 'fingerprint', 'certificate', 'private-key', 'client-fingerprint']) {
  const value = key === 'skip-cert-verify' ? 'true' : key === 'fingerprint' ? 'chrome' : key === 'certificate' ? 'x.pem' : key === 'private-key' ? 'k.pem' : 'example.org'
  add('gost-relay', key, value)
}
add('ssh', 'private-key', "''")
add('ssh', 'private-key-passphrase', "''")
add('ssh', 'host-key', '[]')
add('ssh', 'host-key-algorithms', '[]')
add('ssr', 'protocol-param', "''")
add('ssr', 'obfs-param', "''")

function parseArgs(argv) {
  const options = { rust: null, mihomo: null, out: null }
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--rust') options.rust = argv[++index]
    else if (argv[index] === '--mihomo') options.mihomo = argv[++index]
    else if (argv[index] === '--out') options.out = argv[++index]
    else throw new Error(`unknown argument ${argv[index]}`)
  }
  if (!options.rust) throw new Error('provide --rust <billow-kernel binary>')
  return options
}

const options = parseArgs(process.argv.slice(2))
const binary = resolve(options.rust)
const mihomo = options.mihomo ? resolve(options.mihomo) : null
const dir = mkdtempSync(join(tmpdir(), 'kernel-option-probe-'))
const lines = []
const problems = []
let rustPort = 17991

function runCase({ type, key, base, option }, expectReject, group) {
  const config = join(dir, `${group}-${type}-${key}.yaml`.replace(/[^a-z0-9.-]/gi, '-'))
  writeFileSync(
    config,
    `mixed-port: 1\nproxies:\n  - {name: p, type: ${type}, ${base}, ${option}}\nrules:\n  - 'MATCH,p'\n`,
  )
  rustPort = rustPort === 17991 ? 17992 : 17991
  const rust = spawnSync(binary, [config, '--check', '--port', String(rustPort)], { encoding: 'utf8' })
  const rustRejected = rust.status !== 0
  const rustNamed = `${rust.stderr}`.includes(`'${key}'`)
  let mihomoVerdict = '-'
  if (mihomo) {
    const peerDir = mkdtempSync(join(dir, 'peer-'))
    const run = spawnSync(mihomo, ['-t', '-d', peerDir, '-f', config], { encoding: 'utf8' })
    mihomoVerdict = run.status === 0 ? 'accept' : 'reject'
    rmSync(peerDir, { recursive: true, force: true })
  }
  const label = `${group.padEnd(7)} ${type.padEnd(7)} ${key.padEnd(28)}`
  const verdict = `rust=${rustRejected ? 'reject' : 'accept'} mihomo=${mihomoVerdict}`
  if (expectReject) {
    if (!rustRejected || !rustNamed) problems.push(`${type}/${key}: an enabled option was accepted or not named`)
    if (!registered(type, key)) problems.push(`${type}/${key}: rejected but not registered as notImplemented`)
    // A form Mihomo itself rejects needs no implementation; both engines
    // rejecting it is the correct outcome and is recorded as such.
  } else {
    if (rustRejected) problems.push(`${type}/${key}: a no-op form was rejected (${`${rust.stderr}`.trim().split('\n')[0] ?? ''})`)
    if (mihomo && mihomoVerdict !== 'accept') problems.push(`${type}/${key}: Mihomo rejects a case listed as a no-op`)
  }
  lines.push(`${label} ${verdict}${rustRejected && rustNamed ? '' : expectReject ? '' : ''}`)
}

for (const entry of noops) runCase(entry, false, 'noop')
for (const entry of uniqueEnabled) runCase(entry, true, 'enabled')

const header = [
  '# Proxy option matrix: no-op forms must load, enabled forms must be rejected.',
  `# rust: ${binary}`,
  `# mihomo: ${mihomo ?? '(not provided: only the Rust verdict was checked)'}`,
  `# no-op cases: ${noops.length}, enabled cases: ${uniqueEnabled.length}, problems: ${problems.length}`,
  '# command: node tool/kernel-compat/option-probe.mjs --rust <billow-kernel> --mihomo <mihomo>',
  '',
]
const text = [...header, ...lines, ...(problems.length ? ['', ...problems.map((problem) => `PROBLEM ${problem}`)] : [])].join('\n') + '\n'
if (options.out) writeFileSync(options.out, text)
process.stdout.write(text)
if (problems.length) {
  console.error(`${problems.length} option-matrix problem(s)`)
  process.exitCode = 1
}
