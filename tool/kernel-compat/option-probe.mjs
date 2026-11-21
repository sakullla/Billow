#!/usr/bin/env node
// Proves that every proxy option the Rust mapping marks as not implemented is
// rejected by the kernel's own configuration check, with the field named.
//
//   node tool/kernel-compat/option-probe.mjs --rust <billow-kernel binary> \
//     [--out tool/kernel-compat/evidence/option-rejection.txt]
//
// The list is the union of the `notImplemented` entries in
// evidence/rust-mapping.json plus `udp: true` for the families without a UDP
// association. A run exits 1 if any case is accepted or reports a different
// field, so a future option table that silently admits one fails here.
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = fileURLToPath(new URL('.', import.meta.url))
const mapping = JSON.parse(readFileSync(join(here, 'evidence', 'rust-mapping.json'), 'utf8'))

const bases = {
  socks5: 'server: 127.0.0.1, port: 1',
  http: 'server: 127.0.0.1, port: 1',
  ss: 'server: 127.0.0.1, port: 1, cipher: aes-256-gcm, password: p',
  trojan: 'server: 127.0.0.1, port: 1, password: p',
  vless: 'server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68',
  anytls: 'server: 127.0.0.1, port: 1, password: p',
}

const booleans = new Set(['udp', 'tfo', 'mptcp', 'smux', 'packet-addr', 'xudp', 'disable-reuse'])

const valueFor = (key) => {
  if (booleans.has(key)) return 'true'
  if (key === 'ip-version') return 'ipv4'
  if (key === 'fingerprint' || key === 'client-fingerprint') return 'chrome'
  if (key === 'certificate') return 'cert.pem'
  if (key === 'private-key') return 'key.pem'
  if (key === 'name-cert-verify') return 'example.org'
  if (key === 'udp-over-tcp-version') return '2'
  if (key === 'flow') return 'xtls-rprx-vision'
  if (key === 'plugin') return 'obfs'
  if (key === 'network') return 'grpc'
  return '{enabled: true}'
}

// `notImplemented` entries are either a key name or `key: true` for a boolean
// whose default state this kernel already has; explanatory text is skipped.
const cases = []
for (const [type, entry] of Object.entries(mapping.proxies)) {
  for (const option of entry.notImplemented ?? []) {
    const parsed = /^([a-z0-9.-]+)(?::\s*true)?$/.exec(option)
    if (!parsed) continue
    cases.push({ type, key: parsed[1] })
  }
}
// Keep one row per (type, key).
const unique = [...new Map(cases.map((entry) => [`${entry.type}/${entry.key}`, entry])).values()]

function parseArgs(argv) {
  const options = { rust: null, out: null }
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--rust') options.rust = argv[++index]
    else if (argv[index] === '--out') options.out = argv[++index]
    else throw new Error(`unknown argument ${argv[index]}`)
  }
  if (!options.rust) throw new Error('provide --rust <billow-kernel binary>')
  return options
}

const options = parseArgs(process.argv.slice(2))
const binary = resolve(options.rust)
const dir = mkdtempSync(join(tmpdir(), 'kernel-option-probe-'))
const lines = []
let failed = 0
try {
  for (const { type, key } of unique) {
    const config = join(dir, 'probe.yaml')
    const value = valueFor(key)
    writeFileSync(
      config,
      `mixed-port: 1\nproxies:\n  - {name: p, type: ${type}, ${bases[type]}, ${key}: ${value}}\nrules:\n  - 'MATCH,p'\n`,
    )
    const run = spawnSync(binary, [config, '--check', '--port', '17991'], { encoding: 'utf8' })
    const rejected = run.status !== 0 && `${run.stderr}`.includes(key) && `${run.stderr}`.includes('unsupported')
    if (!rejected) failed += 1
    lines.push(
      `${rejected ? 'rejected' : 'ACCEPTED'}  ${type.padEnd(7)} ${key.padEnd(28)} exit=${run.status} ${`${run.stderr}`.trim().split('\n')[0] ?? ''}`,
    )
  }
} finally {
  rmSync(dir, { recursive: true, force: true })
}

const header = [
  '# Proxy options the Rust mapping marks as not implemented, probed with the kernel CLI.',
  `# binary: ${binary}`,
  `# cases: ${unique.length}, accepted: ${failed}`,
  '# command: node tool/kernel-compat/option-probe.mjs --rust <billow-kernel binary>',
  '',
]
const text = [...header, ...lines].join('\n') + '\n'
if (options.out) writeFileSync(options.out, text)
process.stdout.write(text)
if (failed > 0) {
  console.error(`${failed} option(s) were accepted; the mapping and the parser disagree`)
  process.exitCode = 1
}
