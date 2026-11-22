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
  tuic: {
    off: 'server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, password: p',
    on: 'server: 127.0.0.1, port: 1, uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68, password: p',
  },
  hysteria: {
    off: 'server: 127.0.0.1, port: 1, up: 50 Mbps, down: 50 Mbps',
    on: 'server: 127.0.0.1, port: 1, up: 50 Mbps, down: 50 Mbps',
  },
  hysteria2: {
    off: 'server: 127.0.0.1, port: 1, password: p',
    on: 'server: 127.0.0.1, port: 1, password: p',
  },
  // T13 families: the pinned types have no TLS options.
  mieru: {
    off: 'server: 127.0.0.1, port: 1, transport: TCP, username: u, password: p',
    on: null,
  },
  shadowquic: {
    off: 'server: 127.0.0.1, port: 1, username: alice, password: p',
    on: null,
  },
  // T16: the transport adapters load and reject their documented gaps; the
  // bases satisfy each pinned type's required fields (a WireGuard peer and an
  // inline CA). A real self-signed CA fixture is used so Mihomo parses it.
  wireguard: {
    off: 'ip: 10.13.13.2, private-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, peers: [{server: 127.0.0.1, port: 1, public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, allowed-ips: [0.0.0.0/0]}]',
    on: 'ip: 10.13.13.2, private-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, peers: [{server: 127.0.0.1, port: 1, public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, allowed-ips: [0.0.0.0/0]}]',
  },
  // T18: the pinned masque type is a Cloudflare WARP CONNECT-IP client, so
  // its base carries the required key pair and local address. The P-256 key
  // and endpoint SPKI are throwaway test material (nothing is registered with
  // them): both engines only parse them under `-t`.
  masque: {
    off: `server: 127.0.0.1, port: 1, udp: true, private-key: 'MHcCAQEEIDKh56LbUI7PTfKO5ojiPkNrK2H8jcLrmfdlhv3TsqRzoAoGCCqGSM49AwEHoUQDQgAEMAUkhPqJXQGTsDj6a3yC7F2zxIWXs6UJCc/Mwr6wL3GWgqbrP6tvB52ZUbnalrJXSxMwUFXDTHNqxPhpzzUawA==', public-key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMAUkhPqJXQGTsDj6a3yC7F2zxIWXs6UJCc/Mwr6wL3GWgqbrP6tvB52ZUbnalrJXSxMwUFXDTHNqxPhpzzUawA==', ip: 172.16.0.2`,
    on: `server: 127.0.0.1, port: 1, udp: true, private-key: 'MHcCAQEEIDKh56LbUI7PTfKO5ojiPkNrK2H8jcLrmfdlhv3TsqRzoAoGCCqGSM49AwEHoUQDQgAEMAUkhPqJXQGTsDj6a3yC7F2zxIWXs6UJCc/Mwr6wL3GWgqbrP6tvB52ZUbnalrJXSxMwUFXDTHNqxPhpzzUawA==', public-key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMAUkhPqJXQGTsDj6a3yC7F2zxIWXs6UJCc/Mwr6wL3GWgqbrP6tvB52ZUbnalrJXSxMwUFXDTHNqxPhpzzUawA==', ip: 172.16.0.2, sni: consumer-masque.cloudflareclient.com`,
  },
  openvpn: {
    off: 'server: 127.0.0.1, port: 1, username: u, password: p, ca: "-----BEGIN CERTIFICATE-----\\nMIIBeDCCAR6gAwIBAgIUNGxTOw8p4EwO9gCDn0yLtj+cTSEwCgYIKoZIzj0EAwIw\\nIjEgMB4GA1UEAwwXQmlsbG93IE9wdGlvbiBNYXRyaXggQ0EwHhcNMjYxMTIxMjMx\\nNzE5WhcNMzYxMTE4MjMxNzE5WjAiMSAwHgYDVQQDDBdCaWxsb3cgT3B0aW9uIE1h\\ndHJpeCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCwKe7m/tSYnofl9zXGB\\n6imRADX7EOIt14x3sj8Q/Q6z8LFfLclUHxwQhCKZVSLU0OFzZ0OEX8E4JfzTh5Fz\\nvEijMjAwMB0GA1UdDgQWBBQ0WIDTOFy2zdCN8RfgUCVQqwz69DAPBgNVHRMBAf8E\\nBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIAXkgPSMN+BkP+IuwAiVTPUx/r8sv2v4\\nR/iS/uiN/Q0XAiEA2sVdFi6rQvNnpbPOlU0qXOPYZOK4KKNG/w4+o+JVVrA=\\n-----END CERTIFICATE-----"',
    on: 'server: 127.0.0.1, port: 1, username: u, password: p, ca: "-----BEGIN CERTIFICATE-----\\nMIIBeDCCAR6gAwIBAgIUNGxTOw8p4EwO9gCDn0yLtj+cTSEwCgYIKoZIzj0EAwIw\\nIjEgMB4GA1UEAwwXQmlsbG93IE9wdGlvbiBNYXRyaXggQ0EwHhcNMjYxMTIxMjMx\\nNzE5WhcNMzYxMTE4MjMxNzE5WjAiMSAwHgYDVQQDDBdCaWxsb3cgT3B0aW9uIE1h\\ndHJpeCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCwKe7m/tSYnofl9zXGB\\n6imRADX7EOIt14x3sj8Q/Q6z8LFfLclUHxwQhCKZVSLU0OFzZ0OEX8E4JfzTh5Fz\\nvEijMjAwMB0GA1UdDgQWBBQ0WIDTOFy2zdCN8RfgUCVQqwz69DAPBgNVHRMBAf8E\\nBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIAXkgPSMN+BkP+IuwAiVTPUx/r8sv2v4\\nR/iS/uiN/Q0XAiEA2sVdFi6rQvNnpbPOlU0qXOPYZOK4KKNG/w4+o+JVVrA=\\n-----END CERTIFICATE-----"',
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

const booleans = new Set([
  'udp',
  'tfo',
  'mptcp',
  'smux',
  'packet-addr',
  'xudp',
  'disable-reuse',
  'udp-over-tcp',
  'reduce-rtt',
  'fast-open',
  'udp-over-stream',
  'disable-mtu-discovery',
])

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
  // T10's families are exercised explicitly below; the generic valueFor()
  // shapes do not match their required fields (`protocol`, `ports`, ...).
  // shadowquic is explicit for the same reason: `quic-versions` is a list and
  // `up`/`down` are rate strings.
  if (['tuic', 'hysteria', 'hysteria2', 'shadowquic', 'wireguard', 'openvpn', 'masque'].includes(type)) continue
  for (const option of entry.notImplemented ?? []) {
    const parsed = /^([a-z0-9.-]+)(?::\s*true)?$/.exec(option)
    if (!parsed) continue
    const key = parsed[1]
    // Sub-options (`ws-opts.…`) are exercised by the transport tests, and
    // `plugin-opts` is a no-op unless a plugin is configured (which is itself
    // rejected), so neither can be enabled at the proxy level.
    if (key.includes('.')) continue
    if (transportBlocks.has(key) || key === 'plugin-opts') continue
    // Families without a comparable base (masque) are named in `skipped`.
    if (!bases[type]) continue
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

// T10 QUIC families: explicit forms because their bases/values differ from the
// generic shapes (`protocol` is a transport name, `ports` is a range, ...).
const t10Enabled = [
  ['tuic', 'token', 'token: legacy'],
  ['tuic', 'udp-relay-mode', 'udp-relay-mode: quic'],
  ['tuic', 'reduce-rtt', 'reduce-rtt: true'],
  ['tuic', 'fast-open', 'fast-open: true'],
  ['tuic', 'udp-over-stream', 'udp-over-stream: true'],
  ['tuic', 'congestion-controller', 'congestion-controller: bbr'],
  ['tuic', 'cwnd', 'cwnd: 32'],
  ['tuic', 'bbr-profile', 'bbr-profile: standard'],
  ['tuic', 'recv-window-conn', 'recv-window-conn: 1024'],
  ['tuic', 'recv-window', 'recv-window: 1024'],
  ['tuic', 'disable-mtu-discovery', 'disable-mtu-discovery: true'],
  ['tuic', 'max-datagram-frame-size', 'max-datagram-frame-size: 1400'],
  ['tuic', 'max-udp-relay-packet-size', 'max-udp-relay-packet-size: 1252'],
  ['tuic', 'ech-opts', 'ech-opts: {enable: true, config: x}'],
  ['tuic', 'name-cert-verify', 'name-cert-verify: example.org'],
  ['tuic', 'fingerprint', `fingerprint: ${pin}`],
  ['tuic', 'certificate', 'certificate: cert.pem'],
  ['tuic', 'private-key', 'private-key: key.pem'],
  ['tuic', 'client-fingerprint', 'client-fingerprint: chrome'],
  ['tuic', 'ip-version', 'ip-version: ipv4'],
  ['tuic', 'tfo', 'tfo: true'],
  ['tuic', 'mptcp', 'mptcp: true'],
  ['tuic', 'interface-name', 'interface-name: eth0'],
  ['tuic', 'routing-mark', 'routing-mark: 100'],
  ['hysteria', 'ports', 'ports: 443,8443'],
  ['hysteria', 'hop-interval', 'hop-interval: 10'],
  ['hysteria', 'obfs', 'obfs: xplus'],
  ['hysteria', 'protocol', 'protocol: faketcp'],
  ['hysteria', 'recv-window-conn', 'recv-window-conn: 1024'],
  ['hysteria', 'recv-window', 'recv-window: 1024'],
  ['hysteria', 'disable-mtu-discovery', 'disable-mtu-discovery: true'],
  ['hysteria', 'fast-open', 'fast-open: true'],
  ['hysteria', 'ech-opts', 'ech-opts: {enable: true, config: x}'],
  ['hysteria', 'name-cert-verify', 'name-cert-verify: example.org'],
  ['hysteria', 'fingerprint', `fingerprint: ${pin}`],
  ['hysteria', 'certificate', 'certificate: cert.pem'],
  ['hysteria', 'private-key', 'private-key: key.pem'],
  ['hysteria', 'client-fingerprint', 'client-fingerprint: chrome'],
  ['hysteria', 'ip-version', 'ip-version: ipv4'],
  ['hysteria', 'tfo', 'tfo: true'],
  ['hysteria', 'mptcp', 'mptcp: true'],
  ['hysteria', 'interface-name', 'interface-name: eth0'],
  ['hysteria', 'routing-mark', 'routing-mark: 100'],
  ['hysteria2', 'up', 'up: 50 Mbps'],
  ['hysteria2', 'ports', 'ports: 443,8443'],
  ['hysteria2', 'hop-interval', 'hop-interval: 10'],
  ['hysteria2', 'obfs', 'obfs: salamander'],
  ['hysteria2', 'realm-opts', 'realm-opts: {enable: true, server-url: "https://realm.example"}'],
  ['hysteria2', 'udp-mtu', 'udp-mtu: 1200'],
  ['hysteria2', 'cwnd', 'cwnd: 32'],
  ['hysteria2', 'bbr-profile', 'bbr-profile: standard'],
  ['hysteria2', 'initial-stream-receive-window', 'initial-stream-receive-window: 1024'],
  ['hysteria2', 'max-stream-receive-window', 'max-stream-receive-window: 1024'],
  ['hysteria2', 'initial-connection-receive-window', 'initial-connection-receive-window: 1024'],
  ['hysteria2', 'max-connection-receive-window', 'max-connection-receive-window: 1024'],
  ['hysteria2', 'ech-opts', 'ech-opts: {enable: true, config: x}'],
  ['hysteria2', 'name-cert-verify', 'name-cert-verify: example.org'],
  ['hysteria2', 'fingerprint', `fingerprint: ${pin}`],
  ['hysteria2', 'certificate', 'certificate: cert.pem'],
  ['hysteria2', 'private-key', 'private-key: key.pem'],
  ['hysteria2', 'client-fingerprint', 'client-fingerprint: chrome'],
  ['hysteria2', 'ip-version', 'ip-version: ipv4'],
  ['hysteria2', 'tfo', 'tfo: true'],
  ['hysteria2', 'mptcp', 'mptcp: true'],
  ['hysteria2', 'interface-name', 'interface-name: eth0'],
  ['hysteria2', 'routing-mark', 'routing-mark: 100'],
].map(([type, key, option]) => ({ type, key, base: bases[type].on, option }))
// T13 family: explicit forms, because some rejected values are not booleans
// (`multiplexing: MULTIPLEXING_LOW`) and the generic `{enabled: true}` shape
// would be a YAML type error. `sudoku` is rejected as a whole type, so it has
// no per-option rows.
const t13Enabled = [
  ['mieru', 'udp', 'udp: true'],
  ['mieru', 'multiplexing', 'multiplexing: MULTIPLEXING_LOW'],
  ['mieru', 'traffic-pattern', 'traffic-pattern: AbCd'],
  ['mieru', 'tfo', 'tfo: true'],
  ['mieru', 'mptcp', 'mptcp: true'],
  ['mieru', 'interface-name', 'interface-name: eth0'],
  ['mieru', 'routing-mark', 'routing-mark: 100'],
  ['mieru', 'ip-version', 'ip-version: ipv4'],
].map(([type, key, option]) => ({ type, key, base: bases[type].off, option }))
// T15 shadowquic: explicit enabled forms (a list for `quic-versions` and rate
// strings for `up`/`down`).
const t15Enabled = [
  ['shadowquic', 'zero-rtt', 'zero-rtt: true'],
  ['shadowquic', 'quic-versions', 'quic-versions: [v2]'],
  ['shadowquic', 'congestion-controller', 'congestion-controller: bbr'],
  ['shadowquic', 'bbr-profile', 'bbr-profile: aggressive'],
  ['shadowquic', 'cwnd', 'cwnd: 64'],
  ['shadowquic', 'up', 'up: 50 Mbps'],
  ['shadowquic', 'down', 'down: 50 Mbps'],
  ['shadowquic', 'tfo', 'tfo: true'],
  ['shadowquic', 'mptcp', 'mptcp: true'],
  ['shadowquic', 'interface-name', 'interface-name: eth0'],
  ['shadowquic', 'routing-mark', 'routing-mark: 100'],
  ['shadowquic', 'ip-version', 'ip-version: ipv4'],
].map(([type, key, option]) => ({ type, key, base: bases[type].off, option }))
// T16 families: explicit forms, because the generic `{enabled: true}` shape is
// not valid for `amnezia-wg-option`, `ip-stack`, `dns` or `dialer-proxy`.
const t16Enabled = [
  ['wireguard', 'amnezia-wg-option', 'amnezia-wg-option: {jc: 4}'],
  ['wireguard', 'ip-stack.mode', 'ip-stack: {mode: gvisor}'],
  ['wireguard', 'ip-stack.congestion-controller', 'ip-stack: {congestion-controller: bbr}'],
  ['wireguard', 'remote-dns-resolve', 'remote-dns-resolve: true'],
  ['wireguard', 'dns', 'dns: [1.1.1.1]'],
  ['wireguard', 'refresh-server-ip-interval', 'refresh-server-ip-interval: 10'],
  ['wireguard', 'dialer-proxy', 'dialer-proxy: p'],
  ['wireguard', 'tfo', 'tfo: true'],
  ['wireguard', 'mptcp', 'mptcp: true'],
  ['wireguard', 'interface-name', 'interface-name: eth0'],
  ['wireguard', 'routing-mark', 'routing-mark: 100'],
  ['wireguard', 'ip-version', 'ip-version: ipv4'],
  ['openvpn', 'tls-auth', 'tls-auth: secret'],
  ['openvpn', 'tls-crypt', 'tls-crypt: secret'],
  ['openvpn', 'tls-crypt-v2', 'tls-crypt-v2: secret'],
  ['openvpn', 'comp-lzo', 'comp-lzo: yes'],
  ['openvpn', 'cipher', 'cipher: AES-128-CBC'],
  ['openvpn', 'data-ciphers', 'data-ciphers: [AES-128-CBC]'],
  ['openvpn', 'dev', 'dev: tap'],
  ['openvpn', 'ip-stack.mode', 'ip-stack: {mode: gvisor}'],
  ['openvpn', 'ip-stack.congestion-controller', 'ip-stack: {congestion-controller: bbr}'],
  ['openvpn', 'remote-dns-resolve', 'remote-dns-resolve: true'],
  ['openvpn', 'dns', 'dns: [1.1.1.1]'],
  ['openvpn', 'dialer-proxy', 'dialer-proxy: p'],
].map(([type, key, option]) => ({ type, key, base: bases[type].off, option }))
// T18 masque: the pinned WARP shape loads; the modes and QUIC/stack knobs it
// does not implement must be rejected by name.
const t18Enabled = [
  ['masque', 'network', 'network: h2'],
  ['masque', 'network', 'network: h3-l4proxy'],
  ['masque', 'congestion-controller', 'congestion-controller: bbr'],
  ['masque', 'cwnd', 'cwnd: 32'],
  ['masque', 'bbr-profile', 'bbr-profile: standard'],
  ['masque', 'ip-stack.mode', 'ip-stack: {mode: gvisor}'],
  ['masque', 'dialer-proxy', 'dialer-proxy: hop'],
].map(([type, key, option]) => ({ type, key, base: bases[type].off, option }))
const allEnabled = [...uniqueEnabled, ...t10Enabled, ...t13Enabled, ...t15Enabled, ...t16Enabled, ...t18Enabled]

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
// T18 masque: the pinned WARP shape's no-op forms (the endpoint key pin is the
// only verification, so name and TLS options do not change behaviour; the
// stack selection is wire-invisible and the resolver is opt-in).
for (const [key, value] of [
  ['sni', 'example.org'],
  ['skip-cert-verify', 'true'],
  ['name-cert-verify', 'example.org'],
  ['handshake-timeout', '5'],
  ['mtu', '1280'],
  ['uri', 'https://cloudflareaccess.com'],
  ['ipv6', 'fd00::2'],
  ['ip-stack', '{mode: auto}'],
  ['ip-stack', '{mode: mips}'],
  ['ip-stack', '{congestion-controller: cubic}'],
  ['remote-dns-resolve', 'false'],
  ['dns', '[]'],
  ['network', "''"],
]) {
  add('masque', key, value)
}

// T10 families: no-op forms accepted by both engines.
for (const type of ['tuic', 'hysteria', 'hysteria2']) {
  add(type, 'tfo', 'false')
  add(type, 'mptcp', 'false')
  add(type, 'interface-name', "''")
  add(type, 'routing-mark', '0')
  add(type, 'ip-version', "''")
}
for (const key of ['reduce-rtt', 'fast-open', 'udp-over-stream', 'disable-mtu-discovery']) add('tuic', key, 'false')
add('tuic', 'max-open-streams', '0')
for (const key of ['fast-open', 'disable-mtu-discovery']) add('hysteria', key, 'false')
add('hysteria', 'recv-window', '0')
add('hysteria', 'recv-window-conn', '0')
add('hysteria', 'hop-interval', '0')
add('hysteria', 'ports', "''")
add('hysteria', 'obfs', "''")
add('hysteria', 'protocol', 'udp')
add('hysteria2', 'up', "''")
add('hysteria2', 'down', "''")
add('hysteria2', 'ports', "''")
add('hysteria2', 'hop-interval', "''")
add('hysteria2', 'obfs', "''")
add('hysteria2', 'obfs-password', "''")
add('hysteria2', 'udp-mtu', '0')
add('hysteria2', 'cwnd', '0')
add('hysteria2', 'bbr-profile', "''")
add('hysteria2', 'realm-opts', '{enable: false}')

// T13 family: no-op forms accepted by both engines.
for (const type of ['mieru']) {
  add(type, 'udp', 'false')
  add(type, 'tfo', 'false')
  add(type, 'mptcp', 'false')
  add(type, 'interface-name', "''")
  add(type, 'routing-mark', '0')
  add(type, 'ip-version', "''")
}
add('mieru', 'multiplexing', 'MULTIPLEXING_OFF')
add('mieru', 'handshake-mode', 'HANDSHAKE_STANDARD')
add('mieru', 'handshake-mode', 'HANDSHAKE_NO_WAIT')

// T15 shadowquic: no-op forms accepted by both engines.
for (const type of ['shadowquic']) {
  add(type, 'tfo', 'false')
  add(type, 'mptcp', 'false')
  add(type, 'interface-name', "''")
  add(type, 'routing-mark', '0')
  add(type, 'ip-version', "''")
  add(type, 'zero-rtt', 'false')
  add(type, 'udp-over-stream', 'false')
  add(type, 'disable-mtu-discovery', 'false')
  add(type, 'cwnd', '0')
  add(type, 'cwnd', '32')
  add(type, 'up', "''")
  add(type, 'down', "''")
  add(type, 'keep-alive-interval', '0')
  add(type, 'recv-window', '0')
  add(type, 'recv-window-conn', '0')
  add(type, 'max-datagram-frame-size', '0')
  add(type, 'max-open-streams', '0')
  add(type, 'quic-versions', '[]')
  // The pinned ShadowQuicOption does not declare tls/skip-cert-verify/udp;
  // Mihomo ignores them and the kernel leaves them unread for the same reason.
  add(type, 'skip-cert-verify', 'true')
  add(type, 'udp', 'false')
}
// T16 families: no-op forms accepted by both engines.
for (const type of ['wireguard', 'openvpn']) {
  add(type, 'udp', 'false')
  add(type, 'tfo', 'false')
  add(type, 'mptcp', 'false')
  add(type, 'interface-name', "''")
  add(type, 'routing-mark', '0')
  add(type, 'ip-version', "''")
  add(type, 'ip-stack', '{}')
}
add('wireguard', 'workers', '0')
add('wireguard', 'mtu', '0')
add('wireguard', 'persistent-keepalive', '0')
add('openvpn', 'comp-lzo', 'no')
add('openvpn', 'ping', '0')
add('openvpn', 'ping-restart', '0')
add('openvpn', 'tran-window', '0')
add('openvpn', 'handshake-timeout', '0')
add('openvpn', 'mtu', '0')
add('openvpn', 'key-direction', "''")

// Enabled forms: every one must be rejected by name.

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
for (const entry of allEnabled) runCase(entry, true, 'enabled')

// A family the matrix cannot compare: its pinned base configuration itself
// selects behaviour this kernel rejects, so every row would report the base's
// rejection instead of the option under test. It is named here rather than
// dropped silently.
const skipped = []
const header = [
  '# Proxy option matrix: no-op forms must load, enabled forms must be rejected.',
  `# rust: ${binary}`,
  `# mihomo: ${mihomo ?? '(not provided: only the Rust verdict was checked)'}`,
  `# no-op cases: ${noops.length}, enabled cases: ${allEnabled.length}, problems: ${problems.length}`,
  '# command: node tool/kernel-compat/option-probe.mjs --rust <billow-kernel> --mihomo <mihomo>',
  ...skipped.map(([type, reason]) => `# skipped: ${type} (- ${reason})`),
  '',
]
const text = [...header, ...lines, ...(problems.length ? ['', ...problems.map((problem) => `PROBLEM ${problem}`)] : [])].join('\n') + '\n'
if (options.out) writeFileSync(options.out, text)
process.stdout.write(text)
if (problems.length) {
  console.error(`${problems.length} option-matrix problem(s)`)
  process.exitCode = 1
}
