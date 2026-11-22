// Billow's effective (launcher-settled) configuration for the Rust engine.
//
// `src-tauri/src/profile.rs` is not importable from Node: `kernel_yaml_for`
// lives inside the Tauri crate and needs the profile store. This module mirrors
// the steps that actually shape the YAML handed to `Engine::Rust` and is kept
// next to the differential so the artifact is generated, not hand-written:
//
//   prepare_named            override merge          (profile.rs:5927)
//   apply_settings           settings + platform     (profile.rs:4704-4943)
//   strip_launcher_tun       Rust + !tun_enable       (profile.rs:5103-5112)
//   ensure_tun_dns           no-op while tun disabled (profile.rs:5114-5138)
//   force_mode               UI mode                  (profile.rs:5877-5887)
//   finish_yaml_for          selection order only    (profile.rs:3712-3718)
//
// Two shapes matter for the native kernel:
// - desktop: desktop `apply_settings` materializes a launcher `tun` block even
//   when the profile wrote none; `strip_launcher_tun` removes it again because
//   the kernel has no TUN path.
// - Android: `apply_settings` rewrites the legacy listeners to `0`, adds a
//   private `external-controller` and a disabled `tun` block; the same
//   `strip_launcher_tun` removes the launcher block because the user profile
//   carried no `tun` key.
//
// The profile fixture is JSON, which is also valid YAML 1.2, so this mirror can
// parse it without a YAML dependency. The emitted artifact is block YAML, the
// same shape `serde_yaml::to_string` produces for these scalar/sequence values.

const LOOPBACK_RANGES = ['127.0.0.1/8', '::1/128']

function withLoopback(existing, extra) {
  const items = Array.isArray(existing) ? existing.slice() : []
  for (const item of [...extra, ...LOOPBACK_RANGES]) {
    if (!items.includes(item)) items.push(item)
  }
  return items
}

function defaultSniffer() {
  return {
    enable: true,
    'force-dns-mapping': true,
    'parse-pure-ip': true,
    sniff: {
      HTTP: { ports: [80, '8080-8880'], 'override-destination': true },
      TLS: { ports: [443, 8443] },
      QUIC: { ports: [443, 8443] },
    },
    'skip-domain': ['Mijia Cloud', '+.push.apple.com'],
  }
}

function overlaySniffer(sniffer, settings) {
  const ports = [
    ['HTTP', settings.sniffPorts?.http],
    ['TLS', settings.sniffPorts?.tls],
    ['QUIC', settings.sniffPorts?.quic],
  ]
  if (ports.some(([, items]) => items)) {
    sniffer.sniff ??= {}
    for (const [protocol, items] of ports) {
      if (!items) continue
      sniffer.sniff[protocol] = {
        ...(sniffer.sniff[protocol] ?? {}),
        ports: items.map((item) => (/^\d+$/.test(item) ? Number(item) : item)),
      }
    }
  }
  if (settings.sniffForceDomain) sniffer['force-domain'] = settings.sniffForceDomain
  if (settings.sniffSkipDomain) sniffer['skip-domain'] = settings.sniffSkipDomain
  if (settings.sniffOverrideDestination !== undefined) {
    sniffer['override-destination'] = settings.sniffOverrideDestination
    for (const entry of Object.values(sniffer.sniff ?? {})) {
      if (entry && Object.hasOwn(entry, 'override-destination')) {
        entry['override-destination'] = settings.sniffOverrideDestination
      }
    }
  }
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value))
}

/**
 * Mirrors `ProfileBook::kernel_yaml_for(Engine::Rust, tun_enable=false)`.
 * `platform` is `'desktop'` or `'android'`; `settings` uses the
 * `KernelSettings` field names in camelCase.
 */
export function effectiveYaml(profileText, settings, platform) {
  const result = effectiveConfig(profileText, settings, platform)
  return { ...result, yaml: emitYaml(result.config) }
}

export function effectiveConfig(profileText, settings, platform) {
  const desktop = platform === 'desktop'
  const map = JSON.parse(profileText)
  const userHadTun = map.tun !== undefined

  // apply_settings: mixed-port selection.
  if (settings.mixedPort) {
    map['mixed-port'] = settings.mixedPort
    if (desktop) {
      delete map.port
      delete map['socks-port']
    }
  } else if (map['mixed-port'] === undefined && map.port === undefined) {
    map['mixed-port'] = 7890
  } else if (map['mixed-port'] === undefined && typeof map.port === 'number') {
    map['mixed-port'] = map.port
    if (desktop) delete map.port
  }

  if (desktop) {
    const mixed = map['mixed-port']
    if (mixed > 0) {
      for (const name of ['port', 'socks-port', 'redir-port', 'tproxy-port']) {
        if (map[name] === mixed) delete map[name]
      }
    }
    const explicit = [
      ['socks-port', settings.socksPort],
      ['port', settings.httpPort],
      ['redir-port', settings.redirPort],
      ['tproxy-port', settings.tproxyPort],
    ]
    const taken = explicit.map(([, port]) => port).filter((port) => port > 0)
    for (const [name, port] of explicit) {
      if (port) map[name] = port
      else if (taken.includes(map[name])) delete map[name]
    }
    if (settings.interfaceName !== undefined) {
      if (settings.interfaceName === '') delete map['interface-name']
      else map['interface-name'] = settings.interfaceName
    }
    if (settings.routingMark !== undefined) {
      if (settings.routingMark === 0) delete map['routing-mark']
      else map['routing-mark'] = settings.routingMark
    }
  } else {
    // Android: private controller, legacy listeners disabled, TUN belongs to
    // the VPN service (the launcher block is removed for the Rust engine).
    for (const name of ['port', 'socks-port', 'redir-port', 'tproxy-port']) map[name] = 0
    map['external-controller'] = `127.0.0.1:${settings.androidControllerPort}`
    map.tun = {
      ...(map.tun ?? {}),
      enable: false,
      'auto-route': false,
      'auto-detect-interface': false,
      'dns-hijack': ['any:53'],
    }
  }

  if (settings.allowLan !== undefined) map['allow-lan'] = settings.allowLan
  if (settings.ipv6 !== undefined) map.ipv6 = settings.ipv6
  if (settings.logLevel !== undefined) map['log-level'] = settings.logLevel
  if (settings.unifiedDelay !== undefined) map['unified-delay'] = settings.unifiedDelay
  if (settings.tcpConcurrent !== undefined) map['tcp-concurrent'] = settings.tcpConcurrent
  if (settings.findProcessMode !== undefined) map['find-process-mode'] = settings.findProcessMode

  if (settings.dnsOverride) {
    map.dns = settings.dns
    if (settings.dns?.useHosts && settings.dns.hosts) {
      map.hosts = { ...(map.hosts ?? {}), ...settings.dns.hosts }
    }
  }
  if (settings.geodataMode !== undefined) map['geodata-mode'] = settings.geodataMode
  if (settings.geodataLoader !== undefined) map['geodata-loader'] = settings.geodataLoader
  if (settings.geoAutoUpdate !== undefined) map['geo-auto-update'] = settings.geoAutoUpdate
  if (settings.geoUpdateInterval) map['geo-update-interval'] = settings.geoUpdateInterval
  if (settings.geoSource) {
    map['geox-url'] = { 'geoip': settings.geoSource, 'geosite': settings.geoSource }
  }
  if (settings.keepAliveInterval === 0) map['disable-keep-alive'] = true
  else if (settings.keepAliveInterval) {
    map['disable-keep-alive'] = false
    map['keep-alive-interval'] = settings.keepAliveInterval
  }
  if (settings.lanAuth?.length) {
    map.authentication = settings.lanAuth
    map['skip-auth-prefixes'] = withLoopback(map['skip-auth-prefixes'], [])
  }
  if (settings.lanAllowedIps?.length) {
    map['lan-allowed-ips'] = withLoopback(undefined, settings.lanAllowedIps)
  }
  if (settings.sniffer === true) {
    map.sniffer = defaultSniffer()
    overlaySniffer(map.sniffer, settings)
  } else if (settings.sniffer === false) {
    map.sniffer = { enable: false }
  }
  if (desktop) {
    // TUN settings are always materialized on desktop; the Rust path below
    // removes them when the profile itself wrote no `tun` key.
    const tun = { ...(map.tun ?? {}) }
    if (settings.tun?.stack) tun.stack = settings.tun.stack
    tun['auto-route'] = Boolean(settings.tun?.autoRoute)
    tun['auto-detect-interface'] = Boolean(settings.tun?.autoDetectInterface)
    tun['strict-route'] = Boolean(settings.tun?.strictRoute)
    tun['dns-hijack'] = settings.tun?.dnsHijack ?? ['any:53']
    if (settings.tun?.mtu > 0) tun.mtu = settings.tun.mtu
    if (settings.tun?.device) tun.device = settings.tun.device
    map.tun = tun
  }

  // strip_launcher_tun: only the launcher block goes; a user-written `tun`
  // key stays and is rejected by name in the kernel.
  if (!userHadTun) delete map.tun
  // ensure_tun_dns is a no-op while `tun.enable` is not true.
  return { config: map, profileHadTun: userHadTun, platform }
}

// Block YAML for the value shapes this artifact contains.
export function emitYaml(value, indent = 0) {
  const pad = ' '.repeat(indent)
  if (Array.isArray(value)) {
    if (value.length === 0) return `${pad}[]`
    return value
      .map((item) => {
        if (item !== null && typeof item === 'object') {
          const body = emitYaml(item, indent + 2).split('\n')
          const first = body[0].slice(indent + 2)
          return [`${pad}- ${first}`, ...body.slice(1)].join('\n')
        }
        return `${pad}- ${scalar(item)}`
      })
      .join('\n')
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value)
    if (entries.length === 0) return `${pad}{}`
    return entries
      .map(([name, item]) => {
        const label = `${pad}${safeKey(name)}:`
        if (Array.isArray(item)) {
          if (item.length === 0) return `${label} []`
          if (item.every((entry) => entry === null || typeof entry !== 'object')) {
            return `${label} [${item.map(scalar).join(', ')}]`
          }
          return `${label}\n${emitYaml(item, indent + 2)}`
        }
        if (item !== null && typeof item === 'object') {
          return `${label}\n${emitYaml(item, indent + 2)}`
        }
        return `${label} ${scalar(item)}`
      })
      .join('\n')
  }
  return `${pad}${scalar(value)}`
}

function safeKey(name) {
  return /^[A-Za-z0-9_.+-]+$/.test(name) ? name : JSON.stringify(name)
}

function scalar(value) {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(String(value))
}

// Representative `KernelSettings` for the desktop and Android artifacts. Values
// follow the shipped UI defaults where one exists; `sniffer: true` is a real
// user-facing toggle and is the key the kernel still rejects by name (T7).
export const T5_SETTINGS = {
  mixedPort: 7890,
  allowLan: true,
  ipv6: false,
  logLevel: 'warning',
  unifiedDelay: true,
  tcpConcurrent: true,
  findProcessMode: 'off',
  dnsOverride: false,
  // GeoIP.dat mode keeps the artifact self-contained: the bundled MMDB is
  // shipped compressed (`.mmdb.br`) and decompressing it is a delivery step,
  // while the dat fixtures are generated by the harness.
  geodataMode: true,
  geodataLoader: 'memconservative',
  geoAutoUpdate: false,
  geoUpdateInterval: 24,
  geoSource: '',
  keepAliveInterval: 30,
  // LAN auth and allowed-IP lists stay out of this artifact: they are
  // user opt-ins whose keys the kernel still rejects by name (see evidence).
  lanAuth: [],
  lanAllowedIps: [],
  sniffer: true,
  sniffPorts: { http: ['80', '8080-8880'], tls: ['443'], quic: ['443'] },
  sniffForceDomain: ['+.force.example'],
  sniffSkipDomain: ['+.skip.example'],
  sniffOverrideDestination: true,
  tun: {
    stack: 'mixed',
    autoRoute: true,
    autoDetectInterface: true,
    strictRoute: false,
    dnsHijack: ['any:53'],
    mtu: 9000,
    device: 'Mihomo',
  },
  androidControllerPort: 49152,
  socksPort: undefined,
  httpPort: undefined,
  redirPort: undefined,
  tproxyPort: undefined,
  interfaceName: undefined,
  routingMark: undefined,
}
