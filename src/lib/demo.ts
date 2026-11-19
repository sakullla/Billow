import type { Backend, NodeTestEvent } from './backend'
import { ruleKeys } from './rule-keys'
import {
  DNS_QUERY_TYPES,
  emptyKernelSettings,
  isValidDnsName,
  emptySnapshot,
  type AppInfo,
  type ConfigOverview,
  type ConnectionRow,
  type DnsQueryResult,
  type KernelStatus,
  type LogLine,
  type NodeGroup,
  type ProviderRow,
  type ProfileItem,
  type RuleRow,
  type Snapshot,
  type ThemePreference,
} from './types'

/**
 * In-memory backend used when the page runs outside Tauri (browser preview, tests).
 * It behaves like the real one closely enough to exercise every screen.
 */

const REGIONS = ['香港', '日本', '新加坡', '美国', '台湾', '韩国', '德国', '英国']
const TYPES = ['vless', 'trojan', 'ss', 'hysteria2', 'vmess', 'tuic']
/** Demo capability tags per protocol, matching what the backend derives from a config. */
const DEMO_TAGS: Record<string, string[]> = {
  vless: ['UDP', 'Reality', 'Vision'],
  trojan: ['UDP', 'WS'],
  ss: ['UDP'],
  hysteria2: ['UDP'],
  vmess: ['TLS', 'gRPC'],
  tuic: ['UDP'],
}
const HOSTS = [
  'www.google.com',
  'api.github.com',
  'i.ytimg.com',
  'www.youtube.com',
  'gateway.icloud.com',
  'cdn.jsdelivr.net',
  'api.openai.com',
  'claude.ai',
  'www.bilibili.com',
  'registry.npmjs.org',
  'discord.com',
  'pbs.twimg.com',
]
const PROCESSES = ['chrome', 'Telegram', 'node', 'Code', 'curl', 'Safari', 'Discord']

function nodeNames(): string[] {
  const names: string[] = []
  REGIONS.forEach((region, index) => {
    const count = index < 3 ? 3 : 2
    for (let i = 1; i <= count; i += 1) names.push(`${region} ${String(i).padStart(2, '0')}`)
  })
  return names
}

interface DemoOptions {
  profiles?: boolean
  platform?: 'desktop' | 'android'
  /** Group icons by group name; include an unreachable URL to exercise the fallback. */
  groupIcons?: Record<string, string>
  /** Simulate a `/connections` read failure while connected. */
  connectionsFailure?: boolean
  /** When false, `/rules` reports no hit statistics. */
  rulesExtra?: boolean
  /** Fail every refresh of this profile, so partial update-all and retry can be exercised. */
  failRefreshId?: string
  /** Add a dozen more rule sets, the shape of a typical rule-heavy subscription. */
  manyProviders?: boolean
  /** Airport-style long node names and a nested group chain (`?demo=long`). */
  longNames?: boolean
  /** A heavy subscription: ~60 nodes and ~30 policy groups (`?demo=big`), for performance checks. */
  big?: boolean
  /** Groups the config marks `hidden: true` (R29). */
  hiddenGroups?: readonly string[]
  /** Add a `load-balance` group, which stays automatic (R28). */
  loadBalance?: boolean
  /**
   * A fixed set of this many connections, one per demo host in order, that
   * never churn or refill, so close-by-filter can be checked row for row (R30).
   */
  stableConnections?: number
}

/** Fixed `/dns/query` answers the demo returns per record type (R31). */
const DEMO_DNS_ANSWERS: Record<string, { type: string; value: string; ttl: number }[]> = {
  A: [
    { type: 'A', value: '93.184.215.14', ttl: 300 },
    { type: 'A', value: '23.192.228.80', ttl: 300 },
  ],
  AAAA: [{ type: 'AAAA', value: '2606:2800:21f:cb07:6820:80da:af6b:8b2c', ttl: 300 }],
  CNAME: [{ type: 'CNAME', value: 'edge.example.net.', ttl: 3600 }],
  MX: [{ type: 'MX', value: '10 mail.example.com.', ttl: 3600 }],
  TXT: [{ type: 'TXT', value: '"v=spf1 -all"', ttl: 3600 }],
  NS: [
    { type: 'NS', value: 'a.iana-servers.net.', ttl: 86400 },
    { type: 'NS', value: 'b.iana-servers.net.', ttl: 86400 },
  ],
  SRV: [],
  HTTPS: [{ type: 'HTTPS', value: '1 . alpn="h2,h3"', ttl: 300 }],
}

/** Real subscriptions pack region, line, rate and unlocks into one name. */
export const DEMO_LONG_NAMES = [
  '🇭🇰 香港 HKT 家宽 01 丨 0.8x 倍率 丨 解锁 Netflix / Disney+ / ChatGPT 丨 IPLC 专线',
  '🇺🇸 美国 洛杉矶 CN2 GIA 高速 02 [x1.5] Hysteria2 原生 IP 落地',
  '🇯🇵 日本 东京 Oracle → 新加坡 中转 → 美国 落地（链式）',
]

const DUPLICATE_ERROR = '该订阅已存在'
const AGE_KEY_ERROR = 'age 私钥格式不正确：每行一个以 AGE-SECRET-KEY-1 开头的私钥，# 开头的行视为注释'

const DEMO_GROUP_ICONS: Record<string, string> = {
  流媒体: 'https://icons.example.com/media.png',
  OpenAI: 'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=',
  国内网站: 'https://unreachable.invalid/cn.png',
}

export function createDemoBackend(options: DemoOptions = {}): Backend {
  const baseNames = options.longNames ? [...DEMO_LONG_NAMES, ...nodeNames()] : nodeNames()
  const names = options.big
    ? [...baseNames, ...Array.from({ length: 48 }, (_, index) => `【KLM】Hong Kong ${String(index + 1).padStart(2, '0')}`)]
    : baseNames
  const groupIcons = options.groupIcons ?? DEMO_GROUP_ICONS
  const rulesExtra = options.rulesExtra !== false
  const failRefreshId = options.failRefreshId ?? null
  const types = new Map(names.map((name, index) => [name, TYPES[index % TYPES.length]]))
  const state: Snapshot = emptySnapshot()
  state.platform = options.platform ?? 'desktop'
  state.mode = 'rule'
  let theme: ThemePreference = 'system'
  let entry = 'home'
  let kernel: KernelStatus = { channel: 'stable', failure: null, ready: true, version: 'v1.19.17' }
  let app: AppInfo = {
    version: '0.2.0',
    platform: 'demo',
    // Android has no autostart or tray; the real shell reports null there.
    autostart: options.platform === 'android' ? null : false,
    close_to_tray: true,
    silent_start: false,
    data_dir: null,
  }
  const delays = new Map<string, number | null>()
  const selections = new Map<string, string>([['节点选择', '香港 01']])
  if (options.longNames) {
    selections.set('节点选择', '自动选择')
    selections.set('漏网之鱼', '节点选择')
  }
  const autoNow = new Map<string, string>()
  /** Nodes fixed on url-test / fallback groups; replayed whenever the demo kernel starts (R28). */
  const fixed = new Map<string, string>()
  const hiddenGroups = new Set(options.hiddenGroups ?? [])
  const pinnable = (type: string) => type === 'url-test' || type === 'fallback'
  let connections: ConnectionRow[] = []
  /** `stableConnections` seeds once per connected session. */
  let stableSeeded = false
  let totals = { up: 0, down: 0 }
  let startedAt: number | null = null
  let nextId = 1
  const listeners = new Set<(snapshot: Snapshot) => void>()
  const contents = new Map<string, string>()

  const groupsDef = (): { name: string; type: string; proxies: string[] }[] => [
    { name: '节点选择', type: 'select', proxies: ['自动选择', '故障转移', ...names, 'DIRECT'] },
    { name: '自动选择', type: 'url-test', proxies: names },
    { name: '故障转移', type: 'fallback', proxies: names.slice(0, 6) },
    { name: '流媒体', type: 'select', proxies: ['节点选择', ...names.filter((n) => !n.startsWith('德国'))] },
    { name: 'OpenAI', type: 'select', proxies: ['美国 01', '美国 02', '日本 01', '新加坡 01'] },
    { name: '国内网站', type: 'select', proxies: ['DIRECT', '节点选择'] },
    { name: '漏网之鱼', type: 'select', proxies: ['节点选择', 'DIRECT'] },
    ...(options.loadBalance ? [{ name: '负载均衡', type: 'load-balance', proxies: names.slice(0, 4) }] : []),
    ...(options.big
      ? Array.from({ length: 24 }, (_, index) => ({ name: `策略组 ${index + 1}`, type: 'select', proxies: ['节点选择', '自动选择', ...names] }))
      : []),
  ]

  /** Top-level options of the demo profile file, as the backend would summarize them. */
  function demoProfileOptions(): Record<string, unknown> {
    return {
      'mixed-port': 7890,
      mode: 'rule',
      'allow-lan': false,
      ipv6: false,
      'log-level': 'info',
      'unified-delay': true,
      'tcp-concurrent': true,
      'find-process-mode': 'strict',
      'global-client-fingerprint': 'chrome',
      'external-controller': '127.0.0.1:9090',
      profile: { 'store-selected': true, 'store-fake-ip': true },
      dns: {
        enable: true,
        ipv6: false,
        'enhanced-mode': 'fake-ip',
        'fake-ip-range': '198.18.0.1/16',
        'default-nameserver': ['223.5.5.5', '119.29.29.29'],
        nameserver: ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query'],
        'nameserver-policy': { 'geosite:geolocation-!cn': ['https://1.1.1.1/dns-query'] },
      },
      sniffer: { enable: true, sniff: { HTTP: { ports: [80] }, TLS: { ports: [443] }, QUIC: { ports: [443] } } },
      'geodata-mode': true,
      'geo-auto-update': false,
    }
  }

  /** Simple `key: scalar` lines of a 覆写; enough for the demo to show the layer. */
  function demoOverrideOptions(text: string): Record<string, unknown> {
    const out: Record<string, unknown> = {}
    for (const line of text.split(/\r?\n/)) {
      const match = /^([A-Za-z][\w-]*):\s*(\S.*)$/.exec(line)
      if (!match) continue
      const raw = match[2]!.replace(/\s+#.*$/, '').trim()
      out[match[1]!] = raw === 'true' ? true : raw === 'false' ? false : /^\d+$/.test(raw) ? Number(raw) : raw.replace(/^['"]|['"]$/g, '')
    }
    return out
  }

  /** Mirror of the backend's apply_settings for the options the overview shows. */
  function demoEffectiveOptions(prepared: Record<string, unknown>): Record<string, unknown> {
    const s = state.settings
    const out: Record<string, unknown> = JSON.parse(JSON.stringify(prepared))
    if (state.mode) out.mode = state.mode
    if (s.mixed_port) out['mixed-port'] = s.mixed_port
    const flags: [keyof typeof s, string][] = [
      ['allow_lan', 'allow-lan'],
      ['ipv6', 'ipv6'],
      ['unified_delay', 'unified-delay'],
      ['tcp_concurrent', 'tcp-concurrent'],
    ]
    for (const [key, name] of flags) if (s[key] != null) out[name] = s[key]
    if (s.log_level) out['log-level'] = s.log_level
    if (s.find_process_mode) out['find-process-mode'] = s.find_process_mode
    if (s.geodata_mode != null) out['geodata-mode'] = s.geodata_mode
    if (s.geodata_loader) out['geodata-loader'] = s.geodata_loader
    if (s.geo_auto_update != null) out['geo-auto-update'] = s.geo_auto_update
    if (s.geo_auto_update && s.geo_update_interval) out['geo-update-interval'] = s.geo_update_interval
    if (s.keep_alive_interval === 0) out['disable-keep-alive'] = true
    else if (s.keep_alive_interval != null) {
      out['disable-keep-alive'] = false
      out['keep-alive-interval'] = s.keep_alive_interval
    }
    const loopback = ['127.0.0.1/8', '::1/128']
    if (s.lan_auth.length) {
      out.authentication = s.lan_auth.map((entry) => `${entry.split(':')[0]}:••••`)
      out['skip-auth-prefixes'] = loopback
    }
    if (s.lan_allowed_ips.length) out['lan-allowed-ips'] = [...s.lan_allowed_ips, ...loopback]
    if (s.sniffer != null) out.sniffer = s.sniffer ? demoProfileOptions().sniffer : { enable: false }
    if (s.dns_override) {
      out.dns = {
        enable: true,
        ipv6: s.dns.ipv6,
        'enhanced-mode': s.dns.enhanced_mode,
        'fake-ip-range': s.dns.fake_ip_range,
        nameserver: s.dns.nameserver,
        'default-nameserver': s.dns.default_nameserver,
      }
    }
    if (state.platform !== 'android') {
      out.tun = {
        enable: state.tun,
        ...(s.tun.stack ? { stack: s.tun.stack } : {}),
        'auto-route': s.tun.auto_route,
        'auto-detect-interface': s.tun.auto_detect_interface,
        'strict-route': s.tun.strict_route,
        'dns-hijack': s.tun.dns_hijack,
        ...(s.tun.mtu ? { mtu: s.tun.mtu } : {}),
      }
    }
    return out
  }

  function addProfile(partial: Partial<ProfileItem>): ProfileItem {
    const id = `p${nextId++}`
    const profile: ProfileItem = {
      id,
      name: '新配置',
      kind: 'subscription',
      source: '',
      current: false,
      failure: null,
      override_text: '',
      override_error: null,
      used: null,
      total: null,
      expire: null,
      last_success_ms: null,
      interval_hours: 0,
      updated_ms: null,
      proxy_count: names.length,
      age_recipients: [],
      user_agent: '',
      ...partial,
    }
    state.profiles.push(profile)
    contents.set(id, `mixed-port: 7890\nmode: rule\nproxies:\n${names.map((n) => `  - { name: "${n}", type: ${types.get(n)}, server: example.com, port: 443 }`).join('\n')}\n`)
    return profile
  }

  if (options.profiles !== false) {
    const now = Date.now()
    addProfile({
      name: '星河云',
      source: 'https://sub.example.com/api/v1/client/subscribe?token=demo',
      used: 86.4 * 1024 ** 3,
      total: 200 * 1024 ** 3,
      expire: Math.floor(now / 1000) + 41 * 86400,
      last_success_ms: now - 2 * 3600_000,
      updated_ms: now - 2 * 3600_000,
      interval_hours: 12,
    })
    addProfile({
      name: '备用机场',
      source: 'https://backup.example.net/link/abcdef?clash=1',
      used: 12.1 * 1024 ** 3,
      total: 50 * 1024 ** 3,
      expire: Math.floor(now / 1000) + 5 * 86400,
      last_success_ms: now - 3 * 86400_000,
      updated_ms: now - 3 * 86400_000,
    })
    addProfile({ name: 'home-lab.yaml', kind: 'local', proxy_count: 4, updated_ms: now - 9 * 86400_000 })
    state.active_id = 'p1'
    state.mixed_port = 7890
  }

  if (state.platform === 'android') {
    state.installed = [
      { name: 'Chrome', package_name: 'com.android.chrome', system: false },
      { name: 'Telegram', package_name: 'org.telegram.messenger', system: false },
      { name: '微信', package_name: 'com.tencent.mm', system: false },
      { name: '支付宝', package_name: 'com.eg.android.AlipayGphone', system: false },
      { name: 'YouTube', package_name: 'com.google.android.youtube', system: false },
      { name: '哔哩哔哩', package_name: 'tv.danmaku.bili', system: false },
      { name: 'GitHub', package_name: 'com.github.android', system: false },
      { name: '招商银行', package_name: 'cmb.pb', system: false },
      { name: 'Google Play 服务', package_name: 'com.google.android.gms', system: true },
      { name: '设置', package_name: 'com.android.settings', system: true },
      { name: '系统界面', package_name: 'com.android.systemui', system: true },
    ]
    state.excluded = ['com.tencent.mm']
  }

  const ruleSeeds: { kind: string; payload: string; proxy: string }[] = [
    { kind: 'DomainSuffix', payload: 'openai.com', proxy: 'OpenAI' },
    { kind: 'DomainSuffix', payload: 'claude.ai', proxy: 'OpenAI' },
    { kind: 'DomainKeyword', payload: 'youtube', proxy: '流媒体' },
    { kind: 'DomainSuffix', payload: 'netflix.com', proxy: '流媒体' },
    { kind: 'DomainSuffix', payload: 'github.com', proxy: '节点选择' },
    { kind: 'DomainSuffix', payload: 'google.com', proxy: '节点选择' },
    { kind: 'RuleSet', payload: 'telegram', proxy: '节点选择' },
    { kind: 'DomainSuffix', payload: 'bilibili.com', proxy: '国内网站' },
    { kind: 'RuleSet', payload: 'cn-domains', proxy: '国内网站' },
    { kind: 'GeoIP', payload: 'LAN', proxy: 'DIRECT' },
    { kind: 'GeoIP', payload: 'CN', proxy: '国内网站' },
    { kind: 'Match', payload: '', proxy: '漏网之鱼' },
  ]
  const ruleCounts = [18, 6, 130, 24, 91, 512, 77, 0, 1204, 880, 320, 46]
  const ruleKeyList = ruleKeys(ruleSeeds)
  const rules: RuleRow[] = ruleSeeds.map((rule, index) => ({
    ...rule,
    hit_count: rulesExtra ? ruleCounts[index] ?? 0 : null,
    last_hit: rulesExtra ? new Date(Date.now() - (index + 1) * 7 * 60_000).toISOString() : null,
    key: ruleKeyList[index],
    disabled: false,
  }))
  const disabledRules = new Set<string>()
  const nodeTestListeners = new Set<(event: NodeTestEvent) => void>()

  const hoursAgo = (h: number) => new Date(Date.now() - h * 3600_000).toISOString()
  const providerRows: ProviderRow[] = [
    { name: '机场订阅', kind: 'proxy', vehicle: 'HTTP', behavior: '', format: '', count: 19, updated_at: hoursAgo(5), used: 86 * 1024 ** 3, total: 200 * 1024 ** 3, expire: null },
    { name: '自建节点', kind: 'proxy', vehicle: 'File', behavior: '', format: '', count: 3, updated_at: hoursAgo(80), used: null, total: null, expire: null },
    { name: 'cn-domains', kind: 'rule', vehicle: 'HTTP', behavior: 'Domain', format: 'MrsRule', count: 112480, updated_at: hoursAgo(20), used: null, total: null, expire: null },
    { name: 'telegram', kind: 'rule', vehicle: 'HTTP', behavior: 'IPCIDR', format: 'YamlRule', count: 18, updated_at: hoursAgo(20), used: null, total: null, expire: null },
    { name: 'private', kind: 'rule', vehicle: 'Inline', behavior: 'Classical', format: '', count: 6, updated_at: hoursAgo(20), used: null, total: null, expire: null },
  ]
  if (options.manyProviders) {
    const extra: [string, number][] = [
      ['Apple', 1592], ['BiliBili', 129], ['ChinaMax', 123062], ['Claude', 3], ['Disney', 174], ['GlobalMedia', 2265],
      ['Google', 701], ['Lan', 18], ['Microsoft', 380], ['Netflix', 47], ['OpenAI', 26], ['Steam', 64], ['YouTube', 59],
    ]
    for (const [name, count] of extra) {
      providerRows.push({ name, kind: 'rule', vehicle: 'HTTP', behavior: 'Classical', format: 'YamlRule', count, updated_at: hoursAgo(1), used: null, total: null, expire: null })
    }
  }

  const initialGeoAt = Date.now() - 3 * 86_400_000
  const geoStore: Record<string, { exists: boolean; size: number | null; modified_ms: number | null }> = {
    geoip: { exists: true, size: 11_534_336, modified_ms: initialGeoAt },
    geosite: { exists: true, size: 5_976_883, modified_ms: initialGeoAt },
    mmdb: { exists: true, size: 9_123_456, modified_ms: initialGeoAt },
    asn: { exists: false, size: null, modified_ms: null },
  }

  function log(level: LogLine['level'], message: string) {
    state.logs.push({ level, message, time_ms: Date.now() })
    if (state.logs.length > 1000) state.logs.splice(0, state.logs.length - 1000)
  }

  function catalog(): NodeGroup[] {
    if (!state.active_id) return []
    return groupsDef().map((group) => {
      const manual = group.type === 'select'
      const canPin = pinnable(group.type)
      const pinned = canPin ? fixed.get(group.name) ?? null : null
      const now = manual
        ? selections.get(group.name) ?? group.proxies[0]
        : autoNow.get(group.name) ?? pinned ?? (state.kernel_running ? group.proxies[0] : '')
      return {
        name: group.name,
        kind: manual ? 'manual' : 'auto',
        now,
        sort: 'default',
        group_type: group.type,
        icon: groupIcons[group.name] ?? null,
        pinnable: canPin,
        fixed: pinned,
        hidden: hiddenGroups.has(group.name),
        nodes: group.proxies.map((name) => {
          const delay = delays.get(name)
          const baseTags = DEMO_TAGS[types.get(name) ?? ''] ?? []
          const isChained = name === DEMO_LONG_NAMES[2]
          return {
            name,
            delay_ms: delay ?? null,
            failed: delay === null,
            selected: name === now,
            node_type: types.get(name) ?? groupsDef().find((g) => g.name === name)?.type ?? (name === 'DIRECT' ? 'direct' : ''),
            tags: isChained ? [...baseTags, '链式'] : baseTags,
            ...(isChained ? { dialer_proxy: '香港 01' } : {}),
          }
        }),
      }
    })
  }

  function makeConnection(pick?: string): ConnectionRow {
    const host = pick ?? HOSTS[Math.floor(Math.random() * HOSTS.length)]
    const target = host.includes('bilibili') ? 'DIRECT' : options.longNames ? '漏网之鱼' : '节点选择'
    const hops: string[] = []
    for (let at: string | undefined = target; at && !hops.includes(at); ) {
      hops.unshift(at)
      const group = catalog().find((item) => item.name === at)
      at = group ? group.now || undefined : undefined
    }
    if (!options.longNames && hops.length > 2) hops.splice(1, hops.length - 2)
    const chain = hops[0] ?? 'DIRECT'
    return {
      id: Math.random().toString(16).slice(2, 10) + '-' + Date.now().toString(16),
      host,
      outbound: chain,
      network: Math.random() > 0.85 ? 'udp' : 'tcp',
      conn_type: 'HTTP Connect',
      destination: `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.0.${Math.floor(Math.random() * 255)}:443`,
      source: `127.0.0.1:${50000 + Math.floor(Math.random() * 9000)}`,
      process: PROCESSES[Math.floor(Math.random() * PROCESSES.length)],
      rule: host.includes('bilibili') ? 'DomainSuffix' : 'Match',
      rule_payload: host.includes('bilibili') ? 'bilibili.com' : '',
      chains: hops,
      upload: Math.floor(Math.random() * 40_000),
      download: Math.floor(Math.random() * 4_000_000),
      start: new Date(Date.now() - Math.floor(Math.random() * 600_000)).toISOString(),
    }
  }

  function tick() {
    if (!state.connected) {
      state.upload = null
      state.download = null
      state.upload_total = null
      state.download_total = null
      connections = []
      stableSeeded = false
      return
    }
    const wave = Math.sin(Date.now() / 4000)
    const up = Math.max(0, Math.round(18_000 + wave * 12_000 + Math.random() * 15_000))
    const down = Math.max(0, Math.round(420_000 + wave * 380_000 + Math.random() * 600_000))
    state.upload = up
    state.download = down
    totals = { up: totals.up + up, down: totals.down + down }
    state.upload_total = totals.up
    state.download_total = totals.down
    if (options.stableConnections !== undefined) {
      if (!stableSeeded) {
        stableSeeded = true
        connections = Array.from({ length: options.stableConnections }, (_, index) => ({
          ...makeConnection(HOSTS[index % HOSTS.length]),
          id: `stable-${index + 1}`,
        }))
      }
      return
    }
    connections = connections
      .filter(() => Math.random() > 0.06)
      .map((row) => ({ ...row, upload: row.upload + Math.floor(Math.random() * 3000), download: row.download + Math.floor(Math.random() * 90_000) }))
    while (connections.length < 14) connections.push(makeConnection())
    // Keep one DIRECT row alive so the route filter always has both sides to show.
    if (!connections.some((row) => row.chains[0] === 'DIRECT')) {
      connections[connections.length - 1] = makeConnection(HOSTS.find((host) => host.includes('bilibili')))
    }
    if (Math.random() > 0.6) {
      const row = connections[Math.floor(Math.random() * connections.length)]
      log('info', `[TCP] ${row.source} --> ${row.host}:443 match ${row.rule}(${row.rule_payload}) using ${row.chains.join('[')}${row.chains.length > 1 ? ']' : ''}`)
    }
    if (Math.random() > 0.97) log('warning', `[UDP] dial ${selections.get('节点选择')} error: i/o timeout`)
  }

  function snapshot(): Snapshot {
    state.connected = state.kernel_running && (state.system_proxy || state.tun || state.vpn)
    tick()
    state.profiles.forEach((profile) => (profile.current = profile.id === state.active_id))
    const failure = Boolean(options.connectionsFailure) && state.connected
    state.connections = failure ? [] : [...connections]
    state.connection_total = state.connected && !failure ? connections.length : 0
    state.connections_error = failure ? '连接没有读取' : null
    state.kernel_memory = state.connected ? 128 * 1024 * 1024 : null
    state.kernel_uptime_secs =
      state.connected && startedAt !== null ? Math.max(0, Math.floor((Date.now() - startedAt) / 1000)) : null
    state.node_catalog = catalog()
    state.nodes_notice = state.active_id ? null : '需要先添加或更新配置'
    state.config_values = {
      mixed_port: 7890,
      allow_lan: false,
      ipv6: false,
      log_level: 'info',
      unified_delay: true,
      tcp_concurrent: true,
      find_process_mode: 'strict',
      keep_alive_interval: null,
      disable_keep_alive: null,
    }
    state.mixed_port = state.settings.mixed_port ?? (state.active_id ? 7890 : null)
    return structuredClone(state)
  }

  const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
  const done = async (ms = 120) => {
    await wait(ms)
    const snap = snapshot()
    listeners.forEach((handler) => handler(snap))
    return snap
  }
  const profile = (id: string) => state.profiles.find((item) => item.id === id)

  function startKernel(): boolean {
    if (!state.active_id) {
      state.failure = '没有可用配置'
      log('error', state.failure)
      return false
    }
    state.kernel_running = true
    state.connected = true
    state.failure = null
    startedAt = Date.now()
    autoNow.set('自动选择', names[1])
    autoNow.set('故障转移', names[0])
    if (options.loadBalance) autoNow.set('负载均衡', names[0])
    fixed.forEach((node, group) => autoNow.set(group, node))
    log('info', `Mihomo ${kernel.version} started, mixed proxy listening at 127.0.0.1:${state.mixed_port ?? 7890}`)
    return true
  }

  async function probe(list: string[]) {
    await wait(700)
    for (const name of list) {
      if (name === 'DIRECT') delays.set(name, 2 + Math.floor(Math.random() * 6))
      else if (Math.random() < 0.08) delays.set(name, null)
      else delays.set(name, 40 + Math.floor(Math.random() * 900 * Math.random()))
    }
  }

  function rulesSnapshot() {
    const disabled = [...disabledRules]
    if (!state.kernel_running) return { rules: [], error: '内核没有运行', disabled }
    return {
      rules: rules.map((row) => ({ ...row, disabled: row.key !== null && disabledRules.has(row.key) })),
      error: null,
      disabled,
    }
  }

  /** Emits one `node-test` event per node on a timer so progress is visible. */
  function simulateTestAll(members = groupsDef().flatMap((group) => group.proxies), interval = 70): Promise<void> {
    const list = [...new Set(members)]
    const total = list.length
    return new Promise((resolve) => {
      let index = 0
      let tested = 0
      const step = () => {
        if (index >= list.length) {
          resolve()
          return
        }
        const name = list[index]
        const delay =
          name === 'DIRECT' ? 2 + (index % 6) : index % 9 === 8 ? null : 40 + ((index * 37) % 520)
        delays.set(name, delay)
        tested += 1
        const event: NodeTestEvent = { node: name, delay, failed: delay === null, tested, total }
        nodeTestListeners.forEach((handler) => handler(event))
        index += 1
        if (index < list.length) setTimeout(step, interval)
        else resolve()
      }
      step()
    })
  }

  return {
    live: false,
    async shell() {
      return { theme, last_entry: entry }
    },
    async setTheme(next) {
      theme = next
    },
    async setEntry(next) {
      entry = next
    },
    async appInfo() {
      return app
    },
    async setAutostart(enabled) {
      app = { ...app, autostart: enabled }
      return app
    },
    async setAppBehavior(closeToTray, silentStart) {
      app = { ...app, close_to_tray: closeToTray, silent_start: silentStart }
      return app
    },
    async kernel() {
      return kernel
    },
    async setChannel(channel) {
      await wait(800)
      kernel = { ...kernel, channel, version: channel === 'preview' ? 'alpha-3f2c1a9' : 'v1.19.17', failure: null }
      return kernel
    },
    async refreshKernel() {
      await wait(900)
      return kernel
    },

    state: async () => snapshot(),
    async addSubscription(url) {
      try {
        const parsed = new URL(url.trim())
        if (!/^https?:$/.test(parsed.protocol)) throw new Error('scheme')
        const source = url.trim()
        if (state.profiles.some((item) => item.source.trim() === source)) {
          state.input_error = DUPLICATE_ERROR
        } else {
          addProfile({ name: parsed.host, source })
          state.input_error = null
        }
      } catch {
        state.input_error = '订阅链接不可用'
      }
      return done()
    },
    async addLocal(name, content) {
      if (!content.trim()) state.input_error = '配置无法应用'
      else {
        const created = addProfile({ name: name || '本地配置', kind: 'local', updated_ms: Date.now() })
        contents.set(created.id, content)
        state.input_error = null
      }
      return done()
    },
    async confirmInstall() {
      const pending = state.pending_url
      if (!pending) return done()
      if (state.profiles.some((item) => item.source.trim() === pending.trim())) {
        state.input_error = DUPLICATE_ERROR
        return done()
      }
      state.pending_url = null
      state.input_error = null
      addProfile({ name: new URL(pending).host, source: pending })
      return done()
    },
    async cancelInstall() {
      state.pending_url = null
      return done()
    },
    async enable(id) {
      const item = profile(id)
      if (item) {
        await wait(500)
        if (/^\s*-/.test(item.override_text)) {
          item.override_error = '覆写无法应用'
          return done()
        }
        state.active_id = id
        item.last_success_ms = Date.now()
        item.failure = null
        item.override_error = null
        delays.clear()
        if (state.kernel_running) log('info', `配置已切换为 ${item.name}`)
      }
      return done()
    },
    async update(id) {
      const item = profile(id)
      if (item) {
        await wait(900)
        item.updated_ms = Date.now()
        if (failRefreshId === id) item.failure = '订阅没有取回'
        else {
          item.last_success_ms = Date.now()
          item.failure = null
        }
      }
      return done()
    },
    async refresh(id) {
      return this.update(id)
    },
    async refreshAll() {
      await wait(1000)
      state.profiles.filter((p) => p.kind === 'subscription').forEach((p) => {
        p.updated_ms = Date.now()
        p.last_success_ms = Date.now()
      })
      return done()
    },
    async remove(id) {
      if (id === state.active_id && state.connected) state.notice = '请先断开连接再删除当前配置'
      else {
        state.profiles = state.profiles.filter((item) => item.id !== id)
        if (state.active_id === id) state.active_id = null
      }
      return done()
    },
    async rename(id, name) {
      const item = profile(id)
      const cleaned = name.trim().replace(/[/\\\r\n]/g, '').slice(0, 80)
      if (item && cleaned) {
        item.name = cleaned
        state.input_error = null
      }
      return done()
    },
    async setSource(id, url) {
      const item = profile(id)
      if (!item || item.kind !== 'subscription') return done()
      const trimmed = url.trim()
      try {
        if (!/^https?:\/\//i.test(trimmed) || /[\s\x00-\x1f\x7f]/.test(trimmed)) throw new Error('scheme')
        const parsed = new URL(trimmed)
        if (!/^https?:$/.test(parsed.protocol)) throw new Error('scheme')
        const host = parsed.hostname
        if (!host || (!host.includes('.') && host !== 'localhost' && !host.startsWith('['))) throw new Error('host')
        item.source = trimmed
        state.input_error = null
      } catch {
        state.input_error = '订阅链接不可用'
      }
      return done()
    },
    async setUserAgent(id, userAgent) {
      const item = profile(id)
      if (!item || item.kind !== 'subscription') return done()
      if (userAgent.length > 256 || /[^\x20-\x7e]/.test(userAgent)) {
        state.input_error = 'User-Agent 只能包含可打印的 ASCII 字符，长度不能超过 256，不能含换行'
      } else {
        item.user_agent = userAgent.trim()
        state.input_error = null
      }
      return done()
    },
    async setInterval(id, hours) {
      const item = profile(id)
      if (item) item.interval_hours = hours
      return done()
    },
    async setAgeKey(id, key) {
      const item = profile(id)
      if (!item || item.kind !== 'subscription') return done()
      const lines = key
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#'))
      // The demo mirrors the backend contract: X25519 identities only, public keys shown.
      if (lines.some((line) => !/^AGE-SECRET-KEY-1[0-9A-Z]{58}$/.test(line))) {
        state.input_error = AGE_KEY_ERROR
        return done()
      }
      state.input_error = null
      item.age_recipients = lines.map((line) => `age1${line.slice(16, 74).toLowerCase()}`)
      return done()
    },
    async content(id) {
      return contents.get(id) ?? ''
    },
    async saveContent(id, content) {
      contents.set(id, content)
      return done()
    },
    async effectiveConfig() {
      const active = state.active_id ? profile(state.active_id) : null
      if (!active) throw new Error('还没有启用配置')
      const override = active.override_text.trim()
      const base = contents.get(active.id) ?? ''
      const head = `mixed-port: ${state.mixed_port ?? 7890}\nmode: ${state.mode ?? 'rule'}\nexternal-controller: 127.0.0.1:9090\n`
      return `${head}${override ? `# ── 覆写 ──\n${override}\n` : ''}${base.replace(/^(mixed-port|mode):.*\n/gm, '')}`
    },
    async configOverview(): Promise<ConfigOverview> {
      await wait(120)
      const active = state.active_id ? profile(state.active_id) : null
      if (!active) throw new Error('还没有启用配置')
      const base = demoProfileOptions()
      const prepared = { ...base, ...demoOverrideOptions(active.override_text) }
      const groups = groupsDef()
      const groupTypes: Record<string, number> = {}
      for (const group of groups) groupTypes[group.type] = (groupTypes[group.type] ?? 0) + 1
      return {
        profile: base,
        prepared,
        effective: demoEffectiveOptions(prepared),
        counts: {
          proxies: names.length,
          'proxy-groups': groups.length,
          'proxy-providers': providerRows.filter((row) => row.kind === 'proxy').length,
          'rule-providers': providerRows.filter((row) => row.kind === 'rule').length,
          rules: rules.length,
        },
        group_types: groupTypes,
        running: state.kernel_running,
      }
    },
    async lanAddress() {
      return state.platform === 'android' ? '192.168.1.42' : '192.168.1.23'
    },
    async previewOverride(id, text) {
      await wait(250)
      const item = profile(id)
      if (!item) throw new Error('配置不存在')
      if (/^\s*-/.test(text)) throw new Error('YAML 覆写需要是键值对，例如 mixed-port: 7890')
      const logs = [...text.matchAll(/console\.log\((['"])(.*?)\1\)/g)].map((match) => match[2])
      return { yaml: `# 预览环境：仅示意合并结果\n${text.trim()}\n`, logs }
    },
    async saveOverride(id, text) {
      const item = profile(id)
      if (item) {
        item.override_text = text
        item.override_error = /^\s*-/.test(text) ? '覆写无法应用' : null
      }
      return done()
    },

    async connect() {
      await wait(600)
      if (startKernel()) {
        if (state.platform === 'android') state.vpn = true
        else {
          state.system_proxy = true
          state.tun = state.tun_wanted
        }
      }
      return done(0)
    },
    async disconnect() {
      await wait(300)
      state.connected = false
      state.kernel_running = false
      state.system_proxy = false
      state.tun = false
      state.vpn = false
      startedAt = null
      autoNow.clear()
      log('info', '内核已停止')
      return done(0)
    },
    async setSystemProxy(enabled) {
      if (enabled && !state.kernel_running && !startKernel()) return done()
      state.system_proxy = enabled
      return done()
    },
    async setTun(enabled) {
      state.tun_wanted = enabled
      if (enabled && !state.kernel_running && !startKernel()) return done()
      state.tun = enabled
      return done(400)
    },
    async setMode(mode) {
      state.mode = mode
      log('info', `出站模式切换为 ${mode}`)
      return done()
    },
    async exclude(pkg) {
      if (!state.excluded.includes(pkg)) state.excluded.push(pkg)
      return done()
    },
    async setAppRules(mode, packages) {
      const clean = [...new Set(packages.map((item) => item.trim()).filter(Boolean))]
      state.app_mode = mode
      if (mode === 'include') state.included = clean
      else state.excluded = clean
      return done(200)
    },
    async include(pkg) {
      state.excluded = state.excluded.filter((item) => item !== pkg)
      return done()
    },

    async selectNode(group, node) {
      const def = groupsDef().find((item) => item.name === group)
      if (def && def.type !== 'select') {
        if (!pinnable(def.type)) state.nodes_error = '不能改选'
        else if (!state.kernel_running) state.nodes_error = '内核没有运行'
        else {
          state.nodes_error = null
          const changed = autoNow.get(group) !== node
          fixed.set(group, node)
          autoNow.set(group, node)
          if (changed && state.settings.close_connections_on_switch) {
            connections = connections.filter((row) => !row.chains.includes(group) || row.chains.includes(node))
          }
        }
        return done(60)
      }
      const changed = selections.get(group) !== node
      state.nodes_error = null
      selections.set(group, node)
      if (changed && state.settings.close_connections_on_switch) {
        connections = connections.filter((row) => !row.chains.includes(group) || row.chains.includes(node))
      }
      return done(60)
    },
    async unfixGroup(group) {
      const def = groupsDef().find((item) => item.name === group)
      if (!def || !pinnable(def.type)) state.nodes_error = '不能改选'
      else if (!state.kernel_running) state.nodes_error = '内核没有运行'
      else {
        state.nodes_error = null
        fixed.delete(group)
        // The group picks again: the fastest tested member, else its default choice.
        const tested = def.proxies.filter((name) => typeof delays.get(name) === 'number')
        const fastest = tested.sort((a, b) => (delays.get(a) as number) - (delays.get(b) as number))[0]
        autoNow.set(group, (def.type === 'url-test' ? fastest ?? def.proxies[1] : undefined) ?? def.proxies[0] ?? '')
      }
      return done(60)
    },
    async testGroup(group) {
      const def = groupsDef().find((item) => item.name === group)
      if (!state.kernel_running) state.nodes_error = '内核没有运行'
      else {
        state.nodes_error = null
        await simulateTestAll(def?.proxies ?? [], 25)
      }
      return done(0)
    },
    async testAll() {
      if (!state.kernel_running) {
        state.nodes_error = '内核没有运行'
        return done(0)
      }
      state.nodes_error = null
      await simulateTestAll()
      return done(0)
    },
    async testNode(node) {
      if (!state.kernel_running) state.nodes_error = '内核没有运行'
      else await probe([node])
      return done(0)
    },
    async onNodeTest(handler) {
      nodeTestListeners.add(handler)
      return () => nodeTestListeners.delete(handler)
    },

    async closeConnection(id) {
      connections = id ? connections.filter((row) => row.id !== id) : []
      return done(60)
    },
    async closeConnections(ids) {
      if (!state.kernel_running) {
        state.notice = '内核没有运行'
        return done(0)
      }
      const targets = ids ? new Set(ids) : null
      connections = targets ? connections.filter((row) => !targets.has(row.id)) : []
      state.notice = null
      return done(60)
    },
    async dnsQuery(name, qtype) {
      const result: DnsQueryResult = { name: name.trim(), qtype, status: null, answers: [], elapsed_ms: 0, error: null }
      if (!isValidDnsName(name)) return { ...result, error: '域名格式无效' }
      if (!DNS_QUERY_TYPES.includes(qtype)) return { ...result, error: '不支持的记录类型' }
      await wait(80)
      if (!state.kernel_running) return { ...result, error: '内核没有运行' }
      const host = name.trim().replace(/\.$/, '').toLowerCase()
      if (host.endsWith('.invalid')) return { ...result, name: host, status: 3, elapsed_ms: 31, error: '没有找到记录（NXDOMAIN）' }
      const answers = DEMO_DNS_ANSWERS[qtype] ?? []
      return {
        ...result,
        name: host,
        status: 0,
        answers: answers.map((answer) => ({ ...answer })),
        elapsed_ms: 24,
        error: answers.length ? null : `没有找到 ${qtype} 记录`,
      }
    },
    async rules() {
      await wait(200)
      return rulesSnapshot()
    },
    async setRuleDisabled(key, disabled) {
      await wait(120)
      if (!state.kernel_running) throw new Error('内核没有运行')
      if (!ruleKeyList.includes(key)) throw new Error('没有这条规则')
      if (disabled) disabledRules.add(key)
      else disabledRules.delete(key)
      return rulesSnapshot()
    },
    async providers() {
      await wait(200)
      if (!state.kernel_running) return { providers: [], error: '内核没有运行' }
      return { providers: providerRows.map((row) => ({ ...row })), error: null }
    },
    async providerAction(kind, name, action) {
      await wait(900)
      const row = providerRows.find((item) => item.kind === kind && item.name === name)
      if (row && action === 'update') row.updated_at = new Date().toISOString()
      log('info', `${action === 'update' ? '更新' : '健康检查'} ${name} 完成`)
    },
    async upgradeGeo(key) {
      await wait(400)
      const now = Date.now()
      const defaultSizes: Record<string, number> = {
        geoip: 11_534_336,
        geosite: 5_976_883,
        mmdb: 9_123_456,
        asn: 8_421_376,
      }
      const keys = key ? [key] : ['geoip', 'geosite', 'mmdb', 'asn']
      for (const k of keys) {
        if (geoStore[k]) {
          geoStore[k] = { exists: true, size: defaultSizes[k] ?? 4_194_304, modified_ms: now }
        }
      }
      log('info', key ? `GEO 数据库 (${key}) 已更新` : 'GEO 数据库已更新')
      return [
        { key: 'geoip', label: 'GeoIP', file: 'GeoIP.dat', ...geoStore.geoip },
        { key: 'geosite', label: 'GeoSite', file: 'GeoSite.dat', ...geoStore.geosite },
        { key: 'mmdb', label: 'MMDB', file: 'Country.mmdb', ...geoStore.mmdb },
        { key: 'asn', label: 'ASN', file: 'ASN.mmdb', ...geoStore.asn },
      ]
    },
    async openUwpTool() {
      await wait(60)
      log('info', '已打开 UWP 回环豁免工具')
    },
    async providerDetail(kind, name, query) {
      await wait(200)
      const row = providerRows.find((item) => item.kind === kind && item.name === name)
      if (!row) throw new Error('没有这个资源')
      if (kind === 'proxy') {
        const proxies = names.slice(0, row.count).map((node, index) => ({
          name: node,
          node_type: types.get(node) ?? 'ss',
          tags: DEMO_TAGS[types.get(node) ?? ''] ?? [],
          delay_ms: state.kernel_running && index % 7 !== 3 ? 60 + index * 23 : null,
          alive: state.kernel_running ? index % 7 !== 3 : null,
        }))
        return { kind, name, proxies, rules: [], total: proxies.length, notice: null, source: null }
      }
      // Mirrors the backend: MRS decodes to domains, previews stop at 5000 rows, a query searches all.
      const all = row.vehicle === 'Inline'
        ? ['DOMAIN-SUFFIX,local', 'DOMAIN-SUFFIX,lan', 'IP-CIDR,10.0.0.0/8', 'IP-CIDR,172.16.0.0/12', 'IP-CIDR,192.168.0.0/16', 'IP-CIDR,127.0.0.0/8']
        : row.format === 'MrsRule'
          ? Array.from({ length: row.count }, (_, index) => `${index % 3 ? '+.' : ''}site${String(index).padStart(6, '0')}.cn`)
          : Array.from({ length: row.count }, (_, index) => `91.108.${4 + index}.0/22`)
      const needle = (query ?? '').trim().toLowerCase()
      const matched = needle ? all.filter((rule) => rule.toLowerCase().includes(needle)) : all
      const limit = 5000
      const notice = matched.length <= limit ? null
        : needle ? `匹配 ${matched.length} 条，只列出前 ${limit} 条`
        : `共 ${matched.length} 条，只列出前 ${limit} 条；搜索会查找全部规则`
      const source = row.vehicle === 'Inline' ? 'inline' : row.format === 'MrsRule' ? 'https://example.com/cn.mrs' : 'https://example.com/telegram.yaml'
      return { kind, name, proxies: [], rules: matched.slice(0, limit), total: matched.length, notice, source }
    },
    async geoFiles() {
      return [
        { key: 'geoip', label: 'GeoIP', file: 'GeoIP.dat', ...geoStore.geoip },
        { key: 'geosite', label: 'GeoSite', file: 'GeoSite.dat', ...geoStore.geosite },
        { key: 'mmdb', label: 'MMDB', file: 'Country.mmdb', ...geoStore.mmdb },
        { key: 'asn', label: 'ASN', file: 'ASN.mmdb', ...geoStore.asn },
      ]
    },
    async flushCache(which) {
      log('info', which === 'fakeip' ? 'FakeIP 缓存已清除' : 'DNS 缓存已清除')
      return done(100)
    },
    async clearLogs() {
      state.logs = []
      return done(0)
    },
    async exportLogs() {
      await wait(80)
      const stamp = new Date().toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15)
      const directory =
        state.platform === 'android'
          ? '/storage/emulated/0/Android/data/app.billow/files/Documents'
          : 'C:\\Users\\demo\\Downloads'
      return `${directory}/billow-logs-${stamp}.log`
    },
    async clearNotice() {
      state.notice = null
      return done(0)
    },
    async saveSettings(settings) {
      state.settings = JSON.parse(JSON.stringify({ ...emptyKernelSettings(), ...settings }))
      return done(300)
    },
    async syncTray() {},

    async onChange(handler) {
      listeners.add(handler)
      return () => listeners.delete(handler)
    },
  }
}
