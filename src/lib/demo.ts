import type { Backend, NodeTestEvent } from './backend'
import { locale, resolveLanguage, translate } from './i18n'
import { ruleKeys } from './rule-keys'
import {
  DNS_QUERY_TYPES,
  emptyConfigValues,
  emptyKernelSettings,
  isCidrEntry,
  isPortEntry,
  isValidDnsName,
  emptySnapshot,
  localDateKey,
  shiftDateKey,
  type AppInfo,
  type KernelSettings,
  type ConfigOverview,
  type ConnectionRow,
  type DnsQueryResult,
  type ExitIpInfo,
  type HotkeyAction,
  type HotkeySettings,
  type KernelStatus,
  type LanguagePreference,
  type Locale,
  type LogLine,
  type NodeGroup,
  type ProviderRow,
  type ProfileItem,
  type RuleRow,
  type Snapshot,
  type ThemePreference,
  type TrafficHistoryEntry,
  type TrafficHistoryView,
  type TrafficRange,
  type UwpApp,
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

function nodeNames(regions: readonly string[] = REGIONS): string[] {
  const names: string[] = []
  regions.forEach((region, index) => {
    const count = index < 3 ? 3 : 2
    for (let i = 1; i <= count; i += 1) names.push(`${region} ${String(i).padStart(2, '0')}`)
  })
  return names
}

interface DemoOptions {
  profiles?: boolean
  platform?: 'desktop' | 'android'
  /** Desktop OS reported as `AppInfo.platform` (`windows` / `macos` / `linux`); defaults to `demo`. */
  os?: string
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
  /** OS language the demo reports: `system` resolves to this locale (R42). */
  systemLocale?: Locale
  /** Latin-only demo data (`?demo=latin`) for the English whole-UI check (T8). */
  latin?: boolean
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

/** Latin-only demo data for `?demo=latin` (T8): names, regions and group labels. */
const LATIN_EXACT: Record<string, string> = {
  设置: 'Settings',
  系统界面: 'System UI',
  微信: 'WeChat',
  支付宝: 'Alipay',
  哔哩哔哩: 'Bilibili',
  招商银行: 'China Merchants Bank',
  星河云: 'Galaxy Cloud',
  备用机场: 'Backup Provider',
  新配置: 'New Profile',
  'Google Play 服务': 'Google Play Services',
  本地配置: 'Local Profile',
  远程配置: 'Remote Profile',
  自建节点: 'Self-hosted',
  测试订阅: 'Test Subscription',
}
const LATIN_PARTS: Record<string, string> = {
  节点选择: 'Node Select',
  自动选择: 'Auto Select',
  故障转移: 'Fallback',
  负载均衡: 'Load Balance',
  流媒体: 'Streaming',
  国内网站: 'China Sites',
  漏网之鱼: 'Final',
  策略组: 'Policy Group',
  香港: 'Hong Kong',
  日本: 'Japan',
  新加坡: 'Singapore',
  美国: 'US',
  台湾: 'Taiwan',
  韩国: 'South Korea',
  德国: 'Germany',
  英国: 'UK',
}

function latinText(value: string): string {
  if (LATIN_EXACT[value]) return LATIN_EXACT[value]
  let out = value
  for (const [zh, en] of Object.entries(LATIN_PARTS)) out = out.split(zh).join(en)
  return out
}

/** Rewrite every string in a demo result so the Latin demo contains no Chinese names. */
function latinize<T>(value: T): T {
  if (typeof value === 'string') return latinText(value) as T
  if (Array.isArray(value)) return value.map((item) => latinize(item)) as T
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) out[key] = latinize(item)
    return out as T
  }
  return value
}

/** Turn a name the UI received from the Latin demo back into the internal Chinese one. */
function delatinName(value: string): string {
  const exact = Object.entries(LATIN_EXACT).find(([, en]) => en === value)
  if (exact) return exact[0]
  for (const [zh, en] of Object.entries(LATIN_PARTS)) {
    if (value === en) return zh
    if (value.startsWith(`${en} `)) return zh + value.slice(en.length)
  }
  return value
}

export function createDemoBackend(options: DemoOptions = {}): Backend {
  const demoUwpApps: UwpApp[] = [
    {
      name: 'Microsoft.WindowsStore',
      display_name: 'Microsoft Store',
      family_name: 'Microsoft.WindowsStore_8wekyb3d8bbwe',
      sid: 'S-1-15-2-1609473798-1231923017-684268153-4268514328',
      exempted: true,
    },
    {
      name: 'Microsoft.WindowsTerminal',
      display_name: 'Windows Terminal',
      family_name: 'Microsoft.WindowsTerminal_8wekyb3d8bbwe',
      sid: 'S-1-15-2-2381923017-684268153-4268514328',
      exempted: false,
    },
    {
      name: 'Microsoft.XboxApp',
      display_name: 'Xbox',
      family_name: 'Microsoft.XboxApp_8wekyb3d8bbwe',
      sid: 'S-1-15-2-3381923017-684268153-4268514328',
      exempted: false,
    },
    {
      name: 'Microsoft.Todos',
      display_name: 'Microsoft To Do',
      family_name: 'Microsoft.Todos_8wekyb3d8bbwe',
      sid: 'S-1-15-2-4381923017-684268153-4268514328',
      exempted: false,
    },
  ]
  const latinRegions = REGIONS.map((region) => LATIN_PARTS[region]!)
  const baseNames = options.latin
    ? nodeNames(latinRegions)
    : options.longNames
      ? [...DEMO_LONG_NAMES, ...nodeNames()]
      : nodeNames()
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
  let language: LanguagePreference = 'system'
  /** WebDAV account, the last connection test and the backups in the cloud (R38). */
  let webdav = { url: '', username: '', password: '' }
  let webdavVerified = false
  let remoteBackups: { name: string; device: string; modified: string | null; size: number | null; text: string }[] = []
  /** Pretend the OS reports this language; tests pin the default to Chinese. */
  const systemLocale: Locale = options.systemLocale ?? 'zh-CN'
  let kernel: KernelStatus = { channel: 'stable', failure: null, ready: true, version: 'v1.19.17' }
  let app: AppInfo = {
    version: '0.2.0',
    platform: options.platform === 'android' ? 'android' : (options.os ?? 'demo'),
    // Android has no autostart or tray; the real shell reports null there.
    autostart: options.platform === 'android' ? null : false,
    close_to_tray: true,
    silent_start: false,
    release_ui_on_close: false,
    auto_exit_ip: false,
    traffic_history: false,
    data_dir: null,
  }
  /** Desktop global shortcuts (R39): nothing is bound until the user records one. */
  const hotkeys = new Map<HotkeyAction, string>()
  const HOTKEY_LABELS: Record<HotkeyAction, string> = {
    connect: '连接 / 断开',
    proxy: '系统代理',
    tun: 'TUN 模式',
    'mode-rule': '规则',
    'mode-global': '全局',
    'mode-direct': '直连',
    window: '显示 / 隐藏主窗口',
  }
  function hotkeySettings(): HotkeySettings {
    const available = options.platform !== 'android'
    return {
      available,
      reason: available ? null : '此系统不支持全局快捷键',
      platform: app.platform,
      bindings: [...hotkeys].map(([action, combo]) => ({ action, combo, active: available, error: null })),
    }
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
  /**
   * Traffic history (R43) in the demo: the same date × profile × group × node
   * buckets as Rust, fed from the simulated connections on every poll while the
   * switch is on. Off until the user turns it on.
   */
  let trafficRecording = false
  // Set when recording is switched on or the view is cleared: the next poll only
  // adopts the open connections so bytes from before add nothing.
  let trafficSeed = false
  const trafficDays = new Map<string, Map<string, TrafficHistoryEntry>>()
  const trafficBaselines = new Map<string, { upload: number; download: number }>()
  const DIRECT_POLICIES = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS'])

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
    const sniffer = out.sniffer as Record<string, unknown> | undefined
    if (sniffer?.enable === true) {
      const sniff = { ...(sniffer.sniff as Record<string, Record<string, unknown>> | undefined) }
      const ports: [string, string[] | null][] = [
        ['HTTP', s.sniff_ports.http],
        ['TLS', s.sniff_ports.tls],
        ['QUIC', s.sniff_ports.quic],
      ]
      for (const [protocol, items] of ports) {
        if (items) sniff[protocol] = { ...sniff[protocol], ports: items.map((item) => (/^\d+$/.test(item) ? Number(item) : item)) }
      }
      sniffer.sniff = sniff
      if (s.sniff_force_domain) sniffer['force-domain'] = s.sniff_force_domain
      if (s.sniff_skip_domain) sniffer['skip-domain'] = s.sniff_skip_domain
      if (s.sniff_override_destination != null) sniffer['override-destination'] = s.sniff_override_destination
    }
    if (state.platform !== 'android') {
      const explicit: [string, number | null][] = [
        ['socks-port', s.socks_port],
        ['port', s.http_port],
        ['redir-port', s.redir_port],
        ['tproxy-port', s.tproxy_port],
      ]
      for (const [name, port] of explicit) if (port != null) out[name] = port
      if (s.interface_name === '') delete out['interface-name']
      else if (s.interface_name) out['interface-name'] = s.interface_name
      if (s.routing_mark === 0) delete out['routing-mark']
      else if (s.routing_mark != null) out['routing-mark'] = s.routing_mark
    }
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
        ...(s.tun.route_address ? { 'route-address': s.tun.route_address } : {}),
        ...(s.tun.route_exclude_address ? { 'route-exclude-address': s.tun.route_exclude_address } : {}),
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
    state.logs.push({ level, message, time_ms: Date.now(), hint: null, hint_kind: null })
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
            tags: isChained ? [...baseTags, 'chained'] : baseTags,
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
      trafficBaselines.clear()
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
    recordTrafficHistory()
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
      ...emptyConfigValues(),
      mixed_port: 7890,
      allow_lan: false,
      ipv6: false,
      log_level: 'info',
      unified_delay: true,
      tcp_concurrent: true,
      find_process_mode: 'strict',
      sniffer: true,
      sniff_http_ports: ['80'],
      sniff_tls_ports: ['443'],
      sniff_quic_ports: ['443'],
    }
    state.mixed_port = state.settings.mixed_port ?? (state.active_id ? 7890 : null)
    const result = structuredClone(state)
    return options.latin ? latinize(result) : result
  }

  /** Fold one simulated sample into today's buckets, with the same deltas as Rust. */
  function recordTrafficHistory() {
    if (!trafficRecording || !state.connected) return
    // The first poll after the switch went on only adopts the open connections,
    // so bytes from before recording (or from while it was off) add nothing.
    const seeding = trafficSeed
    trafficSeed = false
    const profile = state.profiles.find((item) => item.id === state.active_id)?.name ?? ''
    const date = localDateKey()
    const seen = new Set<string>()
    for (const row of connections) {
      const node = (row.chains[0] ?? '').trim()
      const group = (row.chains[row.chains.length - 1] ?? '').trim()
      if (!node && !group) continue
      seen.add(row.id)
      const last = seeding ? undefined : trafficBaselines.get(row.id)
      trafficBaselines.set(row.id, { upload: row.upload, download: row.download })
      if (seeding) continue
      let upload = 0
      let download = 0
      if (!last) {
        // A connection opened after the switch counts from its own zero.
        upload = row.upload
        download = row.download
      } else {
        upload = Math.max(0, row.upload - last.upload)
        download = Math.max(0, row.download - last.download)
      }
      if (!upload && !download) continue
      const direct = DIRECT_POLICIES.has(node.toUpperCase()) || DIRECT_POLICIES.has(group.toUpperCase())
      const rowGroup = direct ? '' : group || node
      const rowNode = direct ? '' : node
      const key = `${profile}\u001f${rowGroup}\u001f${rowNode}\u001f${direct ? 1 : 0}`
      let day = trafficDays.get(date)
      if (!day) {
        day = new Map()
        trafficDays.set(date, day)
      }
      const entry = day.get(key) ?? {
        date,
        profile,
        group: rowGroup,
        node: rowNode,
        direct,
        upload: 0,
        download: 0,
      }
      entry.upload += upload
      entry.download += download
      day.set(key, entry)
    }
    for (const id of [...trafficBaselines.keys()]) {
      if (!seen.has(id)) trafficBaselines.delete(id)
    }
  }

  const TRAFFIC_RETENTION_DAYS = 90

  function trafficBounds(range: TrafficRange, from?: string | null, to?: string | null) {
    const today = localDateKey()
    const oldest = shiftDateKey(today, -(TRAFFIC_RETENTION_DAYS - 1))
    const isDate = (value: string | null | undefined): value is string =>
      Boolean(value && /^\d{4}-\d{2}-\d{2}$/.test(value))
    const clamp = (value: string) => (value < oldest ? oldest : value > today ? today : value)
    if (range === '7d') return { today, from: shiftDateKey(today, -6), to: today }
    if (range === '30d') return { today, from: shiftDateKey(today, -29), to: today }
    if (range === 'custom') {
      let start = isDate(from) ? clamp(from) : today
      let end = isDate(to) ? clamp(to) : today
      if (start > end) [start, end] = [end, start]
      return { today, from: start, to: end }
    }
    return { today, from: today, to: today }
  }

  function trafficHistoryView(
    range: TrafficRange,
    from?: string | null,
    to?: string | null,
  ): TrafficHistoryView {
    const bounds = trafficBounds(range, from, to)
    const entries: TrafficHistoryEntry[] = []
    for (const [date, day] of trafficDays) {
      if (date < bounds.from || date > bounds.to) continue
      for (const entry of day.values()) entries.push({ ...entry })
    }
    entries.sort(
      (left, right) =>
        right.date.localeCompare(left.date) ||
        right.upload + right.download - (left.upload + left.download),
    )
    return {
      enabled: trafficRecording,
      retention_days: TRAFFIC_RETENTION_DAYS,
      today: bounds.today,
      from: bounds.from,
      to: bounds.to,
      entries,
    }
  }

  const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
  const done = async (ms = 120) => {
    await wait(ms)
    const snap = snapshot()
    listeners.forEach((handler) => handler(snap))
    return snap
  }
  const profile = (id: string) => state.profiles.find((item) => item.id === id)

  // ── 备份与恢复 (R38): the same versioned shape and refusal reasons as Rust ──
  const UNKNOWN_BACKUP = '无法识别这个备份文件，请选择 Billow 导出的备份文件'
  const DAMAGED_BACKUP = '备份文件已损坏，无法恢复'

  function backupText(): string {
    return JSON.stringify(
      {
        format: 'billow-backup',
        version: 1,
        app_version: app.version,
        platform: state.platform,
        device: 'demo',
        created_ms: Date.now(),
        profiles: {
          next_id: state.profiles.length + 1,
          active_id: state.active_id,
          profiles: state.profiles.map((item) => ({
            id: item.id,
            name: item.name,
            kind: item.kind,
            source: item.source,
            user_agent: item.user_agent,
            content: '',
            override_text: item.override_text,
            applied_override: '',
            selected: Object.fromEntries(selections),
            fixed: Object.fromEntries(fixed),
            interval_hours: item.interval_hours,
            age_key: '',
            updated_ms: item.updated_ms,
          })),
          settings: state.settings,
          tun_wanted: state.tun_wanted,
          excluded_packages: state.excluded,
          included_packages: state.included,
          app_mode: state.app_mode,
          chosen_mode: state.mode,
        },
        shell: {
          theme,
          close_to_tray: app.close_to_tray,
          silent_start: app.silent_start,
          language,
        },
      },
      null,
      2,
    )
  }

  function newerVersion(candidate: string, current: string): boolean {
    const parse = (raw: string) =>
      raw.trim().replace(/^v/, '').split(/[.-]/).map((part) => Number.parseInt(part, 10) || 0)
    const left = parse(candidate)
    const right = parse(current)
    for (let index = 0; index < 3; index += 1) {
      const a = left[index] ?? 0
      const b = right[index] ?? 0
      if (a !== b) return a > b
    }
    return false
  }

  function readBackup(text: string) {
    let raw: unknown
    try {
      raw = JSON.parse(text)
    } catch {
      throw new Error(UNKNOWN_BACKUP)
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error(UNKNOWN_BACKUP)
    const file = raw as Record<string, unknown>
    if (file.format !== 'billow-backup') throw new Error(UNKNOWN_BACKUP)
    const version = typeof file.version === 'number' ? file.version : 0
    const versionText = typeof file.app_version === 'string' ? file.app_version : String(version)
    if (version > 1 || newerVersion(versionText, app.version)) {
      throw new Error(`备份来自更新的版本（${versionText}），请先更新 Billow`)
    }
    const part = file.profiles
    if (!part || typeof part !== 'object' || Array.isArray(part)) throw new Error(DAMAGED_BACKUP)
    const profiles = part as Record<string, unknown>
    if (!Array.isArray(profiles.profiles) || !profiles.settings || typeof profiles.settings !== 'object') {
      throw new Error(DAMAGED_BACKUP)
    }
    const shell = file.shell && typeof file.shell === 'object' ? (file.shell as Record<string, unknown>) : {}
    return { profiles, shell }
  }

  function applyBackup(profiles: Record<string, unknown>, shell: Record<string, unknown>) {
    const list = (profiles.profiles as unknown[]).map((raw, index): ProfileItem => {
      const entry = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}
      return {
        id: typeof entry.id === 'string' && entry.id ? entry.id : `p${index + 1}`,
        name: typeof entry.name === 'string' && entry.name ? entry.name : '配置',
        kind: entry.kind === 'subscription' ? 'subscription' : 'local',
        source: typeof entry.source === 'string' ? entry.source : '',
        user_agent: typeof entry.user_agent === 'string' ? entry.user_agent : '',
        current: false,
        failure: null,
        override_text: typeof entry.override_text === 'string' ? entry.override_text : '',
        override_error: null,
        used: null,
        total: null,
        expire: null,
        last_success_ms: null,
        interval_hours: typeof entry.interval_hours === 'number' ? entry.interval_hours : 0,
        updated_ms: typeof entry.updated_ms === 'number' ? entry.updated_ms : null,
        proxy_count: 0,
        age_recipients: [],
      }
    })
    const active = typeof profiles.active_id === 'string' ? profiles.active_id : null
    state.profiles = list
    state.active_id = list.some((item) => item.id === active) ? active : null
    state.settings = { ...emptyKernelSettings(), ...(profiles.settings as KernelSettings) }
    state.tun_wanted = Boolean(profiles.tun_wanted)
    state.excluded = Array.isArray(profiles.excluded_packages)
      ? profiles.excluded_packages.filter((item): item is string => typeof item === 'string')
      : []
    state.included = Array.isArray(profiles.included_packages)
      ? profiles.included_packages.filter((item): item is string => typeof item === 'string')
      : []
    state.app_mode = profiles.app_mode === 'include' ? 'include' : 'exclude'
    const mode = profiles.chosen_mode
    if (mode === 'rule' || mode === 'global' || mode === 'direct') state.mode = mode
    // App settings travel too; platform-only ones (WebDAV credentials, window
    // size, the current page) are not in the file at all.
    if (shell.theme === 'light' || shell.theme === 'dark' || shell.theme === 'system') theme = shell.theme
    if (shell.language === 'en' || shell.language === 'zh-CN') language = shell.language
    if (typeof shell.close_to_tray === 'boolean' || typeof shell.silent_start === 'boolean') {
      app = {
        ...app,
        close_to_tray: typeof shell.close_to_tray === 'boolean' ? shell.close_to_tray : app.close_to_tray,
        silent_start: typeof shell.silent_start === 'boolean' ? shell.silent_start : app.silent_start,
      }
    }
  }

  function backupStamp(): string {
    return new Date().toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15)
  }

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
      return { theme, last_entry: entry, language, locale: resolveLanguage(language, systemLocale) }
    },
    async setTheme(next) {
      theme = next
    },
    async setLanguage(next) {
      language = next
      return { theme, last_entry: entry, language, locale: resolveLanguage(language, systemLocale) }
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
    async setAppBehavior(closeToTray, silentStart, releaseUiOnClose) {
      app = {
        ...app,
        close_to_tray: closeToTray,
        silent_start: silentStart,
        release_ui_on_close: releaseUiOnClose,
      }
      return app
    },
    /** Pretends the lookup went through the mixed port and ip.sb (R40). */
    async exitIp() {
      if (!state.connected) throw new Error(translate(locale.value, 'exitIp.offline'))
      await wait(320)
      const node = catalog().find((group) => group.name === '节点选择')?.now ?? ''
      const region = node.split(' ')[0] ?? ''
      const result: ExitIpInfo = {
        ip: '203.0.113.42',
        region: latinText(region || '香港'),
        isp: 'AS15169 Google LLC',
        service: 'ip.sb',
        time_ms: Date.now(),
      }
      return result
    },
    async setExitIpAuto(enabled) {
      app = { ...app, auto_exit_ip: enabled }
      return app
    },
    async trafficHistory(range, from, to) {
      const view = trafficHistoryView(range, from, to)
      return options.latin ? latinize(view) : view
    },
    async setTrafficRecording(enabled) {
      if (trafficRecording !== enabled) {
        trafficRecording = enabled
        trafficBaselines.clear()
        // Enabling adopts the open counters on the next poll, so pre-enable
        // traffic is not added and re-enabling never re-counts recorded bytes.
        trafficSeed = enabled
      }
      app = { ...app, traffic_history: enabled }
      return app
    },
    async clearTrafficHistory() {
      trafficDays.clear()
      trafficBaselines.clear()
      // A running poll would otherwise count every open connection's totals
      // again; the next poll only seeds the id table.
      trafficSeed = trafficRecording
    },
    async hotkeySettings() {
      return hotkeySettings()
    },
    async setHotkey(action, combo) {
      if (!hotkeySettings().available) throw new Error('此系统不支持全局快捷键')
      if (!combo) {
        hotkeys.delete(action)
        return hotkeySettings()
      }
      const clash = [...hotkeys].find(([other, bound]) => other !== action && bound === combo)
      if (clash) {
        throw new Error(`组合键 ${combo} 已绑定给「${HOTKEY_LABELS[clash[0]]}」`)
      }
      hotkeys.set(action, combo)
      return hotkeySettings()
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
      const text = `${head}${override ? `# ── 覆写 ──\n${override}\n` : ''}${base.replace(/^(mixed-port|mode):.*\n/gm, '')}`
      return options.latin ? latinText(text) : text
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
      if (options.latin) {
        group = delatinName(group)
        node = delatinName(node)
      }
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
      if (options.latin) group = delatinName(group)
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
      if (options.latin) group = delatinName(group)
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
      if (options.latin) node = delatinName(node)
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
      const result = rulesSnapshot()
      return options.latin ? latinize(result) : result
    },
    async setRuleDisabled(key, disabled) {
      await wait(120)
      if (!state.kernel_running) throw new Error('内核没有运行')
      if (!ruleKeyList.includes(key)) throw new Error('没有这条规则')
      if (disabled) disabledRules.add(key)
      else disabledRules.delete(key)
      const result = rulesSnapshot()
      return options.latin ? latinize(result) : result
    },
    async providers() {
      await wait(200)
      if (!state.kernel_running) return { providers: [], error: '内核没有运行' }
      const result = { providers: providerRows.map((row) => ({ ...row })), error: null }
      return options.latin ? latinize(result) : result
    },
    async providerAction(kind, name, action) {
      await wait(900)
      if (options.latin) name = delatinName(name)
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
    async listUwpApps() {
      await wait(80)
      return demoUwpApps.map((item) => ({ ...item }))
    },
    async saveUwpExemptions(familyNames) {
      await wait(120)
      const desired = new Set(familyNames.map((n) => n.toLowerCase()))
      for (const app of demoUwpApps) {
        app.exempted = desired.has(app.family_name.toLowerCase())
      }
      demoUwpApps.sort((a, b) => Number(b.exempted) - Number(a.exempted) || a.display_name.localeCompare(b.display_name))
      log('info', `已保存 UWP 回环豁免：${demoUwpApps.filter((a) => a.exempted).length} 个应用`)
      return demoUwpApps.map((item) => ({ ...item }))
    },
    async providerDetail(kind, name, query) {
      await wait(200)
      if (options.latin) name = delatinName(name)
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
        const result = { kind, name, proxies, rules: [], total: proxies.length, notice: null, source: null }
        return options.latin ? latinize(result) : result
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
      const result = { kind, name, proxies: [], rules: matched.slice(0, limit), total: matched.length, notice, source }
      return options.latin ? latinize(result) : result
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
    async restartKernel() {
      if (!state.kernel_running || !(state.system_proxy || state.tun || state.vpn)) throw new Error('请先连接，再重启内核')
      await wait(600)
      // Billow respawns the process: uptime restarts, takeover and mode stay as they were.
      startedAt = Date.now()
      log('info', '内核已重启')
      return done(0)
    },
    async gcKernel() {
      const level = state.settings.log_level ?? 'info'
      if (!state.kernel_running) throw new Error('内核没有运行')
      if (level !== 'debug') throw new Error('内存没有回收：日志级别为 debug 时才可用，请稍后重试')
      await wait(80)
      log('debug', '已手动触发内存回收')
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
    async exportBackup() {
      await wait(120)
      const directory =
        state.platform === 'android'
          ? '/storage/emulated/0/Android/data/app.billow/files/Documents'
          : 'C:\\Users\\demo\\Downloads'
      return `${directory}/billow-backup-${backupStamp()}.json`
    },
    async restoreBackup(text) {
      await wait(150)
      const { profiles, shell } = readBackup(text)
      applyBackup(profiles, shell)
      log('info', `已从备份恢复 ${state.profiles.length} 份配置`)
      return done(0)
    },
    async webdavSettings() {
      return { ...webdav, available: webdavVerified }
    },
    async setWebdav(url, username, password) {
      const changed = webdav.url !== url || webdav.username !== username || webdav.password !== password
      webdav = { url, username, password }
      // Saving the same account again keeps a successful test; a change drops it.
      if (changed) webdavVerified = false
      return { ...webdav, available: webdavVerified }
    },
    async testWebdav() {
      await wait(150)
      if (!webdav.url.trim()) return { available: false, error: '请填写 WebDAV 服务器地址' }
      if (!/^https?:\/\//i.test(webdav.url.trim())) {
        return { available: false, error: 'WebDAV 地址需要以 http:// 或 https:// 开头' }
      }
      if (webdav.password === 'bad') {
        webdavVerified = false
        return { available: false, error: 'WebDAV 认证失败（401）' }
      }
      webdavVerified = true
      return { available: true, error: null }
    },
    async uploadBackup() {
      if (!webdavVerified) throw new Error('请先测试连接，WebDAV 还不可用')
      await wait(200)
      const text = backupText()
      const name = `billow-backup-demo-${backupStamp()}.json`
      remoteBackups = [
        { name, device: 'demo', modified: new Date().toUTCString(), size: text.length, text },
        ...remoteBackups,
      ]
      return name
    },
    async listRemoteBackups() {
      await wait(120)
      return remoteBackups.map((item) => ({
        name: item.name,
        device: item.device,
        modified: item.modified,
        size: item.size,
      }))
    },
    async restoreRemoteBackup(name) {
      await wait(150)
      const item = remoteBackups.find((entry) => entry.name === name)
      if (!item) throw new Error('云端没有这份备份，请刷新列表')
      const { profiles, shell } = readBackup(item.text)
      applyBackup(profiles, shell)
      log('info', `已从云端备份恢复 ${state.profiles.length} 份配置`)
      return done(0)
    },
    async saveSettings(settings) {
      const refused = demoSettingsError(settings, settings.mixed_port || state.config_values.mixed_port || 7890)
      if (refused) {
        state.input_error = refused
        return done(120)
      }
      state.input_error = null
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

/** Mirror of the backend's KernelSettings::validate: refuse and name the first bad entry. */
function demoSettingsError(s: KernelSettings, mixed: number): string | null {
  const routes: [string, string[] | null | undefined][] = [
    ['只让这些地址走 TUN', s.tun?.route_address],
    ['不走 TUN 的地址', s.tun?.route_exclude_address],
  ]
  for (const [label, items] of routes) {
    const bad = items?.find((item) => !isCidrEntry(item))
    if (bad) return `${label}中的「${bad}」不是有效的 IP 或网段，例如 192.168.0.0/16`
  }
  const sniff: [string, string[] | null | undefined][] = [
    ['HTTP 嗅探端口', s.sniff_ports?.http],
    ['TLS 嗅探端口', s.sniff_ports?.tls],
    ['QUIC 嗅探端口', s.sniff_ports?.quic],
  ]
  for (const [label, items] of sniff) {
    const bad = items?.find((item) => !isPortEntry(item))
    if (bad) return `${label}中的「${bad.trim()}」无效，请填 1–65535 的端口或“起-止”范围`
  }
  if (s.interface_name && /\s/.test(s.interface_name.trim())) return '出口网卡名称不能包含空格'
  const taken: [string, number][] = mixed > 0 ? [['混合端口', mixed]] : []
  const ports: [string, number | null | undefined][] = [
    ['SOCKS 端口', s.socks_port],
    ['HTTP 端口', s.http_port],
    ['redir 端口', s.redir_port],
    ['tproxy 端口', s.tproxy_port],
  ]
  for (const [label, port] of ports) {
    if (!port) continue
    const other = taken.find(([, used]) => used === port)
    if (other) return `${label} ${port} 与${other[0]}重复，请换一个端口`
    taken.push([label, port])
  }
  return null
}
