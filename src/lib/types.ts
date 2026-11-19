export type Mode = 'rule' | 'global' | 'direct'
export type ThemePreference = 'system' | 'light' | 'dark'
/** Interface language: Simplified Chinese and English only (R42, R46). */
export type Locale = 'zh-CN' | 'en'
/** `system` follows the operating system language. */
export type LanguagePreference = 'system' | Locale
export type KernelChannel = 'stable' | 'preview'
export type LogLevel = 'debug' | 'info' | 'warning' | 'error'
export type Platform = 'desktop' | 'android'

export interface ProfileItem {
  id: string
  name: string
  kind: 'subscription' | 'local'
  source: string
  user_agent: string
  current: boolean
  failure: string | null
  override_text: string
  override_error: string | null
  used: number | null
  total: number | null
  expire: number | null
  last_success_ms: number | null
  interval_hours: number
  updated_ms: number | null
  proxy_count: number
  /** Public keys (`age1…`) of the age identities set for this subscription; never the secret. */
  age_recipients: string[]
}

export interface InstalledApp {
  name: string
  package_name: string
  /** Preinstalled system app; hidden from the access-control list by default. */
  system: boolean
}

/** Android access control: listed apps bypass the VPN, or only listed apps use it. */
export type AppMode = 'exclude' | 'include'

export interface NodeItem {
  name: string
  delay_ms: number | null
  failed: boolean
  selected: boolean
  node_type: string
  /** Capability tags from the config: UDP, Reality/TLS, transport, Vision, Mux, TFO, MPTCP, 链式. */
  tags: string[]
  /** Upstream transit proxy or group when `dialer-proxy` is configured. */
  dialer_proxy?: string | null
}

export interface NodeGroup {
  name: string
  kind: 'manual' | 'auto'
  now: string
  sort: string
  nodes: NodeItem[]
  group_type: string
  /** Config `proxy-groups[].icon`; only http(s) and image data survive normalization. */
  icon: string | null
  /** `url-test` / `fallback`: picking a node fixes it until 恢复自动 (R28). Normalized snapshots always set these three. */
  pinnable?: boolean
  /** Node fixed on a pinnable group; null while the group picks by itself. */
  fixed?: string | null
  /** Config `hidden: true`: left out of group lists, still part of chains (R29). */
  hidden?: boolean
}

export interface ConnectionRow {
  id: string
  host: string
  outbound: string
  network: string
  conn_type: string
  destination: string
  source: string
  process: string
  rule: string
  rule_payload: string
  chains: string[]
  upload: number
  download: number
  start: string
}

export interface ClosedConnectionRow extends ConnectionRow {
  closed_at_ms: number
}

export interface LogLine {
  level: LogLevel
  message: string
  time_ms: number
  /** Structured kernel hint, so views never decide by matching Chinese text (T8). */
  hint?: 'port' | 'tun' | null
  /** Which listener failed for a port hint. */
  hint_kind?: 'mixed' | 'http' | 'socks' | 'redir' | 'tproxy' | null
}

export interface RuleRow {
  kind: string
  payload: string
  proxy: string
  /** `/rules` `extra.hitCount`; null when the kernel does not report hits. */
  hit_count: number | null
  /** `/rules` `extra.lastHit`; null when the kernel does not report hits. */
  last_hit: string | null
  /** Stable toggle key; null for kernel-injected rules absent from the config. */
  key: string | null
  /** True while the rule is temporarily removed from the runtime config. */
  disabled: boolean
}

export type SystemProxyMode = 'manual' | 'pac'

export interface SystemProxySettings {
  host: string
  mode: SystemProxyMode
  pac_script: string
  bypass: string[]
}

export interface GeoUrls {
  geoip: string
  mmdb: string
  geosite: string
  asn: string
}

export interface DnsSettings {
  listen: string
  enhanced_mode: 'fake-ip' | 'redir-host' | 'normal'
  fake_ip_range: string
  /** `rule` (mihomo v1.19.x) reads the filter as rules ending in fake-ip / real-ip. */
  fake_ip_filter_mode: 'blacklist' | 'whitelist' | 'rule'
  fake_ip_filter: string[]
  ipv6: boolean
  prefer_h3: boolean
  cache_algorithm: 'lru' | 'arc'
  use_hosts: boolean
  use_system_hosts: boolean
  respect_rules: boolean
  direct_nameserver_follow_policy: boolean
  default_nameserver: string[]
  nameserver: string[]
  fallback: string[]
  proxy_server_nameserver: string[]
  direct_nameserver: string[]
  nameserver_policy: Record<string, string[]>
  hosts: Record<string, string[]>
}

export interface TunSettings {
  /** '' leaves the stack to the profile, then the kernel (mips since mihomo v1.19.32). */
  stack: '' | 'mips' | 'mixed' | 'system' | 'gvisor'
  auto_route: boolean
  auto_detect_interface: boolean
  strict_route: boolean
  dns_hijack: string[]
  mtu: number
  device: string
  /** `tun.route-address`; null follows the profile. Desktop only. */
  route_address: string[] | null
  /** `tun.route-exclude-address`; null follows the profile. Desktop only. */
  route_exclude_address: string[] | null
}

/** Per-protocol sniff ports (`443` or `8000-9000`); null keeps the sniffer block's own. */
export interface SniffPorts {
  http: string[] | null
  tls: string[] | null
  quic: string[] | null
}

export interface ProviderRow {
  name: string
  kind: 'proxy' | 'rule'
  vehicle: string
  behavior: string
  format: string
  count: number
  updated_at: string
  used: number | null
  total: number | null
  expire: number | null
}

export interface ProvidersResult {
  providers: ProviderRow[]
  error: string | null
}

export interface KernelSettings {
  auto_connect: boolean
  close_connections_on_switch: boolean
  subscription_user_agent: string
  mixed_port: number | null
  allow_lan: boolean | null
  ipv6: boolean | null
  log_level: string | null
  unified_delay: boolean | null
  tcp_concurrent: boolean | null
  find_process_mode: string | null
  test_url: string
  test_timeout_ms: number
  sniffer: boolean | null
  /** TCP keep-alive interval in seconds; 0 turns keep-alive off, null follows the profile. */
  keep_alive_interval: number | null
  /** `user:pass` pairs LAN clients sign in with; loopback stays exempt. */
  lan_auth: string[]
  /** Source ranges allowed to use the inbound ports; empty follows the profile. */
  lan_allowed_ips: string[]
  system_proxy: SystemProxySettings
  dns_override: boolean
  dns: DnsSettings
  tun: TunSettings
  /** GEO databases; null follows the profile (false = db/MMDB, true = dat). */
  geodata_mode: boolean | null
  geodata_loader: 'standard' | 'memconservative' | null
  geo_auto_update: boolean | null
  geo_update_interval: number | null
  /** '' follows the profile's geox-url; otherwise a named mirror. */
  geo_source: GeoSource
  /** Individual URL overrides per GEO database. */
  geo_urls: GeoUrls
  /** Sniffer details layered on the final sniffer block while it is on; null follows it. */
  sniff_ports: SniffPorts
  sniff_force_domain: string[] | null
  sniff_skip_domain: string[] | null
  sniff_override_destination: boolean | null
  /** Extra inbound ports; 0 turns a listener off, null follows the profile. */
  socks_port: number | null
  /** mihomo `port`, the HTTP-only listener. */
  http_port: number | null
  redir_port: number | null
  tproxy_port: number | null
  /** Outbound interface; '' drops the profile's, null follows it. */
  interface_name: string | null
  /** Linux `routing-mark`; 0 drops the profile's, null follows it. */
  routing_mark: number | null
}

export type GeoSource = '' | 'github' | 'jsdelivr' | 'testingcf'

export interface GeoFile {
  key: string
  label: string
  file: string
  exists: boolean
  size: number | null
  modified_ms: number | null
}

export interface ProviderProxy {
  name: string
  node_type: string
  tags: string[]
  delay_ms: number | null
  alive: boolean | null
}

export interface ProviderDetail {
  kind: 'proxy' | 'rule'
  name: string
  proxies: ProviderProxy[]
  rules: string[]
  total: number
  notice: string | null
  source: string | null
}

export interface ConfigValues {
  mixed_port: number | null
  allow_lan: boolean | null
  ipv6: boolean | null
  log_level: string | null
  unified_delay: boolean | null
  tcp_concurrent: boolean | null
  find_process_mode: string | null
  keep_alive_interval: number | null
  disable_keep_alive: boolean | null
  socks_port: number | null
  /** The profile's own `port`; `mixed_port` falls back to it. */
  http_port: number | null
  redir_port: number | null
  tproxy_port: number | null
  interface_name: string | null
  routing_mark: number | null
  /** `sniffer.enable` in the profile. */
  sniffer: boolean | null
  sniff_http_ports: string[] | null
  sniff_tls_ports: string[] | null
  sniff_quic_ports: string[] | null
  sniff_force_domain: string[] | null
  sniff_skip_domain: string[] | null
  sniff_override_destination: boolean | null
  tun_route_address: string[] | null
  tun_route_exclude_address: string[] | null
}

/** A 覆写 applied to its profile without saving. */
export interface OverridePreview {
  yaml: string
  logs: string[]
}

/**
 * Read-only summary of the running config. Each layer holds top-level options
 * only; list sections are counted and credentials arrive masked.
 */
export interface ConfigOverview {
  effective: Record<string, unknown>
  /** Profile with its 覆写 merged, before Billow's settings. */
  prepared: Record<string, unknown>
  /** The profile file alone. */
  profile: Record<string, unknown>
  counts: Record<string, number>
  group_types: Record<string, number>
  running: boolean
}

export function normalizeConfigOverview(raw: unknown): ConfigOverview {
  const value = obj(raw)
  const layer = (item: unknown): Record<string, unknown> =>
    item && typeof item === 'object' && !Array.isArray(item) ? (item as Record<string, unknown>) : {}
  const counts = (item: unknown): Record<string, number> =>
    Object.fromEntries(Object.entries(layer(item)).filter((entry): entry is [string, number] => typeof entry[1] === 'number'))
  return {
    effective: layer(value.effective),
    prepared: layer(value.prepared),
    profile: layer(value.profile),
    counts: counts(value.counts),
    group_types: counts(value.group_types),
    running: Boolean(value.running),
  }
}

/** Record types the DNS query tool offers (R31); the backend checks the same list. */
export const DNS_QUERY_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'HTTPS'] as const
export type DnsQueryType = (typeof DNS_QUERY_TYPES)[number]

export interface DnsAnswer {
  type: string
  value: string
  ttl: number
}

export interface DnsQueryResult {
  name: string
  qtype: string
  /** DNS RCODE from the kernel; null when no answer arrived. */
  status: number | null
  answers: DnsAnswer[]
  elapsed_ms: number
  error: string | null
}

/**
 * Hostname check mirrored from the backend: 1–253 chars, dot-separated
 * 1–63 char labels of ASCII letters, digits, `-` or `_`, no edge hyphens.
 * A single trailing dot is allowed.
 */
export function isValidDnsName(raw: string): boolean {
  let name = raw.trim()
  if (name.endsWith('.')) name = name.slice(0, -1)
  if (!name || name.length > 253) return false
  return name
    .split('.')
    .every((label) => label.length > 0 && label.length <= 63 && /^[A-Za-z0-9_-]+$/.test(label) && !label.startsWith('-') && !label.endsWith('-'))
}

export function normalizeDnsQueryResult(raw: unknown): DnsQueryResult {
  const value = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}
  const text = (item: unknown) => (typeof item === 'string' ? item : '')
  const count = (item: unknown) => (typeof item === 'number' && Number.isFinite(item) && item >= 0 ? item : 0)
  const answers = Array.isArray(value.answers) ? value.answers : []
  return {
    name: text(value.name),
    qtype: text(value.qtype),
    status: typeof value.status === 'number' && Number.isFinite(value.status) ? value.status : null,
    answers: answers
      .filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object')
      .map((item) => ({ type: text(item.type), value: text(item.value), ttl: count(item.ttl) }))
      .filter((item) => item.value !== ''),
    elapsed_ms: count(value.elapsed_ms),
    error: typeof value.error === 'string' && value.error ? value.error : null,
  }
}

/**
 * One exit-IP lookup (R40): the IP the internet sees, its region and ISP, the
 * service that answered and when. Streaming unlock checks are out of scope (R47).
 */
export interface ExitIpInfo {
  ip: string
  region: string
  isp: string
  service: string
  time_ms: number
}

export function normalizeExitIp(raw: unknown): ExitIpInfo | null {
  const value = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}
  const text = (item: unknown) => (typeof item === 'string' ? item.trim() : '')
  const ip = text(value.ip)
  if (!ip) return null
  return {
    ip,
    region: text(value.region),
    isp: text(value.isp),
    service: text(value.service),
    time_ms:
      typeof value.time_ms === 'number' && Number.isFinite(value.time_ms) && value.time_ms > 0
        ? value.time_ms
        : Date.now(),
  }
}

export type FailureHint = 'port' | 'tun'

export interface Snapshot {
  profiles: ProfileItem[]
  active_id: string | null
  mixed_port: number | null
  mode: Mode | null
  system_proxy: boolean
  tun: boolean
  vpn: boolean
  pending_url: string | null
  failure: string | null
  /** Structured settings shortcut for a failed action; null when no settings page applies (T8). */
  failure_hint: FailureHint | null
  input_error: string | null
  connected: boolean
  platform: Platform
  tun_wanted: boolean
  excluded: string[]
  /** Allowlist used in `include` mode. */
  included: string[]
  app_mode: AppMode
  installed: InstalledApp[]
  node_catalog: NodeGroup[]
  nodes_notice: string | null
  nodes_error: string | null
  kernel_running: boolean
  /** Kernel memory in bytes; null when the kernel does not report it. */
  kernel_memory: number | null
  /** Seconds since the kernel process started; null while it is not running. */
  kernel_uptime_secs: number | null
  connections: ConnectionRow[]
  /** Open connections the kernel reported, even if the list keeps only 500 rows. */
  connection_total: number
  /** Set when `/connections` could not be read; an empty list is not a failure. */
  connections_error: string | null
  logs: LogLine[]
  upload: number | null
  download: number | null
  upload_total: number | null
  download_total: number | null
  settings: KernelSettings
  config_values: ConfigValues
  notice: string | null
}

export interface KernelStatus {
  channel: KernelChannel
  failure: string | null
  ready: boolean
  version: string | null
}

export interface AppInfo {
  version: string
  platform: string
  autostart: boolean | null
  close_to_tray: boolean
  silent_start: boolean
  /** Desktop only; hidden while `close_to_tray` is off (R44). */
  release_ui_on_close: boolean
  /** Query the exit IP automatically; off by default (R40). */
  auto_exit_ip: boolean
  /** Keep a daily traffic history; off by default (R43). */
  traffic_history: boolean
  data_dir: string | null
}

/** The stats dialog's time range (R43); custom stays inside the retention window. */
export type TrafficRange = 'today' | '7d' | '30d' | 'custom'

/** How the stats table groups the same rows. */
export type TrafficGrouping = 'profile' | 'group' | 'node'

/** One aggregated row: a date, a profile, a group and an exit node (R43). */
export interface TrafficHistoryEntry {
  date: string
  profile: string
  group: string
  node: string
  /** DIRECT / REJECT traffic, shown as one "Direct" row. */
  direct: boolean
  upload: number
  download: number
}

/** Everything the stats dialog needs: the switch, the window and the rows. */
export interface TrafficHistoryView {
  enabled: boolean
  retention_days: number
  today: string
  from: string
  to: string
  entries: TrafficHistoryEntry[]
}

/** Local `YYYY-MM-DD`; a traffic day is the user's calendar day. */
export function localDateKey(date = new Date()): string {
  const pad = (value: number) => String(value).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
}

/** Shift a `YYYY-MM-DD` key by whole days, staying in local time. */
export function shiftDateKey(key: string, days: number): string {
  const [year, month, day] = key.split('-').map(Number)
  if (!year || !month || !day) return key
  return localDateKey(new Date(year, month - 1, day + days))
}

export function normalizeTrafficHistory(raw: unknown): TrafficHistoryView {
  const value = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}
  const text = (item: unknown, fallback = '') => (typeof item === 'string' ? item : fallback)
  const count = (item: unknown) => (typeof item === 'number' && Number.isFinite(item) && item > 0 ? item : 0)
  const today = text(value.today) || localDateKey()
  const rows = Array.isArray(value.entries) ? value.entries : []
  const entries: TrafficHistoryEntry[] = []
  for (const row of rows) {
    if (!row || typeof row !== 'object') continue
    const item = row as Record<string, unknown>
    const date = text(item.date)
    if (!date) continue
    entries.push({
      date,
      profile: text(item.profile),
      group: text(item.group),
      node: text(item.node),
      direct: Boolean(item.direct),
      upload: count(item.upload),
      download: count(item.download),
    })
  }
  return {
    enabled: Boolean(value.enabled),
    retention_days: count(value.retention_days) || 90,
    today,
    from: text(value.from) || today,
    to: text(value.to) || today,
    entries,
  }
}

export interface ShellState {
  theme: ThemePreference
  last_entry: string
  /** Stored preference: `system`, `zh-CN` or `en` (R42). */
  language: LanguagePreference
  /** Effective locale after `system` is resolved by the backend. */
  locale: Locale
}

/** A backup file the WebDAV listing reports (R38). */
export interface RemoteBackup {
  /** File name inside the configured folder, used to fetch it again. */
  name: string
  /** Device that uploaded it, recovered from the file name. */
  device: string
  /** Server `getlastmodified` text, shown as is. */
  modified: string | null
  size: number | null
}

/** WebDAV account and whether this session's connection test succeeded (R38). */
export interface WebdavSettings {
  url: string
  username: string
  password: string
  available: boolean
}

export interface WebdavTestResult {
  available: boolean
  error: string | null
}

/** One thing a desktop global shortcut can do (R39); the ids are stored as is. */
export type HotkeyAction =
  | 'connect'
  | 'proxy'
  | 'tun'
  | 'mode-rule'
  | 'mode-global'
  | 'mode-direct'
  | 'window'

export const HOTKEY_ACTIONS: readonly HotkeyAction[] = [
  'connect',
  'proxy',
  'tun',
  'mode-rule',
  'mode-global',
  'mode-direct',
  'window',
]

/** A saved binding; `active` is false when the system refused it at startup. */
export interface HotkeyBinding {
  action: HotkeyAction
  combo: string
  active: boolean
  error: string | null
}

/** Everything the hotkey section needs, including why it is disabled (R39). */
export interface HotkeySettings {
  available: boolean
  reason: string | null
  platform: string
  bindings: HotkeyBinding[]
}

export interface RulesResult {
  rules: RuleRow[]
  error: string | null
}

export interface UwpApp {
  name: string
  display_name: string
  family_name: string
  sid: string
  exempted: boolean
}

export const DEFAULT_PAC_SCRIPT = `function FindProxyForURL(url, host) {
  if (
    isPlainHostName(host) ||
    shExpMatch(host, "*.local") ||
    shExpMatch(host, "*.lan") ||
    isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
    isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
    isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
    isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")
  ) {
    return "DIRECT";
  }
  return "PROXY %proxy-host%:%mixed-port%; SOCKS5 %proxy-host%:%mixed-port%; DIRECT";
}`

export const DEFAULT_PROXY_BYPASS: string[] = [
  'localhost',
  '127.*',
  '10.*',
  '172.16.*',
  '172.17.*',
  '172.18.*',
  '172.19.*',
  '172.20.*',
  '172.21.*',
  '172.22.*',
  '172.23.*',
  '172.24.*',
  '172.25.*',
  '172.26.*',
  '172.27.*',
  '172.28.*',
  '172.29.*',
  '172.30.*',
  '172.31.*',
  '192.168.*',
  '*.local',
  '*.lan',
  '<local>',
]

export const GEO_SOURCE_PRESETS: Record<Exclude<GeoSource, ''>, GeoUrls> = {
  github: {
    geoip: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat',
    geosite: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat',
    mmdb: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb',
    asn: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb',
  },
  jsdelivr: {
    geoip: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
    geosite: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
    mmdb: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb',
    asn: 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb',
  },
  testingcf: {
    geoip: 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
    geosite: 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
    mmdb: 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb',
    asn: 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb',
  },
}

export function defaultSystemProxy(): SystemProxySettings {
  return {
    host: '',
    mode: 'manual',
    pac_script: DEFAULT_PAC_SCRIPT,
    bypass: [...DEFAULT_PROXY_BYPASS],
  }
}

export function defaultGeoUrls(): GeoUrls {
  return {
    geoip: '',
    mmdb: '',
    geosite: '',
    asn: '',
  }
}

export function defaultDns(): DnsSettings {
  return {
    listen: '',
    enhanced_mode: 'fake-ip',
    fake_ip_range: '198.18.0.1/16',
    fake_ip_filter_mode: 'blacklist',
    fake_ip_filter: [
      '*.lan',
      '*.local',
      '*.localdomain',
      'localhost.ptlogin2.qq.com',
      '+.msftconnecttest.com',
      '+.msftncsi.com',
      '+.stun.*.*',
      '+.stun.*.*.*',
      'time.*.com',
      'ntp.*.com',
      '+.market.xiaomi.com',
    ],
    ipv6: false,
    prefer_h3: false,
    cache_algorithm: 'lru',
    use_hosts: true,
    use_system_hosts: true,
    respect_rules: false,
    direct_nameserver_follow_policy: false,
    default_nameserver: ['223.5.5.5', '119.29.29.29'],
    nameserver: ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query'],
    fallback: [],
    proxy_server_nameserver: ['https://doh.pub/dns-query'],
    direct_nameserver: [],
    nameserver_policy: {},
    hosts: {},
  }
}

export function defaultTun(): TunSettings {
  return {
    stack: '',
    auto_route: true,
    auto_detect_interface: true,
    strict_route: false,
    dns_hijack: ['any:53', 'tcp://any:53'],
    mtu: 1500,
    device: '',
    route_address: null,
    route_exclude_address: null,
  }
}

export function emptySniffPorts(): SniffPorts {
  return { http: null, tls: null, quic: null }
}

export function emptyConfigValues(): ConfigValues {
  return {
    mixed_port: null,
    allow_lan: null,
    ipv6: null,
    log_level: null,
    unified_delay: null,
    tcp_concurrent: null,
    find_process_mode: null,
    keep_alive_interval: null,
    disable_keep_alive: null,
    socks_port: null,
    http_port: null,
    redir_port: null,
    tproxy_port: null,
    interface_name: null,
    routing_mark: null,
    sniffer: null,
    sniff_http_ports: null,
    sniff_tls_ports: null,
    sniff_quic_ports: null,
    sniff_force_domain: null,
    sniff_skip_domain: null,
    sniff_override_destination: null,
    tun_route_address: null,
    tun_route_exclude_address: null,
  }
}

export function emptyKernelSettings(): KernelSettings {
  return {
    auto_connect: false,
    close_connections_on_switch: true,
    subscription_user_agent: '',
    geodata_mode: null,
    geodata_loader: null,
    geo_auto_update: null,
    geo_update_interval: null,
    geo_source: '',
    geo_urls: defaultGeoUrls(),
    sniffer: null,
    keep_alive_interval: null,
    lan_auth: [],
    lan_allowed_ips: [],
    system_proxy: defaultSystemProxy(),
    dns_override: false,
    dns: defaultDns(),
    tun: defaultTun(),
    mixed_port: null,
    allow_lan: null,
    ipv6: null,
    log_level: null,
    unified_delay: null,
    tcp_concurrent: null,
    find_process_mode: null,
    test_url: '',
    test_timeout_ms: 0,
    sniff_ports: emptySniffPorts(),
    sniff_force_domain: null,
    sniff_skip_domain: null,
    sniff_override_destination: null,
    socks_port: null,
    http_port: null,
    redir_port: null,
    tproxy_port: null,
    interface_name: null,
    routing_mark: null,
  }
}

export function emptySnapshot(): Snapshot {
  return {
    profiles: [],
    active_id: null,
    mixed_port: null,
    mode: null,
    system_proxy: false,
    tun: false,
    vpn: false,
    pending_url: null,
    failure: null,
    failure_hint: null,
    input_error: null,
    connected: false,
    platform: 'desktop',
    tun_wanted: false,
    excluded: [],
    included: [],
    app_mode: 'exclude',
    installed: [],
    node_catalog: [],
    nodes_notice: null,
    nodes_error: null,
    kernel_running: false,
    kernel_memory: null,
    kernel_uptime_secs: null,
    connections: [],
    connection_total: 0,
    connections_error: null,
    logs: [],
    upload: null,
    download: null,
    upload_total: null,
    download_total: null,
    settings: emptyKernelSettings(),
    config_values: emptyConfigValues(),
    notice: null,
  }
}

const str = (value: unknown, fallback = ''): string => (typeof value === 'string' ? value : fallback)
const optStr = (value: unknown): string | null =>
  typeof value === 'string' && value.length > 0 ? value : null
const num = (value: unknown): number | null =>
  typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
const optBool = (value: unknown): boolean | null => (typeof value === 'boolean' ? value : null)
const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : [])
const obj = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' ? (value as Record<string, unknown>) : {}

export function normalizeMode(value: unknown): Mode | null {
  const text = str(value).trim().toLowerCase()
  return text === 'rule' || text === 'global' || text === 'direct' ? text : null
}

function normalizeLevel(value: unknown): LogLevel {
  const text = str(value)
  return text === 'debug' || text === 'warning' || text === 'error' ? text : 'info'
}

function normalizeNode(raw: unknown): NodeItem {
  const node = obj(raw)
  const failed = Boolean(node.failed)
  const dialer = optStr(node.dialer_proxy)
  return {
    name: str(node.name),
    delay_ms: failed ? null : num(node.delay_ms),
    failed,
    selected: Boolean(node.selected),
    node_type: str(node.node_type),
    tags: Array.isArray(node.tags) ? node.tags.filter((tag): tag is string => typeof tag === 'string' && tag.length > 0) : [],
    ...(dialer ? { dialer_proxy: dialer } : {}),
  }
}

function normalizeGroup(raw: unknown): NodeGroup {
  const group = obj(raw)
  return {
    name: str(group.name),
    kind: group.kind === 'auto' ? 'auto' : 'manual',
    now: str(group.now),
    sort: str(group.sort, 'default'),
    nodes: list(group.nodes).map(normalizeNode).filter((node) => node.name),
    group_type: str(group.group_type),
    icon: normalizeIcon(group.icon),
    pinnable: group.kind === 'auto' && group.pinnable === true,
    fixed: group.kind === 'auto' && group.pinnable === true ? optStr(group.fixed) || null : null,
    hidden: group.hidden === true,
  }
}

/** Only remote http(s) images and inline image data are usable as group icons. */
export function normalizeIcon(raw: unknown): string | null {
  const text = str(raw).trim()
  if (!text || /\s/.test(text)) return null
  const lower = text.toLowerCase()
  const allowed =
    lower.startsWith('http://') || lower.startsWith('https://') || lower.startsWith('data:image/')
  return allowed ? text.slice(0, 2048) : null
}

export function normalizeRuleRow(raw: unknown): RuleRow {
  const rule = obj(raw)
  return {
    kind: str(rule.kind),
    payload: str(rule.payload),
    proxy: str(rule.proxy),
    hit_count: num(rule.hit_count),
    last_hit: optStr(rule.last_hit),
    key: optStr(rule.key),
    disabled: Boolean(rule.disabled),
  }
}

const strings = (value: unknown): string[] =>
  list(value).filter((item): item is string => typeof item === 'string')
/** A list that may be absent (null = follow the profile); an empty one counts as absent. */
const optStrings = (value: unknown): string[] | null => {
  if (!Array.isArray(value)) return null
  const items = value
    .map((item) => (typeof item === 'number' ? String(item) : item))
    .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
  return items.length ? items : null
}
const optPort = (value: unknown): number | null => {
  const port = num(value)
  return port != null && Number.isInteger(port) && port <= 65535 ? port : null
}

function normalizeStringMap(raw: unknown): Record<string, string[]> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
  const out: Record<string, string[]> = {}
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    const key = k.trim()
    if (!key) continue
    const items = typeof v === 'string' ? [v.trim()].filter(Boolean) : strings(v).map((s) => s.trim()).filter(Boolean)
    if (items.length) out[key] = items
  }
  return out
}

function normalizeSystemProxy(raw: unknown): SystemProxySettings {
  const base = defaultSystemProxy()
  if (!raw || typeof raw !== 'object') return base
  const value = obj(raw)
  const mode = str(value.mode)
  const pacScript = str(value.pac_script).trim()
  return {
    host: str(value.host).trim(),
    mode: mode === 'pac' ? 'pac' : 'manual',
    pac_script: pacScript || base.pac_script,
    bypass: Array.isArray(value.bypass) ? strings(value.bypass) : base.bypass,
  }
}

function normalizeGeoUrls(raw: unknown): GeoUrls {
  const base = defaultGeoUrls()
  if (!raw || typeof raw !== 'object') return base
  const value = obj(raw)
  return {
    geoip: str(value.geoip).trim(),
    mmdb: str(value.mmdb).trim(),
    geosite: str(value.geosite).trim(),
    asn: str(value.asn).trim(),
  }
}

function normalizeDns(raw: unknown): DnsSettings {
  const value = obj(raw)
  const base = defaultDns()
  if (!raw || typeof raw !== 'object') return base
  const mode = str(value.enhanced_mode)
  const filterMode = str(value.fake_ip_filter_mode)
  const cacheAlgo = str(value.cache_algorithm)
  return {
    listen: str(value.listen),
    enhanced_mode: mode === 'redir-host' || mode === 'normal' ? mode : 'fake-ip',
    fake_ip_range: str(value.fake_ip_range, base.fake_ip_range),
    fake_ip_filter_mode: filterMode === 'whitelist' || filterMode === 'rule' ? filterMode : 'blacklist',
    fake_ip_filter: strings(value.fake_ip_filter),
    ipv6: Boolean(value.ipv6),
    prefer_h3: Boolean(value.prefer_h3),
    cache_algorithm: cacheAlgo === 'arc' ? 'arc' : 'lru',
    use_hosts: value.use_hosts !== false,
    use_system_hosts: value.use_system_hosts !== false,
    respect_rules: Boolean(value.respect_rules),
    direct_nameserver_follow_policy: Boolean(value.direct_nameserver_follow_policy),
    default_nameserver: strings(value.default_nameserver),
    nameserver: strings(value.nameserver),
    fallback: strings(value.fallback),
    proxy_server_nameserver: strings(value.proxy_server_nameserver),
    direct_nameserver: strings(value.direct_nameserver),
    nameserver_policy: normalizeStringMap(value.nameserver_policy),
    hosts: normalizeStringMap(value.hosts),
  }
}

function normalizeTun(raw: unknown): TunSettings {
  const value = obj(raw)
  const base = defaultTun()
  if (!raw || typeof raw !== 'object') return base
  const stack = str(value.stack)
  return {
    stack: stack === 'system' || stack === 'gvisor' || stack === 'mixed' || stack === 'mips' ? stack : '',
    auto_route: value.auto_route !== false,
    auto_detect_interface: value.auto_detect_interface !== false,
    strict_route: Boolean(value.strict_route),
    dns_hijack: strings(value.dns_hijack),
    mtu: num(value.mtu) ?? base.mtu,
    device: str(value.device),
    route_address: optStrings(value.route_address),
    route_exclude_address: optStrings(value.route_exclude_address),
  }
}

function normalizeSettings(raw: unknown): KernelSettings {
  const value = obj(raw)
  const geoSource = str(value.geo_source)
  const geoLoader = str(value.geodata_loader)
  return {
    auto_connect: Boolean(value.auto_connect),
    close_connections_on_switch: value.close_connections_on_switch !== false,
    subscription_user_agent: str(value.subscription_user_agent).trim(),
    geodata_mode: optBool(value.geodata_mode),
    geodata_loader: geoLoader === 'standard' || geoLoader === 'memconservative' ? geoLoader : null,
    geo_auto_update: optBool(value.geo_auto_update),
    geo_update_interval: num(value.geo_update_interval),
    geo_source: geoSource === 'github' || geoSource === 'jsdelivr' || geoSource === 'testingcf' ? geoSource : '',
    geo_urls: normalizeGeoUrls(value.geo_urls),
    sniffer: optBool(value.sniffer),
    keep_alive_interval: num(value.keep_alive_interval),
    lan_auth: strings(value.lan_auth),
    lan_allowed_ips: strings(value.lan_allowed_ips),
    system_proxy: normalizeSystemProxy(value.system_proxy),
    dns_override: Boolean(value.dns_override),
    dns: normalizeDns(value.dns),
    tun: normalizeTun(value.tun),
    mixed_port: num(value.mixed_port),
    allow_lan: optBool(value.allow_lan),
    ipv6: optBool(value.ipv6),
    log_level: optStr(value.log_level),
    unified_delay: optBool(value.unified_delay),
    tcp_concurrent: optBool(value.tcp_concurrent),
    find_process_mode: optStr(value.find_process_mode),
    test_url: str(value.test_url),
    test_timeout_ms: num(value.test_timeout_ms) ?? 0,
    sniff_ports: {
      http: optStrings(obj(value.sniff_ports).http),
      tls: optStrings(obj(value.sniff_ports).tls),
      quic: optStrings(obj(value.sniff_ports).quic),
    },
    sniff_force_domain: optStrings(value.sniff_force_domain),
    sniff_skip_domain: optStrings(value.sniff_skip_domain),
    sniff_override_destination: optBool(value.sniff_override_destination),
    socks_port: optPort(value.socks_port),
    http_port: optPort(value.http_port),
    redir_port: optPort(value.redir_port),
    tproxy_port: optPort(value.tproxy_port),
    interface_name: typeof value.interface_name === 'string' ? value.interface_name.trim() : null,
    routing_mark: num(value.routing_mark),
  }
}

/** Accepts whatever the backend sends and fills every field the UI reads. */
export function normalizeSnapshot(raw: unknown): Snapshot {
  const source = obj(raw)
  const config = obj(source.config_values)
  return {
    profiles: list(source.profiles).map((item) => {
      const profile = obj(item)
      return {
        id: str(profile.id),
        name: str(profile.name),
        kind: profile.kind === 'local' ? 'local' : 'subscription',
        source: str(profile.source),
        user_agent: str(profile.user_agent).trim(),
        current: Boolean(profile.current),
        failure: optStr(profile.failure),
        override_text: str(profile.override_text),
        override_error: optStr(profile.override_error),
        used: num(profile.used),
        total: num(profile.total) || null,
        expire: num(profile.expire) || null,
        last_success_ms: num(profile.last_success_ms) || null,
        interval_hours: num(profile.interval_hours) ?? 0,
        updated_ms: num(profile.updated_ms) || null,
        proxy_count: num(profile.proxy_count) ?? 0,
        age_recipients: Array.isArray(profile.age_recipients)
          ? profile.age_recipients.filter((item): item is string => typeof item === 'string' && item.length > 0)
          : [],
      } satisfies ProfileItem
    }),
    active_id: optStr(source.active_id),
    mixed_port: num(source.mixed_port),
    mode: normalizeMode(source.mode),
    system_proxy: Boolean(source.system_proxy),
    tun: Boolean(source.tun),
    vpn: Boolean(source.vpn),
    pending_url: optStr(source.pending_url),
    failure: optStr(source.failure),
    failure_hint: source.failure_hint === 'port' || source.failure_hint === 'tun' ? source.failure_hint : null,
    input_error: optStr(source.input_error),
    connected: Boolean(source.connected),
    platform: source.platform === 'android' ? 'android' : 'desktop',
    tun_wanted: Boolean(source.tun_wanted),
    excluded: list(source.excluded).filter((item): item is string => typeof item === 'string'),
    included: list(source.included).filter((item): item is string => typeof item === 'string'),
    app_mode: source.app_mode === 'include' ? 'include' : 'exclude',
    installed: list(source.installed)
      .map((item) => ({ name: str(obj(item).name), package_name: str(obj(item).package_name), system: Boolean(obj(item).system) }))
      .filter((app) => app.package_name),
    node_catalog: list(source.node_catalog).map(normalizeGroup).filter((group) => group.name),
    nodes_notice: optStr(source.nodes_notice),
    nodes_error: optStr(source.nodes_error),
    kernel_running: Boolean(source.kernel_running),
    kernel_memory: num(source.kernel_memory),
    kernel_uptime_secs: num(source.kernel_uptime_secs),
    connections: list(source.connections).map((item) => {
      const row = obj(item)
      return {
        id: str(row.id),
        host: str(row.host),
        outbound: str(row.outbound),
        network: str(row.network),
        conn_type: str(row.conn_type),
        destination: str(row.destination),
        source: str(row.source),
        process: str(row.process),
        rule: str(row.rule),
        rule_payload: str(row.rule_payload),
        chains: list(row.chains).filter((chain): chain is string => typeof chain === 'string'),
        upload: num(row.upload) ?? 0,
        download: num(row.download) ?? 0,
        start: str(row.start),
      }
    }),
    connection_total: num(source.connection_total) ?? 0,
    connections_error: optStr(source.connections_error),
    logs: list(source.logs).map((item) => {
      const line = obj(item)
      return {
        level: normalizeLevel(line.level),
        message: str(line.message),
        time_ms: num(line.time_ms) ?? 0,
        hint: line.hint === 'port' || line.hint === 'tun' ? line.hint : null,
        hint_kind: ['mixed', 'http', 'socks', 'redir', 'tproxy'].includes(str(line.hint_kind))
          ? (str(line.hint_kind) as 'mixed' | 'http' | 'socks' | 'redir' | 'tproxy')
          : null,
      }
    }),
    upload: num(source.upload),
    download: num(source.download),
    upload_total: num(source.upload_total),
    download_total: num(source.download_total),
    settings: normalizeSettings(source.settings),
    config_values: {
      mixed_port: num(config.mixed_port),
      allow_lan: optBool(config.allow_lan),
      ipv6: optBool(config.ipv6),
      log_level: optStr(config.log_level),
      unified_delay: optBool(config.unified_delay),
      tcp_concurrent: optBool(config.tcp_concurrent),
      find_process_mode: optStr(config.find_process_mode),
      keep_alive_interval: num(config.keep_alive_interval),
      disable_keep_alive: optBool(config.disable_keep_alive),
      socks_port: num(config.socks_port),
      http_port: num(config.http_port),
      redir_port: num(config.redir_port),
      tproxy_port: num(config.tproxy_port),
      interface_name: optStr(config.interface_name),
      routing_mark: num(config.routing_mark),
      sniffer: optBool(config.sniffer),
      sniff_http_ports: optStrings(config.sniff_http_ports),
      sniff_tls_ports: optStrings(config.sniff_tls_ports),
      sniff_quic_ports: optStrings(config.sniff_quic_ports),
      sniff_force_domain: optStrings(config.sniff_force_domain),
      sniff_skip_domain: optStrings(config.sniff_skip_domain),
      sniff_override_destination: optBool(config.sniff_override_destination),
      tun_route_address: optStrings(config.tun_route_address),
      tun_route_exclude_address: optStrings(config.tun_route_exclude_address),
    },
    notice: optStr(source.notice),
  }
}

export function normalizeKernel(raw: unknown): KernelStatus {
  const value = obj(raw)
  return {
    channel: value.channel === 'preview' ? 'preview' : 'stable',
    failure: optStr(value.failure),
    ready: Boolean(value.ready),
    version: optStr(value.version),
  }
}

/** Entries of a comma / whitespace / newline separated list, empty ones dropped. */
export function splitList(text: string): string[] {
  return text.split(/[\s,，;；]+/).map((item) => item.trim()).filter(Boolean)
}

function ipv4(text: string): boolean {
  const parts = text.split('.')
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

function ipv6(text: string): boolean {
  if (!/^[0-9a-f:.]+$/i.test(text) || !text.includes(':')) return false
  const tail = text.includes('.') ? text.slice(text.lastIndexOf(':') + 1) : ''
  if (tail && !ipv4(tail)) return false
  const head = tail ? text.slice(0, text.lastIndexOf(':') + 1) + '0:0' : text
  const halves = head.split('::')
  if (halves.length > 2) return false
  const groups = halves.flatMap((half) => (half ? half.split(':') : []))
  if (groups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) return false
  return halves.length === 2 ? groups.length < 8 : groups.length === 8
}

/** An IP address or `ip/prefix` network, as the backend accepts it. */
export function isCidrEntry(entry: string): boolean {
  const [addr, prefix, ...rest] = entry.trim().split('/')
  if (rest.length || !addr) return false
  const v4 = ipv4(addr)
  if (!v4 && !ipv6(addr)) return false
  if (prefix === undefined) return true
  if (!/^\d{1,3}$/.test(prefix)) return false
  return Number(prefix) <= (v4 ? 32 : 128)
}

/** A sniff port entry: `443` or `8000-9000`, each end within 1–65535. */
export function isPortEntry(entry: string): boolean {
  const text = entry.replace(/\s+/g, '')
  const port = (part: string) => /^\d{1,5}$/.test(part) && Number(part) >= 1 && Number(part) <= 65535
  const range = /^(\d+)-(\d+)$/.exec(text)
  if (range) return port(range[1]!) && port(range[2]!) && Number(range[1]) <= Number(range[2])
  return port(text)
}
