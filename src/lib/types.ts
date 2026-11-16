export type Mode = 'rule' | 'global' | 'direct'
export type ThemePreference = 'system' | 'light' | 'dark'
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

export interface LogLine {
  level: LogLevel
  message: string
  time_ms: number
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
  data_dir: string | null
}

export interface ShellState {
  theme: ThemePreference
  last_entry: string
}

export interface RulesResult {
  rules: RuleRow[]
  error: string | null
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
  }
}

export function emptyKernelSettings(): KernelSettings {
  return {
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
    config_values: {
      mixed_port: null,
      allow_lan: null,
      ipv6: null,
      log_level: null,
      unified_delay: null,
      tcp_concurrent: null,
      find_process_mode: null,
      keep_alive_interval: null,
      disable_keep_alive: null,
    },
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
  return {
    name: str(node.name),
    delay_ms: failed ? null : num(node.delay_ms),
    failed,
    selected: Boolean(node.selected),
    node_type: str(node.node_type),
    tags: Array.isArray(node.tags) ? node.tags.filter((tag): tag is string => typeof tag === 'string' && tag.length > 0) : [],
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
  }
}

function normalizeSettings(raw: unknown): KernelSettings {
  const value = obj(raw)
  const geoSource = str(value.geo_source)
  const geoLoader = str(value.geodata_loader)
  return {
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
      return { level: normalizeLevel(line.level), message: str(line.message), time_ms: num(line.time_ms) ?? 0 }
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
