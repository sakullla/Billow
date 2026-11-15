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
}

export interface InstalledApp {
  name: string
  package_name: string
}

export interface NodeItem {
  name: string
  delay_ms: number | null
  failed: boolean
  selected: boolean
  node_type: string
}

export interface NodeGroup {
  name: string
  kind: 'manual' | 'auto'
  now: string
  sort: string
  nodes: NodeItem[]
  group_type: string
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
}

export interface DnsSettings {
  enhanced_mode: 'fake-ip' | 'redir-host' | 'normal'
  fake_ip_range: string
  fake_ip_filter: string[]
  ipv6: boolean
  use_hosts: boolean
  respect_rules: boolean
  default_nameserver: string[]
  nameserver: string[]
  fallback: string[]
  proxy_server_nameserver: string[]
  direct_nameserver: string[]
}

export interface TunSettings {
  stack: 'mixed' | 'system' | 'gvisor'
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
  dns_override: boolean
  dns: DnsSettings
  tun: TunSettings
}

export interface ConfigValues {
  mixed_port: number | null
  allow_lan: boolean | null
  ipv6: boolean | null
  log_level: string | null
  unified_delay: boolean | null
  tcp_concurrent: boolean | null
  find_process_mode: string | null
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
  installed: InstalledApp[]
  node_catalog: NodeGroup[]
  nodes_notice: string | null
  nodes_error: string | null
  kernel_running: boolean
  connections: ConnectionRow[]
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

export function defaultDns(): DnsSettings {
  return {
    enhanced_mode: 'fake-ip',
    fake_ip_range: '198.18.0.1/16',
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
    use_hosts: true,
    respect_rules: false,
    default_nameserver: ['223.5.5.5', '119.29.29.29'],
    nameserver: ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query'],
    fallback: [],
    proxy_server_nameserver: ['https://doh.pub/dns-query'],
    direct_nameserver: [],
  }
}

export function defaultTun(): TunSettings {
  return {
    stack: 'mixed',
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
    sniffer: null,
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
    installed: [],
    node_catalog: [],
    nodes_notice: null,
    nodes_error: null,
    kernel_running: false,
    connections: [],
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
  }
}

const strings = (value: unknown): string[] =>
  list(value).filter((item): item is string => typeof item === 'string')

function normalizeDns(raw: unknown): DnsSettings {
  const value = obj(raw)
  const base = defaultDns()
  if (!raw || typeof raw !== 'object') return base
  const mode = str(value.enhanced_mode)
  return {
    enhanced_mode: mode === 'redir-host' || mode === 'normal' ? mode : 'fake-ip',
    fake_ip_range: str(value.fake_ip_range, base.fake_ip_range),
    fake_ip_filter: strings(value.fake_ip_filter),
    ipv6: Boolean(value.ipv6),
    use_hosts: value.use_hosts !== false,
    respect_rules: Boolean(value.respect_rules),
    default_nameserver: strings(value.default_nameserver),
    nameserver: strings(value.nameserver),
    fallback: strings(value.fallback),
    proxy_server_nameserver: strings(value.proxy_server_nameserver),
    direct_nameserver: strings(value.direct_nameserver),
  }
}

function normalizeTun(raw: unknown): TunSettings {
  const value = obj(raw)
  const base = defaultTun()
  if (!raw || typeof raw !== 'object') return base
  const stack = str(value.stack)
  return {
    stack: stack === 'system' || stack === 'gvisor' ? stack : 'mixed',
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
  return {
    sniffer: optBool(value.sniffer),
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
    installed: list(source.installed)
      .map((item) => ({ name: str(obj(item).name), package_name: str(obj(item).package_name) }))
      .filter((app) => app.package_name),
    node_catalog: list(source.node_catalog).map(normalizeGroup).filter((group) => group.name),
    nodes_notice: optStr(source.nodes_notice),
    nodes_error: optStr(source.nodes_error),
    kernel_running: Boolean(source.kernel_running),
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
