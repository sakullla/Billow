import type { PageId, SettingsTab } from './store'
import { groupTypeLabel } from './format'
import { matchesTokens, splitQueryTokens } from './search'
import type { ConfigOverview } from './types'

/**
 * Turns the backend's layered config summary into labelled rows for the
 * read-only overview. Core options always appear (showing the kernel default
 * when unset); niche ones only when the config actually sets them, so the
 * screen stays short for ordinary profiles.
 */

/** Where a value comes from, last writer first. */
export type OverviewSource = 'billow' | 'override' | 'profile' | 'default'

export interface OverviewTarget {
  page: PageId
  tab?: SettingsTab
}

export interface OverviewRow {
  /** YAML path, e.g. `dns.enhanced-mode`; also what search matches. */
  path: string
  label: string
  value: string
  /** Full value when the visible one is shortened. */
  title?: string
  source: OverviewSource
  /** Value before Billow or the 覆写 changed it, for the source tooltip. */
  before?: string
  to?: OverviewTarget
}

export interface OverviewSection {
  id: string
  title: string
  rows: OverviewRow[]
  /** Raw leftovers fold away by default. */
  folded?: boolean
}

type Format = (value: unknown) => string

interface Field {
  path: string
  label: string
  format?: Format
  /** Kernel default shown as "默认 · …" when the key is unset; without it the row hides. */
  fallback?: string
  to?: OverviewTarget
}

const KERNEL: OverviewTarget = { page: 'settings', tab: 'kernel' }
const DNS: OverviewTarget = { page: 'settings', tab: 'dns' }
const TUN: OverviewTarget = { page: 'settings', tab: 'tun' }
const RESOURCES: OverviewTarget = { page: 'resources' }

const ENUMS: Record<string, string> = {
  rule: '规则',
  global: '全局',
  direct: '直连',
  debug: '调试',
  info: '信息',
  warning: '警告',
  error: '错误',
  silent: '静默',
  always: '始终',
  strict: '自动',
  off: '关闭',
  'fake-ip': 'Fake-IP',
  'redir-host': 'Redir-Host',
  normal: 'Normal',
  mixed: 'Mixed',
  gvisor: 'gVisor',
  system: 'System',
}

const pick =
  (labels: Record<string, string>): Format =>
  (value) =>
    typeof value === 'string' ? (labels[value.toLowerCase()] ?? value) : formatValue(value)
const loader = pick({ memconservative: '低内存', standard: '标准' })
const filterMode = pick({ blacklist: '黑名单', whitelist: '白名单', rule: '规则' })
const tunDns = pick({ disabled: '不设置', native: '指向 TUN', hijack: '指向 TUN 并拦截' })

const FINGERPRINTS: Record<string, string> = {
  chrome: 'Chrome',
  firefox: 'Firefox',
  safari: 'Safari',
  ios: 'iOS',
  android: 'Android',
  edge: 'Edge',
  '360': '360',
  qq: 'QQ',
  random: '随机',
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

/** Generic display: booleans as 开启/关闭, short lists inline, maps as a count. */
export function formatValue(value: unknown): string {
  if (value === undefined || value === null || value === '') return '未设置'
  if (typeof value === 'boolean') return value ? '开启' : '关闭'
  if (typeof value === 'number') return String(value)
  if (typeof value === 'string') return ENUMS[value.toLowerCase()] ?? value
  if (Array.isArray(value)) {
    if (!value.length) return '无'
    const items = value.map((item) => (typeof item === 'string' || typeof item === 'number' ? String(item) : JSON.stringify(item)))
    return items.length > 3 ? `${items.slice(0, 3).join('、')} 等 ${items.length} 项` : items.join('、')
  }
  if (isRecord(value)) {
    const size = Object.keys(value).length
    return size ? `${size} 项` : '无'
  }
  return String(value)
}

/** Long values keep a full-text tooltip; short ones need none. */
function fullText(value: unknown): string | undefined {
  if (Array.isArray(value) && value.length > 3) return value.map((item) => (typeof item === 'string' ? item : JSON.stringify(item))).join('\n')
  if (isRecord(value)) {
    const text = JSON.stringify(value, null, 1)
    return text.length > 600 ? `${text.slice(0, 600)}…` : text
  }
  return undefined
}

const entries: Format = (value) => (isRecord(value) ? `${Object.keys(value).length} 条` : formatValue(value))
const seconds: Format = (value) => (typeof value === 'number' ? `${value} 秒` : formatValue(value))
const hours: Format = (value) => (typeof value === 'number' ? `${value} 小时` : formatValue(value))
/** mihomo removed the global fingerprint (v1.19.34 logs an error and ignores it); profiles may still carry it. */
const removedFingerprint: Format = (value) =>
  `${typeof value === 'string' ? (FINGERPRINTS[value.toLowerCase()] ?? value) : formatValue(value)}（内核已移除，不生效）`
const users: Format = (value) => {
  if (!Array.isArray(value) || !value.length) return formatValue(value)
  const names = value.map((item) => String(item).split(':')[0])
  return names.length > 2 ? `${names.slice(0, 2).join('、')} 等 ${names.length} 个用户` : names.join('、')
}
const sniffs: Format = (value) => (isRecord(value) ? Object.keys(value).join('、') || '无' : formatValue(value))
const geodata: Format = (value) => (value === true ? 'dat（GeoIP / GeoSite）' : value === false ? 'mmdb' : formatValue(value))

const SECTIONS: { id: string; title: string; fields: Field[]; desktopOnly?: boolean }[] = [
  {
    id: 'inbound',
    title: '入站',
    fields: [
      { path: 'mixed-port', label: '混合端口', to: KERNEL },
      { path: 'port', label: 'HTTP 端口' },
      { path: 'socks-port', label: 'SOCKS5 端口' },
      { path: 'redir-port', label: '透明代理端口' },
      { path: 'tproxy-port', label: 'TProxy 端口' },
      { path: 'allow-lan', label: '局域网连接', fallback: '关闭', to: KERNEL },
      { path: 'bind-address', label: '监听地址' },
      { path: 'lan-allowed-ips', label: '允许的来源', to: KERNEL },
      { path: 'lan-disallowed-ips', label: '禁止的来源' },
      { path: 'authentication', label: '访问认证', format: users, to: KERNEL },
      { path: 'skip-auth-prefixes', label: '免认证来源' },
    ],
  },
  {
    id: 'outbound',
    title: '出站',
    fields: [
      { path: 'mode', label: '出站模式', fallback: '规则', to: { page: 'home' } },
      { path: 'global-client-fingerprint', label: '全局 TLS 指纹', format: removedFingerprint },
      { path: 'keep-alive-interval', label: 'TCP 保活间隔', format: seconds, to: KERNEL },
      { path: 'keep-alive-idle', label: 'TCP 保活空闲', format: seconds },
      { path: 'disable-keep-alive', label: '关闭 TCP 保活', to: KERNEL },
      { path: 'interface-name', label: '出口网卡' },
      { path: 'routing-mark', label: '路由标记' },
    ],
  },
  {
    id: 'dns',
    title: 'DNS',
    fields: [
      { path: 'dns.enable', label: '内置 DNS', fallback: '关闭', to: DNS },
      { path: 'dns.enhanced-mode', label: '域名映射', to: DNS },
      { path: 'dns.listen', label: '监听地址', to: DNS },
      { path: 'dns.nameserver', label: '主 DNS', to: DNS },
      { path: 'dns.default-nameserver', label: '引导 DNS', to: DNS },
      { path: 'dns.fallback', label: '备用 DNS', to: DNS },
      { path: 'dns.proxy-server-nameserver', label: '节点域名解析', to: DNS },
      { path: 'dns.nameserver-policy', label: '解析策略', format: entries, to: DNS },
      { path: 'dns.fake-ip-range', label: 'Fake-IP 地址段', to: DNS },
      { path: 'dns.fake-ip-filter-mode', label: 'Fake-IP 过滤模式', format: filterMode, to: DNS },
      { path: 'dns.respect-rules', label: '遵循分流规则', to: DNS },
      { path: 'hosts', label: 'Hosts', format: entries, to: DNS },
    ],
  },
  {
    id: 'tun',
    title: 'TUN',
    desktopOnly: true,
    fields: [
      { path: 'tun.enable', label: 'TUN 模式', fallback: '关闭', to: TUN },
      { path: 'tun.stack', label: '协议栈', fallback: '内核默认（Mips）', to: TUN },
      { path: 'tun.dns-mode', label: '系统 DNS', format: tunDns },
      { path: 'tun.auto-route', label: '自动路由', to: TUN },
      { path: 'tun.strict-route', label: '严格路由', to: TUN },
      { path: 'tun.dns-hijack', label: 'DNS 劫持', to: TUN },
      { path: 'tun.mtu', label: 'MTU', to: TUN },
      { path: 'tun.device', label: '网卡名称', to: TUN },
    ],
  },
  {
    id: 'sniff',
    title: '嗅探与 GEO',
    fields: [
      { path: 'sniffer.enable', label: '域名嗅探', fallback: '关闭', to: KERNEL },
      { path: 'sniffer.sniff', label: '嗅探协议', format: sniffs },
      { path: 'geodata-mode', label: 'GeoIP 格式', format: geodata, fallback: 'mmdb', to: RESOURCES },
      { path: 'geodata-loader', label: 'GEO 加载方式', format: loader, fallback: '低内存', to: RESOURCES },
      { path: 'geo-auto-update', label: '自动更新 GEO', to: RESOURCES },
      { path: 'geo-update-interval', label: 'GEO 更新间隔', format: hours, to: RESOURCES },
      { path: 'geox-url', label: 'GEO 下载地址', format: entries, to: RESOURCES },
    ],
  },
  {
    id: 'misc',
    title: '运行',
    fields: [
      { path: 'log-level', label: '日志级别', fallback: '信息', to: KERNEL },
      { path: 'ipv6', label: 'IPv6', fallback: '开启', to: KERNEL },
      { path: 'unified-delay', label: '统一延迟', fallback: '关闭', to: KERNEL },
      { path: 'tcp-concurrent', label: 'TCP 并发', fallback: '关闭', to: KERNEL },
      { path: 'find-process-mode', label: '进程匹配', fallback: '自动', to: KERNEL },
      { path: 'global-ua', label: '外部资源 UA' },
      { path: 'etag-support', label: 'ETag 缓存' },
    ],
  },
]

/** Top-level keys covered by a field or managed by Billow itself; the rest go to 「其他字段」. */
const COVERED = new Set([
  ...SECTIONS.flatMap((section) => section.fields.map((field) => field.path.split('.')[0]!)),
  'external-controller',
  'external-controller-tls',
  'external-controller-unix',
  'external-controller-pipe',
  'secret',
])

export function valueAt(layer: Record<string, unknown>, path: string): unknown {
  let current: unknown = layer
  for (const part of path.split('.')) {
    if (!isRecord(current)) return undefined
    current = current[part]
  }
  return current
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b)
}

function sourceOf(data: ConfigOverview, path: string): { source: OverviewSource; before?: unknown } {
  const effective = valueAt(data.effective, path)
  if (effective === undefined) return { source: 'default' }
  const prepared = valueAt(data.prepared, path)
  if (!same(effective, prepared)) return { source: 'billow', before: prepared }
  const profile = valueAt(data.profile, path)
  if (!same(prepared, profile)) return { source: 'override', before: profile }
  return { source: 'profile' }
}

function countRow(data: ConfigOverview, key: string, label: string, to: OverviewTarget, detail?: string): OverviewRow | null {
  const count = data.counts[key]
  if (count == null) return null
  return { path: key, label, value: detail ? `${count} 个 · ${detail}` : `${count} 个`, source: 'profile', to }
}

/** Group count broken down by type, in the proxy page's own wording. */
function groupDetail(types: Record<string, number>): string | undefined {
  const parts = Object.entries(types)
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => `${groupTypeLabel({ group_type: type, kind: type === 'select' ? 'manual' : 'auto' })} ${count}`)
  return parts.length ? parts.join(' · ') : undefined
}

export function buildOverview(data: ConfigOverview, options: { android?: boolean } = {}): OverviewSection[] {
  const sections: OverviewSection[] = []
  for (const section of SECTIONS) {
    if (section.desktopOnly && options.android) continue
    const rows: OverviewRow[] = []
    for (const field of section.fields) {
      const value = valueAt(data.effective, field.path)
      const { source, before } = sourceOf(data, field.path)
      if (value === undefined && field.fallback == null) continue
      const format = field.format ?? formatValue
      rows.push({
        path: field.path,
        label: field.label,
        value: value === undefined ? field.fallback! : format(value),
        title: value === undefined ? undefined : fullText(value),
        source,
        before: source === 'billow' || source === 'override' ? (before === undefined ? '未设置' : format(before)) : undefined,
        // Android owns routing and DNS hijack; those settings pages do not exist there.
        to: options.android && field.to?.tab === 'tun' ? undefined : field.to,
      })
    }
    if (section.id === 'outbound') {
      const counted = [
        countRow(data, 'proxies', '节点', { page: 'proxies' }),
        countRow(data, 'proxy-groups', '代理组', { page: 'proxies' }, groupDetail(data.group_types)),
        countRow(data, 'proxy-providers', '代理集', RESOURCES),
        countRow(data, 'rules', '规则', { page: 'rules' }),
        countRow(data, 'rule-providers', '规则集', RESOURCES),
      ].filter((row): row is OverviewRow => row !== null)
      rows.splice(1, 0, ...counted)
    }
    if (section.id === 'inbound') {
      const listeners = countRow(data, 'listeners', '额外监听', KERNEL)
      if (listeners && data.counts.listeners) rows.push({ ...listeners, to: undefined })
    }
    if (rows.length) sections.push({ id: section.id, title: section.title, rows })
  }
  const rest = Object.keys(data.effective)
    .filter((key) => !COVERED.has(key))
    .sort()
    .map<OverviewRow>((key) => {
      const value = data.effective[key]
      const { source, before } = sourceOf(data, key)
      return {
        path: key,
        label: key,
        value: formatValue(value),
        title: fullText(value),
        source,
        before: source === 'billow' || source === 'override' ? formatValue(before) : undefined,
      }
    })
  if (rest.length) sections.push({ id: 'rest', title: '其他字段', rows: rest, folded: true })
  return sections
}

/** Rows matching a search needle by label, value or YAML key. */
export function filterOverview(sections: OverviewSection[], needle: string, source: OverviewSource | 'all' = 'all'): OverviewSection[] {
  const tokens = splitQueryTokens(needle)
  return sections
    .map((section) => ({
      ...section,
      rows: section.rows.filter(
        (row) =>
          (source === 'all' || row.source === source) &&
          matchesTokens(`${row.label} ${row.value} ${row.path}`, tokens),
      ),
    }))
    .filter((section) => section.rows.length)
}
