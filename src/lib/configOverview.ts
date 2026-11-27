import { tr } from './i18n'
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
  /** Row to scroll to and highlight (`data-setting` id). */
  focus?: string
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
const at = (tab: SettingsTab, focus?: string): OverviewTarget => ({ page: 'settings', tab, focus })
const DNS: OverviewTarget = { page: 'settings', tab: 'dns' }
const TUN: OverviewTarget = { page: 'settings', tab: 'tun' }
const RESOURCES: OverviewTarget = { page: 'resources' }

const ENUMS: Record<string, string> = {
  rule: tr('规则'),
  global: tr('全局'),
  direct: tr('直连'),
  debug: tr('调试'),
  info: tr('信息'),
  warning: tr('警告'),
  error: tr('错误'),
  silent: tr('静默'),
  always: tr('始终'),
  strict: tr('自动'),
  off: tr('关闭'),
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
    typeof value === 'string' ? tr(labels[value.toLowerCase()] ?? value) : formatValue(value)
const loader = pick({ memconservative: tr('低内存'), standard: tr('标准') })
const filterMode = pick({ blacklist: tr('黑名单'), whitelist: tr('白名单'), rule: tr('规则') })
const tunDns = pick({ disabled: tr('不设置'), native: tr('指向 TUN'), hijack: tr('指向 TUN 并拦截') })

const FINGERPRINTS: Record<string, string> = {
  chrome: 'Chrome',
  firefox: 'Firefox',
  safari: 'Safari',
  ios: 'iOS',
  android: 'Android',
  edge: 'Edge',
  '360': '360',
  qq: 'QQ',
  random: tr('随机'),
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

/** Generic display: booleans as 开启/关闭, short lists inline, maps as a count. */
export function formatValue(value: unknown): string {
  if (value === undefined || value === null || value === '') return tr('未设置')
  if (typeof value === 'boolean') return value ? tr('开启') : tr('关闭')
  if (typeof value === 'number') return String(value)
  if (typeof value === 'string') return tr(ENUMS[value.toLowerCase()] ?? value)
  if (Array.isArray(value)) {
    if (!value.length) return tr('无')
    const items = value.map((item) => (typeof item === 'string' || typeof item === 'number' ? String(item) : JSON.stringify(item)))
    return items.length > 3 ? tr('{0} 等 {1} 项', { 0: items.slice(0, 3).join('、'), 1: items.length }) : items.join('、')
  }
  if (isRecord(value)) {
    const size = Object.keys(value).length
    return size ? tr('{0} 项', { 0: size }) : tr('无')
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

const entries: Format = (value) => (isRecord(value) ? tr('{0} 条', { 0: Object.keys(value).length }) : formatValue(value))
const seconds: Format = (value) => (typeof value === 'number' ? tr('{0} 秒', { 0: value }) : formatValue(value))
const hours: Format = (value) => (typeof value === 'number' ? tr('{0} 小时', { 0: value }) : formatValue(value))
/** mihomo removed the global fingerprint (v1.19.34 logs an error and ignores it); profiles may still carry it. */
const removedFingerprint: Format = (value) =>
  tr('{0}（内核已移除，不生效）', { 0: typeof value === 'string' ? tr(FINGERPRINTS[value.toLowerCase()] ?? value) : formatValue(value) })
const users: Format = (value) => {
  if (!Array.isArray(value) || !value.length) return formatValue(value)
  const names = value.map((item) => String(item).split(':')[0])
  return names.length > 2 ? tr('{0} 等 {1} 个用户', { 0: names.slice(0, 2).join('、'), 1: names.length }) : names.join('、')
}
/** mihomo reads port 0 as a listener that stays off. */
const port: Format = (value) => (value === 0 ? tr('关闭') : formatValue(value))
const sniffs: Format = (value) => (isRecord(value) ? Object.keys(value).join('、') || tr('无') : formatValue(value))
const geodata: Format = (value) => (value === true ? 'dat（GeoIP / GeoSite）' : value === false ? 'mmdb' : formatValue(value))

const SECTIONS: { id: string; title: string; fields: Field[]; desktopOnly?: boolean }[] = [
  {
    id: 'inbound',
    get title() { return tr('入站') },
    fields: [
      { path: 'mixed-port', get label() { return tr('混合端口') }, to: at('network', 'mixed-port') },
      { path: 'port', get label() { return tr('HTTP 端口') }, format: port, to: at('network', 'extra-ports') },
      { path: 'socks-port', get label() { return tr('SOCKS5 端口') }, format: port, to: at('network', 'extra-ports') },
      { path: 'redir-port', get label() { return tr('透明代理端口') }, format: port, to: at('network', 'extra-ports') },
      { path: 'tproxy-port', get label() { return tr('TProxy 端口') }, format: port, to: at('network', 'extra-ports') },
      { path: 'allow-lan', get label() { return tr('局域网连接') }, get fallback() { return tr('关闭') }, to: at('network', 'allow-lan') },
      { path: 'bind-address', get label() { return tr('监听地址') } },
      { path: 'lan-allowed-ips', get label() { return tr('允许的来源') }, to: at('network', 'lan-access') },
      { path: 'lan-disallowed-ips', get label() { return tr('禁止的来源') } },
      { path: 'authentication', get label() { return tr('访问认证') }, format: users, to: at('network', 'lan-access') },
      { path: 'skip-auth-prefixes', get label() { return tr('免认证来源') } },
    ],
  },
  {
    id: 'outbound',
    get title() { return tr('出站') },
    fields: [
      { path: 'mode', get label() { return tr('出站模式') }, get fallback() { return tr('规则') }, to: { page: 'home' } },
      { path: 'global-client-fingerprint', get label() { return tr('全局 TLS 指纹') }, format: removedFingerprint },
      { path: 'keep-alive-interval', get label() { return tr('TCP 保活间隔') }, format: seconds, to: at('network', 'keep-alive') },
      { path: 'keep-alive-idle', get label() { return tr('TCP 保活空闲') }, format: seconds },
      { path: 'disable-keep-alive', get label() { return tr('关闭 TCP 保活') }, to: at('network', 'keep-alive') },
      { path: 'interface-name', get label() { return tr('出口网卡') }, to: at('network', 'extra-ports') },
      { path: 'routing-mark', get label() { return tr('路由标记') }, to: at('network', 'extra-ports') },
    ],
  },
  {
    id: 'dns',
    title: 'DNS',
    fields: [
      { path: 'dns.enable', get label() { return tr('内置 DNS') }, get fallback() { return tr('关闭') }, to: DNS },
      { path: 'dns.enhanced-mode', get label() { return tr('域名映射') }, to: at('dns', 'dns-mode') },
      { path: 'dns.listen', get label() { return tr('监听地址') }, to: at('dns', 'dns-listen') },
      { path: 'dns.nameserver', get label() { return tr('主 DNS') }, to: at('dns', 'dns-nameserver') },
      { path: 'dns.default-nameserver', get label() { return tr('引导 DNS') }, to: at('dns', 'dns-default-nameserver') },
      { path: 'dns.fallback', get label() { return tr('备用 DNS') }, to: at('dns', 'dns-fallback') },
      { path: 'dns.proxy-server-nameserver', get label() { return tr('节点域名解析') }, to: at('dns', 'dns-proxy-nameserver') },
      { path: 'dns.nameserver-policy', get label() { return tr('解析策略') }, format: entries, to: at('dns', 'dns-policy') },
      { path: 'dns.fake-ip-range', get label() { return tr('Fake-IP 地址段') }, to: at('dns', 'dns-fake-ip-range') },
      { path: 'dns.fake-ip-filter-mode', get label() { return tr('Fake-IP 过滤模式') }, format: filterMode, to: at('dns', 'dns-filter-mode') },
      { path: 'dns.respect-rules', get label() { return tr('遵循分流规则') }, to: at('dns', 'dns-respect-rules') },
      { path: 'hosts', label: 'Hosts', format: entries, to: at('dns', 'dns-hosts') },
    ],
  },
  {
    id: 'tun',
    title: 'TUN',
    desktopOnly: true,
    fields: [
      { path: 'tun.enable', get label() { return tr('TUN 模式') }, get fallback() { return tr('关闭') }, to: TUN },
      { path: 'tun.stack', get label() { return tr('协议栈') }, get fallback() { return tr('内核默认（Mips）') }, to: at('tun', 'tun-stack') },
      { path: 'tun.dns-mode', get label() { return tr('系统 DNS') }, format: tunDns },
      { path: 'tun.auto-route', get label() { return tr('自动路由') }, to: at('tun', 'tun-auto-route') },
      { path: 'tun.strict-route', get label() { return tr('严格路由') }, to: at('tun', 'tun-strict-route') },
      { path: 'tun.dns-hijack', get label() { return tr('DNS 劫持') }, to: at('tun', 'tun-dns-hijack') },
      { path: 'tun.mtu', label: 'MTU', to: at('tun', 'tun-mtu') },
      { path: 'tun.device', get label() { return tr('网卡名称') }, to: at('tun', 'tun-device') },
      { path: 'tun.route-address', get label() { return tr('只走 TUN 的地址') }, to: at('tun', 'tun-route-include') },
      { path: 'tun.route-exclude-address', get label() { return tr('不走 TUN 的地址') }, to: at('tun', 'tun-route-exclude') },
    ],
  },
  {
    id: 'sniff',
    get title() { return tr('嗅探与 GEO') },
    fields: [
      { path: 'sniffer.enable', get label() { return tr('域名嗅探') }, get fallback() { return tr('关闭') }, to: at('behavior', 'sniffer') },
      { path: 'sniffer.sniff', get label() { return tr('嗅探协议') }, format: sniffs },
      { path: 'sniffer.sniff.HTTP.ports', get label() { return tr('HTTP 嗅探端口') }, to: at('behavior', 'sniffer-options') },
      { path: 'sniffer.sniff.TLS.ports', get label() { return tr('TLS 嗅探端口') }, to: at('behavior', 'sniffer-options') },
      { path: 'sniffer.sniff.QUIC.ports', get label() { return tr('QUIC 嗅探端口') }, to: at('behavior', 'sniffer-options') },
      { path: 'sniffer.force-domain', get label() { return tr('强制嗅探域名') }, to: at('behavior', 'sniffer-options') },
      { path: 'sniffer.skip-domain', get label() { return tr('跳过嗅探域名') }, to: at('behavior', 'sniffer-options') },
      { path: 'sniffer.override-destination', get label() { return tr('嗅探结果覆盖目标') }, to: at('behavior', 'sniffer-options') },
      { path: 'geodata-mode', get label() { return tr('GeoIP 格式') }, format: geodata, fallback: 'mmdb', to: RESOURCES },
      { path: 'geodata-loader', get label() { return tr('GEO 加载方式') }, format: loader, get fallback() { return tr('低内存') }, to: RESOURCES },
      { path: 'geo-auto-update', get label() { return tr('自动更新 GEO') }, to: RESOURCES },
      { path: 'geo-update-interval', get label() { return tr('GEO 更新间隔') }, format: hours, to: RESOURCES },
      { path: 'geox-url', get label() { return tr('GEO 下载地址') }, format: entries, to: RESOURCES },
    ],
  },
  {
    id: 'misc',
    get title() { return tr('运行') },
    fields: [
      { path: 'log-level', get label() { return tr('日志级别') }, get fallback() { return tr('信息') }, to: at('kernel', 'log-level') },
      { path: 'ipv6', label: 'IPv6', get fallback() { return tr('开启') }, to: at('network', 'ipv6') },
      { path: 'unified-delay', get label() { return tr('统一延迟') }, get fallback() { return tr('关闭') }, to: at('behavior', 'unified-delay') },
      { path: 'tcp-concurrent', get label() { return tr('TCP 并发') }, get fallback() { return tr('关闭') }, to: at('network', 'tcp-concurrent') },
      { path: 'find-process-mode', get label() { return tr('进程匹配') }, get fallback() { return tr('自动') }, to: at('behavior', 'process-mode') },
      { path: 'global-ua', get label() { return tr('外部资源 UA') } },
      { path: 'etag-support', get label() { return tr('ETag 缓存') } },
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
  return { path: key, label, value: detail ? tr('{0} 个 · {1}', { 0: count, 1: detail }) : tr('{0} 个', { 0: count }), source: 'profile', to }
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
        before: source === 'billow' || source === 'override' ? (before === undefined ? tr('未设置') : format(before)) : undefined,
        // Android owns routing and DNS hijack; those settings pages do not exist there.
        to: options.android && field.to?.tab === 'tun' ? undefined : field.to,
      })
    }
    if (section.id === 'outbound') {
      const counted = [
        countRow(data, 'proxies', tr('节点'), { page: 'proxies' }),
        countRow(data, 'proxy-groups', tr('代理组'), { page: 'proxies' }, groupDetail(data.group_types)),
        countRow(data, 'proxy-providers', tr('代理集'), RESOURCES),
        countRow(data, 'rules', tr('规则'), { page: 'rules' }),
        countRow(data, 'rule-providers', tr('规则集'), RESOURCES),
      ].filter((row): row is OverviewRow => row !== null)
      rows.splice(1, 0, ...counted)
    }
    if (section.id === 'inbound') {
      const listeners = countRow(data, 'listeners', tr('额外监听'), KERNEL)
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
  if (rest.length) sections.push({ id: 'rest', get title() { return tr('其他字段') }, rows: rest, folded: true })
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
