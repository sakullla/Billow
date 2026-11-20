import { locale, tr, type Locale } from './i18n'
import type { ConnectionRow, NodeGroup, NodeItem } from './types'

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
const intlLocale = { en: 'en-US', 'zh-CN': 'zh-CN' } as const
const numbers: Record<Locale, Intl.NumberFormat[]> = { en: [], 'zh-CN': [] }
const collators: Partial<Record<Locale, Intl.Collator>> = {}
const dates: Partial<Record<Locale, Intl.DateTimeFormat>> = {}

/** Numbers follow the selected language (R42): grouping and decimal separators. */
export function formatNumber(value: number, digits = 0): string {
  const current = locale.value
  const cache = numbers[current]
  if (cache[digits]) return cache[digits].format(value)
  const formatter = new Intl.NumberFormat(intlLocale[current], {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  })
  // Byte and rate displays use only these precisions. Other callers can still
  // request any precision Intl supports without growing the shared cache.
  if (Number.isInteger(digits) && digits >= 0 && digits <= 2) cache[digits] = formatter
  return formatter.format(value)
}

/** Collation follows the selected language (R42): names sort as the reader expects. */
export function compareText(a: string, b: string): number {
  const current = locale.value
  const collator = collators[current] ??= new Intl.Collator(intlLocale[current], {
    numeric: true,
    sensitivity: 'base',
  })
  return collator.compare(a, b)
}

/** 1536 → "1.5 KB". Whole bytes stay integers; larger units keep up to one or two decimals. */
export function formatBytes(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value) || value < 0) return '—'
  let size = value
  let unit = 0
  while (size >= 1024 && unit < UNITS.length - 1) {
    size /= 1024
    unit += 1
  }
  if (unit === 0) return `${formatNumber(Math.round(size))} B`
  const digits = size >= 100 ? 0 : size >= 10 ? 1 : 2
  return `${formatNumber(size, digits)} ${UNITS[unit]}`
}

export function formatSpeed(value: number | null | undefined): string {
  if (value == null) return '—'
  return `${formatBytes(value)}/s`
}

/**
 * Narrow-slot speed (sidebar capsule): at most five characters plus a unit letter,
 * so the row never wraps or truncates; the full value lives in the tooltip.
 */
export function formatSpeedCompact(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value) || value < 0) return '—'
  const units = ['B', 'K', 'M', 'G', 'T']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  if (unit === 0) return `${Math.round(size)}B`
  const digits = size >= 100 ? 0 : size >= 10 ? 1 : 2
  return `${size.toFixed(digits)}${units[unit]}`
}

export function formatDate(seconds: number): string {
  const date = new Date(seconds * 1000)
  if (Number.isNaN(date.getTime())) return '—'
  // Both languages use an unambiguous numeric date, but in their own order (R42).
  const current = locale.value
  const formatter = dates[current] ??= new Intl.DateTimeFormat(intlLocale[current], {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  })
  return formatter.format(date)
}

export function formatClock(ms: number): string {
  if (!ms) return ''
  const date = new Date(ms)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

/** "刚刚", "5 分钟前", "3 小时前", "2 天前", or a date for older times. */
export function formatRelative(ms: number | null | undefined, now = Date.now()): string {
  if (!ms) return tr('从未')
  const diff = Math.max(0, now - ms)
  const minute = 60_000
  const hour = 60 * minute
  const day = 24 * hour
  if (diff < minute) return tr('刚刚')
  if (diff < hour) return tr('{0} 分钟前', { 0: Math.floor(diff / minute) })
  if (diff < day) return tr('{0} 小时前', { 0: Math.floor(diff / hour) })
  if (diff < 30 * day) return tr('{0} 天前', { 0: Math.floor(diff / day) })
  return formatDate(Math.floor(ms / 1000))
}

/** Days left until a unix-seconds expiry; negative when already expired. */
export function daysLeft(expireSeconds: number, now = Date.now()): number {
  return Math.ceil((expireSeconds * 1000 - now) / 86_400_000)
}

export function formatDuration(fromIso: string, now = Date.now()): string {
  const start = Date.parse(fromIso)
  if (Number.isNaN(start)) return ''
  const seconds = Math.max(0, Math.floor((now - start) / 1000))
  if (seconds < 60) return tr('{0} 秒', { 0: seconds })
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return tr('{0} 分', { 0: minutes })
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return tr('{0} 时 {1} 分', { 0: hours, 1: minutes % 60 })
  return tr('{0} 天', { 0: Math.floor(hours / 24) })
}

export type DelayTone = 'good' | 'fair' | 'poor' | 'fail' | 'none'

export function delayTone(delay: number | null, failed: boolean): DelayTone {
  if (failed) return 'fail'
  if (delay == null) return 'none'
  if (delay < 300) return 'good'
  if (delay < 800) return 'fair'
  return 'poor'
}

export function delayText(delay: number | null, failed: boolean): string {
  if (failed) return tr('超时')
  if (delay == null) return ''
  return `${delay} ms`
}

const PROTOCOL_LABELS: Record<string, string> = {
  ss: 'SS',
  ssr: 'SSR',
  // The controller API reports full type names ("Shadowsocks"); keep the same short tags as the config names.
  shadowsocks: 'SS',
  shadowsocksr: 'SSR',
  vmess: 'VMess',
  vless: 'VLESS',
  trojan: 'Trojan',
  hysteria: 'Hysteria',
  hysteria2: 'Hy2',
  tuic: 'TUIC',
  wireguard: 'WG',
  http: 'HTTP',
  socks5: 'SOCKS5',
  snell: 'Snell',
  anytls: 'AnyTLS',
  ssh: 'SSH',
  mieru: 'Mieru',
  direct: tr('直连'),
  reject: tr('拒绝'),
  select: tr('手选'),
  selector: tr('手选'),
  'url-test': tr('自动'),
  urltest: tr('自动'),
  fallback: tr('故障转移'),
  'load-balance': tr('负载均衡'),
  loadbalance: tr('负载均衡'),
  smart: tr('智能'),
  relay: tr('链式'),
}

export function protocolLabel(type: string): string {
  const key = type.trim().toLowerCase()
  if (!key) return ''
  return tr(PROTOCOL_LABELS[key] ?? type)
}

export interface GroupStrategy {
  /** Short tag, same wording as the group type label. */
  label: string
  icon: string
  /** One sentence on how the kernel picks the node, shown inside the group (R14). */
  hint: string
  /** Member order matters: fallback walks the list top-down. */
  ordered: boolean
}

const STRATEGIES: Record<string, GroupStrategy> = {
  'url-test': { label: tr('自动'), icon: 'url-test', hint: tr('内核定期测速，自动使用延迟最低的节点。'), ordered: false },
  fallback: { label: tr('故障转移'), icon: 'fallback', hint: tr('按顺序使用第一个可用的节点；前面的节点恢复后自动切回。'), ordered: true },
  'load-balance': { label: tr('负载均衡'), icon: 'load-balance', hint: tr('把连接分摊到多个节点，不固定使用某一个。'), ordered: false },
  smart: { label: tr('智能'), icon: 'sparkles', hint: tr('根据历史连接质量为不同站点自动挑选节点。'), ordered: false },
}
const STRATEGY_ALIASES: Record<string, string> = { urltest: 'url-test', loadbalance: 'load-balance' }

/** Group lists skip config `hidden: true`; chains still resolve through the full catalog (R29). */
export function listedGroups<T extends { hidden?: boolean }>(groups: readonly T[]): T[] {
  return groups.filter((group) => !group.hidden)
}

/** Select groups switch by hand; url-test / fallback pin the picked node until 恢复自动 (R28). */
export function canPickNode(group: { kind: string; pinnable?: boolean }): boolean {
  return group.kind === 'manual' || group.pinnable === true
}

/** How an automatic group chooses its node; null for hand-picked groups. */
export function groupStrategy(type: string): GroupStrategy | null {
  const key = type.trim().toLowerCase()
  const strategy = STRATEGIES[STRATEGY_ALIASES[key] ?? key]
  return strategy ? { ...strategy, label: tr(strategy.label), hint: tr(strategy.hint) } : null
}

/**
 * Follow `now` through nested groups (节点选择 → 自动选择 → 香港 01) so the UI can
 * name the server that actually carries traffic. When the resolved server itself
 * declares a `dialer-proxy`, its upstream transit hop is placed right before it.
 */
export function resolveChain(
  start: string,
  groups: readonly { name: string; now: string; nodes?: readonly { name: string; dialer_proxy?: string | null }[] }[],
): string[] {
  const byName = new Map(groups.map((group) => [group.name, group]))
  const chain: string[] = []
  let current = byName.get(start)?.now ?? ''
  while (current && !chain.includes(current) && chain.length < 8) {
    chain.push(current)
    current = byName.get(current)?.now ?? ''
  }
  const dialerByNode = new Map<string, string>()
  for (const group of groups) {
    for (const node of group.nodes ?? []) {
      if (node.dialer_proxy && !dialerByNode.has(node.name)) {
        dialerByNode.set(node.name, node.dialer_proxy)
      }
    }
  }
  if (chain.length > 0 && dialerByNode.size > 0) {
    const pre: string[] = []
    let cursor = dialerByNode.get(chain[chain.length - 1]!) ?? ''
    const seen = new Set(chain)
    while (cursor && !seen.has(cursor) && pre.length < 4) {
      seen.add(cursor)
      const resolvedGroup = byName.get(cursor)
      if (resolvedGroup) {
        const sub = resolveChain(cursor, groups)
        const server = sub[sub.length - 1]
        if (server && !seen.has(server)) {
          seen.add(server)
          pre.unshift(server)
          cursor = dialerByNode.get(server) ?? ''
          continue
        }
      }
      pre.unshift(cursor)
      cursor = dialerByNode.get(cursor) ?? ''
    }
    if (pre.length > 0) {
      chain.splice(chain.length - 1, 0, ...pre)
    }
  }
  return chain
}

/**
 * Resolves the delay of a group's active exit node, following nested groups so
 * policy groups like `Telegram → Available → 香港 01` inherit `香港 01`'s latency.
 */
export function effectiveGroupDelay(
  group: NodeGroup,
  catalog: readonly NodeGroup[],
  liveResults: Readonly<Record<string, { delay: number | null; failed: boolean }>> = {},
): { delay: number | null; failed: boolean; target: string } {
  const chain = resolveChain(group.name, catalog)
  const target = chain[chain.length - 1] || group.now
  if (!target || ['direct', 'reject', 'reject-drop'].includes(target.toLowerCase())) {
    return { delay: null, failed: false, target: '' }
  }
  const live = liveResults[target]
  if (live) return { delay: live.delay, failed: live.failed, target }
  const direct: NodeItem | undefined = group.nodes.find((node) => node.name === target)
  if (direct && (direct.delay_ms != null || direct.failed)) {
    return { delay: direct.delay_ms, failed: direct.failed, target }
  }
  for (const item of catalog) {
    const found = item.nodes.find((node) => node.name === target && (node.delay_ms != null || node.failed))
    if (found) return { delay: found.delay_ms, failed: found.failed, target }
  }
  return { delay: direct?.delay_ms ?? null, failed: direct?.failed ?? false, target }
}

const MULTI_PART_TLDS = new Set([
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'com.hk', 'edu.hk', 'gov.hk', 'org.hk', 'net.hk',
  'com.tw', 'org.tw', 'net.tw', 'gov.tw', 'edu.tw',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'co.kr', 'or.kr', 'ne.kr', 'go.kr',
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk',
  'com.au', 'net.au', 'org.au', 'edu.au',
  'com.sg', 'edu.sg', 'gov.sg',
  'co.nz', 'com.br', 'co.in',
])

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/

/** Strip port from `host:443` or `[2001:db8::1]:443`. */
export function stripEndpointPort(raw: string): string {
  const text = raw.trim()
  if (!text) return ''
  if (text.startsWith('[')) {
    const close = text.indexOf(']')
    return close > 1 ? text.slice(1, close) : text
  }
  const firstColon = text.indexOf(':')
  const lastColon = text.lastIndexOf(':')
  if (firstColon > 0 && firstColon === lastColon) {
    return text.slice(0, firstColon)
  }
  return text
}

/** True when `ip` falls inside Mihomo's standard Fake-IP pools (`198.18.0.0/15`, `fc00::/18`). */
export function isFakeIp(ip: string): boolean {
  const clean = stripEndpointPort(ip).toLowerCase()
  if (!clean) return false
  if (clean.startsWith('198.18.') || clean.startsWith('198.19.')) return true
  if (clean.startsWith('fc00:')) return true
  return false
}

export function extractEndpointIp(raw: string): { ip: string; v6: boolean } | null {
  const host = stripEndpointPort(raw)
  if (!host) return null
  if (IPV4_RE.test(host)) return { ip: host, v6: false }
  if (host.includes(':') && /^[0-9a-fA-F:.]+$/.test(host)) return { ip: host, v6: true }
  return null
}

export function extractCleanDomain(raw: string): string {
  const host = stripEndpointPort(raw).toLowerCase().replace(/\.+$/, '')
  if (!host || IPV4_RE.test(host) || host.includes(':') || /[\s/]/.test(host)) return ''
  return host
}

export function registrableDomain(domain: string): string {
  const clean = extractCleanDomain(domain)
  if (!clean) return ''
  const parts = clean.split('.').filter(Boolean)
  if (parts.length <= 2) return clean
  const tail2 = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`
  if (MULTI_PART_TLDS.has(tail2) && parts.length >= 3) {
    return `${parts[parts.length - 3]}.${tail2}`
  }
  return tail2
}

export function processBasename(raw: string): string {
  const trimmed = raw.trim()
  if (!trimmed) return ''
  const parts = trimmed.split(/[\\/]/)
  return parts[parts.length - 1]?.trim() || trimmed
}

export interface GeneratedRule {
  id: string
  label: string
  rule: string
}

/** Ready-to-use Mihomo routing rules derived from a live or closed connection. */
export function connectionRules(row: ConnectionRow, policy: string): GeneratedRule[] {
  const target = policy.trim() || 'DIRECT'
  const out: GeneratedRule[] = []
  const seen = new Set<string>()
  const push = (id: string, label: string, rule: string) => {
    if (seen.has(rule)) return
    seen.add(rule)
    out.push({ id, label, rule })
  }
  const domain = extractCleanDomain(row.host)
  if (domain) {
    const root = registrableDomain(domain)
    if (root && domain.includes('.')) {
      push('domain-suffix', root === domain ? tr('域名后缀') : tr('根域名后缀'), `DOMAIN-SUFFIX,${root},${target}`)
    }
    if (domain !== root || !domain.includes('.')) {
      push('domain', tr('精确域名'), `DOMAIN,${domain},${target}`)
    } else {
      push('domain', tr('精确域名'), `DOMAIN,${domain},${target}`)
    }
  }
  const ipInfo = extractEndpointIp(row.destination) ?? extractEndpointIp(row.host)
  if (ipInfo && !isFakeIp(ipInfo.ip)) {
    const kind = ipInfo.v6 ? 'IP-CIDR6' : 'IP-CIDR'
    const mask = ipInfo.v6 ? '128' : '32'
    push('ip-cidr', tr('目标 IP'), `${kind},${ipInfo.ip}/${mask},${target},no-resolve`)
  }
  const proc = processBasename(row.process)
  if (proc) {
    push('process', tr('进程名'), `PROCESS-NAME,${proc},${target}`)
  }
  return out
}

const INFO_NODE_PATTERNS = [
  /剩余流量|已用流量|总流量|套餐到期|到期时间|过期时间|下次重置|距离.*重置|重置剩余|官网/,
  /expire\s*(date|time|at)?\s*[:：]|traffic\s*reset|remaining\s*traffic|days?\s*left/i,
  /\d+(\.\d+)?\s*[KMGT]i?B\s*[|/]\s*\d+(\.\d+)?\s*[KMGT]i?B/i,
]

/**
 * Subscriptions often smuggle quota and expiry text in as fake nodes
 * ("Traffic Reset: 17 Days Left", "4.49 GB | 500 GB"). They are not servers, so
 * the proxy page lifts them into an info line instead of the node grid.
 */
export function isInfoNode(name: string): boolean {
  return INFO_NODE_PATTERNS.some((pattern) => pattern.test(name))
}

/** Group type label shared by the home cards and the proxy page (R1). */
export function groupTypeLabel(group: { group_type: string; kind: string }): string {
  return protocolLabel(group.group_type) || (group.kind === 'manual' ? tr('手选') : tr('自动'))
}

/**
 * Badge text for a group's strategy. Plain select groups are the norm and carry no badge;
 * only automatic strategies (自动选择、故障转移、负载均衡…) are worth calling out.
 */
export function autoTypeLabel(group: { group_type: string; kind: string }): string {
  return group.kind === 'manual' ? '' : groupTypeLabel(group)
}

/**
 * Airport names often lead with a provider tag such as 【KLM】 or [LOCAL]. Splitting it off
 * lets the UI dim the tag so the region and line number stay readable.
 */
export function splitNodePrefix(name: string): { prefix: string; rest: string } {
  const match = /^(\s*[【[][^】\]]{1,16}[】\]]\s*)(\S.*)$/u.exec(name)
  return match ? { prefix: match[1]!, rest: match[2]! } : { prefix: '', rest: name }
}

export function usagePercent(used: number | null, total: number | null): number | null {
  if (used == null || total == null || total <= 0) return null
  return Math.min(100, Math.max(0, (used / total) * 100))
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return url
  }
}
