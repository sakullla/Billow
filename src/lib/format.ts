const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

/** 1536 → "1.5 KB". Whole bytes stay integers; larger units keep up to one or two decimals. */
export function formatBytes(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value) || value < 0) return '—'
  let size = value
  let unit = 0
  while (size >= 1024 && unit < UNITS.length - 1) {
    size /= 1024
    unit += 1
  }
  if (unit === 0) return `${Math.round(size)} B`
  const digits = size >= 100 ? 0 : size >= 10 ? 1 : 2
  return `${size.toFixed(digits)} ${UNITS[unit]}`
}

export function formatSpeed(value: number | null | undefined): string {
  if (value == null) return '—'
  return `${formatBytes(value)}/s`
}

export function formatDate(seconds: number): string {
  const date = new Date(seconds * 1000)
  if (Number.isNaN(date.getTime())) return '—'
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
}

export function formatClock(ms: number): string {
  if (!ms) return ''
  const date = new Date(ms)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

/** "刚刚", "5 分钟前", "3 小时前", "2 天前", or a date for older times. */
export function formatRelative(ms: number | null | undefined, now = Date.now()): string {
  if (!ms) return '从未'
  const diff = Math.max(0, now - ms)
  const minute = 60_000
  const hour = 60 * minute
  const day = 24 * hour
  if (diff < minute) return '刚刚'
  if (diff < hour) return `${Math.floor(diff / minute)} 分钟前`
  if (diff < day) return `${Math.floor(diff / hour)} 小时前`
  if (diff < 30 * day) return `${Math.floor(diff / day)} 天前`
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
  if (seconds < 60) return `${seconds} 秒`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} 分`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} 时 ${minutes % 60} 分`
  return `${Math.floor(hours / 24)} 天`
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
  if (failed) return '超时'
  if (delay == null) return ''
  return `${delay} ms`
}

const PROTOCOL_LABELS: Record<string, string> = {
  ss: 'SS',
  ssr: 'SSR',
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
  direct: '直连',
  reject: '拒绝',
  select: '手选',
  selector: '手选',
  'url-test': '自动',
  urltest: '自动',
  fallback: '故障转移',
  'load-balance': '负载均衡',
  loadbalance: '负载均衡',
  relay: '链式',
}

export function protocolLabel(type: string): string {
  const key = type.trim().toLowerCase()
  if (!key) return ''
  return PROTOCOL_LABELS[key] ?? type
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
