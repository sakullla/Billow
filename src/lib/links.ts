import { inTauri } from './backend'

export const REPO_URL = 'https://github.com/sakullla/Billow'
/** Shown without the scheme; the link itself always opens the full URL. */
export const REPO_LABEL = 'github.com/sakullla/Billow'

/** Opens a page in the system browser; the browser preview falls back to a new tab. */
export async function openExternal(url: string): Promise<void> {
  if (inTauri()) {
    const { openUrl } = await import('@tauri-apps/plugin-opener')
    await openUrl(url)
    return
  }
  window.open(url, '_blank', 'noopener,noreferrer')
}

const NODE_SCHEME_RE = /^(vless|vmess|trojan|ss|hysteria2|hy2|tuic|anytls|socks5|socks):\/\//i
const HTTP_PROXY_CRED_RE = /^https?:\/\/[^/\s@]+@[^/\s]+$/i

/**
 * Heuristic check for whether user input looks like one or more custom proxy
 * node definitions (share URI, credentialed HTTP proxy, YAML proxy snippet,
 * or base64-encoded node list) rather than a remote subscription URL.
 */
export function looksLikeCustomNodeInput(raw: string): boolean {
  const trimmed = raw.trim()
  if (!trimmed) return false
  const lines = trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
  if (lines.some((line) => NODE_SCHEME_RE.test(line))) return true
  if (lines.length === 1 && HTTP_PROXY_CRED_RE.test(lines[0]!)) return true
  if (/^proxies\s*:/im.test(trimmed) || (/\btype\s*:/i.test(trimmed) && /\bserver\s*:/i.test(trimmed))) {
    return true
  }
  if (!/^https?:\/\//i.test(trimmed)) {
    const compact = trimmed.replace(/\s+/g, '')
    if (compact.length >= 16 && /^[A-Za-z0-9+/=_-]+$/.test(compact)) return true
  }
  return false
}
