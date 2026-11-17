/**
 * System-proxy bypass entries only steer apps that honour the OS proxy. With TUN
 * every app reaches the kernel, so the same intent needs DIRECT rules; these
 * helpers translate the list into a `+rules` 覆写 block.
 */

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/

/** Mihomo rule for one bypass entry, or null when it has no rule form (`<local>`). */
export function bypassRule(entry: string): string | null {
  const item = entry.trim()
  if (!item || item === '<local>' || item === '<-loopback>') return null
  // 10.* / 172.16.* / 192.168.*: whole octets become a CIDR.
  const wildcardIp = /^(\d{1,3}(?:\.\d{1,3}){0,3})\.\*$/.exec(item)
  if (wildcardIp) {
    const octets = wildcardIp[1].split('.')
    const base = [...octets, '0', '0', '0', '0'].slice(0, 4).join('.')
    return `IP-CIDR,${base}/${octets.length * 8},DIRECT,no-resolve`
  }
  if (/^[\d.]+\/\d{1,2}$/.test(item)) return `IP-CIDR,${item},DIRECT,no-resolve`
  if (item.includes(':')) {
    const cidr = item.includes('/') ? item : `${item.replace(/^\[|\]$/g, '')}/128`
    return /^[0-9a-fA-F:]+\/\d{1,3}$/.test(cidr) ? `IP-CIDR6,${cidr},DIRECT,no-resolve` : null
  }
  if (IPV4.test(item)) return `IP-CIDR,${item}/32,DIRECT,no-resolve`
  const suffix = /^(?:\*\.|\+\.|\.)([^*]+)$/.exec(item)
  if (suffix) return `DOMAIN-SUFFIX,${suffix[1]},DIRECT`
  if (item.includes('*')) return `DOMAIN-WILDCARD,${item},DIRECT`
  if (!item.includes('.')) return `DOMAIN,${item},DIRECT`
  return `DOMAIN-SUFFIX,${item},DIRECT`
}

/** `+rules` 覆写 block for the bypass list; empty when nothing translates. */
export function bypassOverride(entries: readonly string[]): string {
  const rules = [...new Set(entries.map(bypassRule).filter((rule): rule is string => Boolean(rule)))]
  if (!rules.length) return ''
  return `# 由代理绕过列表生成：TUN 下这些地址也直连\n+rules:\n${rules.map((rule) => `  - ${rule}`).join('\n')}\n`
}
