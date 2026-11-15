/**
 * Rule toggle keys shared by the demo backend and tests. Production keys come
 * from Rust so they are computed over the full config rule list; this helper
 * mirrors that format without importing the backend module.
 */

export interface RuleIdentity {
  kind: string
  payload: string
  proxy: string
}

export function normalizeRuleKind(kind: string): string {
  return kind.toLowerCase().replace(/[^a-z0-9]/g, '')
}

export function ruleKey(
  kind: string,
  payload: string,
  proxy: string,
  occurrence: number,
): string {
  return `${normalizeRuleKind(kind)}|${payload.trim()}|${proxy.trim()}|${occurrence}`
}

/** Keys in list order, counting duplicate identities as separate occurrences. */
export function ruleKeys(rules: RuleIdentity[]): string[] {
  const seen = new Map<string, number>()
  return rules.map((rule) => {
    const base = `${normalizeRuleKind(rule.kind)}|${rule.payload.trim()}|${rule.proxy.trim()}`
    const occurrence = seen.get(base) ?? 0
    seen.set(base, occurrence + 1)
    return `${base}|${occurrence}`
  })
}
