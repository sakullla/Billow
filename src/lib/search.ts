export interface HighlightPart {
  text: string
  hit: boolean
}

/**
 * Splits a user search string into lowercase whitespace-delimited tokens,
 * preserving order and removing duplicates so multi-keyword queries like
 * "香港 iplc" or "chrome google" match naturally without regex escaping issues.
 */
export function splitQueryTokens(query: string): string[] {
  const trimmed = query.trim().toLowerCase()
  if (!trimmed) return []
  const seen = new Set<string>()
  const out: string[] = []
  for (const part of trimmed.split(/\s+/)) {
    if (part && !seen.has(part)) {
      seen.add(part)
      out.push(part)
    }
  }
  return out
}

/** True when every query token appears somewhere in `haystack` (case-insensitive). */
export function matchesTokens(haystack: string, tokens: readonly string[]): boolean {
  if (!tokens.length) return true
  const lower = haystack.toLowerCase()
  for (const token of tokens) {
    if (!lower.includes(token)) return false
  }
  return true
}

/**
 * Highlights all matched phrases and tokens in `text`. Adjacent or overlapping
 * matches are coalesced into single `<mark>` spans to keep DOM node counts minimal.
 */
export function highlightTokens(text: string, query: string): HighlightPart[] {
  const trimmed = query.trim().toLowerCase()
  if (!trimmed || !text) return [{ text, hit: false }]
  const tokens = splitQueryTokens(trimmed)
  const terms = (trimmed.includes(' ') ? [trimmed, ...tokens] : tokens).sort((a, b) => b.length - a.length)
  const lower = text.toLowerCase()

  const ranges: [number, number][] = []
  for (const term of terms) {
    if (!term) continue
    let from = 0
    let found = lower.indexOf(term, from)
    while (found >= 0) {
      ranges.push([found, found + term.length])
      from = found + term.length
      found = lower.indexOf(term, from)
    }
  }
  if (!ranges.length) return [{ text, hit: false }]

  ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1])
  const merged: [number, number][] = []
  for (const [start, end] of ranges) {
    const prev = merged[merged.length - 1]
    if (prev && start <= prev[1]) {
      if (end > prev[1]) prev[1] = end
    } else {
      merged.push([start, end])
    }
  }

  const parts: HighlightPart[] = []
  let cursor = 0
  for (const [start, end] of merged) {
    if (start > cursor) parts.push({ text: text.slice(cursor, start), hit: false })
    parts.push({ text: text.slice(start, end), hit: true })
    cursor = end
  }
  if (cursor < text.length) parts.push({ text: text.slice(cursor), hit: false })
  return parts
}
