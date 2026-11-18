const PREPEND_HEADER_RE = /^(\+rules|prepend-rules)\s*:\s*(?:#.*)?$/
const LIST_ITEM_RE = /^(\s*)-\s+(.+?)\s*$/

function parseAppendedRules(append: string): string[] | null {
  const lines = append
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'))
  if (lines.length < 2 || !PREPEND_HEADER_RE.test(lines[0]!)) return null
  const rules: string[] = []
  for (let i = 1; i < lines.length; i += 1) {
    const match = /^-\s+(.+)$/.exec(lines[i]!)
    if (!match) return null
    const rule = match[1]!.trim()
    if (rule && !rules.includes(rule)) rules.push(rule)
  }
  return rules.length ? rules : null
}

function unquoteScalar(raw: string): string {
  const trimmed = raw.trim()
  if (
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2) ||
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2)
  ) {
    return trimmed.slice(1, -1).trim()
  }
  return trimmed.replace(/\s+#.*$/, '').trim()
}

/**
 * Merges a `+rules:` snippet into an existing YAML override without producing
 * duplicate top-level `+rules:` keys or duplicate rule entries.
 */
export function mergeOverrideAppend(
  existing: string,
  append: string,
): { text: string; added: number; changed: boolean } {
  const incoming = parseAppendedRules(append)
  if (!existing.trim()) {
    return {
      text: append,
      added: incoming ? incoming.length : append.trim() ? 1 : 0,
      changed: Boolean(append.trim()),
    }
  }
  if (!incoming) {
    const next = `${existing.replace(/\s*$/, '')}\n\n${append}`
    return { text: next, added: 1, changed: true }
  }

  const lines = existing.split(/\r?\n/)
  const headerIdx = lines.findIndex((line) => PREPEND_HEADER_RE.test(line))
  if (headerIdx === -1) {
    const next = `${existing.replace(/\s*$/, '')}\n\n${append}`
    return { text: next, added: incoming.length, changed: true }
  }

  const present = new Set<string>()
  let insertAfter = headerIdx
  let itemIndent = '  '

  for (let i = headerIdx + 1; i < lines.length; i += 1) {
    const line = lines[i]!
    const trimmed = line.trim()
    if (!trimmed) continue
    if (trimmed.startsWith('#')) {
      if (/^\s+/.test(line)) insertAfter = i
      continue
    }
    const itemMatch = LIST_ITEM_RE.exec(line)
    if (itemMatch) {
      itemIndent = itemMatch[1] || '  '
      present.add(unquoteScalar(itemMatch[2]!))
      insertAfter = i
      continue
    }
    if (/^\S/.test(line)) break
  }

  const fresh = incoming.filter((rule) => !present.has(unquoteScalar(rule)))
  if (!fresh.length) {
    return { text: existing, added: 0, changed: false }
  }

  const addition = fresh.map((rule) => `${itemIndent}- ${rule}`)
  const merged = [...lines.slice(0, insertAfter + 1), ...addition, ...lines.slice(insertAfter + 1)]
  return {
    text: merged.join('\n'),
    added: fresh.length,
    changed: true,
  }
}
