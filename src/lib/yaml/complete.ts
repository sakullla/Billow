/**
 * Mihomo-aware YAML completion, independent of the editor. It reads the block
 * structure above the cursor (indentation, `- ` items, compact sequences) to
 * find the key path, then offers keys, fixed values, rule types or proxy/group
 * names from the schema. Flow mappings are only read for names.
 */
import { BUILTIN_TARGETS, RULE_TYPES, resolve, type SchemaNode } from './schema'

export interface CompletionOption {
  label: string
  /** Text inserted in place of the typed prefix; defaults to the label. */
  apply?: string
  detail?: string
  type: 'property' | 'enum' | 'keyword' | 'variable' | 'constant'
}

export interface CompletionResult {
  from: number
  options: CompletionOption[]
}

export interface KnownNames {
  proxies?: readonly string[]
  groups?: readonly string[]
  ruleProviders?: readonly string[]
}

interface Frame {
  col: number
  seg: string
}

interface LineShape {
  /** Column of the first character after indentation and any `- ` markers. */
  col: number
  /** Columns of each `- ` marker on the line (nested `- - x` is rare but legal). */
  dashes: number[]
  key: string | null
  value: string
}

const KEY_LINE = /^([^\s#'"{[][^:#]*?|"[^"]*"|'[^']*'):(?:\s+(.*)|$)/

function shape(line: string): LineShape {
  let col = 0
  while (line[col] === ' ') col += 1
  const dashes: number[] = []
  while (line[col] === '-' && (line[col + 1] === ' ' || col + 1 === line.length)) {
    dashes.push(col)
    col += 1
    while (line[col] === ' ') col += 1
  }
  const rest = line.slice(col)
  const match = KEY_LINE.exec(rest)
  if (!match) return { col, dashes, key: null, value: rest }
  const key = match[1].replace(/^(['"])(.*)\1$/, '$2').trim()
  return { col, dashes, key, value: (match[2] ?? '').replace(/\s+#.*$/, '') }
}

function isSkippable(line: string): boolean {
  const trimmed = line.trim()
  return trimmed === '' || trimmed.startsWith('#') || trimmed === '---'
}

/** Push one line onto the block stack (frames are parent keys and `[]` items). */
function step(stack: Frame[], info: LineShape) {
  for (const dash of info.dashes) {
    // A dash closes deeper frames and the previous item at its column, but keeps a
    // key at the same column: `rules:\n- MATCH,DIRECT` is a valid compact sequence.
    while (stack.length && (stack[stack.length - 1].col > dash || (stack[stack.length - 1].col === dash && stack[stack.length - 1].seg === '[]'))) stack.pop()
    stack.push({ col: dash, seg: '[]' })
  }
  if (info.key != null) {
    while (stack.length && stack[stack.length - 1].col >= info.col) stack.pop()
    stack.push({ col: info.col, seg: info.key })
  } else if (!info.dashes.length) {
    while (stack.length && stack[stack.length - 1].col >= info.col) stack.pop()
  }
}

function pathOf(stack: Frame[]): string[] {
  return stack.map((frame) => frame.seg)
}

/** Proxy, group and rule-provider names declared in the document itself. */
export function collectNames(text: string): Required<KnownNames> {
  const proxies: string[] = []
  const groups: string[] = []
  const ruleProviders: string[] = []
  const stack: Frame[] = []
  for (const line of text.split('\n')) {
    if (isSkippable(line)) continue
    const info = shape(line)
    step(stack, info)
    const path = pathOf(stack)
    const top = path.join('.')
    if (info.key === 'name' && (top === 'proxies.[].name' || top === 'proxy-groups.[].name')) {
      const name = info.value.replace(/^(['"])(.*)\1$/, '$2').trim()
      if (name) (top.startsWith('proxies') ? proxies : groups).push(name)
    } else if (info.dashes.length && info.key == null && (top === 'proxies.[]' || top === 'proxy-groups.[]')) {
      // Flow style, common in subscriptions: `- {name: 香港 01, type: ss, ...}`.
      const match = /name:\s*(['"]?)([^,'"}]+)\1/.exec(info.value)
      if (match) (top.startsWith('proxies') ? proxies : groups).push(match[2].trim())
    } else if (info.key != null && path.length === 2 && path[0] === 'rule-providers') {
      ruleProviders.push(info.key)
    }
  }
  return { proxies, groups, ruleProviders }
}

function unique(values: Iterable<string>): string[] {
  return [...new Set(values)].filter(Boolean)
}

function startsWith(label: string, prefix: string): boolean {
  return !prefix || label.toLowerCase().startsWith(prefix.toLowerCase()) || label.toLowerCase().includes(prefix.toLowerCase())
}

function quoteName(name: string): string {
  return /^[\w一-龥 .-]+$/.test(name) && !/^\s|\s$/.test(name) ? name : JSON.stringify(name)
}

function keyOptions(node: SchemaNode, indent: number, prefix: string, siblings: Set<string>): CompletionOption[] {
  const pad = ' '.repeat(indent + 2)
  return Object.entries(node.keys ?? {})
    .filter(([key]) => !siblings.has(key) && startsWith(key, prefix))
    .map(([key, child]) => {
      let apply = `${key}: `
      if (child.keys && Object.keys(child.keys).length) apply = `${key}:\n${pad}`
      else if (child.item) apply = `${key}:\n${pad}- `
      return { label: key, apply, detail: child.doc, type: 'property' as const }
    })
}

function valueOptions(node: SchemaNode, names: Required<KnownNames>, prefix: string): CompletionOption[] {
  if (node.values) {
    return node.values.filter((value) => startsWith(value, prefix)).map((value) => ({
      label: value,
      type: value === 'true' || value === 'false' ? ('keyword' as const) : ('enum' as const),
    }))
  }
  if (node.names) return nameOptions(node.names, names, prefix)
  return []
}

function nameOptions(kind: 'proxies' | 'groups' | 'targets', names: Required<KnownNames>, prefix: string): CompletionOption[] {
  const groups = unique(names.groups).map((label) => ({ label, detail: '代理组', type: 'variable' as const }))
  const proxies = unique(names.proxies).map((label) => ({ label, detail: '节点', type: 'variable' as const }))
  const builtins = BUILTIN_TARGETS.map((label) => ({ label, detail: '内置', type: 'constant' as const }))
  const all = kind === 'groups' ? groups : kind === 'proxies' ? proxies : [...groups, ...builtins, ...proxies]
  const seen = new Set<string>()
  return all
    .filter((option) => !seen.has(option.label) && seen.add(option.label) && startsWith(option.label, prefix))
    .map((option) => ({ ...option, apply: quoteName(option.label) }))
}

const IP_RULES = new Set(['IP-CIDR', 'IP-CIDR6', 'IP-SUFFIX', 'IP-ASN', 'GEOIP'])

function ruleOptions(body: string, bodyFrom: number, names: Required<KnownNames>): CompletionResult | null {
  const parts = body.split(',')
  const index = parts.length - 1
  const prefix = parts[index].trimStart()
  const from = bodyFrom + body.length - prefix.length
  const type = parts[0].trim().toUpperCase()
  if (index === 0) {
    return {
      from,
      options: RULE_TYPES.filter((rule) => startsWith(rule, prefix)).map((rule) => ({
        label: rule,
        apply: rule === 'MATCH' ? 'MATCH,' : `${rule},`,
        detail: '规则类型',
        type: 'keyword',
      })),
    }
  }
  if ((index === 1 && type === 'MATCH') || index === 2) {
    return { from, options: nameOptions('targets', names, prefix) }
  }
  if (index === 1 && type === 'RULE-SET') {
    return {
      from,
      options: unique(names.ruleProviders)
        .filter((name) => startsWith(name, prefix))
        .map((label) => ({ label, apply: `${label},`, detail: '规则集', type: 'variable' })),
    }
  }
  if (index === 3 && IP_RULES.has(type)) {
    return { from, options: [{ label: 'no-resolve', detail: '不为匹配解析域名', type: 'keyword' }].filter((option) => startsWith(option.label, prefix)) as CompletionOption[] }
  }
  return null
}

/**
 * Completions at `pos`. `known` adds names from outside the document (e.g. the
 * profile an override applies to); names declared in the text are always used.
 */
export function complete(text: string, pos: number, known: KnownNames = {}): CompletionResult | null {
  const result = completeRaw(text, pos, known)
  if (!result) return null
  const typed = text.slice(result.from, pos).toLowerCase()
  // Prefix matches first, then substring matches, each in schema order.
  const rank = (option: CompletionOption) => (option.label.toLowerCase().startsWith(typed) ? 0 : 1)
  const options = result.options.map((option, index) => ({ option, index }))
  options.sort((a, b) => rank(a.option) - rank(b.option) || a.index - b.index)
  return { from: result.from, options: options.map((item) => item.option) }
}

function completeRaw(text: string, pos: number, known: KnownNames): CompletionResult | null {
  const lineStart = text.lastIndexOf('\n', pos - 1) + 1
  const before = text.slice(lineStart, pos)
  if (before.trimStart().startsWith('#')) return null

  const declared = collectNames(text)
  const names: Required<KnownNames> = {
    proxies: [...declared.proxies, ...(known.proxies ?? [])],
    groups: [...declared.groups, ...(known.groups ?? [])],
    ruleProviders: [...declared.ruleProviders, ...(known.ruleProviders ?? [])],
  }

  const stack: Frame[] = []
  const lines = text.slice(0, lineStart).split('\n')
  for (const line of lines) if (!isSkippable(line)) step(stack, shape(line))

  const info = shape(before)
  // Parent frames only: the current line contributes its dashes but not its own key.
  step(stack, { ...info, key: null })
  if (!info.dashes.length) while (stack.length && stack[stack.length - 1].col >= info.col) stack.pop()
  const path = pathOf(stack)
  const node = resolve(path)
  if (!node) return null

  const typed = before.slice(info.col)
  const keyMatch = /^([\w.-]+):\s*(.*)$/.exec(typed)
  if (keyMatch) {
    const valueNode = resolve([...path, keyMatch[1]])
    if (!valueNode) return null
    const prefix = keyMatch[2]
    if (/^\{|^\[/.test(prefix)) return null
    const options = valueOptions(valueNode, names, prefix.replace(/^['"]/, ''))
    return options.length ? { from: pos - prefix.replace(/^['"]/, '').length, options } : null
  }

  if (node.rules) return ruleOptions(typed, lineStart + info.col, names)
  if (/[:{[,]/.test(typed)) return null

  if (node.keys && Object.keys(node.keys).length) {
    const siblings = siblingKeys(text, lineStart, pos, info.col)
    const options = keyOptions(node, info.col, typed, siblings)
    return options.length ? { from: pos - typed.length, options } : null
  }
  const options = valueOptions(node, names, typed)
  return options.length ? { from: pos - typed.length, options } : null
}

/** Keys already present in the same mapping, so they are not offered twice. */
function siblingKeys(text: string, lineStart: number, pos: number, col: number): Set<string> {
  const keys = new Set<string>()
  const scan = (lines: string[]) => {
    for (const line of lines) {
      if (isSkippable(line)) continue
      const info = shape(line)
      const own = info.dashes.length ? info.dashes[info.dashes.length - 1] + 2 : info.col
      if (info.col < col || (info.dashes.length && own <= col && info.col !== col)) break
      if (info.col === col && info.key) keys.add(info.key)
      if (info.dashes.length && info.col === col) break
    }
  }
  scan(text.slice(0, Math.max(0, lineStart - 1)).split('\n').reverse())
  const end = text.indexOf('\n', pos)
  scan(end < 0 ? [] : text.slice(end + 1).split('\n'))
  return keys
}
