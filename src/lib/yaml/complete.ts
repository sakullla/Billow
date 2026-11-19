/**
 * Mihomo-aware YAML completion, independent of the editor. It reads the block
 * structure above the cursor (indentation, `- ` items, compact sequences) to
 * find the key path, then offers keys, fixed values, rule types or proxy/group
 * names from the schema. Flow mappings are only read for names.
 */
import { BUILTIN_TARGETS, RULE_TYPES, resolve, type SchemaNode } from './schema'
import { tr, locale } from '../i18n'

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

/**
 * The config key behind a 覆写 key: `key!` (replace), `+key` / `key+` (prepend /
 * append a list) and `<key>` (quoted key) all address `key`.
 */
export function overrideBaseKey(key: string): string {
  let name = key.endsWith('!') ? key.slice(0, -1) : key
  if (name.startsWith('+') && !name.startsWith('+.')) name = name.slice(1)
  else if (name.startsWith('+<')) name = name.slice(1)
  if (name.endsWith('+')) name = name.slice(0, -1)
  if (name.length >= 2 && name.startsWith('<') && name.endsWith('>')) name = name.slice(1, -1)
  const verge = /^(?:prepend|append)-(rules|proxies|proxy-groups)$/.exec(name)
  return verge ? verge[1] : name
}

function pathOf(stack: Frame[]): string[] {
  return stack.map((frame) => (frame.seg === '[]' ? frame.seg : overrideBaseKey(frame.seg)))
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

function keyOptions(node: SchemaNode, indent: number, prefix: string, siblings: Set<string>, override: boolean): CompletionOption[] {
  const pad = ' '.repeat(indent + 2)
  const options: CompletionOption[] = []
  for (const [key, child] of Object.entries(node.keys ?? {})) {
    // `keys: {}` plus `item` describes a map of named entries (rule-providers).
    const mapping = Boolean(child.keys)
    const list = !child.keys && Boolean(child.item || child.rules)
    const body = mapping ? `\n${pad}` : list ? `\n${pad}- ` : ' '
    const doc = child.doc ? tr(child.doc) : key
    // Without a translation, an English completion shows the config key (already
    // English) instead of leaving Chinese text in the popup (T8).
    const detail = locale.value === 'en' && doc === child.doc ? key : doc
    const variants: { label: string; detail?: string }[] = [{ label: key, detail }]
    if (override && list) {
      variants.push({ label: `+${key}`, detail: tr('插入到原列表前面') }, { label: `${key}+`, detail: tr('追加到原列表后面') })
    }
    if (override && mapping) variants.push({ label: `${key}!`, detail: tr('整体替换，不与原配置合并') })
    for (const variant of variants) {
      if (siblings.has(variant.label) || !startsWith(variant.label, prefix)) continue
      options.push({ label: variant.label, apply: `${variant.label}:${body}`, detail: variant.detail, type: 'property' })
    }
  }
  return options
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
  const groups = unique(names.groups).map((label) => ({ label, detail: tr('代理组'), type: 'variable' as const }))
  const proxies = unique(names.proxies).map((label) => ({ label, detail: tr('节点'), type: 'variable' as const }))
  const builtins = BUILTIN_TARGETS.map((label) => ({ label, detail: tr('内置'), type: 'constant' as const }))
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
        detail: tr('规则类型'),
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
        .map((label) => ({ label, apply: `${label},`, detail: tr('规则集'), type: 'variable' })),
    }
  }
  if (index === 3 && IP_RULES.has(type)) {
    return { from, options: [{ label: 'no-resolve', detail: tr('不为匹配解析域名'), type: 'keyword' }].filter((option) => startsWith(option.label, prefix)) as CompletionOption[] }
  }
  return null
}

/**
 * Completions at `pos`. `known` adds names from outside the document (e.g. the
 * profile an override applies to); names declared in the text are always used.
 */
export function complete(text: string, pos: number, known: KnownNames = {}, override = false): CompletionResult | null {
  const result = completeRaw(text, pos, known, override)
  if (!result) return null
  const typed = text.slice(result.from, pos).toLowerCase()
  // Prefix matches first, then substring matches, each in schema order.
  const rank = (option: CompletionOption) => (option.label.toLowerCase().startsWith(typed) ? 0 : 1)
  const options = result.options.map((option, index) => ({ option, index }))
  options.sort((a, b) => rank(a.option) - rank(b.option) || a.index - b.index)
  return { from: result.from, options: options.map((item) => item.option) }
}

function completeRaw(text: string, pos: number, known: KnownNames, override: boolean): CompletionResult | null {
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
  const keyMatch = /^([+<]*[\w.-]+>?[+!]?):\s*(.*)$/.exec(typed)
  if (keyMatch) {
    const valueNode = resolve([...path, overrideBaseKey(keyMatch[1])])
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
    const options = keyOptions(node, info.col, typed, siblings, override)
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
