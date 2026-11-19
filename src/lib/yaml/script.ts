/**
 * JavaScript 覆写 helpers, shared by the editor and the profile view. A script
 * defines `main(config, profileName)` and returns the config (Clash Party /
 * Clash Verge compatible); the backend runs it in QuickJS.
 */
import { resolve } from './schema'
import { tr } from '../i18n'

export type OverrideLanguage = 'yaml' | 'javascript'

/** Same rule as the backend: a top-level `main` definition makes the text a script. */
export function overrideLanguage(text: string): OverrideLanguage {
  return /^(?:async\s+)?function\s+main\s*\(|^(?:const|let|var)\s+main\s*=/m.test(text) ? 'javascript' : 'yaml'
}

export function scriptTemplate(): string {
  return `// ${tr('返回修改后的 config；profileName 是当前配置名称')}
function main(config, profileName) {
  // ${tr('在规则最前面插入直连规则')}
  config.rules = config.rules ?? []
  config.rules.unshift('DOMAIN-SUFFIX,example.com,DIRECT')

  return config
}
`
}

export function yamlTemplate(): string {
  return `# ${tr('只写需要改的部分，其余沿用原配置')}
# key: 值        ${tr('深度合并（对象递归合并，其余直接替换）')}
# +rules:        ${tr('插入到原列表前面；rules+: 追加到后面')}
# dns!:          ${tr('整体替换，不与原配置合并')}
# <+.a.com>:     ${tr('键名本身以 + 开头或结尾时用尖括号包裹')}
+rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
`
}

export interface ScriptCompletion {
  label: string
  /** Replacement for the text after `from`. */
  apply: string
  detail?: string
  type: 'property' | 'function' | 'text'
}

const IDENT = /^[A-Za-z_$][\w$]*$/

/** Property path written before the cursor, e.g. `config.dns['fake-ip-filter'].` → ['dns', 'fake-ip-filter']. */
function accessPath(chain: string): string[] | null {
  const path: string[] = []
  const pattern = /\.([A-Za-z_$][\w$]*)|\[\s*(['"])([^'"]+)\2\s*\]/y
  let index = 0
  while (index < chain.length) {
    pattern.lastIndex = index
    const match = pattern.exec(chain)
    if (!match) return null
    path.push(match[1] ?? match[3])
    index = pattern.lastIndex
  }
  return path
}

/**
 * Completions for `config.<key>` chains from the mihomo schema. Keys that are not
 * identifiers (`mixed-port`) switch to bracket access.
 */
export function completeConfigAccess(before: string): { from: number; options: ScriptCompletion[] } | null {
  const match = /\bconfig((?:\.[A-Za-z_$][\w$]*|\[\s*['"][^'"]+['"]\s*\])*)(\.([\w$-]*)|\[\s*(['"])([\w-]*))$/.exec(before)
  if (!match) return null
  const path = accessPath(match[1])
  if (!path) return null
  const node = resolve(path)
  if (!node?.keys) return null
  const bracket = match[4] != null
  const typed = bracket ? match[5] : match[3]
  const dotFrom = before.length - match[2].length
  const options: ScriptCompletion[] = []
  for (const [key, child] of Object.entries(node.keys)) {
    if (typed && !key.toLowerCase().startsWith(typed.toLowerCase())) continue
    const apply = bracket ? `${match[4]}${key}${match[4]}]` : IDENT.test(key) ? `.${key}` : `['${key}']`
    options.push({ label: key, apply, detail: child.doc, type: 'property' })
  }
  return { from: bracket ? before.length - match[2].length + match[2].indexOf(match[4]) : dotFrom, options }
}

/** Ready-made statements for the common edits. */
export const SCRIPT_SNIPPETS: { label: string; detail: string; snippet: string }[] = [
  { label: 'main', detail: '入口函数', snippet: 'function main(config, profileName) {\n  ${}\n  return config\n}' },
  { label: 'prepend rule', detail: '在最前面插入规则', snippet: "config.rules.unshift('${DOMAIN-SUFFIX},${example.com},${DIRECT}')" },
  { label: 'append rule', detail: '在末尾追加规则（MATCH 之前）', snippet: "config.rules.splice(Math.max(0, config.rules.length - 1), 0, '${DOMAIN-SUFFIX},${example.com},${DIRECT}')" },
  { label: 'add proxy group', detail: '新增代理组', snippet: "config['proxy-groups'].push({\n  name: '${名称}',\n  type: 'select',\n  proxies: config.proxies.map((proxy) => proxy.name),\n})" },
  { label: 'filter proxies', detail: '按名称筛选节点', snippet: "config.proxies = config.proxies.filter((proxy) => !/${过期|剩余}/.test(proxy.name))" },
  { label: 'nameserver-policy', detail: '为域名指定 DNS', snippet: "config.dns = config.dns ?? {}\nconfig.dns['nameserver-policy'] = {\n  ...config.dns['nameserver-policy'],\n  '${+.corp.example}': ['${223.5.5.5}'],\n}" },
  { label: 'console.log', detail: '在预览中输出日志', snippet: 'console.log(${})' },
]
