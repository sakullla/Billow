import { ref } from 'vue'
import type { LanguagePreference, Locale } from '../types'
import { EN } from './en'
import { UI_EN } from './ui-en'
import { ZH_CN, type MessageKey } from './zh-CN'

/**
 * UI language (R42): Simplified Chinese and English only, with the Chinese text
 * as the base every message falls back to. The locale lives in a single
 * reactive value, so `t()` in a template re-renders when it changes.
 */

export type { LanguagePreference, Locale }

export type MessageParams = Record<string, string | number>
export type Dictionary = Partial<Record<MessageKey, string>>

/** Starts as Simplified Chinese and is replaced by the effective locale on load. */
export const locale = ref<Locale>('zh-CN')

export function normalizeLocale(value: unknown): Locale {
  return value === 'en' ? 'en' : 'zh-CN'
}

export function normalizeLanguage(value: unknown): LanguagePreference {
  if (value === 'en' || value === 'zh-CN') return value
  return 'system'
}

/** Only two languages exist: Traditional Chinese systems fall back to Simplified. */
export function resolveLanguage(preference: LanguagePreference, system: Locale): Locale {
  return preference === 'system' ? system : preference
}

/**
 * Render one message. A key with no English text returns the Chinese text (R42),
 * never the key itself or an empty string.
 */
export function translate(
  target: Locale,
  key: MessageKey,
  params: MessageParams = {},
  dictionary: Dictionary = EN,
): string {
  const template = (target === 'en' ? dictionary[key] : undefined) ?? ZH_CN[key]
  return template.replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? String(params[name]) : match,
  )
}

/** The message in the current locale. Read inside a render function to stay reactive. */
export function t(key: MessageKey, params: MessageParams = {}): string {
  return translate(locale.value, key, params)
}

/** Dynamic backend messages that Rust formats before the UI sees them (T8). */
const UI_PATTERNS: { pattern: RegExp; render: (match: RegExpMatchArray) => string }[] = [
  { pattern: /^共 (\d+) 条，只列出前 (\d+) 条；搜索会查找全部规则$/, render: (m) => `Showing the first ${m[2]} of ${m[1]} rules; search looks through all of them` },
  { pattern: /^匹配 (\d+) 条，只列出前 (\d+) 条$/, render: (m) => `Showing the first ${m[2]} of ${m[1]} matches` },
  { pattern: /^YAML 第 (\d+) 行第 (\d+) 列有误：(.*)$/, render: (m) => `YAML error on line ${m[1]}, column ${m[2]}: ${m[3]}` },
  { pattern: /^YAML 第 (\d+) 行有误：(.*)$/, render: (m) => `YAML error on line ${m[1]}: ${m[2]}` },
  { pattern: /^YAML 有误：(.*)$/, render: (m) => `YAML error: ${m[1]}` },
  { pattern: /^内置内核初始化失败：(.*)$/, render: (m) => `Bundled kernel failed to initialise: ${m[1]}` },
  { pattern: /^内置内核状态保存失败：(.*)$/, render: (m) => `Could not save the bundled kernel state: ${m[1]}` },
  { pattern: /^MRS 解压失败：(.*)$/, render: (m) => `MRS extraction failed: ${m[1]}` },
  { pattern: /^脚本引擎启动失败：(.*)$/, render: (m) => `Could not start the script engine: ${m[1]}` },
  { pattern: /^脚本有误：(.*)$/, render: (m) => `Script error: ${m[1]}` },
  { pattern: /^脚本结果无法读取：(.*)$/, render: (m) => `Could not read the script result: ${m[1]}` },
  { pattern: /^main 运行出错：(.*)$/, render: (m) => `main failed: ${m[1]}` },
  { pattern: /^脚本运行出错：(.*)$/, render: (m) => `Script failed: ${m[1]}` },
  { pattern: /^替换 (.*) 数据库失败：(.*)$/, render: (m) => `Could not replace the ${m[1]} database: ${m[2]}` },
  { pattern: /^部分旧连接未能关闭（(\d+)\/(\d+)），可在连接页重试$/, render: (m) => `Some old connections could not be closed (${m[1]}/${m[2]}); retry on the Connections page` },
  { pattern: /^DNS 查询失败（HTTP (\d+)）$/, render: (m) => `DNS query failed (HTTP ${m[1]})` },
  { pattern: /^DNS 查询失败：(.*)$/, render: (m) => `DNS query failed: ${m[1]}` },
  { pattern: /^没有找到记录（(.*)）$/, render: (m) => `No records found (${m[1]})` },
  { pattern: /^没有找到 (.*) 记录$/, render: (m) => `No ${m[1]} records found` },
  { pattern: /^无法检查更新：(.*)$/, render: (m) => `Could not check for updates: ${m[1]}` },
  { pattern: /^版本信息无效：(.*)$/, render: (m) => `Invalid version information: ${m[1]}` },
  { pattern: /^请求失败：(.*)$/, render: (m) => `Request failed: ${m[1]}` },
  { pattern: /^读取失败：(.*)$/, render: (m) => `Read failed: ${m[1]}` },
  { pattern: /^保存失败：(.*)$/, render: (m) => `Save failed: ${m[1]}` },
  { pattern: /^写入失败：(.*)$/, render: (m) => `Write failed: ${m[1]}` },
  { pattern: /^写入临时文件失败：(.*)$/, render: (m) => `Could not write the temporary file: ${m[1]}` },
  { pattern: /^下载写入失败：(.*)$/, render: (m) => `Could not write the download: ${m[1]}` },
  { pattern: /^还没有找到可读取的规则文件（(.*)）；连接并更新这个规则集后再查看$/, render: (m) => `No readable rule file yet (${m[1]}); connect and update this rule set first` },
  { pattern: /^(.+)（请求超时）$/, render: (m) => `${m[1]} (request timed out)` },
]

/**
 * Translate a Chinese source string through the UI catalog (T8). Chinese stays
 * the base text, so an untranslated string renders exactly as written and an
 * English entry is only an override. Reading `locale` here keeps templates
 * reactive when the language changes.
 */
function translateMessage(text: string, depth = 0): string {
  if (locale.value !== 'en') return text
  const exact = UI_EN[text]
  if (exact) return exact
  for (const rule of UI_PATTERNS) {
    const match = text.match(rule.pattern)
    if (match) return rule.render(match)
  }
  // A message may combine a translated prefix with a Chinese reason built by
  // Rust (e.g. "The override could not be applied: YAML 第 3 行有误：…").
  if (depth < 2) {
    const ascii = text.indexOf(': ')
    const split = ascii > 0 ? ascii : text.indexOf('：')
    if (split > 0) {
      const head = text.slice(0, split)
      const tail = text.slice(split + (ascii > 0 ? 2 : 1)).trim()
      const headEn = UI_EN[head] ?? head
      const tailEn = translateMessage(tail, depth + 1)
      if (headEn !== head || tailEn !== tail) return `${headEn}: ${tailEn}`
    }
  }
  return text
}

export function tr(text: string, params: Record<string, string | number | null | undefined> = {}): string {
  return translateMessage(text).replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? String(params[name] ?? '') : match,
  )
}

/** Apply one locale to the dictionary and the document, without a restart. */
export function applyLocale(next: Locale) {
  locale.value = next
  if (typeof document !== 'undefined') document.documentElement.lang = next
}
