import { ref } from 'vue'
import type { LanguagePreference, Locale } from '../types'
import { EN } from './en'
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

/** Apply one locale to the dictionary and the document, without a restart. */
export function applyLocale(next: Locale) {
  locale.value = next
  if (typeof document !== 'undefined') document.documentElement.lang = next
}
