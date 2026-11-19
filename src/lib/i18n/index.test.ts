import { afterEach, describe, expect, it } from 'vitest'
import { locale, applyLocale, normalizeLanguage, normalizeLocale, resolveLanguage, t, translate } from './index'
import { EN } from './en'
import { ZH_CN } from './zh-CN'

afterEach(() => {
  applyLocale('zh-CN')
})

describe('frontend dictionary', () => {
  it('falls back to Chinese when a key has no English text', () => {
    // An empty dictionary is how an untranslated key behaves: never a key or a blank.
    expect(translate('en', 'settings.language.title', {}, {})).toBe('界面语言')
    expect(translate('en', 'settings.language.title', {}, {})).not.toContain('settings.language')
    // A translated key uses English; Chinese always uses the base text.
    expect(translate('en', 'settings.language.title')).toBe('Language')
    expect(translate('zh-CN', 'settings.language.title')).toBe('界面语言')
  })

  it('keeps every key non-empty in both languages', () => {
    for (const key of Object.keys(ZH_CN) as (keyof typeof ZH_CN)[]) {
      expect(ZH_CN[key].trim()).not.toBe('')
      expect(translate('zh-CN', key).trim()).not.toBe('')
      expect(translate('en', key).trim()).not.toBe('')
      expect(translate('en', key)).not.toBe(key)
      // A missing translation must be the Chinese text, never something else.
      if (!EN[key]) expect(translate('en', key)).toBe(ZH_CN[key])
    }
  })

  it('renders params and leaves unknown placeholders alone', () => {
    expect(translate('zh-CN', 'settings.language.title', { unused: 1 })).toBe('界面语言')
    expect(translate('en', 'language.system', {})).toBe('Follow system')
  })
})

describe('language preference', () => {
  it('switches t() and the document lang without a restart', () => {
    expect(t('settings.language.title')).toBe('界面语言')
    expect(document.documentElement.lang).toBe('zh-CN')
    applyLocale('en')
    expect(locale.value).toBe('en')
    expect(t('settings.language.title')).toBe('Language')
    expect(document.documentElement.lang).toBe('en')
  })

  it('only resolves Simplified Chinese and English', () => {
    expect(resolveLanguage('system', 'zh-CN')).toBe('zh-CN')
    expect(resolveLanguage('system', 'en')).toBe('en')
    // Traditional Chinese systems get Simplified Chinese (R46).
    expect(resolveLanguage('zh-CN', 'en')).toBe('zh-CN')
    expect(resolveLanguage('en', 'zh-CN')).toBe('en')
    expect(normalizeLocale('zh-TW')).toBe('zh-CN')
    expect(normalizeLocale('en-US')).toBe('zh-CN')
    expect(normalizeLocale('en')).toBe('en')
    expect(normalizeLanguage('zh-TW')).toBe('system')
    expect(normalizeLanguage('en')).toBe('en')
    expect(normalizeLanguage(undefined)).toBe('system')
  })
})
