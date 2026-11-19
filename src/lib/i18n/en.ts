import type { MessageKey } from './zh-CN'

/**
 * English text per key. It is deliberately partial: any key left out renders its
 * Chinese base text instead of a key name or a blank line (R42).
 */
export const EN: Partial<Record<MessageKey, string>> = {
  'settings.language.title': 'Language',
  'settings.language.detail':
    'Applied immediately; Follow system uses Simplified Chinese on Chinese systems and English otherwise',
  'language.system': 'Follow system',
}
