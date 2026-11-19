/**
 * Simplified Chinese is the base dictionary (R42): every message starts here and
 * English entries are optional, so a missing translation falls back to Chinese.
 */
export const ZH_CN = {
  'settings.language.title': '界面语言',
  'settings.language.detail': '切换后立即生效；跟随系统时，中文系统用简体中文，其他语言用英文',
  'language.system': '跟随系统',
} as const

export type MessageKey = keyof typeof ZH_CN
