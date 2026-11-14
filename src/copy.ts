export const PRODUCT_NAME = 'Billow'
export const WINDOW_TITLE = 'Billow'
export const LICENSE_NAME = 'GPL-3'
export const ABOUT_TITLE = '关于'
export const ABOUT_TEXT = 'Billow 以 GPL-3 许可发布。'
export const HOME_STATUS = '未连接'
export const HOME_HINT = '连接信息会显示在这里。'
export const NODES_TITLE = '节点'
export const NODES_EMPTY = '还没有可显示的节点。'
export const SETTINGS_TITLE = '配置'
export const THEME_TITLE = '主题'
export const KERNEL_TITLE = '内核渠道'

export const NAV_ITEMS = [
  { id: 'home', label: '首页' },
  { id: 'nodes', label: '节点' },
  { id: 'settings', label: '配置' },
] as const

export const THEME_OPTIONS = [
  { id: 'system', label: '跟随系统' },
  { id: 'light', label: '始终浅色' },
  { id: 'dark', label: '始终深色' },
] as const

export const KERNEL_OPTIONS = [
  { id: 'stable', label: '稳定版' },
  { id: 'preview', label: '预览版' },
] as const

export type EntryId = (typeof NAV_ITEMS)[number]['id']
export type ThemePreference = (typeof THEME_OPTIONS)[number]['id']
export type KernelChannel = (typeof KERNEL_OPTIONS)[number]['id']
