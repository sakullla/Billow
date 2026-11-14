export const PRODUCT_NAME = 'Billow'
export const WINDOW_TITLE = 'Billow'
export const LICENSE_NAME = 'GPL-3'
export const ABOUT_TITLE = '关于'
export const ABOUT_TEXT = 'Billow 以 GPL-3 许可发布。'
export const HOME_STATUS = '未连接'
export const STATUS_CONNECTING = '连接中'
export const STATUS_CONNECTED = '已连接'
export const HOME_HINT = '连接信息会显示在这里。'
export const ACTION_CONNECT = '连接'
export const ACTION_DISCONNECT = '断开'
export const ACTION_ADD_PROFILE = '添加配置'
export const MODE_RULE = '规则'
export const MODE_GLOBAL = '全局'
export const MODE_DIRECT = '直连'
export const MODE_RULE_HINT = '按配置自动选择'
export const MODE_GLOBAL_HINT = '全部走当前节点'
export const MODE_DIRECT_HINT = '新连接不走代理'
export const RATE_UP = '上行'
export const RATE_DOWN = '下行'
export const PROFILE_LOCAL = '本地'
export const PROFILE_SUBSCRIPTION = '订阅'
export const PROFILE_SUCCESS = '最近成功'

export const OUTBOUND_MODES = [
  { id: 'rule', label: MODE_RULE, hint: MODE_RULE_HINT },
  { id: 'global', label: MODE_GLOBAL, hint: MODE_GLOBAL_HINT },
  { id: 'direct', label: MODE_DIRECT, hint: MODE_DIRECT_HINT },
] as const

export type OutboundMode = (typeof OUTBOUND_MODES)[number]['id']
export const PROXY_HINT = '浏览器和遵守系统设置的应用'
export const TUN_HINT = '不遵守系统代理的应用也走代理，并需要系统授权'
export const VPN_EXCLUDE = '按应用排除'
export const EXCLUDE_SEARCH = '搜索应用'
export const EXCLUDE_ON = '已排除'
export const EXCLUDE_OFF = '未排除'
export const NODES_TITLE = '节点'
export const NODES_EMPTY = '还没有可显示的节点。'
export const NODES_NEED_PROFILE = '需要先添加或更新配置'
export const NODES_NO_MATCH = '没有匹配的节点'
export const NODES_SEARCH = '搜索节点'
export const NODES_MANUAL = '手动'
export const NODES_AUTO = '自动'
export const NODES_NOW = '当前节点'
export const NODES_UNKNOWN = '未知'
export const NODES_TEST = '测试'
export const NODES_FAILED = '失败'
export const NODES_SELECTED = '已选'
export const NODES_KERNEL_DOWN = '内核没有运行'
export const NODES_NOT_MANUAL = '不能改选'
export const NODES_MISSING = '没有这个节点'

export const NODE_SORTS = [
  { id: 'default', label: '默认' },
  { id: 'delay', label: '延迟' },
  { id: 'name', label: '名称' },
] as const
export const SETTINGS_TITLE = '配置'
export const THEME_TITLE = '主题'
export const KERNEL_TITLE = '内核渠道'
export const PROFILES_EMPTY = '还没有配置。'
export const ADD_SUBSCRIPTION = '订阅链接'
export const ADD_LOCAL = '本地文件'
export const PROFILE_ENABLE = '启用'
export const PROFILE_UPDATE = '更新'
export const PROFILE_ADVANCED = '高级'
export const OVERRIDE_TITLE = '覆写'
export const ACTION_SAVE = '保存'
export const ACTION_CLOSE = '关闭'
export const ACTION_CONFIRM = '确认'
export const ACTION_CANCEL = '取消'
export const ACTION_ADD = '添加'
export const CURRENT_MARK = '当前'
export const USAGE_USED = '已用'
export const USAGE_TOTAL = '总量'
export const USAGE_EXPIRE = '到期'
export const EFFECTIVE_LABEL = '生效'
export const TAKEOVER_PROXY = '系统代理'
export const TAKEOVER_TUN = 'TUN'
export const TAKEOVER_VPN = 'VPN'
export const INSTALL_PROMPT = '确认添加这条订阅链接？'
export const SUBSCRIPTION_PLACEHOLDER = '输入订阅链接'
export const OPEN_DIAGNOSTICS = '连接与日志'
export const VIEW_DIAGNOSTICS = '查看诊断'
export const DIAGNOSTICS_TITLE = '诊断'
export const DIAGNOSTIC_CONNECTIONS = '连接'
export const DIAGNOSTIC_LOGS = '日志'
export const CONNECTION_SEARCH = '搜索目标'
export const CONNECTIONS_NONE = '没有当前连接'
export const ACTION_BACK = '返回'

export const LOG_FILTERS = [
  { id: 'all', label: '全部' },
  { id: 'error', label: '错误' },
  { id: 'warning', label: '警告' },
  { id: 'info', label: '信息' },
] as const

export type LogFilter = (typeof LOG_FILTERS)[number]['id']

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
