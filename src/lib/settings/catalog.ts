import { tr } from '../i18n'
import type { SettingsTab } from '../store'

/**
 * Settings information architecture (v3): categories follow what the user is
 * trying to do, not where mihomo keeps the key. Every searchable row carries a
 * stable id that the page renders as `data-setting`, so search results, error
 * banners and the effective-config viewer can all jump to the exact row.
 */

export type CategoryId = Exclude<SettingsTab, 'home'>
export type CategoryTone = 'slate' | 'blue' | 'indigo' | 'teal' | 'amber' | 'violet' | 'orange' | 'green' | 'gray'

export interface PlatformContext {
  android: boolean
  windows: boolean
  linux: boolean
  mac: boolean
}

/** A settings page the user picks in the menu. It shows one or more panes. */
export interface SettingsCategory {
  id: CategoryId
  label: () => string
  description: () => string
  icon: string
  tone: CategoryTone
  /** Panes shown on this page, in order. */
  panes: readonly CategoryId[]
  /** How multi-pane categories present their panes: segmented sub-tabs or flat stacked sections. */
  layout?: 'tabs' | 'stack'
  /** Optional platform visibility guard (e.g., System Proxy & TUN is desktop-only). */
  when?: (ctx: PlatformContext) => boolean
  /** Grouping on the phone root list. */
  group: 'network' | 'app'
}

/** A block of related rows. Its id is what search results and deep links target. */
export interface SettingsPane {
  id: CategoryId
  label: () => string
  description: () => string
  when?: (ctx: PlatformContext) => boolean
}

const desktop = (ctx: PlatformContext) => !ctx.android

export const SETTINGS_PANES: readonly SettingsPane[] = [
  { id: 'general', label: () => tr('通用'), description: () => tr('外观、启动、统计与快捷键') },
  { id: 'proxy', label: () => tr('系统代理'), description: () => tr('代理主机、PAC 与绕过列表'), when: desktop },
  { id: 'tun', label: () => tr('TUN 模式'), description: () => tr('用虚拟网卡接管全部流量'), when: desktop },
  { id: 'network', label: () => tr('端口与网络'), description: () => tr('代理端口、局域网共享与 IPv6') },
  { id: 'behavior', label: () => tr('代理与测速'), description: () => tr('节点切换、延迟测试、嗅探与订阅') },
  { id: 'dns', label: () => 'DNS', description: () => tr('上游服务器、解析策略与 Hosts') },
  { id: 'kernel', label: () => tr('内核'), description: () => tr('Mihomo 版本、日志与运行维护') },
  { id: 'backup', label: () => tr('备份与同步'), description: () => tr('本地备份与 WebDAV 云端同步') },
  { id: 'about', label: () => tr('关于'), description: () => tr('版本与应用更新') },
]

export const SETTINGS_CATEGORIES: readonly SettingsCategory[] = [
  { id: 'general', label: () => tr('通用'), description: () => tr('外观、启动、统计与快捷键'), icon: 'sliders', tone: 'gray', panes: ['general'], group: 'app' },
  { id: 'proxy', label: () => tr('系统与 TUN'), description: () => tr('系统代理与 TUN 虚拟网卡'), icon: 'shield', tone: 'indigo', panes: ['proxy', 'tun'], layout: 'tabs', when: desktop, group: 'network' },
  { id: 'network', label: () => tr('端口与网络'), description: () => tr('代理端口、局域网共享与 IPv6'), icon: 'network', tone: 'blue', panes: ['network'], group: 'network' },
  { id: 'behavior', label: () => tr('代理与测速'), description: () => tr('节点切换、延迟测试、嗅探与订阅'), icon: 'zap', tone: 'amber', panes: ['behavior'], group: 'network' },
  { id: 'dns', label: () => 'DNS', description: () => tr('上游服务器、解析策略与 Hosts'), icon: 'globe', tone: 'teal', panes: ['dns'], group: 'network' },
  { id: 'kernel', label: () => tr('内核'), description: () => tr('Mihomo 版本、日志与运行维护'), icon: 'cpu', tone: 'orange', panes: ['kernel'], group: 'app' },
  { id: 'backup', label: () => tr('备份与关于'), description: () => tr('备份恢复、版本与更新'), icon: 'database', tone: 'green', panes: ['backup', 'about'], layout: 'stack', group: 'app' },
]

export function visibleCategories(ctx: PlatformContext): SettingsCategory[] {
  return SETTINGS_CATEGORIES.filter((category) => !category.when || category.when(ctx))
}

export function paneOf(id: CategoryId): SettingsPane {
  return SETTINGS_PANES.find((pane) => pane.id === id) ?? SETTINGS_PANES[0]!
}

/** Panes of a category that exist on this platform. */
export function visiblePanes(category: SettingsCategory, ctx: PlatformContext): SettingsPane[] {
  return category.panes.map(paneOf).filter((pane) => !pane.when || pane.when(ctx))
}

/** The page that shows a tab. Pane ids (`dns`, `tun`, `about`...) resolve to their page. */
export function categoryOf(tab: SettingsTab): SettingsCategory {
  if (tab === 'home') return SETTINGS_CATEGORIES[0]!
  return (
    SETTINGS_CATEGORIES.find((category) => category.id === tab || category.panes.includes(tab)) ?? SETTINGS_CATEGORIES[0]!
  )
}
export interface SettingsEntry {
  /** Rendered as `data-setting` on the row. */
  id: string
  tab: CategoryId
  title: () => string
  description?: () => string
  /** Extra search terms: mihomo keys and English words, so both audiences find it. */
  keywords?: string
  when?: (ctx: PlatformContext) => boolean
}

const windows = (ctx: PlatformContext) => ctx.windows

export const SETTINGS_INDEX: readonly SettingsEntry[] = [
  // 通用
  { id: 'theme', tab: 'general', title: () => tr('主题'), description: () => tr('浅色、深色或跟随系统'), keywords: 'theme dark light 深色 浅色 外观' },
  { id: 'language', tab: 'general', title: () => tr('界面语言'), keywords: 'language english 中文 语言' },
  { id: 'shortcuts', tab: 'general', title: () => tr('键盘快捷键'), keywords: 'shortcut hotkey keyboard 快捷键 热键 全局' },
  { id: 'auto-connect', tab: 'general', title: () => tr('打开时自动启动内核'), keywords: 'auto connect start 自动连接' },
  { id: 'autostart', tab: 'general', title: () => tr('开机自启'), keywords: 'autostart login boot 开机', when: desktop },
  { id: 'silent-start', tab: 'general', title: () => tr('静默启动'), keywords: 'silent tray 托盘', when: desktop },
  { id: 'close-to-tray', tab: 'general', title: () => tr('关闭时最小化到托盘'), keywords: 'tray close minimize 托盘', when: desktop },
  { id: 'release-ui', tab: 'general', title: () => tr('关闭窗口时释放界面'), keywords: 'lightweight memory 轻量 内存', when: desktop },
  // 系统代理
  { id: 'system-proxy', tab: 'proxy', title: () => tr('启用系统代理'), keywords: 'system proxy 系统代理', when: desktop },
  { id: 'proxy-mode', tab: 'proxy', title: () => tr('代理模式'), description: () => tr('手动或 PAC'), keywords: 'pac manual mode', when: desktop },
  { id: 'pac-script', tab: 'proxy', title: () => tr('PAC 脚本'), keywords: 'pac script', when: desktop },
  { id: 'proxy-host', tab: 'proxy', title: () => tr('代理主机'), keywords: 'host 127.0.0.1', when: desktop },
  { id: 'proxy-bypass', tab: 'proxy', title: () => tr('代理绕过列表'), keywords: 'bypass exclude 绕过 直连 局域网', when: desktop },
  { id: 'uwp', tab: 'proxy', title: () => tr('UWP 工具'), keywords: 'uwp loopback windows store 回环', when: windows },
  // TUN
  { id: 'tun', tab: 'tun', title: () => tr('启用 TUN'), keywords: 'tun vpn 虚拟网卡', when: desktop },
  { id: 'tun-stack', tab: 'tun', title: () => tr('协议栈'), keywords: 'stack gvisor system mixed mips', when: desktop },
  { id: 'tun-auto-route', tab: 'tun', title: () => tr('自动设置路由'), keywords: 'auto-route route 路由', when: desktop },
  { id: 'tun-strict-route', tab: 'tun', title: () => tr('严格路由'), keywords: 'strict-route dns leak 泄漏', when: desktop },
  { id: 'tun-auto-detect', tab: 'tun', title: () => tr('自动选择出口网卡'), keywords: 'auto-detect-interface', when: desktop },
  { id: 'tun-dns-hijack', tab: 'tun', title: () => tr('DNS 劫持'), keywords: 'dns-hijack', when: desktop },
  { id: 'tun-mtu', tab: 'tun', title: () => 'MTU', keywords: 'mtu', when: desktop },
  { id: 'tun-device', tab: 'tun', title: () => tr('网卡名称'), keywords: 'device utun', when: desktop },
  { id: 'tun-route-exclude', tab: 'tun', title: () => tr('不走 TUN 的地址'), keywords: 'route-exclude-address 排除', when: desktop },
  { id: 'tun-route-include', tab: 'tun', title: () => tr('只让这些地址走 TUN'), keywords: 'route-address', when: desktop },
  // 网络与端口
  { id: 'mixed-port', tab: 'network', title: () => tr('混合代理端口'), keywords: 'mixed-port port 端口 7890' },
  { id: 'extra-ports', tab: 'network', title: () => tr('更多端口与出口'), description: () => tr('SOCKS / HTTP 端口、出口网卡与路由标记'), keywords: 'socks-port port redir tproxy interface-name routing-mark 网卡 端口' },
  { id: 'allow-lan', tab: 'network', title: () => tr('局域网连接'), keywords: 'allow-lan lan share 共享 局域网' },
  { id: 'lan-access', tab: 'network', title: () => tr('访问控制'), description: () => tr('访问认证与允许的设备'), keywords: 'authentication lan-allowed-ips password 密码 认证' },
  { id: 'ipv6', tab: 'network', title: () => 'IPv6', keywords: 'ipv6' },
  { id: 'tcp-concurrent', tab: 'network', title: () => tr('TCP 并发'), keywords: 'tcp-concurrent' },
  { id: 'keep-alive', tab: 'network', title: () => tr('TCP 保活'), keywords: 'keep-alive-interval 保活 省电', when: desktop },
  // 代理与测速
  { id: 'node-switch', tab: 'behavior', title: () => tr('切换节点后重连'), keywords: 'reconnect close connections 断开' },
  { id: 'test-url', tab: 'behavior', title: () => tr('测速地址'), keywords: 'url test delay latency 延迟 测速' },
  { id: 'test-timeout', tab: 'behavior', title: () => tr('测速超时'), keywords: 'timeout 超时' },
  { id: 'unified-delay', tab: 'behavior', title: () => tr('统一延迟'), keywords: 'unified-delay 延迟' },
  { id: 'sniffer', tab: 'behavior', title: () => tr('域名嗅探'), keywords: 'sniffer sniff 嗅探' },
  { id: 'sniffer-options', tab: 'behavior', title: () => tr('嗅探选项'), keywords: 'sniff ports force-domain skip-domain override-destination' },
  { id: 'process-mode', tab: 'behavior', title: () => tr('进程匹配'), keywords: 'find-process-mode process 进程', when: desktop },
  { id: 'subscription-ua', tab: 'behavior', title: () => tr('订阅 User-Agent'), keywords: 'user-agent ua subscription 订阅' },
  // DNS
  { id: 'dns-override', tab: 'dns', title: () => tr('DNS 覆写'), keywords: 'dns override 覆写' },
  { id: 'dns-mode', tab: 'dns', title: () => tr('域名映射模式'), keywords: 'enhanced-mode fake-ip redir-host normal' },
  { id: 'dns-nameserver', tab: 'dns', title: () => tr('主 DNS 服务器'), keywords: 'nameserver doh dot 上游' },
  { id: 'dns-default-nameserver', tab: 'dns', title: () => tr('引导 DNS'), keywords: 'default-nameserver bootstrap' },
  { id: 'dns-proxy-nameserver', tab: 'dns', title: () => tr('节点域名解析'), keywords: 'proxy-server-nameserver' },
  { id: 'dns-direct-nameserver', tab: 'dns', title: () => tr('直连域名解析'), keywords: 'direct-nameserver' },
  { id: 'dns-fallback', tab: 'dns', title: () => tr('备用 DNS'), keywords: 'fallback' },
  { id: 'dns-policy', tab: 'dns', title: () => tr('域名解析策略'), keywords: 'nameserver-policy geosite 分流' },
  { id: 'dns-respect-rules', tab: 'dns', title: () => tr('遵循分流规则'), keywords: 'respect-rules' },
  { id: 'dns-direct-follow', tab: 'dns', title: () => tr('直连遵循解析策略'), keywords: 'direct-nameserver-follow-policy' },
  { id: 'dns-use-hosts', tab: 'dns', title: () => tr('使用 hosts'), keywords: 'use-hosts hosts' },
  { id: 'dns-system-hosts', tab: 'dns', title: () => tr('读取系统 Hosts'), keywords: 'use-system-hosts hosts' },
  { id: 'dns-hosts', tab: 'dns', title: () => tr('自定义 Hosts'), keywords: 'hosts 映射' },
  { id: 'dns-fake-ip-range', tab: 'dns', title: () => tr('Fake-IP 地址段'), keywords: 'fake-ip-range' },
  { id: 'dns-filter-mode', tab: 'dns', title: () => tr('过滤列表模式'), keywords: 'fake-ip-filter-mode blacklist whitelist' },
  { id: 'dns-fake-ip-filter', tab: 'dns', title: () => tr('Fake-IP 过滤'), keywords: 'fake-ip-filter' },
  { id: 'dns-listen', tab: 'dns', title: () => tr('DNS 监听地址'), keywords: 'listen 53 1053' },
  { id: 'dns-ipv6', tab: 'dns', title: () => tr('IPv6 解析'), keywords: 'ipv6 aaaa' },
  { id: 'dns-prefer-h3', tab: 'dns', title: () => tr('DoH 优先 HTTP/3'), keywords: 'prefer-h3 quic' },
  { id: 'dns-cache-algorithm', tab: 'dns', title: () => tr('缓存算法'), keywords: 'cache-algorithm lru arc' },
  { id: 'dns-flush-fakeip', tab: 'dns', title: () => tr('清除 FakeIP 缓存'), keywords: 'flush fakeip cache 缓存' },
  { id: 'dns-flush', tab: 'dns', title: () => tr('清除 DNS 缓存'), keywords: 'flush dns cache 缓存' },
  { id: 'dns-query', tab: 'dns', title: () => tr('DNS 查询'), keywords: 'lookup resolve nslookup dig 查询' },
  // 内核
  { id: 'kernel-channel', tab: 'kernel', title: () => tr('更新渠道'), keywords: 'channel stable preview alpha 预览' },
  { id: 'kernel-update', tab: 'kernel', title: () => tr('检查更新'), keywords: 'kernel update mihomo 内核 更新' },
  { id: 'log-level', tab: 'kernel', title: () => tr('日志级别'), keywords: 'log-level debug 日志' },
  { id: 'effective-config', tab: 'kernel', title: () => tr('生效配置'), keywords: 'config yaml effective 配置' },
  { id: 'kernel-restart', tab: 'kernel', title: () => tr('重启内核'), keywords: 'restart 重启' },
  { id: 'kernel-gc', tab: 'kernel', title: () => tr('回收内存'), keywords: 'gc memory 内存' },
  { id: 'kernel-reset', tab: 'kernel', title: () => tr('全部跟随配置'), keywords: 'reset follow 恢复 覆盖' },
  // 通用（首页与统计）
  { id: 'exit-ip', tab: 'general', title: () => tr('自动查询出口 IP'), keywords: 'exit ip 出口 ip.sb' },
  { id: 'traffic-history', tab: 'general', title: () => tr('流量历史'), keywords: 'traffic history stats usage 流量 统计' },
  // 备份与同步
  { id: 'backup-file', tab: 'backup', title: () => tr('备份文件'), keywords: 'backup export import restore 备份 导出 导入 恢复' },
  { id: 'webdav', tab: 'backup', title: () => 'WebDAV', keywords: 'webdav cloud sync 云端 同步' },
  // 关于
  { id: 'app-update', tab: 'about', title: () => tr('应用更新'), keywords: 'update version 更新 版本' },
  { id: 'about', tab: 'about', title: () => tr('关于 Billow'), keywords: 'about github license 版本' },
]

/** Plain lower-case substring search over title, description, keywords and category name. */
export function searchSettings(query: string, ctx: PlatformContext): SettingsEntry[] {
  const needle = query.trim().toLowerCase()
  if (!needle) return []
  const tokens = needle.split(/\s+/).filter(Boolean)

  const scored: { entry: SettingsEntry; score: number }[] = []
  for (const entry of SETTINGS_INDEX) {
    const pane = paneOf(entry.tab)
    if ((pane.when && !pane.when(ctx)) || (entry.when && !entry.when(ctx))) continue
    const category = categoryOf(entry.tab)
    const title = entry.title().toLowerCase()
    const haystack = [title, entry.description?.() ?? '', entry.keywords ?? '', category.label(), pane.label()].join(' ').toLowerCase()
    if (!tokens.every((token) => haystack.includes(token))) continue
    // Title hits first, prefix hits before infix ones.
    const score = title.startsWith(needle) ? 0 : title.includes(needle) ? 1 : 2
    scored.push({ entry, score })
  }
  return scored.sort((a, b) => a.score - b.score).map((item) => item.entry)
}

/** Where the effective-config viewer and error banners send a mihomo key. */
export function settingFor(id: string): { tab: CategoryId; id: string } | null {
  const entry = SETTINGS_INDEX.find((item) => item.id === id)
  return entry ? { tab: entry.tab, id: entry.id } : null
}
