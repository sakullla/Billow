<script setup lang="ts">
import { computed, inject, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import Icon from '../components/Icon.vue'
import Segmented from '../components/Segmented.vue'
import SelectField from '../components/SelectField.vue'
import Toggle from '../components/Toggle.vue'
import AppUpdateCard from '../components/AppUpdateCard.vue'
import { useStore } from '../lib/store'
import { layerDepth } from '../lib/ui/focus'
import { useHotkeys } from '../lib/ui/hotkeys'
import { shortcutKeyLabel } from '../lib/ui/shortcuts'
import { subscriptionUserAgent } from '../lib/subscription'
import { bypassOverride } from '../lib/bypass'
import {
  DEFAULT_PAC_SCRIPT,
  DEFAULT_PROXY_BYPASS,
  defaultDns,
  defaultSystemProxy,
  defaultTun,
  type DnsSettings,
  type KernelChannel,
  type KernelSettings,
  type SystemProxyMode,
  type SystemProxySettings,
  type ThemePreference,
  type TunSettings,
} from '../lib/types'
import type { SettingsTab } from '../lib/store'

const props = defineProps<{ compact?: boolean }>()
const appIcon = `${import.meta.env.BASE_URL}icon.png`
const store = useStore()
const snap = computed(() => store.snapshot.value)
const app = computed(() => store.app.value)
const kernel = computed(() => store.kernel.value)

const THEMES: { id: ThemePreference; label: string; icon: string }[] = [
  { id: 'system', label: '跟随系统', icon: 'laptop' },
  { id: 'light', label: '浅色', icon: 'sun' },
  { id: 'dark', label: '深色', icon: 'moon' },
]
const CHANNELS: { id: KernelChannel; label: string }[] = [
  { id: 'stable', label: '稳定版' },
  { id: 'preview', label: '预览版' },
]
const LOG_LEVELS = [
  { id: '', label: '跟随配置' },
  { id: 'debug', label: '调试' },
  { id: 'info', label: '信息' },
  { id: 'warning', label: '警告' },
  { id: 'error', label: '错误' },
  { id: 'silent', label: '静默' },
]
const PROCESS_MODES = [
  { id: '', label: '跟随配置' },
  { id: 'always', label: '始终' },
  { id: 'strict', label: '自动' },
  { id: 'off', label: '关闭' },
]

/** Seconds; '0' turns TCP keep-alive off. */
const KEEP_ALIVE = [
  { id: '', label: '跟随配置' },
  { id: '15', label: '15 秒' },
  { id: '30', label: '30 秒' },
  { id: '60', label: '60 秒' },
  { id: '120', label: '120 秒（省电）' },
  { id: '0', label: '关闭' },
]

type Flag = 'allow_lan' | 'ipv6' | 'unified_delay' | 'tcp_concurrent'
const FLAGS: { key: Flag; title: string; hint: string }[] = [
  { key: 'allow_lan', title: '局域网连接', hint: '允许同一网络的其他设备使用本机代理' },
  { key: 'ipv6', title: 'IPv6', hint: '解析并连接 IPv6 地址' },
  { key: 'unified_delay', title: '统一延迟', hint: '测速时去除握手耗时，结果更接近真实体验' },
  { key: 'tcp_concurrent', title: 'TCP 并发', hint: '同时连接多个解析结果，取最快的一个' },
]

const pendingSettings = ref<KernelSettings | null>(null)
const currentSettings = computed(() => pendingSettings.value ?? snap.value.settings)
const subscriptionUa = ref('')
const subscriptionUaFocused = ref(false)
const defaultSubscriptionUa = computed(() => subscriptionUserAgent(kernel.value.version))
watch(() => snap.value.settings.subscription_user_agent, (value) => {
  if (!subscriptionUaFocused.value) subscriptionUa.value = value
}, { immediate: true })
function commitSubscriptionUa() {
  const value = subscriptionUa.value
  if (value.length > 256 || /[^\x20-\x7e]/.test(value)) {
    store.toast('User-Agent 只能包含可打印的 ASCII 字符，不能含换行', 'error')
    return
  }
  if (value.trim() !== currentSettings.value.subscription_user_agent) save({ subscription_user_agent: value.trim() })
}


const port = ref('')
const portFocused = ref(false)
const portError = ref<string | null>(null)
const portInputEl = ref<HTMLInputElement | null>(null)
let lastSyncedPort: number | null | undefined = undefined
watch(
  () => snap.value.settings.mixed_port,
  (mixedPort) => {
    if (mixedPort === lastSyncedPort) return
    lastSyncedPort = mixedPort
    if (!portFocused.value && !portError.value) {
      port.value = mixedPort ? String(mixedPort) : ''
    }
  },
  { immediate: true },
)

const testUrl = ref('')
const timeout = ref('')
const testUrlFocused = ref(false)
const timeoutFocused = ref(false)
let lastSyncedProbe = ''
watch(
  () => `${snap.value.settings.test_url}\n${snap.value.settings.test_timeout_ms}`,
  (key) => {
    if (key === lastSyncedProbe) return
    lastSyncedProbe = key
    if (!testUrlFocused.value) {
      testUrl.value = snap.value.settings.test_url
    }
    if (!timeoutFocused.value) {
      timeout.value = snap.value.settings.test_timeout_ms ? String(snap.value.settings.test_timeout_ms) : ''
    }
  },
  { immediate: true },
)

const savedPortText = computed(() => {
  const mixed = currentSettings.value.mixed_port
  return mixed ? String(mixed) : ''
})
const portDirty = computed(() => port.value.trim() !== savedPortText.value)
const effectiveMixedPort = computed(
  () => snap.value.mixed_port ?? snap.value.settings.mixed_port ?? snap.value.config_values.mixed_port ?? 7890,
)

const probeDirty = computed(() => {
  const base = currentSettings.value
  const rawTimeout = timeout.value.trim()
  const ms = rawTimeout ? Number(rawTimeout) : 0
  return testUrl.value.trim() !== base.test_url || ms !== base.test_timeout_ms
})

const overridden = computed(() => {
  const s = snap.value.settings
  return Boolean(
    s.mixed_port || s.log_level || s.find_process_mode || s.test_url || s.test_timeout_ms || s.sniffer != null ||
      s.keep_alive_interval != null || s.lan_auth.length || s.lan_allowed_ips.length ||
      FLAGS.some((flag) => s[flag.key] != null),
  )
})

/** What the profile itself says about keep-alive, for the "跟随配置" hint. */
const profileKeepAlive = computed(() => {
  const config = snap.value.config_values
  if (config.disable_keep_alive) return '配置中已关闭'
  return config.keep_alive_interval ? `配置中为 ${config.keep_alive_interval} 秒` : '配置未设置，默认 15 秒'
})

// ── LAN access: only shown while 局域网连接 is on ──
const lanAddress = ref<string | null>(null)
const lanUser = ref('')
const lanPass = ref('')
const lanPassVisible = ref(false)
const lanIps = ref('')
let lastSyncedLan = ''

function splitAuth(entry: string | undefined): [string, string] {
  if (!entry) return ['', '']
  const at = entry.indexOf(':')
  return at < 0 ? [entry, ''] : [entry.slice(0, at), entry.slice(at + 1)]
}

watch(
  () => [snap.value.settings.lan_auth, snap.value.settings.lan_allowed_ips] as const,
  ([auth, ips]) => {
    const key = JSON.stringify([auth, ips])
    if (key === lastSyncedLan) return
    lastSyncedLan = key
    ;[lanUser.value, lanPass.value] = splitAuth(auth[0])
    lanIps.value = ips.join(', ')
  },
  { immediate: true },
)

const splitIps = (text: string) => text.split(/[\s,，;；]+/).map((item) => item.trim()).filter(Boolean)
const IP_ENTRY = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]*)(?:\/\d{1,3})?$/i
const lanDirty = computed(() => {
  const [user, pass] = splitAuth(snap.value.settings.lan_auth[0])
  return (
    lanUser.value.trim() !== user ||
    lanPass.value !== pass ||
    splitIps(lanIps.value).join(',') !== snap.value.settings.lan_allowed_ips.join(',')
  )
})

const lanOn = computed(() => effective('allow_lan'))
watch(
  lanOn,
  (on) => {
    if (on && lanAddress.value == null) {
      void store.backend
        .lanAddress()
        .then((address) => (lanAddress.value = address))
        .catch(() => (lanAddress.value = null))
    }
  },
  { immediate: true },
)
const lanPort = computed(() => snap.value.mixed_port ?? snap.value.settings.mixed_port ?? snap.value.config_values.mixed_port ?? 7890)

function saveLan() {
  const user = lanUser.value.trim()
  const pass = lanPass.value
  if (Boolean(user) !== Boolean(pass)) {
    store.toast('用户名和密码需要同时填写；都留空则不需要认证', 'error')
    return
  }
  if (/[\s:]/.test(user) || /\s/.test(pass)) {
    store.toast('用户名不能含空格或冒号，密码不能含空格', 'error')
    return
  }
  const ips = splitIps(lanIps.value)
  const bad = ips.find((item) => !IP_ENTRY.test(item))
  if (bad) {
    store.toast(`无法识别「${bad}」，请填写 IP 或网段，例如 192.168.1.0/24`, 'error')
    return
  }
  // Extra users from earlier versions or other tools stay; this form edits the first one.
  const rest = snap.value.settings.lan_auth.slice(1)
  lastSyncedLan = ''
  save({ lan_auth: user ? [`${user}:${pass}`, ...rest] : rest, lan_allowed_ips: ips })
}

function undoLan() {
  ;[lanUser.value, lanPass.value] = splitAuth(snap.value.settings.lan_auth[0])
  lanIps.value = snap.value.settings.lan_allowed_ips.join(', ')
}

async function copyLanAddress() {
  if (!lanAddress.value) return
  await store.copyText(`${lanAddress.value}:${lanPort.value}`, '已复制局域网代理地址')
}

function effective(key: Flag): boolean {
  return snap.value.settings[key] ?? snap.value.config_values[key] ?? false
}

function save(patch: Partial<KernelSettings>) {
  const next: KernelSettings = { ...currentSettings.value, ...patch }
  pendingSettings.value = next
  return store.saveSettings(next).finally(() => {
    if (pendingSettings.value === next) pendingSettings.value = null
  })
}

const PORT_RANGE_ERROR = '混合端口必须是 1–65535 之间的整数'

function validateMixedPort(raw: string): { valid: true; value: number | null } | { valid: false; message: string } {
  const text = raw.trim()
  if (!text) return { valid: true, value: null }
  if (!/^\d+$/.test(text)) return { valid: false, message: PORT_RANGE_ERROR }
  const num = Number(text)
  if (!Number.isSafeInteger(num) || num < 1 || num > 65535) {
    return { valid: false, message: PORT_RANGE_ERROR }
  }
  return { valid: true, value: num }
}

function onPortInput() {
  if (portError.value && port.value.trim() === savedPortText.value) {
    portError.value = null
  }
}

async function commitPort(silentInvalid = false, focusOnInvalid = false) {
  const base = currentSettings.value
  const checked = validateMixedPort(port.value)
  if (!checked.valid) {
    if (!silentInvalid) {
      portError.value = checked.message
      if (focusOnInvalid) {
        await nextTick()
        portInputEl.value?.scrollIntoView?.({ block: 'nearest' })
        portInputEl.value?.focus({ preventScroll: true })
      }
    }
    return
  }
  portError.value = null
  const value = checked.value
  if (value === base.mixed_port) {
    port.value = value ? String(value) : ''
    return
  }
  const previousPort = base.mixed_port
  lastSyncedPort = value
  const result = await save({ mixed_port: value })
  if (!result) {
    lastSyncedPort = previousPort
    portError.value = store.lastRunError.value ?? '混合端口未能保存'
    return
  }
  port.value = value ? String(value) : ''
}

function commitProbe(silentInvalid = false) {
  const base = currentSettings.value
  const trimmedUrl = testUrl.value.trim()
  const rawTimeout = timeout.value.trim()
  const parsed = rawTimeout ? Number(rawTimeout) : 0
  if (rawTimeout && (!Number.isInteger(parsed) || parsed < 0)) {
    if (!silentInvalid) {
      store.toast('测速超时需要是非负整数（毫秒）', 'error')
      timeout.value = base.test_timeout_ms ? String(base.test_timeout_ms) : ''
    }
    return
  }
  const ms = Number.isFinite(parsed) ? parsed : 0
  lastSyncedProbe = `${trimmedUrl}\n${ms}`
  if (trimmedUrl === base.test_url && ms === base.test_timeout_ms) return
  void save({ test_url: trimmedUrl, test_timeout_ms: ms })
}

function flushKernelInputs() {
  if (portDirty.value) void commitPort(true)
  if (portError.value) {
    portError.value = null
    port.value = snap.value.settings.mixed_port ? String(snap.value.settings.mixed_port) : ''
  }
  if (probeDirty.value) commitProbe(true)
}

watch(
  () => store.settingsTab.value,
  (_next, prev) => {
    if (prev === 'kernel') flushKernelInputs()
  },
)

onBeforeUnmount(() => {
  if (store.page.value !== 'settings') flushKernelInputs()
})

function reset() {
  portFocused.value = false
  portError.value = null
  testUrlFocused.value = false
  timeoutFocused.value = false
  port.value = ''
  testUrl.value = ''
  timeout.value = ''
  lastSyncedPort = null
  lastSyncedProbe = '\n0'
  void save({
    sniffer: null,
    keep_alive_interval: null,
    lan_auth: [],
    lan_allowed_ips: [],
    mixed_port: null,
    allow_lan: null,
    ipv6: null,
    log_level: null,
    unified_delay: null,
    tcp_concurrent: null,
    find_process_mode: null,
    test_url: '',
    test_timeout_ms: 0,
  })
}
void props

const copy = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T

/** Phone sub-pages go back through the app history when possible (App provides it). */
const settingsBack = inject<() => void>('settingsBack', () => (store.settingsTab.value = 'general'))
const openShortcuts = inject<(() => void) | null>('openShortcuts', null)
const SUB_TITLES: Record<SettingsTab, string> = {
  general: '设置',
  proxy: '系统代理',
  kernel: '内核',
  tun: 'TUN 模式',
  dns: 'DNS',
}

const isWindows = computed(
  () => app.value?.platform === 'windows' || (typeof navigator !== 'undefined' && /Windows/i.test(navigator.userAgent)),
)

const appSummary = computed(() => {
  const s = snap.value
  if (s.app_mode === 'include' && s.included.length) return `仅 ${s.included.length} 个应用`
  return s.excluded.length ? `绕过 ${s.excluded.length} 个` : '全部应用'
})

// ── System Proxy draft
const PROXY_MODES: { id: SystemProxyMode; label: string }[] = [
  { id: 'manual', label: '手动' },
  { id: 'pac', label: 'PAC' },
]
const proxyHost = ref('')
const proxyMode = ref<SystemProxyMode>('manual')
const pacScript = ref(DEFAULT_PAC_SCRIPT)
const bypassItems = ref<string[]>([])
const bypassBatchMode = ref(false)
const bypassBatchText = ref('')
const newBypassItem = ref('')
let lastSyncedProxy = ''

function parseBypassText(text: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of text.split(/[\r\n;,]+/)) {
    const item = raw.trim()
    if (item && !seen.has(item)) {
      seen.add(item)
      out.push(item)
    }
  }
  return out
}

function applyProxyDraft(value: SystemProxySettings) {
  proxyHost.value = value.host
  proxyMode.value = value.mode
  pacScript.value = value.pac_script || DEFAULT_PAC_SCRIPT
  bypassItems.value = [...value.bypass]
  bypassBatchText.value = value.bypass.join('\n')
  newBypassItem.value = ''
}

function loadProxy(value: SystemProxySettings) {
  applyProxyDraft(value)
  lastSyncedProxy = JSON.stringify(value)
}

watch(
  () => snap.value.settings.system_proxy,
  (value) => {
    const serialized = JSON.stringify(value)
    if (serialized === lastSyncedProxy) return
    loadProxy(value)
  },
  { immediate: true, deep: true },
)

const proxyDraft = computed<SystemProxySettings>(() => {
  const baseBypass = bypassBatchMode.value ? parseBypassText(bypassBatchText.value) : [...bypassItems.value]
  const pending = parseBypassText(newBypassItem.value)
  const merged = [...baseBypass]
  for (const item of pending) {
    if (!merged.includes(item)) merged.push(item)
  }
  return {
    host: proxyHost.value.trim(),
    mode: proxyMode.value,
    pac_script: pacScript.value.trim() || DEFAULT_PAC_SCRIPT,
    bypass: merged,
  }
})
const proxyDirty = computed(() => JSON.stringify(proxyDraft.value) !== JSON.stringify(snap.value.settings.system_proxy))

watch(bypassBatchText, (text) => {
  if (bypassBatchMode.value) bypassItems.value = parseBypassText(text)
})

function toggleBypassBatch() {
  if (bypassBatchMode.value) {
    bypassItems.value = parseBypassText(bypassBatchText.value)
    bypassBatchMode.value = false
  } else {
    bypassBatchText.value = bypassItems.value.join('\n')
    bypassBatchMode.value = true
  }
}

function addBypassItem() {
  const entries = parseBypassText(newBypassItem.value)
  if (!entries.length) return
  for (const item of entries) {
    if (!bypassItems.value.includes(item)) bypassItems.value.push(item)
  }
  bypassBatchText.value = bypassItems.value.join('\n')
  newBypassItem.value = ''
}

function removeBypassItem(index: number) {
  bypassItems.value.splice(index, 1)
  bypassBatchText.value = bypassItems.value.join('\n')
}

function clearBypass() {
  bypassItems.value = []
  bypassBatchText.value = ''
  newBypassItem.value = ''
}

function addDefaultBypass() {
  const current = bypassBatchMode.value ? parseBypassText(bypassBatchText.value) : [...bypassItems.value]
  let added = 0
  for (const item of DEFAULT_PROXY_BYPASS) {
    if (!current.includes(item)) {
      current.push(item)
      added += 1
    }
  }
  bypassItems.value = current
  bypassBatchText.value = current.join('\n')
  if (!added) store.toast('默认代理绕过规则已全部包含')
}

/** TUN sends every app to the kernel; bypass entries need DIRECT rules there. */
function bypassToOverride() {
  const append = bypassOverride(proxyDraft.value.bypass)
  const id = snap.value.active_id
  if (!append) {
    store.toast('列表中没有可以转换的地址', 'info')
    return
  }
  if (!id) {
    store.toast('请先启用一个配置', 'info')
    return
  }
  store.overrideRequest.value = { id, append }
  store.go('profiles')
}

function undoProxy() {
  loadProxy(snap.value.settings.system_proxy)
}

function resetProxy() {
  applyProxyDraft(defaultSystemProxy())
}

function saveProxy() {
  const draft = proxyDraft.value
  bypassItems.value = [...draft.bypass]
  bypassBatchText.value = draft.bypass.join('\n')
  newBypassItem.value = ''
  save({ system_proxy: draft })
}

// ── TUN draft
const STACKS = [
  { id: '', label: '默认' },
  { id: 'mixed', label: 'Mixed' },
  { id: 'gvisor', label: 'gVisor' },
  { id: 'system', label: 'System' },
] as const
const STACK_HINTS: Record<TunSettings['stack'], string> = {
  '': '跟随配置；配置未指定时用内核推荐的 Mips 自研协议栈（旧内核为 gVisor）',
  mips: 'Mips：mihomo 自研协议栈，新版内核的默认值',
  mixed: 'Mixed：TCP 走系统栈、UDP 走 gVisor；开着防火墙时需放行内核',
  gvisor: 'gVisor：用户态协议栈，隔离性好，不受系统防火墙影响',
  system: 'System：系统协议栈，占用最低；开着防火墙时需放行内核',
}
const tun = ref<TunSettings>(copy(snap.value.settings.tun))
const tunHijack = ref('')
const tunMtu = ref('')
let lastSyncedTun = ''
function applyTunDraft(value: TunSettings) {
  tun.value = copy(value)
  tunHijack.value = value.dns_hijack.join('\n')
  tunMtu.value = value.mtu ? String(value.mtu) : ''
}
function loadTun(value: TunSettings) {
  applyTunDraft(value)
  lastSyncedTun = JSON.stringify(value)
}
watch(
  () => snap.value.settings.tun,
  (value) => {
    const serialized = JSON.stringify(value)
    if (serialized === lastSyncedTun) return
    loadTun(value)
  },
  { immediate: true, deep: true },
)
const lines = (text: string) => text.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)
const tunDraft = computed<TunSettings>(() => {
  const mtuNum = Number(tunMtu.value.trim())
  return {
    ...tun.value,
    dns_hijack: lines(tunHijack.value),
    mtu: Number.isFinite(mtuNum) && mtuNum > 0 ? Math.round(mtuNum) : 0,
  }
})
const tunDirty = computed(() => JSON.stringify(tunDraft.value) !== JSON.stringify(snap.value.settings.tun))
function undoTun() {
  loadTun(snap.value.settings.tun)
}
function saveTun() {
  save({ tun: tunDraft.value })
}
function resetTun() {
  applyTunDraft(defaultTun())
}

// ── DNS draft
const MODES_DNS = [
  { id: 'fake-ip', label: 'Fake-IP' },
  { id: 'redir-host', label: 'Redir-Host' },
  { id: 'normal', label: 'Normal' },
] as const
const FILTER_MODES_DNS = [
  { id: 'blacklist', label: '黑名单' },
  { id: 'whitelist', label: '白名单' },
  { id: 'rule', label: '规则' },
] as const
const FILTER_MODE_HINTS: Record<DnsSettings['fake_ip_filter_mode'], string> = {
  blacklist: '黑名单：列表中的域名返回真实 IP，其余返回虚拟地址',
  whitelist: '白名单：仅列表中的域名返回虚拟地址，其余返回真实 IP',
  rule: '规则：列表按规则写法自上而下匹配，例如 GEOSITE,cn,real-ip，最后写 MATCH,fake-ip',
}
const CACHE_ALGOS_DNS = [
  { id: 'lru', label: 'LRU' },
  { id: 'arc', label: 'ARC' },
] as const
type ListKey = 'nameserver' | 'default_nameserver' | 'fallback' | 'proxy_server_nameserver' | 'direct_nameserver' | 'fake_ip_filter'
const LISTS: { key: ListKey; title: string; hint: string; fakeIpOnly?: boolean; core?: boolean }[] = [
  { key: 'nameserver', title: '主 DNS 服务器', hint: '默认用于解析所有域名，支持 DoH / DoT / DoQ', core: true },
  { key: 'default_nameserver', title: '引导 DNS', hint: '只用 IP 形式，用于解析上面 DoH 等服务器自身的域名', core: true },
  { key: 'proxy_server_nameserver', title: '节点域名解析', hint: '解析代理节点服务器地址' },
  { key: 'direct_nameserver', title: '直连域名解析', hint: '直连出站使用；留空则用主 DNS' },
  { key: 'fallback', title: '备用 DNS', hint: '可选，海外服务器；留空则不启用' },
  { key: 'fake_ip_filter', title: 'Fake-IP 过滤', hint: '黑名单下这些域名返回真实 IP；白名单下仅这些域名返回 Fake-IP；规则模式下每行一条规则', fakeIpOnly: true },
]
const CORE_DNS_LISTS = LISTS.filter((item) => item.core)
const ADV_DNS_LISTS = LISTS.filter((item) => !item.core)
const dns = ref<DnsSettings>(copy(snap.value.settings.dns))
const dnsText = ref<Record<ListKey, string>>({} as Record<ListKey, string>)
const policyRows = ref<{ pattern: string; servers: string }[]>([])
const policyBatchMode = ref(false)
const policyBatchText = ref('')
const newPolicyPattern = ref('')
const newPolicyServers = ref('')
const policyServersInput = ref<HTMLInputElement | null>(null)
const hostRows = ref<{ domain: string; targets: string }[]>([])
const hostBatchMode = ref(false)
const hostBatchText = ref('')
const newHostDomain = ref('')
const newHostTargets = ref('')
const hostTargetInput = ref<HTMLInputElement | null>(null)
let lastSyncedDns = ''

const splitTargets = (text: string) =>
  text
    .split(/[,;\n]+/)
    .map((item) => item.trim())
    .filter(Boolean)

function mapToRows(map: Record<string, string[]>): { key: string; val: string }[] {
  return Object.entries(map).map(([key, vals]) => ({ key, val: vals.join(', ') }))
}

function formatMapText(rows: { key: string; val: string }[]): string {
  return rows.map((row) => `${row.key} = ${row.val}`).join('\n')
}

/** `#` starts a comment only at the line start or after a space; DNS URLs may carry `#proxy` / `#h3=true`. */
const stripComment = (line: string) => line.replace(/(^|\s)#.*$/, '').trim()

/** 1-based numbers of non-empty lines a batch parser could not read. */
function invalidLines(text: string, parse: (line: string) => Record<string, string[]>): number[] {
  const out: number[] = []
  text.split(/\r?\n/).forEach((line, index) => {
    if (stripComment(line) && !Object.keys(parse(line)).length) out.push(index + 1)
  })
  return out
}

function parsePolicyBatchText(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {}
  for (const rawLine of text.split(/\r?\n/)) {
    const line = stripComment(rawLine)
    if (!line) continue
    const eq = line.indexOf('=')
    let pattern = ''
    let rest = ''
    // Also read YAML pasted from a config: `'+.a.com': [1.1.1.1, 2.2.2.2]`.
    const yamlPair = /^(['"]?)(.+?)\1:\s+(.+)$/.exec(line)
    if (eq > 0) {
      pattern = line.slice(0, eq).trim()
      rest = line.slice(eq + 1).trim()
    } else if (yamlPair) {
      pattern = yamlPair[2]
      rest = yamlPair[3]
    } else {
      const ws = line.search(/\s+/)
      if (ws > 0) {
        pattern = line.slice(0, ws).trim()
        rest = line.slice(ws + 1).trim()
      }
    }
    pattern = pattern.replace(/^(['"])(.*)\1$/, '$2').trim()
    const servers = splitTargets(rest.replace(/^\[(.*)\]$/, '$1')).map((item) => item.replace(/^(['"])(.*)\1$/, '$2'))
    if (pattern && servers.length) out[pattern] = servers
  }
  return out
}

function parseHostsBatchText(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {}
  const ipLiteral = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)$/
  for (const rawLine of text.split(/\r?\n/)) {
    const line = stripComment(rawLine)
    if (!line) continue
    const eq = line.indexOf('=')
    if (eq > 0) {
      const domain = line.slice(0, eq).trim()
      const targets = splitTargets(line.slice(eq + 1))
      if (domain && targets.length) out[domain] = targets
      continue
    }
    const tokens = line.split(/\s+/).filter(Boolean)
    if (tokens.length >= 2 && ipLiteral.test(tokens[0]!)) {
      const ip = tokens[0]!
      for (const host of tokens.slice(1)) {
        const list = out[host] ?? []
        if (!list.includes(ip)) list.push(ip)
        out[host] = list
      }
    } else if (tokens.length >= 2) {
      const domain = tokens[0]!
      const targets = splitTargets(tokens.slice(1).join(','))
      if (domain && targets.length) out[domain] = targets
    }
  }
  return out
}

function applyDnsDraft(value: DnsSettings) {
  dns.value = copy(value)
  dnsText.value = Object.fromEntries(LISTS.map((item) => [item.key, value[item.key].join('\n')])) as Record<ListKey, string>
  const pRows = mapToRows(value.nameserver_policy)
  policyRows.value = pRows.map(({ key, val }) => ({ pattern: key, servers: val }))
  policyBatchText.value = formatMapText(pRows)
  newPolicyPattern.value = ''
  newPolicyServers.value = ''
  const hRows = mapToRows(value.hosts)
  hostRows.value = hRows.map(({ key, val }) => ({ domain: key, targets: val }))
  hostBatchText.value = formatMapText(hRows)
  newHostDomain.value = ''
  newHostTargets.value = ''
}

function loadDns(value: DnsSettings) {
  applyDnsDraft(value)
  lastSyncedDns = JSON.stringify(value)
}

watch(
  () => snap.value.settings.dns,
  (value) => {
    const serialized = JSON.stringify(value)
    if (serialized === lastSyncedDns) return
    loadDns(value)
  },
  { immediate: true, deep: true },
)

function buildPolicyMap(): Record<string, string[]> {
  if (policyBatchMode.value) return parsePolicyBatchText(policyBatchText.value)
  const out: Record<string, string[]> = {}
  const all = [
    ...policyRows.value,
    ...(newPolicyPattern.value.trim() && newPolicyServers.value.trim()
      ? [{ pattern: newPolicyPattern.value, servers: newPolicyServers.value }]
      : []),
  ]
  for (const row of all) {
    const key = row.pattern.trim()
    const servers = splitTargets(row.servers)
    if (key && servers.length) out[key] = servers
  }
  return out
}

function buildHostsMap(): Record<string, string[]> {
  if (hostBatchMode.value) return parseHostsBatchText(hostBatchText.value)
  const out: Record<string, string[]> = {}
  const all = [
    ...hostRows.value,
    ...(newHostDomain.value.trim() && newHostTargets.value.trim()
      ? [{ domain: newHostDomain.value, targets: newHostTargets.value }]
      : []),
  ]
  for (const row of all) {
    const key = row.domain.trim()
    const targets = splitTargets(row.targets)
    if (key && targets.length) out[key] = targets
  }
  return out
}

function addPolicyRow() {
  const pattern = newPolicyPattern.value.trim()
  const servers = splitTargets(newPolicyServers.value)
  if (!pattern || !servers.length) return
  const existing = policyRows.value.find((row) => row.pattern.trim() === pattern)
  if (existing) existing.servers = servers.join(', ')
  else policyRows.value.push({ pattern, servers: servers.join(', ') })
  newPolicyPattern.value = ''
  newPolicyServers.value = ''
}

function addCnPolicyPreset() {
  const presetKey = 'geosite:cn,private'
  const presetVal = 'https://doh.pub/dns-query, 223.5.5.5'
  if (policyBatchMode.value) {
    const map = parsePolicyBatchText(policyBatchText.value)
    map[presetKey] = splitTargets(presetVal)
    policyBatchText.value = formatMapText(mapToRows(map))
    return
  }
  const existing = policyRows.value.find((row) => row.pattern.trim() === presetKey)
  if (existing) existing.servers = presetVal
  else policyRows.value.push({ pattern: presetKey, servers: presetVal })
}

// Batch text is the source of truth while it is shown: rows follow every edit, so
// switching back never depends on a one-shot conversion.
const policyInvalid = computed(() => (policyBatchMode.value ? invalidLines(policyBatchText.value, parsePolicyBatchText) : []))
watch(policyBatchText, (text) => {
  if (!policyBatchMode.value) return
  policyRows.value = mapToRows(parsePolicyBatchText(text)).map(({ key, val }) => ({ pattern: key, servers: val }))
})

function togglePolicyBatch() {
  if (policyBatchMode.value) {
    if (policyInvalid.value.length) {
      store.toast(`第 ${policyInvalid.value.join('、')} 行格式不对，修正或删除后再切换`, 'error')
      return
    }
    policyRows.value = mapToRows(parsePolicyBatchText(policyBatchText.value)).map(({ key, val }) => ({ pattern: key, servers: val }))
    policyBatchMode.value = false
  } else {
    addPolicyRow()
    policyBatchText.value = formatMapText(policyRows.value.map((r) => ({ key: r.pattern, val: r.servers })))
    policyBatchMode.value = true
  }
}

function addHostRow() {
  const domain = newHostDomain.value.trim()
  const targets = splitTargets(newHostTargets.value)
  if (!domain || !targets.length) return
  const existing = hostRows.value.find((row) => row.domain.trim() === domain)
  if (existing) existing.targets = targets.join(', ')
  else hostRows.value.push({ domain, targets: targets.join(', ') })
  newHostDomain.value = ''
  newHostTargets.value = ''
}

const hostInvalid = computed(() => (hostBatchMode.value ? invalidLines(hostBatchText.value, parseHostsBatchText) : []))
watch(hostBatchText, (text) => {
  if (!hostBatchMode.value) return
  hostRows.value = mapToRows(parseHostsBatchText(text)).map(({ key, val }) => ({ domain: key, targets: val }))
})

function toggleHostBatch() {
  if (hostBatchMode.value) {
    if (hostInvalid.value.length) {
      store.toast(`第 ${hostInvalid.value.join('、')} 行格式不对，修正或删除后再切换`, 'error')
      return
    }
    hostRows.value = mapToRows(parseHostsBatchText(hostBatchText.value)).map(({ key, val }) => ({ domain: key, targets: val }))
    hostBatchMode.value = false
  } else {
    addHostRow()
    hostBatchText.value = formatMapText(hostRows.value.map((r) => ({ key: r.domain, val: r.targets })))
    hostBatchMode.value = true
  }
}

const dnsDraft = computed<DnsSettings>(() => ({
  ...dns.value,
  listen: dns.value.listen.trim(),
  ...Object.fromEntries(LISTS.map((item) => [item.key, lines(dnsText.value[item.key] ?? '')])),
  nameserver_policy: buildPolicyMap(),
  hosts: buildHostsMap(),
}))
const dnsDirty = computed(() => JSON.stringify(dnsDraft.value) !== JSON.stringify(snap.value.settings.dns))
function saveDns() {
  const draft = dnsDraft.value
  policyRows.value = mapToRows(draft.nameserver_policy).map(({ key, val }) => ({ pattern: key, servers: val }))
  policyBatchText.value = formatMapText(mapToRows(draft.nameserver_policy))
  newPolicyPattern.value = ''
  newPolicyServers.value = ''
  hostRows.value = mapToRows(draft.hosts).map(({ key, val }) => ({ domain: key, targets: val }))
  hostBatchText.value = formatMapText(mapToRows(draft.hosts))
  newHostDomain.value = ''
  newHostTargets.value = ''
  save({ dns: draft })
}
function resetDns() {
  applyDnsDraft(defaultDns())
}

function saveActiveTab() {
  if (store.busy.settings) return
  const tab = store.settingsTab.value
  if (tab === 'proxy' && proxyDirty.value) saveProxy()
  else if (tab === 'tun' && tunDirty.value) saveTun()
  else if (tab === 'dns' && dnsDirty.value) saveDns()
  else if (tab === 'kernel') {
    if (lanDirty.value) saveLan()
    if (portDirty.value) commitPort()
    if (probeDirty.value) commitProbe()
  } else if (tab === 'general') {
    commitSubscriptionUa()
  }
}

useHotkeys([
  {
    combo: 'mod+s',
    allowInInput: true,
    when: () => layerDepth() === 0,
    handler: saveActiveTab,
  },
])

const saveKey = shortcutKeyLabel('mod+s')
const kernelDirty = computed(() => lanDirty.value || portDirty.value || probeDirty.value)

function onPolicyPatternEnter() {
  if (!newPolicyPattern.value.trim()) return
  if (!newPolicyServers.value.trim()) {
    policyServersInput.value?.focus()
    return
  }
  addPolicyRow()
}

function onHostDomainEnter() {
  if (!newHostDomain.value.trim()) return
  if (!newHostTargets.value.trim()) {
    hostTargetInput.value?.focus()
    return
  }
  addHostRow()
}

const TABS = computed(() => [
  { id: 'general' as SettingsTab, label: '通用', icon: 'sliders' },
  ...(store.isAndroid.value ? [] : [{ id: 'proxy' as SettingsTab, label: proxyDirty.value ? '系统代理 •' : '系统代理', icon: 'monitor' }]),
  { id: 'kernel' as SettingsTab, label: kernelDirty.value ? '内核 •' : '内核', icon: 'cpu' },
  ...(store.isAndroid.value ? [] : [{ id: 'tun' as SettingsTab, label: tunDirty.value ? 'TUN •' : 'TUN', icon: 'shield' }]),
  { id: 'dns' as SettingsTab, label: dnsDirty.value ? 'DNS •' : 'DNS', icon: 'globe' },
])
</script>

<template>
  <div class="page settings" :class="{ 'settings-phone': compact }">
    <!-- Phone sub-page: a back control and the section title replace the tab bar. -->
    <header v-if="compact && store.settingsTab.value !== 'general'" class="settings-subhead">
      <button type="button" class="back-btn" data-testid="settings-back" @click="settingsBack">
        <Icon name="chevron-left" :size="18" /><span>设置</span>
      </button>
      <h1>{{ SUB_TITLES[store.settingsTab.value] }}</h1>
    </header>
    <header v-else-if="compact" class="page-head">
      <div>
        <h1>设置</h1>
        <p class="muted small">Billow {{ app?.version ?? '' }}<template v-if="kernel.version"> · Mihomo {{ kernel.version }}</template></p>
      </div>
    </header>
    <header v-else class="page-head">
      <div>
        <h1>设置</h1>
        <p class="muted small">Billow {{ app?.version ?? '' }}</p>
      </div>
      <Segmented
        :model-value="store.settingsTab.value"
        :options="TABS"
        size="sm"
        label="设置分类"
        data-testid="settings-tabs"
        @update:model-value="(tab) => (store.settingsTab.value = tab)"
      />
    </header>

    <!-- ───────── 通用 ───────── -->
    <template v-if="store.settingsTab.value === 'general'">
      <!-- Phones reach the tool pages from here (the tab bar keeps four entries). -->
      <nav v-if="compact" class="tool-grid" aria-label="工具" data-testid="tool-grid">
        <button type="button" class="tool-tile" data-tool="connections" @click="store.go('connections')">
          <span class="tool-icon blue"><Icon name="activity" /></span>
          <strong>连接</strong>
          <span class="muted small">{{ snap.connected ? `${snap.connection_total} 个活动` : '未连接' }}</span>
        </button>
        <button type="button" class="tool-tile" data-tool="logs" @click="store.go('logs')">
          <span class="tool-icon amber"><Icon name="terminal" /></span>
          <strong>日志</strong>
          <span class="muted small">{{ snap.logs.length ? `${snap.logs.length} 条` : '暂无' }}</span>
        </button>
        <button type="button" class="tool-tile" data-tool="rules" @click="store.go('rules')">
          <span class="tool-icon violet"><Icon name="route" /></span>
          <strong>规则</strong>
          <span class="muted small">分流规则与命中</span>
        </button>
        <button type="button" class="tool-tile" data-tool="resources" @click="store.go('resources')">
          <span class="tool-icon green"><Icon name="database" /></span>
          <strong>外部资源</strong>
          <span class="muted small">规则集与代理集</span>
        </button>
      </nav>

      <!-- Phone: grouped list in the shape of the system settings app; each row says its current value. -->
      <template v-if="compact">
        <p class="settings-group-label">网络</p>
        <section class="card list-card settings-list" data-testid="settings-network">
          <button v-if="store.isAndroid.value" type="button" class="nav-row" data-testid="open-apps" @click="store.go('apps')">
            <span class="nav-row-icon green"><Icon name="apps" /></span>
            <span class="nav-row-title">应用访问控制</span>
            <span class="nav-row-value">{{ appSummary }}</span>
            <Icon name="chevron-right" :size="16" class="muted" />
          </button>
          <template v-else>
            <button type="button" class="nav-row" data-testid="open-proxy" @click="store.settingsTab.value = 'proxy'">
              <span class="nav-row-icon green"><Icon name="monitor" /></span>
              <span class="nav-row-title">系统代理</span>
              <span class="nav-row-value">{{ snap.system_proxy ? (snap.settings.system_proxy.mode === 'pac' ? 'PAC' : '已开启') : '关闭' }}</span>
              <Icon name="chevron-right" :size="16" class="muted" />
            </button>
            <button type="button" class="nav-row" data-testid="open-tun" @click="store.settingsTab.value = 'tun'">
              <span class="nav-row-icon blue"><Icon name="shield" /></span>
              <span class="nav-row-title">TUN 模式</span>
              <span class="nav-row-value">{{ snap.tun ? '已开启' : '关闭' }}</span>
              <Icon name="chevron-right" :size="16" class="muted" />
            </button>
          </template>
          <button type="button" class="nav-row" data-testid="open-dns" @click="store.settingsTab.value = 'dns'">
            <span class="nav-row-icon violet"><Icon name="globe" /></span>
            <span class="nav-row-title">DNS</span>
            <span class="nav-row-value">{{ snap.settings.dns_override ? '已覆写' : '跟随配置' }}</span>
            <Icon name="chevron-right" :size="16" class="muted" />
          </button>
          <button type="button" class="nav-row" data-testid="open-kernel" @click="store.settingsTab.value = 'kernel'">
            <span class="nav-row-icon amber"><Icon name="cpu" /></span>
            <span class="nav-row-title">内核</span>
            <span class="nav-row-value">{{ kernel.ready ? (kernel.version ?? '已安装') : '未安装' }}{{ overridden ? ' · 已调整' : '' }}</span>
            <Icon name="chevron-right" :size="16" class="muted" />
          </button>
        </section>

        <p class="settings-group-label">外观与启动</p>
        <section class="card list-card settings-list">
          <div class="nav-row static">
            <span class="nav-row-icon slate"><Icon :name="THEMES.find((theme) => theme.id === store.theme.value)?.icon ?? 'laptop'" /></span>
            <span class="nav-row-title">主题</span>
            <Segmented :model-value="store.theme.value" :options="THEMES.map(({ id, label }) => ({ id, label: id === 'system' ? '自动' : label }))" size="sm" label="主题" @update:model-value="store.setTheme" />
          </div>
          <div class="nav-row static">
            <span class="nav-row-icon green"><Icon name="power" /></span>
            <div class="grow min0">
              <span class="nav-row-title">打开时自动启动内核</span>
              <p class="muted small">异常退出时自动暂停重试并回退代理</p>
            </div>
            <Toggle
              :model-value="currentSettings.auto_connect"
              label="打开时自动启动内核"
              data-testid="auto-connect-toggle"
              @update:model-value="(on) => save({ auto_connect: on })"
            />
          </div>
        </section>
      </template>

      <section v-else class="card">
        <header class="card-head"><h2>外观与操作</h2></header>
        <div class="setting-row">
          <div class="grow">
            <strong>主题</strong>
            <p class="muted small">浅色、深色或跟随系统</p>
          </div>
          <Segmented :model-value="store.theme.value" :options="THEMES" size="sm" label="主题" @update:model-value="store.setTheme" />
        </div>
        <div v-if="openShortcuts" class="setting-row">
          <div class="grow">
            <strong>键盘快捷键</strong>
            <p class="muted small">命令面板、搜索聚焦与快速清除</p>
          </div>
          <button type="button" class="btn ghost sm" data-testid="settings-shortcuts" @click="openShortcuts()">
            <Icon name="keyboard" :size="15" />查看快捷键
          </button>
        </div>
      </section>

      <section v-if="!compact" class="card" data-testid="startup-settings">
        <header class="card-head"><h2>启动与窗口</h2></header>
        <div class="setting-row">
          <div class="grow">
            <strong>打开时自动启动内核</strong>
            <p class="muted small">启动 Billow 后自动恢复代理连接；若配置有误或内核连续异常退出，将自动停止重试并回退系统代理</p>
          </div>
          <Toggle
            :model-value="currentSettings.auto_connect"
            label="打开时自动启动内核"
            data-testid="auto-connect-toggle"
            @update:model-value="(on) => save({ auto_connect: on })"
          />
        </div>
        <template v-if="app && app.autostart != null">
          <div class="setting-row">
            <div class="grow">
              <strong>开机自启</strong>
              <p class="muted small">登录系统后自动运行 Billow</p>
            </div>
            <Toggle :model-value="Boolean(app.autostart)" label="开机自启" @update:model-value="store.setAutostart" />
          </div>
          <div class="setting-row">
            <div class="grow">
              <strong>静默启动</strong>
              <p class="muted small">开机自启时不弹出主窗口，只在托盘显示</p>
            </div>
            <Toggle :model-value="app.silent_start" label="静默启动" @update:model-value="(on) => store.setBehavior(app!.close_to_tray, on)" />
          </div>
          <div class="setting-row">
            <div class="grow">
              <strong>关闭时最小化到托盘</strong>
              <p class="muted small">关闭窗口后继续在后台运行；从托盘菜单退出</p>
            </div>
            <Toggle :model-value="app.close_to_tray" label="关闭时最小化到托盘" @update:model-value="(on) => store.setBehavior(on, app!.silent_start)" />
          </div>
        </template>
      </section>

      <!-- Phone: the rest of the general page keeps the grouped-list rhythm instead of loose cards. -->
      <template v-if="compact">
        <p class="settings-group-label">代理行为</p>
        <section class="card list-card settings-list" data-testid="node-switch-settings">
          <div class="nav-row static">
            <span class="nav-row-icon blue"><Icon name="refresh" /></span>
            <div class="grow min0">
              <span class="nav-row-title">切换节点后重连</span>
              <p class="muted small">让旧连接立即改走新节点，下载或通话可能中断</p>
            </div>
            <Toggle :model-value="currentSettings.close_connections_on_switch" label="切换节点后重连" data-testid="close-on-node-switch"
              @update:model-value="(on) => save({ close_connections_on_switch: on })" />
          </div>
          <details class="nav-fold" data-testid="subscription-settings" :open="Boolean(snap.settings.subscription_user_agent) || undefined">
            <summary class="nav-row">
              <span class="nav-row-icon violet"><Icon name="link" /></span>
              <span class="nav-row-title">订阅 User-Agent</span>
              <span class="nav-row-value">{{ snap.settings.subscription_user_agent ? '已自定义' : '默认' }}</span>
              <Icon name="chevron-right" :size="16" class="muted nav-fold-chevron" />
            </summary>
            <label class="field nav-fold-body">
              <span class="sr-only">默认 User-Agent</span>
              <input v-model="subscriptionUa" type="text" maxlength="256" :placeholder="defaultSubscriptionUa" spellcheck="false" autocomplete="off" autocapitalize="off" enterkeyhint="done" data-testid="global-subscription-user-agent"
                @focus="subscriptionUaFocused = true" @blur="subscriptionUaFocused = false; commitSubscriptionUa()" @keydown.enter.prevent="($event.target as HTMLInputElement).blur()" />
              <p class="muted small">更新订阅时使用；留空用内核默认值，单个订阅可在「编辑信息」中覆盖。</p>
            </label>
          </details>
        </section>

        <p class="settings-group-label">关于</p>
        <section class="card list-card settings-list" data-testid="settings-about">
          <AppUpdateCard variant="row" />
          <div v-if="app?.data_dir" class="nav-row static">
            <span class="nav-row-icon slate"><Icon name="database" /></span>
            <div class="grow min0">
              <span class="nav-row-title">数据目录</span>
              <p class="muted small mono ellipsis" :title="app.data_dir">{{ app.data_dir }}</p>
            </div>
            <button
              type="button"
              class="icon-btn"
              aria-label="复制数据目录路径"
              data-testid="copy-data-dir"
              @click="store.copyText(app.data_dir, '已复制数据目录路径')"
            >
              <Icon name="copy" :size="16" />
            </button>
          </div>
        </section>
        <p class="settings-foot">基于 Mihomo 内核的跨平台代理客户端 · GPL-3.0</p>
      </template>

      <template v-else>
      <section class="card" data-testid="node-switch-settings">
        <div class="setting-row">
          <div class="grow">
            <strong>切换节点后重连</strong>
            <p class="muted small">关闭经过当前代理组的旧连接，让应用重连新节点。下载、视频或通话可能中断；关闭后仅新连接使用新节点。</p>
          </div>
          <Toggle :model-value="currentSettings.close_connections_on_switch" label="切换节点后重连" data-testid="close-on-node-switch"
            @update:model-value="(on) => save({ close_connections_on_switch: on })" />
        </div>
      </section>

      <section class="card" data-testid="subscription-settings">
        <details class="settings-fold flush" :open="Boolean(snap.settings.subscription_user_agent) || undefined">
          <summary>
            <Icon name="chevron-right" :size="14" />
            <span>订阅请求</span>
            <span v-if="snap.settings.subscription_user_agent" class="tag accent sm">已自定义</span>
            <span class="muted small">更新订阅时使用的 User-Agent</span>
          </summary>
          <div class="settings-fold-body">
            <label class="field fold-field">
              <span>默认 User-Agent</span>
              <input v-model="subscriptionUa" type="text" maxlength="256" :placeholder="defaultSubscriptionUa" spellcheck="false" autocomplete="off" data-testid="global-subscription-user-agent"
                @focus="subscriptionUaFocused = true" @blur="subscriptionUaFocused = false; commitSubscriptionUa()" @keydown.enter.prevent="commitSubscriptionUa()" />
              <span class="muted small">留空使用内核默认值；单个订阅可在「编辑信息 › 高级选项」中覆盖。</span>
            </label>
          </div>
        </details>
      </section>

      <AppUpdateCard />

      <section class="card">
        <header class="card-head"><h2>关于</h2></header>
        <div class="about">
          <span class="brand-mark lg"><img :src="appIcon" alt="" /></span>
          <div class="grow min0">
            <strong>Billow</strong>
            <p class="muted small">基于 Mihomo 内核的跨平台代理客户端 · GPL-3.0</p>
            <div v-if="app?.data_dir" class="about-dir">
              <p class="muted small mono ellipsis" :title="app.data_dir">{{ app.data_dir }}</p>
              <button
                type="button"
                class="icon-btn sm"
                title="复制数据目录路径"
                aria-label="复制数据目录路径"
                data-testid="copy-data-dir"
                @click="store.copyText(app.data_dir, '已复制数据目录路径')"
              >
                <Icon name="copy" :size="13" />
              </button>
            </div>
          </div>
          <span class="muted small mono">v{{ app?.version ?? '—' }}</span>
        </div>
      </section>
      </template>
    </template>

    <!-- ───────── 系统代理 ───────── -->
    <template v-else-if="store.settingsTab.value === 'proxy'">
      <section class="card" data-testid="proxy-settings">
        <header class="card-head">
          <h2>系统代理</h2>
          <button type="button" class="btn ghost sm" @click="resetProxy">恢复默认</button>
        </header>
        <p class="muted small card-note">配置系统级 HTTP / SOCKS 接管方式、代理主机与 PAC 脚本。修改后立即应用，不会中断当前内核连接。</p>
        <div class="setting-row master-row" :class="{ active: snap.system_proxy }">
          <span class="row-icon"><Icon name="monitor" /></span>
          <div class="grow">
            <strong>启用系统代理</strong>
            <p class="muted small">{{ snap.system_proxy ? (snap.mixed_port ? `${snap.settings.system_proxy.host || '127.0.0.1'}:${snap.mixed_port}` : '已开启，连接后生效') : '未开启' }}</p>
          </div>
          <Toggle :model-value="snap.system_proxy" :busy="store.busy.proxy" label="启用系统代理" @update:model-value="store.setSystemProxy" />
        </div>
        <div class="setting-row wrap">
          <div class="grow">
            <strong>代理主机</strong>
            <p class="muted small">若无特殊需求请勿修改，留空默认使用 127.0.0.1</p>
          </div>
          <input
            v-model="proxyHost"
            class="input sm mono proxy-host-field"
            placeholder="127.0.0.1"
            aria-label="代理主机"
            data-testid="proxy-host-input"
          />
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>代理模式</strong>
            <p class="muted small">{{ proxyMode === 'pac' ? 'PAC 自动配置脚本：通过本地 HTTP 服务按域名动态决定是否走代理' : '手动代理：直接将 HTTP / HTTPS / SOCKS 指向本地混合端口' }}</p>
          </div>
          <Segmented v-model="proxyMode" :options="PROXY_MODES" size="sm" label="代理模式" data-testid="proxy-mode" />
        </div>
        <div v-if="proxyMode === 'pac'" class="setting-row stacked">
          <div class="kv-section-head">
            <div>
              <strong>PAC 脚本</strong>
              <p class="muted small">支持 <code>%proxy-host%</code> 与 <code>%mixed-port%</code> 占位符</p>
            </div>
            <button type="button" class="btn ghost sm" @click="pacScript = DEFAULT_PAC_SCRIPT">恢复默认脚本</button>
          </div>
          <textarea
            v-model="pacScript"
            class="input list-input mono"
            rows="9"
            spellcheck="false"
            aria-label="PAC 脚本"
            data-testid="pac-script-input"
          />
        </div>
        <div v-if="isWindows" class="setting-row">
          <div class="grow">
            <strong>UWP 工具</strong>
            <p class="muted small">解除 Windows 商店（UWP）应用的本地回环代理限制</p>
          </div>
          <button
            type="button"
            class="btn sm"
            :disabled="store.busy.uwp"
            data-testid="open-uwp-tool"
            @click="store.openUwpTool()"
          >
            打开 UWP 工具
          </button>
        </div>
      </section>

      <section class="card" data-testid="proxy-bypass-card">
        <header class="card-head wrap-head">
          <div>
            <h2>代理绕过列表 <span class="muted">{{ proxyDraft.bypass.length }}</span></h2>
            <p class="muted small">遵循系统代理的应用访问这些地址时直接连接，不经过内核</p>
          </div>
          <div class="head-actions">
            <button type="button" class="btn ghost sm" data-testid="add-default-bypass" @click="addDefaultBypass">
              添加默认代理绕过
            </button>
            <button
              v-if="bypassItems.length && !bypassBatchMode"
              type="button"
              class="btn ghost sm danger-text"
              data-testid="clear-bypass"
              @click="clearBypass"
            >
              清空
            </button>
            <button type="button" class="btn ghost sm" data-testid="toggle-bypass-batch" @click="toggleBypassBatch">
              {{ bypassBatchMode ? '列表视图' : '批量编辑' }}
            </button>
          </div>
        </header>
        <div v-if="snap.tun || snap.tun_wanted" class="hint-box small bypass-tun-note" data-testid="bypass-tun-note">
          <Icon name="info" :size="15" />
          <p class="grow">
            TUN 已开启：所有应用的流量都会进入内核，命令行工具等不读系统代理的程序不受绕过列表影响。需要直连请在当前配置的覆写里添加 DIRECT 规则。
          </p>
          <button type="button" class="btn sm" data-testid="bypass-to-override" @click="bypassToOverride">生成直连规则</button>
        </div>
        <template v-if="!bypassBatchMode">
          <div class="bypass-add-row">
            <input
              v-model="newBypassItem"
              class="input sm mono grow"
              placeholder="输入绕过域名、IP 或网段，如 *.corp.local 或 10.*"
              aria-label="新增代理绕过地址"
              data-testid="bypass-add-input"
              @keydown.enter.prevent="addBypassItem"
            />
            <button type="button" class="btn sm" :disabled="!newBypassItem.trim()" data-testid="bypass-add-btn" @click="addBypassItem">
              <Icon name="plus" :size="14" />添加
            </button>
          </div>
          <ul v-if="bypassItems.length" class="bypass-list" data-testid="bypass-list">
            <li v-for="(item, index) in bypassItems" :key="`${item}-${index}`" class="bypass-item">
              <span class="mono small ellipsis grow" :title="item">{{ item }}</span>
              <button
                type="button"
                class="icon-btn sm"
                :title="`删除 ${item}`"
                :aria-label="`删除 ${item}`"
                @click="removeBypassItem(index)"
              >
                <Icon name="trash" :size="14" />
              </button>
            </li>
          </ul>
          <p v-else class="muted small empty-hint">当前未配置代理绕过地址，可点击上方“添加默认代理绕过”快速填入局域网与本地回环地址。</p>
        </template>
        <div v-else class="setting-row stacked">
          <p class="muted small">每行一条，也支持分号或逗号分隔</p>
          <textarea
            v-model="bypassBatchText"
            class="input list-input mono"
            rows="8"
            spellcheck="false"
            aria-label="代理绕过列表批量编辑"
            data-testid="bypass-batch-textarea"
          />
        </div>
      </section>

      <div v-if="proxyDirty" class="save-bar floating-save-bar">
        <span class="muted small grow">有未保存的系统代理修改（保存后立即生效，不会中断连接）</span>
        <kbd v-if="!compact" class="palette-kbd save-kbd" aria-hidden="true">{{ saveKey }}</kbd>
        <button type="button" class="btn ghost sm" @click="undoProxy">撤销</button>
        <button type="button" class="btn primary sm" :disabled="store.busy.settings" data-testid="save-proxy" @click="saveProxy">保存</button>
      </div>
    </template>

    <!-- ───────── 内核 ───────── -->
    <template v-else-if="store.settingsTab.value === 'kernel'">
      <section class="card">
        <header class="card-head">
          <h2>Mihomo 内核</h2>
          <span class="tag" :class="kernel.ready ? 'ok' : 'warn'">{{ kernel.ready ? kernel.version ?? '已安装' : '未安装' }}</span>
        </header>
        <div class="setting-row">
          <div class="grow">
            <strong>更新渠道</strong>
            <p class="muted small">预览版更新更快，可能不稳定；切换后下次连接生效</p>
          </div>
          <Segmented
            :model-value="kernel.channel"
            :options="CHANNELS"
            size="sm"
            label="内核渠道"
            :disabled="store.busy.kernel"
            @update:model-value="store.setChannel"
          />
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>检查更新</strong>
            <p class="muted small">{{ kernel.failure ?? (store.isAndroid.value ? '内核随 Billow 更新，安装后即可使用' : '已安装的内核直接使用；可手动检查新版本') }}</p>
          </div>
          <button type="button" class="btn ghost sm" :disabled="store.busy.kernel" @click="store.isAndroid.value ? store.appUpdate.check() : store.refreshKernel()">
            <Icon name="refresh" :size="15" :class="{ spin: store.busy.kernel }" />检查
          </button>
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>生效配置</strong>
            <p class="muted small">{{ snap.active_id ? '合并订阅、覆写与下方设置后的全部选项，并标出每项来源' : '启用一份配置后可查看' }}</p>
          </div>
          <button
            type="button"
            class="btn ghost sm"
            :disabled="!snap.active_id"
            data-testid="settings-open-config"
            @click="store.openConfig()"
          >
            <Icon name="file" :size="15" />查看
          </button>
        </div>
      </section>

      <section class="card">
        <header class="card-head">
          <h2>内核设置</h2>
          <button v-if="overridden" type="button" class="btn ghost sm" @click="reset">全部跟随配置</button>
        </header>
        <p class="muted small card-note">这些设置覆盖每份配置中的同名项；留空或选择“跟随配置”则使用配置文件的值。修改后运行中的内核会自动重启。</p>
        <div class="setting-row wrap port-setting-row" :class="{ 'has-error': Boolean(portError) }">
          <div class="grow">
            <strong>混合代理端口<span v-if="snap.settings.mixed_port" class="tag accent sm">已覆盖</span></strong>
            <p class="muted small" data-testid="mixed-port-effective">
              HTTP 与 SOCKS5 共用，系统代理指向它 · 当前生效 {{ effectiveMixedPort }}
            </p>
          </div>
          <div class="port-field-wrap">
            <div class="inline-field">
              <input
                ref="portInputEl"
                v-model="port"
                class="input sm mono"
                inputmode="numeric"
                :placeholder="String(snap.config_values.mixed_port ?? 7890)"
                aria-label="混合代理端口"
                :aria-invalid="portError ? 'true' : undefined"
                :aria-describedby="portError ? 'mixed-port-error' : undefined"
                data-testid="mixed-port-input"
                @focus="portFocused = true"
                @input="onPortInput"
                @blur="portFocused = false; commitPort()"
                @keydown.enter.prevent="commitPort(false, true)"
              />
              <button
                v-if="portDirty || portError"
                type="button"
                class="btn primary sm"
                :disabled="store.busy.settings"
                data-testid="save-port"
                @mousedown.prevent
                @click="commitPort(false, true)"
              >
                保存
              </button>
            </div>
            <p
              v-if="portError"
              id="mixed-port-error"
              class="field-error small"
              role="alert"
              data-testid="mixed-port-error"
            >
              <Icon name="alert" :size="13" />
              <span>{{ portError }}</span>
            </p>
          </div>
        </div>
        <template v-for="flag in FLAGS" :key="flag.key">
          <div class="setting-row">
            <div class="grow">
              <strong>{{ flag.title }}<span v-if="snap.settings[flag.key] != null" class="tag accent sm">已覆盖</span></strong>
              <p class="muted small">{{ flag.hint }}</p>
            </div>
            <Toggle :model-value="effective(flag.key)" :busy="store.busy.settings" :label="flag.title" @update:model-value="(on) => save({ [flag.key]: on })" />
          </div>
          <!-- Sharing the proxy with other devices: where to point them and who may use it. -->
          <div v-if="flag.key === 'allow_lan' && lanOn" class="lan-block" data-testid="lan-block">
            <p class="lan-address small">
              <Icon name="network" :size="14" />
              <template v-if="lanAddress">
                其他设备的代理地址填
                <button type="button" class="lan-address-value mono" title="复制" data-testid="lan-address" @click="copyLanAddress">
                  {{ lanAddress }}:{{ lanPort }}<Icon name="copy" :size="12" />
                </button>
              </template>
              <template v-else>其他设备的代理地址填本机局域网 IP 与端口 {{ lanPort }}</template>
            </p>
            <div class="lan-field">
              <div class="lan-label">
                <strong>访问认证<span v-if="snap.settings.lan_auth.length" class="tag accent sm">已开启</span></strong>
                <p class="muted small">留空则不需要密码；本机访问始终免认证</p>
              </div>
              <div class="lan-inputs">
                <input
                  v-model="lanUser"
                  class="input sm"
                  autocomplete="off"
                  spellcheck="false"
                  placeholder="用户名"
                  aria-label="局域网访问用户名"
                  data-testid="lan-user"
                />
                <div class="lan-pass">
                  <input
                    v-model="lanPass"
                    class="input sm"
                    :type="lanPassVisible ? 'text' : 'password'"
                    autocomplete="new-password"
                    placeholder="密码"
                    aria-label="局域网访问密码"
                    data-testid="lan-pass"
                  />
                  <button
                    type="button"
                    class="icon-btn sm"
                    :aria-pressed="lanPassVisible"
                    :aria-label="lanPassVisible ? '隐藏密码' : '显示密码'"
                    @click="lanPassVisible = !lanPassVisible"
                  >
                    <Icon :name="lanPassVisible ? 'eye-off' : 'eye'" :size="14" />
                  </button>
                </div>
              </div>
            </div>
            <div class="lan-field">
              <div class="lan-label">
                <strong>允许的设备</strong>
                <p class="muted small">留空允许所有局域网设备；填 IP 或网段，逗号分隔</p>
              </div>
              <div class="lan-inputs">
                <input
                  v-model="lanIps"
                  class="input sm mono"
                  spellcheck="false"
                  :placeholder="lanAddress ? `${lanAddress.replace(/\.\d+$/, '.0')}/24` : '192.168.1.0/24'"
                  aria-label="允许的设备"
                  data-testid="lan-ips"
                  @keydown.enter="saveLan"
                />
              </div>
            </div>
            <div v-if="lanDirty" class="lan-actions">
              <button type="button" class="btn ghost sm" data-testid="undo-lan" @click="undoLan">撤销</button>
              <button type="button" class="btn primary sm" :disabled="store.busy.settings" data-testid="save-lan" @click="saveLan">保存</button>
            </div>
          </div>
        </template>
        <details class="settings-fold">
          <summary>
            <Icon name="chevron-right" :size="14" />
            <span>高级内核与测速选项</span>
            <span class="muted small">{{ store.isAndroid.value ? '日志、进程匹配、嗅探与测速地址' : '日志、进程匹配、嗅探、TCP 保活与测速地址' }}</span>
          </summary>
          <div class="settings-fold-body">
            <div class="setting-row">
              <div class="grow">
                <strong>日志级别</strong>
                <p class="muted small">配置中为 {{ snap.config_values.log_level ?? 'info' }}</p>
              </div>
              <SelectField
                :model-value="snap.settings.log_level ?? ''"
                :options="LOG_LEVELS.map((level) => ({ value: level.id, label: level.label }))"
                :sheet="compact"
                size="sm"
                label="日志级别"
                @update:model-value="(value) => save({ log_level: String(value) || null })"
              />
            </div>
            <div v-if="!store.isAndroid.value" class="setting-row">
              <div class="grow">
                <strong>进程匹配</strong>
                <p class="muted small">识别连接来自哪个应用，用于连接页与进程规则</p>
              </div>
              <SelectField
                :model-value="snap.settings.find_process_mode ?? ''"
                :options="PROCESS_MODES.map((mode) => ({ value: mode.id, label: mode.label }))"
                :sheet="compact"
                size="sm"
                label="进程匹配"
                @update:model-value="(value) => save({ find_process_mode: String(value) || null })"
              />
            </div>
            <div class="setting-row">
              <div class="grow">
                <strong>域名嗅探<span v-if="snap.settings.sniffer != null" class="tag accent sm">已覆盖</span></strong>
                <p class="muted small">从 HTTP / TLS / QUIC 流量中识别域名，让按域名分流在 IP 直连时也生效</p>
              </div>
              <Toggle :model-value="Boolean(snap.settings.sniffer)" :busy="store.busy.settings" label="域名嗅探" @update:model-value="(on) => save({ sniffer: on })" />
            </div>
            <!-- mihomo always disables TCP keep-alive on Android, so the choice would do nothing there. -->
            <div v-if="!store.isAndroid.value" class="setting-row">
              <div class="grow">
                <strong>TCP 保活<span v-if="snap.settings.keep_alive_interval != null" class="tag accent sm">已覆盖</span></strong>
                <p class="muted small">空闲连接的心跳间隔，手机上调长可省电；{{ profileKeepAlive }}</p>
              </div>
              <SelectField
                :model-value="snap.settings.keep_alive_interval == null ? '' : String(snap.settings.keep_alive_interval)"
                :options="KEEP_ALIVE.map((item) => ({ value: item.id, label: item.label }))"
                :sheet="compact"
                size="sm"
                label="TCP 保活"
                data-testid="keep-alive-select"
                @update:model-value="(value) => save({ keep_alive_interval: value === '' ? null : Number(value) })"
              />
            </div>
            <div class="setting-row wrap">
              <div class="grow">
                <strong>测速地址</strong>
                <p class="muted small">延迟测试请求的网址与超时（毫秒）</p>
              </div>
              <div class="inline-field">
                <div class="input-pair">
                  <input
                    v-model="testUrl"
                    class="input sm mono"
                    type="url"
                    placeholder="http://www.gstatic.com/generate_204"
                    aria-label="测速地址"
                    @focus="testUrlFocused = true"
                    @blur="testUrlFocused = false; commitProbe()"
                    @keydown.enter="($event.target as HTMLInputElement).blur()"
                  />
                  <input
                    v-model="timeout"
                    class="input sm mono short"
                    inputmode="numeric"
                    placeholder="5000"
                    aria-label="测速超时"
                    @focus="timeoutFocused = true"
                    @blur="timeoutFocused = false; commitProbe()"
                    @keydown.enter="($event.target as HTMLInputElement).blur()"
                  />
                </div>
                <button
                  v-if="probeDirty"
                  type="button"
                  class="btn primary sm"
                  :disabled="store.busy.settings"
                  data-testid="save-probe"
                  @mousedown.prevent
                  @click="commitProbe()"
                >
                  保存
                </button>
              </div>
            </div>
          </div>
        </details>
      </section>
    </template>

    <!-- ───────── TUN ───────── -->
    <template v-else-if="store.settingsTab.value === 'tun'">
      <section class="card" data-testid="tun-settings">
        <header class="card-head">
          <h2>TUN 模式</h2>
          <button type="button" class="btn ghost sm" @click="resetTun">恢复默认</button>
        </header>
        <p class="muted small card-note">在系统中创建虚拟网卡接管全部流量，包括不读取系统代理的应用和命令行工具。以下设置覆盖配置文件中的 tun 段。</p>
        <div class="setting-row master-row" :class="{ active: snap.tun }">
          <span class="row-icon"><Icon name="shield" /></span>
          <div class="grow">
            <strong>启用 TUN</strong>
            <p class="muted small">{{ snap.tun ? '运行中' : snap.tun_wanted ? '已记住开启，下次连接生效' : '未开启' }}；首次开启需要系统授权</p>
          </div>
          <Toggle :model-value="snap.tun" :busy="store.busy.tun" label="启用 TUN" @update:model-value="store.setTun" />
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>协议栈</strong>
            <p class="muted small">{{ STACK_HINTS[tun.stack] }}</p>
          </div>
          <Segmented v-model="tun.stack" :options="STACKS" size="sm" label="协议栈" data-testid="tun-stack" />
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>自动设置路由</strong>
            <p class="muted small">把全局流量路由到 TUN 网卡，关闭后需要自行配置路由</p>
          </div>
          <Toggle v-model="tun.auto_route" label="自动设置路由" />
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>严格路由</strong>
            <p class="muted small">阻止流量绕过 TUN（防 DNS 泄漏），但可能让局域网访问失效</p>
          </div>
          <Toggle v-model="tun.strict_route" label="严格路由" />
        </div>
        <details class="settings-fold">
          <summary>
            <Icon name="chevron-right" :size="14" />
            <span>高级虚拟网卡参数</span>
            <span class="muted small">出口接口、DNS 劫持、MTU 与网卡名称</span>
          </summary>
          <div class="settings-fold-body">
            <div class="setting-row">
              <div class="grow">
                <strong>自动选择出口网卡</strong>
                <p class="muted small">避免代理流量绕回 TUN 造成回环</p>
              </div>
              <Toggle v-model="tun.auto_detect_interface" label="自动选择出口网卡" />
            </div>
            <div class="setting-row wrap">
              <div class="grow">
                <strong>DNS 劫持</strong>
                <p class="muted small">把发往这些地址的 DNS 查询交给内核，每行一个</p>
              </div>
              <textarea v-model="tunHijack" class="input list-input mono" rows="2" spellcheck="false" aria-label="DNS 劫持" />
            </div>
            <div class="setting-row">
              <div class="grow">
                <strong>MTU</strong>
                <p class="muted small">一般保持 1500；遇到大包问题可调小，例如 1400</p>
              </div>
              <input v-model="tunMtu" class="input sm mono short" inputmode="numeric" placeholder="1500" aria-label="MTU" />
            </div>
            <div class="setting-row">
              <div class="grow">
                <strong>网卡名称</strong>
                <p class="muted small">留空由内核决定（macOS 需为 utun 开头）</p>
              </div>
              <input v-model="tun.device" class="input sm mono" placeholder="自动" aria-label="网卡名称" />
            </div>
          </div>
        </details>
      </section>

      <div v-if="tunDirty" class="save-bar floating-save-bar">
        <span class="muted small grow">有未保存的修改{{ snap.kernel_running ? '，保存后将平滑热重载生效' : '' }}</span>
        <kbd v-if="!compact" class="palette-kbd save-kbd" aria-hidden="true">{{ saveKey }}</kbd>
        <button type="button" class="btn ghost sm" @click="undoTun">撤销</button>
        <button type="button" class="btn primary sm" :disabled="store.busy.settings" data-testid="save-tun" @click="saveTun">保存</button>
      </div>
    </template>

    <!-- ───────── DNS ───────── -->
    <template v-else>
      <section class="card" data-testid="dns-settings">
        <header class="card-head">
          <h2>DNS</h2>
          <button type="button" class="btn ghost sm" @click="resetDns">恢复默认</button>
        </header>
        <div class="setting-row master-row" :class="{ active: snap.settings.dns_override }">
          <span class="row-icon"><Icon name="sliders" /></span>
          <div class="grow">
            <strong>DNS 覆写</strong>
            <p class="muted small">开启后用下面的设置替换每份配置里的 dns 段与自定义 hosts；关闭则使用配置文件自带的设置</p>
          </div>
          <Toggle
            :model-value="snap.settings.dns_override"
            :busy="store.busy.settings"
            label="DNS 覆写"
            data-testid="dns-override"
            @update:model-value="(on) => save({ dns_override: on, dns: dnsDraft })"
          />
        </div>
        <p v-if="!snap.settings.dns_override" class="hint-box small">
          <Icon name="info" :size="14" />
          覆写关闭时，若开启 TUN 而配置文件没有启用 DNS，Billow 会自动使用下方设置，避免 TUN 下域名无法解析。
        </p>
        <div class="setting-row">
          <div class="grow">
            <strong>域名映射模式</strong>
            <p class="muted small">
              {{ dns.enhanced_mode === 'fake-ip' ? 'Fake-IP：先返回虚拟地址，连接时再解析，速度最快' : dns.enhanced_mode === 'redir-host' ? 'Redir-Host：返回真实 IP 并记录映射，兼容性更好' : 'Normal：标准解析，不做增强映射' }}
            </p>
          </div>
          <Segmented v-model="dns.enhanced_mode" :options="MODES_DNS" size="sm" label="增强模式" data-testid="dns-enhanced-mode" />
        </div>
        <template v-for="item in CORE_DNS_LISTS" :key="item.key">
          <div class="setting-row stacked">
            <div>
              <strong>{{ item.title }}</strong>
              <p class="muted small">{{ item.hint }}，每行一个</p>
            </div>
            <textarea
              v-model="dnsText[item.key]"
              class="input list-input mono"
              :rows="Math.min(6, Math.max(2, (dnsText[item.key] ?? '').split('\n').length))"
              spellcheck="false"
              :aria-label="item.title"
            />
          </div>
        </template>
        <details class="settings-fold">
          <summary>
            <Icon name="chevron-right" :size="14" />
            <span>高级解析参数</span>
            <span class="muted small">{{ dns.enhanced_mode === 'fake-ip' ? 'Fake-IP 地址池、监听端口、HTTP/3、缓存与分流解析' : '监听端口、HTTP/3、缓存算法与分流解析' }}</span>
          </summary>
          <div class="settings-fold-body">
            <div v-if="dns.enhanced_mode === 'fake-ip'" class="setting-row">
              <div class="grow">
                <strong>Fake-IP 地址段</strong>
                <p class="muted small">虚拟地址池，不要与本地网络冲突</p>
              </div>
              <input v-model="dns.fake_ip_range" class="input sm mono" aria-label="Fake-IP 地址段" />
            </div>
            <div v-if="dns.enhanced_mode === 'fake-ip'" class="setting-row">
              <div class="grow">
                <strong>过滤列表模式</strong>
                <p class="muted small">{{ FILTER_MODE_HINTS[dns.fake_ip_filter_mode] }}</p>
              </div>
              <Segmented
                v-model="dns.fake_ip_filter_mode"
                :options="FILTER_MODES_DNS"
                size="sm"
                label="过滤列表模式"
                data-testid="dns-filter-mode"
              />
            </div>
            <div class="setting-row">
              <div class="grow">
                <strong>DNS 监听地址</strong>
                <p class="muted small">可选本地监听端口，例如 <code>127.0.0.1:1053</code>；留空则仅在内核内部处理</p>
              </div>
              <input
                v-model="dns.listen"
                class="input sm mono"
                placeholder="留空不监听"
                aria-label="DNS 监听地址"
                data-testid="dns-listen"
              />
            </div>
            <div class="setting-row">
              <div class="grow">
                <strong>IPv6 解析</strong>
                <p class="muted small">允许返回 AAAA 记录</p>
              </div>
              <Toggle v-model="dns.ipv6" label="IPv6 解析" />
            </div>
            <div class="setting-row">
              <div class="grow">
                <strong>DoH 优先 HTTP/3</strong>
                <p class="muted small">加密 DNS 支持 QUIC 时优先使用 HTTP/3 连接（prefer-h3）</p>
              </div>
              <Toggle v-model="dns.prefer_h3" label="DoH 优先 HTTP/3" data-testid="dns-prefer-h3" />
            </div>
            <div class="setting-row">
              <div class="grow">
                <strong>缓存算法</strong>
                <p class="muted small">ARC 命中率更高，LRU 内存开销更稳定</p>
              </div>
              <Segmented v-model="dns.cache_algorithm" :options="CACHE_ALGOS_DNS" size="sm" label="缓存算法" data-testid="dns-cache-algorithm" />
            </div>
            <div class="setting-row">
              <div class="grow">
                <strong>遵循分流规则</strong>
                <p class="muted small">DNS 查询也按分流规则走代理或直连（respect-rules）</p>
              </div>
              <Toggle v-model="dns.respect_rules" label="遵循分流规则" />
            </div>
            <div class="setting-row">
              <div class="grow">
                <strong>直连遵循解析策略</strong>
                <p class="muted small">直连出站解析域名时优先匹配下方的域名解析策略（direct-nameserver-follow-policy）</p>
              </div>
              <Toggle v-model="dns.direct_nameserver_follow_policy" label="直连遵循解析策略" data-testid="dns-direct-follow-policy" />
            </div>
            <template v-for="item in ADV_DNS_LISTS" :key="item.key">
              <div v-if="!item.fakeIpOnly || dns.enhanced_mode === 'fake-ip'" class="setting-row stacked">
                <div>
                  <strong>{{ item.title }}</strong>
                  <p class="muted small">{{ item.hint }}，每行一个</p>
                </div>
                <textarea
                  v-model="dnsText[item.key]"
                  class="input list-input mono"
                  :rows="Math.min(8, Math.max(2, (dnsText[item.key] ?? '').split('\n').length))"
                  spellcheck="false"
                  :aria-label="item.title"
                />
              </div>
            </template>
          </div>
        </details>
      </section>

      <section class="card" data-testid="dns-policy-card">
        <header class="card-head wrap-head">
          <div>
            <h2>域名解析策略 <span v-if="Object.keys(dnsDraft.nameserver_policy).length" class="muted">{{ Object.keys(dnsDraft.nameserver_policy).length }}</span></h2>
            <p class="muted small">按域名、通配符或规则集指定专属上游 DNS（nameserver-policy），避免国内外域名分流污染</p>
          </div>
          <div class="head-actions">
            <button type="button" class="btn ghost sm" data-testid="preset-cn-policy" @click="addCnPolicyPreset">
              <Icon name="plus" :size="14" />国内域名分流
            </button>
            <button type="button" class="btn ghost sm" data-testid="toggle-policy-batch" @click="togglePolicyBatch">
              {{ policyBatchMode ? '列表视图' : '批量编辑' }}
            </button>
          </div>
        </header>
        <template v-if="!policyBatchMode">
          <div class="kv-add-row">
            <input
              v-model="newPolicyPattern"
              class="input sm mono kv-key"
              placeholder="规则，如 geosite:cn 或 +.corp.local"
              aria-label="解析策略匹配规则"
              data-testid="policy-pattern-input"
              @keydown.enter.prevent="onPolicyPatternEnter"
            />
            <input
              ref="policyServersInput"
              v-model="newPolicyServers"
              class="input sm mono grow"
              placeholder="DNS 服务器，多个用逗号分隔"
              aria-label="解析策略 DNS 服务器"
              data-testid="policy-servers-input"
              @keydown.enter.prevent="addPolicyRow"
            />
            <button
              type="button"
              class="btn sm"
              :disabled="!newPolicyPattern.trim() || !newPolicyServers.trim()"
              data-testid="add-policy-btn"
              @click="addPolicyRow"
            >
              <Icon name="plus" :size="14" />添加
            </button>
          </div>
          <div v-if="policyRows.length" class="kv-list" data-testid="policy-list">
            <div v-for="(row, index) in policyRows" :key="index" class="kv-row">
              <input v-model="row.pattern" class="input sm mono kv-key" placeholder="匹配规则" :aria-label="`策略规则 ${index + 1}`" />
              <input v-model="row.servers" class="input sm mono grow" placeholder="DNS 服务器" :aria-label="`策略服务器 ${index + 1}`" />
              <button type="button" class="icon-btn sm" title="删除策略" aria-label="删除策略" @click="policyRows.splice(index, 1)">
                <Icon name="trash" :size="14" />
              </button>
            </div>
          </div>
          <p v-else class="muted small empty-hint">尚未配置专属域名解析策略，支持 <code>+.domain.com</code>、<code>geosite:cn</code>、<code>rule-set:name</code> 等格式。</p>
        </template>
        <div v-else class="setting-row stacked">
          <p class="muted small">每行一条，格式：<code>规则 = DNS1, DNS2</code>（例如 <code>geosite:cn,private = https://doh.pub/dns-query, 223.5.5.5</code>）</p>
          <textarea
            v-model="policyBatchText"
            class="input list-input mono"
            rows="6"
            spellcheck="false"
            aria-label="域名解析策略批量编辑"
            data-testid="policy-batch-textarea"
            :aria-invalid="policyInvalid.length ? 'true' : undefined"
          />
          <p v-if="policyInvalid.length" class="field-error small" role="alert" data-testid="policy-batch-invalid">
            <Icon name="alert" :size="13" /> 第 {{ policyInvalid.join('、') }} 行缺少“=”或 DNS 服务器，保存时会被忽略
          </p>
        </div>
      </section>

      <section class="card" data-testid="dns-hosts-card">
        <header class="card-head wrap-head">
          <div>
            <h2>Hosts 映射 <span v-if="Object.keys(dnsDraft.hosts).length" class="muted">{{ Object.keys(dnsDraft.hosts).length }}</span></h2>
            <p class="muted small">静态域名解析与本机 Hosts 控制，支持 IP 列表与泛域名映射</p>
          </div>
          <button type="button" class="btn ghost sm" data-testid="toggle-host-batch" @click="toggleHostBatch">
            {{ hostBatchMode ? '列表视图' : '批量编辑' }}
          </button>
        </header>
        <div class="setting-row">
          <div class="grow">
            <strong>使用 hosts</strong>
            <p class="muted small">启用配置与下方自定义的静态域名映射（use-hosts）</p>
          </div>
          <Toggle v-model="dns.use_hosts" label="使用 hosts" />
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>读取系统 Hosts</strong>
            <p class="muted small">同时读取操作系统 /etc/hosts 或 Windows hosts 文件（use-system-hosts）</p>
          </div>
          <Toggle v-model="dns.use_system_hosts" label="读取系统 Hosts" data-testid="dns-system-hosts" />
        </div>
        <template v-if="!hostBatchMode">
          <div class="kv-add-row">
            <input
              v-model="newHostDomain"
              class="input sm mono kv-key"
              placeholder="域名，如 router.local 或 *.dev.test"
              aria-label="Hosts 域名"
              data-testid="host-domain-input"
              @keydown.enter.prevent="onHostDomainEnter"
            />
            <input
              ref="hostTargetInput"
              v-model="newHostTargets"
              class="input sm mono grow"
              placeholder="IP 或目标域名，多个用逗号分隔"
              aria-label="Hosts 目标地址"
              data-testid="host-target-input"
              @keydown.enter.prevent="addHostRow"
            />
            <button
              type="button"
              class="btn sm"
              :disabled="!newHostDomain.trim() || !newHostTargets.trim()"
              data-testid="add-host-btn"
              @click="addHostRow"
            >
              <Icon name="plus" :size="14" />添加
            </button>
          </div>
          <div v-if="hostRows.length" class="kv-list" data-testid="hosts-list">
            <div v-for="(row, index) in hostRows" :key="index" class="kv-row">
              <input v-model="row.domain" class="input sm mono kv-key" placeholder="域名" :aria-label="`Hosts 域名 ${index + 1}`" />
              <input v-model="row.targets" class="input sm mono grow" placeholder="IP 或目标域名" :aria-label="`Hosts 地址 ${index + 1}`" />
              <button type="button" class="icon-btn sm" title="删除映射" aria-label="删除映射" @click="hostRows.splice(index, 1)">
                <Icon name="trash" :size="14" />
              </button>
            </div>
          </div>
          <p v-else class="muted small empty-hint">尚未添加自定义 Hosts 映射。</p>
        </template>
        <div v-else class="setting-row stacked">
          <p class="muted small">支持 <code>域名 = IP1, IP2</code> 或标准系统 hosts 格式 <code>192.168.1.1 router.local</code></p>
          <textarea
            v-model="hostBatchText"
            class="input list-input mono"
            rows="6"
            spellcheck="false"
            aria-label="Hosts 批量编辑"
            data-testid="host-batch-textarea"
            :aria-invalid="hostInvalid.length ? 'true' : undefined"
          />
          <p v-if="hostInvalid.length" class="field-error small" role="alert" data-testid="host-batch-invalid">
            <Icon name="alert" :size="13" /> 第 {{ hostInvalid.join('、') }} 行缺少目标地址，保存时会被忽略
          </p>
        </div>
      </section>

      <div v-if="dnsDirty" class="save-bar floating-save-bar">
        <span class="muted small grow">有未保存的 DNS 修改{{ snap.kernel_running && snap.settings.dns_override ? '，保存后将平滑热重载生效' : '' }}</span>
        <kbd v-if="!compact" class="palette-kbd save-kbd" aria-hidden="true">{{ saveKey }}</kbd>
        <button type="button" class="btn ghost sm" @click="loadDns(snap.settings.dns)">撤销</button>
        <button type="button" class="btn primary sm" :disabled="store.busy.settings" data-testid="save-dns" @click="saveDns">保存</button>
      </div>

      <section class="card">
        <header class="card-head"><h2>缓存</h2></header>
        <div class="setting-row">
          <div class="grow">
            <strong>清除 FakeIP 缓存</strong>
            <p class="muted small">虚拟地址映射错乱、换节点后网站仍打不开时使用</p>
          </div>
          <button type="button" class="btn sm" :disabled="!snap.kernel_running || store.busy['flush:fakeip']" @click="store.flushCache('fakeip')">清除</button>
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>清除 DNS 缓存</strong>
            <p class="muted small">让内核重新解析所有域名</p>
          </div>
          <button type="button" class="btn sm" :disabled="!snap.kernel_running || store.busy['flush:dns']" @click="store.flushCache('dns')">清除</button>
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>DNS 查询</strong>
            <p class="muted small">用内核当前的 DNS 配置解析域名，查看记录、TTL 与耗时</p>
          </div>
          <button type="button" class="btn sm" data-testid="open-dns-query" @click="store.dnsQueryOpen.value = true">查询</button>
        </div>
      </section>
    </template>
  </div>
</template>
