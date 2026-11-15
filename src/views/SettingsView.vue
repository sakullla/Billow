<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import Icon from '../components/Icon.vue'
import Segmented from '../components/Segmented.vue'
import Toggle from '../components/Toggle.vue'
import { useStore } from '../lib/store'
import { defaultDns, defaultTun, type DnsSettings, type KernelChannel, type KernelSettings, type ThemePreference, type TunSettings } from '../lib/types'
import type { SettingsTab } from '../lib/store'

const props = defineProps<{ compact?: boolean }>()
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

type Flag = 'allow_lan' | 'ipv6' | 'unified_delay' | 'tcp_concurrent'
const FLAGS: { key: Flag; title: string; hint: string }[] = [
  { key: 'allow_lan', title: '局域网连接', hint: '允许同一网络的其他设备使用本机代理' },
  { key: 'ipv6', title: 'IPv6', hint: '解析并连接 IPv6 地址' },
  { key: 'unified_delay', title: '统一延迟', hint: '测速时去除握手耗时，结果更接近真实体验' },
  { key: 'tcp_concurrent', title: 'TCP 并发', hint: '同时连接多个解析结果，取最快的一个' },
]

const port = ref('')
const testUrl = ref('')
const timeout = ref('')
watch(
  () => snap.value.settings,
  (settings) => {
    port.value = settings.mixed_port ? String(settings.mixed_port) : ''
    testUrl.value = settings.test_url
    timeout.value = settings.test_timeout_ms ? String(settings.test_timeout_ms) : ''
  },
  { immediate: true },
)

const overridden = computed(() => {
  const s = snap.value.settings
  return Boolean(
    s.mixed_port || s.log_level || s.find_process_mode || s.test_url || s.test_timeout_ms || s.sniffer != null ||
      FLAGS.some((flag) => s[flag.key] != null),
  )
})

function effective(key: Flag): boolean {
  return snap.value.settings[key] ?? snap.value.config_values[key] ?? false
}

function save(patch: Partial<KernelSettings>) {
  void store.saveSettings({ ...snap.value.settings, ...patch })
}

function commitPort() {
  const text = port.value.trim()
  const value = text ? Number(text) : null
  if (value != null && (!Number.isInteger(value) || value < 1 || value > 65535)) {
    store.toast('端口需要是 1–65535 之间的整数', 'error')
    port.value = snap.value.settings.mixed_port ? String(snap.value.settings.mixed_port) : ''
    return
  }
  if (value !== snap.value.settings.mixed_port) save({ mixed_port: value })
}

function commitProbe() {
  const ms = timeout.value.trim() ? Number(timeout.value) : 0
  if (testUrl.value.trim() === snap.value.settings.test_url && ms === snap.value.settings.test_timeout_ms) return
  save({ test_url: testUrl.value.trim(), test_timeout_ms: Number.isFinite(ms) ? ms : 0 })
}

function reset() {
  void store.saveSettings({
    ...snap.value.settings,
    sniffer: null,
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

const TABS = computed(() =>
  [
    { id: 'general' as SettingsTab, label: '通用' },
    { id: 'kernel' as SettingsTab, label: '内核' },
    ...(store.isAndroid.value ? [] : [{ id: 'tun' as SettingsTab, label: 'TUN' }]),
    { id: 'dns' as SettingsTab, label: 'DNS' },
  ],
)

// ── TUN draft
const STACKS = [
  { id: 'mixed', label: 'Mixed' },
  { id: 'gvisor', label: 'gVisor' },
  { id: 'system', label: 'System' },
] as const
const tun = ref<TunSettings>(copy(snap.value.settings.tun))
const tunHijack = ref('')
watch(
  () => snap.value.settings.tun,
  (value) => {
    tun.value = copy(value)
    tunHijack.value = value.dns_hijack.join('\n')
  },
  { immediate: true, deep: true },
)
const lines = (text: string) => text.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)
const tunDraft = computed<TunSettings>(() => ({ ...tun.value, dns_hijack: lines(tunHijack.value), mtu: Number(tun.value.mtu) || 0 }))
const tunDirty = computed(() => JSON.stringify(tunDraft.value) !== JSON.stringify(snap.value.settings.tun))
function undoTun() {
  tun.value = copy(snap.value.settings.tun)
  tunHijack.value = snap.value.settings.tun.dns_hijack.join('\n')
}
function saveTun() {
  save({ tun: tunDraft.value })
}
function resetTun() {
  const base = defaultTun()
  tun.value = base
  tunHijack.value = base.dns_hijack.join('\n')
}

// ── DNS draft
const MODES_DNS = [
  { id: 'fake-ip', label: 'Fake-IP' },
  { id: 'redir-host', label: 'Redir-Host' },
  { id: 'normal', label: 'Normal' },
] as const
type ListKey = 'nameserver' | 'default_nameserver' | 'fallback' | 'proxy_server_nameserver' | 'direct_nameserver' | 'fake_ip_filter'
const LISTS: { key: ListKey; title: string; hint: string; fakeIpOnly?: boolean }[] = [
  { key: 'nameserver', title: '主 DNS 服务器', hint: '默认用于解析所有域名，支持 DoH / DoT / DoQ' },
  { key: 'default_nameserver', title: '引导 DNS', hint: '只用 IP 形式，用于解析上面 DoH 等服务器自身的域名' },
  { key: 'proxy_server_nameserver', title: '节点域名解析', hint: '解析代理节点服务器地址' },
  { key: 'direct_nameserver', title: '直连域名解析', hint: '直连出站使用；留空则用主 DNS' },
  { key: 'fallback', title: '备用 DNS', hint: '可选，海外服务器；留空则不启用' },
  { key: 'fake_ip_filter', title: 'Fake-IP 过滤', hint: '这些域名返回真实 IP，例如局域网、NTP、游戏联机', fakeIpOnly: true },
]
const dns = ref<DnsSettings>(copy(snap.value.settings.dns))
const dnsText = ref<Record<ListKey, string>>({} as Record<ListKey, string>)
function loadDns(value: DnsSettings) {
  dns.value = copy(value)
  dnsText.value = Object.fromEntries(LISTS.map((item) => [item.key, value[item.key].join('\n')])) as Record<ListKey, string>
}
watch(() => snap.value.settings.dns, loadDns, { immediate: true, deep: true })
const dnsDraft = computed<DnsSettings>(() => ({
  ...dns.value,
  ...Object.fromEntries(LISTS.map((item) => [item.key, lines(dnsText.value[item.key] ?? '')])),
}))
const dnsDirty = computed(() => JSON.stringify(dnsDraft.value) !== JSON.stringify(snap.value.settings.dns))
function saveDns() {
  save({ dns: dnsDraft.value })
}
function resetDns() {
  loadDns(defaultDns())
}
</script>

<template>
  <div class="page settings">
    <header class="page-head">
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
      <div v-if="compact" class="card shortcut-card">
        <button type="button" class="setting-row link" @click="store.go('logs')">
          <span class="row-icon"><Icon name="terminal" /></span>
          <strong class="grow">日志</strong>
          <span class="muted small">{{ snap.logs.length }}</span>
          <Icon name="chevron-right" class="muted" />
        </button>
        <button type="button" class="setting-row link" @click="store.go('rules')">
          <span class="row-icon"><Icon name="route" /></span>
          <strong class="grow">规则</strong>
          <Icon name="chevron-right" class="muted" />
        </button>
        <button type="button" class="setting-row link" @click="store.go('resources')">
          <span class="row-icon"><Icon name="database" /></span>
          <strong class="grow">外部资源</strong>
          <Icon name="chevron-right" class="muted" />
        </button>
      </div>

      <section class="card">
        <header class="card-head"><h2>外观</h2></header>
        <div class="setting-row">
          <div class="grow">
            <strong>主题</strong>
            <p class="muted small">浅色、深色或跟随系统</p>
          </div>
          <Segmented :model-value="store.theme.value" :options="THEMES" size="sm" label="主题" @update:model-value="store.setTheme" />
        </div>
      </section>

      <section v-if="app && app.autostart != null" class="card">
        <header class="card-head"><h2>启动与窗口</h2></header>
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
      </section>

      <section class="card">
        <header class="card-head"><h2>关于</h2></header>
        <div class="about">
          <span class="brand-mark lg"><Icon name="logo" :size="26" :stroke="2" /></span>
          <div class="grow min0">
            <strong>Billow</strong>
            <p class="muted small">基于 Mihomo 内核的跨平台代理客户端 · GPL-3.0</p>
            <p v-if="app?.data_dir" class="muted small mono ellipsis" :title="app.data_dir">{{ app.data_dir }}</p>
          </div>
          <span class="muted small mono">v{{ app?.version ?? '—' }}</span>
        </div>
      </section>
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
            <p class="muted small">{{ kernel.failure ?? '启动时会自动检查所选渠道的最新内核' }}</p>
          </div>
          <button type="button" class="btn ghost sm" :disabled="store.busy.kernel" @click="store.refreshKernel()">
            <Icon name="refresh" :size="15" :class="{ spin: store.busy.kernel }" />检查
          </button>
        </div>
      </section>

      <section class="card">
        <header class="card-head">
          <h2>内核设置</h2>
          <button v-if="overridden" type="button" class="btn ghost sm" @click="reset">全部跟随配置</button>
        </header>
        <p class="muted small card-note">这些设置覆盖每份配置中的同名项；留空或选择“跟随配置”则使用配置文件的值。修改后运行中的内核会自动重启。</p>
        <div class="setting-row">
          <div class="grow">
            <strong>混合代理端口</strong>
            <p class="muted small">HTTP 与 SOCKS5 共用，系统代理指向它</p>
          </div>
          <input
            v-model="port"
            class="input sm mono"
            inputmode="numeric"
            :placeholder="String(snap.config_values.mixed_port ?? 7890)"
            aria-label="混合代理端口"
            @blur="commitPort"
            @keydown.enter="($event.target as HTMLInputElement).blur()"
          />
        </div>
        <div v-for="flag in FLAGS" :key="flag.key" class="setting-row">
          <div class="grow">
            <strong>{{ flag.title }}<span v-if="snap.settings[flag.key] != null" class="tag accent sm">已覆盖</span></strong>
            <p class="muted small">{{ flag.hint }}</p>
          </div>
          <Toggle :model-value="effective(flag.key)" :busy="store.busy.settings" :label="flag.title" @update:model-value="(on) => save({ [flag.key]: on })" />
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>日志级别</strong>
            <p class="muted small">配置中为 {{ snap.config_values.log_level ?? 'info' }}</p>
          </div>
          <select class="input sm" :value="snap.settings.log_level ?? ''" aria-label="日志级别" @change="save({ log_level: ($event.target as HTMLSelectElement).value || null })">
            <option v-for="level in LOG_LEVELS" :key="level.id" :value="level.id">{{ level.label }}</option>
          </select>
        </div>
        <div v-if="!store.isAndroid.value" class="setting-row">
          <div class="grow">
            <strong>进程匹配</strong>
            <p class="muted small">识别连接来自哪个应用，用于连接页与进程规则</p>
          </div>
          <select class="input sm" :value="snap.settings.find_process_mode ?? ''" aria-label="进程匹配" @change="save({ find_process_mode: ($event.target as HTMLSelectElement).value || null })">
            <option v-for="mode in PROCESS_MODES" :key="mode.id" :value="mode.id">{{ mode.label }}</option>
          </select>
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>域名嗅探<span v-if="snap.settings.sniffer != null" class="tag accent sm">已覆盖</span></strong>
            <p class="muted small">从 HTTP / TLS / QUIC 流量中识别域名，让按域名分流在 IP 直连时也生效</p>
          </div>
          <Toggle :model-value="Boolean(snap.settings.sniffer)" :busy="store.busy.settings" label="域名嗅探" @update:model-value="(on) => save({ sniffer: on })" />
        </div>
        <div class="setting-row wrap">
          <div class="grow">
            <strong>测速地址</strong>
            <p class="muted small">延迟测试请求的网址与超时（毫秒）</p>
          </div>
          <div class="input-pair">
            <input
              v-model="testUrl"
              class="input sm mono"
              type="url"
              placeholder="http://www.gstatic.com/generate_204"
              aria-label="测速地址"
              @blur="commitProbe"
              @keydown.enter="($event.target as HTMLInputElement).blur()"
            />
            <input
              v-model="timeout"
              class="input sm mono short"
              inputmode="numeric"
              placeholder="5000"
              aria-label="测速超时"
              @blur="commitProbe"
              @keydown.enter="($event.target as HTMLInputElement).blur()"
            />
          </div>
        </div>
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
        <div class="setting-row">
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
            <p class="muted small">Mixed：TCP 走系统栈、UDP 走 gVisor，兼容性与性能兼顾</p>
          </div>
          <Segmented v-model="tun.stack" :options="STACKS" size="sm" label="协议栈" />
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
            <strong>自动选择出口网卡</strong>
            <p class="muted small">避免代理流量绕回 TUN 造成回环</p>
          </div>
          <Toggle v-model="tun.auto_detect_interface" label="自动选择出口网卡" />
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>严格路由</strong>
            <p class="muted small">阻止流量绕过 TUN（防 DNS 泄漏），但可能让局域网访问失效</p>
          </div>
          <Toggle v-model="tun.strict_route" label="严格路由" />
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
          <input v-model.number="tun.mtu" class="input sm mono short" inputmode="numeric" aria-label="MTU" />
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>网卡名称</strong>
            <p class="muted small">留空由内核决定（macOS 需为 utun 开头）</p>
          </div>
          <input v-model="tun.device" class="input sm mono" placeholder="自动" aria-label="网卡名称" />
        </div>
        <div v-if="tunDirty" class="save-bar">
          <span class="muted small grow">有未保存的修改{{ snap.kernel_running ? '，保存后内核会重启' : '' }}</span>
          <button type="button" class="btn ghost sm" @click="undoTun">撤销</button>
          <button type="button" class="btn primary sm" :disabled="store.busy.settings" data-testid="save-tun" @click="saveTun">保存</button>
        </div>
      </section>
    </template>

    <!-- ───────── DNS ───────── -->
    <template v-else>
      <section class="card" data-testid="dns-settings">
        <header class="card-head">
          <h2>DNS</h2>
          <button type="button" class="btn ghost sm" @click="resetDns">恢复默认</button>
        </header>
        <div class="setting-row">
          <span class="row-icon"><Icon name="sliders" /></span>
          <div class="grow">
            <strong>DNS 覆写</strong>
            <p class="muted small">开启后用下面的设置替换每份配置里的 dns 段；关闭则使用配置文件自带的 DNS</p>
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
            <strong>增强模式</strong>
            <p class="muted small">
              {{ dns.enhanced_mode === 'fake-ip' ? 'Fake-IP：先返回虚拟地址，连接时再解析，速度最快' : dns.enhanced_mode === 'redir-host' ? 'Redir-Host：返回真实 IP，兼容性更好' : 'Normal：不做增强处理' }}
            </p>
          </div>
          <Segmented v-model="dns.enhanced_mode" :options="MODES_DNS" size="sm" label="增强模式" />
        </div>
        <div v-if="dns.enhanced_mode === 'fake-ip'" class="setting-row">
          <div class="grow">
            <strong>Fake-IP 地址段</strong>
            <p class="muted small">虚拟地址池，不要与本地网络冲突</p>
          </div>
          <input v-model="dns.fake_ip_range" class="input sm mono" aria-label="Fake-IP 地址段" />
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>IPv6 解析</strong>
            <p class="muted small">返回 AAAA 记录</p>
          </div>
          <Toggle v-model="dns.ipv6" label="IPv6 解析" />
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>使用 hosts</strong>
            <p class="muted small">优先使用配置中的 hosts 映射</p>
          </div>
          <Toggle v-model="dns.use_hosts" label="使用 hosts" />
        </div>
        <div class="setting-row">
          <div class="grow">
            <strong>遵循分流规则</strong>
            <p class="muted small">DNS 查询也按规则走代理或直连（respect-rules）</p>
          </div>
          <Toggle v-model="dns.respect_rules" label="遵循分流规则" />
        </div>
        <template v-for="item in LISTS" :key="item.key">
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
        <div v-if="dnsDirty" class="save-bar">
          <span class="muted small grow">有未保存的修改{{ snap.kernel_running && snap.settings.dns_override ? '，保存后内核会重启' : '' }}</span>
          <button type="button" class="btn ghost sm" @click="loadDns(snap.settings.dns)">撤销</button>
          <button type="button" class="btn primary sm" :disabled="store.busy.settings" data-testid="save-dns" @click="saveDns">保存</button>
        </div>
      </section>

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
      </section>
    </template>
  </div>
</template>
