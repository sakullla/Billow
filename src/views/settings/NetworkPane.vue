<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import Icon from '../../components/Icon.vue'
import Segmented from '../../components/Segmented.vue'
import SelectField from '../../components/SelectField.vue'
import Toggle from '../../components/Toggle.vue'
import EditorDialog from '../../components/settings/EditorDialog.vue'
import SettingsRow from '../../components/settings/SettingsRow.vue'
import SettingsSection from '../../components/settings/SettingsSection.vue'
import { tr } from '../../lib/i18n'
import { useSettingsSave } from '../../lib/settings/save'
import { useStore } from '../../lib/store'

const props = defineProps<{ compact?: boolean }>()
const store = useStore()
const { current, save } = useSettingsSave()
const snap = computed(() => store.snapshot.value)
const settings = computed(() => snap.value.settings)
const config = computed(() => snap.value.config_values)
const busy = computed(() => Boolean(store.busy.settings))
const overridden = tr('已覆盖')

type Flag = 'allow_lan' | 'ipv6' | 'tcp_concurrent'
function effective(key: Flag): boolean {
  return current.value[key] ?? config.value[key] ?? false
}

// ── 混合代理端口: saved on blur / Enter, with the error kept next to the field.
const effectiveMixedPort = computed(() => snap.value.mixed_port ?? settings.value.mixed_port ?? config.value.mixed_port ?? 7890)
const port = ref(settings.value.mixed_port ? String(settings.value.mixed_port) : '')
const portFocused = ref(false)
const portError = ref<string | null>(null)
const portInputEl = ref<HTMLInputElement | null>(null)
let lastSyncedPort: number | null | undefined = settings.value.mixed_port
watch(
  () => settings.value.mixed_port,
  (mixedPort) => {
    if (mixedPort === lastSyncedPort) return
    lastSyncedPort = mixedPort
    if (!portFocused.value && !portError.value) port.value = mixedPort ? String(mixedPort) : ''
  },
)
const savedPortText = computed(() => (current.value.mixed_port ? String(current.value.mixed_port) : ''))
const portDirty = computed(() => port.value.trim() !== savedPortText.value)
const PORT_RANGE_ERROR = computed(() => tr('混合端口必须是 1–65535 之间的整数'))

function onPortInput() {
  if (portError.value && port.value.trim() === savedPortText.value) portError.value = null
}

async function commitPort(silentInvalid = false, focusOnInvalid = false) {
  const text = port.value.trim()
  let value: number | null = null
  if (text) {
    const num = Number(text)
    if (!/^\d+$/.test(text) || !Number.isSafeInteger(num) || num < 1 || num > 65535) {
      if (!silentInvalid) {
        portError.value = PORT_RANGE_ERROR.value
        if (focusOnInvalid) {
          await nextTick()
          portInputEl.value?.focus({ preventScroll: true })
        }
      }
      return
    }
    value = num
  }
  portError.value = null
  if (value === current.value.mixed_port) {
    port.value = value ? String(value) : ''
    return
  }
  const previous = current.value.mixed_port
  lastSyncedPort = value
  const result = await save({ mixed_port: value })
  if (!result) {
    lastSyncedPort = previous
    portError.value = store.lastRunError.value ?? tr('混合端口未能保存')
    return
  }
  port.value = value ? String(value) : ''
}

onBeforeUnmount(() => {
  if (portDirty.value && !portError.value) void commitPort(true)
})

// ── LAN sharing (R23): where to point other devices, and who may connect.
const lanOn = computed(() => effective('allow_lan'))
const lanAddress = ref<string | null>(null)
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
const lanPort = computed(() => snap.value.mixed_port ?? settings.value.mixed_port ?? config.value.mixed_port ?? 7890)
/** SOCKS / HTTP listeners other devices can also use, with the value the kernel would bind (R34). */
const lanExtraPorts = computed(() => {
  if (store.isAndroid.value) return []
  const s = settings.value
  const follow = (value: number | null) => (s.mixed_port || value === effectiveMixedPort.value ? null : value)
  const extra = [
    { label: 'SOCKS', port: s.socks_port ?? follow(config.value.socks_port) },
    { label: 'HTTP', port: s.http_port ?? follow(config.value.http_port) },
  ]
  return extra.filter((item): item is { label: string; port: number } => Boolean(item.port))
})
async function copyLanAddress() {
  if (!lanAddress.value) return
  await store.copyText(`${lanAddress.value}:${lanPort.value}`, tr('已复制局域网代理地址'))
}

function splitAuth(entry: string | undefined): [string, string] {
  if (!entry) return ['', '']
  const at = entry.indexOf(':')
  return at < 0 ? [entry, ''] : [entry.slice(0, at), entry.slice(at + 1)]
}
const splitIps = (text: string) => text.split(/[\s,，;；]+/).map((item) => item.trim()).filter(Boolean)
const IP_ENTRY = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]*)(?:\/\d{1,3})?$/i

const lanSummary = computed(() => {
  const auth = settings.value.lan_auth.length > 0
  const ips = settings.value.lan_allowed_ips.length
  if (!auth && !ips) return tr('任何设备，无需密码')
  const parts = []
  if (auth) parts.push(tr('需要密码'))
  if (ips) parts.push(tr('限 {0} 个地址', { 0: ips }))
  return parts.join(' · ')
})

const lanOpen = ref(false)
const lanUser = ref('')
const lanPass = ref('')
const lanPassVisible = ref(false)
const lanIps = ref('')
const lanError = ref<string | null>(null)
function openLan() {
  ;[lanUser.value, lanPass.value] = splitAuth(settings.value.lan_auth[0])
  lanIps.value = settings.value.lan_allowed_ips.join(', ')
  lanPassVisible.value = false
  lanError.value = null
  lanOpen.value = true
}
const lanDirty = computed(() => {
  const [user, pass] = splitAuth(settings.value.lan_auth[0])
  return (
    lanUser.value.trim() !== user ||
    lanPass.value !== pass ||
    splitIps(lanIps.value).join(',') !== settings.value.lan_allowed_ips.join(',')
  )
})
async function saveLan() {
  const user = lanUser.value.trim()
  const pass = lanPass.value
  if (Boolean(user) !== Boolean(pass)) {
    lanError.value = tr('用户名和密码需要同时填写；都留空则不需要认证')
    return
  }
  if (/[\s:]/.test(user) || /\s/.test(pass)) {
    lanError.value = tr('用户名不能含空格或冒号，密码不能含空格')
    return
  }
  const ips = splitIps(lanIps.value)
  const bad = ips.find((item) => !IP_ENTRY.test(item))
  if (bad) {
    lanError.value = tr('无法识别「{0}」，请填写 IP 或网段，例如 192.168.1.0/24', { 0: bad })
    return
  }
  lanError.value = null
  // Extra users from earlier versions or other tools stay; this form edits the first one.
  const rest = settings.value.lan_auth.slice(1)
  await save({ lan_auth: user ? [`${user}:${pass}`, ...rest] : rest, lan_allowed_ips: ips })
  lanOpen.value = false
}

// ── TCP keep-alive (desktop: mihomo always disables it on Android).
const KEEP_ALIVE = computed(() => [
  { value: '', label: tr('跟随配置') },
  { value: '15', label: tr('15 秒') },
  { value: '30', label: tr('30 秒') },
  { value: '60', label: tr('60 秒') },
  { value: '120', label: tr('120 秒（省电）') },
  { value: '0', label: tr('关闭') },
])
const profileKeepAlive = computed(() => {
  if (config.value.disable_keep_alive) return tr('配置中已关闭')
  return config.value.keep_alive_interval ? tr('配置中为 {0} 秒', { 0: config.value.keep_alive_interval }) : tr('配置未设置，默认 15 秒')
})

// ── Extra listeners, outbound interface and routing mark (R34), edited together.
type PortKey = 'socks_port' | 'http_port' | 'redir_port' | 'tproxy_port'
const PORT_FIELDS: { key: PortKey; label: () => string; hint: () => string }[] = [
  { key: 'socks_port', label: () => tr('SOCKS 端口'), hint: () => tr('单独的 SOCKS5 入站') },
  { key: 'http_port', label: () => tr('HTTP 端口'), hint: () => tr('单独的 HTTP 代理入站') },
  { key: 'redir_port', label: () => tr('redir 端口'), hint: () => tr('配合防火墙重定向使用') },
  { key: 'tproxy_port', label: () => tr('tproxy 端口'), hint: () => tr('配合 iptables / nftables TProxy 使用') },
]
/** mihomo implements redir on Linux and macOS, tproxy and routing marks on Linux only. */
const visiblePorts = computed(() =>
  PORT_FIELDS.filter((field) => {
    if (field.key === 'redir_port') return store.isLinux.value || store.isMac.value
    if (field.key === 'tproxy_port') return store.isLinux.value
    return !store.isAndroid.value
  }),
)
const showRoutingMark = computed(() => store.isLinux.value)
const showNetBlock = computed(() => !store.isAndroid.value)

type IfaceChoice = 'follow' | 'off' | 'custom'
const IFACE_CHOICES = computed<{ id: IfaceChoice; label: string }[]>(() => [
  { id: 'follow', label: tr('跟随配置') },
  { id: 'off', label: tr('不指定') },
  { id: 'custom', label: tr('指定') },
])
const NET_KEYS = ['socks_port', 'http_port', 'redir_port', 'tproxy_port', 'interface_name', 'routing_mark'] as const
const netCustomCount = computed(() => NET_KEYS.filter((key) => settings.value[key] != null).length)

const netOpen = ref(false)
const netText = ref<Record<PortKey | 'routing_mark' | 'interface_name', string>>({
  socks_port: '',
  http_port: '',
  redir_port: '',
  tproxy_port: '',
  routing_mark: '',
  interface_name: '',
})
const ifaceChoice = ref<IfaceChoice>('follow')
const netError = ref<string | null>(null)
const netSaved = computed(() => {
  const s = settings.value
  return {
    socks_port: s.socks_port,
    http_port: s.http_port,
    redir_port: s.redir_port,
    tproxy_port: s.tproxy_port,
    interface_name: s.interface_name,
    routing_mark: s.routing_mark,
  }
})
function openNet() {
  const value = netSaved.value
  const text = (item: number | null) => (item == null ? '' : String(item))
  netText.value = {
    socks_port: text(value.socks_port),
    http_port: text(value.http_port),
    redir_port: text(value.redir_port),
    tproxy_port: text(value.tproxy_port),
    routing_mark: text(value.routing_mark),
    interface_name: value.interface_name ?? '',
  }
  ifaceChoice.value = value.interface_name == null ? 'follow' : value.interface_name === '' ? 'off' : 'custom'
  netError.value = null
  netOpen.value = true
}
const numberOrNull = (text: string) => (text.trim() === '' ? null : Number(text.trim()))
const netDraft = computed(() => ({
  socks_port: numberOrNull(netText.value.socks_port),
  http_port: numberOrNull(netText.value.http_port),
  redir_port: numberOrNull(netText.value.redir_port),
  tproxy_port: numberOrNull(netText.value.tproxy_port),
  interface_name: ifaceChoice.value === 'follow' ? null : ifaceChoice.value === 'off' ? '' : netText.value.interface_name.trim(),
  routing_mark: numberOrNull(netText.value.routing_mark),
}))
const netDirty = computed(() => JSON.stringify(netDraft.value) !== JSON.stringify(netSaved.value))
/**
 * A saved port can come to equal the mixed port later, e.g. after switching to a profile
 * whose mixed-port differs. Saving does not re-check that case, so warn instead.
 */
const portClashes = computed(() => {
  const mixed = effectiveMixedPort.value
  const out: Partial<Record<PortKey, string>> = {}
  for (const field of PORT_FIELDS) {
    const saved = settings.value[field.key]
    if (saved && saved === mixed) out[field.key] = tr('与当前混合端口 {0} 相同，连接时会因端口被占用而失败；请改用其他端口或留空跟随配置', { 0: mixed })
  }
  return out
})
const clashCount = computed(() => Object.keys(portClashes.value).length)
function configPort(key: PortKey): string {
  const c = config.value
  const value = { socks_port: c.socks_port, http_port: c.http_port, redir_port: c.redir_port, tproxy_port: c.tproxy_port }[key]
  if (key === 'http_port' && value != null && value === c.mixed_port && !settings.value.mixed_port) return tr('配置中的 port 已作为混合端口')
  return value == null ? tr('配置未设置') : value === 0 ? tr('配置中为关闭') : tr('配置中为 {0}', { 0: value })
}
function netValidationError(): string | null {
  const text = netText.value
  for (const field of PORT_FIELDS) {
    const raw = text[field.key].trim()
    if (raw && (!/^\d+$/.test(raw) || Number(raw) > 65535)) return tr('{0}必须是 1–65535 的整数，填 0 表示关闭', { 0: field.label() })
  }
  const mark = text.routing_mark.trim()
  if (mark && (!/^\d+$/.test(mark) || Number(mark) > 4294967295)) return tr('路由标记必须是非负整数，填 0 表示不设置')
  if (ifaceChoice.value === 'custom') {
    const name = text.interface_name.trim()
    if (!name) return tr('请填写出口网卡名称，或选择“跟随配置”')
    if (/\s/.test(name)) return tr('出口网卡名称不能包含空格')
  }
  const draft = netDraft.value
  const mixed = settings.value.mixed_port || config.value.mixed_port || 7890
  const taken: [string, number][] = [[tr('混合端口'), mixed]]
  for (const field of PORT_FIELDS) {
    const value = draft[field.key]
    if (!value) continue
    const other = taken.find(([, used]) => used === value)
    if (other) return tr('{0} {1} 与{2}重复，请换一个端口', { 0: field.label(), 1: value, 2: other[0] })
    taken.push([field.label(), value])
  }
  return null
}
async function saveNet() {
  const error = netValidationError()
  netError.value = error
  if (error) return
  await save({ ...netDraft.value })
  netOpen.value = false
}
void props
</script>

<template>
  <SettingsSection :title="tr('代理端口')">
    <SettingsRow
      :title="tr('混合代理端口')"
      :badge="settings.mixed_port ? overridden : undefined"
      setting="mixed-port"
      class="port-setting-row"
      :class="{ 'has-error': Boolean(portError) }"
    >
      <template #description>
        <span data-testid="mixed-port-effective">{{ tr('HTTP 与 SOCKS5 共用，系统代理指向它 · 当前生效') }} {{ effectiveMixedPort }}</span>
      </template>
      <template #below>
        <span v-if="portError" id="mixed-port-error" class="field-error small" role="alert" data-testid="mixed-port-error">
          <Icon name="alert" :size="13" /><span>{{ portError }}</span>
        </span>
      </template>
      <div class="inline-field">
        <input
          ref="portInputEl"
          v-model="port"
          class="input sm mono srow-input short"
          inputmode="numeric"
          :placeholder="String(config.mixed_port ?? 7890)"
          :aria-label="tr('混合代理端口')"
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
          :disabled="busy"
          data-testid="save-port"
          @mousedown.prevent
          @click="commitPort(false, true)"
        >{{ tr('保存') }}</button>
      </div>
    </SettingsRow>
    <SettingsRow
      v-if="showNetBlock"
      nav
      :title="tr('更多端口与出口')"
      :description="tr('SOCKS / HTTP 端口、出口网卡与路由标记')"
      :value="clashCount ? tr('端口冲突') : netCustomCount ? tr('已自定义 {0} 项', { 0: netCustomCount }) : tr('跟随配置')"
      :class="{ 'srow-warn': clashCount > 0 }"
      setting="extra-ports"
      data-testid="open-extra-ports"
      @open="openNet"
    />
  </SettingsSection>

  <SettingsSection :title="tr('局域网共享')">
    <SettingsRow
      :title="tr('局域网连接')"
      :description="tr('允许同一网络的其他设备使用本机代理')"
      :badge="settings.allow_lan != null ? overridden : undefined"
      setting="allow-lan"
    >
      <Toggle :model-value="lanOn" :busy="busy" :label="tr('局域网连接')" @update:model-value="(on) => save({ allow_lan: on })" />
    </SettingsRow>
    <template v-if="lanOn">
      <div class="srow srow-info nested" data-testid="lan-block">
        <div class="srow-main">
          <span class="srow-title">{{ tr('在其他设备上填写') }}</span>
          <span class="srow-desc lan-addresses">
            <button
              v-if="lanAddress"
              type="button"
              class="copy-chip mono"
              :title="tr('复制')"
              data-testid="lan-address"
              @click="copyLanAddress"
            >{{ lanAddress }}:{{ lanPort }}<Icon name="copy" :size="12" /></button>
            <span v-else>{{ tr('本机局域网 IP 与端口') }} {{ lanPort }}</span>
            <span v-for="extra in lanExtraPorts" :key="extra.label" class="copy-chip static mono" data-testid="lan-extra-address">
              {{ extra.label }} {{ lanAddress ?? tr('本机局域网 IP') }}:{{ extra.port }}
            </span>
          </span>
        </div>
      </div>
      <SettingsRow
        nav
        nested
        :title="tr('访问控制')"
        :description="tr('访问认证与允许的设备')"
        :value="lanSummary"
        :badge="settings.lan_auth.length ? tr('已开启') : undefined"
        setting="lan-access"
        data-testid="open-lan-access"
        @open="openLan"
      />
    </template>
  </SettingsSection>

  <SettingsSection :title="tr('连接')">
    <SettingsRow :title="'IPv6'" :description="tr('解析并连接 IPv6 地址')" :badge="settings.ipv6 != null ? overridden : undefined" setting="ipv6">
      <Toggle :model-value="effective('ipv6')" :busy="busy" label="IPv6" @update:model-value="(on) => save({ ipv6: on })" />
    </SettingsRow>
    <SettingsRow
      :title="tr('TCP 并发')"
      :description="tr('同时连接多个解析结果，取最快的一个')"
      :badge="settings.tcp_concurrent != null ? overridden : undefined"
      setting="tcp-concurrent"
    >
      <Toggle :model-value="effective('tcp_concurrent')" :busy="busy" :label="tr('TCP 并发')" @update:model-value="(on) => save({ tcp_concurrent: on })" />
    </SettingsRow>
    <!-- mihomo always disables TCP keep-alive on Android, so the choice would do nothing there. -->
    <SettingsRow
      v-if="!store.isAndroid.value"
      :title="tr('TCP 保活')"
      :badge="settings.keep_alive_interval != null ? overridden : undefined"
      setting="keep-alive"
    >
      <template #description>{{ tr('空闲连接的心跳间隔；') }}{{ profileKeepAlive }}</template>
      <SelectField
        :model-value="settings.keep_alive_interval == null ? '' : String(settings.keep_alive_interval)"
        :options="KEEP_ALIVE"
        :sheet="compact"
        size="sm"
        :label="tr('TCP 保活')"
        data-testid="keep-alive-select"
        @update:model-value="(value) => save({ keep_alive_interval: value === '' ? null : Number(value) })"
      />
    </SettingsRow>
  </SettingsSection>

  <EditorDialog
    v-if="lanOpen"
    :title="tr('局域网访问控制')"
    :subtitle="tr('本机访问始终免认证')"
    :dirty="lanDirty"
    :saving="busy"
    save-testid="save-lan"
    cancel-testid="undo-lan"
    @save="saveLan"
    @close="lanOpen = false"
  >
    <div class="form-stack">
      <div class="field">
        <span>{{ tr('访问认证') }}</span>
        <div class="field-pair">
          <input
            v-model="lanUser"
            class="input"
            autocomplete="off"
            spellcheck="false"
            :placeholder="tr('用户名')"
            :aria-label="tr('局域网访问用户名')"
            data-testid="lan-user"
          />
          <div class="input-with-action">
            <input
              v-model="lanPass"
              class="input"
              :type="lanPassVisible ? 'text' : 'password'"
              autocomplete="new-password"
              :placeholder="tr('密码')"
              :aria-label="tr('局域网访问密码')"
              data-testid="lan-pass"
            />
            <button
              type="button"
              class="icon-btn sm"
              :aria-pressed="lanPassVisible"
              :aria-label="lanPassVisible ? tr('隐藏密码') : tr('显示密码')"
              @click="lanPassVisible = !lanPassVisible"
            >
              <Icon :name="lanPassVisible ? 'eye-off' : 'eye'" :size="14" />
            </button>
          </div>
        </div>
        <p class="muted small">{{ tr('都留空则不需要密码') }}</p>
      </div>
      <label class="field">
        <span>{{ tr('允许的设备') }}</span>
        <input
          v-model="lanIps"
          class="input mono"
          spellcheck="false"
          :placeholder="lanAddress ? `${lanAddress.replace(/\.\d+$/, '.0')}/24` : '192.168.1.0/24'"
          :aria-label="tr('允许的设备')"
          data-testid="lan-ips"
        />
        <span class="muted small field-note">{{ tr('留空允许所有局域网设备；填 IP 或网段，逗号分隔') }}</span>
      </label>
      <p v-if="lanError" class="field-error small" role="alert" data-testid="lan-error">
        <Icon name="alert" :size="13" /><span>{{ lanError }}</span>
      </p>
    </div>
  </EditorDialog>

  <EditorDialog
    v-if="netOpen"
    :title="tr('更多端口与出口')"
    :subtitle="tr('留空跟随配置；端口填 0 表示关闭')"
    :dirty="netDirty"
    :saving="busy"
    save-testid="save-net"
    cancel-testid="undo-net"
    @save="saveNet"
    @close="netOpen = false"
  >
    <div class="form-stack">
      <div class="form-grid">
        <label v-for="field in visiblePorts" :key="field.key" class="field">
          <span>{{ field.label() }}</span>
          <input
            v-model="netText[field.key]"
            class="input mono"
            inputmode="numeric"
            :placeholder="tr('跟随配置')"
            :aria-label="field.label()"
            :data-testid="`port-${field.key}`"
          />
          <span class="muted small field-note">{{ field.hint() }} · {{ configPort(field.key) }}</span>
          <span v-if="portClashes[field.key]" class="field-error small" role="alert" :data-testid="`port-clash-${field.key}`">
            <Icon name="alert" :size="13" /><span>{{ portClashes[field.key] }}</span>
          </span>
        </label>
      </div>
      <div class="field">
        <span>{{ tr('出口网卡') }}</span>
        <div class="inline-field">
          <Segmented v-model="ifaceChoice" :options="IFACE_CHOICES" size="sm" :label="tr('出口网卡')" data-testid="interface-choice" />
          <input
            v-if="ifaceChoice === 'custom'"
            v-model="netText.interface_name"
            class="input sm mono short"
            spellcheck="false"
            :placeholder="tr('例如 en0')"
            :aria-label="tr('出口网卡名称')"
            data-testid="interface-name"
          />
        </div>
        <span class="muted small field-note">
          {{ tr('让代理流量从指定网卡发出') }}{{ config.interface_name ? tr(' · 配置中为 {0}', { 0: config.interface_name }) : tr(' · 配置未设置') }}
        </span>
      </div>
      <label v-if="showRoutingMark" class="field">
        <span>{{ tr('路由标记') }}</span>
        <input
          v-model="netText.routing_mark"
          class="input mono short"
          inputmode="numeric"
          :placeholder="tr('跟随配置')"
          :aria-label="tr('路由标记')"
          data-testid="routing-mark"
        />
        <span class="muted small field-note">
          {{ tr('给出站连接打上 fwmark，配合策略路由；填 0 不设置') }}{{ config.routing_mark != null ? tr(' · 配置中为 {0}', { 0: config.routing_mark }) : '' }}
        </span>
      </label>
      <p v-if="netError" class="field-error small" role="alert" data-testid="net-error">
        <Icon name="alert" :size="13" /><span>{{ netError }}</span>
      </p>
    </div>
  </EditorDialog>
</template>
