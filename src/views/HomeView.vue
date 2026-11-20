<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'
import ChainPath from '../components/ChainPath.vue'
import BrandMark from '../components/BrandMark.vue'
import GroupIcon from '../components/GroupIcon.vue'
import Icon from '../components/Icon.vue'
import Modal from '../components/Modal.vue'
import NodePickerModal from '../components/NodePickerModal.vue'
import Segmented from '../components/Segmented.vue'
import Toggle from '../components/Toggle.vue'
import TrafficChart from '../components/TrafficChart.vue'
import TrafficStatsDialog from '../components/TrafficStatsDialog.vue'
import {
  daysLeft,
  delayText,
  delayTone,
  effectiveGroupDelay,
  formatBytes,
  formatDate,
  formatClock,
  formatRelative,
  formatSpeed,
  canPickNode,
  autoTypeLabel,
  resolveChain,
  usagePercent,
} from '../lib/format'
import { useStore } from '../lib/store'
import { t, tr } from '../lib/i18n'
import type { Mode, NodeGroup, ProfileItem } from '../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)
const profile = computed(() => store.current.value)

const MODES: { id: Mode; label: string; hint: string; icon: string }[] = [
  { id: 'rule', get label() { return tr('规则') }, get hint() { return tr('按配置中的规则分流') }, icon: 'route' },
  { id: 'global', get label() { return tr('全局') }, get hint() { return tr('全部流量走当前节点') }, icon: 'globe' },
  { id: 'direct', get label() { return tr('直连') }, get hint() { return tr('新连接都不经过代理') }, icon: 'zap' },
]
/** Seconds of samples before the chart replaces its "collecting" note with curves (R2). */
const MIN_CHART_SAMPLES = 5
const MODE_OPTIONS = MODES.map(({ id, label, icon }) => ({ id, label, icon }))

const status = computed(() => {
  if (store.restarting.value) return { word: tr('重启中'), tone: 'pending' }
  if (store.connecting.value) return { word: snap.value.connected ? tr('断开中') : tr('连接中'), tone: 'pending' }
  if (snap.value.connected) return { word: tr('已连接'), tone: 'on' }
  return { word: tr('未连接'), tone: 'off' }
})

/** One control owns connect, disconnect and the empty-state add action (R24). */
const connectLabel = computed(() => {
  if (!store.hasProfiles.value) return tr('添加配置')
  if (store.restarting.value) return tr('重启中')
  if (store.connecting.value) return snap.value.connected ? tr('断开中') : tr('连接中')
  return snap.value.connected ? tr('断开') : tr('连接')
})
const connectIcon = computed(() => (store.hasProfiles.value ? 'power' : 'plus'))

const activeMode = computed(() => MODES.find((mode) => mode.id === snap.value.mode) ?? null)
const modeHint = computed(() => activeMode.value?.hint ?? tr('还没有读到出站模式'))
const modeBusy = computed(() => Boolean(store.busy.mode))

/** Any running test blocks another; only a full run reads as 测速中 here. */
const testBlocked = computed(() => store.testing.value)
const testBusy = computed(() => store.activeTest.value?.kind === 'all')
const homeTestTitle = computed(() => {
  if (testBusy.value && store.testProgress.value.total > 0) {
    return tr('测速中 ({0}/{1})', { 0: store.testProgress.value.tested, 1: store.testProgress.value.total })
  }
  return tr('测试全部节点延迟')
})
const updateBusy = computed(() => (profile.value ? Boolean(store.busy[`update:${profile.value.id}`]) : false))

const showAllGroups = ref(false)
/** Config `hidden: true` groups stay out of the picker; chains below still pass through them (R29). */
const allManualGroups = computed(() => snap.value.node_catalog.filter((group) => group.kind === 'manual' && !group.hidden))
/** The groups card also lists url-test / fallback groups, which can be pinned like select groups (R28). */
const allPickableGroups = computed(() => snap.value.node_catalog.filter((group) => canPickNode(group) && !group.hidden))
const manualGroups = computed(() => (showAllGroups.value ? allPickableGroups.value : allPickableGroups.value.slice(0, 8)))
const hiddenGroupCount = computed(() => Math.max(0, allPickableGroups.value.length - 8))
const primaryGroup = computed(() => {
  if (snap.value.mode === 'global') {
    return snap.value.node_catalog.find((group) => group.name === 'GLOBAL') ?? allManualGroups.value[0] ?? null
  }
  return allManualGroups.value.find((group) => Boolean(group.now)) ?? allManualGroups.value[0] ?? null
})
const primaryDelay = computed(() => (primaryGroup.value ? groupDelay(primaryGroup.value) : { text: '—', tone: 'none' }))

function openProfileOverride(id: string) {
  store.overrideRequest.value = { id, append: '' }
  store.go('profiles')
}

const profileSheetOpen = ref(false)
const switchingProfileId = ref<string | null>(null)
const sheetFailure = ref<{ id: string; reason: string } | null>(null)
const pickerGroupName = ref<string | null>(null)
const pickerGroup = computed(() =>
  pickerGroupName.value ? snap.value.node_catalog.find((group) => group.name === pickerGroupName.value) ?? null : null,
)
const welcomeDragging = ref(false)

function openNodePicker(groupName: string) {
  pickerGroupName.value = groupName
}
function closeNodePicker() {
  pickerGroupName.value = null
}
const orderedProfiles = computed(() =>
  [...snap.value.profiles].sort((a, b) => Number(b.current) - Number(a.current)),
)

function isEnablingProfile(id: string): boolean {
  return switchingProfileId.value === id || Boolean(store.busy[`enable:${id}`])
}

const isSheetSwitching = computed(
  () => switchingProfileId.value !== null || snap.value.profiles.some((item) => Boolean(store.busy[`enable:${item.id}`])),
)

function sheetFailureFor(id: string): string | null {
  return sheetFailure.value?.id === id ? sheetFailure.value.reason : null
}

function openProfileSheet() {
  sheetFailure.value = null
  profileSheetOpen.value = true
}

function closeProfileSheet() {
  if (isSheetSwitching.value) return
  profileSheetOpen.value = false
}

function sheetInitialFocus(): HTMLElement | null | undefined {
  if (typeof window !== 'undefined' && window.matchMedia?.('(pointer: coarse)').matches === true) {
    return undefined
  }
  const currentId = profile.value?.id ?? orderedProfiles.value[0]?.id
  if (!currentId) return undefined
  return document.querySelector<HTMLElement>(`[data-testid="sheet-profile-${CSS.escape(currentId)}"]`)
}

async function switchFromSheet(target: ProfileItem) {
  if (isSheetSwitching.value) return
  if (target.current) {
    sheetFailure.value = null
    profileSheetOpen.value = false
    return
  }
  switchingProfileId.value = target.id
  sheetFailure.value = null
  try {
    const result = await store.enable(target.id)
    const after = result?.profiles.find((item) => item.id === target.id)
    const succeeded = Boolean(
      result && result.active_id === target.id && after?.current && !after.failure && !after.override_error,
    )
    if (succeeded) {
      sheetFailure.value = null
      profileSheetOpen.value = false
      return
    }
    const reason =
      after?.failure ||
      after?.override_error ||
      (result ? result.failure || result.notice || result.input_error : null) ||
      store.lastRunError.value ||
      tr('配置未能启用')
    sheetFailure.value = { id: target.id, reason }
  } finally {
    switchingProfileId.value = null
  }
}

function addFromSheet() {
  if (isSheetSwitching.value) return
  profileSheetOpen.value = false
  store.adding.value = true
}
function manageFromSheet() {
  if (isSheetSwitching.value) return
  profileSheetOpen.value = false
  store.go('profiles')
}

async function onWelcomeDrop(event: DragEvent) {
  welcomeDragging.value = false
  const file = event.dataTransfer?.files?.[0]
  if (!file) return
  const before = snap.value.profiles.length
  await store.addLocal(file.name.replace(/\.(ya?ml|txt)$/i, ''), await file.text())
  if (snap.value.profiles.length > before) {
    store.toast(tr('已导入 {0}', { 0: file.name }), 'success')
    const added = snap.value.profiles[snap.value.profiles.length - 1]
    if (!snap.value.active_id && added) void store.enable(added.id)
  }
}

const usage = computed(() => (profile.value ? usagePercent(profile.value.used, profile.value.total) : null))
const remainingBytes = computed(() => {
  const p = profile.value
  return p && p.total != null && p.used != null && p.total > 0 ? Math.max(0, p.total - p.used) : null
})
const expireDays = computed(() => (profile.value?.expire ? daysLeft(profile.value.expire) : null))

/** Home failure banner: the store owns it so a retry clears it even when the backend keeps the reason. */
const failureText = computed(() => store.lastActionError.value)
const failureSettingsAction = computed<{ label: string; tab: 'network' | 'tun'; focus?: string } | null>(() => {
  if (!failureText.value) return null
  const hint = snap.value.failure_hint
  if (hint === 'port') return { get label() { return tr('更换端口') }, tab: 'network', focus: 'mixed-port' }
  if (hint === 'tun') return { get label() { return tr('TUN 设置') }, tab: 'tun' }
  return null
})

/** Only values the kernel actually reported survive; a missing reading hides the row (R24). */
const runtime = computed(() => {
  const items: { key: string; label: string; value: string }[] = []
  if (snap.value.connected) {
    items.push({ key: 'connections', get label() { return tr('活动连接') }, value: String(snap.value.connection_total) })
  }
  if (snap.value.kernel_memory != null) {
    items.push({ key: 'memory', get label() { return tr('内核内存') }, value: formatBytes(snap.value.kernel_memory) })
  }
  if (snap.value.kernel_uptime_secs != null) {
    items.push({ key: 'uptime', get label() { return tr('运行时长') }, value: uptimeText(snap.value.kernel_uptime_secs) })
  }
  const version = store.kernel.value.version
  if (version) items.push({ key: 'kernel', get label() { return tr('内核版本') }, value: version })
  return items
})

const takeoverSummary = computed(() => {
  if (store.isAndroid.value) return snap.value.vpn ? tr('VPN 已接管设备流量') : tr('VPN 未开启')
  const on: string[] = []
  if (snap.value.system_proxy) on.push(tr('系统代理'))
  if (snap.value.tun) on.push('TUN')
  return on.length ? tr('{0} 已开启', { 0: on.join(' · ') }) : tr('未接管系统流量')
})

const takeoverOn = computed(() => (store.isAndroid.value ? snap.value.vpn : snap.value.system_proxy || snap.value.tun))

const proxySubtitle = computed(() => {
  const sp = snap.value.settings.system_proxy
  const host = sp.host.trim()
  const port = snap.value.mixed_port ?? snap.value.settings.mixed_port ?? 7890
  if (sp.mode === 'pac') {
    return host ? tr('PAC 自动分流 · {0}', { 0: host }) : tr('PAC 脚本自动分流')
  }
  if (host && host !== '127.0.0.1') {
    return `${host}:${port}`
  }
  return snap.value.system_proxy ? `HTTP / SOCKS · :${port}` : tr('浏览器与常规应用')
})

const tunSubtitle = computed(() => {
  if (snap.value.tun) return tr('{0} 栈 · 全局接管', { 0: snap.value.settings.tun.stack.toUpperCase() })
  return tr('虚拟网卡接管全部流量')
})

/** The hero's first line answers "is my traffic going through Billow?", not just "is the kernel up?". */
const heroEyebrow = computed(() => {
  if (store.connecting.value) return tr('请稍候')
  if (!snap.value.kernel_running) return tr('代理未运行')
  if (store.isAndroid.value) {
    return snap.value.vpn ? tr('VPN 已接管设备流量') : tr('VPN 未开启 · 未接管设备流量')
  }
  if (takeoverOn.value) return takeoverSummary.value
  const port = snap.value.mixed_port
  return port ? tr('内核运行中 · 未接管系统流量 · 仅端口 {0} 可用', { 0: port }) : tr('内核运行中 · 未接管系统流量')
})

function uptimeText(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds))
  const days = Math.floor(total / 86_400)
  const hours = Math.floor((total % 86_400) / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  if (days > 0) return tr('{0} 天 {1} 时', { 0: days, 1: hours })
  if (hours > 0) return tr('{0} 时 {1} 分', { 0: hours, 1: minutes })
  return minutes > 0 ? tr('{0} 分', { 0: minutes }) : tr('不到 1 分')
}

const groupNames = computed(() => new Set(snap.value.node_catalog.map((group) => group.name)))

/**
 * Home group cards always reserve a delay slot (R1). Nested policy groups follow
 * their chain to the real exit server; disconnected, untested and DIRECT/REJECT read as "—".
 */
function groupDelay(group: NodeGroup): { text: string; tone: string } {
  const none = { text: '—', tone: 'none' }
  if (!snap.value.connected) return none
  const state = effectiveGroupDelay(group, snap.value.node_catalog, store.testResults.value)
  if (!state.target || (!state.failed && state.delay == null)) return none
  return { text: delayText(state.delay, state.failed), tone: delayTone(state.delay, state.failed) }
}

/** 自动选择 › 香港 01 when a group points at another group, so the real server stays visible (R14). */
function hopsOf(group: NodeGroup): string[] {
  const chain = resolveChain(group.name, snap.value.node_catalog)
  return chain.length ? chain : group.now ? [group.now] : []
}

function heroHopsOf(group: NodeGroup): string[] {
  if (!group.now) return [group.name]
  const hops = hopsOf(group)
  // On phones, drop policy group prefixes; keep an upstream transit server if chained.
  const serverTail = hops.filter((hop, idx) => idx === hops.length - 1 || (!groupNames.value.has(hop) && hop !== 'GLOBAL'))
  return serverTail.length ? serverTail : hops.slice(-1)
}

function onPrimary() {
  if (!store.hasProfiles.value) {
    store.adding.value = true
    return
  }
  void store.toggleConnection()
}

const portCopied = ref(false)
let portCopiedTimer: ReturnType<typeof setTimeout> | null = null

async function onCopyProxyEnv() {
  await store.copyProxyEnv()
  portCopied.value = true
  if (portCopiedTimer) clearTimeout(portCopiedTimer)
  portCopiedTimer = setTimeout(() => {
    portCopied.value = false
    portCopiedTimer = null
  }, 1600)
}

function toggleSystemProxyTile() {
  if (store.busy.proxy) return
  void store.setSystemProxy(!snap.value.system_proxy)
}

function toggleTunTile() {
  if (store.busy.tun) return
  void store.setTun(!snap.value.tun)
}

onBeforeUnmount(() => {
  if (portCopiedTimer) clearTimeout(portCopiedTimer)
  portCopiedTimer = null
})
</script>

<template>
  <div class="page home">
    <div v-if="store.hasProfiles.value && failureText" class="banner error" role="alert" data-testid="home-failure">
      <Icon name="alert" />
      <span class="grow">{{ tr(failureText) }}</span>
      <button
        v-if="failureSettingsAction"
        type="button"
        class="btn ghost sm"
        data-testid="failure-open-settings"
        @click="store.openSettings(failureSettingsAction.tab, failureSettingsAction.focus)"
      >
        {{ failureSettingsAction.label }}
      </button>
      <button
        v-if="store.lastFailedAction.value"
        type="button"
        class="btn ghost sm"
        data-testid="retry"
        @click="store.retryLastAction()"
      > {{ tr('重试') }} </button>
      <button type="button" class="btn ghost sm" @click="store.go('logs')">{{ tr('查看日志') }}</button>
    </div>

    <section
      v-if="!store.hasProfiles.value"
      class="card welcome"
      :class="{ over: welcomeDragging }"
      data-testid="welcome"
      @dragover.prevent="welcomeDragging = true"
      @dragleave="welcomeDragging = false"
      @drop.prevent="onWelcomeDrop"
    >
      <div class="welcome-emblem">
        <BrandMark size="lg" />
      </div>
      <h1 class="status-word" data-testid="status">{{ tr('欢迎使用 Billow') }}</h1>
      <p class="hero-sub muted">{{ tr('轻量、纯净的现代网络代理客户端，导入一份配置即可开始') }}</p>
      <button type="button" class="connect-control" data-testid="power" @click="store.adding.value = true">
        <span class="connect-glyph"><Icon name="plus" :size="22" :stroke="2.2" /></span>
        <span class="connect-label">{{ tr('添加配置') }}</span>
      </button>
      <div class="welcome-steps" aria-hidden="true">
        <span><Icon name="link" :size="13" />{{ tr('粘贴订阅链接') }}</span>
        <span><Icon name="file" :size="13" />{{ tr('拖入本地文件') }}</span>
        <span><Icon name="zap" :size="13" />{{ tr('一键开启分流') }}</span>
      </div>
      <p class="muted small welcome-hint" data-testid="import-hint">{{ tr('支持订阅链接与 Clash / Mihomo YAML 文件；也可直接将配置文件拖入此处。') }}</p>
    </section>

    <div v-else class="home-layout">
      <!-- Unified Cockpit Hero: state, 1-tap profile/node pills, primary power orb/trigger, live rates, chart & runtime -->
      <section class="card hero" :class="[status.tone, { bare: snap.kernel_running && !takeoverOn }]" data-testid="home-status">
        <div class="hero-topbar">
          <span class="hero-status-pill">
            <Icon v-if="snap.kernel_running && !takeoverOn && !store.connecting.value" name="alert" :size="13" aria-hidden="true" />
            <Icon v-else-if="takeoverOn && !store.connecting.value" name="check" :size="13" aria-hidden="true" />
            <span v-else class="hero-dot" aria-hidden="true" />
            <span data-testid="hero-eyebrow">{{ heroEyebrow }}</span>
          </span>
          <div class="hero-pills-right">
            <button
              v-if="!store.isAndroid.value && snap.mixed_port"
              type="button"
              class="hero-port-btn mono"
              :class="{ copied: portCopied }"
              :title="tr('点击复制终端环境变量 (127.0.0.1:{0})', { 0: snap.mixed_port })"
              data-testid="copy-proxy-cmd"
              @click="onCopyProxyEnv"
            >
              <span>:{{ snap.mixed_port }}</span>
              <Icon :name="portCopied ? 'check' : 'copy'" :size="12" />
            </button>
            <button
              v-if="profile"
              type="button"
              class="hero-profile-pill"
              data-testid="mobile-profile-trigger"
              :aria-label="tr('当前配置：{0}，点击切换配置', { 0: profile.name })"
              :title="tr('当前配置：{0}（点击切换配置）', { 0: profile.name })"
              @click="openProfileSheet"
            >
              <Icon :name="profile.kind === 'local' ? 'file' : 'link'" :size="13" />
              <span class="hero-profile ellipsis">{{ profile.name }}</span>
              <Icon name="chevron-down" :size="13" />
            </button>
          </div>
        </div>

        <div class="hero-main">
          <div class="hero-state">
            <h1 class="status-word" data-testid="status">{{ status.word }}</h1>
            <p v-if="store.connectStage.value" class="hero-sub muted" role="status">{{ store.connectStage.value }}</p>
            <div v-else class="hero-context">
              <button
                v-if="primaryGroup && snap.mode !== 'direct'"
                type="button"
                class="hero-node-pill"
                data-testid="hero-node-pill"
                :title="tr('点击切换「{0}」节点', { 0: primaryGroup.name })"
                @click="openNodePicker(primaryGroup.name)"
              >
                <Icon name="globe" :size="14" class="hero-node-icon" />
                <span v-if="!compact" class="hero-node-group">{{ primaryGroup.name }}</span>
                <span v-if="!compact" class="hero-node-sep" aria-hidden="true">·</span>
                <!-- Phones drop the group label here, so they show only the server (or relay → server) the traffic leaves through. -->
                <ChainPath class="hero-node-name" :hops="compact ? heroHopsOf(primaryGroup) : (primaryGroup.now ? hopsOf(primaryGroup) : [primaryGroup.name])" :groups="groupNames" />
                <span
                  v-if="primaryDelay.tone !== 'none'"
                  class="hero-node-delay mono"
                  :class="primaryDelay.tone"
                >{{ primaryDelay.text }}</span>
                <Icon name="chevron-right" :size="13" class="muted" />
              </button>
              <p v-else-if="snap.mode === 'direct'" class="hero-sub muted">
                <span>{{ tr('当前直连出站 · 不经过代理节点') }}</span>
                <button
                  type="button"
                  class="link-btn"
                  :disabled="modeBusy"
                  data-testid="home-switch-rule"
                  @click="store.setMode('rule')"
                >{{ tr('切回规则模式') }}</button>
              </p>
              <p v-else-if="!profile" class="hero-sub muted">{{ tr('选择一份配置后即可开启代理') }}</p>
              <p v-else class="hero-sub muted">
                <span>{{ activeMode ? tr('{0}模式', { 0: activeMode.label }) : tr('就绪') }}</span>
                <template v-if="store.isAndroid.value && snap.mixed_port">
                  <span>{{ tr('· 端口') }} {{ snap.mixed_port }}</span>
                </template>
              </p>
            </div>
          </div>

          <Transition name="hero-reveal">
            <div v-if="snap.connected" class="hero-rates" data-testid="rates">
              <div class="rate down">
                <span class="rate-label"><Icon name="down" :size="13" />{{ tr('下载') }}</span>
                <span class="rate-value">{{ formatSpeed(snap.download ?? 0) }}</span>
                <span v-if="snap.download_total != null" class="rate-total">{{ tr('本次') }} {{ formatBytes(snap.download_total) }}</span>
              </div>
              <div class="rate up">
                <span class="rate-label"><Icon name="up" :size="13" />{{ tr('上传') }}</span>
                <span class="rate-value">{{ formatSpeed(snap.upload ?? 0) }}</span>
                <span v-if="snap.upload_total != null" class="rate-total">{{ tr('本次') }} {{ formatBytes(snap.upload_total) }}</span>
              </div>
            </div>
          </Transition>

          <div class="hero-action" data-testid="home-action">
            <button
              type="button"
              class="connect-control"
              :class="status.tone"
              :disabled="store.connecting.value"
              :aria-busy="store.connecting.value || undefined"
              data-testid="power"
              @click="onPrimary"
            >
              <span class="connect-glyph">
                <span v-if="store.connecting.value" class="spinner sm" />
                <Icon v-else :name="connectIcon" :size="compact ? 30 : 21" :stroke="2.3" />
              </span>
              <span class="connect-label">{{ connectLabel }}</span>
            </button>
          </div>
        </div>

        <Transition name="hero-reveal">
          <div v-if="snap.connected" class="hero-chart" data-testid="traffic-card">
            <TrafficChart
              :up="store.traffic.value.up"
              :down="store.traffic.value.down"
              :height="compact ? 52 : 84"
              :collecting="store.trafficSamples.value < MIN_CHART_SAMPLES"
            >
              <!-- History lives one click away from the live chart, but only once recording is on (R43). -->
              <template v-if="store.app.value?.traffic_history" #head-end>
                <button type="button" class="chart-link" data-testid="open-traffic-stats" @click="store.openTrafficStats">
                  {{ t('settings.traffic.open') }}<Icon name="chevron-right" :size="12" />
                </button>
              </template>
            </TrafficChart>
          </div>
        </Transition>

        <Transition name="hero-reveal">
          <dl v-if="snap.connected && runtime.length" class="runtime" data-testid="runtime">
            <div v-for="item in runtime" :key="item.key" class="runtime-item" :data-testid="`runtime-${item.key}`">
              <dt>{{ item.label }}</dt>
              <dd>
                <button v-if="item.key === 'connections'" type="button" class="runtime-link" @click="store.go('connections')">
                  {{ item.value }}<Icon name="chevron-right" :size="13" />
                </button>
                <template v-else>{{ item.value }}</template>
              </dd>
            </div>
          </dl>
        </Transition>
      </section>

      <div class="home-columns">
        <div class="home-col">
          <!-- Control Center: Outbound Mode + Tactile Traffic Takeover Bento Tiles -->
          <section class="card control-card" data-testid="control-card">
            <div class="control-block" data-testid="mode-card">
              <header class="control-head">
                <h2>{{ tr('出站模式') }}</h2>
                <p class="mode-hint" aria-live="polite" data-testid="mode-hint">{{ modeBusy ? tr('切换中…') : modeHint }}</p>
              </header>
              <div class="mode-segmented" data-testid="mode-segmented">
                <Segmented
                  :model-value="snap.mode"
                  :options="MODE_OPTIONS"
                  :label="tr('出站模式')"
                  :disabled="modeBusy"
                  @update:model-value="store.setMode"
                />
              </div>
            </div>

            <div v-if="!store.isAndroid.value" class="control-block takeover" data-testid="takeover-card">
              <header class="control-head">
                <h2>{{ tr('流量接管') }}</h2>
                <p
                  class="mode-hint takeover-hint-text"
                  :class="{ 'text-warn': snap.kernel_running && !takeoverOn }"
                  data-testid="takeover-hint"
                >
                  <Icon v-if="snap.kernel_running && !takeoverOn" name="alert" :size="13" aria-hidden="true" />
                  <span>{{ takeoverSummary }}</span>
                </p>
              </header>
              <div class="takeover-grid">
                <div
                  class="takeover-tile"
                  :class="{ active: snap.system_proxy, busy: Boolean(store.busy.proxy) }"
                  @click="toggleSystemProxyTile"
                >
                  <div class="takeover-tile-top">
                    <span class="row-icon"><Icon name="monitor" :size="17" /></span>
                    <div class="takeover-tile-actions" @click.stop>
                      <button
                        type="button"
                        class="icon-btn sm"
                        :title="tr('系统代理设置')"
                        :aria-label="tr('系统代理设置')"
                        data-testid="proxy-settings-link"
                        @click="store.openSettings('proxy')"
                      >
                        <Icon name="sliders" :size="14" />
                      </button>
                      <Toggle
                        :model-value="snap.system_proxy"
                        :busy="store.busy.proxy"
                        :label="tr('系统代理')"
                        data-testid="toggle-proxy"
                        @update:model-value="store.setSystemProxy"
                      />
                    </div>
                  </div>
                  <div class="takeover-tile-body">
                    <strong>{{ tr('系统代理') }}</strong>
                    <p class="muted small ellipsis">{{ proxySubtitle }}</p>
                  </div>
                </div>

                <div
                  class="takeover-tile"
                  :class="{ active: snap.tun, busy: Boolean(store.busy.tun) }"
                  @click="toggleTunTile"
                >
                  <div class="takeover-tile-top">
                    <span class="row-icon"><Icon name="shield" :size="17" /></span>
                    <div class="takeover-tile-actions" @click.stop>
                      <button
                        type="button"
                        class="icon-btn sm"
                        :title="tr('TUN 设置')"
                        :aria-label="tr('TUN 设置')"
                        data-testid="tun-settings-link"
                        @click="store.openSettings('tun')"
                      >
                        <Icon name="sliders" :size="14" />
                      </button>
                      <Toggle
                        :model-value="snap.tun"
                        :busy="store.busy.tun"
                        :label="tr('TUN 模式')"
                        data-testid="toggle-tun"
                        @update:model-value="store.setTun"
                      />
                    </div>
                  </div>
                  <div class="takeover-tile-body">
                    <strong>{{ tr('TUN 模式') }}</strong>
                    <p class="muted small ellipsis">{{ tunSubtitle }}</p>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section class="card home-subscription" data-testid="profile-card">
            <header class="card-head">
              <h2>{{ tr('当前配置') }}</h2>
              <button type="button" class="btn ghost sm" @click="store.go('profiles')">{{ tr('管理') }}<Icon name="chevron-right" :size="14" /></button>
            </header>
            <template v-if="profile">
              <div class="sub-head">
                <span class="sub-icon"><Icon :name="profile.kind === 'local' ? 'file' : 'link'" /></span>
                <div class="grow min0">
                  <strong class="ellipsis">{{ profile.name }}</strong>
                  <p class="muted small">
                    {{ profile.kind === 'local' ? tr('本地配置') : tr('更新于 {0}', { 0: formatRelative(profile.updated_ms ?? profile.last_success_ms) }) }}
                    <template v-if="profile.proxy_count"> · {{ profile.proxy_count }} {{ tr('个节点') }}</template>
                  </p>
                </div>
                <button
                  v-if="profile.kind === 'subscription'"
                  type="button"
                  class="btn ghost sm"
                  :disabled="updateBusy"
                  :aria-busy="updateBusy || undefined"
                  data-testid="update-subscription"
                  @click="store.update(profile.id)"
                >
                  <span v-if="updateBusy" class="spinner xs" aria-hidden="true" />
                  <Icon v-else name="refresh" :size="14" />
                  {{ updateBusy ? tr('更新中') : tr('更新') }}
                </button>
              </div>
              <div v-if="usage != null || profile.expire" class="usage">
                <div v-if="usage != null" class="usage-bar">
                  <span
                    :style="{ width: `${usage > 0 ? Math.max(usage, 1.5) : 0}%` }"
                    :class="{
                      danger: usage >= 98 || (expireDays != null && expireDays < 0),
                      warn: usage > 85 && usage < 98 && (expireDays == null || expireDays >= 0),
                    }"
                  />
                </div>
                <div class="usage-text small">
                  <span v-if="usage != null" class="mono">
                    {{ formatBytes(profile.used) }} / {{ formatBytes(profile.total) }}
                    <span v-if="remainingBytes != null" class="muted">{{ tr('· 剩 {0}', { 0: formatBytes(remainingBytes) }) }}</span>
                  </span>
                  <span v-else class="muted">{{ tr('不限流量') }}</span>
                  <span
                    v-if="profile.expire"
                    :class="{
                      'text-error': expireDays != null && expireDays < 0,
                      'text-warn': expireDays != null && expireDays >= 0 && expireDays <= 7,
                    }"
                  >
                    {{ expireDays != null && expireDays < 0 ? tr('已过期') : tr('{0} 到期 · 剩 {1} 天', { 0: formatDate(profile.expire), 1: expireDays }) }}
                  </span>
                </div>
              </div>
              <p v-else class="muted small">{{ tr('本地或无流量统计信息') }}</p>
              <p v-if="profile.failure" class="field-error home-profile-failure" role="alert">
                <Icon name="alert" :size="13" />
                <span class="grow">{{ tr(profile.failure) }}</span>
                <button
                  v-if="profile.kind === 'subscription'"
                  type="button"
                  class="btn ghost sm"
                  :disabled="updateBusy"
                  :aria-busy="updateBusy || undefined"
                  data-testid="home-profile-retry"
                  @click="store.update(profile.id)"
                >
                  <span v-if="updateBusy" class="spinner xs" aria-hidden="true" />
                  {{ updateBusy ? tr('更新中') : tr('重试') }}
                </button>
              </p>
              <p v-if="profile.override_error" class="field-error">
                <Icon name="alert" :size="13" /> {{ tr(profile.override_error) }}
                <button type="button" class="btn ghost sm" data-testid="home-override-fix" @click="openProfileOverride(profile.id)">{{ tr('修改覆写') }}</button>
              </p>
            </template>
            <p v-else class="empty-line muted">{{ tr('还没有启用配置，去配置页选择一份') }}</p>
          </section>

          <!-- Exit IP (R40): absent while auto-query is off, so nothing is requested. -->
          <section v-if="store.autoExitIp.value" class="card exit-ip-card" :class="{ stale: store.exitIpStale.value }" data-testid="exit-ip-card">
            <header class="card-head">
              <h2>
                {{ t('exitIp.title') }}
                <span v-if="store.exitIpStale.value" class="tag sm warn" data-testid="exit-ip-stale">{{ t('exitIp.changed') }}</span>
              </h2>
              <button
                v-if="store.exitIp.value"
                type="button"
                class="btn ghost sm"
                :class="{ 'accent-text': store.exitIpStale.value }"
                :disabled="!snap.connected || store.exitIpBusy.value"
                :aria-busy="store.exitIpBusy.value || undefined"
                data-testid="exit-ip-refresh"
                @click="store.queryExitIp()"
              >
                <span v-if="store.exitIpBusy.value" class="spinner xs" aria-hidden="true" />
                <Icon v-else name="refresh" :size="14" />
                {{ store.exitIpBusy.value ? t('exitIp.querying') : t('exitIp.refresh') }}
              </button>
            </header>
            <div v-if="store.exitIp.value" class="sub-head exit-ip-result" data-testid="exit-ip-result">
              <span class="sub-icon"><Icon name="globe" /></span>
              <div class="grow min0">
                <button
                  type="button"
                  class="exit-ip-value mono"
                  :title="t('exitIp.copy')"
                  data-testid="exit-ip-copy"
                  @click="store.copyText(store.exitIp.value.ip, t('exitIp.copied'))"
                >
                  <span data-testid="exit-ip-value">{{ store.exitIp.value.ip }}</span><Icon name="copy" :size="12" class="exit-ip-copy-icon" />
                </button>
                <p class="muted small ellipsis exit-ip-line">
                  <span data-testid="exit-ip-region" :title="t('exitIp.region', { region: store.exitIp.value.region || '—' })">{{ store.exitIp.value.region || '—' }}</span>
                  <span aria-hidden="true"> · </span>
                  <span data-testid="exit-ip-isp" :title="t('exitIp.isp', { isp: store.exitIp.value.isp || '—' })">{{ store.exitIp.value.isp || '—' }}</span>
                </p>
              </div>
            </div>
            <p v-if="store.exitIp.value" class="muted small exit-ip-meta" data-testid="exit-ip-meta">
              {{ t('exitIp.meta', { service: store.exitIp.value.service, time: formatClock(store.exitIp.value.time_ms) }) }}
            </p>
            <p v-if="store.exitIpError.value" class="field-error small exit-ip-note" role="alert" data-testid="exit-ip-error">
              <Icon name="alert" :size="13" />{{ tr(store.exitIpError.value) }}
            </p>
            <p v-if="!snap.connected" class="muted small exit-ip-note" data-testid="exit-ip-offline">
              {{ t('exitIp.offline') }}
            </p>
            <button
              v-if="!store.exitIp.value"
              type="button"
              class="btn sm block exit-ip-query"
              :disabled="!snap.connected || store.exitIpBusy.value"
              :aria-busy="store.exitIpBusy.value || undefined"
              data-testid="exit-ip-query"
              @click="store.queryExitIp()"
            >
              <span v-if="store.exitIpBusy.value" class="spinner xs" aria-hidden="true" />
              <Icon v-else name="globe" :size="14" />
              {{ store.exitIpBusy.value ? t('exitIp.querying') : t('exitIp.query') }}
            </button>
          </section>
        </div>

        <div class="home-col">
          <section class="card home-groups" :class="{ 'direct-dim': snap.mode === 'direct' }" data-testid="groups-card">
            <header class="card-head">
              <h2> {{ tr('代理组') }}<span v-if="allPickableGroups.length" class="card-count">{{ allPickableGroups.length }}</span>
                <span v-if="snap.mode === 'direct' && manualGroups.length" class="tag sm">{{ tr('直连中') }}</span>
              </h2>
              <div class="card-head-actions">
                <!-- Fills the delay slots below without a detour through the proxy page. -->
                <button
                  v-if="snap.connected && manualGroups.length"
                  type="button"
                  class="btn ghost sm"
                  :disabled="testBlocked"
                  :aria-busy="testBusy || undefined"
                  :title="homeTestTitle"
                  data-testid="home-test-all"
                  @click="store.testAll()"
                >
                  <span v-if="testBusy" class="spinner xs" aria-hidden="true" />
                  <Icon v-else name="zap" :size="14" />
                  {{ testBusy ? tr('测速中') : tr('测速') }}
                </button>
                <button type="button" class="btn ghost sm" @click="store.go('proxies')">{{ tr('查看全部') }}<Icon name="chevron-right" :size="14" /></button>
              </div>
            </header>
            <p v-if="snap.mode === 'direct' && manualGroups.length" class="card-note muted small">{{ tr('当前为直连模式，新发起的连接不经过代理组') }}</p>
            <p v-if="!manualGroups.length" class="empty-line muted">{{ snap.nodes_notice ? tr(snap.nodes_notice) : tr('这份配置没有可手动选择的代理组') }}</p>
            <div v-else class="home-groups-grid" :class="{ single: manualGroups.length === 1 }">
              <button
                v-for="group in manualGroups"
                :key="group.name"
                type="button"
                class="group-row"
                :data-group="group.name"
                @click="openNodePicker(group.name)"
              >
                <template v-if="compact">
                  <span class="group-row-icon"><GroupIcon :icon="group.icon" :type="group.group_type" :size="20" /></span>
                  <div class="group-row-text">
                    <span class="group-row-head">
                      <span class="group-row-name">{{ group.name }}</span>
                      <span v-if="autoTypeLabel(group)" class="tag sm" data-testid="home-group-type">{{ autoTypeLabel(group) }}</span>
                      <span
                        v-if="group.fixed"
                        class="tag sm accent"
                        :title="tr('已固定使用 {0}', { 0: group.fixed })"
                        data-testid="home-group-fixed"
                      >{{ tr('已固定') }}</span>
                    </span>
                    <span class="group-row-now">
                      <ChainPath :hops="hopsOf(group)" :groups="groupNames" fold data-testid="home-group-now" />
                    </span>
                  </div>
                  <span class="group-row-side">
                    <span
                      class="delay home-group-delay mono"
                      :class="groupDelay(group).tone"
                      data-testid="home-group-delay"
                    >{{ groupDelay(group).text }}</span>
                    <Icon name="chevron-right" :size="14" class="group-tile-arrow" />
                  </span>
                </template>
                <template v-else>
                  <div class="group-tile-top">
                    <span class="group-row-icon"><GroupIcon :icon="group.icon" :type="group.group_type" :size="20" /></span>
                    <span class="group-tile-meta">
                      <span v-if="autoTypeLabel(group)" class="tag sm" data-testid="home-group-type">{{ autoTypeLabel(group) }}</span>
                      <span
                        v-if="group.fixed"
                        class="tag sm accent"
                        :title="tr('已固定使用 {0}', { 0: group.fixed })"
                        data-testid="home-group-fixed"
                      >{{ tr('已固定') }}</span>
                      <span
                        class="delay home-group-delay mono"
                        :class="groupDelay(group).tone"
                        data-testid="home-group-delay"
                      >{{ groupDelay(group).text }}</span>
                    </span>
                  </div>
                  <div class="group-row-text">
                    <span class="group-row-name">{{ group.name }}</span>
                    <span class="group-row-now">
                      <ChainPath :hops="hopsOf(group)" :groups="groupNames" fold data-testid="home-group-now" />
                      <Icon name="chevron-right" :size="13" class="group-tile-arrow" />
                    </span>
                  </div>
                </template>
              </button>
            </div>
            <button
              v-if="hiddenGroupCount > 0"
              type="button"
              class="btn ghost sm block home-groups-more"
              data-testid="home-groups-expand"
              @click="showAllGroups = !showAllGroups"
            >
              <Icon :name="showAllGroups ? 'up' : 'chevron-down'" :size="14" />
              {{ showAllGroups ? tr('收起其余代理组') : tr('展开其余 {0} 个代理组', { 0: hiddenGroupCount }) }}
            </button>
          </section>
        </div>
      </div>
    </div>

    <Modal
      :open="profileSheetOpen"
      :title="tr('切换配置')"
      :subtitle="tr('选择后立即启用，无需离开首页')"
      :before-close="() => !isSheetSwitching"
      :initial-focus="sheetInitialFocus"
      @close="closeProfileSheet"
    >
      <div class="option-list profile-sheet-list" data-testid="home-profile-sheet">
        <div
          v-for="item in orderedProfiles"
          :key="item.id"
          class="profile-sheet-item"
          :class="{
            active: item.current,
            enabling: isEnablingProfile(item.id),
            failed: sheetFailureFor(item.id) !== null,
          }"
          :data-testid="`sheet-item-${item.id}`"
        >
          <button
            type="button"
            class="option-row profile-sheet-row"
            :class="{ active: item.current, enabling: isEnablingProfile(item.id) }"
            :aria-current="item.current ? 'true' : undefined"
            :aria-busy="isEnablingProfile(item.id) || undefined"
            :aria-disabled="isSheetSwitching || undefined"
            :aria-describedby="sheetFailureFor(item.id) ? `sheet-error-${item.id}` : undefined"
            :data-testid="`sheet-profile-${item.id}`"
            @click="switchFromSheet(item)"
          >
            <span class="sub-icon sm"><Icon :name="item.kind === 'local' ? 'file' : 'link'" :size="16" /></span>
            <span class="profile-sheet-body">
              <span class="profile-sheet-title-row">
                <span class="option-label profile-sheet-name" :title="item.name">{{ item.name }}</span>
                <span v-if="item.current" class="tag accent sm" data-testid="sheet-current-tag">{{ tr('使用中') }}</span>
              </span>
              <span class="muted small">
                {{ item.proxy_count ? tr('{0} 个节点', { 0: item.proxy_count }) : item.kind === 'local' ? tr('本地配置') : tr('远程订阅') }}
                <template v-if="usagePercent(item.used, item.total) != null"> {{ tr('· 已用') }} {{ Math.round(usagePercent(item.used, item.total)!) }}%
                </template>
                <span v-if="item.expire && daysLeft(item.expire) < 0" class="text-error">{{ tr('· 已过期') }}</span>
                <span v-else-if="item.expire && daysLeft(item.expire) <= 7" class="text-warn">{{ tr('· 剩 {0} 天', { 0: daysLeft(item.expire) }) }}</span>
                <span v-else-if="item.failure || item.override_error" class="text-error">{{ tr('· 有异常') }}</span>
              </span>
            </span>
            <span
              v-if="isEnablingProfile(item.id)"
              class="profile-sheet-state pending"
              role="status"
              data-testid="sheet-enabling"
            >
              <span class="spinner xs" aria-hidden="true" />
              <span>{{ tr('正在启用') }}</span>
            </span>
            <Icon v-else-if="item.current" name="check" :size="18" class="option-check" aria-hidden="true" />
          </button>
          <div
            v-if="sheetFailureFor(item.id)"
            :id="`sheet-error-${item.id}`"
            class="profile-sheet-error field-error small"
            role="alert"
            :data-testid="`sheet-error-${item.id}`"
          >
            <Icon name="alert" :size="14" />
            <span class="grow">{{ tr(sheetFailureFor(item.id) ?? '') }}</span>
            <button
              type="button"
              class="btn ghost sm"
              :disabled="isSheetSwitching"
              :data-testid="`sheet-retry-${item.id}`"
              @click="switchFromSheet(item)"
            > {{ tr('重试') }} </button>
          </div>
        </div>
      </div>
      <template #footer>
        <button type="button" class="btn ghost" :disabled="isSheetSwitching" @click="manageFromSheet">{{ tr('管理配置') }}</button>
        <button type="button" class="btn primary" :disabled="isSheetSwitching" @click="addFromSheet"><Icon name="plus" :size="15" />{{ tr('添加新配置') }}</button>
      </template>
    </Modal>
    <NodePickerModal
      :open="Boolean(pickerGroup)"
      :group="pickerGroup"
      :compact="compact"
      @close="closeNodePicker"
    />
    <TrafficStatsDialog v-if="store.trafficStatsOpen.value" @close="store.trafficStatsOpen.value = false" />
  </div>
</template>

<style scoped>
.exit-ip-result {
  margin-bottom: 0;
}

.exit-ip-value {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  max-width: 100%;
  font-size: var(--text-lg);
  font-weight: 650;
  color: var(--text);
  border-radius: 6px;
  padding: 0 4px;
  margin: 0 -4px;
  transition: background var(--dur-fast) var(--ease);
}

.exit-ip-value > span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.exit-ip-value:hover {
  background: var(--hover);
}

.exit-ip-copy-icon {
  flex: none;
  color: var(--muted);
  opacity: 0;
  transition: opacity var(--dur-fast) var(--ease);
}

.exit-ip-value:hover .exit-ip-copy-icon,
.exit-ip-value:focus-visible .exit-ip-copy-icon {
  opacity: 1;
}

.exit-ip-line {
  margin-top: 2px;
}

.exit-ip-card.stale .exit-ip-value,
.exit-ip-card.stale .exit-ip-line {
  opacity: 0.6;
}

.exit-ip-meta {
  margin-top: 10px;
  font-size: var(--text-xs);
}

.exit-ip-note {
  margin-top: 8px;
}

.exit-ip-query {
  margin-top: 10px;
}

.accent-text {
  color: var(--accent-ink);
}
</style>
