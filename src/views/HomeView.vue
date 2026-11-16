<script setup lang="ts">
import { computed, ref } from 'vue'
import GroupIcon from '../components/GroupIcon.vue'
import Icon from '../components/Icon.vue'
import Modal from '../components/Modal.vue'
import Segmented from '../components/Segmented.vue'
import Toggle from '../components/Toggle.vue'
import TrafficChart from '../components/TrafficChart.vue'
import {
  daysLeft,
  delayText,
  delayTone,
  formatBytes,
  formatDate,
  formatRelative,
  formatSpeed,
  usagePercent,
} from '../lib/format'
import { useStore } from '../lib/store'
import type { Mode, ProfileItem } from '../lib/types'

defineProps<{ compact?: boolean }>()
const appIcon = `${import.meta.env.BASE_URL}icon.png`
const store = useStore()
const snap = computed(() => store.snapshot.value)
const profile = computed(() => store.current.value)

const MODES: { id: Mode; label: string; hint: string; icon: string }[] = [
  { id: 'rule', label: '规则', hint: '按配置中的规则分流', icon: 'route' },
  { id: 'global', label: '全局', hint: '全部流量走当前节点', icon: 'globe' },
  { id: 'direct', label: '直连', hint: '新连接都不经过代理', icon: 'zap' },
]
const MODE_OPTIONS = MODES.map(({ id, label, icon }) => ({ id, label, icon }))

const status = computed(() => {
  if (store.connecting.value) return { word: snap.value.connected ? '断开中' : '连接中', tone: 'pending' }
  if (snap.value.connected) return { word: '已连接', tone: 'on' }
  return { word: '未连接', tone: 'off' }
})

/** One control owns connect, disconnect and the empty-state add action (R24). */
const connectLabel = computed(() => {
  if (!store.hasProfiles.value) return '添加配置'
  if (store.connecting.value) return snap.value.connected ? '断开中' : '连接中'
  return snap.value.connected ? '断开' : '连接'
})
const connectIcon = computed(() => (store.hasProfiles.value ? 'power' : 'plus'))

const activeMode = computed(() => MODES.find((mode) => mode.id === snap.value.mode) ?? null)
const modeHint = computed(() => activeMode.value?.hint ?? '还没有读到出站模式')
const modeBusy = computed(() => Boolean(store.busy.mode))

const updateBusy = computed(() => (profile.value ? Boolean(store.busy[`update:${profile.value.id}`]) : false))

const allManualGroups = computed(() => snap.value.node_catalog.filter((group) => group.kind === 'manual'))
const manualGroups = computed(() => allManualGroups.value.slice(0, 8))
const primaryGroup = computed(() => {
  if (snap.value.mode === 'global') {
    return snap.value.node_catalog.find((group) => group.name === 'GLOBAL') ?? allManualGroups.value[0] ?? null
  }
  return allManualGroups.value.find((group) => Boolean(group.now)) ?? allManualGroups.value[0] ?? null
})
const primaryNode = computed(() => (primaryGroup.value ? nodeOf(primaryGroup.value) : undefined))

const profileSheetOpen = ref(false)
const welcomeDragging = ref(false)
const orderedProfiles = computed(() =>
  [...snap.value.profiles].sort((a, b) => Number(b.current) - Number(a.current)),
)

function switchFromSheet(target: ProfileItem) {
  profileSheetOpen.value = false
  if (!target.current && !store.busy[`enable:${target.id}`]) {
    void store.enable(target.id)
  }
}
function addFromSheet() {
  profileSheetOpen.value = false
  store.adding.value = true
}
function manageFromSheet() {
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
    store.toast(`已导入 ${file.name}`, 'success')
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
const failureSettingsAction = computed<{ label: string; tab: 'kernel' | 'tun' } | null>(() => {
  const text = failureText.value
  if (!text) return null
  if (text.includes('混合端口') || (text.includes('端口') && text.includes('占用'))) {
    return { label: '更换端口', tab: 'kernel' }
  }
  if (text.includes('TUN')) {
    return { label: 'TUN 设置', tab: 'tun' }
  }
  return null
})

/** Only values the kernel actually reported survive; a missing reading hides the row (R24). */
const runtime = computed(() => {
  const items: { key: string; label: string; value: string }[] = []
  if (snap.value.connected) {
    items.push({ key: 'connections', label: '活动连接', value: String(snap.value.connection_total) })
  }
  if (snap.value.kernel_memory != null) {
    items.push({ key: 'memory', label: '内核内存', value: formatBytes(snap.value.kernel_memory) })
  }
  if (snap.value.kernel_uptime_secs != null) {
    items.push({ key: 'uptime', label: '运行时长', value: uptimeText(snap.value.kernel_uptime_secs) })
  }
  const version = store.kernel.value.version
  if (version) items.push({ key: 'kernel', label: '内核版本', value: version })
  return items
})

const takeoverSummary = computed(() => {
  if (store.isAndroid.value) return snap.value.vpn ? 'VPN 已接管设备流量' : 'VPN 未开启'
  const on: string[] = []
  if (snap.value.system_proxy) on.push('系统代理')
  if (snap.value.tun) on.push('TUN')
  return on.length ? `${on.join(' · ')} 已开启` : '未接管任何流量'
})

const takeoverOn = computed(() => (store.isAndroid.value ? snap.value.vpn : snap.value.system_proxy || snap.value.tun))

const proxySubtitle = computed(() => {
  const sp = snap.value.settings.system_proxy
  const host = sp.host.trim()
  const port = snap.value.mixed_port ?? snap.value.settings.mixed_port ?? 7890
  if (sp.mode === 'pac') {
    return host ? `PAC 自动分流 · ${host}` : 'PAC 脚本自动分流'
  }
  if (host && host !== '127.0.0.1') {
    return `${host}:${port}`
  }
  return snap.value.system_proxy ? `HTTP / SOCKS · :${port}` : '浏览器与常规应用'
})

const tunSubtitle = computed(() => {
  if (snap.value.tun) return `${snap.value.settings.tun.stack.toUpperCase()} 栈 · 全局接管`
  return '虚拟网卡接管全部流量'
})

/** The hero's first line answers "is my traffic going through Billow?", not just "is the kernel up?". */
const heroEyebrow = computed(() => {
  if (store.connecting.value) return '请稍候'
  if (!snap.value.connected) return '代理未运行'
  if (takeoverOn.value) return takeoverSummary.value
  const port = snap.value.mixed_port
  return port ? `未接管系统流量 · 仅端口 ${port} 可用` : '未接管系统流量'
})

function uptimeText(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds))
  const days = Math.floor(total / 86_400)
  const hours = Math.floor((total % 86_400) / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  if (days > 0) return `${days} 天 ${hours} 时`
  if (hours > 0) return `${hours} 时 ${minutes} 分`
  return minutes > 0 ? `${minutes} 分` : '不到 1 分'
}

function nodeOf(group: { now: string; nodes: { name: string; delay_ms: number | null; failed: boolean }[] }) {
  return group.nodes.find((node) => node.name === group.now)
}

function onPrimary() {
  if (!store.hasProfiles.value) {
    store.adding.value = true
    return
  }
  void store.toggleConnection()
}
</script>

<template>
  <div class="page home">
    <div v-if="store.hasProfiles.value && failureText" class="banner error" role="alert" data-testid="home-failure">
      <Icon name="alert" />
      <span class="grow">{{ failureText }}</span>
      <button
        v-if="failureSettingsAction"
        type="button"
        class="btn ghost sm"
        data-testid="failure-open-settings"
        @click="store.openSettings(failureSettingsAction.tab)"
      >
        {{ failureSettingsAction.label }}
      </button>
      <button
        v-if="store.lastFailedAction.value"
        type="button"
        class="btn ghost sm"
        data-testid="retry"
        @click="store.retryLastAction()"
      >
        重试
      </button>
      <button type="button" class="btn ghost sm" @click="store.go('logs')">查看日志</button>
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
        <span class="brand-mark lg"><img :src="appIcon" alt="" /></span>
      </div>
      <h1 class="status-word" data-testid="status">欢迎使用 Billow</h1>
      <p class="hero-sub muted">轻量、纯净的现代网络代理客户端，导入一份配置即可开始</p>
      <button type="button" class="connect-control" data-testid="power" @click="store.adding.value = true">
        <span class="connect-glyph"><Icon name="plus" :size="22" :stroke="2.2" /></span>
        <span class="connect-label">添加配置</span>
      </button>
      <div class="welcome-steps" aria-hidden="true">
        <span><Icon name="link" :size="13" />粘贴订阅链接</span>
        <span><Icon name="file" :size="13" />拖入本地文件</span>
        <span><Icon name="zap" :size="13" />一键开启分流</span>
      </div>
      <p class="muted small welcome-hint" data-testid="import-hint">支持订阅链接与 Clash / Mihomo YAML 文件；也可直接将配置文件拖入此处。</p>
    </section>

    <div v-else class="home-layout">
      <!-- Unified Cockpit Hero: state, 1-tap profile/node pills, primary power orb/trigger, live rates, chart & runtime -->
      <section class="card hero" :class="[status.tone, { bare: snap.connected && !takeoverOn }]" data-testid="home-status">
        <div class="hero-topbar">
          <span class="hero-status-pill">
            <span class="hero-dot" aria-hidden="true" />
            <span data-testid="hero-eyebrow">{{ heroEyebrow }}</span>
          </span>
          <div class="hero-pills-right">
            <button
              v-if="!compact && !store.isAndroid.value && snap.mixed_port"
              type="button"
              class="hero-port-btn mono"
              :title="`点击复制终端环境变量 (127.0.0.1:${snap.mixed_port})`"
              data-testid="copy-proxy-cmd"
              @click="store.copyProxyEnv()"
            >
              <span>:{{ snap.mixed_port }}</span>
              <Icon name="copy" :size="12" />
            </button>
            <button
              v-if="profile"
              type="button"
              class="hero-profile-pill"
              data-testid="mobile-profile-trigger"
              title="快速切换配置"
              @click="profileSheetOpen = true"
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
                :title="`点击前往「${primaryGroup.name}」切换节点`"
                @click="store.go('proxies', primaryGroup.name)"
              >
                <Icon name="globe" :size="14" class="hero-node-icon" />
                <span v-if="!compact" class="hero-node-group">{{ primaryGroup.name }}</span>
                <span v-if="!compact" class="hero-node-sep" aria-hidden="true">·</span>
                <span class="hero-node-name ellipsis">{{ primaryGroup.now || primaryGroup.name }}</span>
                <span
                  v-if="primaryNode && (primaryNode.delay_ms != null || primaryNode.failed)"
                  class="hero-node-delay mono"
                  :class="delayTone(primaryNode.delay_ms, primaryNode.failed)"
                >{{ delayText(primaryNode.delay_ms, primaryNode.failed) }}</span>
                <Icon name="chevron-right" :size="13" class="muted" />
              </button>
              <p v-else-if="snap.mode === 'direct'" class="hero-sub muted">当前直连出站 · 不经过代理节点</p>
              <p v-else-if="!profile" class="hero-sub muted">选择一份配置后即可开启代理</p>
              <p v-else class="hero-sub muted">
                <span>{{ activeMode ? `${activeMode.label}模式` : '就绪' }}</span>
                <template v-if="store.isAndroid.value && snap.mixed_port">
                  <span>· 端口 {{ snap.mixed_port }}</span>
                </template>
              </p>
            </div>
          </div>

          <div v-if="snap.connected" class="hero-rates mono" data-testid="rates">
            <div class="rate down">
              <span class="rate-label"><Icon name="down" :size="13" />下载</span>
              <span class="rate-value">{{ formatSpeed(snap.download ?? 0) }}</span>
              <span v-if="snap.download_total != null" class="rate-total">本次 {{ formatBytes(snap.download_total) }}</span>
            </div>
            <div class="rate up">
              <span class="rate-label"><Icon name="up" :size="13" />上传</span>
              <span class="rate-value">{{ formatSpeed(snap.upload ?? 0) }}</span>
              <span v-if="snap.upload_total != null" class="rate-total">本次 {{ formatBytes(snap.upload_total) }}</span>
            </div>
          </div>

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

        <div v-if="snap.connected" class="hero-chart" data-testid="traffic-card">
          <TrafficChart :up="store.traffic.value.up" :down="store.traffic.value.down" :height="compact ? 72 : 84" />
        </div>

        <dl v-if="snap.connected && runtime.length" class="runtime" data-testid="runtime">
          <div v-for="item in runtime" :key="item.key" class="runtime-item" :data-testid="`runtime-${item.key}`">
            <dt>{{ item.label }}</dt>
            <dd class="mono">
              <button v-if="item.key === 'connections'" type="button" class="runtime-link" @click="store.go('connections')">
                {{ item.value }}<Icon name="chevron-right" :size="13" />
              </button>
              <template v-else>{{ item.value }}</template>
            </dd>
          </div>
        </dl>
      </section>

      <div class="home-columns">
        <div class="home-col">
          <!-- Control Center: Outbound Mode + Tactile Traffic Takeover Bento Tiles -->
          <section class="card control-card" data-testid="control-card">
            <div class="control-block" data-testid="mode-card">
              <header class="control-head">
                <h2>出站模式</h2>
                <p class="mode-hint" aria-live="polite" data-testid="mode-hint">{{ modeBusy ? '切换中…' : modeHint }}</p>
              </header>
              <div class="mode-segmented" data-testid="mode-segmented">
                <Segmented
                  :model-value="snap.mode"
                  :options="MODE_OPTIONS"
                  label="出站模式"
                  :disabled="modeBusy"
                  @update:model-value="store.setMode"
                />
              </div>
            </div>

            <div v-if="!store.isAndroid.value" class="control-block takeover" data-testid="takeover-card">
              <div class="takeover-grid">
                <div
                  class="takeover-tile"
                  :class="{ active: snap.system_proxy }"
                  @click="store.setSystemProxy(!snap.system_proxy)"
                >
                  <div class="takeover-tile-top">
                    <span class="row-icon"><Icon name="monitor" :size="17" /></span>
                    <div class="takeover-tile-actions" @click.stop>
                      <button
                        type="button"
                        class="icon-btn sm"
                        title="系统代理设置"
                        aria-label="系统代理设置"
                        data-testid="proxy-settings-link"
                        @click="store.openSettings('proxy')"
                      >
                        <Icon name="sliders" :size="14" />
                      </button>
                      <Toggle
                        :model-value="snap.system_proxy"
                        :busy="store.busy.proxy"
                        label="系统代理"
                        data-testid="toggle-proxy"
                        @update:model-value="store.setSystemProxy"
                      />
                    </div>
                  </div>
                  <div class="takeover-tile-body">
                    <strong>系统代理</strong>
                    <p class="muted small ellipsis">{{ proxySubtitle }}</p>
                  </div>
                </div>

                <div
                  class="takeover-tile"
                  :class="{ active: snap.tun }"
                  @click="store.setTun(!snap.tun)"
                >
                  <div class="takeover-tile-top">
                    <span class="row-icon"><Icon name="shield" :size="17" /></span>
                    <div class="takeover-tile-actions" @click.stop>
                      <button
                        type="button"
                        class="icon-btn sm"
                        title="TUN 设置"
                        aria-label="TUN 设置"
                        data-testid="tun-settings-link"
                        @click="store.openSettings('tun')"
                      >
                        <Icon name="sliders" :size="14" />
                      </button>
                      <Toggle
                        :model-value="snap.tun"
                        :busy="store.busy.tun"
                        label="TUN 模式"
                        data-testid="toggle-tun"
                        @update:model-value="store.setTun"
                      />
                    </div>
                  </div>
                  <div class="takeover-tile-body">
                    <strong>TUN 模式</strong>
                    <p class="muted small ellipsis">{{ tunSubtitle }}</p>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section class="card home-subscription" data-testid="profile-card">
            <header class="card-head">
              <h2>当前配置</h2>
              <button type="button" class="btn ghost sm" @click="store.go('profiles')">管理<Icon name="chevron-right" :size="14" /></button>
            </header>
            <template v-if="profile">
              <div class="sub-head">
                <span class="sub-icon"><Icon :name="profile.kind === 'local' ? 'file' : 'link'" /></span>
                <div class="grow min0">
                  <strong class="ellipsis">{{ profile.name }}</strong>
                  <p class="muted small">
                    {{ profile.kind === 'local' ? '本地配置' : `更新于 ${formatRelative(profile.updated_ms ?? profile.last_success_ms)}` }}
                    <template v-if="profile.proxy_count"> · {{ profile.proxy_count }} 个节点</template>
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
                  {{ updateBusy ? '更新中' : '更新' }}
                </button>
              </div>
              <div v-if="usage != null" class="usage">
                <div class="usage-bar"><span :style="{ width: `${usage}%` }" :class="{ warn: usage > 85 }" /></div>
                <div class="usage-text small">
                  <span class="mono">
                    {{ formatBytes(profile.used) }} / {{ formatBytes(profile.total) }}
                    <span v-if="remainingBytes != null" class="muted">· 剩 {{ formatBytes(remainingBytes) }}</span>
                  </span>
                  <span
                    v-if="profile.expire"
                    :class="{
                      'text-error': expireDays != null && expireDays < 0,
                      'text-warn': expireDays != null && expireDays >= 0 && expireDays <= 7,
                    }"
                  >
                    {{ expireDays != null && expireDays < 0 ? '已过期' : `${formatDate(profile.expire)} 到期 · 剩 ${expireDays} 天` }}
                  </span>
                </div>
              </div>
              <p v-else class="muted small">本地或无流量统计信息</p>
              <p v-if="profile.failure" class="field-error">{{ profile.failure }}</p>
            </template>
            <p v-else class="empty-line muted">还没有启用配置，去配置页选择一份</p>
          </section>
        </div>

        <div class="home-col">
          <section class="card home-groups" :class="{ 'direct-dim': snap.mode === 'direct' }" data-testid="groups-card">
            <header class="card-head">
              <h2>
                代理组<span v-if="allManualGroups.length" class="card-count">{{ allManualGroups.length }}</span>
                <span v-if="snap.mode === 'direct' && manualGroups.length" class="tag sm">直连中</span>
              </h2>
              <button type="button" class="btn ghost sm" @click="store.go('proxies')">查看全部<Icon name="chevron-right" :size="14" /></button>
            </header>
            <p v-if="snap.mode === 'direct' && manualGroups.length" class="card-note muted small">当前为直连模式，新发起的连接不经过代理组</p>
            <p v-if="!manualGroups.length" class="empty-line muted">{{ snap.nodes_notice ?? '这份配置没有可手动选择的代理组' }}</p>
            <div v-else class="home-groups-grid" :class="{ single: manualGroups.length === 1 }">
              <button
                v-for="group in manualGroups"
                :key="group.name"
                type="button"
                class="group-row"
                :data-group="group.name"
                @click="store.go('proxies', group.name)"
              >
                <div class="group-tile-top">
                  <span class="group-row-icon"><GroupIcon :icon="group.icon" :type="group.group_type" :size="compact ? 22 : 20" /></span>
                  <span
                    v-if="nodeOf(group) && (nodeOf(group)!.delay_ms != null || nodeOf(group)!.failed)"
                    class="delay"
                    :class="delayTone(nodeOf(group)!.delay_ms, nodeOf(group)!.failed)"
                  >{{ delayText(nodeOf(group)!.delay_ms, nodeOf(group)!.failed) }}</span>
                  <Icon v-else name="chevron-right" :size="14" class="muted group-tile-arrow" />
                </div>
                <div class="group-row-text">
                  <span class="group-row-name">{{ group.name }}</span>
                  <span class="group-row-now">{{ group.now || '—' }}</span>
                </div>
              </button>
            </div>
          </section>
        </div>
      </div>
    </div>

    <Modal v-if="profileSheetOpen" title="切换配置" subtitle="点击立即启用，无需离开首页" @close="profileSheetOpen = false">
      <div class="option-list" data-testid="home-profile-sheet">
        <button
          v-for="item in orderedProfiles"
          :key="item.id"
          type="button"
          class="option-row profile-sheet-row"
          :class="{ active: item.current }"
          :data-testid="`sheet-profile-${item.id}`"
          @click="switchFromSheet(item)"
        >
          <span class="sub-icon sm"><Icon :name="item.kind === 'local' ? 'file' : 'link'" :size="16" /></span>
          <span class="profile-sheet-body">
            <span class="option-label">{{ item.name }}</span>
            <span class="muted small">
              {{ item.proxy_count ? `${item.proxy_count} 个节点` : item.kind === 'local' ? '本地配置' : '远程订阅' }}
              <template v-if="usagePercent(item.used, item.total) != null">
                · 已用 {{ Math.round(usagePercent(item.used, item.total)!) }}%
              </template>
            </span>
          </span>
          <Icon v-if="item.current" name="check" :size="18" class="option-check" />
        </button>
      </div>
      <template #footer>
        <button type="button" class="btn ghost" @click="manageFromSheet">管理配置</button>
        <button type="button" class="btn primary" @click="addFromSheet"><Icon name="plus" :size="15" />添加新配置</button>
      </template>
    </Modal>
  </div>
</template>
