<script setup lang="ts">
import { computed, ref } from 'vue'
import Icon from '../components/Icon.vue'
import Modal from '../components/Modal.vue'
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
import type { Mode } from '../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)
const profile = computed(() => store.current.value)

const MODES: { id: Mode; label: string; hint: string; icon: string }[] = [
  { id: 'rule', label: '规则', hint: '按配置中的规则分流', icon: 'route' },
  { id: 'global', label: '全局', hint: '全部流量走当前节点', icon: 'globe' },
  { id: 'direct', label: '直连', hint: '新连接都不经过代理', icon: 'zap' },
]

const status = computed(() => {
  if (store.connecting.value) return { word: snap.value.connected ? '断开中' : '连接中', tone: 'pending' }
  if (snap.value.connected) return { word: '已连接', tone: 'on' }
  return { word: '未连接', tone: 'off' }
})

const manualGroups = computed(() => snap.value.node_catalog.filter((group) => group.kind === 'manual').slice(0, 8))
const usage = computed(() => (profile.value ? usagePercent(profile.value.used, profile.value.total) : null))
const expireDays = computed(() => (profile.value?.expire ? daysLeft(profile.value.expire) : null))

function nodeOf(group: { now: string; nodes: { name: string; delay_ms: number | null; failed: boolean }[] }) {
  return group.nodes.find((node) => node.name === group.now)
}

// Android per-app exclusion
const appsOpen = ref(false)
const appQuery = ref('')
const apps = computed(() => {
  const needle = appQuery.value.trim().toLowerCase()
  const list = [...snap.value.installed].sort(
    (a, b) => Number(snap.value.excluded.includes(b.package_name)) - Number(snap.value.excluded.includes(a.package_name)),
  )
  if (!needle) return list
  return list.filter((app) => app.name.toLowerCase().includes(needle) || app.package_name.toLowerCase().includes(needle))
})
</script>

<template>
  <div class="page home">
    <div v-if="snap.failure" class="banner error" role="alert" data-testid="home-failure">
      <Icon name="alert" />
      <span class="grow">{{ snap.failure }}</span>
      <button type="button" class="btn ghost sm" @click="store.go('logs')">查看日志</button>
    </div>

    <section class="card hero" :class="status.tone" data-testid="hero">
      <button
        type="button"
        class="power"
        :class="status.tone"
        :disabled="store.connecting.value"
        :aria-label="!store.hasProfiles.value ? '添加配置' : snap.connected ? '断开' : '连接'"
        data-testid="power"
        @click="store.toggleConnection()"
      >
        <span v-if="store.connecting.value" class="spinner lg" />
        <Icon v-else :name="store.hasProfiles.value ? 'power' : 'plus'" :size="30" :stroke="2.2" />
      </button>
      <div class="hero-text">
        <h1 class="status-word" data-testid="status">{{ store.hasProfiles.value ? status.word : '欢迎使用 Billow' }}</h1>
        <p v-if="profile" class="hero-sub">
          <span class="hero-profile">{{ profile.name }}</span>
          <span v-if="snap.mixed_port" class="muted">· 端口 {{ snap.mixed_port }}</span>
        </p>
        <p v-else-if="!store.hasProfiles.value" class="hero-sub muted">添加一个订阅或本地配置即可开始</p>
        <p v-else class="hero-sub muted">选择一份配置后连接</p>
      </div>
      <div v-if="snap.connected" class="hero-rates mono" data-testid="rates">
        <div class="rate up"><Icon name="up" :size="14" /><span>{{ formatSpeed(snap.upload ?? 0) }}</span></div>
        <div class="rate down"><Icon name="down" :size="14" /><span>{{ formatSpeed(snap.download ?? 0) }}</span></div>
      </div>
      <button v-else-if="!store.hasProfiles.value" type="button" class="btn primary" @click="store.adding.value = true">
        <Icon name="plus" :size="16" /> 添加配置
      </button>
      <button v-else type="button" class="btn primary" :disabled="store.connecting.value" @click="store.toggleConnection()">
        连接
      </button>
    </section>

    <div v-if="store.hasProfiles.value" class="grid-2">
      <section class="card" data-testid="mode-card">
        <header class="card-head"><h2>出站模式</h2></header>
        <div class="mode-cards" role="radiogroup" aria-label="出站模式">
          <button
            v-for="mode in MODES"
            :key="mode.id"
            type="button"
            role="radio"
            class="mode-card"
            :class="{ active: snap.mode === mode.id }"
            :aria-checked="snap.mode === mode.id"
            :data-mode="mode.id"
            :disabled="store.busy.mode"
            @click="store.setMode(mode.id)"
          >
            <Icon :name="mode.icon" :size="20" />
            <strong>{{ mode.label }}</strong>
            <span>{{ mode.hint }}</span>
          </button>
        </div>
      </section>

      <section class="card" data-testid="takeover-card">
        <header class="card-head"><h2>网络接管</h2></header>
        <template v-if="!store.isAndroid.value">
          <div class="setting-row">
            <span class="row-icon"><Icon name="monitor" /></span>
            <div class="grow">
              <strong>系统代理</strong>
              <p class="muted small">浏览器和遵守系统设置的应用</p>
            </div>
            <Toggle :model-value="snap.system_proxy" :busy="store.busy.proxy" label="系统代理" data-testid="toggle-proxy" @update:model-value="store.setSystemProxy" />
          </div>
          <div class="setting-row">
            <span class="row-icon"><Icon name="shield" /></span>
            <div class="grow">
              <strong>TUN 模式</strong>
              <p class="muted small">接管全部流量，包括不支持代理的应用；需要授权</p>
            </div>
            <button type="button" class="icon-btn" title="TUN 设置" data-testid="tun-settings-link" @click="store.openSettings('tun')"><Icon name="sliders" :size="16" /></button>
            <Toggle :model-value="snap.tun" :busy="store.busy.tun" label="TUN 模式" data-testid="toggle-tun" @update:model-value="store.setTun" />
          </div>
        </template>
        <template v-else>
          <div class="setting-row">
            <span class="row-icon"><Icon name="shield" /></span>
            <div class="grow">
              <strong>VPN</strong>
              <p class="muted small">设备流量经由 Billow 处理</p>
            </div>
            <Toggle :model-value="snap.vpn" :busy="store.connecting.value" label="VPN" @update:model-value="store.toggleConnection()" />
          </div>
          <button type="button" class="setting-row link" data-testid="open-apps" @click="appsOpen = true">
            <span class="row-icon"><Icon name="apps" /></span>
            <div class="grow">
              <strong>分应用代理</strong>
              <p class="muted small">{{ snap.excluded.length ? `已排除 ${snap.excluded.length} 个应用` : '所有应用都经过 VPN' }}</p>
            </div>
            <Icon name="chevron-right" class="muted" />
          </button>
        </template>
      </section>

      <section class="card span-2 traffic-card" data-testid="traffic-card">
        <header class="card-head">
          <h2>实时流量</h2>
          <div class="legend">
            <span class="legend-item up">上传</span>
            <span class="legend-item down">下载</span>
          </div>
        </header>
        <TrafficChart :up="store.traffic.value.up" :down="store.traffic.value.down" :height="compact ? 110 : 150" />
        <div class="stats">
          <div class="stat">
            <span class="stat-label">上传速度</span>
            <span class="stat-value mono">{{ snap.connected ? formatSpeed(snap.upload ?? 0) : '—' }}</span>
          </div>
          <div class="stat">
            <span class="stat-label">下载速度</span>
            <span class="stat-value mono">{{ snap.connected ? formatSpeed(snap.download ?? 0) : '—' }}</span>
          </div>
          <div class="stat">
            <span class="stat-label">本次上传</span>
            <span class="stat-value mono">{{ formatBytes(snap.upload_total) }}</span>
          </div>
          <div class="stat">
            <span class="stat-label">本次下载</span>
            <span class="stat-value mono">{{ formatBytes(snap.download_total) }}</span>
          </div>
          <button type="button" class="stat link" @click="store.go('connections')">
            <span class="stat-label">活动连接</span>
            <span class="stat-value mono">{{ snap.connected ? snap.connections.length : '—' }}</span>
          </button>
        </div>
      </section>

      <section class="card" data-testid="groups-card">
        <header class="card-head">
          <h2>当前节点</h2>
          <button type="button" class="btn ghost sm" @click="store.go('proxies')">全部<Icon name="chevron-right" :size="14" /></button>
        </header>
        <p v-if="!manualGroups.length" class="empty-line muted">{{ snap.nodes_notice ?? '这份配置没有可手动选择的代理组' }}</p>
        <button
          v-for="group in manualGroups"
          :key="group.name"
          type="button"
          class="group-row"
          :data-group="group.name"
          @click="store.go('proxies', group.name)"
        >
          <span class="group-row-name">{{ group.name }}</span>
          <span class="group-row-now">{{ group.now || '—' }}</span>
          <span
            v-if="nodeOf(group) && (nodeOf(group)!.delay_ms != null || nodeOf(group)!.failed)"
            class="delay"
            :class="delayTone(nodeOf(group)!.delay_ms, nodeOf(group)!.failed)"
          >{{ delayText(nodeOf(group)!.delay_ms, nodeOf(group)!.failed) }}</span>
          <Icon name="chevron-right" :size="16" class="muted" />
        </button>
      </section>

      <section class="card" data-testid="profile-card">
        <header class="card-head">
          <h2>订阅</h2>
          <button type="button" class="btn ghost sm" @click="store.go('profiles')">管理<Icon name="chevron-right" :size="14" /></button>
        </header>
        <template v-if="profile">
          <div class="sub-head">
            <span class="sub-icon"><Icon :name="profile.kind === 'local' ? 'file' : 'link'" /></span>
            <div class="grow">
              <strong>{{ profile.name }}</strong>
              <p class="muted small">
                {{ profile.kind === 'local' ? '本地配置' : `更新于 ${formatRelative(profile.updated_ms ?? profile.last_success_ms)}` }}
                <template v-if="profile.proxy_count"> · {{ profile.proxy_count }} 个节点</template>
              </p>
            </div>
            <button
              v-if="profile.kind === 'subscription'"
              type="button"
              class="icon-btn"
              title="更新订阅"
              :disabled="store.busy[`update:${profile.id}`]"
              @click="store.update(profile.id)"
            >
              <Icon name="refresh" :class="{ spin: store.busy[`update:${profile.id}`] }" />
            </button>
          </div>
          <div v-if="usage != null" class="usage">
            <div class="usage-bar"><span :style="{ width: `${usage}%` }" :class="{ warn: usage > 85 }" /></div>
            <div class="usage-text small">
              <span class="mono">{{ formatBytes(profile.used) }} / {{ formatBytes(profile.total) }}</span>
              <span v-if="profile.expire" :class="{ 'text-warn': expireDays != null && expireDays <= 7 }">
                {{ expireDays != null && expireDays < 0 ? '已过期' : `${formatDate(profile.expire)} 到期 · 剩 ${expireDays} 天` }}
              </span>
            </div>
          </div>
          <p v-else class="muted small">订阅没有提供流量信息</p>
          <p v-if="profile.failure" class="field-error">{{ profile.failure }}</p>
        </template>
        <p v-else class="empty-line muted">还没有启用配置，去配置页选择一份</p>
      </section>
    </div>

    <Modal v-if="appsOpen" title="分应用代理" subtitle="打开开关的应用将不经过 VPN" @close="appsOpen = false">
      <div class="search">
        <Icon name="search" :size="16" />
        <input v-model="appQuery" type="search" placeholder="搜索应用" />
      </div>
      <p v-if="!apps.length" class="empty-line muted">{{ appQuery ? '没有匹配的应用' : '没有读取到已安装的应用' }}</p>
      <ul class="app-list">
        <li v-for="app in apps" :key="app.package_name" class="setting-row">
          <div class="grow">
            <strong>{{ app.name }}</strong>
            <p class="muted small mono">{{ app.package_name }}</p>
          </div>
          <Toggle
            :model-value="snap.excluded.includes(app.package_name)"
            :label="`排除 ${app.name}`"
            @update:model-value="(on) => (on ? store.exclude(app.package_name) : store.include(app.package_name))"
          />
        </li>
      </ul>
    </Modal>
  </div>
</template>
