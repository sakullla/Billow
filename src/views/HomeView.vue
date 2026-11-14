<script setup lang="ts">
import { computed, ref } from 'vue'
import {
  ACTION_ADD_PROFILE,
  ACTION_CONNECT,
  ACTION_DISCONNECT,
  EXCLUDE_OFF,
  EXCLUDE_ON,
  EXCLUDE_SEARCH,
  NODES_NOW,
  NODES_UNKNOWN,
  OUTBOUND_MODES,
  PROXY_HINT,
  RATE_DOWN,
  RATE_UP,
  STATUS_CONNECTED,
  STATUS_CONNECTING,
  TAKEOVER_PROXY,
  TAKEOVER_TUN,
  TAKEOVER_VPN,
  TUN_HINT,
  USAGE_EXPIRE,
  USAGE_TOTAL,
  USAGE_USED,
  VIEW_DIAGNOSTICS,
  VPN_EXCLUDE,
  HOME_STATUS,
  OPEN_DIAGNOSTICS,
  type OutboundMode,
} from '../copy'
import { formatExpire, showsExpire, showsUsage, type InstalledApp, type NodeGroup } from '../profile'

const props = defineProps<{
  failure: string | null
  profileName: string | null
  hasProfiles: boolean
  used: number | null
  total: number | null
  expire: number | null
  mode: OutboundMode | null
  upload: number | null
  download: number | null
  groups: NodeGroup[]
  arrangement: 'columns' | 'stack'
  platform: 'desktop' | 'android'
  connected: boolean
  connecting: boolean
  systemProxy: boolean
  tun: boolean
  vpn: boolean
  excluded: string[]
  installed: InstalledApp[]
}>()

const emit = defineEmits<{
  connect: []
  disconnect: []
  add: []
  mode: [mode: OutboundMode]
  'open-group': [name: string]
  'system-proxy': [enabled: boolean]
  tun: [enabled: boolean]
  exclude: [packageName: string]
  include: [packageName: string]
  diagnostics: []
}>()

const excluding = ref(false)
const query = ref('')

const statusLabel = computed(() => {
  if (props.connecting) return STATUS_CONNECTING
  if (props.connected) return STATUS_CONNECTED
  return HOME_STATUS
})

const modeHint = computed(() => OUTBOUND_MODES.find((item) => item.id === props.mode)?.hint ?? '')

const addingProfile = computed(() => !props.hasProfiles && !props.connected)

const primaryLabel = computed(() => {
  if (addingProfile.value) return ACTION_ADD_PROFILE
  return props.connected ? ACTION_DISCONNECT : ACTION_CONNECT
})

const filteredApps = computed(() => {
  const needle = query.value.trim()
  if (!needle) return props.installed
  return props.installed.filter((app) => app.name.includes(needle))
})

function onPrimary() {
  if (props.connecting) return
  if (addingProfile.value) {
    emit('add')
    return
  }
  if (props.connected) emit('disconnect')
  else emit('connect')
}
</script>

<template>
  <section class="screen" data-screen="home">
    <div class="home-board" data-testid="home-board" :data-arrangement="arrangement">
      <div class="home-main" data-testid="home-column-main">
        <h1 class="status-word" data-testid="link-status" :data-connected="connected ? 'true' : 'false'">
          {{ statusLabel }}
        </h1>
        <p v-if="hasProfiles && profileName" class="config-name" data-testid="home-profile">{{ profileName }}</p>
        <p v-if="hasProfiles && showsUsage(used, total)" data-testid="home-usage">
          {{ USAGE_USED }} {{ used }} {{ USAGE_TOTAL }} {{ total }}
        </p>
        <p v-if="hasProfiles && showsExpire(expire)" data-testid="home-expire">
          {{ USAGE_EXPIRE }} {{ formatExpire(expire ?? 0) }}
        </p>
        <p v-if="failure" class="notice failure-row" data-testid="home-failure" role="alert">
          <span>{{ failure }}</span>
          <button type="button" class="text-link" data-testid="open-diagnostics-failure" @click="emit('diagnostics')">
            {{ VIEW_DIAGNOSTICS }}
          </button>
        </p>
        <button
          type="button"
          class="btn-primary"
          :data-testid="addingProfile ? 'home-add' : 'session-connect'"
          :disabled="connecting"
          @click="onPrimary"
        >
          {{ primaryLabel }}
        </button>
        <template v-if="hasProfiles">
          <div
            class="segment"
            role="radiogroup"
            aria-label="出站模式"
            data-testid="mode-switch"
            :data-mode="mode ?? ''"
          >
            <button
              v-for="option in OUTBOUND_MODES"
              :key="option.id"
              type="button"
              class="choice"
              :class="{ selected: mode === option.id }"
              role="radio"
              :aria-checked="mode === option.id ? 'true' : 'false'"
              :data-mode="option.id"
              @click="emit('mode', option.id)"
            >
              {{ option.label }}
            </button>
          </div>
          <p v-if="modeHint" class="muted" data-testid="mode-hint">{{ modeHint }}</p>
          <div v-if="platform !== 'android'" data-testid="desktop-controls">
            <p
              data-testid="home-takeover"
              :data-system-proxy="systemProxy ? 'on' : 'off'"
              :data-tun="tun ? 'on' : 'off'"
              :data-vpn="vpn ? 'on' : 'off'"
            >
              {{ TAKEOVER_PROXY }}{{ systemProxy ? '开启' : '关闭' }}
              {{ TAKEOVER_TUN }}{{ tun ? '开启' : '关闭' }}
            </p>
            <button
              type="button"
              class="choice"
              :class="{ selected: systemProxy }"
              data-testid="system-proxy-toggle"
              :aria-pressed="systemProxy"
              @click="emit('system-proxy', !systemProxy)"
            >
              {{ TAKEOVER_PROXY }}{{ systemProxy ? '开启' : '关闭' }}
            </button>
            <p class="muted" data-testid="system-proxy-hint">{{ PROXY_HINT }}</p>
            <button
              type="button"
              class="choice"
              :class="{ selected: tun }"
              data-testid="tun-toggle"
              :aria-pressed="tun"
              @click="emit('tun', !tun)"
            >
              {{ TAKEOVER_TUN }}{{ tun ? '开启' : '关闭' }}
            </button>
            <p class="muted" data-testid="tun-hint">{{ TUN_HINT }}</p>
          </div>
          <div v-else data-testid="android-controls">
            <p
              data-testid="home-takeover"
              :data-system-proxy="systemProxy ? 'on' : 'off'"
              :data-tun="tun ? 'on' : 'off'"
              :data-vpn="vpn ? 'on' : 'off'"
            >
              {{ TAKEOVER_VPN }}{{ vpn ? '开启' : '关闭' }}
            </p>
            <button
              type="button"
              class="choice"
              :class="{ selected: vpn }"
              data-testid="vpn-toggle"
              :aria-pressed="vpn"
              @click="vpn ? emit('disconnect') : emit('connect')"
            >
              {{ TAKEOVER_VPN }}{{ vpn ? '开启' : '关闭' }}
            </button>
            <button type="button" class="btn" data-testid="open-exclusions" @click="excluding = !excluding">
              {{ VPN_EXCLUDE }}
            </button>
            <div v-if="excluding" data-testid="exclude-panel">
              <input v-model="query" type="search" data-testid="exclude-search" :placeholder="EXCLUDE_SEARCH" />
              <ul class="profile-list">
                <li
                  v-for="app in filteredApps"
                  :key="app.package_name"
                  data-testid="exclude-row"
                  :data-package="app.package_name"
                  :data-name="app.name"
                  :data-excluded="excluded.includes(app.package_name) ? 'true' : 'false'"
                >
                  <span>{{ app.name }}</span>
                  <span>{{ excluded.includes(app.package_name) ? EXCLUDE_ON : EXCLUDE_OFF }}</span>
                  <button
                    type="button"
                    @click="
                      excluded.includes(app.package_name)
                        ? emit('include', app.package_name)
                        : emit('exclude', app.package_name)
                    "
                  >
                    {{ excluded.includes(app.package_name) ? EXCLUDE_ON : EXCLUDE_OFF }}
                  </button>
                </li>
              </ul>
            </div>
          </div>
        </template>
      </div>
      <div v-if="hasProfiles" class="home-side" data-testid="home-column-groups">
        <button
          v-for="group in groups"
          :key="group.name"
          type="button"
          class="choice home-group"
          data-testid="home-group"
          :data-group="group.name"
          @click="emit('open-group', group.name)"
        >
          <span>{{ group.name }}</span>
          <span>{{ NODES_NOW }} {{ group.now || NODES_UNKNOWN }}</span>
        </button>
        <p v-if="connected && upload != null && download != null" class="rate-line" data-testid="home-rates">
          <span>{{ RATE_UP }} {{ upload }}</span>
          <span>{{ RATE_DOWN }} {{ download }}</span>
        </p>
      </div>
    </div>
    <button
      v-if="hasProfiles"
      type="button"
      class="text-link"
      data-testid="open-diagnostics"
      @click="emit('diagnostics')"
    >
      {{ OPEN_DIAGNOSTICS }}
    </button>
  </section>
</template>
