<script setup lang="ts">
import { computed, ref } from 'vue'
import {
  ACTION_CONNECT,
  ACTION_DISCONNECT,
  EFFECTIVE_LABEL,
  EXCLUDE_OFF,
  EXCLUDE_ON,
  EXCLUDE_SEARCH,
  HOME_HINT,
  HOME_STATUS,
  PROXY_HINT,
  STATUS_CONNECTED,
  STATUS_CONNECTING,
  TAKEOVER_PROXY,
  TAKEOVER_TUN,
  TAKEOVER_VPN,
  TUN_HINT,
  USAGE_EXPIRE,
  USAGE_TOTAL,
  USAGE_USED,
  VPN_EXCLUDE,
  PRODUCT_NAME,
} from '../copy'
import { formatExpire, showsExpire, showsUsage } from '../profile'

const props = defineProps<{
  failure: string | null
  used: number | null
  total: number | null
  expire: number | null
  mixedPort: number | null
  platform: 'desktop' | 'android'
  connected: boolean
  connecting: boolean
  systemProxy: boolean
  tun: boolean
  vpn: boolean
  excluded: string[]
}>()

const emit = defineEmits<{
  connect: []
  disconnect: []
  'system-proxy': [enabled: boolean]
  tun: [enabled: boolean]
  exclude: [packageName: string]
  include: [packageName: string]
}>()

const excluding = ref(false)
const query = ref('')

const statusLabel = computed(() => {
  if (props.connecting) return STATUS_CONNECTING
  if (props.connected) return STATUS_CONNECTED
  return HOME_STATUS
})

const filteredExcluded = computed(() => {
  const needle = query.value.trim()
  if (!needle) return props.excluded
  return props.excluded.filter((name) => name.includes(needle))
})

const candidate = computed(() => {
  const needle = query.value.trim()
  if (!needle || props.excluded.includes(needle)) return ''
  return needle
})

function toggleConnection() {
  if (props.connecting) return
  if (props.connected) emit('disconnect')
  else emit('connect')
}
</script>

<template>
  <section class="screen" data-screen="home">
    <p class="product">{{ PRODUCT_NAME }}</p>
    <h1 class="status-word" data-testid="link-status" :data-connected="connected ? 'true' : 'false'">
      {{ statusLabel }}
    </h1>
    <article class="card">
      <p>{{ HOME_HINT }}</p>
      <p
        v-if="showsUsage(used, total)"
        data-testid="home-usage"
      >
        {{ USAGE_USED }} {{ used }} {{ USAGE_TOTAL }} {{ total }}
      </p>
      <p v-if="showsExpire(expire)" data-testid="home-expire">{{ USAGE_EXPIRE }} {{ formatExpire(expire ?? 0) }}</p>
      <p v-if="mixedPort != null" data-testid="home-effective">{{ EFFECTIVE_LABEL }} {{ mixedPort }}</p>
      <p v-if="failure" class="notice" data-testid="home-failure" role="alert">{{ failure }}</p>
      <p
        data-testid="home-takeover"
        :data-system-proxy="systemProxy ? 'on' : 'off'"
        :data-tun="tun ? 'on' : 'off'"
        :data-vpn="vpn ? 'on' : 'off'"
      >
        <template v-if="platform !== 'android'">
          {{ TAKEOVER_PROXY }}{{ systemProxy ? '开启' : '关闭' }}
          {{ TAKEOVER_TUN }}{{ tun ? '开启' : '关闭' }}
        </template>
        <template v-else>
          {{ TAKEOVER_VPN }}{{ vpn ? '开启' : '关闭' }}
        </template>
      </p>
      <button
        type="button"
        class="btn"
        data-testid="session-connect"
        :disabled="connecting"
        @click="toggleConnection"
      >
        {{ connected ? ACTION_DISCONNECT : ACTION_CONNECT }}
      </button>
      <div v-if="platform !== 'android'" data-testid="desktop-controls">
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
            <li v-if="candidate" data-testid="exclude-row" :data-package="candidate" data-excluded="false">
              <span>{{ candidate }}</span>
              <span>{{ EXCLUDE_OFF }}</span>
              <button type="button" @click="emit('exclude', candidate)">{{ EXCLUDE_OFF }}</button>
            </li>
            <li
              v-for="name in filteredExcluded"
              :key="name"
              data-testid="exclude-row"
              :data-package="name"
              data-excluded="true"
            >
              <span>{{ name }}</span>
              <span>{{ EXCLUDE_ON }}</span>
              <button type="button" @click="emit('include', name)">{{ EXCLUDE_ON }}</button>
            </li>
          </ul>
        </div>
      </div>
    </article>
  </section>
</template>
