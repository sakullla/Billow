<script setup lang="ts">
import {
  EFFECTIVE_LABEL,
  HOME_HINT,
  HOME_STATUS,
  PRODUCT_NAME,
  TAKEOVER_PROXY,
  TAKEOVER_TUN,
  TAKEOVER_VPN,
  USAGE_EXPIRE,
  USAGE_TOTAL,
  USAGE_USED,
} from '../copy'
import { formatExpire, showsExpire, showsUsage } from '../profile'

defineProps<{
  failure: string | null
  used: number | null
  total: number | null
  expire: number | null
  mixedPort: number | null
  systemProxy: boolean
  tun: boolean
  vpn: boolean
}>()
</script>

<template>
  <section class="screen" data-screen="home">
    <p class="product">{{ PRODUCT_NAME }}</p>
    <h1 class="status-word">{{ HOME_STATUS }}</h1>
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
        {{ TAKEOVER_PROXY }}{{ systemProxy ? '开启' : '关闭' }}
        {{ TAKEOVER_TUN }}{{ tun ? '开启' : '关闭' }}
        {{ TAKEOVER_VPN }}{{ vpn ? '开启' : '关闭' }}
      </p>
    </article>
  </section>
</template>
