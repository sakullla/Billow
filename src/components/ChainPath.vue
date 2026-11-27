<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed } from 'vue'
import { splitNodePrefix } from '../lib/format'
import Icon from './Icon.vue'

/**
 * A proxy chain in reading order: the group a rule or selector starts from first,
 * any upstream transit server (`dialer-proxy` / `relay`), and the exit server last.
 * Inline keeps the server relay readable and folds policy groups first; steps lists
 * every hop with its role (`策略组` / `中转` / `出口`).
 */
const props = defineProps<{
  hops: readonly string[]
  /** Known policy group names so real transit servers are distinguished from groups. */
  groups?: ReadonlySet<string>
  variant?: 'inline' | 'steps'
  /** Style the exit like the connection table's outbound pill. */
  pill?: boolean
  /** In a narrow slot, fold policy groups first rather than clipping the server name. */
  fold?: boolean
}>()

const BUILTIN_POLICIES = new Set(['direct', 'reject', 'reject-drop', 'pass', 'compatible'])

function isGroupHop(hop: string): boolean {
  if (!props.groups || props.groups.size === 0) return true
  return props.groups.has(hop) || hop === 'GLOBAL'
}

function isRelayServer(hop: string, index: number): boolean {
  if (index >= props.hops.length - 1) return false
  if (!props.groups || props.groups.size === 0) return false
  if (isGroupHop(hop)) return false
  return !BUILTIN_POLICIES.has(hop.toLowerCase())
}

const exit = computed(() => props.hops[props.hops.length - 1] ?? '')
const exitParts = computed(() => splitNodePrefix(exit.value))
const relayServers = computed(() =>
  props.hops.filter((hop, index) => isRelayServer(hop, index)),
)
const lastRelay = computed(() => relayServers.value[relayServers.value.length - 1] ?? '')
const hasRelay = computed(() => Boolean(lastRelay.value))

/** Normal chain: `via` is hops[0]; Chained proxy: `via` is only a leading policy group, if any. */
const via = computed(() => {
  if (props.hops.length <= 1) return ''
  if (hasRelay.value) {
    return isGroupHop(props.hops[0]!) ? props.hops[0]! : ''
  }
  return props.hops[0]!
})

const hidden = computed(() => {
  if (hasRelay.value) {
    return Math.max(0, props.hops.length - (via.value ? 3 : 2))
  }
  return Math.max(0, props.hops.length - 2)
})

const full = computed(() => props.hops.join(' → '))

function stepRole(hop: string, index: number): { kind: 'exit' | 'relay' | 'group' | ''; label: string } {
  if (index === props.hops.length - 1) {
    return { kind: 'exit', label: props.hops.length > 1 ? tr('出口') : '' }
  }
  if (isRelayServer(hop, index)) {
    return { kind: 'relay', label: tr('中转') }
  }
  if (props.groups && props.groups.size > 0 && isGroupHop(hop)) {
    return { kind: 'group', label: tr('策略组') }
  }
  return { kind: '', label: '' }
}
</script>

<template>
  <ol v-if="variant === 'steps'" class="chain-steps" data-testid="chain-steps">
    <li
      v-for="(hop, index) in hops"
      :key="`${index}:${hop}`"
      :class="stepRole(hop, index).kind"
    >
      <span class="chain-step-name">{{ hop }}</span>
      <span
        v-if="stepRole(hop, index).label"
        class="chain-step-tag"
        :class="stepRole(hop, index).kind"
      >{{ stepRole(hop, index).label }}</span>
    </li>
  </ol>
  <span v-else :class="fold ? 'chain-box' : 'chain-wrap'">
    <span class="chain" :class="{ 'is-chained': hasRelay }" :title="full || undefined" data-testid="chain-path">
      <template v-if="via">
        <span class="chain-via">{{ via }}</span>
        <span v-if="hidden" class="chain-more mono" :aria-label="tr('经过另外 {0} 跳', { 0: hidden })">+{{ hidden }}</span>
        <span v-if="fold && !hasRelay" class="chain-count mono" aria-hidden="true">+{{ hops.length - 1 }}</span>
        <Icon name="chevron-right" :size="12" class="chain-sep" :class="{ 'chain-via-sep': hasRelay }" />
      </template>
      <template v-else-if="hasRelay && hidden">
        <span class="chain-more mono" :aria-label="tr('经过另外 {0} 跳', { 0: hidden })">+{{ hidden }}</span>
      </template>
      <template v-if="hasRelay">
        <span class="chain-relay-badge" data-testid="chain-relay-badge">{{ tr('链式') }}</span>
        <span class="chain-relay" data-testid="chain-relay">{{ lastRelay }}</span>
        <span class="chain-relay-arrow" aria-hidden="true">→</span>
      </template>
      <span class="chain-exit" :class="{ 'outbound-pill': pill }" :data-policy="pill ? exit.toUpperCase() : undefined"><template v-if="exitParts.prefix"><span class="chain-exit-prefix">{{ exitParts.prefix }}</span>{{ exitParts.rest }}</template><template v-else>{{ exit || '—' }}</template></span>
    </span>
  </span>
</template>
