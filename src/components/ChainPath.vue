<script setup lang="ts">
import { computed } from 'vue'
import Icon from './Icon.vue'

/**
 * A proxy chain in reading order: the group a rule or selector starts from first,
 * the server that actually carries the traffic last. Inline it keeps the server
 * readable and folds the middle hops into "+N"; steps lists every hop in full.
 */
const props = defineProps<{
  hops: readonly string[]
  variant?: 'inline' | 'steps'
  /** Style the exit like the connection table's outbound pill. */
  pill?: boolean
  /** In a narrow slot, fold the entry group into "+N" rather than a clipped stub. */
  fold?: boolean
}>()

const exit = computed(() => props.hops[props.hops.length - 1] ?? '')
const via = computed(() => (props.hops.length > 1 ? props.hops[0]! : ''))
const hidden = computed(() => Math.max(0, props.hops.length - 2))
const full = computed(() => props.hops.join(' → '))
</script>

<template>
  <ol v-if="variant === 'steps'" class="chain-steps" data-testid="chain-steps">
    <li v-for="(hop, index) in hops" :key="`${index}:${hop}`" :class="{ exit: index === hops.length - 1 }">
      <span class="chain-step-name">{{ hop }}</span>
      <span v-if="index === hops.length - 1 && hops.length > 1" class="chain-step-tag">出口</span>
    </li>
  </ol>
  <span v-else :class="fold ? 'chain-box' : 'chain-wrap'">
    <span class="chain" :title="full || undefined" data-testid="chain-path">
      <template v-if="via">
        <span class="chain-via">{{ via }}</span>
        <span v-if="hidden" class="chain-more mono" :aria-label="`经过另外 ${hidden} 个代理组`">+{{ hidden }}</span>
        <span v-if="fold" class="chain-count mono" aria-hidden="true">+{{ hops.length - 1 }}</span>
        <Icon name="chevron-right" :size="12" class="chain-sep" />
      </template>
      <span class="chain-exit" :class="{ 'outbound-pill': pill }" :data-policy="pill ? exit.toUpperCase() : undefined">{{ exit || '—' }}</span>
    </span>
  </span>
</template>
