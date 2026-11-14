<script setup lang="ts">
import { nextTick, onMounted, ref, watch } from 'vue'
import {
  ACTION_BACK,
  CONNECTION_SEARCH,
  CONNECTIONS_NONE,
  DIAGNOSTIC_CONNECTIONS,
  DIAGNOSTIC_LOGS,
  DIAGNOSTICS_TITLE,
  HOME_STATUS,
  LOG_FILTERS,
  type LogFilter,
} from '../copy'
import type { ConnectionRow, LogLine } from '../profile'

const props = defineProps<{
  connected: boolean
  connections: ConnectionRow[]
  connectionQuery: string
  logs: LogLine[]
  logFilter: LogFilter
}>()

const emit = defineEmits<{
  close: []
  query: [value: string]
  'log-filter': [value: LogFilter]
}>()

const segment = ref<'connections' | 'logs'>('connections')
const follow = ref(true)
const scroller = ref<HTMLElement | null>(null)

function levelLabel(level: LogLine['level']): string {
  return LOG_FILTERS.find((item) => item.id === level)?.label ?? level
}

function onQuery(event: Event) {
  emit('query', (event.target as HTMLInputElement).value)
}

function onScroll() {
  const el = scroller.value
  if (!el) return
  follow.value = el.scrollHeight - el.scrollTop - el.clientHeight < 16
}

async function stickToBottom() {
  if (segment.value !== 'logs' || !follow.value) return
  await nextTick()
  const el = scroller.value
  if (!el) return
  el.scrollTop = el.scrollHeight
}

watch(() => props.logs, () => {
  void stickToBottom()
})

watch(segment, () => {
  void stickToBottom()
})

onMounted(() => {
  void stickToBottom()
})
</script>

<template>
  <section class="screen" data-screen="diagnostics">
    <button type="button" class="text-link" data-testid="diagnostics-back" @click="emit('close')">
      {{ ACTION_BACK }}
    </button>
    <h1 class="page-title">{{ DIAGNOSTICS_TITLE }}</h1>
    <div class="segment" role="tablist" aria-label="诊断">
      <button
        type="button"
        class="choice"
        data-testid="diagnostic-tab-connections"
        :class="{ selected: segment === 'connections' }"
        :aria-selected="segment === 'connections'"
        @click="segment = 'connections'"
      >
        {{ DIAGNOSTIC_CONNECTIONS }}
      </button>
      <button
        type="button"
        class="choice"
        data-testid="diagnostic-tab-logs"
        :class="{ selected: segment === 'logs' }"
        :aria-selected="segment === 'logs'"
        @click="segment = 'logs'"
      >
        {{ DIAGNOSTIC_LOGS }}
      </button>
    </div>
    <div v-if="segment === 'connections'" data-testid="connection-panel">
      <input
        class="node-query"
        data-testid="connection-query"
        type="search"
        :value="connectionQuery"
        :aria-label="CONNECTION_SEARCH"
        :placeholder="CONNECTION_SEARCH"
        @input="onQuery"
      />
      <p v-if="!connected" class="card" data-testid="connection-empty">{{ HOME_STATUS }}</p>
      <p v-else-if="connections.length === 0" class="card" data-testid="connection-empty">{{ CONNECTIONS_NONE }}</p>
      <ul v-else class="profile-list">
        <li
          v-for="(row, index) in connections"
          :key="`${row.host}-${row.outbound}-${index}`"
          data-testid="connection-row"
          :data-host="row.host"
          :data-outbound="row.outbound"
        >
          <span class="connection-host">{{ row.host }}</span>
          <span class="connection-outbound">{{ row.outbound }}</span>
        </li>
      </ul>
    </div>
    <div v-else data-testid="log-panel">
      <div class="segment" role="radiogroup" aria-label="日志级别">
        <button
          v-for="option in LOG_FILTERS"
          :key="option.id"
          type="button"
          class="choice"
          data-testid="log-filter"
          :data-level="option.id"
          :class="{ selected: logFilter === option.id }"
          :aria-checked="logFilter === option.id"
          @click="emit('log-filter', option.id)"
        >
          {{ option.label }}
        </button>
      </div>
      <div
        ref="scroller"
        class="log-scroller"
        data-testid="log-scroller"
        :data-follow="follow ? 'true' : 'false'"
        @scroll="onScroll"
      >
        <p v-for="(line, index) in logs" :key="`${line.level}-${index}-${line.message}`" class="log-row">
          <span class="muted">{{ levelLabel(line.level) }}</span>
          <span class="log-line" data-testid="log-line" :data-level="line.level">{{ line.message }}</span>
        </p>
      </div>
    </div>
  </section>
</template>
