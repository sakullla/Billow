<script setup lang="ts">
import { computed, nextTick, onMounted, ref, shallowRef, watch } from 'vue'
import Icon from '../components/Icon.vue'
import Segmented from '../components/Segmented.vue'
import { formatClock } from '../lib/format'
import { useStore } from '../lib/store'
import type { LogLevel, LogLine } from '../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

type Filter = 'all' | LogLevel
const FILTERS: { id: Filter; label: string }[] = [
  { id: 'all', label: '全部' },
  { id: 'debug', label: '调试' },
  { id: 'info', label: '信息' },
  { id: 'warning', label: '警告' },
  { id: 'error', label: '错误' },
]
const LABEL: Record<LogLevel, string> = { debug: 'DBG', info: 'INF', warning: 'WRN', error: 'ERR' }

const filter = ref<Filter>('all')
const query = ref('')
const paused = ref(false)
const frozen = shallowRef<LogLine[]>([])
const follow = ref(true)
const scroller = ref<HTMLElement | null>(null)

watch(paused, (on) => {
  if (on) frozen.value = snap.value.logs
})

const lines = computed(() => {
  const source = paused.value ? frozen.value : snap.value.logs
  const needle = query.value.trim().toLowerCase()
  return source.filter(
    (line) =>
      (filter.value === 'all' || line.level === filter.value) &&
      (!needle || line.message.toLowerCase().includes(needle)),
  )
})

const counts = computed(() => ({
  warning: snap.value.logs.filter((line) => line.level === 'warning').length,
  error: snap.value.logs.filter((line) => line.level === 'error').length,
}))

function onScroll() {
  const el = scroller.value
  if (!el) return
  follow.value = el.scrollHeight - el.scrollTop - el.clientHeight < 24
}

async function toBottom(force = false) {
  if (!force && !follow.value) return
  await nextTick()
  const el = scroller.value
  if (el) el.scrollTop = el.scrollHeight
  follow.value = true
}

watch(() => lines.value.length, () => void toBottom())
onMounted(() => void toBottom(true))

async function copyAll() {
  try {
    await navigator.clipboard.writeText(lines.value.map((line) => `${formatClock(line.time_ms)} [${line.level}] ${line.message}`).join('\n'))
    store.toast(`已复制 ${lines.value.length} 行日志`, 'success')
  } catch {
    store.toast('无法写入剪贴板', 'error')
  }
}
</script>

<template>
  <div class="page logs">
    <header class="page-head">
      <div>
        <h1>日志</h1>
        <p class="muted small">
          {{ snap.logs.length }} 条
          <template v-if="counts.warning"> · <span class="text-warn">{{ counts.warning }} 警告</span></template>
          <template v-if="counts.error"> · <span class="text-error">{{ counts.error }} 错误</span></template>
        </p>
      </div>
      <div class="head-actions">
        <button type="button" class="btn ghost sm" :class="{ active: paused }" @click="paused = !paused">
          <Icon :name="paused ? 'play' : 'pause'" :size="14" />{{ paused ? '继续' : '暂停' }}
        </button>
        <button type="button" class="icon-btn" title="复制日志" :disabled="!lines.length" @click="copyAll"><Icon name="copy" /></button>
        <button type="button" class="icon-btn" title="清空日志" :disabled="!snap.logs.length" @click="store.clearLogs()"><Icon name="trash" /></button>
      </div>
    </header>

    <div class="toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" placeholder="搜索日志" data-page-search />
      </div>
      <Segmented v-model="filter" :options="FILTERS" size="sm" label="日志级别" />
    </div>

    <div class="card log-card">
      <div ref="scroller" class="log-scroll" data-testid="log-scroll" @scroll="onScroll">
        <p v-if="!lines.length" class="empty-line muted">{{ snap.logs.length ? '没有匹配的日志' : '暂无日志，连接后内核输出会出现在这里' }}</p>
        <div v-for="(line, index) in lines" :key="index" class="log-line" :class="line.level">
          <span class="log-time mono">{{ formatClock(line.time_ms) }}</span>
          <span class="log-level mono">{{ LABEL[line.level] }}</span>
          <span class="log-msg mono">{{ line.message }}</span>
        </div>
      </div>
      <button v-if="!follow" type="button" class="jump" @click="toBottom(true)"><Icon name="down" :size="14" />最新</button>
    </div>
  </div>
</template>
