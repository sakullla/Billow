<script setup lang="ts">
import { computed, nextTick, onMounted, ref, shallowRef, watch } from 'vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import Modal from '../components/Modal.vue'
import Segmented from '../components/Segmented.vue'
import Toggle from '../components/Toggle.vue'
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
const pausedAt = ref<number | null>(null)
const frozen = shallowRef<LogLine[]>([])
const wrap = ref(true)
const follow = ref(true)
const confirmClear = ref(false)
const scroller = ref<HTMLElement | null>(null)

const lineKey = (line: LogLine) => `${line.time_ms}|${line.level}|${line.message}`

/** Pausing freezes the list and every count, while the store keeps buffering (R28). */
const source = computed(() => (paused.value ? frozen.value : snap.value.logs))

const needle = computed(() => query.value.trim().toLowerCase())
const isFiltered = computed(() => Boolean(needle.value) || filter.value !== 'all')

interface HighlightPart {
  text: string
  hit: boolean
}

function highlight(value: string): HighlightPart[] {
  const q = needle.value
  if (!q || !value) return [{ text: value, hit: false }]
  const lower = value.toLowerCase()
  const parts: HighlightPart[] = []
  let idx = 0
  let found = lower.indexOf(q)
  while (found >= 0) {
    if (found > idx) parts.push({ text: value.slice(idx, found), hit: false })
    parts.push({ text: value.slice(found, found + q.length), hit: true })
    idx = found + q.length
    found = lower.indexOf(q, idx)
  }
  if (idx < value.length) parts.push({ text: value.slice(idx), hit: false })
  return parts.length ? parts : [{ text: value, hit: false }]
}

/**
 * Filtered rows keep a content-stable key (`time|level|message` plus an
 * occurrence counter for duplicate lines). Trimming the front of the capped
 * buffer then leaves every surviving key intact, so v-memo only mounts the new
 * lines instead of rebuilding the table (R31).
 */
const entries = computed(() => {
  const q = needle.value
  const seen = new Map<string, number>()
  const result: { line: LogLine; key: string }[] = []
  for (const line of source.value) {
    const base = lineKey(line)
    const occurrence = seen.get(base) ?? 0
    seen.set(base, occurrence + 1)
    if (filter.value !== 'all' && line.level !== filter.value) continue
    if (q && !line.message.toLowerCase().includes(q)) continue
    result.push({ line, key: `${base}#${occurrence}` })
  }
  return result
})

const lines = computed(() => entries.value.map((entry) => entry.line))

const counts = computed(() => {
  const totals: Record<LogLevel, number> = { debug: 0, info: 0, warning: 0, error: 0 }
  for (const line of source.value) totals[line.level] += 1
  return totals
})

/** Level counts ride on the filter so pausing freezes them too (R28). */
const filterOptions = computed(() =>
  FILTERS.map((option) => ({
    ...option,
    label: `${option.label} ${option.id === 'all' ? source.value.length : counts.value[option.id]}`,
  })),
)

/** Lines buffered since the freeze, found from the frozen tail so a capped buffer still counts. */
const newCount = computed(() => {
  if (!paused.value || !pausedAt.value) return 0
  const live = snap.value.logs
  const tail = frozen.value.length ? lineKey(frozen.value[frozen.value.length - 1] as LogLine) : null
  if (tail) {
    const index = live.findIndex((line) => lineKey(line) === tail)
    if (index >= 0) return live.length - index - 1
  }
  return live.filter((line) => line.time_ms > (pausedAt.value ?? 0)).length
})

function pause() {
  frozen.value = snap.value.logs
  pausedAt.value = Date.now()
  paused.value = true
}

function resume() {
  paused.value = false
  pausedAt.value = null
  frozen.value = []
  if (follow.value) void toBottom(true)
}

function togglePause() {
  if (paused.value) resume()
  else pause()
}

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

// The count stays pinned at the 1000-line cap, so a length watcher goes silent
// there. Watching the row list itself re-pins follow-tail after every append or
// trim, while a user-scrolled view is left exactly where it is (R31).
watch(entries, () => void toBottom())
watch(paused, (on) => {
  if (!on) void toBottom()
})
onMounted(() => void toBottom(true))

function textOf(line: LogLine) {
  return `${formatClock(line.time_ms)} [${line.level}] ${line.message}`
}

async function copyLine(line: LogLine) {
  await store.copyText(textOf(line), '已复制这行日志')
}

async function copyFiltered() {
  if (!lines.value.length) return
  await store.copyText(lines.value.map(textOf).join('\n'), `已复制 ${lines.value.length} 行日志`)
}

async function exportLogs() {
  if (!lines.value.length) return
  try {
    const path = await store.backend.exportLogs(lines.value.map(textOf).join('\n'))
    store.toast(`已导出到 ${path}`, 'success')
  } catch (err) {
    store.toast(`导出失败：${err instanceof Error ? err.message : String(err)}`, 'error')
  }
}

async function clear() {
  confirmClear.value = false
  const result = await store.clearLogs()
  frozen.value = []
  pausedAt.value = paused.value ? Date.now() : null
  if (result) store.toast('日志已清空', 'success')
}

function resetFilters() {
  query.value = ''
  filter.value = 'all'
}

const conflictAction = computed<{ message: string; label: string; tab: 'kernel' | 'tun' } | null>(() => {
  if (snap.value.connected) return null
  for (let i = source.value.length - 1; i >= 0; i -= 1) {
    const line = source.value[i]!
    if (line.level !== 'error') continue
    if (line.message.includes('更换混合端口') || (line.message.includes('端口') && line.message.includes('占用'))) {
      return {
        message: '本地监听端口冲突导致内核未能启动，可前往内核设置更换混合代理端口后重新连接。',
        label: '更换混合端口',
        tab: 'kernel',
      }
    }
    if (line.message.includes('TUN 设置') || (line.message.includes('TUN') && line.message.includes('占用'))) {
      return {
        message: '虚拟网卡冲突导致内核未能启动，可前往 TUN 设置调整或关闭其他 VPN 后重试。',
        label: 'TUN 设置',
        tab: 'tun',
      }
    }
  }
  return null
})
</script>

<template>
  <div class="page logs">
    <header class="page-head">
      <div>
        <h1>日志</h1>
        <p class="muted small">
          <span data-testid="log-count">{{ source.length }} 条</span>
          <template v-if="isFiltered"> · 显示 {{ lines.length }} 条</template>
          · {{ counts.warning }} 警告
          · {{ counts.error }} 错误
          <template v-if="paused"> · 暂停于 {{ formatClock(pausedAt ?? 0) }}</template>
        </p>
        <p v-if="paused" class="muted small log-status" role="status" aria-live="polite" data-testid="log-paused">
          已暂停，新增 <strong data-testid="log-new">{{ newCount }}</strong> 条日志；<button type="button" class="link-btn" data-testid="log-resume-inline" @click="resume()">继续</button>后追平。
        </p>
      </div>
      <div class="head-actions">
        <button
          type="button"
          class="btn ghost sm"
          :class="{ active: paused }"
          :aria-pressed="paused"
          data-testid="pause-logs"
          @click="togglePause"
        >
          <Icon :name="paused ? 'play' : 'pause'" :size="14" />{{ paused ? '继续' : '暂停' }}
        </button>
        <label class="wrap-field small muted" data-testid="wrap-field">
          <Toggle v-model="wrap" label="自动换行" />
          自动换行
        </label>
        <button
          type="button"
          class="btn ghost sm"
          :disabled="!lines.length"
          :title="`复制当前 ${lines.length} 行日志`"
          data-testid="copy-logs"
          @click="copyFiltered"
        >
          <Icon name="copy" :size="15" />复制
        </button>
        <button
          type="button"
          class="btn ghost sm"
          :disabled="!lines.length"
          data-testid="export-logs"
          @click="exportLogs"
        >
          <Icon name="download" :size="15" />导出
        </button>
        <button
          type="button"
          class="btn ghost sm danger-text"
          :disabled="!snap.logs.length"
          data-testid="clear-logs"
          @click="confirmClear = true"
        >
          <Icon name="trash" :size="15" />清空
        </button>
      </div>
    </header>

    <div class="toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" placeholder="搜索日志" data-page-search />
        <kbd v-if="!compact && !query" class="search-kbd" aria-hidden="true">/</kbd>
        <button
          v-if="query"
          type="button"
          class="icon-btn sm"
          aria-label="清空搜索"
          data-testid="clear-log-search"
          @click="query = ''"
        >
          <Icon name="x" :size="14" />
        </button>
      </div>
      <Segmented v-model="filter" :options="filterOptions" size="sm" label="日志级别" />
    </div>

    <div v-if="conflictAction" class="banner error log-conflict" role="alert" data-testid="log-conflict">
      <Icon name="alert" :size="16" />
      <span class="grow small">{{ conflictAction.message }}</span>
      <button
        type="button"
        class="btn ghost sm"
        data-testid="logs-open-settings"
        @click="store.openSettings(conflictAction.tab)"
      >
        <Icon name="sliders" :size="14" />{{ conflictAction.label }}
      </button>
    </div>

    <div class="card log-card" :class="{ paused }">
      <div
        ref="scroller"
        class="log-scroll"
        :class="{ 'no-wrap': !wrap }"
        data-testid="log-scroll"
        role="region"
        aria-label="日志内容"
        tabindex="0"
        @scroll="onScroll"
      >
        <EmptyState
          v-if="!lines.length"
          compact
          :variant="source.length ? 'no-match' : 'no-data'"
          :icon="source.length ? undefined : 'terminal'"
          :title="source.length ? '没有匹配的日志' : '暂无日志'"
          :description="source.length ? '换一个关键词或级别，或清空当前筛选。' : '连接后内核输出会出现在这里。'"
        >
          <template v-if="source.length" #action>
            <button type="button" class="btn ghost sm" data-testid="clear-log-filter" @click="resetFilters">清空筛选</button>
          </template>
        </EmptyState>
        <div
          v-for="entry in entries"
          :key="entry.key"
          v-memo="[entry.line.time_ms, entry.line.level, entry.line.message, needle]"
          class="log-line"
          :class="entry.line.level"
          :data-log-line="lineKey(entry.line)"
          :data-log-key="entry.key"
        >
          <span class="log-time mono">{{ formatClock(entry.line.time_ms) }}</span>
          <span class="log-level mono">{{ LABEL[entry.line.level] }}</span>
          <span class="log-msg mono">
            <template v-for="(part, partIdx) in highlight(entry.line.message)" :key="partIdx">
              <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
            </template>
          </span>
          <button
            type="button"
            class="icon-btn sm log-copy"
            :aria-label="`复制 ${formatClock(entry.line.time_ms)} 的这行日志`"
            title="复制这行"
            data-testid="copy-log-line"
            @click="copyLine(entry.line)"
          >
            <Icon name="copy" :size="13" />
          </button>
        </div>
      </div>
      <button v-if="!follow" type="button" class="jump" data-testid="log-jump" @click="toBottom(true)">
        <Icon name="down" :size="14" />最新
      </button>
    </div>

    <Modal v-if="confirmClear" title="清空日志" @close="confirmClear = false">
      <p class="small">将清空当前 {{ snap.logs.length }} 条日志，操作无法撤销。</p>
      <template #footer>
        <button type="button" class="btn ghost" data-testid="cancel-clear-logs" @click="confirmClear = false">取消</button>
        <button type="button" class="btn danger" data-testid="confirm-clear-logs" @click="clear">清空日志</button>
      </template>
    </Modal>
  </div>
</template>
