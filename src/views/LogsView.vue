<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed, nextTick, onMounted, ref, shallowRef, watch } from 'vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import Menu, { type MenuItem } from '../components/Menu.vue'
import Modal from '../components/Modal.vue'
import Segmented from '../components/Segmented.vue'
import Toggle from '../components/Toggle.vue'
import { formatClock } from '../lib/format'
import { highlightTokens, matchesTokens, splitQueryTokens } from '../lib/search'
import { useStore } from '../lib/store'
import type { LogLevel, LogLine } from '../lib/types'

const props = defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

type Filter = 'all' | LogLevel
const FILTERS: { id: Filter; label: string }[] = [
  { id: 'all', get label() { return tr('全部') } },
  { id: 'debug', get label() { return tr('调试') } },
  { id: 'info', get label() { return tr('信息') } },
  { id: 'warning', get label() { return tr('警告') } },
  { id: 'error', get label() { return tr('错误') } },
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

/** Phones keep pause in reach and fold the rarer actions into one menu so the head stays one row. */
const moreOpen = ref(false)
const moreItems = computed<MenuItem[]>(() => [
  { id: 'wrap', label: wrap.value ? tr('关闭自动换行') : tr('开启自动换行'), icon: 'list' },
  { id: 'copy', label: tr('复制 {0} 行', { 0: lines.value.length }), icon: 'copy', disabled: !lines.value.length, reason: tr('没有日志') },
  { id: 'export', get label() { return tr('导出日志') }, icon: 'download', disabled: !lines.value.length, reason: tr('没有日志') },
  { id: 'clear', get label() { return tr('清空日志') }, icon: 'trash', danger: true, disabled: !snap.value.logs.length, reason: tr('没有日志') },
])
function onMore(item: MenuItem) {
  moreOpen.value = false
  if (item.id === 'wrap') wrap.value = !wrap.value
  else if (item.id === 'copy') void copyFiltered()
  else if (item.id === 'export') void exportLogs()
  else if (item.id === 'clear') confirmClear.value = true
}

const lineKey = (line: LogLine) => `${line.time_ms}|${line.level}|${line.message}`

/** Pausing freezes the list and every count, while the store keeps buffering (R28). */
const source = computed(() => (paused.value ? frozen.value : snap.value.logs))

const needle = computed(() => query.value.trim().toLowerCase())
const queryTokens = computed(() => splitQueryTokens(query.value))
const isFiltered = computed(() => Boolean(needle.value) || filter.value !== 'all')

function highlight(value: string) {
  return highlightTokens(value, query.value)
}

/**
 * Filtered rows keep a content-stable key (`time|level|message` plus an
 * occurrence counter for duplicate lines). Trimming the front of the capped
 * buffer then leaves every surviving key intact, so v-memo only mounts the new
 * lines instead of rebuilding the table (R31).
 */
const entries = computed(() => {
  const tokens = queryTokens.value
  const seen = new Map<string, number>()
  const result: { line: LogLine; key: string }[] = []
  for (const line of source.value) {
    const base = lineKey(line)
    const occurrence = seen.get(base) ?? 0
    seen.set(base, occurrence + 1)
    if (filter.value !== 'all' && line.level !== filter.value) continue
    if (tokens.length && !matchesTokens(`${line.level} ${LABEL[line.level]} ${line.message}`, tokens)) continue
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
  await store.copyText(textOf(line), tr('已复制这行日志'))
}

async function copyFiltered() {
  if (!lines.value.length) return
  await store.copyText(lines.value.map(textOf).join('\n'), tr('已复制 {0} 行日志', { 0: lines.value.length }))
}

async function exportLogs() {
  if (!lines.value.length) return
  try {
    const path = await store.backend.exportLogs(lines.value.map(textOf).join('\n'))
    store.toast(tr('已导出到 {0}', { 0: path }), 'success')
  } catch (err) {
    store.toast(tr('导出失败：{0}', { 0: err instanceof Error ? err.message : String(err) }), 'error')
  }
}

async function clear() {
  confirmClear.value = false
  const result = await store.clearLogs()
  frozen.value = []
  pausedAt.value = paused.value ? Date.now() : null
  if (result) store.toast(tr('日志已清空'), 'success')
}

function resetFilters() {
  query.value = ''
  filter.value = 'all'
}

const conflictAction = computed<{ message: string; label: string; tab: 'network' | 'tun'; focus?: string } | null>(() => {
  if (snap.value.connected) return null
  for (let i = source.value.length - 1; i >= 0; i -= 1) {
    const line = source.value[i]!
    if (line.level !== 'error') continue
    if (line.hint === 'port') {
      const labels = {
        mixed: '混合代理端口',
        http: 'HTTP 端口',
        socks: 'SOCKS 端口',
        redir: 'redir 端口',
        tproxy: 'tproxy 端口',
      } as const
      const kind = tr(labels[line.hint_kind ?? 'mixed'])
      return {
        message: tr('本地监听端口冲突导致内核未能启动，可前往网络设置更换{0}后重新连接。', { 0: kind }),
        label: tr('更换{0}', { 0: kind }),
        tab: 'network',
        focus: line.hint_kind && line.hint_kind !== 'mixed' ? 'extra-ports' : 'mixed-port',
      }
    }
    if (line.hint === 'tun') {
      return {
        message: tr('虚拟网卡冲突导致内核未能启动，可前往 TUN 设置调整或关闭其他 VPN 后重试。'),
        get label() { return tr('TUN 设置') },
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
        <h1>{{ tr('日志') }}</h1>
        <p class="muted small">
          <span data-testid="log-count">{{ source.length }} {{ tr('条') }}</span>
          <template v-if="isFiltered"> {{ tr('· 显示') }} {{ lines.length }} {{ tr('条') }}</template>
          · {{ counts.warning }} {{ tr('警告 ·') }} {{ counts.error }} {{ tr('错误') }} <template v-if="paused"> {{ tr('· 暂停于') }} {{ formatClock(pausedAt ?? 0) }}</template>
        </p>
        <p v-if="paused" class="muted small log-status" role="status" aria-live="polite" data-testid="log-paused"> {{ tr('已暂停，新增') }} <strong data-testid="log-new">{{ newCount }}</strong> {{ tr('条日志；') }}<button type="button" class="link-btn" data-testid="log-resume-inline" @click="resume()">{{ tr('继续') }}</button>{{ tr('后追平。') }} </p>
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
          <Icon :name="paused ? 'play' : 'pause'" :size="14" />{{ paused ? tr('继续') : tr('暂停') }}
        </button>
        <div v-if="props.compact" class="menu-anchor">
          <button
            type="button"
            class="icon-btn"
            :aria-label="tr('更多日志操作')"
            aria-haspopup="menu"
            :aria-expanded="moreOpen"
            data-testid="log-more"
            @click="moreOpen = !moreOpen"
          >
            <Icon name="more" />
          </button>
          <Menu :open="moreOpen" :items="moreItems" :label="tr('日志操作')" @select="onMore" @close="moreOpen = false" />
        </div>
        <template v-else>
          <label class="wrap-field small muted" data-testid="wrap-field">
            <Toggle v-model="wrap" :label="tr('自动换行')" /> {{ tr('自动换行') }} </label>
          <button
            type="button"
            class="btn ghost sm"
            :disabled="!lines.length"
            :title="tr('复制当前 {0} 行日志', { 0: lines.length })"
            data-testid="copy-logs"
            @click="copyFiltered"
          >
            <Icon name="copy" :size="15" />{{ tr('复制') }} </button>
          <button
            type="button"
            class="btn ghost sm"
            :disabled="!lines.length"
            data-testid="export-logs"
            @click="exportLogs"
          >
            <Icon name="download" :size="15" />{{ tr('导出') }} </button>
          <button
            type="button"
            class="btn ghost sm danger-text"
            :disabled="!snap.logs.length"
            data-testid="clear-logs"
            @click="confirmClear = true"
          >
            <Icon name="trash" :size="15" />{{ tr('清空') }} </button>
        </template>
      </div>
    </header>

    <div class="toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" :placeholder="tr('搜索日志')" data-page-search />
        <kbd v-if="!compact && !query" class="search-kbd" aria-hidden="true">/</kbd>
        <button
          v-if="query"
          type="button"
          class="icon-btn sm"
          :aria-label="tr('清空搜索')"
          data-testid="clear-log-search"
          @click="query = ''"
        >
          <Icon name="x" :size="14" />
        </button>
      </div>
      <Segmented v-model="filter" :options="filterOptions" size="sm" :label="tr('日志级别')" />
      <button v-if="isFiltered" type="button" class="btn ghost sm" data-testid="reset-log-toolbar" @click="resetFilters"> {{ tr('重置') }} </button>
    </div>

    <div v-if="conflictAction" class="banner error log-conflict" role="alert" data-testid="log-conflict">
      <Icon name="alert" :size="16" />
      <span class="grow small">{{ conflictAction.message }}</span>
      <button
        type="button"
        class="btn ghost sm"
        data-testid="logs-open-settings"
        @click="store.openSettings(conflictAction.tab, conflictAction.focus)"
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
        :aria-label="tr('日志内容')"
        tabindex="0"
        @scroll="onScroll"
      >
        <EmptyState
          v-if="!lines.length"
          compact
          :variant="source.length ? 'no-match' : 'no-data'"
          :icon="source.length ? undefined : 'terminal'"
          :title="source.length ? tr('没有匹配的日志') : tr('暂无日志')"
          :description="source.length ? tr('换一个关键词或级别，或清空当前筛选。') : tr('连接后内核输出会出现在这里。')"
        >
          <template v-if="source.length" #action>
            <button type="button" class="btn ghost sm" data-testid="clear-log-filter" @click="resetFilters">{{ tr('清空筛选') }}</button>
          </template>
        </EmptyState>
        <div
          v-for="entry in entries"
          :key="entry.key"
          v-memo="[entry.line.time_ms, entry.line.level, entry.line.message, needle, filter]"
          class="log-line"
          :class="entry.line.level"
          :data-log-line="lineKey(entry.line)"
          :data-log-key="entry.key"
        >
          <span class="log-time mono">{{ formatClock(entry.line.time_ms) }}</span>
          <button
            type="button"
            class="log-level mono"
            :title="filter === entry.line.level ? tr('点击恢复全部级别') : tr('仅看 {0} 级别日志', { 0: LABEL[entry.line.level] })"
            data-testid="log-level-badge"
            @click="filter = filter === entry.line.level ? 'all' : entry.line.level"
          >{{ LABEL[entry.line.level] }}</button>
          <span class="log-msg mono">
            <template v-for="(part, partIdx) in highlight(entry.line.message)" :key="partIdx">
              <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
            </template>
          </span>
          <button
            type="button"
            class="icon-btn sm log-copy"
            :aria-label="tr('复制 {0} 的这行日志', { 0: formatClock(entry.line.time_ms) })"
            :title="tr('复制这行')"
            data-testid="copy-log-line"
            @click="copyLine(entry.line)"
          >
            <Icon name="copy" :size="13" />
          </button>
        </div>
      </div>
      <Transition name="menu-pop">
        <button v-if="!follow" type="button" class="jump" data-testid="log-jump" @click="toBottom(true)">
          <Icon name="down" :size="14" />{{ tr('最新') }} </button>
      </Transition>
    </div>

    <Modal :open="confirmClear" :title="tr('清空日志')" @close="confirmClear = false">
      <p class="small">{{ tr('将清空当前') }} {{ snap.logs.length }} {{ tr('条日志，操作无法撤销。') }}</p>
      <template #footer>
        <button type="button" class="btn ghost" data-testid="cancel-clear-logs" @click="confirmClear = false">{{ tr('取消') }}</button>
        <button type="button" class="btn danger" data-testid="confirm-clear-logs" @click="clear">{{ tr('清空日志') }}</button>
      </template>
    </Modal>
  </div>
</template>
