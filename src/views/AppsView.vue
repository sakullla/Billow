<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import Icon from '../components/Icon.vue'
import Menu, { type MenuItem } from '../components/Menu.vue'
import Segmented from '../components/Segmented.vue'
import { useStore } from '../lib/store'
import type { AppMode, InstalledApp } from '../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

const MODES: { id: AppMode; label: string }[] = [
  { id: 'exclude', label: tr('绕过选中应用') },
  { id: 'include', label: tr('仅代理选中应用') },
]

// ── Drafts: each mode keeps its own list; edits commit in one batch ──
const mode = ref<AppMode>(snap.value.app_mode)
const drafts = ref<Record<AppMode, Set<string>>>({
  exclude: new Set(snap.value.excluded),
  include: new Set(snap.value.included),
})
const selected = computed(() => drafts.value[mode.value])
const saving = ref<'idle' | 'pending' | 'saved'>('idle')
let commitTimer: ReturnType<typeof setTimeout> | null = null
let revision = 0
let pending = 0
let saves = Promise.resolve()

/** Reconnecting the VPN per tap would stall the phone; wait for a pause in edits. */
const COMMIT_DELAY = 700

function scheduleCommit(delay = COMMIT_DELAY) {
  revision++
  saving.value = 'pending'
  if (commitTimer) clearTimeout(commitTimer)
  commitTimer = setTimeout(() => void commit(), delay)
}

function commit() {
  if (commitTimer) clearTimeout(commitTimer)
  commitTimer = null
  const version = revision
  const savedMode = mode.value
  const packages = [...selected.value]
  pending++
  saves = saves.then(async () => {
    try {
      const result = await store.setAppRules(savedMode, packages)
      if (version === revision) saving.value = result ? 'saved' : 'idle'
    } finally {
      pending--
    }
  })
  return saves
}

function setMode(next: AppMode) {
  if (next === mode.value) return
  if (commitTimer) void commit()
  mode.value = next
  reorder()
  scheduleCommit(0)
}

function toggle(app: InstalledApp) {
  const next = new Set(selected.value)
  if (next.has(app.package_name)) next.delete(app.package_name)
  else next.add(app.package_name)
  drafts.value = { ...drafts.value, [mode.value]: next }
  scheduleCommit()
}

// ── Filtering and a stable order ──
const query = ref('')
const showSystem = ref(false)
const needle = computed(() => query.value.trim().toLowerCase())

/**
 * Selected apps lead the list, but only as of the last reorder (open, mode or
 * filter change). Re-sorting on every tap would move the row under the finger.
 */
const pinned = ref<Set<string>>(new Set(selected.value))
function reorder() {
  pinned.value = new Set(drafts.value[mode.value])
}
watch([needle, showSystem], reorder)

const visible = computed(() => {
  const term = needle.value
  return snap.value.installed
    .filter((app) => showSystem.value || !app.system || selected.value.has(app.package_name))
    .filter((app) => !term || app.name.toLowerCase().includes(term) || app.package_name.toLowerCase().includes(term))
    .sort((a, b) => Number(pinned.value.has(b.package_name)) - Number(pinned.value.has(a.package_name)))
})
// Mount only the page viewport so app icon textures and DOM do not grow with scrolling.
const listElement = ref<HTMLElement | null>(null)
const pageOffset = ref(0)
const pageHeight = ref(600)
const APP_ROW = 72
let pageScroller: HTMLElement | null = null
let scrollFrame = 0
const rowStart = computed(() => Math.min(Math.max(0, Math.floor(pageOffset.value / APP_ROW) - 4), Math.max(0, visible.value.length - 1)))
const rowEnd = computed(() => Math.min(visible.value.length, rowStart.value + Math.ceil(pageHeight.value / APP_ROW) + 8))
const rendered = computed(() => visible.value.slice(rowStart.value, rowEnd.value))
function measurePage() {
  scrollFrame = 0
  if (!listElement.value || !pageScroller) return
  pageOffset.value = Math.max(0, pageScroller.getBoundingClientRect().top - listElement.value.getBoundingClientRect().top)
  pageHeight.value = pageScroller.clientHeight || 600
}
function pageScroll() {
  if (!scrollFrame) scrollFrame = requestAnimationFrame(measurePage)
}
watch(visible, () => void nextTick(measurePage))
watch(listElement, (element) => {
  pageScroller?.removeEventListener('scroll', pageScroll)
  pageScroller = element?.closest<HTMLElement>('.main') ?? null
  pageScroller?.addEventListener('scroll', pageScroll, { passive: true })
  measurePage()
})
watch([needle, showSystem, mode], () => {
  pageOffset.value = 0
  if (pageScroller) pageScroller.scrollTop = 0
})
const systemCount = computed(() => snap.value.installed.filter((app) => app.system).length)

// ── Bulk actions ──
const menuOpen = ref(false)
const menuItems = computed<MenuItem[]>(() => [
  { id: 'all', label: needle.value ? tr('全选搜索结果') : tr('全选'), icon: 'check', disabled: !visible.value.length },
  { id: 'invert', get label() { return tr('反选') }, icon: 'refresh', disabled: !visible.value.length },
  { id: 'clear', get label() { return tr('清空选择') }, icon: 'x', disabled: !selected.value.size },
  { id: 'import', get label() { return tr('从剪贴板导入') }, icon: 'clipboard' },
  { id: 'export', get label() { return tr('复制包名列表') }, icon: 'copy', disabled: !selected.value.size },
])

async function onMenu(item: MenuItem) {
  menuOpen.value = false
  const next = new Set(selected.value)
  if (item.id === 'all') visible.value.forEach((app) => next.add(app.package_name))
  else if (item.id === 'invert') visible.value.forEach((app) => (next.has(app.package_name) ? next.delete(app.package_name) : next.add(app.package_name)))
  else if (item.id === 'clear') next.clear()
  else if (item.id === 'export') {
    try {
      await navigator.clipboard.writeText([...selected.value].join('\n'))
      store.toast(tr('已复制 {0} 个包名', { 0: selected.value.size }), 'success')
    } catch {
      store.toast(tr('无法写入剪贴板'), 'error')
    }
    return
  } else if (item.id === 'import') {
    try {
      const text = await navigator.clipboard.readText()
      // One package per line, or comma/space separated; anything that is not a package name is ignored.
      const names = text.split(/[\s,;]+/).filter((name) => /^[a-zA-Z][\w]*(\.[\w]+)+$/.test(name))
      if (!names.length) {
        store.toast(tr('剪贴板里没有应用包名'), 'error')
        return
      }
      names.forEach((name) => next.add(name))
      store.toast(tr('已导入 {0} 个应用', { 0: names.length }), 'success')
    } catch {
      store.toast(tr('无法读取剪贴板'), 'error')
      return
    }
  }
  drafts.value = { ...drafts.value, [mode.value]: next }
  reorder()
  scheduleCommit(0)
}

// ── Summary ──
const summary = computed(() => {
  const count = selected.value.size
  if (mode.value === 'include') return count ? tr('只有 {0} 个应用经过 VPN', { 0: count }) : tr('还没有选择应用，目前所有应用都经过 VPN')
  return count ? tr('{0} 个应用绕过 VPN，其余都经过 VPN', { 0: count }) : tr('所有应用都经过 VPN')
})
const hint = computed(() =>
  mode.value === 'include'
    ? tr('适合只想让少数应用（如浏览器、Telegram）走代理')
    : tr('适合银行、支付、游戏等需要直连的应用'),
)

// ── Icons: native bridge, loaded lazily as rows scroll into view ──
const icons = shallowRef<Record<string, string>>({})
const bridge = typeof window !== 'undefined' ? (window as Window & { BillowApps?: { icon(pkg: string): string } }).BillowApps : undefined
let disposed = false
let iconTimer: ReturnType<typeof setTimeout> | null = null
const iconQueue: string[] = []

function drainIcons() {
  iconTimer = null
  if (disposed || !bridge) return
  const pkg = iconQueue.shift()
  if (!pkg) return
  try {
    const url = bridge.icon(pkg)
    if (url) icons.value = { ...icons.value, [pkg]: url }
  } catch { /* letter avatar stays */ }
  if (iconQueue.length) iconTimer = setTimeout(drainIcons, 16)
}

function loadIcon(pkg: string) {
  if (disposed || !bridge || pkg in icons.value) return
  icons.value = { ...icons.value, [pkg]: '' }
  iconQueue.push(pkg)
  // One icon per turn; do not enqueue a timer for every visible/recycled row.
  if (iconTimer === null) iconTimer = setTimeout(drainIcons, 16)
}

function observe(element: unknown) {
  if (element instanceof HTMLElement && element.dataset.app) loadIcon(element.dataset.app)
}

watch(rendered, (rows) => {
  const keep = new Set(rows.map((row) => row.package_name))
  icons.value = Object.fromEntries(Object.entries(icons.value).filter(([pkg]) => keep.has(pkg)))
  for (let i = iconQueue.length - 1; i >= 0; i--) {
    if (!keep.has(iconQueue[i])) iconQueue.splice(i, 1)
  }
})

const AVATAR_HUES = [210, 260, 160, 20, 330, 190, 40]
function avatarHue(name: string): number {
  let hash = 0
  for (const char of name) hash = (hash * 31 + char.charCodeAt(0)) >>> 0
  return AVATAR_HUES[hash % AVATAR_HUES.length]
}

onMounted(() => {
  reorder()
  pageScroller = listElement.value?.closest<HTMLElement>('.main') ?? null
  pageScroller?.addEventListener('scroll', pageScroll, { passive: true })
  window.addEventListener('resize', pageScroll)
  measurePage()
})
onBeforeUnmount(() => {
  disposed = true
  pageScroller?.removeEventListener('scroll', pageScroll)
  window.removeEventListener('resize', pageScroll)
  if (scrollFrame) cancelAnimationFrame(scrollFrame)
  if (iconTimer !== null) clearTimeout(iconTimer)
  iconQueue.length = 0
  icons.value = {}
  // Leaving with a pending batch still saves it.
  if (commitTimer) {
    clearTimeout(commitTimer)
    void commit()
  }
})

// Another surface (or a restart) changed the rules: follow it unless edits are pending.
watch(
  [() => snap.value.app_mode, () => snap.value.excluded, () => snap.value.included],
  ([nextMode, excluded, included]) => {
    if (commitTimer || pending) return
    mode.value = nextMode
    drafts.value = { exclude: new Set(excluded), include: new Set(included) }
  },
)
</script>

<template>
  <div class="page apps">
    <header class="page-head">
      <div>
        <h1>{{ tr('应用访问控制') }}</h1>
        <p class="muted small" aria-live="polite" data-testid="apps-summary">{{ summary }}</p>
      </div>
      <span v-if="saving !== 'idle'" class="muted small apps-saving" aria-live="polite" data-testid="apps-saving">
        <span v-if="saving === 'pending'" class="spinner xs" aria-hidden="true" />
        <Icon v-else name="check" :size="13" />
        {{ saving === 'pending' ? (snap.vpn ? tr('正在应用') : tr('正在保存')) : tr('已保存') }}
      </span>
    </header>

    <section class="card apps-mode">
      <Segmented :model-value="mode" :options="MODES" :label="tr('访问控制模式')" data-testid="apps-mode" @update:model-value="setMode" />
      <p class="muted small">{{ hint }}{{ snap.vpn ? tr('；修改后 VPN 会短暂重连') : '' }}</p>
    </section>

    <div class="toolbar apps-toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" :placeholder="tr('搜索应用或包名')" data-page-search data-testid="apps-search" />
        <button v-if="query" type="button" class="icon-btn sm" :aria-label="tr('清空搜索')" @click="query = ''"><Icon name="x" :size="14" /></button>
      </div>
      <button
        v-if="systemCount"
        type="button"
        class="chip-btn"
        :class="{ active: showSystem }"
        :aria-pressed="showSystem"
        data-testid="apps-system"
        @click="showSystem = !showSystem"
      > {{ tr('系统应用') }} </button>
      <div class="menu-anchor">
        <button type="button" class="icon-btn options-btn" :aria-label="tr('批量操作')" aria-haspopup="menu" :aria-expanded="menuOpen" data-testid="apps-menu" @click="menuOpen = !menuOpen">
          <Icon name="more" />
        </button>
        <Menu v-if="menuOpen" :items="menuItems" :label="tr('批量操作')" @select="onMenu" @close="menuOpen = false" />
      </div>
    </div>

    <div v-if="!snap.installed.length" class="empty">
      <Icon name="apps" :size="40" :stroke="1.4" />
      <h3>{{ tr('没有读取到已安装的应用') }}</h3>
      <p class="muted">{{ tr('请在系统设置中允许 Billow 读取应用列表，然后重新打开此页。') }}</p>
    </div>
    <div v-else-if="!visible.length" class="empty small">
      <h3>{{ tr('没有匹配的应用') }}</h3>
      <button v-if="!showSystem && systemCount" type="button" class="btn ghost" @click="showSystem = true">{{ tr('包含系统应用') }}</button>
    </div>

    <ul v-else ref="listElement" class="card list-card app-list" data-testid="app-list">
      <li v-if="rowStart" aria-hidden="true" :style="{ height: `${rowStart * APP_ROW}px` }" />
      <li v-for="app in rendered" :key="app.package_name">
        <button
          :ref="observe"
          type="button"
          role="checkbox"
          class="app-row"
          :aria-checked="selected.has(app.package_name)"
          :data-app="app.package_name"
          @click="toggle(app)"
        >
          <img v-if="icons[app.package_name]" class="app-icon" :src="icons[app.package_name]" alt="" />
          <span v-else class="app-icon letter" :style="{ '--hue': avatarHue(app.name) }" aria-hidden="true">{{ app.name.slice(0, 1).toUpperCase() }}</span>
          <span class="app-text">
            <strong class="ellipsis">{{ app.name }}<span v-if="app.system" class="tag sm">{{ tr('系统') }}</span></strong>
            <span class="muted small mono ellipsis">{{ app.package_name }}</span>
          </span>
          <span class="check-box" aria-hidden="true"><Icon v-if="selected.has(app.package_name)" name="check" :size="14" :stroke="2.6" /></span>
        </button>
      </li>
      <li v-if="rowEnd < visible.length" aria-hidden="true" :style="{ height: `${(visible.length - rowEnd) * APP_ROW}px` }" />
    </ul>
  </div>
</template>
