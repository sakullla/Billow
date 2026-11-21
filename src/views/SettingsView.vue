<script setup lang="ts">
import { computed, inject, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import Icon from '../components/Icon.vue'
import TrafficStatsDialog from '../components/TrafficStatsDialog.vue'
import {
  categoryOf,
  paneOf,
  searchSettings,
  visibleCategories,
  visiblePanes,
  type CategoryId,
  type SettingsCategory,
  type SettingsEntry,
} from '../lib/settings/catalog'
import { tr } from '../lib/i18n'
import { useStore } from '../lib/store'
import PaneStack from './settings/PaneStack.vue'

/**
 * Settings shell (v3). Desktop: a category rail with search beside the pane.
 * Phone: a category list that drills into one pane at a time. Each pane owns
 * its own state; toggles and choices apply at once, lists and multi-field
 * forms open an editor dialog with explicit 保存 / 取消.
 */
const props = defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

const platform = computed(() => ({
  android: store.isAndroid.value,
  windows:
    store.app.value?.platform === 'windows' || (typeof navigator !== 'undefined' && /Windows/i.test(navigator.userAgent)),
  linux: store.isLinux.value,
  mac: store.isMac.value,
}))
const categories = computed(() => visibleCategories(platform.value))

/** Phone root is the category list; desktop always shows a pane. */
const atRoot = computed(() => props.compact && store.settingsTab.value === 'home')
const active = computed<SettingsCategory>(() => categoryOf(store.settingsTab.value))
const activePanes = computed(() => visiblePanes(active.value, platform.value).map((item) => item.id))
/** Pane unfolded on a multi-pane page: the deep-linked one, otherwise the first. */
const openPane = computed<CategoryId | undefined>(() => {
  const tab = store.settingsTab.value
  const list = activePanes.value
  return tab !== active.value.id && list.includes(tab as CategoryId) ? (tab as CategoryId) : list[0]
})

function openCategory(id: CategoryId) {
  query.value = ''
  store.settingsFocus.value = null
  store.settingsTab.value = id
  void nextTick(scrollToTop)
}

/** One-word state per category on the phone list, so the list answers "what is on?". */
function summary(id: CategoryId): string {
  const s = snap.value
  switch (id) {
    case 'general':
      return store.theme.value === 'dark' ? tr('深色') : store.theme.value === 'light' ? tr('浅色') : tr('自动')
    case 'network':
      return `:${s.mixed_port ?? s.settings.mixed_port ?? s.config_values.mixed_port ?? 7890}`
    case 'kernel':
      return store.kernel.value.ready ? (store.kernel.value.version ?? tr('已安装')) : tr('未安装')
    case 'backup':
      return store.app.value?.version ? `v${store.app.value.version}` : ''
    default:
      return ''
  }
}

const appSummary = computed(() => {
  const s = snap.value
  if (s.app_mode === 'include' && s.included.length) return tr('仅 {0} 个应用', { 0: s.included.length })
  return s.excluded.length ? tr('绕过 {0} 个', { 0: s.excluded.length }) : tr('全部应用')
})

// ── Search: every row is indexed, a result jumps to the row and highlights it.
const query = ref('')
const results = computed(() => searchSettings(query.value, platform.value))
const searching = computed(() => query.value.trim().length > 0)
/** Search results group by pane; a page with several panes names both. */
function resultTitle(tab: CategoryId): string {
  const category = categoryOf(tab)
  return category.panes.length > 1 ? `${category.label()} · ${paneOf(tab).label()}` : category.label()
}
const resultGroups = computed(() => {
  const groups: { id: CategoryId; title: string; entries: SettingsEntry[] }[] = []
  for (const entry of results.value) {
    let group = groups.find((item) => item.id === entry.tab)
    if (!group) {
      group = { id: entry.tab, title: resultTitle(entry.tab), entries: [] }
      groups.push(group)
    }
    group.entries.push(entry)
  }
  return groups
})
function pick(entry: SettingsEntry) {
  query.value = ''
  store.settingsTab.value = entry.tab
  store.settingsFocus.value = entry.id
}
function onSearchKey(event: KeyboardEvent) {
  if (event.key === 'Enter' && results.value[0]) {
    event.preventDefault()
    pick(results.value[0])
  } else if (event.key === 'Escape' && query.value) {
    event.preventDefault()
    event.stopPropagation()
    query.value = ''
  }
}

const content = ref<HTMLElement | null>(null)

// Narrow windows fold the rail into a horizontal strip: let the mouse wheel scroll
// it sideways and keep the active category visible.
const navEl = ref<HTMLElement | null>(null)
function onNavWheel(event: WheelEvent) {
  const el = navEl.value
  if (!el || el.scrollWidth <= el.clientWidth || Math.abs(event.deltaX) >= Math.abs(event.deltaY)) return
  el.scrollLeft += event.deltaY
  event.preventDefault()
}
watch(
  () => active.value.id,
  () => void nextTick(() => navEl.value?.querySelector<HTMLElement>('.settings-nav-item.active')?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' })),
  { flush: 'post' },
)

function scrollToTop() {
  const main = document.querySelector('.main')
  if (main) main.scrollTop = 0
}

let flashTimer: ReturnType<typeof setTimeout> | undefined
/** Scroll a row into view, unfolding its group first, and flash it once. */
async function revealSetting(id: string) {
  await nextTick()
  await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()))
  const target = content.value?.querySelector<HTMLElement>(`[data-setting="${CSS.escape(id)}"]`)
  if (!target) return
  const fold = target.closest('details')
  if (fold && !fold.open) fold.open = true
  target.scrollIntoView?.({ block: 'center', behavior: 'smooth' })
  target.classList.remove('srow-flash')
  void target.offsetWidth
  target.classList.add('srow-flash')
  clearTimeout(flashTimer)
  flashTimer = setTimeout(() => target.classList.remove('srow-flash'), 1800)
  store.settingsFocus.value = null
}
watch(
  () => [store.settingsFocus.value, store.settingsTab.value] as const,
  ([focus]) => {
    if (focus) void revealSetting(focus)
  },
  { immediate: true },
)
onBeforeUnmount(() => clearTimeout(flashTimer))

/** Phone sub-pages go back through the app history when possible (App provides it). */
const settingsBack = inject<() => void>('settingsBack', () => (store.settingsTab.value = 'home'))
</script>

<template>
  <!-- ───────── Phone: category list ───────── -->
  <div v-if="compact" class="page settings settings-phone" :class="{ 'settings-root': atRoot }">
    <template v-if="atRoot">
      <header class="page-head settings-phone-head">
        <div>
          <h1>{{ tr('设置') }}</h1>
          <p class="muted small">Billow {{ store.app.value?.version ?? '' }}<template v-if="store.kernel.value.version"> · Mihomo {{ store.kernel.value.version }}</template></p>
        </div>
      </header>
      <label class="settings-search">
        <Icon name="search" :size="16" />
        <input
          v-model="query"
          type="search"
          data-page-search
          :placeholder="tr('搜索设置')"
          :aria-label="tr('搜索设置')"
          data-testid="settings-search"
          @keydown="onSearchKey"
        />
      </label>

      <div v-if="searching" ref="content" class="settings-results" data-testid="settings-results">
        <template v-if="resultGroups.length">
          <section v-for="group in resultGroups" :key="group.id" class="sgroup">
            <header class="sgroup-head"><h3>{{ group.title }}</h3></header>
            <div class="sgroup-card">
              <button v-for="entry in group.entries" :key="entry.id" type="button" class="srow srow-nav" :data-result="entry.id" @click="pick(entry)">
                <div class="srow-main">
                  <span class="srow-title">{{ entry.title() }}</span>
                  <span v-if="entry.description" class="srow-desc">{{ entry.description() }}</span>
                </div>
                <Icon name="chevron-right" :size="16" class="srow-chevron" />
              </button>
            </div>
          </section>
        </template>
        <p v-else class="settings-empty">{{ tr('没有找到“{0}”相关的设置', { 0: query.trim() }) }}</p>
      </div>

      <template v-else>
        <nav class="tool-grid" :aria-label="tr('工具')" data-testid="tool-grid">
          <button type="button" class="tool-tile" data-tool="connections" @click="store.go('connections')">
            <span class="tool-icon blue"><Icon name="activity" /></span>
            <strong>{{ tr('连接') }}</strong>
            <span class="muted small">{{ snap.connected ? tr('{0} 个活动', { 0: snap.connection_total }) : tr('未连接') }}</span>
          </button>
          <button type="button" class="tool-tile" data-tool="logs" @click="store.go('logs')">
            <span class="tool-icon amber"><Icon name="terminal" /></span>
            <strong>{{ tr('日志') }}</strong>
            <span class="muted small">{{ snap.logs.length ? tr('{0} 条', { 0: snap.logs.length }) : tr('暂无') }}</span>
          </button>
          <button type="button" class="tool-tile" data-tool="rules" @click="store.go('rules')">
            <span class="tool-icon violet"><Icon name="route" /></span>
            <strong>{{ tr('规则') }}</strong>
            <span class="muted small">{{ tr('分流规则与命中') }}</span>
          </button>
          <button type="button" class="tool-tile" data-tool="resources" @click="store.go('resources')">
            <span class="tool-icon green"><Icon name="database" /></span>
            <strong>{{ tr('外部资源') }}</strong>
            <span class="muted small">{{ tr('规则集与代理集') }}</span>
          </button>
        </nav>

        <section class="sgroup">
          <div class="sgroup-card">
            <template v-for="category in categories" :key="category.id">
              <button
                type="button"
                class="srow srow-nav srow-cat"
                :data-testid="`open-${category.id}`"
                @click="openCategory(category.id)"
              >
                <span class="cat-icon" :class="category.tone"><Icon :name="category.icon" :size="17" /></span>
                <div class="srow-main">
                  <span class="srow-title">{{ category.label() }}</span>
                  <span class="srow-desc">{{ category.description() }}</span>
                </div>
                <span v-if="summary(category.id)" class="srow-value">{{ summary(category.id) }}</span>
                <Icon name="chevron-right" :size="16" class="srow-chevron" />
              </button>
              <button
                v-if="category.id === 'network' && store.isAndroid.value"
                type="button"
                class="srow srow-nav srow-cat"
                data-testid="open-apps"
                @click="store.go('apps')"
              >
                <span class="cat-icon green"><Icon name="apps" :size="17" /></span>
                <div class="srow-main"><span class="srow-title">{{ tr('应用访问控制') }}</span></div>
                <span class="srow-value">{{ appSummary }}</span>
                <Icon name="chevron-right" :size="16" class="srow-chevron" />
              </button>
            </template>
          </div>
        </section>
        <p class="settings-foot">{{ tr('基于 Mihomo 内核的跨平台代理客户端 · GPL-3.0') }}</p>
      </template>
    </template>

    <template v-else>
      <header class="settings-subhead">
        <button type="button" class="back-btn" data-testid="settings-back" @click="settingsBack">
          <Icon name="chevron-left" :size="18" /><span>{{ tr('设置') }}</span>
        </button>
        <h1>{{ active.label() }}</h1>
      </header>
      <div ref="content">
        <PaneStack :key="active.id" :panes="activePanes" :open="openPane" :compact="compact" />
      </div>
    </template>
    <TrafficStatsDialog v-if="store.trafficStatsOpen.value" @close="store.trafficStatsOpen.value = false" />
  </div>

  <!-- ───────── Desktop: rail + pane ───────── -->
  <div v-else class="page settings settings-desktop">
    <div class="settings-layout">
      <aside class="settings-rail" :aria-label="tr('设置分类')">
        <h1 class="settings-rail-title">{{ tr('设置') }}</h1>
        <label class="settings-search">
          <Icon name="search" :size="15" />
          <input
              v-model="query"
            type="search"
            data-page-search
            :placeholder="tr('搜索设置')"
            :aria-label="tr('搜索设置')"
            data-testid="settings-search"
            @keydown="onSearchKey"
          />
        </label>
        <nav ref="navEl" class="settings-nav" data-testid="settings-tabs" @wheel="onNavWheel">
          <template v-for="category in categories" :key="category.id">
            <button
              type="button"
              class="settings-nav-item"
              :class="{ active: !searching && active.id === category.id }"
              :aria-current="!searching && active.id === category.id ? 'page' : undefined"
              :data-value="category.id"
              :data-testid="`open-${category.id}`"
              @click="openCategory(category.id)"
            >
              <span class="cat-icon sm" :class="category.tone"><Icon :name="category.icon" :size="15" /></span>
              <span class="settings-nav-text">{{ category.label() }}</span>
            </button>
            <button
              v-if="category.id === 'network' && store.isAndroid.value"
              type="button"
              class="settings-nav-item"
              data-testid="open-apps"
              @click="store.go('apps')"
            >
              <span class="cat-icon sm green"><Icon name="apps" :size="15" /></span>
              <span class="settings-nav-text">{{ tr('应用访问控制') }}</span>
            </button>
          </template>
        </nav>
      </aside>

      <div ref="content" class="settings-content">
        <template v-if="searching">
          <header class="settings-pane-head">
            <div>
              <h2>{{ tr('搜索结果') }}</h2>
              <p class="muted">{{ results.length ? tr('找到 {0} 项', { 0: results.length }) : tr('没有找到“{0}”相关的设置', { 0: query.trim() }) }}</p>
            </div>
          </header>
          <div class="settings-results" data-testid="settings-results">
            <section v-for="group in resultGroups" :key="group.id" class="sgroup">
              <header class="sgroup-head"><h3>{{ group.title }}</h3></header>
              <div class="sgroup-card">
                <button v-for="entry in group.entries" :key="entry.id" type="button" class="srow srow-nav" :data-result="entry.id" @click="pick(entry)">
                  <div class="srow-main">
                    <span class="srow-title">{{ entry.title() }}</span>
                    <span v-if="entry.description" class="srow-desc">{{ entry.description() }}</span>
                  </div>
                  <Icon name="chevron-right" :size="16" class="srow-chevron" />
                </button>
              </div>
            </section>
          </div>
        </template>
        <template v-else>
          <header class="settings-pane-head">
            <span class="cat-icon lg" :class="active.tone"><Icon :name="active.icon" :size="20" /></span>
            <div>
              <h2>{{ active.label() }}</h2>
              <p class="muted">{{ active.description() }}</p>
            </div>
          </header>
          <PaneStack :key="active.id" :panes="activePanes" :open="openPane" :compact="compact" />
        </template>
      </div>
    </div>
    <TrafficStatsDialog v-if="store.trafficStatsOpen.value" @close="store.trafficStatsOpen.value = false" />
  </div>
</template>
