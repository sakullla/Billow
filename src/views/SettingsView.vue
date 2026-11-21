<script setup lang="ts">
import { computed, inject, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import TrafficStatsDialog from '../components/TrafficStatsDialog.vue'
import { highlightTokens } from '../lib/search'
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
 * Settings shell (v4):
 * - Desktop: single-column header with inline search + sticky horizontal category tabs
 *   (no second left sidebar beside the app rail, no nested pane accordions).
 * - Phone: grouped category sections below the quick-tools grid, drilling into flat panes.
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
const phoneGroups = computed(() => [
  { id: 'network' as const, label: tr('代理与网络'), items: categories.value.filter((c) => c.group === 'network') },
  { id: 'app' as const, label: tr('应用与内核'), items: categories.value.filter((c) => c.group === 'app') },
])

/** Phone root is the category list; desktop always shows a category. */
const atRoot = computed(() => props.compact && store.settingsTab.value === 'home')
const active = computed<SettingsCategory>(() => {
  const cat = categoryOf(store.settingsTab.value)
  if (!cat.when || cat.when(platform.value)) return cat
  return categories.value[0]!
})
const activePanes = computed(() => visiblePanes(active.value, platform.value).map((item) => item.id))
const activeSubPane = computed<CategoryId>(() => {
  const tab = store.settingsTab.value
  const list = activePanes.value
  return list.includes(tab as CategoryId) ? (tab as CategoryId) : list[0]!
})

function openCategory(id: CategoryId) {
  query.value = ''
  store.settingsFocus.value = null
  store.settingsTab.value = id
  void nextTick(scrollToTop)
}

function selectSubPane(id: CategoryId) {
  store.settingsFocus.value = null
  store.settingsTab.value = id
}

/** One-word live summary per category on the phone list. */
function summary(id: CategoryId): string {
  const s = snap.value
  switch (id) {
    case 'general':
      return store.theme.value === 'dark' ? tr('深色') : store.theme.value === 'light' ? tr('浅色') : tr('自动')
    case 'proxy': {
      const on: string[] = []
      if (s.system_proxy) on.push(tr('系统代理'))
      if (s.tun) on.push('TUN')
      return on.length ? on.join(' · ') : tr('已关闭')
    }
    case 'network':
      return `:${s.mixed_port ?? s.settings.mixed_port ?? s.config_values.mixed_port ?? 7890}`
    case 'dns':
      return s.settings.dns_override ? tr('已覆写') : tr('跟随配置')
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

// Horizontal tab strip: let the mouse wheel scroll sideways when narrow and keep the active tab visible.
const navEl = ref<HTMLElement | null>(null)
function onNavWheel(event: WheelEvent) {
  const el = navEl.value
  if (!el || el.scrollWidth <= el.clientWidth || Math.abs(event.deltaX) >= Math.abs(event.deltaY)) return
  el.scrollLeft += event.deltaY
  event.preventDefault()
}
watch(
  () => active.value.id,
  () => void nextTick(() => navEl.value?.querySelector<HTMLElement>('.settings-tab.active')?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' })),
  { flush: 'post' },
)

function scrollToTop() {
  const main = document.querySelector('.main')
  if (main) main.scrollTop = 0
}

let flashTimer: ReturnType<typeof setTimeout> | undefined
/** Scroll a row into view, unfolding any inner advanced group first, and flash it once. */
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
  <!-- ───────── Phone: grouped category list ───────── -->
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
        <button
          v-if="query"
          type="button"
          class="icon-btn xs"
          :aria-label="tr('清空搜索')"
          data-testid="clear-settings-search"
          @click.prevent="query = ''"
        >
          <Icon name="x" :size="13" />
        </button>
      </label>

      <div v-if="searching" ref="content" class="settings-results" data-testid="settings-results">
        <template v-if="resultGroups.length">
          <section v-for="group in resultGroups" :key="group.id" class="sgroup">
            <header class="sgroup-head"><h3>{{ group.title }}</h3></header>
            <div class="sgroup-card">
              <button v-for="entry in group.entries" :key="entry.id" type="button" class="srow srow-nav" :data-result="entry.id" @click="pick(entry)">
                <div class="srow-main">
                  <span class="srow-title">
                    <template v-for="(part, idx) in highlightTokens(entry.title(), query)" :key="idx">
                      <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                    </template>
                  </span>
                  <span v-if="entry.description" class="srow-desc">
                    <template v-for="(part, idx) in highlightTokens(entry.description(), query)" :key="idx">
                      <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                    </template>
                  </span>
                </div>
                <Icon name="chevron-right" :size="16" class="srow-chevron" />
              </button>
            </div>
          </section>
        </template>
        <EmptyState
          v-else
          compact
          variant="no-match"
          :title="tr('没有找到“{0}”相关的设置', { 0: query.trim() })"
          :description="tr('换一个关键词，或清空搜索查看全部分类。')"
        >
          <template #action>
            <button type="button" class="btn ghost sm" data-testid="reset-settings-search" @click="query = ''">{{ tr('清空搜索') }}</button>
          </template>
        </EmptyState>
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

        <section v-for="group in phoneGroups" :key="group.id" class="sgroup">
          <header class="sgroup-head"><h3>{{ group.label }}</h3></header>
          <div class="sgroup-card">
            <template v-for="category in group.items" :key="category.id">
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
                <span v-if="category.id === 'backup' && store.appUpdate.offer.value" class="tag accent sm">{{ tr('更新') }}</span>
                <span v-else-if="summary(category.id)" class="srow-value">{{ summary(category.id) }}</span>
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
        <PaneStack
          :key="active.id"
          :panes="activePanes"
          :layout="active.layout"
          :active-pane="activeSubPane"
          :compact="compact"
          @select="selectSubPane"
        />
      </div>
    </template>
    <TrafficStatsDialog v-if="store.trafficStatsOpen.value" @close="store.trafficStatsOpen.value = false" />
  </div>

  <!-- ───────── Desktop: clean single-column header + sticky top tabs ───────── -->
  <div v-else class="page settings settings-desktop">
    <header class="page-head settings-head">
      <div>
        <h1>{{ tr('设置') }}</h1>
        <p class="muted small">{{ searching ? tr('搜索全部设置项') : active.description() }}</p>
      </div>
      <label class="settings-search settings-head-search">
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
        <kbd v-if="!query" class="search-kbd" aria-hidden="true">/</kbd>
        <button
          v-else
          type="button"
          class="icon-btn xs"
          :aria-label="tr('清空搜索')"
          data-testid="clear-settings-search"
          @click.prevent="query = ''"
        >
          <Icon name="x" :size="13" />
        </button>
      </label>
    </header>

    <nav
      ref="navEl"
      class="settings-tabs-bar"
      :aria-label="tr('设置分类')"
      data-testid="settings-tabs"
      @wheel="onNavWheel"
    >
      <template v-for="category in categories" :key="category.id">
        <button
          type="button"
          class="settings-tab"
          :class="{ active: !searching && active.id === category.id }"
          :aria-current="!searching && active.id === category.id ? 'page' : undefined"
          :data-value="category.id"
          :data-testid="`open-${category.id}`"
          @click="openCategory(category.id)"
        >
          <Icon :name="category.icon" :size="15" />
          <span>{{ category.label() }}</span>
          <span v-if="category.id === 'backup' && store.appUpdate.offer.value" class="tag accent sm">{{ tr('更新') }}</span>
        </button>
        <button
          v-if="category.id === 'network' && store.isAndroid.value"
          type="button"
          class="settings-tab"
          data-testid="open-apps"
          @click="store.go('apps')"
        >
          <Icon name="apps" :size="15" />
          <span>{{ tr('应用访问控制') }}</span>
        </button>
      </template>
    </nav>

    <div ref="content" class="settings-content">
      <template v-if="searching">
        <header class="settings-pane-head">
          <div>
            <h2>{{ tr('搜索结果') }}</h2>
            <p class="muted">{{ results.length ? tr('找到 {0} 项', { 0: results.length }) : tr('没有找到“{0}”相关的设置', { 0: query.trim() }) }}</p>
          </div>
        </header>
        <div class="settings-results" data-testid="settings-results">
          <template v-if="resultGroups.length">
            <section v-for="group in resultGroups" :key="group.id" class="sgroup">
              <header class="sgroup-head"><h3>{{ group.title }}</h3></header>
              <div class="sgroup-card">
                <button v-for="entry in group.entries" :key="entry.id" type="button" class="srow srow-nav" :data-result="entry.id" @click="pick(entry)">
                  <div class="srow-main">
                    <span class="srow-title">
                      <template v-for="(part, idx) in highlightTokens(entry.title(), query)" :key="idx">
                        <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                      </template>
                    </span>
                    <span v-if="entry.description" class="srow-desc">
                      <template v-for="(part, idx) in highlightTokens(entry.description(), query)" :key="idx">
                        <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                      </template>
                    </span>
                  </div>
                  <Icon name="chevron-right" :size="16" class="srow-chevron" />
                </button>
              </div>
            </section>
          </template>
          <EmptyState
            v-else
            compact
            variant="no-match"
            :title="tr('没有找到匹配的设置')"
            :description="tr('换一个关键词，或清空搜索查看全部分类。')"
          >
            <template #action>
              <button type="button" class="btn ghost sm" data-testid="reset-settings-search" @click="query = ''">{{ tr('清空搜索') }}</button>
            </template>
          </EmptyState>
        </div>
      </template>
      <template v-else>
        <PaneStack
          :key="active.id"
          :panes="activePanes"
          :layout="active.layout"
          :active-pane="activeSubPane"
          :compact="compact"
          @select="selectSubPane"
        />
      </template>
    </div>
    <TrafficStatsDialog v-if="store.trafficStatsOpen.value" @close="store.trafficStatsOpen.value = false" />
  </div>
</template>
