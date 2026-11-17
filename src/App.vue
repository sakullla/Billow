<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, provide, ref, watch } from 'vue'
import CommandPalette from './components/CommandPalette.vue'
import ConfigViewer from './components/ConfigViewer.vue'
import Icon from './components/Icon.vue'
import Modal from './components/Modal.vue'
import TitleBar from './components/TitleBar.vue'
import { createBackend, type Backend } from './lib/backend'
import { formatSpeed, formatSpeedCompact } from './lib/format'
import { createStore, PAGES, resolvePage, STORE, type PageId, type SettingsTab } from './lib/store'
import { closeTopLayer as dismissTopLayer, layerDepth, onLayerChange } from './lib/ui/focus'
import { useHotkeys } from './lib/ui/hotkeys'
import { installInsets, syncSystemBars } from './lib/ui/insets'
import { detectChrome, type WindowChrome } from './lib/ui/windowChrome'
import { getShortcut, pageShortcutCombo, SHORTCUTS, shortcutBindings, shortcutKeyLabel } from './lib/ui/shortcuts'
import AppsView from './views/AppsView.vue'
import ConnectionsView from './views/ConnectionsView.vue'
import HomeView from './views/HomeView.vue'
import LogsView from './views/LogsView.vue'
import ProfilesView from './views/ProfilesView.vue'
import ProxiesView from './views/ProxiesView.vue'
import ResourcesView from './views/ResourcesView.vue'
import RulesView from './views/RulesView.vue'
import SettingsView from './views/SettingsView.vue'

const props = defineProps<{ backend?: Backend; width?: number; chrome?: WindowChrome }>()
/** Custom title bar on Windows (undecorated) and macOS (overlay traffic lights). */
const chrome = props.chrome !== undefined ? props.chrome : detectChrome()
const appIcon = `${import.meta.env.BASE_URL}icon.png`

const store = createStore(props.backend ?? createBackend())
provide(STORE, store)

const width = ref(props.width ?? (typeof window !== 'undefined' ? window.innerWidth : 1024))
const compact = computed(() => width.value < 760)
const SIDEBAR_STORAGE_KEY = 'billow.sidebarCollapsed'
function readSidebarCollapsed(): boolean {
  try {
    return typeof localStorage !== 'undefined' && localStorage.getItem(SIDEBAR_STORAGE_KEY) === '1'
  } catch {
    return false
  }
}
const sidebarCollapsed = ref(readSidebarCollapsed())
function toggleSidebar() {
  sidebarCollapsed.value = !sidebarCollapsed.value
  try {
    localStorage?.setItem(SIDEBAR_STORAGE_KEY, sidebarCollapsed.value ? '1' : '0')
  } catch {
    /* ignore storage quota errors */
  }
}
const snap = computed(() => store.snapshot.value)
const sideStatusWord = computed(() => {
  if (store.connecting.value) return snap.value.connected ? '断开中…' : '连接中…'
  return snap.value.connected ? '已连接' : '未连接'
})
const themeMeta = computed(() => {
  if (store.theme.value === 'light') return { icon: 'sun', label: '浅色主题' }
  if (store.theme.value === 'dark') return { icon: 'moon', label: '深色主题' }
  return { icon: 'laptop', label: '跟随系统' }
})

const views = {
  home: HomeView,
  proxies: ProxiesView,
  profiles: ProfilesView,
  connections: ConnectionsView,
  rules: RulesView,
  resources: ResourcesView,
  logs: LogsView,
  settings: SettingsView,
  apps: AppsView,
} as const
const view = computed(() => views[store.page.value])
const mobilePages = PAGES.filter((page) => page.mobile)
const navGroups = [
  { id: 'core', label: '核心', pages: PAGES.filter((page) => page.group === 'core') },
  { id: 'tools', label: '工具', pages: PAGES.filter((page) => page.group === 'tools') },
]
const settingsPage = PAGES.find((page) => page.id === 'settings')!
/** Sidebar order doubles as the mod+1 … mod+7 order. */
const sidebarPages = navGroups.flatMap((group) => group.pages)
const settingsKey = shortcutKeyLabel(getShortcut('settings').combo)

function pageKeyLabel(id: PageId): string | null {
  const combo = pageShortcutCombo(sidebarPages.findIndex((page) => page.id === id))
  return combo ? shortcutKeyLabel(combo) : null
}

/** Nav tooltip: the keycap always; the label and live count only when the rail hides them. */
function navTitle(item: { id: PageId; label: string }): string {
  const key = pageKeyLabel(item.id)
  const count = sidebarCollapsed.value && item.id === 'connections' && snap.value.connected ? `（${snap.value.connections.length}）` : ''
  return `${item.label}${count}${key ? ` (${key})` : ''}`
}
const TOOL_PAGES: readonly PageId[] = ['connections', 'rules', 'resources', 'logs', 'apps']

/** Connections/rules/resources/logs live behind Settings on mobile, so Settings is the current tab there. */
function isTabCurrent(id: PageId): boolean {
  return store.page.value === id || (id === 'settings' && TOOL_PAGES.includes(store.page.value))
}

/** Phones reach tool pages from Settings, so they get a visible way back besides the system gesture. */
const showBack = computed(() => compact.value && TOOL_PAGES.includes(store.page.value))
/** The page a back press returns to; mirrors the top of the non-reactive page stack. */
const backTo = ref<PageId | null>(null)
const backLabel = computed(() => PAGES.find((page) => page.id === backTo.value)?.label ?? '设置')

function goBack() {
  const previous = backTo.value
  if (historyReady && previous != null && guardActive) {
    window.history.back()
    return
  }
  store.go(previous ?? 'settings')
}

// ── System bars follow the effective theme (Android edge-to-edge) ──
const prefersDark = ref(typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: dark)').matches === true)
const darkTheme = computed(() => store.theme.value === 'dark' || (store.theme.value === 'system' && prefersDark.value))
watch(darkTheme, (dark) => syncSystemBars(dark), { immediate: true })
let darkQuery: MediaQueryList | null = null
function onSchemeChange(event: MediaQueryListEvent) {
  prefersDark.value = event.matches
}

// Add-profile dialog
const addTab = ref<'url' | 'file'>('url')
const url = ref('')
const dragging = ref(false)
const paletteOpen = ref(false)
const helpOpen = ref(false)
const paletteKey = shortcutKeyLabel(getShortcut('palette').combo)
const sidebarKey = shortcutKeyLabel(getShortcut('sidebar').combo)
provide('openShortcuts', () => {
  helpOpen.value = true
})

async function submitUrl() {
  const value = url.value.trim()
  if (!value) return
  const before = snap.value.profiles.length
  await store.addSubscription(value)
  if (snap.value.profiles.length > before) {
    url.value = ''
    store.adding.value = false
    store.toast('已添加订阅，点击即可启用', 'success')
    const added = snap.value.profiles[snap.value.profiles.length - 1]
    if (!snap.value.active_id && added) void store.enable(added.id)
  }
}

async function pasteUrl() {
  try {
    const text = await navigator.clipboard.readText()
    if (text) url.value = text.trim()
  } catch {
    store.toast('无法读取剪贴板，请手动粘贴', 'error')
  }
}

async function addFile(file: File | undefined) {
  if (!file) return
  const before = snap.value.profiles.length
  await store.addLocal(file.name.replace(/\.(ya?ml|txt)$/i, ''), await file.text())
  if (snap.value.profiles.length > before) {
    store.adding.value = false
    store.toast(`已导入 ${file.name}`, 'success')
    const added = snap.value.profiles[snap.value.profiles.length - 1]
    if (!snap.value.active_id && added) void store.enable(added.id)
  }
}

function onFile(event: Event) {
  const input = event.target as HTMLInputElement
  void addFile(input.files?.[0])
  input.value = ''
}

function onDrop(event: DragEvent) {
  dragging.value = false
  void addFile(event.dataTransfer?.files?.[0])
}

// ── Command palette ──
const isAndroid = computed(() => store.isAndroid.value)

function onPaletteNavigate(page: string) {
  paletteOpen.value = false
  store.go(resolvePage(page))
}

/** Tray menu targets: a page id, or the add-profile dialog. */
function onTrayNavigate(target: string) {
  if (target === 'add-profile') {
    store.adding.value = true
    return
  }
  store.go(resolvePage(target))
}

function onPaletteSettings(tab: string) {
  paletteOpen.value = false
  store.openSettings(tab as SettingsTab)
}

function onPaletteAction(id: string) {
  paletteOpen.value = false
  switch (id) {
    case 'connect':
      void store.connect()
      break
    case 'disconnect':
      void store.disconnect()
      break
    case 'test-all':
      void store.testAll()
      break
    case 'refresh-profiles':
      void store.refreshAll()
      break
    case 'add-profile':
      store.adding.value = true
      break
    case 'mode-rule':
      void store.setMode('rule')
      break
    case 'mode-global':
      void store.setMode('global')
      break
    case 'mode-direct':
      void store.setMode('direct')
      break
    case 'toggle-sidebar':
      if (!compact.value) toggleSidebar()
      break
    case 'copy-proxy-env':
      void store.copyProxyEnv()
      break
    case 'toggle-theme':
      store.cycleTheme()
      break
    case 'open-logs':
      store.go('logs')
      break
    case 'open-config':
      store.openConfig()
      break
    case 'open-shortcuts':
      void nextTick(() => {
        helpOpen.value = true
      })
      break
  }
}

// ── Shortcuts ──
/** Every dialog, palette and menu registers in the shared layer stack. */
function layerOpen(): boolean {
  return layerDepth() > 0
}

function currentSearch(): HTMLInputElement | null {
  return document.querySelector<HTMLInputElement>('.main [data-page-search]')
}

function focusSearch() {
  const input = currentSearch()
  if (!input) return
  input.focus({ preventScroll: true })
  input.select?.()
}

/** Escape clears the focused search field; overlays and menus own their own Escape. */
function clearSearch() {
  const element = document.activeElement
  if (!(element instanceof HTMLInputElement)) return
  if (element.type !== 'search' && !element.hasAttribute('data-page-search')) return
  if (!element.value) return
  element.value = ''
  element.dispatchEvent(new Event('input', { bubbles: true }))
}

useHotkeys(
  shortcutBindings(
    {
      palette: () => {
        paletteOpen.value = true
      },
      sidebar: () => {
        if (!compact.value) toggleSidebar()
      },
      settings: () => store.go('settings'),
      search: focusSearch,
      escape: clearSearch,
      help: () => {
        helpOpen.value = true
      },
    },
    { allowInInput: ['escape'] },
  )
    .concat(
      sidebarPages.flatMap((page, index) => {
        const combo = pageShortcutCombo(index)
        return combo ? [{ combo, handler: () => store.go(page.id), allowInInput: true }] : []
      }),
    )
    .map((binding) => ({ ...binding, when: () => !layerOpen() })),
)

// ── Scroll memory (R25) ──
const mainEl = ref<HTMLElement | null>(null)
const scrollPositions = new Map<PageId, number>()

async function restorePageScroll(page: PageId) {
  await nextTick()
  if (store.page.value !== page) return
  const main = mainEl.value
  if (!main) return
  // A group target owns the landing position on the proxy page (D2). If the
  // requested group does not exist, fall back to the top instead of the old offset.
  if (page === 'proxies' && store.focusGroup.value) {
    const target = document.querySelector(`[data-group-card="${CSS.escape(store.focusGroup.value)}"]`)
    if (target) return
    main.scrollTop = 0
    return
  }
  main.scrollTop = scrollPositions.get(page) ?? 0
}

watch(
  () => store.page.value,
  (next, prev) => {
    if (mainEl.value && prev) scrollPositions.set(prev, mainEl.value.scrollTop)
    if (prev) recordPageHistory(prev, next)
    backTo.value = pageStack[pageStack.length - 1] ?? null
    void restorePageScroll(next)
  },
)

let lastWidth = width.value

function onResize() {
  const nextWidth = props.width ?? window.innerWidth
  if (props.width == null) width.value = nextWidth
  // Only width changes invalidate saved offsets. Android soft-keyboard resizes
  // change height alone and must keep the current scroll position (R25).
  if (nextWidth === lastWidth) return
  lastWidth = nextWidth
  scrollPositions.clear()
  if (mainEl.value) mainEl.value.scrollTop = 0
}

// ── Android back bridge (R30) ──
// Tauri Android forwards hardware back to the WebView history. The app keeps one
// sentinel entry above the current URL while it has something back should do (an
// open layer or an earlier page). Each pop consumes the sentinel and the popstate
// handler decides from the shared layer stack and an explicit page stack:
//   - layer open: dismiss the topmost layer and re-arm the sentinel, no navigation;
//   - otherwise: move to the previous app page, re-arming the sentinel while more
//     pages remain;
//   - neither: leave the sentinel consumed so the platform handles the next back.
// `popstate.state` is deliberately ignored: it describes the entry we landed on,
// not the guard we popped.
interface BillowHistoryState {
  billow: 'base' | 'guard'
}

let historyReady = false
let ignorePageHistory = false
let guardActive = false
let releaseLayerWatch: (() => void) | null = null
let releaseInsets: (() => void) | null = null
let releaseTray: (() => void) | null = null
let unmounted = false
const pageStack: PageId[] = []

function pushHistory(state: BillowHistoryState) {
  try {
    window.history?.pushState(state, '')
  } catch {
    /* webview without history support */
  }
}

function replaceHistory(state: BillowHistoryState) {
  try {
    window.history?.replaceState(state, '')
  } catch {
    /* webview without history support */
  }
}

/** Keep exactly one sentinel above the current URL while the app can go back. */
function ensureGuard() {
  if (!historyReady || guardActive) return
  guardActive = true
  pushHistory({ billow: 'guard' })
}

function recordPageHistory(prev: PageId, next: PageId) {
  if (!historyReady || ignorePageHistory) {
    ignorePageHistory = false
    return
  }
  if (prev !== next) pageStack.push(prev)
  ensureGuard()
}

/**
 * Phone settings drill into kernel/TUN/DNS sub-pages. Entering one records a
 * `settings` step so system back returns to the settings list first.
 */
watch(
  () => store.settingsTab.value,
  (next, prev) => {
    if (!compact.value || store.page.value !== 'settings' || !historyReady) return
    if (prev === 'general' && next !== 'general') {
      pageStack.push('settings')
      ensureGuard()
    }
  },
)

/** Phone settings sub-page back: consume the recorded step when it is on top, else just switch. */
provide('settingsBack', () => {
  if (historyReady && guardActive && pageStack[pageStack.length - 1] === 'settings') {
    window.history.back()
    return
  }
  store.settingsTab.value = 'general'
})

/** Layer depth is the single source of truth; never infer it from popstate state. */
function handleLayerDepth(depth: number) {
  if (depth > 0) ensureGuard()
}

function onPopState() {
  if (!historyReady) return
  // The sentinel (or, when exhausted, the base entry) was popped.
  guardActive = false
  if (layerDepth() > 0) {
    // Re-arm before closing when more app history exists (or another layer sits
    // underneath), so a second back is routed by the app rather than a page entry.
    if (pageStack.length > 0 || layerDepth() > 1) ensureGuard()
    dismissTopLayer()
    return
  }
  const previous = pageStack.pop()
  if (previous === 'settings' && store.page.value === 'settings' && store.settingsTab.value !== 'general') {
    store.settingsTab.value = 'general'
    if (pageStack.length > 0 || layerDepth() > 0) ensureGuard()
    return
  }
  if (previous != null) {
    ignorePageHistory = true
    store.go(previous)
    if (pageStack.length > 0 || layerDepth() > 0) ensureGuard()
    return
  }
  // Nothing app-owned is left; let the system handle the next back.
}

function initHistory() {
  if (typeof window === 'undefined' || !window.history) return
  replaceHistory({ billow: 'base' })
  historyReady = true
  // Do not arm a sentinel at the root: with no pages or layers, back belongs to
  // the platform. Navigation and layer opens arm it through ensureGuard().
  if (pageStack.length > 0 || layerDepth() > 0) ensureGuard()
}

onMounted(async () => {
  releaseInsets = installInsets()
  void store.backend.onTrayNavigate?.(onTrayNavigate).then((stop) => {
    if (unmounted) stop()
    else releaseTray = stop
  })
  darkQuery = window.matchMedia?.('(prefers-color-scheme: dark)') ?? null
  darkQuery?.addEventListener?.('change', onSchemeChange)
  window.addEventListener('resize', onResize)
  window.addEventListener('popstate', onPopState)
  releaseLayerWatch = onLayerChange(handleLayerDepth)
  await store.start()
  initHistory()
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  window.removeEventListener('popstate', onPopState)
  releaseLayerWatch?.()
  releaseLayerWatch = null
  releaseInsets?.()
  releaseInsets = null
  unmounted = true
  releaseTray?.()
  releaseTray = null
  darkQuery?.removeEventListener?.('change', onSchemeChange)
  store.stop()
})

defineExpose({ store })
</script>

<template>
  <div class="shell" :class="[{ compact, 'sidebar-collapsed': !compact && sidebarCollapsed }, chrome ? `chrome chrome-${chrome}` : null]">
    <aside v-if="!compact" class="sidebar" :class="{ collapsed: sidebarCollapsed }">
      <!-- macOS: the traffic lights sit here; the strip still moves the window. -->
      <div v-if="chrome === 'macos'" class="sidebar-drag" data-tauri-drag-region />
      <div class="brand" :data-tauri-drag-region="chrome ? '' : undefined">
        <span class="brand-mark"><img :src="appIcon" alt="" /></span>
        <span class="brand-name">Billow</span>
        <div class="brand-actions" @mousedown.stop>
          <button
            v-if="!sidebarCollapsed"
            type="button"
            class="icon-btn sm theme-quick-btn"
            :aria-label="`切换主题（当前：${themeMeta.label}）`"
            :title="`切换主题（当前：${themeMeta.label}）`"
            data-testid="sidebar-theme-toggle"
            @click="store.cycleTheme()"
          >
            <Icon :name="themeMeta.icon" :size="15" />
          </button>
          <button
            type="button"
            class="icon-btn sm sidebar-toggle"
            :aria-expanded="!sidebarCollapsed"
            :aria-label="sidebarCollapsed ? '展开侧边栏' : '收起侧边栏'"
            :title="`${sidebarCollapsed ? '展开侧边栏' : '收起侧边栏'} (${sidebarKey})`"
            data-testid="sidebar-toggle"
            @click="toggleSidebar"
          >
            <Icon :name="sidebarCollapsed ? 'panel-left-open' : 'panel-left-close'" :size="16" />
          </button>
        </div>
      </div>
      <button
        type="button"
        class="side-search"
        :title="sidebarCollapsed ? `搜索与命令 (${paletteKey})` : '搜索页面、设置与快捷动作'"
        aria-label="搜索与命令"
        data-testid="open-palette"
        @click="paletteOpen = true"
      >
        <Icon name="search" :size="15" />
        <span class="side-search-label">搜索与命令</span>
        <kbd class="palette-kbd">{{ paletteKey }}</kbd>
      </button>
      <nav class="nav" aria-label="主导航">
        <div v-for="group in navGroups" :key="group.id" class="nav-group" role="group" :aria-label="group.label">
          <p class="nav-group-label">{{ group.label }}</p>
          <button
            v-for="item in group.pages"
            :key="item.id"
            type="button"
            class="nav-item"
            :class="{ active: store.page.value === item.id }"
            :aria-current="store.page.value === item.id ? 'page' : undefined"
            :aria-label="sidebarCollapsed ? item.label : undefined"
            :title="navTitle(item)"
            :data-page="item.id"
            @click="store.go(item.id)"
          >
            <Icon :name="item.icon" />
            <span class="nav-item-label">{{ item.label }}</span>
            <span v-if="item.id === 'connections' && snap.connected" class="nav-count">{{ snap.connections.length }}</span>
          </button>
        </div>
      </nav>
      <div class="side-foot">
        <button
          type="button"
          class="nav-item"
          :class="{ active: store.page.value === settingsPage.id }"
          :aria-current="store.page.value === settingsPage.id ? 'page' : undefined"
          :aria-label="sidebarCollapsed ? settingsPage.label : undefined"
          :title="`${settingsPage.label}${sidebarCollapsed && store.appUpdate.offer.value ? '（有更新）' : ''} (${settingsKey})`"
          :data-page="settingsPage.id"
          @click="store.go(settingsPage.id)"
        >
          <Icon :name="settingsPage.icon" />
          <span class="nav-item-label">{{ settingsPage.label }}</span>
          <span v-if="store.appUpdate.offer.value" class="tag nav-update-tag">更新</span>
        </button>
        <div
          class="side-status"
          :class="{ on: snap.connected && !store.connecting.value, pending: store.connecting.value }"
          :title="sidebarCollapsed ? `${sideStatusWord}${snap.connected ? ` · ↓${formatSpeed(snap.download ?? 0)} ↑${formatSpeed(snap.upload ?? 0)}` : ''}` : undefined"
          data-testid="side-status"
        >
          <div class="side-status-body" @click="store.page.value !== 'home' && store.go('home')">
            <div class="side-status-head">
              <span class="dot" />
              <span>{{ sideStatusWord }}</span>
            </div>
            <div v-if="snap.connected" class="side-rates mono">
              <span class="down" :title="`下载 ${formatSpeed(snap.download ?? 0)}`"><Icon name="down" :size="11" /><em class="side-rate-num">{{ formatSpeedCompact(snap.download ?? 0) }}</em></span>
              <span class="up" :title="`上传 ${formatSpeed(snap.upload ?? 0)}`"><Icon name="up" :size="11" /><em class="side-rate-num">{{ formatSpeedCompact(snap.upload ?? 0) }}</em></span>
            </div>
            <div v-else class="side-rates muted ellipsis">{{ store.current.value?.name ?? '还没有配置' }}</div>
          </div>
          <button
            v-if="store.hasProfiles.value"
            type="button"
            class="side-power"
            :disabled="store.connecting.value"
            :aria-label="snap.connected ? '断开' : '连接'"
            :title="sidebarCollapsed ? `${sideStatusWord}（点击${snap.connected ? '断开' : '连接'}）` : (snap.connected ? '断开' : '连接')"
            data-testid="side-power"
            @click="store.toggleConnection()"
          >
            <span v-if="store.connecting.value" class="spinner sm" />
            <Icon v-else name="power" :size="16" :stroke="2.2" />
          </button>
          <span v-else-if="sidebarCollapsed" class="dot collapsed-status-dot" aria-hidden="true" />
        </div>
      </div>
    </aside>

    <TitleBar v-if="chrome" :chrome="chrome" :brand="compact" />

    <main ref="mainEl" class="main" :data-page="store.page.value">
      <div v-if="showBack" class="back-bar">
        <button type="button" class="back-btn" data-testid="page-back" @click="goBack">
          <Icon name="chevron-left" :size="18" />
          <span>{{ backLabel }}</span>
        </button>
      </div>
      <component :is="view" v-if="store.loaded.value" :compact="compact" />
      <div v-else class="loading"><span class="spinner" /></div>
    </main>

    <nav v-if="compact" class="tabbar" aria-label="主导航">
      <button
        v-for="item in mobilePages"
        :key="item.id"
        type="button"
        class="tab"
        :class="{ active: isTabCurrent(item.id) }"
        :aria-current="isTabCurrent(item.id) ? 'page' : undefined"
        :data-page="item.id"
        @click="store.go(item.id)"
      >
        <span class="tab-icon-wrap">
          <Icon :name="item.icon" :size="21" />
          <span
            v-if="item.id === 'home' && (snap.connected || store.connecting.value)"
            class="tab-live-dot"
            :class="{ pending: store.connecting.value }"
            aria-hidden="true"
          />
        </span>
        <span class="tab-label">{{ item.label }}<span v-if="item.id === 'settings' && store.appUpdate.offer.value" class="update-dot" aria-label="有可用更新">•</span></span>
      </button>
    </nav>

    <CommandPalette
      v-if="paletteOpen"
      :platform="isAndroid ? 'android' : 'desktop'"
      :connected="snap.connected"
      :has-profiles="snap.profiles.length > 0"
      :current-page="store.page.value"
      :mode="snap.mode"
      :sidebar-collapsed="sidebarCollapsed"
      @navigate="onPaletteNavigate"
      @open-settings="onPaletteSettings"
      @action="onPaletteAction"
      @close="paletteOpen = false"
    />

    <ConfigViewer v-if="store.configView.value" />

    <Modal v-if="helpOpen" title="快捷键" subtitle="在应用内生效，输入框会保留自己的按键" @close="helpOpen = false">
      <dl class="shortcut-list">
        <div v-for="shortcut in SHORTCUTS" :key="shortcut.id" class="shortcut-row">
          <dt><kbd class="palette-kbd">{{ shortcutKeyLabel(shortcut.combo) }}</kbd></dt>
          <dd>
            <strong>{{ shortcut.label }}</strong>
            <p class="muted small">{{ shortcut.description }}</p>
          </dd>
        </div>
      </dl>
    </Modal>

    <Modal v-if="store.adding.value" title="添加配置" subtitle="订阅链接或 Clash / Mihomo YAML 文件" @close="store.adding.value = false">
      <div class="tabs-inline" role="tablist">
        <button type="button" role="tab" :class="{ active: addTab === 'url' }" :aria-selected="addTab === 'url'" @click="addTab = 'url'">
          <Icon name="link" :size="16" /> 订阅链接
        </button>
        <button type="button" role="tab" :class="{ active: addTab === 'file' }" :aria-selected="addTab === 'file'" @click="addTab = 'file'">
          <Icon name="file" :size="16" /> 本地文件
        </button>
      </div>
      <form v-if="addTab === 'url'" class="stack" data-testid="add-url" @submit.prevent="submitUrl">
        <label class="field">
          <span>订阅地址</span>
          <div class="input-group">
            <!-- Phones open the sheet without the keyboard; paste or tap the field to type. -->
            <input v-model="url" type="url" inputmode="url" enterkeyhint="go" placeholder="https://…" autocomplete="off" spellcheck="false" :autofocus="!compact" />
            <button type="button" class="btn ghost" title="从剪贴板粘贴" data-testid="paste-url" @click="pasteUrl"><Icon name="clipboard" :size="16" />粘贴</button>
          </div>
        </label>
        <p v-if="snap.input_error" class="field-error" role="alert">{{ snap.input_error }}</p>
        <p class="muted small">添加后会下载订阅内容，并读取流量与到期信息。</p>
        <button type="submit" class="btn primary block" :disabled="!url.trim() || store.busy.add">
          <span v-if="store.busy.add" class="spinner sm" />
          添加订阅
        </button>
      </form>
      <div v-else class="stack">
        <label
          class="dropzone"
          :class="{ over: dragging }"
          @dragover.prevent="dragging = true"
          @dragleave="dragging = false"
          @drop.prevent="onDrop"
        >
          <Icon name="download" :size="28" />
          <strong>拖入 YAML 配置文件</strong>
          <span class="muted small">或点击选择文件</span>
          <input type="file" accept=".yaml,.yml,.txt,text/yaml" hidden @change="onFile" />
        </label>
        <p v-if="snap.input_error" class="field-error" role="alert">{{ snap.input_error }}</p>
      </div>
    </Modal>

    <Modal v-if="snap.pending_url" title="导入订阅" subtitle="来自外部链接的订阅，确认后才会添加" @close="store.cancelInstall()">
      <p class="url-box mono">{{ snap.pending_url }}</p>
      <template #footer>
        <button type="button" class="btn ghost" @click="store.cancelInstall()">取消</button>
        <button type="button" class="btn primary" @click="store.confirmInstall()">添加</button>
      </template>
    </Modal>

    <div class="toasts" aria-live="polite">
      <TransitionGroup name="toast">
        <div
          v-for="item in store.toasts.value"
          :key="item.id"
          class="toast"
          :class="item.tone"
          title="点击关闭"
          @mouseenter="store.pauseToast(item.id)"
          @mouseleave="store.resumeToast(item.id)"
          @click="store.dismissToast(item.id)"
        >
          <Icon :name="item.tone === 'error' ? 'alert' : item.tone === 'success' ? 'check' : 'info'" :size="16" />
          <span class="grow">{{ item.text }}</span>
        </div>
      </TransitionGroup>
    </div>
  </div>
</template>
