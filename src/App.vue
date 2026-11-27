<script setup lang="ts">import { t, tr } from './lib/i18n'

import { computed, nextTick, onBeforeUnmount, onMounted, provide, ref, watch } from 'vue'
import CommandPalette from './components/CommandPalette.vue'
import ConfigViewer from './components/ConfigViewer.vue'
import DnsQueryDialog from './components/DnsQueryDialog.vue'
import HotkeySection from './components/HotkeySection.vue'
import BrandMark from './components/BrandMark.vue'
import Icon from './components/Icon.vue'
import Modal from './components/Modal.vue'
import TitleBar from './components/TitleBar.vue'
import { createBackend, type Backend } from './lib/backend'
import { formatSpeed, formatSpeedCompact } from './lib/format'
import { looksLikeCustomNodeInput } from './lib/links'
import { getPaletteMeta } from './lib/palettes'
import { createStore, PAGES, resolvePage, STORE, type PageId, type SettingsTab, type Toast } from './lib/store'
import { closeTopLayer as dismissTopLayer, layerDepth, onLayerChange } from './lib/ui/focus'
import { useHotkeys } from './lib/ui/hotkeys'
import { installInsets, syncSystemBars } from './lib/ui/insets'
import { detectChrome, isWindowDecorated, type WindowChrome } from './lib/ui/windowChrome'
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
const chrome = ref<WindowChrome>(props.chrome !== undefined ? props.chrome : detectChrome())

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
  if (store.connecting.value) return snap.value.connected ? tr('断开中…') : tr('连接中…')
  return snap.value.connected ? tr('已连接') : tr('未连接')
})
const sideModeLabel = computed(() => {
  if (snap.value.mode === 'global') return tr('全局')
  if (snap.value.mode === 'direct') return tr('直连')
  return tr('规则')
})
const activeProfileName = computed(
  () => store.current.value?.name ?? (snap.value.custom_profile_active ? t('customNodes.standaloneActive') : null),
)
const sideMetaText = computed(() => {
  const profileName = activeProfileName.value
  return profileName ? `${sideModeLabel.value} · ${profileName}` : sideModeLabel.value
})
const themeMeta = computed(() => {
  if (store.theme.value === 'light') return { icon: 'sun', label: tr('浅色主题') }
  if (store.theme.value === 'dark') return { icon: 'moon', label: tr('深色主题') }
  return { icon: 'laptop', label: tr('跟随系统') }
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
  { id: 'core', get label() { return tr('核心') }, pages: PAGES.filter((page) => page.group === 'core') },
  { id: 'tools', get label() { return tr('工具') }, pages: PAGES.filter((page) => page.group === 'tools') },
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

const hasConnectionReturn = computed(
  () => Boolean(store.connectionReturn.value && store.page.value === store.connectionReturn.value.targetPage),
)
const hasRuleReturn = computed(
  () => Boolean(store.ruleReturn.value && store.page.value === store.ruleReturn.value.targetPage),
)
/** Phones reach tool pages from Settings, so they get a visible way back besides the system gesture. */
const showBack = computed(
  () => compact.value && (TOOL_PAGES.includes(store.page.value) || hasConnectionReturn.value || hasRuleReturn.value),
)
/** Desktop shows a contextual return bar only when drilling from connection detail or rules into another page (R4, R5). */
const showDesktopConnectionReturn = computed(() => !compact.value && hasConnectionReturn.value)
const showDesktopRuleReturn = computed(() => !compact.value && !hasConnectionReturn.value && hasRuleReturn.value)
/** The page a back press returns to; mirrors the top of the non-reactive page stack. */
const backTo = ref<PageId | null>(null)
const backLabel = computed(() => {
  if (hasConnectionReturn.value) return tr('返回连接')
  if (hasRuleReturn.value) return tr('返回规则')
  return PAGES.find((page) => page.id === backTo.value)?.label ?? tr('设置')
})

function goBack() {
  const previous = backTo.value ?? (hasConnectionReturn.value ? 'connections' : hasRuleReturn.value ? 'rules' : null)
  if (historyReady && previous != null && guardActive && layerDepth() === 0) {
    window.history.back()
    return
  }
  if (previous != null && pageStack[pageStack.length - 1] === previous) {
    pageStack.pop()
    backTo.value = pageStack[pageStack.length - 1] ?? null
  }
  ignorePageHistory = true
  store.go(previous ?? 'settings')
}
provide('connectionBack', goBack)
provide('ruleBack', goBack)

// ── System bars & theme-color meta follow the effective theme & palette ──
const prefersDark = ref(typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: dark)').matches === true)
const darkTheme = computed(() => store.theme.value === 'dark' || (store.theme.value === 'system' && prefersDark.value))
watch(darkTheme, (dark) => syncSystemBars(dark), { immediate: true })
watch(
  [darkTheme, store.palette],
  ([dark, palette]) => {
    const meta = getPaletteMeta(palette)
    const content = dark ? meta.dark.bg : meta.light.bg
    document.querySelectorAll('meta[name="theme-color"]').forEach((metaEl) => {
      metaEl.setAttribute('content', content)
    })
  },
  { immediate: true },
)
let darkQuery: MediaQueryList | null = null
function onSchemeChange(event: MediaQueryListEvent) {
  prefersDark.value = event.matches
}

// Add-profile dialog
const addTab = ref<'url' | 'file'>('url')
const url = ref('')
const dragging = ref(false)
const addErrorCleared = ref(true)
const paletteOpen = ref(false)
const helpOpen = ref(false)
const paletteKey = shortcutKeyLabel(getShortcut('palette').combo)
const sidebarKey = shortcutKeyLabel(getShortcut('sidebar').combo)
provide('openShortcuts', () => {
  helpOpen.value = true
})

watch(
  () => store.adding.value,
  (open) => {
    if (open) {
      addErrorCleared.value = true
      dragging.value = false
    }
  },
)

watch(addTab, () => {
  addErrorCleared.value = true
  dragging.value = false
})

const urlLooksLikeNode = computed(() => looksLikeCustomNodeInput(url.value))

function handoffCustomNodeImport(raw = url.value) {
  const value = raw.trim()
  if (!value) return
  store.customNodeImportRequest.value = value
  url.value = ''
  store.adding.value = false
  store.go('profiles')
}

function openCustomNodeSetting() {
  store.adding.value = false
  store.openSettings('general', 'custom-nodes')
}

async function submitUrl() {
  const value = url.value.trim()
  if (!value) return
  if (looksLikeCustomNodeInput(value)) {
    if (store.customNodesVisible.value) handoffCustomNodeImport(value)
    return
  }
  addErrorCleared.value = false
  const before = snap.value.profiles.length
  await store.addSubscription(value)
  if (snap.value.profiles.length > before) {
    url.value = ''
    store.adding.value = false
    store.toast(
      tr('已添加订阅，点击即可启用'),
      'success',
      store.page.value !== 'profiles'
        ? { label: tr('查看配置'), onClick: () => store.go('profiles') }
        : undefined,
    )
    const added = snap.value.profiles[snap.value.profiles.length - 1]
    if (!snap.value.active_id && added) void store.enable(added.id)
  }
}

function onToastMouseLeave(id: number, event: MouseEvent) {
  const el = event.currentTarget as HTMLElement | null
  if (el && document.activeElement && el.contains(document.activeElement)) return
  store.resumeToast(id)
}

function onToastFocusOut(id: number, event: FocusEvent) {
  const el = event.currentTarget as HTMLElement | null
  const next = event.relatedTarget as Node | null
  if (el && next && el.contains(next)) return
  if (el?.matches?.(':hover')) return
  store.resumeToast(id)
}

function runToastAction(item: Toast) {
  const action = item.action
  store.dismissToast(item.id)
  action?.onClick()
}

async function pasteUrl() {
  try {
    const text = await navigator.clipboard.readText()
    if (text) {
      url.value = text.trim()
      addErrorCleared.value = true
    }
  } catch {
    store.toast(tr('无法读取剪贴板，请手动粘贴'), 'error')
  }
}

async function addFile(file: File | undefined) {
  if (!file) return
  addErrorCleared.value = false
  const before = snap.value.profiles.length
  await store.addLocal(file.name.replace(/\.(ya?ml|txt)$/i, ''), await file.text())
  if (snap.value.profiles.length > before) {
    store.adding.value = false
    store.toast(
      tr('已导入 {0}', { 0: file.name }),
      'success',
      store.page.value !== 'profiles'
        ? { label: tr('查看配置'), onClick: () => store.go('profiles') }
        : undefined,
    )
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

function onPaletteSettings(tab: string, focus?: string) {
  paletteOpen.value = false
  store.openSettings(tab as SettingsTab, focus)
}

function onPaletteProfile(id: string) {
  paletteOpen.value = false
  const target = snap.value.profiles.find((item) => item.id === id)
  if (!target) return
  if (target.current) {
    store.go('profiles')
    return
  }
  if (!store.busy[`enable:${id}`]) void store.enable(id)
}

function onPaletteGroup(group: string) {
  paletteOpen.value = false
  store.go('proxies', group)
}

function onPaletteNode(group: string, node: string) {
  paletteOpen.value = false
  const targetGroup = snap.value.node_catalog.find((item) => item.name === group)
  if (targetGroup?.now === node) {
    store.go('proxies', group)
    return
  }
  void store.selectNode(group, node).then((res) => {
    if (res) store.toast(tr('已切换「{0}」至 {1}', { 0: group, 1: node }), 'success')
  })
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
    case 'toggle-system-proxy':
      void store.setSystemProxy(!snap.value.system_proxy)
      break
    case 'toggle-tun':
      void store.setTun(!snap.value.tun)
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
    case 'cycle-palette':
      store.cyclePalette()
      break
    case 'open-logs':
      store.go('logs')
      break
    case 'open-config':
      store.openConfig()
      break
    case 'flush-fakeip':
      void store.flushCache('fakeip')
      break
    case 'flush-dns':
      void store.flushCache('dns')
      break
    case 'dns-query':
      // Opens after the palette has released focus, like the shortcut sheet.
      void nextTick(() => {
        store.dnsQueryOpen.value = true
      })
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
const MAX_PAGE_HISTORY = 100
const pageStack: PageId[] = []

function rememberPage(page: PageId) {
  if (pageStack.length === MAX_PAGE_HISTORY) pageStack.shift()
  pageStack.push(page)
}

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
  if (prev !== next) rememberPage(prev)
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
    if (prev === 'home' && next !== 'home') {
      rememberPage('settings')
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
  store.settingsTab.value = 'home'
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
  backTo.value = pageStack[pageStack.length - 1] ?? null
  if (previous === 'settings' && store.page.value === 'settings' && store.settingsTab.value !== 'home') {
    store.settingsTab.value = 'home'
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

/**
 * Suppress WebView browser chrome menus (`Back / Reload`) on non-editable surfaces
 * while preserving native Cut/Copy/Paste inside inputs, CodeMirror, or selected text.
 */
function onGlobalContextMenu(event: MouseEvent) {
  if (event.defaultPrevented) return
  const target = event.target
  if (target instanceof Element) {
    if (target.closest('input, textarea, [contenteditable="true"], .cm-editor')) return
  }
  const selected = typeof window !== 'undefined' ? window.getSelection?.()?.toString().trim() : ''
  if (selected) return
  event.preventDefault()
}

onMounted(async () => {
  if (chrome.value === 'windows') {
    void isWindowDecorated().then((decorated) => {
      if (!unmounted && decorated) chrome.value = null
    })
  }
  releaseInsets = installInsets()
  void store.backend.onTrayNavigate?.(onTrayNavigate).then((stop) => {
    if (unmounted) stop()
    else releaseTray = stop
  })
  darkQuery = window.matchMedia?.('(prefers-color-scheme: dark)') ?? null
  darkQuery?.addEventListener?.('change', onSchemeChange)
  window.addEventListener('resize', onResize)
  window.addEventListener('popstate', onPopState)
  document.addEventListener('contextmenu', onGlobalContextMenu)
  releaseLayerWatch = onLayerChange(handleLayerDepth)
  await store.start()
  if (!unmounted) initHistory()
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  window.removeEventListener('popstate', onPopState)
  document.removeEventListener('contextmenu', onGlobalContextMenu)
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
        <BrandMark />
        <span class="brand-name">Billow</span>
        <div class="brand-actions" @mousedown.stop>
          <button
            v-if="!sidebarCollapsed"
            type="button"
            class="icon-btn sm theme-quick-btn"
            :aria-label="tr('切换主题（当前：{0}）', { 0: themeMeta.label })"
            :title="tr('切换主题（当前：{0}）', { 0: themeMeta.label })"
            data-testid="sidebar-theme-toggle"
            @click="store.cycleTheme()"
          >
            <Icon :name="themeMeta.icon" :size="15" />
          </button>
          <button
            type="button"
            class="icon-btn sm sidebar-toggle"
            :aria-expanded="!sidebarCollapsed"
            :aria-label="sidebarCollapsed ? tr('展开侧边栏') : tr('收起侧边栏')"
            :title="`${sidebarCollapsed ? tr('展开侧边栏') : tr('收起侧边栏')} (${sidebarKey})`"
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
        :title="sidebarCollapsed ? tr('搜索与命令 ({0})', { 0: paletteKey }) : tr('搜索页面、设置与快捷动作')"
        :aria-label="tr('搜索与命令')"
        data-testid="open-palette"
        @click="paletteOpen = true"
      >
        <Icon name="search" :size="15" />
        <span class="side-search-label">{{ tr('搜索与命令') }}</span>
        <kbd class="palette-kbd">{{ paletteKey }}</kbd>
      </button>
      <nav class="nav" :aria-label="tr('主导航')">
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
          v-if="sidebarCollapsed"
          type="button"
          class="nav-item side-theme-btn"
          :aria-label="tr('切换主题（当前：{0}）', { 0: themeMeta.label })"
          :title="tr('切换主题（当前：{0}）', { 0: themeMeta.label })"
          data-testid="sidebar-theme-toggle"
          @click="store.cycleTheme()"
        >
          <Icon :name="themeMeta.icon" :size="16" />
        </button>
        <button
          type="button"
          class="nav-item"
          :class="{ active: store.page.value === settingsPage.id }"
          :aria-current="store.page.value === settingsPage.id ? 'page' : undefined"
          :aria-label="sidebarCollapsed ? settingsPage.label : undefined"
          :title="`${settingsPage.label}${sidebarCollapsed && store.appUpdate.offer.value ? tr('（有更新）') : ''} (${settingsKey})`"
          :data-page="settingsPage.id"
          @click="store.go(settingsPage.id)"
        >
          <Icon :name="settingsPage.icon" />
          <span class="nav-item-label">{{ settingsPage.label }}</span>
          <span v-if="store.appUpdate.offer.value" class="tag nav-update-tag">{{ tr('更新') }}</span>
        </button>
        <div
          class="side-status"
          :class="{ on: snap.connected && !store.connecting.value, pending: store.connecting.value }"
          :title="sidebarCollapsed ? `${sideStatusWord}${snap.connected ? ` · ${sideMetaText} · ↓${formatSpeed(snap.download ?? 0)} ↑${formatSpeed(snap.upload ?? 0)}` : ''}` : undefined"
          data-testid="side-status"
        >
          <div
            class="side-status-body"
            :class="{ clickable: store.page.value !== 'home' }"
            :role="store.page.value !== 'home' ? 'button' : undefined"
            :tabindex="store.page.value !== 'home' ? 0 : undefined"
            :aria-label="store.page.value !== 'home' ? tr('返回首页') : undefined"
            @click="store.page.value !== 'home' && store.go('home')"
            @keydown.enter.prevent="store.page.value !== 'home' && store.go('home')"
            @keydown.space.prevent="store.page.value !== 'home' && store.go('home')"
          >
            <div class="side-status-head">
              <span>{{ sideStatusWord }}</span>
            </div>
            <template v-if="snap.connected">
              <div class="side-rates mono">
                <span class="down" :title="tr('下载 {0}', { 0: formatSpeed(snap.download ?? 0) })"><Icon name="down" :size="11" /><em class="side-rate-num">{{ formatSpeedCompact(snap.download ?? 0) }}</em><small class="side-rate-unit" aria-hidden="true">/s</small></span>
                <span class="up" :title="tr('上传 {0}', { 0: formatSpeed(snap.upload ?? 0) })"><Icon name="up" :size="11" /><em class="side-rate-num">{{ formatSpeedCompact(snap.upload ?? 0) }}</em><small class="side-rate-unit" aria-hidden="true">/s</small></span>
              </div>
              <div
                class="side-status-meta ellipsis"
                :title="sideMetaText"
                data-testid="side-status-meta"
              >
                <span class="side-mode-badge">{{ sideModeLabel }}</span>
                <span v-if="activeProfileName" class="side-profile-name ellipsis">{{ activeProfileName }}</span>
              </div>
            </template>
            <div v-else class="side-rates muted ellipsis">{{ activeProfileName ?? tr('还没有配置') }}</div>
          </div>
          <button
            v-if="store.hasProfiles.value"
            type="button"
            class="side-power"
            :disabled="store.connecting.value"
            :aria-label="snap.connected ? tr('断开') : tr('连接')"
            :title="sidebarCollapsed ? tr('{0}（点击{1}）', { 0: sideStatusWord, 1: snap.connected ? tr('断开') : tr('连接') }) : (snap.connected ? tr('断开') : tr('连接'))"
            data-testid="side-power"
            @click="store.toggleConnection()"
          >
            <span v-if="store.connecting.value" class="spinner sm" />
            <Icon v-else name="power" :size="16" :stroke="2.2" />
          </button>
          <Icon v-else-if="sidebarCollapsed" name="power" :size="16" class="muted" aria-hidden="true" />
        </div>
      </div>
    </aside>

    <TitleBar v-if="chrome" :chrome="chrome" :brand="compact" />

    <main ref="mainEl" class="main" :data-page="store.page.value">
      <div v-if="showBack" class="back-bar">
        <button
          type="button"
          class="back-btn"
          data-testid="page-back"
          :data-connection-return="hasConnectionReturn ? 'true' : undefined"
          :data-rule-return="hasRuleReturn ? 'true' : undefined"
          @click="goBack"
        >
          <Icon name="chevron-left" :size="18" />
          <span>{{ backLabel }}</span>
        </button>
      </div>
      <div v-else-if="showDesktopConnectionReturn" class="back-bar context-return-bar">
        <button type="button" class="back-btn" data-testid="connection-return" @click="goBack">
          <Icon name="chevron-left" :size="18" />
          <span>{{ tr('返回连接') }}</span>
        </button>
      </div>
      <div v-else-if="showDesktopRuleReturn" class="back-bar context-return-bar">
        <button type="button" class="back-btn" data-testid="rule-return" @click="goBack">
          <Icon name="chevron-left" :size="18" />
          <span>{{ tr('返回规则') }}</span>
        </button>
      </div>
      <component :is="view" v-if="store.loaded.value" :compact="compact" />
      <div
        v-else
        class="page home app-skeleton"
        role="status"
        aria-busy="true"
        aria-live="polite"
        data-testid="app-loading-skeleton"
      >
        <span class="sr-only">{{ tr('正在加载应用状态') }}</span>
        <div class="app-skeleton-hero card" aria-hidden="true">
          <div class="app-skeleton-hero-top">
            <span class="sk-bar sk-pill" />
            <span class="sk-bar sk-pill sm" />
          </div>
          <div class="app-skeleton-hero-main">
            <div class="sk-lines">
              <span class="sk-bar sk-lg sk-w-40" />
              <span class="sk-bar sk-w-60" />
            </div>
            <span class="sk-bar sk-power" />
          </div>
          <div class="app-skeleton-hero-foot">
            <span class="sk-bar sk-w-25" />
            <span class="sk-bar sk-w-30" />
          </div>
        </div>
        <div class="app-skeleton-bento" aria-hidden="true">
          <div class="sk-card">
            <span class="sk-bar sk-w-35" />
            <span class="sk-bar sk-w-80" />
            <span class="sk-bar sk-w-55" />
          </div>
          <div class="sk-card">
            <span class="sk-bar sk-w-40" />
            <span class="sk-bar sk-w-60" />
            <span class="sk-bar sk-w-45" />
          </div>
        </div>
      </div>
    </main>

    <nav v-if="compact" class="tabbar" :aria-label="tr('主导航')">
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
        </span>
        <span class="tab-label">{{ item.label }}</span>
      </button>
    </nav>

    <CommandPalette
      :open="paletteOpen"
      :platform="isAndroid ? 'android' : 'desktop'"
      :connected="snap.connected"
      :kernel-running="snap.kernel_running"
      :has-profiles="store.hasProfiles.value"
      :system-proxy="snap.system_proxy"
      :tun="snap.tun"
      :profiles="snap.profiles"
      :node-catalog="snap.node_catalog"
      :current-page="store.page.value"
      :mode="snap.mode"
      :sidebar-collapsed="sidebarCollapsed"
      @navigate="onPaletteNavigate"
      @open-settings="onPaletteSettings"
      @action="onPaletteAction"
      @select-profile="onPaletteProfile"
      @open-group="onPaletteGroup"
      @select-node="onPaletteNode"
      @close="paletteOpen = false"
    />

    <ConfigViewer v-if="store.configView.value" />

    <DnsQueryDialog
      v-if="store.dnsQueryOpen.value"
      :running="snap.kernel_running"
      :query="store.dnsQuery"
      :compact="compact"
      @close="store.dnsQueryOpen.value = false"
    />

    <Modal :open="helpOpen" :title="tr('快捷键')" @close="helpOpen = false">
      <div class="shortcut-sheet" :class="{ 'has-global': !isAndroid }">
        <section class="shortcut-group">
          <header class="shortcut-group-head">
            <h3>{{ tr('应用内') }}</h3>
            <p class="muted small">{{ tr('在应用内生效，输入框会保留自己的按键') }}</p>
          </header>
          <dl class="shortcut-list">
            <div v-for="shortcut in SHORTCUTS" :key="shortcut.id" class="shortcut-row" :title="shortcut.description">
              <dt><kbd class="palette-kbd">{{ shortcutKeyLabel(shortcut.combo) }}</kbd></dt>
              <dd>{{ shortcut.label }}</dd>
            </div>
          </dl>
        </section>
        <HotkeySection v-if="!isAndroid" />
      </div>
    </Modal>

    <Modal :open="store.adding.value" :title="tr('添加配置')" :subtitle="tr('订阅链接或 Clash / Mihomo YAML 文件')" @close="store.adding.value = false">
      <div
        class="add-modal-drop"
        :class="{ 'drop-over': dragging && addTab === 'url' }"
        @dragover.prevent="dragging = true"
        @dragleave.self="dragging = false"
        @drop.prevent="onDrop"
      >
        <div class="tabs-inline" role="tablist">
          <button type="button" role="tab" :class="{ active: addTab === 'url' }" :aria-selected="addTab === 'url'" @click="addTab = 'url'">
            <Icon name="link" :size="16" /> {{ tr('订阅链接') }} </button>
          <button type="button" role="tab" :class="{ active: addTab === 'file' }" :aria-selected="addTab === 'file'" @click="addTab = 'file'">
            <Icon name="file" :size="16" /> {{ tr('本地文件') }} </button>
        </div>
        <form v-if="addTab === 'url'" class="stack" data-testid="add-url" @submit.prevent="submitUrl">
          <label class="field">
            <span>{{ tr('订阅地址') }}</span>
            <div class="input-group">
              <!-- Phones open the sheet without the keyboard; paste or tap the field to type. -->
              <input
                v-model="url"
                type="text"
                inputmode="url"
                enterkeyhint="go"
                placeholder="https://…"
                autocomplete="off"
                spellcheck="false"
                :autofocus="!compact"
                @input="addErrorCleared = true"
              />
              <button type="button" class="btn ghost" :title="tr('从剪贴板粘贴')" data-testid="paste-url" @click="pasteUrl"><Icon name="clipboard" :size="16" />{{ tr('粘贴') }}</button>
            </div>
          </label>
          <p v-if="snap.input_error && !addErrorCleared" class="field-error" role="alert">{{ snap.input_error }}</p>
          <div v-if="urlLooksLikeNode" class="add-node-notice" data-testid="add-node-detected" role="status">
            <Icon name="sparkles" :size="16" />
            <div class="add-node-notice-body">
              <strong>{{ tr('识别为自建节点链接') }}</strong>
              <p class="muted small">
                {{
                  store.customNodesVisible.value
                    ? tr('这不是订阅地址，将转入自建节点导入并自动预填内容。')
                    : tr('自建节点功能当前已关闭，开启后即可导入并管理单个节点链接。')
                }}
              </p>
            </div>
          </div>
          <template v-if="urlLooksLikeNode && store.customNodesVisible.value">
            <button type="submit" class="btn primary block" data-testid="add-to-custom-nodes">
              {{ tr('转入自建节点导入') }}
            </button>
          </template>
          <template v-else-if="urlLooksLikeNode">
            <button type="button" class="btn primary block" data-testid="add-enable-custom-nodes" @click="openCustomNodeSetting">
              {{ tr('前往开启') }}
            </button>
          </template>
          <template v-else>
            <p class="muted small">{{ tr('添加后会下载订阅内容，并读取流量与到期信息；也可直接拖入 YAML 文件。') }}</p>
            <button type="submit" class="btn primary block" :disabled="!url.trim() || store.busy.add">
              <span v-if="store.busy.add" class="spinner sm" /> {{ tr('添加订阅') }} </button>
          </template>
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
            <strong>{{ tr('拖入 YAML 配置文件') }}</strong>
            <span class="muted small">{{ tr('或点击选择文件') }}</span>
            <input type="file" accept=".yaml,.yml,.txt,text/yaml" hidden @change="onFile" />
          </label>
          <p v-if="snap.input_error && !addErrorCleared" class="field-error" role="alert">{{ snap.input_error }}</p>
        </div>
      </div>
    </Modal>

    <Modal :open="Boolean(snap.pending_url)" :title="tr('导入订阅')" :subtitle="tr('来自外部链接的订阅，确认后才会添加')" @close="store.cancelInstall()">
      <p class="url-box mono">{{ snap.pending_url }}</p>
      <template #footer>
        <button type="button" class="btn ghost" @click="store.cancelInstall()">{{ tr('取消') }}</button>
        <button type="button" class="btn primary" @click="store.confirmInstall()">{{ tr('添加') }}</button>
      </template>
    </Modal>

    <div class="toasts" aria-live="polite">
      <TransitionGroup name="toast">
        <div
          v-for="item in store.toasts.value"
          :key="item.id"
          class="toast"
          :class="[item.tone, { 'has-action': Boolean(item.action) }]"
          :role="item.tone === 'error' ? 'alert' : 'status'"
          :title="tr('点击关闭')"
          @mouseenter="store.pauseToast(item.id)"
          @mouseleave="onToastMouseLeave(item.id, $event)"
          @focusin="store.pauseToast(item.id)"
          @focusout="onToastFocusOut(item.id, $event)"
          @click="store.dismissToast(item.id)"
        >
          <Icon :name="item.tone === 'error' ? 'alert' : item.tone === 'success' ? 'check' : 'info'" :size="16" />
          <span class="grow">{{ item.text }}</span>
          <button
            v-if="item.action"
            type="button"
            class="toast-action"
            data-testid="toast-action"
            @click.stop="runToastAction(item)"
          >
            {{ item.action.label }}
          </button>
        </div>
      </TransitionGroup>
    </div>
  </div>
</template>
