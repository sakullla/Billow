<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, provide, ref, watch } from 'vue'
import CommandPalette from './components/CommandPalette.vue'
import Icon from './components/Icon.vue'
import Modal from './components/Modal.vue'
import { createBackend, type Backend } from './lib/backend'
import { formatSpeed } from './lib/format'
import { createStore, PAGES, resolvePage, STORE, type PageId, type SettingsTab } from './lib/store'
import { hasOpenOverlay } from './lib/ui/focus'
import { useHotkeys } from './lib/ui/hotkeys'
import { SHORTCUTS, shortcutBindings, shortcutKeyLabel } from './lib/ui/shortcuts'
import ConnectionsView from './views/ConnectionsView.vue'
import HomeView from './views/HomeView.vue'
import LogsView from './views/LogsView.vue'
import ProfilesView from './views/ProfilesView.vue'
import ProxiesView from './views/ProxiesView.vue'
import ResourcesView from './views/ResourcesView.vue'
import RulesView from './views/RulesView.vue'
import SettingsView from './views/SettingsView.vue'

const props = defineProps<{ backend?: Backend; width?: number }>()

const store = createStore(props.backend ?? createBackend())
provide(STORE, store)

const width = ref(props.width ?? (typeof window !== 'undefined' ? window.innerWidth : 1024))
const compact = computed(() => width.value < 760)
const snap = computed(() => store.snapshot.value)

const views = {
  home: HomeView,
  proxies: ProxiesView,
  profiles: ProfilesView,
  connections: ConnectionsView,
  rules: RulesView,
  resources: ResourcesView,
  logs: LogsView,
  settings: SettingsView,
} as const
const view = computed(() => views[store.page.value])
const mobilePages = PAGES.filter((page) => page.mobile)
const navGroups = [
  { id: 'core', label: '核心', pages: PAGES.filter((page) => page.group === 'core') },
  { id: 'tools', label: '工具', pages: PAGES.filter((page) => page.group === 'tools') },
]
const settingsPage = PAGES.find((page) => page.id === 'settings')!
const TOOL_PAGES: readonly PageId[] = ['rules', 'resources', 'logs']

/** Rules/resources/logs live behind Settings on mobile, so Settings is the current tab there. */
function isTabCurrent(id: PageId): boolean {
  return store.page.value === id || (id === 'settings' && TOOL_PAGES.includes(store.page.value))
}

// Add-profile dialog
const addTab = ref<'url' | 'file'>('url')
const url = ref('')
const dragging = ref(false)
const paletteOpen = ref(false)
const helpOpen = ref(false)

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
    case 'toggle-theme':
      store.cycleTheme()
      break
    case 'open-logs':
      store.go('logs')
      break
  }
}

// ── Shortcuts ──
/** Menus are plain popovers (not focus traps), so check both before claiming a global key. */
function layerOpen(): boolean {
  return hasOpenOverlay() || Boolean(document.querySelector('[role="menu"]'))
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
      search: focusSearch,
      escape: clearSearch,
      help: () => {
        helpOpen.value = true
      },
    },
    { allowInInput: ['escape'] },
  ).map((binding) => ({ ...binding, when: () => !layerOpen() })),
)

// ── Scroll memory (R25) ──
const mainEl = ref<HTMLElement | null>(null)
const scrollPositions = new Map<PageId, number>()

async function restorePageScroll(page: PageId) {
  await nextTick()
  if (store.page.value !== page) return
  const main = mainEl.value
  if (!main) return
  // A group target owns the landing position on the proxy page (D2).
  if (page === 'proxies' && store.focusGroup.value) return
  main.scrollTop = scrollPositions.get(page) ?? 0
}

watch(
  () => store.page.value,
  (next, prev) => {
    if (mainEl.value && prev) scrollPositions.set(prev, mainEl.value.scrollTop)
    recordPageHistory(next)
    void restorePageScroll(next)
  },
)

function onResize() {
  if (props.width == null) width.value = window.innerWidth
  // Window size changes invalidate saved offsets; start the current page at the top (R25).
  scrollPositions.clear()
  if (mainEl.value) mainEl.value.scrollTop = 0
}

// ── Android back bridge (R30) ──
// Tauri Android forwards hardware back to the WebView history. We keep one guarded
// history entry while any dialog/palette/menu is open: a back press pops that entry
// and closes the topmost layer (Escape reaches the focus trap or the keyboard menu).
// Page switches push their own entries so the next back returns to the previous page.
// With no Billow entry left, popstate is ignored and the platform handles the exit.
interface BillowHistoryState {
  billow?: 'page' | 'overlay'
  page?: PageId
}

let historyReady = false
let ignorePageHistory = false
let overlayHistory = false
let suppressPop = 0
let layerObserver: MutationObserver | null = null

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

function recordPageHistory(page: PageId) {
  if (!historyReady || ignorePageHistory) {
    ignorePageHistory = false
    return
  }
  // Navigating from the palette closes its overlay in the same tick; turn the guard
  // entry into the page entry instead of stacking a page above a stale guard.
  if (overlayHistory) {
    overlayHistory = false
    replaceHistory({ billow: 'page', page })
    return
  }
  pushHistory({ billow: 'page', page })
}

function layerCount(): number {
  return document.querySelectorAll('.overlay, [role="menu"]').length
}

function syncOverlayHistory() {
  const count = layerCount()
  if (count > 0 && !overlayHistory) {
    overlayHistory = true
    pushHistory({ billow: 'overlay' })
  } else if (count === 0 && overlayHistory) {
    overlayHistory = false
    // The guard is only removable while it is the current entry. If a page push
    // already happened above it, leave it for the popstate handler to ignore.
    if (window.history?.state?.billow === 'overlay') {
      suppressPop += 1
      window.history.back()
    }
  }
}

function closeTopLayer() {
  const active = document.activeElement
  const target = active instanceof HTMLElement && active !== document.body ? active : document
  target.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }))
}

async function closeLayerFromBack() {
  closeTopLayer()
  await nextTick()
  if (layerCount() > 0 && !overlayHistory && !hasOpenOverlay()) {
    // Inline menus that predate the shared Menu only close on an outside click.
    document.body.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await nextTick()
  }
  // Dialogs may keep themselves open (e.g. an unsaved-editor guard); restore the
  // guard entry so the next back press is still handled by the layer.
  if (layerCount() > 0 && !overlayHistory) {
    overlayHistory = true
    pushHistory({ billow: 'overlay' })
  }
}

function onPopState(event: PopStateEvent) {
  if (suppressPop > 0) {
    suppressPop -= 1
    return
  }
  const state = event.state as BillowHistoryState | null
  if (layerCount() > 0) {
    if (state?.billow === 'overlay') overlayHistory = false
    void closeLayerFromBack()
    return
  }
  if (state?.billow === 'page' && state.page && state.page !== store.page.value) {
    ignorePageHistory = true
    store.go(state.page)
  }
  // `state === null` means no Billow entry is left; let the system handle the back.
}

function initHistory() {
  if (typeof window === 'undefined' || !window.history) return
  replaceHistory({ billow: 'page', page: store.page.value })
  historyReady = true
}

onMounted(async () => {
  window.addEventListener('resize', onResize)
  window.addEventListener('popstate', onPopState)
  if (typeof MutationObserver !== 'undefined') {
    layerObserver = new MutationObserver(syncOverlayHistory)
    layerObserver.observe(document.body, { childList: true, subtree: true })
  }
  await store.start()
  initHistory()
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  window.removeEventListener('popstate', onPopState)
  layerObserver?.disconnect()
  store.stop()
})

defineExpose({ store })
</script>

<template>
  <div class="shell" :class="{ compact }">
    <aside v-if="!compact" class="sidebar">
      <div class="brand">
        <span class="brand-mark"><Icon name="logo" :size="20" :stroke="2" /></span>
        <span class="brand-name">Billow</span>
      </div>
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
            :data-page="item.id"
            @click="store.go(item.id)"
          >
            <Icon :name="item.icon" />
            <span>{{ item.label }}</span>
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
          :data-page="settingsPage.id"
          @click="store.go(settingsPage.id)"
        >
          <Icon :name="settingsPage.icon" />
          <span>{{ settingsPage.label }}</span>
        </button>
        <div class="side-status" :class="{ on: snap.connected }">
          <div class="side-status-head">
            <span class="dot" />
            <span>{{ store.connecting.value ? '连接中…' : snap.connected ? '已连接' : '未连接' }}</span>
          </div>
          <div v-if="snap.connected" class="side-rates mono">
            <span><Icon name="up" :size="12" />{{ formatSpeed(snap.upload ?? 0) }}</span>
            <span><Icon name="down" :size="12" />{{ formatSpeed(snap.download ?? 0) }}</span>
          </div>
          <div v-else class="side-rates muted small">{{ store.current.value?.name ?? '还没有配置' }}</div>
        </div>
      </div>
    </aside>

    <main ref="mainEl" class="main" :data-page="store.page.value">
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
        <Icon :name="item.icon" :size="21" />
        <span>{{ item.label }}</span>
      </button>
    </nav>

    <CommandPalette
      v-if="paletteOpen"
      :platform="isAndroid ? 'android' : 'desktop'"
      :connected="snap.connected"
      :has-profiles="snap.profiles.length > 0"
      @navigate="onPaletteNavigate"
      @open-settings="onPaletteSettings"
      @action="onPaletteAction"
      @close="paletteOpen = false"
    />

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
            <input v-model="url" type="url" placeholder="https://…" autocomplete="off" spellcheck="false" autofocus />
            <button type="button" class="btn ghost" title="从剪贴板粘贴" @click="pasteUrl"><Icon name="clipboard" :size="16" /></button>
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
        <div v-for="item in store.toasts.value" :key="item.id" class="toast" :class="item.tone">
          <Icon :name="item.tone === 'error' ? 'alert' : item.tone === 'success' ? 'check' : 'info'" :size="16" />
          <span>{{ item.text }}</span>
        </div>
      </TransitionGroup>
    </div>
  </div>
</template>
