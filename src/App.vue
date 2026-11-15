<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, provide, ref } from 'vue'
import Icon from './components/Icon.vue'
import Modal from './components/Modal.vue'
import { createBackend, type Backend } from './lib/backend'
import { formatSpeed } from './lib/format'
import { createStore, PAGES, STORE } from './lib/store'
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

// Add-profile dialog
const addTab = ref<'url' | 'file'>('url')
const url = ref('')
const dragging = ref(false)

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

function onResize() {
  if (props.width == null) width.value = window.innerWidth
}

onMounted(() => {
  window.addEventListener('resize', onResize)
  void store.start()
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
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
        <button
          v-for="item in PAGES"
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
      </nav>
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
    </aside>

    <main class="main" :data-page="store.page.value">
      <component :is="view" v-if="store.loaded.value" :compact="compact" />
      <div v-else class="loading"><span class="spinner" /></div>
    </main>

    <nav v-if="compact" class="tabbar" aria-label="主导航">
      <button
        v-for="item in mobilePages"
        :key="item.id"
        type="button"
        class="tab"
        :class="{ active: store.page.value === item.id || (item.id === 'settings' && ['rules', 'logs', 'resources'].includes(store.page.value)) }"
        :aria-current="store.page.value === item.id ? 'page' : undefined"
        :data-page="item.id"
        @click="store.go(item.id)"
      >
        <Icon :name="item.icon" :size="21" />
        <span>{{ item.label }}</span>
      </button>
    </nav>

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
