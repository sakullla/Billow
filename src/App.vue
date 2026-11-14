<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { NAV_ITEMS, PRODUCT_NAME, type EntryId, type ThemePreference } from './copy'
import { layoutForWidth, resolveEntry } from './navigation'
import { createShellPort, type ShellPort } from './port'
import { applyTheme, resolveTheme } from './theme'
import HomeView from './views/HomeView.vue'
import NodesView from './views/NodesView.vue'
import SettingsView from './views/SettingsView.vue'

const props = defineProps<{
  port?: ShellPort
  initialWidth?: number
}>()

const entry = ref<EntryId>('home')
const theme = ref<ThemePreference>('system')
const width = ref(typeof props.initialWidth === 'number' ? props.initialWidth : window.innerWidth)
const layout = computed(() => layoutForWidth(width.value))

let port: ShellPort | null = props.port ?? null
let persist = false
let resolveReady = () => {}
const ready = new Promise<void>((resolve) => {
  resolveReady = resolve
})

function readWidth() {
  if (typeof props.initialWidth === 'number') {
    width.value = props.initialWidth
    return
  }
  width.value = window.innerWidth
}

watch(
  () => props.initialWidth,
  () => readWidth(),
)

watch(
  theme,
  (value) => {
    applyTheme(value)
    if (!persist || !port) return
    void port.saveTheme(value).catch((error: unknown) => {
      console.error(error)
    })
  },
  { flush: 'sync' },
)

function choose(next: EntryId) {
  entry.value = next
  if (!persist || !port) return
  void port.saveEntry(next).catch((error: unknown) => {
    console.error(error)
  })
}

onMounted(async () => {
  readWidth()
  window.addEventListener('resize', readWidth)
  try {
    port = props.port ?? createShellPort()
    const snapshot = await port.load()
    const nextEntry = resolveEntry(snapshot.entry)
    const nextTheme = resolveTheme(snapshot.theme)
    persist = true
    entry.value = nextEntry
    theme.value = nextTheme
    applyTheme(nextTheme)
    if (snapshot.entry !== nextEntry) await port.saveEntry(nextEntry)
    if (snapshot.theme !== nextTheme) await port.saveTheme(nextTheme)
  } catch (error) {
    console.error(error)
    persist = true
    entry.value = 'home'
    theme.value = 'system'
    applyTheme('system')
  } finally {
    resolveReady()
  }
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', readWidth)
  resolveReady()
})

defineExpose({ ready })
</script>

<template>
  <div class="app" :data-layout="layout">
    <nav v-if="layout === 'sidebar'" class="sidebar" aria-label="主导航">
      <p class="brand">{{ PRODUCT_NAME }}</p>
      <button
        v-for="item in NAV_ITEMS"
        :key="item.id"
        type="button"
        class="nav-button"
        :data-entry="item.id"
        :aria-current="entry === item.id ? 'page' : undefined"
        @click="choose(item.id)"
      >
        {{ item.label }}
      </button>
    </nav>
    <main class="main">
      <HomeView v-if="entry === 'home'" />
      <NodesView v-else-if="entry === 'nodes'" />
      <SettingsView v-else v-model="theme" />
    </main>
    <nav v-if="layout === 'bottom'" class="bottom-nav" aria-label="主导航">
      <button
        v-for="item in NAV_ITEMS"
        :key="item.id"
        type="button"
        class="nav-button"
        :data-entry="item.id"
        :aria-current="entry === item.id ? 'page' : undefined"
        @click="choose(item.id)"
      >
        {{ item.label }}
      </button>
    </nav>
  </div>
</template>
