<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import {
  ACTION_CANCEL,
  ACTION_CONFIRM,
  INSTALL_PROMPT,
  NAV_ITEMS,
  PRODUCT_NAME,
  type EntryId,
  type KernelChannel,
  type ThemePreference,
} from './copy'
import { createKernelPort, createMemoryKernelPort, type KernelPort } from './kernel-port'
import { resolveKernelChannel } from './kernel'
import { layoutForWidth, resolveEntry } from './navigation'
import { createShellPort, type ShellPort } from './port'
import { createMemoryProfilePort, createProfilePort, type ProfilePort } from './profile-port'
import { DIAGNOSTICS_SAMPLE_MS, emptyProfileSnapshot, type ProfileSnapshot } from './profile'
import { applyTheme, resolveTheme } from './theme'
import type { LogFilter } from './copy'
import { normalizeLogFilter } from './profile'
import DiagnosticsView from './views/DiagnosticsView.vue'
import HomeView from './views/HomeView.vue'
import NodesView from './views/NodesView.vue'
import SettingsView from './views/SettingsView.vue'

const props = defineProps<{
  port?: ShellPort
  kernelPort?: KernelPort
  profilePort?: ProfilePort
  initialWidth?: number
}>()

const entry = ref<EntryId>('home')
const diagnostics = ref(false)
const theme = ref<ThemePreference>('system')
const kernelChannel = ref<KernelChannel>('stable')
const kernelFailure = ref<string | null>(null)
const profileState = ref<ProfileSnapshot>(emptyProfileSnapshot())
const connecting = ref(false)
const width = ref(typeof props.initialWidth === 'number' ? props.initialWidth : window.innerWidth)
const layout = computed(() => layoutForWidth(width.value))
const currentProfile = computed(
  () => profileState.value.profiles.find((profile) => profile.current) ?? null,
)
const nodesSearchable = computed(
  () => profileState.value.node_catalog.length > 0 || profileState.value.node_query.trim().length > 0,
)

let port: ShellPort | null = props.port ?? null
const kernel: KernelPort = props.kernelPort ?? (props.port ? createMemoryKernelPort() : createKernelPort())
const profile: ProfilePort =
  props.profilePort ?? (props.port ? createMemoryProfilePort() : createProfilePort())
let kernelEpoch = 0
let profileQueue: Promise<void> = Promise.resolve()
let profilePending = 0
let diagnosticsTimer: ReturnType<typeof setInterval> | null = null
let unsubscribeProfile = () => {}
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

async function refreshKernel() {
  const epoch = ++kernelEpoch
  try {
    const snapshot = await kernel.load()
    if (epoch !== kernelEpoch) return
    kernelChannel.value = resolveKernelChannel(snapshot.channel)
    kernelFailure.value = snapshot.failure
  } catch (error) {
    console.error(error)
    if (epoch !== kernelEpoch) return
    kernelFailure.value = '内核状态没有读取'
  }
}

async function changeKernel(next: KernelChannel) {
  const epoch = ++kernelEpoch
  try {
    const snapshot = await kernel.setChannel(next)
    if (epoch !== kernelEpoch) return
    kernelChannel.value = resolveKernelChannel(snapshot.channel)
    kernelFailure.value = snapshot.failure
  } catch (error) {
    console.error(error)
    if (epoch !== kernelEpoch) return
    kernelFailure.value = '内核下载失败'
  }
}

function applyProfile(snapshot: ProfileSnapshot) {
  profileState.value = snapshot
}

function enqueueProfile(action: () => Promise<ProfileSnapshot>): Promise<void> {
  profilePending += 1
  const run = profileQueue.then(async () => {
    try {
      applyProfile(await action())
    } catch (error) {
      console.error(error)
    } finally {
      profilePending -= 1
    }
  })
  profileQueue = run.then(
    () => undefined,
    () => undefined,
  )
  return run
}

function refreshProfiles() {
  return enqueueProfile(() => profile.load())
}

function runProfile(action: () => Promise<ProfileSnapshot>) {
  return enqueueProfile(action)
}

function stopDiagnosticsSample() {
  if (diagnosticsTimer != null) {
    clearInterval(diagnosticsTimer)
    diagnosticsTimer = null
  }
}

function enableProfile(id: string) {
  void runProfile(() => profile.enable(id))
}

function updateProfile(id: string) {
  void runProfile(() => profile.update(id))
}

function saveOverride(id: string, text: string) {
  void runProfile(() => profile.saveOverride(id, text))
}

function addSubscription(url: string) {
  void runProfile(() => profile.addSubscription(url))
}

function addLocal(name: string, content: string) {
  void runProfile(() => profile.addLocal(name, content))
}

function confirmInstall() {
  void runProfile(() => profile.confirmInstall())
}

function cancelInstall() {
  void runProfile(() => profile.cancelInstall())
}

function connectSession() {
  if (connecting.value) return
  connecting.value = true
  void runProfile(() => profile.connect()).finally(() => {
    connecting.value = false
  })
}

function disconnectSession() {
  if (connecting.value) return
  connecting.value = true
  void runProfile(() => profile.disconnect()).finally(() => {
    connecting.value = false
  })
}

function setSystemProxy(enabled: boolean) {
  void runProfile(() => profile.setSystemProxy(enabled))
}

function setTun(enabled: boolean) {
  void runProfile(() => profile.setTun(enabled))
}

function excludePackage(packageName: string) {
  void runProfile(() => profile.excludePackage(packageName))
}

function includePackage(packageName: string) {
  void runProfile(() => profile.includePackage(packageName))
}

function selectNode(group: string, node: string) {
  void runProfile(() => profile.selectNode(group, node))
}

function testGroup(group: string) {
  void runProfile(() => profile.testGroup(group))
}

function setNodeQuery(query: string) {
  void runProfile(() => profile.setNodeQuery(query))
}

function setNodeSort(group: string, sort: string) {
  void runProfile(() => profile.setNodeSort(group, sort))
}

function openDiagnostics() {
  diagnostics.value = true
}

watch(diagnostics, (open) => {
  stopDiagnosticsSample()
  if (!open) return
  // profile_state is the existing sampler. Connections and logs have no push channel.
  void refreshProfiles()
  diagnosticsTimer = setInterval(() => {
    if (!diagnostics.value || profilePending > 0) return
    void refreshProfiles()
  }, DIAGNOSTICS_SAMPLE_MS)
})

function setConnectionQuery(query: string) {
  void runProfile(() => profile.setConnectionQuery(query))
}

function setLogFilter(level: LogFilter) {
  void runProfile(() => profile.setLogFilter(normalizeLogFilter(level)))
}

async function choose(next: EntryId) {
  diagnostics.value = false
  entry.value = next
  if (persist && port) {
    void port.saveEntry(next).catch((error: unknown) => {
      console.error(error)
    })
  }
  if (next === 'settings') await refreshKernel()
  if (next === 'nodes') await refreshProfiles()
}

onMounted(async () => {
  readWidth()
  window.addEventListener('resize', readWidth)
  const kernelLoad = refreshKernel()
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
    await refreshProfiles()
    resolveReady()
  }
  unsubscribeProfile =
    profile.subscribe?.((snapshot) => {
      void enqueueProfile(async () => snapshot)
    }) ?? (() => {})
  await kernelLoad
})

onBeforeUnmount(() => {
  stopDiagnosticsSample()
  unsubscribeProfile()
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
      <div
        v-if="profileState.pending_url"
        class="card dialog"
        data-testid="install-confirm"
        role="dialog"
        aria-modal="true"
      >
        <p>{{ INSTALL_PROMPT }}</p>
        <p data-testid="install-url">{{ profileState.pending_url }}</p>
        <div class="row-actions">
          <button type="button" class="btn-primary" data-testid="install-confirm-yes" @click="confirmInstall">
            {{ ACTION_CONFIRM }}
          </button>
          <button type="button" class="btn" data-testid="install-cancel" @click="cancelInstall">
            {{ ACTION_CANCEL }}
          </button>
        </div>
      </div>
      <DiagnosticsView
        v-if="diagnostics"
        :connected="profileState.connected"
        :connections="profileState.connections"
        :connection-query="profileState.connection_query"
        :logs="profileState.logs"
        :log-filter="profileState.log_filter"
        @close="diagnostics = false"
        @query="setConnectionQuery"
        @log-filter="setLogFilter"
      />
      <HomeView
        v-else-if="entry === 'home'"
        :failure="profileState.failure"
        :used="currentProfile?.used ?? null"
        :total="currentProfile?.total ?? null"
        :expire="currentProfile?.expire ?? null"
        :mixed-port="profileState.mixed_port"
        :platform="profileState.platform"
        :connected="profileState.connected"
        :connecting="connecting"
        :system-proxy="profileState.system_proxy"
        :tun="profileState.tun"
        :vpn="profileState.vpn"
        :excluded="profileState.excluded"
        :installed="profileState.installed"
        @connect="connectSession"
        @disconnect="disconnectSession"
        @system-proxy="setSystemProxy"
        @tun="setTun"
        @exclude="excludePackage"
        @include="includePackage"
        @diagnostics="openDiagnostics"
      />
      <NodesView
        v-else-if="entry === 'nodes'"
        :groups="profileState.node_groups"
        :query="profileState.node_query"
        :notice="profileState.nodes_notice"
        :error="profileState.nodes_error"
        :searchable="nodesSearchable"
        @query="setNodeQuery"
        @sort="setNodeSort"
        @select="selectNode"
        @test="testGroup"
      />
      <SettingsView
        v-else
        v-model="theme"
        :channel="kernelChannel"
        :failure="kernelFailure"
        :profiles="profileState"
        @update:channel="changeKernel"
        @enable="enableProfile"
        @update="updateProfile"
        @save-override="saveOverride"
        @add-subscription="addSubscription"
        @add-local="addLocal"
      />
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
