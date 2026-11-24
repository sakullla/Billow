<script setup lang="ts">
import { computed, type Component } from 'vue'
import { tr } from '../../lib/i18n'
import { paneOf, type CategoryId } from '../../lib/settings/catalog'
import { useStore } from '../../lib/store'
import AboutPane from './AboutPane.vue'
import BehaviorPane from './BehaviorPane.vue'
import DataPane from './DataPane.vue'
import DnsPane from './DnsPane.vue'
import GeneralPane from './GeneralPane.vue'
import KernelPane from './KernelPane.vue'
import NetworkPane from './NetworkPane.vue'
import ProxyPane from './ProxyPane.vue'
import TunPane from './TunPane.vue'

/**
 * Renders the panes belonging to one settings category:
 * - Single pane: rendered directly.
 * - `layout === 'tabs'` (System Proxy & TUN): crisp segmented switcher with live status pills, zero accordions.
 * - `layout === 'stack'` (Backup & About): flat vertical sections, everything immediately visible.
 */
const props = defineProps<{
  panes: readonly CategoryId[]
  layout?: 'tabs' | 'stack'
  /** Active sub-tab when `layout === 'tabs'`. */
  activePane?: CategoryId
  compact?: boolean
}>()

const emit = defineEmits<{ select: [id: CategoryId] }>()

const store = useStore()
const snap = computed(() => store.snapshot.value)

const currentSubPane = computed<CategoryId>(() =>
  props.activePane && props.panes.includes(props.activePane) ? props.activePane : props.panes[0]!,
)

function subTabStatus(id: CategoryId): { on: boolean; label: string } | null {
  if (id === 'proxy') return { on: snap.value.system_proxy, label: snap.value.system_proxy ? tr('已开启') : tr('已关闭') }
  if (id === 'tun') return { on: snap.value.tun, label: snap.value.tun ? tr('已开启') : tr('已关闭') }
  return null
}

const PANES: Record<CategoryId, Component> = {
  general: GeneralPane,
  proxy: ProxyPane,
  tun: TunPane,
  network: NetworkPane,
  behavior: BehaviorPane,
  dns: DnsPane,
  kernel: KernelPane,
  backup: DataPane,
  about: AboutPane,
}
</script>

<template>
  <div v-if="panes.length === 1" class="settings-pane" :data-pane="panes[0]">
    <component :is="PANES[panes[0]!]" :compact="compact" />
  </div>
  <div v-else-if="layout === 'tabs'" class="settings-subtabs-wrap">
    <div class="settings-subtabs" role="tablist" :aria-label="tr('子分类')" data-testid="settings-subtabs">
      <button
        v-for="id in panes"
        :key="id"
        type="button"
        role="tab"
        class="settings-subtab"
        :class="{ active: currentSubPane === id }"
        :aria-selected="currentSubPane === id"
        :data-subtab="id"
        :data-testid="`subtab-${id}`"
        @click="emit('select', id)"
      >
        <span class="settings-subtab-label">{{ paneOf(id).label() }}</span>
        <span
          v-if="subTabStatus(id)"
          class="settings-subtab-state"
          :class="{ on: subTabStatus(id)!.on }"
          :data-testid="`pane-status-${id}`"
        >{{ subTabStatus(id)!.label }}</span>
      </button>
    </div>
    <div :key="currentSubPane" class="settings-pane" :data-pane="currentSubPane">
      <component :is="PANES[currentSubPane]" :compact="compact" />
    </div>
  </div>
  <div v-else class="settings-pane settings-flat-stack">
    <div v-for="id in panes" :key="id" class="settings-pane-block" :data-pane="id">
      <component :is="PANES[id]" :compact="compact" />
    </div>
  </div>
</template>
