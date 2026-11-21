<script setup lang="ts">
import type { Component } from 'vue'
import Icon from '../../components/Icon.vue'
import { paneOf, type CategoryId } from '../../lib/settings/catalog'
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
 * The panes of one settings page. A page with a single pane renders it as is;
 * a page with several (网络, 数据与关于) folds each pane behind a heading row so
 * the page opens short and the user unfolds only what they need. Folded panes
 * stay mounted, so search and deep links can still find their rows.
 */
defineProps<{
  panes: readonly CategoryId[]
  /** Pane unfolded when the page opens. */
  open?: CategoryId
  compact?: boolean
}>()

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
  <div v-else class="settings-stack">
    <details v-for="id in panes" :key="id" class="pane-fold" :open="open === id" :data-pane-fold="id">
      <summary class="pane-fold-head">
        <span class="pane-fold-text">
          <strong>{{ paneOf(id).label() }}</strong>
          <span>{{ paneOf(id).description() }}</span>
        </span>
        <Icon name="chevron-right" :size="16" class="pane-fold-chevron" />
      </summary>
      <div class="settings-pane" :data-pane="id">
        <component :is="PANES[id]" :compact="compact" />
      </div>
    </details>
  </div>
</template>
