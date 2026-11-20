<script setup lang="ts">import { tr } from '../lib/i18n'

import { onBeforeUnmount, onMounted, ref } from 'vue'
import BrandMark from './BrandMark.vue'
import { closeWindow, minimizeWindow, toggleMaximizeWindow, watchMaximized, type WindowChrome } from '../lib/ui/windowChrome'

const props = defineProps<{ chrome: Exclude<WindowChrome, null>; brand?: boolean }>()

const maximized = ref(false)
let release: (() => void) | null = null
let disposed = false

onMounted(async () => {
  if (props.chrome !== 'windows') return
  const stop = await watchMaximized((value) => (maximized.value = value))
  if (disposed) stop()
  else release = stop
})
onBeforeUnmount(() => {
  disposed = true
  release?.()
})
</script>

<template>
  <!-- The strip itself is the drag handle; double-click maximizes (Tauri drag region). -->
  <header class="titlebar" :class="chrome" data-tauri-drag-region data-testid="titlebar">
    <span v-if="brand" class="titlebar-brand" data-tauri-drag-region>
      <BrandMark size="xs" />
      <span>Billow</span>
    </span>
    <div v-if="chrome === 'windows'" class="caption-buttons">
      <button type="button" class="caption-btn" :aria-label="tr('最小化')" :title="tr('最小化')" data-testid="window-minimize" @click="minimizeWindow">
        <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M0 5h10" /></svg>
      </button>
      <button
        type="button"
        class="caption-btn"
        :aria-label="maximized ? tr('还原') : tr('最大化')"
        :title="maximized ? tr('还原') : tr('最大化')"
        data-testid="window-maximize"
        @click="toggleMaximizeWindow"
      >
        <svg v-if="maximized" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
          <path d="M2.5 2.5V.5h7v7h-2M.5 2.5h7v7h-7z" />
        </svg>
        <svg v-else width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M.5.5h9v9h-9z" /></svg>
      </button>
      <button type="button" class="caption-btn close" :aria-label="tr('关闭')" :title="tr('关闭')" data-testid="window-close" @click="closeWindow">
        <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M.5.5l9 9M9.5.5l-9 9" /></svg>
      </button>
    </div>
  </header>
</template>
