<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import Icon from './Icon.vue'

const props = withDefaults(
  defineProps<{
    /** Config `proxy-groups[].icon`; already limited to http(s) and image data. */
    icon?: string | null
    /** Kernel group type, used to pick the built-in fallback glyph. */
    type?: string
    size?: number
  }>(),
  { icon: null, type: '', size: 24 },
)

// A remote icon can fail at any time (offline, hot-link protection). One failure
// falls back for this URL; a new URL gets a fresh attempt so config updates swap (R33).
const broken = ref(false)
watch(
  () => props.icon,
  () => {
    broken.value = false
  },
)

const source = computed(() => (props.icon && !broken.value ? props.icon : null))

/** The fallback still names the group kind instead of showing an empty box. */
function glyph(type: string): string {
  const key = type.trim().toLowerCase()
  if (key === 'select' || key === 'selector') return 'route'
  if (key === 'relay') return 'layers'
  if (key === 'url-test' || key === 'urltest') return 'network'
  if (key === 'fallback' || key === 'load-balance' || key === 'loadbalance') return 'network'
  return 'globe'
}

const fallback = computed(() => glyph(props.type))
const glyphSize = computed(() => Math.max(12, Math.round(props.size * 0.7)))
</script>

<template>
  <span class="group-icon" :style="{ width: `${size}px`, height: `${size}px` }" aria-hidden="true">
    <img
      v-if="source"
      :key="source"
      class="group-icon-img"
      :src="source"
      :width="size"
      :height="size"
      loading="lazy"
      decoding="async"
      alt=""
      aria-hidden="true"
      @error="broken = true"
    />
    <Icon v-else :name="fallback" :size="glyphSize" />
  </span>
</template>
