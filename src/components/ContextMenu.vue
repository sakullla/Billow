<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { registerLayer } from '../lib/ui/focus'
import Icon from './Icon.vue'
import type { MenuItem } from './Menu.vue'

const props = withDefaults(
  defineProps<{
    open?: boolean
    x: number
    y: number
    items: readonly MenuItem[]
    label?: string
  }>(),
  { open: true, label: tr('快捷操作') },
)
const emit = defineEmits<{ select: [item: MenuItem]; close: [] }>()

const root = ref<HTMLElement | null>(null)
const active = ref(0)
const pos = ref({ left: props.x, top: props.y })
let releaseLayer: (() => void) | null = null
let mounted = false

function cleanupListeners() {
  document.removeEventListener('mousedown', onPointerOutside)
  window.removeEventListener('scroll', onDismissScroll, true)
  window.removeEventListener('resize', close)
  releaseLayer?.()
  releaseLayer = null
}

function activateMenu() {
  if (!mounted || !props.open) return
  active.value = 0
  pos.value = { left: props.x, top: props.y }
  document.addEventListener('mousedown', onPointerOutside)
  window.addEventListener('scroll', onDismissScroll, true)
  window.addEventListener('resize', close)
  releaseLayer?.()
  releaseLayer = registerLayer(close)
  void nextTick(() => {
    if (!mounted || !props.open) return
    clampToViewport()
    focusItem(0)
  })
}

const menuStyle = computed(() => ({
  left: `${pos.value.left}px`,
  top: `${pos.value.top}px`,
}))

function buttons(): HTMLButtonElement[] {
  return Array.from(root.value?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [])
}

function clampToViewport() {
  const el = root.value
  if (!el || typeof window === 'undefined') {
    pos.value = { left: props.x, top: props.y }
    return
  }
  const rect = el.getBoundingClientRect()
  const vw = window.innerWidth || 1024
  const vh = window.innerHeight || 768
  const pad = 10
  let left = props.x
  let top = props.y
  if (rect.width > 0 && left + rect.width > vw - pad) {
    left = Math.max(pad, vw - rect.width - pad)
  }
  if (rect.height > 0 && top + rect.height > vh - pad) {
    top = Math.max(pad, props.y - rect.height)
  }
  pos.value = { left: Math.max(pad, left), top: Math.max(pad, top) }
}

function focusItem(index: number) {
  const list = buttons()
  if (!list.length) return
  const next = Math.min(Math.max(index, 0), list.length - 1)
  active.value = next
  list[next]?.focus({ preventScroll: true })
}

function move(step: number) {
  const count = props.items.length
  if (!count) return
  focusItem((active.value + step + count) % count)
}

function close() {
  cleanupListeners()
  emit('close')
}

function choose(item: MenuItem) {
  if (item.disabled) return
  cleanupListeners()
  emit('select', item)
  close()
}

function onKeydown(event: KeyboardEvent) {
  if (event.key === 'ArrowDown') {
    event.preventDefault()
    move(1)
  } else if (event.key === 'ArrowUp') {
    event.preventDefault()
    move(-1)
  } else if (event.key === 'Home') {
    event.preventDefault()
    focusItem(0)
  } else if (event.key === 'End') {
    event.preventDefault()
    focusItem(props.items.length - 1)
  } else if (event.key === 'Escape' || event.key === 'Tab') {
    event.preventDefault()
    event.stopPropagation()
    close()
  }
}

function onPointerOutside(event: Event) {
  const target = event.target
  if (target instanceof Node && root.value?.contains(target)) return
  close()
}

function onDismissScroll(event: Event) {
  if (event.target instanceof Node && root.value?.contains(event.target)) return
  close()
}

watch(
  () => [props.x, props.y, props.items.length] as const,
  () => {
    if (!props.open) return
    pos.value = { left: props.x, top: props.y }
    void nextTick(() => {
      if (!mounted || !props.open) return
      clampToViewport()
      focusItem(0)
    })
  },
)

watch(
  () => props.open,
  (isOpen) => {
    if (!mounted || isOpen) return
    cleanupListeners()
  },
  { flush: 'sync' },
)

watch(
  () => props.open,
  (isOpen) => {
    if (!mounted || !isOpen) return
    activateMenu()
  },
  { flush: 'post' },
)

onMounted(() => {
  mounted = true
  if (props.open) activateMenu()
})

onBeforeUnmount(() => {
  mounted = false
  cleanupListeners()
})
</script>

<template>
  <Teleport to="body">
    <Transition name="menu-pop" appear>
      <div
        v-if="open"
        ref="root"
        class="menu context-menu"
        :style="menuStyle"
        role="menu"
        :aria-label="label"
        data-focus-portal
        data-testid="context-menu"
        @contextmenu.prevent
        @keydown="onKeydown"
      >
        <button
          v-for="(item, index) in items"
          :key="item.id"
          type="button"
          role="menuitem"
          class="menu-item"
          :class="{ danger: item.danger, disabled: item.disabled }"
          :tabindex="index === active ? 0 : -1"
          :aria-disabled="item.disabled ? 'true' : undefined"
          :data-menu-item="item.id"
          @click="choose(item)"
          @focus="active = index"
        >
          <Icon v-if="item.icon" :name="item.icon" :size="15" />
          <span class="menu-label">{{ item.label }}</span>
          <span v-if="item.disabled && item.reason" class="menu-reason">{{ item.reason }}</span>
        </button>
      </div>
    </Transition>
  </Teleport>
</template>
