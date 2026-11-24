<script setup lang="ts">import { tr } from '../lib/i18n'

import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { registerLayer } from '../lib/ui/focus'
import Icon from './Icon.vue'

export interface MenuItem {
  id: string
  label: string
  icon?: string
  danger?: boolean
  disabled?: boolean
  /** Visible reason shown next to a disabled item (never a tooltip-only hint). */
  reason?: string
}

const props = withDefaults(
  defineProps<{
    open?: boolean
    items: readonly MenuItem[]
    label?: string
    align?: 'start' | 'end'
    /** Optional anchor to treat as part of the menu for outside clicks. */
    anchor?: HTMLElement | null
  }>(),
  { open: true, get label() { return tr('操作') }, align: 'end', anchor: null },
)
const emit = defineEmits<{ select: [item: MenuItem]; close: [] }>()

const root = ref<HTMLElement | null>(null)
const active = ref(0)
const above = ref(false)
let trigger: HTMLElement | null = null
let releaseLayer: (() => void) | null = null
let mounted = false

function cleanupListeners() {
  document.removeEventListener('mousedown', onOutside)
  releaseLayer?.()
  releaseLayer = null
}

function activateMenu() {
  if (!mounted || !props.open) return
  active.value = 0
  above.value = false
  const focused = document.activeElement
  const anchorEl = props.anchor ?? root.value?.closest<HTMLElement>('.menu-anchor') ?? null
  trigger =
    (focused instanceof HTMLElement && focused !== document.body ? focused : null) ??
    (anchorEl?.matches('button, [role="button"], [tabindex]') ? anchorEl : null) ??
    anchorEl?.querySelector<HTMLElement>('[aria-haspopup], button, [role="button"]') ??
    null
  document.addEventListener('mousedown', onOutside)
  releaseLayer?.()
  releaseLayer = registerLayer(() => close(true))
  void nextTick(() => {
    if (!mounted || !props.open) return
    const el = root.value
    if (el && typeof window !== 'undefined') {
      const rect = el.getBoundingClientRect()
      const anchorRect = (trigger ?? anchorEl)?.getBoundingClientRect()
      const vh = window.innerHeight || 768
      if (rect.height > 0 && rect.bottom > vh - 10 && anchorRect && anchorRect.top > rect.height + 16) {
        above.value = true
      }
    }
    focusItem(active.value)
  })
}

function buttons(): HTMLButtonElement[] {
  return Array.from(root.value?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [])
}

function reasonId(index: number): string {
  return `menu-reason-${props.items[index]?.id ?? index}`
}

function reasonText(item: MenuItem): string | undefined {
  return item.disabled ? (item.reason ?? tr('当前不可用')) : undefined
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

function close(restoreFocus = false) {
  cleanupListeners()
  if (restoreFocus && trigger?.isConnected) trigger.focus({ preventScroll: true })
  trigger = null
  emit('close')
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
  } else if (event.key === 'Escape') {
    event.preventDefault()
    event.stopPropagation()
    close(true)
  } else if (event.key === 'Tab') {
    event.preventDefault()
    event.stopPropagation()
    close(true)
  }
}

function choose(item: MenuItem) {
  if (item.disabled) return
  cleanupListeners()
  emit('select', item)
  close(true)
}

function onOutside(event: Event) {
  const target = event.target
  if (!(target instanceof Node)) return
  if (root.value?.contains(target)) return
  if (trigger?.contains(target)) return
  if (props.anchor?.contains(target)) return
  close(false)
}

watch(
  () => props.items.length,
  () => {
    if (active.value >= props.items.length) active.value = Math.max(props.items.length - 1, 0)
  },
)

watch(
  () => props.open,
  (isOpen) => {
    if (!mounted || isOpen) return
    cleanupListeners()
    trigger = null
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
  <Transition name="menu-pop" appear>
    <div
      v-if="open"
      ref="root"
      class="menu"
      :class="[align, { above }]"
      role="menu"
      :aria-label="label"
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
        :aria-describedby="reasonText(item) ? reasonId(index) : undefined"
        :data-menu-item="item.id"
        @click="choose(item)"
        @focus="active = index"
      >
        <Icon v-if="item.icon" :name="item.icon" :size="15" />
        <span class="menu-label">{{ item.label }}</span>
        <span v-if="reasonText(item)" :id="reasonId(index)" class="menu-reason">{{ reasonText(item) }}</span>
      </button>
    </div>
  </Transition>
</template>
