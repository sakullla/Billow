<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import Icon from './Icon.vue'

export interface MenuItem {
  id: string
  label: string
  icon?: string
  danger?: boolean
  disabled?: boolean
  /** Visible reason shown next to a disabled item (never a tooltip-only hint). */
  reason?: string
  /** Draw the small accent dot used for "override is set" markers. */
  mark?: boolean
}

const props = withDefaults(
  defineProps<{
    items: readonly MenuItem[]
    label?: string
    align?: 'start' | 'end'
    /** Optional anchor to treat as part of the menu for outside clicks. */
    anchor?: HTMLElement | null
  }>(),
  { label: '操作', align: 'end', anchor: null },
)
const emit = defineEmits<{ select: [item: MenuItem]; close: [] }>()

const root = ref<HTMLElement | null>(null)
const active = ref(0)
let trigger: HTMLElement | null = null

function buttons(): HTMLButtonElement[] {
  return Array.from(root.value?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [])
}

function reasonId(index: number): string {
  return `menu-reason-${props.items[index]?.id ?? index}`
}

function reasonText(item: MenuItem): string | undefined {
  return item.disabled ? (item.reason ?? '当前不可用') : undefined
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

onMounted(() => {
  const focused = document.activeElement
  const anchorEl = props.anchor ?? root.value?.closest<HTMLElement>('.menu-anchor') ?? null
  trigger =
    (focused instanceof HTMLElement && focused !== document.body ? focused : null) ??
    (anchorEl?.matches('button, [role="button"], [tabindex]') ? anchorEl : null) ??
    anchorEl?.querySelector<HTMLElement>('[aria-haspopup], button, [role="button"]') ??
    null
  document.addEventListener('mousedown', onOutside)
  void nextTick(() => focusItem(active.value))
})

onBeforeUnmount(() => document.removeEventListener('mousedown', onOutside))
</script>

<template>
  <div
    ref="root"
    class="menu"
    :class="align"
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
      <span v-if="item.mark" class="dot-mark" />
      <span v-if="reasonText(item)" :id="reasonId(index)" class="menu-reason">{{ reasonText(item) }}</span>
    </button>
  </div>
</template>
