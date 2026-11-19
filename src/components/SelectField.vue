<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { registerLayer } from '../lib/ui/focus'
import Icon from './Icon.vue'
import Modal from './Modal.vue'

export interface SelectOption {
  value: string | number
  label: string
  /** Secondary text, e.g. a count; shown as a subtle badge/right-aligned count. */
  hint?: string
}

defineOptions({ inheritAttrs: false })

const props = defineProps<{
  modelValue: string | number
  options: readonly SelectOption[]
  /** Accessible name and sheet title. */
  label: string
  /**
   * Phones get a bottom-sheet list; desktop gets a themed floating popover.
   */
  sheet?: boolean
  size?: 'sm'
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string | number] }>()

const SEARCH_THRESHOLD = 8
const open = ref(false)
const filterQuery = ref('')
const activeIndex = ref(0)
const flipAbove = ref(false)
const popoverStyle = ref<Record<string, string>>({})

const triggerRef = ref<HTMLButtonElement | null>(null)
const popoverRef = ref<HTMLDivElement | null>(null)
const listRef = ref<HTMLDivElement | null>(null)
const searchRef = ref<HTMLInputElement | null>(null)

let releaseLayer: (() => void) | null = null

const current = computed(() => props.options.find((option) => option.value === props.modelValue) ?? null)
const searchable = computed(() => props.options.length > SEARCH_THRESHOLD)
const visibleOptions = computed(() => {
  const needle = filterQuery.value.trim().toLowerCase()
  if (!needle) return props.options
  return props.options.filter(
    (option) =>
      option.label.toLowerCase().includes(needle) ||
      String(option.value).toLowerCase().includes(needle),
  )
})

function updatePosition() {
  const trigger = triggerRef.value
  if (!trigger) return
  const rect = trigger.getBoundingClientRect()
  const vw = window.innerWidth || 1024
  const vh = window.innerHeight || 768
  const gap = 6
  const margin = 10
  const spaceBelow = vh - rect.bottom - margin
  const spaceAbove = rect.top - margin
  const placeAbove = spaceBelow < 200 && spaceAbove > spaceBelow
  flipAbove.value = placeAbove

  const minWidth = Math.max(Math.round(rect.width), 172)
  const maxWidth = Math.min(340, vw - margin * 2)
  const left = Math.max(margin, Math.min(Math.round(rect.left), vw - minWidth - margin))
  const maxHeight = Math.max(140, Math.min(320, (placeAbove ? spaceAbove : spaceBelow) - gap))

  popoverStyle.value = {
    minWidth: `${minWidth}px`,
    maxWidth: `${maxWidth}px`,
    left: `${left}px`,
    ...(placeAbove
      ? { bottom: `${Math.round(vh - rect.top + gap)}px` }
      : { top: `${Math.round(rect.bottom + gap)}px` }),
    '--select-max-h': `${Math.round(maxHeight)}px`,
  }
}

function scrollActiveIntoView() {
  const list = listRef.value
  if (!list) return
  const el = list.children[activeIndex.value] as HTMLElement | undefined
  el?.scrollIntoView?.({ block: 'nearest' })
}

function openPopover() {
  if (open.value) return
  filterQuery.value = ''
  const idx = props.options.findIndex((option) => option.value === props.modelValue)
  activeIndex.value = idx >= 0 ? idx : 0
  if (!props.sheet) updatePosition()
  open.value = true
}

function closePopover(restoreFocus = false) {
  if (!open.value) return
  open.value = false
  filterQuery.value = ''
  if (restoreFocus) {
    void nextTick(() => triggerRef.value?.focus({ preventScroll: true }))
  }
}

function toggle() {
  if (open.value) closePopover(true)
  else openPopover()
}

function choose(option: SelectOption) {
  const changed = option.value !== props.modelValue
  closePopover(true)
  if (changed) emit('update:modelValue', option.value)
}

function moveActive(delta: number) {
  const count = visibleOptions.value.length
  if (!count) return
  activeIndex.value = (activeIndex.value + delta + count) % count
  void nextTick(scrollActiveIntoView)
}

function onTriggerKeydown(event: KeyboardEvent) {
  if (props.sheet) return
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault()
    openPopover()
  }
}

function onPopoverKeydown(event: KeyboardEvent) {
  if (event.key === 'ArrowDown') {
    event.preventDefault()
    moveActive(1)
  } else if (event.key === 'ArrowUp') {
    event.preventDefault()
    moveActive(-1)
  } else if (event.key === 'Home' && event.target !== searchRef.value) {
    event.preventDefault()
    activeIndex.value = 0
    void nextTick(scrollActiveIntoView)
  } else if (event.key === 'End' && event.target !== searchRef.value) {
    event.preventDefault()
    activeIndex.value = Math.max(0, visibleOptions.value.length - 1)
    void nextTick(scrollActiveIntoView)
  } else if (event.key === 'Enter') {
    event.preventDefault()
    const picked = visibleOptions.value[activeIndex.value]
    if (picked) choose(picked)
  } else if (event.key === 'Escape') {
    event.preventDefault()
    event.stopPropagation()
    closePopover(true)
  } else if (event.key === 'Tab') {
    event.preventDefault()
    event.stopPropagation()
    closePopover(true)
  }
}

function onOutsideMouseDown(event: Event) {
  const target = event.target
  if (!(target instanceof Node)) return
  if (popoverRef.value?.contains(target)) return
  if (triggerRef.value?.contains(target)) return
  closePopover(false)
}

function onViewportScroll(event: Event) {
  const target = event.target
  if (target instanceof Node && popoverRef.value?.contains(target)) return
  updatePosition()
}

function attachDesktopListeners() {
  document.addEventListener('mousedown', onOutsideMouseDown)
  window.addEventListener('resize', updatePosition)
  window.addEventListener('scroll', onViewportScroll, true)
  releaseLayer = registerLayer(() => closePopover(true))
}

function detachDesktopListeners() {
  document.removeEventListener('mousedown', onOutsideMouseDown)
  window.removeEventListener('resize', updatePosition)
  window.removeEventListener('scroll', onViewportScroll, true)
  releaseLayer?.()
  releaseLayer = null
}

watch(filterQuery, () => {
  activeIndex.value = 0
})

watch(open, (isOpen) => {
  if (props.sheet) return
  if (isOpen) {
    attachDesktopListeners()
    void nextTick(() => {
      updatePosition()
      scrollActiveIntoView()
      if (searchable.value) {
        searchRef.value?.focus({ preventScroll: true })
      } else {
        popoverRef.value?.focus({ preventScroll: true })
      }
    })
  } else {
    detachDesktopListeners()
  }
})

onBeforeUnmount(detachDesktopListeners)
</script>

<template>
  <template v-if="sheet">
    <button
      ref="triggerRef"
      type="button"
      class="input select-trigger"
      :class="[size, { open }]"
      aria-haspopup="dialog"
      :aria-expanded="open"
      :aria-label="`${label}：${current?.label ?? tr('未选择')}`"
      v-bind="$attrs"
      @click="openPopover"
    >
      <span class="select-trigger-text">{{ current?.label ?? tr('未选择') }}</span>
      <span v-if="current?.hint" class="select-trigger-hint mono">{{ current.hint }}</span>
      <Icon name="chevron-down" :size="14" class="select-chevron" />
    </button>
    <Modal v-if="open" :title="label" @close="closePopover(false)">
      <div v-if="searchable" class="search">
        <Icon name="search" :size="15" />
        <input
          v-model="filterQuery"
          type="search"
          :placeholder="tr('搜索选项…')"
          :aria-label="tr('筛选选项')"
          data-testid="select-sheet-search"
        />
        <button
          v-if="filterQuery"
          type="button"
          class="icon-btn sm"
          :aria-label="tr('清空')"
          @click="filterQuery = ''"
        >
          <Icon name="x" :size="13" />
        </button>
      </div>
      <div class="option-list" role="listbox" :aria-label="label">
        <button
          v-for="option in visibleOptions"
          :key="String(option.value)"
          type="button"
          role="option"
          class="option-row"
          :class="{ active: option.value === modelValue }"
          :aria-selected="option.value === modelValue"
          :data-option-value="String(option.value)"
          @click="choose(option)"
        >
          <span class="option-label">{{ option.label }}</span>
          <span v-if="option.hint" class="option-hint">{{ option.hint }}</span>
          <Icon v-if="option.value === modelValue" name="check" :size="18" :stroke="2.4" class="option-check" />
        </button>
        <p v-if="!visibleOptions.length" class="select-empty muted small">{{ tr('无匹配项') }}</p>
      </div>
    </Modal>
  </template>

  <template v-else>
    <button
      ref="triggerRef"
      type="button"
      class="input select-trigger"
      :class="[size, { open }]"
      aria-haspopup="listbox"
      :aria-expanded="open"
      :aria-label="`${label}：${current?.label ?? tr('未选择')}`"
      v-bind="$attrs"
      @click="toggle"
      @keydown="onTriggerKeydown"
    >
      <span class="select-trigger-text">{{ current?.label ?? tr('未选择') }}</span>
      <span v-if="current?.hint" class="select-trigger-hint mono">{{ current.hint }}</span>
      <Icon name="chevron-down" :size="14" class="select-chevron" />
    </button>

    <Teleport to="body">
      <div
        v-if="open"
        ref="popoverRef"
        class="select-popover"
        :class="{ above: flipAbove }"
        :style="popoverStyle"
        tabindex="-1"
        data-focus-portal
        data-testid="select-popover"
        @keydown="onPopoverKeydown"
      >
        <div v-if="searchable" class="select-search">
          <Icon name="search" :size="13" />
          <input
            ref="searchRef"
            v-model="filterQuery"
            type="search"
            :placeholder="tr('搜索选项…')"
            :aria-label="tr('筛选下拉选项')"
            data-testid="select-search"
          />
          <button
            v-if="filterQuery"
            type="button"
            class="icon-btn xs"
            :aria-label="tr('清空')"
            @click="filterQuery = ''; searchRef?.focus({ preventScroll: true })"
          >
            <Icon name="x" :size="12" />
          </button>
        </div>

        <div ref="listRef" class="select-options" role="listbox" :aria-label="label">
          <button
            v-for="(option, index) in visibleOptions"
            :key="String(option.value)"
            type="button"
            role="option"
            class="select-option"
            :class="{ selected: option.value === modelValue, focused: index === activeIndex }"
            :aria-selected="option.value === modelValue"
            :data-option-value="String(option.value)"
            @mouseenter="activeIndex = index"
            @click="choose(option)"
          >
            <Icon v-if="option.value === modelValue" name="check" :size="14" :stroke="2.5" class="select-option-check" />
            <span v-else class="select-option-check-slot" aria-hidden="true" />
            <span class="select-option-label">{{ option.label }}</span>
            <span v-if="option.hint" class="select-option-hint mono">{{ option.hint }}</span>
          </button>
          <p v-if="!visibleOptions.length" class="select-empty muted small">{{ tr('无匹配项') }}</p>
        </div>
      </div>
    </Teleport>
  </template>
</template>
