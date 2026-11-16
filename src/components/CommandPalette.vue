<script setup lang="ts">
import { computed, nextTick, ref, useId, watch } from 'vue'
import { getFocusable, useFocusTrap } from '../lib/ui/focus'
import { getShortcut, shortcutKeyLabel } from '../lib/ui/shortcuts'
import { PAGES } from '../lib/store'
import Icon from './Icon.vue'

export interface PalettePage {
  id: string
  label: string
  icon?: string
}

export interface PaletteSetting {
  id: string
  label: string
  description?: string
  icon?: string
}

export interface PaletteAction {
  id: string
  label: string
  icon?: string
  disabled?: boolean
  /** Visible reason for a disabled action; the command never silently does nothing. */
  reason?: string
  hint?: string
}

const props = withDefaults(
  defineProps<{
    pages?: readonly PalettePage[]
    settings?: readonly PaletteSetting[]
    /** Override the built-in action list; it must not add destructive actions. */
    actions?: readonly PaletteAction[]
    connected?: boolean
    hasProfiles?: boolean
    currentPage?: string
    mode?: string | null
    sidebarCollapsed?: boolean
    /** Android hides the TUN category in settings, so the palette must skip it too. */
    platform?: 'desktop' | 'android'
  }>(),
  {
    pages: () =>
      PAGES.map((page) => ({ id: page.id, label: page.label, icon: page.icon })),
    settings: () => [
      { id: 'general', label: '通用设置', description: '主题、行为与启动', icon: 'sliders' },
      { id: 'proxy', label: '系统代理设置', description: '代理主机、PAC 模式与绕过列表', icon: 'monitor' },
      { id: 'kernel', label: '内核设置', description: '通道与版本', icon: 'cpu' },
      { id: 'tun', label: 'TUN 设置', description: '栈、DNS 劫持与 MTU', icon: 'shield' },
      { id: 'dns', label: 'DNS 设置', description: 'Fake-IP、解析策略与 Hosts', icon: 'globe' },
    ],
    connected: false,
    hasProfiles: true,
    sidebarCollapsed: false,
    platform: 'desktop',
  },
)
const emit = defineEmits<{
  navigate: [page: string]
  'open-settings': [tab: string]
  action: [id: string]
  close: []
}>()

type EntryKind = 'page' | 'setting' | 'action'

interface PaletteEntry {
  key: string
  kind: EntryKind
  id: string
  label: string
  icon?: string
  hint?: string
  disabled?: boolean
  reason?: string
  index: number
}

const panel = ref<HTMLElement | null>(null)
const inputEl = ref<HTMLInputElement | null>(null)
const titleId = useId()
const listId = useId()
const query = ref('')
const active = ref(0)
const paletteKey = shortcutKeyLabel(getShortcut('palette').combo)
const settings = computed(() =>
  props.settings.filter(
    (item) => !(props.platform === 'android' && (item.id === 'tun' || item.id === 'proxy')),
  ),
)

const defaultActions = computed<PaletteAction[]>(() => [
  {
    id: 'connect',
    label: '连接',
    icon: 'power',
    disabled: props.connected,
    reason: props.connected ? '已连接' : undefined,
  },
  {
    id: 'disconnect',
    label: '断开',
    icon: 'stop',
    disabled: !props.connected,
    reason: !props.connected ? '连接后可断开' : undefined,
  },
  {
    id: 'test-all',
    label: '全部测速',
    icon: 'zap',
    disabled: !props.connected,
    reason: !props.connected ? '连接后可测速' : undefined,
  },
  {
    id: 'refresh-profiles',
    label: '更新全部订阅',
    icon: 'refresh',
    disabled: !props.hasProfiles,
    reason: !props.hasProfiles ? '先添加配置' : undefined,
  },
  { id: 'add-profile', label: '添加配置', icon: 'plus' },
  {
    id: 'mode-rule',
    label: '切换为规则模式',
    icon: 'route',
    hint: props.mode === 'rule' ? '当前' : 'Rule',
  },
  {
    id: 'mode-global',
    label: '切换为全局模式',
    icon: 'globe',
    hint: props.mode === 'global' ? '当前' : 'Global',
  },
  {
    id: 'mode-direct',
    label: '切换为直连模式',
    icon: 'zap',
    hint: props.mode === 'direct' ? '当前' : 'Direct',
  },
  ...(props.platform === 'android'
    ? []
    : [
        {
          id: 'toggle-sidebar',
          label: props.sidebarCollapsed ? '展开侧边栏' : '收起侧边栏',
          icon: props.sidebarCollapsed ? 'panel-left-open' : 'panel-left-close',
          hint: shortcutKeyLabel(getShortcut('sidebar').combo),
        },
        { id: 'copy-proxy-env', label: '复制终端环境变量', icon: 'terminal', hint: 'HTTP / SOCKS5' },
        { id: 'open-shortcuts', label: '查看快捷键说明', icon: 'keyboard', hint: '?' },
      ]),
  { id: 'toggle-theme', label: '切换主题', icon: 'moon' },
  { id: 'open-logs', label: '打开日志', icon: 'terminal' },
])

const normalized = computed(() => query.value.trim().toLowerCase())

// The palette never offers irreversible actions, whatever a caller passes in (R25).
const DESTRUCTIVE_ACTION = /(^|:)(delete|remove|clear|reset)(:|$)|删除|清空|重置/

function matches(label: string, hint?: string): boolean {
  if (!normalized.value) return true
  return `${label} ${hint ?? ''}`.toLowerCase().includes(normalized.value)
}

const groups = computed(() => {
  let index = 0
  const build = <T extends PalettePage | PaletteSetting | PaletteAction>(
    kind: EntryKind,
    title: string,
    items: readonly T[],
    icon: (item: T) => string | undefined,
    hint: (item: T) => string | undefined,
    disabled: (item: T) => boolean,
    reason: (item: T) => string | undefined,
  ) => {
    const entries: PaletteEntry[] = []
    for (const item of items) {
      const itemHint = hint(item)
      if (!matches(item.label, itemHint)) continue
      const isDisabled = disabled(item)
      entries.push({
        key: `${kind}:${item.id}`,
        kind,
        id: item.id,
        label: item.label,
        icon: icon(item),
        hint: itemHint,
        disabled: isDisabled,
        reason: isDisabled ? (reason(item) ?? '当前不可用') : undefined,
        index: index++,
      })
    }
    return { id: kind, label: title, entries }
  }

  const actionItems = (props.actions ?? defaultActions.value).filter(
    (item) => !DESTRUCTIVE_ACTION.test(`${item.id} ${item.label}`),
  )
  return [
    build(
      'page',
      '页面',
      props.pages,
      (item) => item.icon,
      (item) => (props.currentPage && item.id === props.currentPage ? '当前' : undefined),
      () => false,
      () => undefined,
    ),
    build(
      'setting',
      '设置',
      settings.value,
      (item) => item.icon,
      (item) => item.description,
      () => false,
      () => undefined,
    ),
    build(
      'action',
      '动作',
      actionItems,
      (item) => item.icon,
      (item) => item.hint,
      (item) => Boolean(item.disabled),
      (item) => item.reason,
    ),
  ].filter((group) => group.entries.length > 0)
})

const entries = computed(() => groups.value.flatMap((group) => group.entries))
const activeEntry = computed(
  () => entries.value[Math.min(active.value, Math.max(entries.value.length - 1, 0))] ?? null,
)

function reasonId(entry: PaletteEntry): string {
  return `${entry.key}-reason`
}

function setActive(index: number) {
  const count = entries.value.length
  if (!count) return
  active.value = Math.min(Math.max(index, 0), count - 1)
}

function onKeydown(event: KeyboardEvent) {
  const count = entries.value.length
  if (!count) return
  const current = activeEntry.value?.index ?? 0
  if (event.key === 'ArrowDown') {
    event.preventDefault()
    setActive((current + 1) % count)
  } else if (event.key === 'ArrowUp') {
    event.preventDefault()
    setActive((current - 1 + count) % count)
  } else if (event.key === 'Home') {
    event.preventDefault()
    setActive(0)
  } else if (event.key === 'End') {
    event.preventDefault()
    setActive(count - 1)
  } else if (event.key === 'Enter') {
    event.preventDefault()
    if (activeEntry.value) choose(activeEntry.value)
  }
}

function choose(entry: PaletteEntry) {
  if (entry.disabled) return
  if (entry.kind === 'page') emit('navigate', entry.id)
  else if (entry.kind === 'setting') emit('open-settings', entry.id)
  else emit('action', entry.id)
  emit('close')
}

watch(query, () => {
  active.value = 0
})

watch(
  () => entries.value.length,
  (length) => {
    if (active.value >= length) active.value = Math.max(length - 1, 0)
  },
)

watch(active, () => {
  void nextTick(() => {
    const target = activeEntry.value
    if (target) document.getElementById(target.key)?.scrollIntoView?.({ block: 'nearest' })
  })
})

useFocusTrap(() => panel.value, {
  onClose: () => emit('close'),
  initialFocus: () => inputEl.value ?? getFocusable(panel.value)[0] ?? null,
})
</script>

<template>
  <Teleport to="body">
    <div class="overlay palette-overlay" @mousedown.self="emit('close')">
      <section
        ref="panel"
        class="palette"
        role="dialog"
        aria-modal="true"
        :aria-labelledby="titleId"
        @keydown="onKeydown"
      >
        <h2 :id="titleId" class="sr-only">命令面板</h2>
        <div class="palette-search">
          <Icon name="search" :size="16" />
          <input
            ref="inputEl"
            v-model="query"
            type="search"
            role="combobox"
            aria-autocomplete="list"
            aria-expanded="true"
            :aria-controls="listId"
            :aria-activedescendant="activeEntry?.key"
            aria-label="搜索命令"
            placeholder="搜索页面、设置或动作"
            autocomplete="off"
            spellcheck="false"
            @input="active = 0"
          />
          <button
            v-if="query"
            type="button"
            class="icon-btn sm"
            aria-label="清空搜索"
            data-testid="palette-clear"
            @click="query = ''; inputEl?.focus()"
          >
            <Icon name="x" :size="14" />
          </button>
          <kbd class="palette-kbd">{{ paletteKey }}</kbd>
          <button type="button" class="icon-btn sm" aria-label="关闭" @click="emit('close')">
            <Icon name="x" :size="15" />
          </button>
        </div>

        <div :id="listId" class="palette-list" role="listbox" aria-label="命令">
          <div v-for="group in groups" :key="group.id" class="palette-group" role="group" :aria-label="group.label">
            <p class="palette-group-label" aria-hidden="true">{{ group.label }}</p>
            <div
              v-for="entry in group.entries"
              :id="entry.key"
              :key="entry.key"
              class="palette-option"
              :class="{ active: activeEntry?.index === entry.index, disabled: entry.disabled }"
              role="option"
              :aria-selected="activeEntry?.index === entry.index"
              :aria-disabled="entry.disabled ? 'true' : undefined"
              :aria-describedby="entry.disabled && entry.reason ? reasonId(entry) : undefined"
              :data-command="entry.key"
              @mousedown.prevent
              @mousemove="setActive(entry.index)"
              @click="choose(entry)"
            >
              <Icon v-if="entry.icon" :name="entry.icon" :size="16" />
              <span class="palette-label">{{ entry.label }}</span>
              <span v-if="entry.disabled && entry.reason" :id="reasonId(entry)" class="palette-reason">
                {{ entry.reason }}
              </span>
              <span v-else-if="entry.hint" class="palette-hint">{{ entry.hint }}</span>
            </div>
          </div>
          <p v-if="!groups.length" class="palette-empty">没有匹配的命令</p>
        </div>

        <footer class="palette-foot">
          <span>↑↓ 选择</span>
          <span>Enter 执行</span>
          <span>Esc 关闭</span>
        </footer>
      </section>
    </div>
  </Teleport>
</template>
