<script setup lang="ts">
import { computed, nextTick, ref, useId, watch } from 'vue'
import { delayText, groupTypeLabel, isInfoNode, protocolLabel } from '../lib/format'
import { highlightTokens, matchesTokens, splitQueryTokens } from '../lib/search'
import { getFocusable, useFocusTrap } from '../lib/ui/focus'
import { getShortcut, pageShortcutCombo, shortcutKeyLabel } from '../lib/ui/shortcuts'
import { PAGES } from '../lib/store'
import type { NodeGroup, ProfileItem } from '../lib/types'
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
    profiles?: readonly ProfileItem[]
    nodeCatalog?: readonly NodeGroup[]
    connected?: boolean
    hasProfiles?: boolean
    systemProxy?: boolean
    tun?: boolean
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
    profiles: () => [],
    nodeCatalog: () => [],
    connected: false,
    hasProfiles: true,
    systemProxy: false,
    tun: false,
    sidebarCollapsed: false,
    platform: 'desktop',
  },
)
const emit = defineEmits<{
  navigate: [page: string]
  'open-settings': [tab: string]
  action: [id: string]
  'select-profile': [id: string]
  'open-group': [group: string]
  'select-node': [group: string, node: string]
  close: []
}>()

type EntryKind = 'page' | 'setting' | 'action' | 'profile' | 'group' | 'node'

interface PaletteEntry {
  key: string
  kind: EntryKind
  id: string
  groupName?: string
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
          id: 'toggle-system-proxy',
          label: props.systemProxy ? '关闭系统代理' : '开启系统代理',
          icon: 'monitor',
          hint: props.systemProxy ? '已开启' : 'HTTP / SOCKS',
        },
        {
          id: 'toggle-tun',
          label: props.tun ? '关闭 TUN 模式' : '开启 TUN 模式',
          icon: 'shield',
          hint: props.tun ? '已开启' : '虚拟网卡',
        },
        {
          id: 'toggle-sidebar',
          label: props.sidebarCollapsed ? '展开侧边栏' : '收起侧边栏',
          icon: props.sidebarCollapsed ? 'panel-left-open' : 'panel-left-close',
          hint: shortcutKeyLabel(getShortcut('sidebar').combo),
        },
        { id: 'copy-proxy-env', label: '复制终端环境变量', icon: 'terminal', hint: 'HTTP / SOCKS5' },
        { id: 'open-shortcuts', label: '查看快捷键说明', icon: 'keyboard', hint: '?' },
      ]),
  {
    id: 'open-config',
    label: '查看生效配置',
    icon: 'file',
    hint: 'YAML',
    disabled: !props.hasProfiles,
    reason: !props.hasProfiles ? '先添加配置' : undefined,
  },
  {
    id: 'flush-fakeip',
    label: '刷新 FakeIP 缓存',
    icon: 'refresh',
    disabled: !props.connected,
    reason: !props.connected ? '连接后可用' : undefined,
  },
  {
    id: 'flush-dns',
    label: '刷新 DNS 缓存',
    icon: 'refresh',
    disabled: !props.connected,
    reason: !props.connected ? '连接后可用' : undefined,
  },
  { id: 'toggle-theme', label: '切换主题', icon: 'moon' },
  { id: 'open-logs', label: '打开日志', icon: 'terminal' },
])

const normalized = computed(() => query.value.trim().toLowerCase())
const queryTokens = computed(() => splitQueryTokens(query.value))

const sidebarPageIds = PAGES.filter((page) => page.group === 'core' || page.group === 'tools').map((page) => page.id)
function pageKeyHint(id: string): string | undefined {
  if (props.platform === 'android') return undefined
  if (id === 'settings') return shortcutKeyLabel(getShortcut('settings').combo)
  const idx = sidebarPageIds.indexOf(id as (typeof sidebarPageIds)[number])
  const combo = pageShortcutCombo(idx)
  return combo ? shortcutKeyLabel(combo) : undefined
}

// The palette never offers irreversible actions, whatever a caller passes in (R25).
const DESTRUCTIVE_ACTION = /(^|:)(delete|remove|clear|reset)(:|$)|删除|清空|重置/

function matches(label: string, hint?: string): boolean {
  if (!queryTokens.value.length) return true
  return matchesTokens(`${label} ${hint ?? ''}`, queryTokens.value)
}

const primaryManualGroup = computed(() => {
  const manual = props.nodeCatalog.filter((group) => group.kind === 'manual')
  if (props.mode === 'global') {
    return props.nodeCatalog.find((group) => group.name === 'GLOBAL') ?? manual[0] ?? null
  }
  return manual.find((group) => Boolean(group.now)) ?? manual[0] ?? null
})

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

  const profileEntries: PaletteEntry[] = []
  const proxyEntries: PaletteEntry[] = []
  if (normalized.value) {
    for (const item of props.profiles) {
      const itemHint = item.current ? '当前' : item.proxy_count ? `${item.proxy_count} 个节点` : undefined
      if (!matches(item.name, itemHint)) continue
      profileEntries.push({
        key: `profile:${item.id}`,
        kind: 'profile',
        id: item.id,
        label: item.name,
        icon: item.kind === 'local' ? 'file' : 'link',
        hint: itemHint,
        index: 0,
      })
    }

    const visibleGroups = props.mode === 'global'
      ? props.nodeCatalog
      : props.nodeCatalog.filter((group) => group.name !== 'GLOBAL')
    for (const group of visibleGroups) {
      const typeLabel = groupTypeLabel(group)
      if (!matches(group.name, typeLabel)) continue
      proxyEntries.push({
        key: `group:${group.name}`,
        kind: 'group',
        id: group.name,
        label: group.name,
        icon: 'route',
        hint: group.now ? `${typeLabel} · ${group.now}` : typeLabel,
        index: 0,
      })
    }

    const primary = primaryManualGroup.value
    const manualGroups = [
      ...(primary && primary.kind === 'manual' ? [primary] : []),
      ...visibleGroups.filter((group) => group.kind === 'manual' && group.name !== primary?.name),
    ]
    const groupNames = new Set(props.nodeCatalog.map((group) => group.name))
    let added = 0
    for (const targetGroup of manualGroups) {
      if (added >= 12) break
      for (const node of targetGroup.nodes) {
        if (added >= 12) break
        if (groupNames.has(node.name) || isInfoNode(node.name)) continue
        const proto = protocolLabel(node.node_type)
        const tagText = [targetGroup.name, proto, ...node.tags].filter(Boolean).join(' ')
        if (!matches(node.name, tagText)) continue
        const delay = props.connected ? delayText(node.delay_ms, node.failed) : ''
        proxyEntries.push({
          key: `node:${targetGroup.name}:${node.name}`,
          kind: 'node',
          id: node.name,
          groupName: targetGroup.name,
          label: node.name,
          icon: 'globe',
          hint: [targetGroup.name, node.selected ? '当前' : delay || proto].filter(Boolean).join(' · '),
          index: 0,
        })
        added += 1
      }
    }
  }

  const sections = [
    build(
      'page',
      '页面',
      props.pages,
      (item) => item.icon,
      (item) => (props.currentPage && item.id === props.currentPage ? '当前' : pageKeyHint(item.id)),
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
    { id: 'profile', label: '配置', entries: profileEntries },
    { id: 'proxy', label: '代理组与节点', entries: proxyEntries },
  ].filter((group) => group.entries.length > 0)

  let finalIndex = 0
  for (const section of sections) {
    for (const entry of section.entries) {
      entry.index = finalIndex++
    }
  }
  return sections
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
  else if (entry.kind === 'profile') emit('select-profile', entry.id)
  else if (entry.kind === 'group') emit('open-group', entry.id)
  else if (entry.kind === 'node' && entry.groupName) emit('select-node', entry.groupName, entry.id)
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
            placeholder="搜索页面、设置、节点或动作"
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
              <span class="palette-label">
                <template v-for="(part, idx) in highlightTokens(entry.label, query)" :key="idx">
                  <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                </template>
              </span>
              <span v-if="entry.disabled && entry.reason" :id="reasonId(entry)" class="palette-reason">
                {{ entry.reason }}
              </span>
              <span v-else-if="entry.hint" class="palette-hint" :class="{ current: entry.hint === '当前' || entry.hint.endsWith('· 当前') }">{{ entry.hint }}</span>
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
