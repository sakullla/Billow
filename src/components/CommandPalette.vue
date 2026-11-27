<script setup lang="ts">
import { computed, defineComponent, nextTick, ref, useId, watch, type PropType } from 'vue'
import { autoTypeLabel, delayText, groupTypeLabel, isInfoNode, listedGroups, protocolLabel } from '../lib/format'
import { t, tr } from '../lib/i18n'
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
    open?: boolean
    pages?: readonly PalettePage[]
    settings?: readonly PaletteSetting[]
    /** Override the built-in action list; it must not add destructive actions. */
    actions?: readonly PaletteAction[]
    profiles?: readonly ProfileItem[]
    nodeCatalog?: readonly NodeGroup[]
    connected?: boolean
    /** Pinning a url-test / fallback node only needs the kernel controller, not takeover (R28). */
    kernelRunning?: boolean
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
    open: true,
    pages: () =>
      PAGES.map((page) => ({ id: page.id, get label() { return page.label }, icon: page.icon })),
    settings: () => [
      { id: 'general', get label() { return tr('通用设置') }, get description() { return tr('外观、启动、统计与快捷键') }, icon: 'sliders' },
      { id: 'proxy', get label() { return tr('系统代理设置') }, get description() { return tr('代理主机、PAC 模式与绕过列表') }, icon: 'monitor' },
      { id: 'tun', get label() { return tr('TUN 设置') }, get description() { return tr('栈、DNS 劫持与 MTU') }, icon: 'shield' },
      { id: 'network', get label() { return tr('端口与网络') }, get description() { return tr('代理端口、局域网共享与 IPv6') }, icon: 'network' },
      { id: 'behavior', get label() { return tr('代理与测速') }, get description() { return tr('节点切换、延迟测试与嗅探') }, icon: 'zap' },
      { id: 'dns', get label() { return tr('DNS 设置') }, get description() { return tr('Fake-IP、解析策略与 Hosts') }, icon: 'globe' },
      { id: 'kernel', get label() { return tr('内核设置') }, get description() { return tr('Mihomo 版本、日志与运行维护') }, icon: 'cpu' },
      { id: 'backup', get label() { return tr('备份与关于') }, get description() { return tr('备份恢复、版本与更新') }, icon: 'database' },
    ],
    profiles: () => [],
    nodeCatalog: () => [],
    connected: false,
    kernelRunning: false,
    hasProfiles: true,
    systemProxy: false,
    tun: false,
    sidebarCollapsed: false,
    platform: 'desktop',
  },
)
const emit = defineEmits<{
  navigate: [page: string]
  'open-settings': [tab: string, focus?: string]
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
const settings = computed(() => [
  ...props.settings.filter(
    (item) => !(props.platform === 'android' && (item.id === 'tun' || item.id === 'proxy')),
  ),
  // Traffic stats live on the general settings page, where the switch and the
  // stats button are; the palette jumps there so the entry always has a target (R43).
  {
    id: 'traffic-stats',
    label: t('settings.traffic.title'),
    description: t('traffic.subtitle'),
    icon: 'activity',
  },
])

const defaultActions = computed<PaletteAction[]>(() => [
  {
    id: 'connect',
    get label() { return tr('连接') },
    icon: 'power',
    disabled: props.connected,
    reason: props.connected ? tr('已连接') : undefined,
  },
  {
    id: 'disconnect',
    get label() { return tr('断开') },
    icon: 'stop',
    disabled: !props.connected,
    reason: !props.connected ? tr('连接后可断开') : undefined,
  },
  {
    id: 'test-all',
    get label() { return tr('全部测速') },
    icon: 'zap',
    disabled: !props.connected,
    reason: !props.connected ? tr('连接后可测速') : undefined,
  },
  {
    id: 'refresh-profiles',
    get label() { return tr('更新全部订阅') },
    icon: 'refresh',
    disabled: !props.hasProfiles,
    reason: !props.hasProfiles ? tr('先添加配置') : undefined,
  },
  { id: 'add-profile', get label() { return tr('添加配置') }, icon: 'plus' },
  {
    id: 'mode-rule',
    get label() { return tr('切换为规则模式') },
    icon: 'route',
    hint: props.mode === 'rule' ? tr('当前') : 'Rule',
  },
  {
    id: 'mode-global',
    get label() { return tr('切换为全局模式') },
    icon: 'globe',
    hint: props.mode === 'global' ? tr('当前') : 'Global',
  },
  {
    id: 'mode-direct',
    get label() { return tr('切换为直连模式') },
    icon: 'zap',
    hint: props.mode === 'direct' ? tr('当前') : 'Direct',
  },
  ...(props.platform === 'android'
    ? []
    : [
        {
          id: 'toggle-system-proxy',
          label: props.systemProxy ? tr('关闭系统代理') : tr('开启系统代理'),
          icon: 'monitor',
          hint: props.systemProxy ? tr('已开启') : 'HTTP / SOCKS',
        },
        {
          id: 'toggle-tun',
          label: props.tun ? tr('关闭 TUN 模式') : tr('开启 TUN 模式'),
          icon: 'shield',
          hint: props.tun ? tr('已开启') : tr('虚拟网卡'),
        },
        {
          id: 'toggle-sidebar',
          label: props.sidebarCollapsed ? tr('展开侧边栏') : tr('收起侧边栏'),
          icon: props.sidebarCollapsed ? 'panel-left-open' : 'panel-left-close',
          hint: shortcutKeyLabel(getShortcut('sidebar').combo),
        },
        { id: 'copy-proxy-env', get label() { return tr('复制终端环境变量') }, icon: 'terminal', hint: 'HTTP / SOCKS5' },
        { id: 'open-shortcuts', get label() { return tr('查看快捷键说明') }, icon: 'keyboard', hint: '?' },
      ]),
  {
    id: 'open-config',
    get label() { return tr('查看生效配置') },
    icon: 'file',
    hint: 'YAML',
    disabled: !props.hasProfiles,
    reason: !props.hasProfiles ? tr('先添加配置') : undefined,
  },
  {
    id: 'flush-fakeip',
    get label() { return tr('刷新 FakeIP 缓存') },
    icon: 'refresh',
    disabled: !props.connected,
    reason: !props.connected ? tr('连接后可用') : undefined,
  },
  {
    id: 'flush-dns',
    get label() { return tr('刷新 DNS 缓存') },
    icon: 'refresh',
    disabled: !props.connected,
    reason: !props.connected ? tr('连接后可用') : undefined,
  },
  // Opens even while the kernel is down: the dialog itself says why it cannot query (R31).
  { id: 'dns-query', get label() { return tr('DNS 查询') }, icon: 'search', hint: 'A / AAAA / MX' },
  { id: 'toggle-theme', get label() { return tr('切换主题') }, icon: 'moon' },
  { id: 'cycle-palette', get label() { return tr('切换配色方案') }, icon: 'sparkles' },
  { id: 'open-logs', get label() { return tr('打开日志') }, icon: 'terminal' },
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

const RECENT_STORAGE_KEY = 'billow:palette-recent'
const MAX_RECENT = 4
const VALID_KINDS = new Set<EntryKind>(['page', 'setting', 'action', 'profile', 'group', 'node'])

interface RecentRecord {
  kind: EntryKind
  id: string
  groupName?: string
}

function readRecent(): RecentRecord[] | null {
  try {
    if (typeof localStorage === 'undefined') return null
    const raw = localStorage.getItem(RECENT_STORAGE_KEY)
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    const result: RecentRecord[] = []
    for (const item of parsed) {
      if (!item || typeof item !== 'object') continue
      const rec = item as Record<string, unknown>
      if (typeof rec.kind !== 'string' || !VALID_KINDS.has(rec.kind as EntryKind)) continue
      if (typeof rec.id !== 'string' || !rec.id) continue
      if (rec.groupName !== undefined && typeof rec.groupName !== 'string') continue
      result.push({
        kind: rec.kind as EntryKind,
        id: rec.id,
        ...(rec.groupName ? { groupName: rec.groupName } : {}),
      })
      if (result.length >= MAX_RECENT) break
    }
    return result
  } catch {
    return null
  }
}

function writeRecent(items: readonly RecentRecord[]) {
  try {
    if (typeof localStorage === 'undefined') return
    localStorage.setItem(RECENT_STORAGE_KEY, JSON.stringify(items.slice(0, MAX_RECENT)))
  } catch {
    /* degrade silently to in-memory recent list */
  }
}

const recentRecords = ref<RecentRecord[]>(readRecent() ?? [])

function recordRecent(entry: PaletteEntry) {
  if (DESTRUCTIVE_ACTION.test(`${entry.id} ${entry.label}`)) return
  const nextRecord: RecentRecord = {
    kind: entry.kind,
    id: entry.id,
    ...(entry.groupName ? { groupName: entry.groupName } : {}),
  }
  const deduped = recentRecords.value.filter(
    (item) =>
      !(
        item.kind === nextRecord.kind &&
        item.id === nextRecord.id &&
        (item.groupName ?? '') === (nextRecord.groupName ?? '')
      ),
  )
  const updated = [nextRecord, ...deduped].slice(0, MAX_RECENT)
  recentRecords.value = updated
  writeRecent(updated)
}

function matches(label: string, hint?: string): boolean {
  if (!queryTokens.value.length) return true
  return matchesTokens(`${label} ${hint ?? ''}`, queryTokens.value)
}

/** Config `hidden: true` groups are not offered here (R29). */
const listedCatalog = computed(() => listedGroups(props.nodeCatalog))

const primaryManualGroup = computed(() => {
  const manual = listedCatalog.value.filter((group) => group.kind === 'manual')
  if (props.mode === 'global') {
    return listedCatalog.value.find((group) => group.name === 'GLOBAL') ?? manual[0] ?? null
  }
  return manual.find((group) => Boolean(group.now)) ?? manual[0] ?? null
})

function groupHint(group: NodeGroup): string {
  const typeLabel = autoTypeLabel(group)
  const now = [typeLabel, group.now].filter(Boolean).join(' · ') || tr('未选择节点')
  return group.fixed ? tr('{0} · 已固定', { 0: now }) : now
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
        reason: isDisabled ? (reason(item) ?? tr('当前不可用')) : undefined,
        index: index++,
      })
    }
    return { id: kind, label: title, entries }
  }

  const actionItems = (props.actions ?? defaultActions.value).filter(
    (item) => !DESTRUCTIVE_ACTION.test(`${item.id} ${item.label}`),
  )

  const visibleGroups = props.mode === 'global'
    ? listedCatalog.value
    : listedCatalog.value.filter((group) => group.name !== 'GLOBAL')
  const groupNames = new Set(props.nodeCatalog.map((group) => group.name))

  const recentEntries: PaletteEntry[] = []
  const quickEntries: PaletteEntry[] = []
  const profileEntries: PaletteEntry[] = []
  const proxyEntries: PaletteEntry[] = []

  if (!normalized.value) {
    for (const rec of recentRecords.value) {
      const recentKey = `recent:${rec.kind}:${rec.id}${rec.groupName ? `:${rec.groupName}` : ''}`
      if (rec.kind === 'page') {
        const page = props.pages.find((item) => item.id === rec.id)
        if (!page) continue
        recentEntries.push({
          key: recentKey,
          kind: 'page',
          id: page.id,
          label: page.label,
          icon: page.icon,
          hint: props.currentPage && page.id === props.currentPage ? tr('当前') : pageKeyHint(page.id),
          index: 0,
        })
      } else if (rec.kind === 'setting') {
        const setting = settings.value.find((item) => item.id === rec.id)
        if (!setting) continue
        recentEntries.push({
          key: recentKey,
          kind: 'setting',
          id: setting.id,
          label: setting.label,
          icon: setting.icon,
          hint: setting.description,
          index: 0,
        })
      } else if (rec.kind === 'action') {
        const action = actionItems.find((item) => item.id === rec.id)
        if (!action) continue
        const isDisabled = Boolean(action.disabled)
        recentEntries.push({
          key: recentKey,
          kind: 'action',
          id: action.id,
          label: action.label,
          icon: action.icon,
          hint: action.hint,
          disabled: isDisabled,
          reason: isDisabled ? (action.reason ?? tr('当前不可用')) : undefined,
          index: 0,
        })
      } else if (rec.kind === 'profile') {
        const profile = props.profiles.find((item) => item.id === rec.id)
        if (!profile) continue
        recentEntries.push({
          key: recentKey,
          kind: 'profile',
          id: profile.id,
          label: profile.name,
          icon: profile.kind === 'local' ? 'file' : 'link',
          hint: profile.current
            ? tr('当前')
            : profile.proxy_count
              ? tr('{0} 个节点', { 0: profile.proxy_count })
              : undefined,
          index: 0,
        })
      } else if (rec.kind === 'group') {
        const group = visibleGroups.find((item) => item.name === rec.id)
        if (!group) continue
        recentEntries.push({
          key: recentKey,
          kind: 'group',
          id: group.name,
          label: group.name,
          icon: 'route',
          hint: groupHint(group),
          index: 0,
        })
      } else if (rec.kind === 'node' && rec.groupName) {
        const targetGroup = visibleGroups.find((item) => item.name === rec.groupName)
        if (!targetGroup || (targetGroup.kind !== 'manual' && !targetGroup.pinnable)) continue
        const node = targetGroup.nodes.find((item) => item.name === rec.id)
        if (!node || groupNames.has(node.name) || isInfoNode(node.name)) continue
        const proto = protocolLabel(node.node_type)
        const delay = props.connected ? delayText(node.delay_ms, node.failed) : ''
        const pinned = targetGroup.pinnable && targetGroup.fixed === node.name
        const pinOffline = targetGroup.pinnable && !props.kernelRunning
        recentEntries.push({
          key: recentKey,
          kind: 'node',
          id: node.name,
          groupName: targetGroup.name,
          label: node.name,
          icon: 'globe',
          hint: [targetGroup.name, pinned ? tr('已固定') : node.selected ? tr('当前') : delay || proto]
            .filter(Boolean)
            .join(' · '),
          disabled: pinOffline || undefined,
          reason: pinOffline ? tr('内核没有运行') : undefined,
          index: 0,
        })
      }
    }

    const currentProfile = props.profiles.find((item) => item.current) ?? null
    if (currentProfile) {
      quickEntries.push({
        key: `profile:${currentProfile.id}`,
        kind: 'profile',
        id: currentProfile.id,
        label: currentProfile.name,
        icon: currentProfile.kind === 'local' ? 'file' : 'link',
        hint: tr('当前配置'),
        index: 0,
      })
    }
    const primary = primaryManualGroup.value
    if (primary) {
      quickEntries.push({
        key: `group:${primary.name}`,
        kind: 'group',
        id: primary.name,
        label: primary.name,
        icon: 'route',
        hint: groupHint(primary),
        index: 0,
      })
    }
  } else {
    for (const item of props.profiles) {
      const itemHint = item.current ? tr('当前') : item.proxy_count ? tr('{0} 个节点', { 0: item.proxy_count }) : undefined
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

    for (const group of visibleGroups) {
      const typeLabel = autoTypeLabel(group)
      if (!matches(group.name, typeLabel || groupTypeLabel(group))) continue
      proxyEntries.push({
        key: `group:${group.name}`,
        kind: 'group',
        id: group.name,
        label: group.name,
        icon: 'route',
        hint: groupHint(group),
        index: 0,
      })
    }

    const primary = primaryManualGroup.value
    // url-test / fallback come after select groups: picking there fixes the node (R28).
    const manualGroups = [
      ...(primary && primary.kind === 'manual' ? [primary] : []),
      ...visibleGroups.filter((group) => group.kind === 'manual' && group.name !== primary?.name),
      ...visibleGroups.filter((group) => group.pinnable),
    ]
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
        const pinned = targetGroup.pinnable && targetGroup.fixed === node.name
        const pinOffline = targetGroup.pinnable && !props.kernelRunning
        proxyEntries.push({
          key: `node:${targetGroup.name}:${node.name}`,
          kind: 'node',
          id: node.name,
          groupName: targetGroup.name,
          label: node.name,
          icon: 'globe',
          hint: [targetGroup.name, pinned ? tr('已固定') : node.selected ? tr('当前') : delay || proto].filter(Boolean).join(' · '),
          disabled: pinOffline || undefined,
          reason: pinOffline ? tr('内核没有运行') : undefined,
          index: 0,
        })
        added += 1
      }
    }
  }

  const sections = [
    { id: 'recent', get label() { return tr('最近使用') }, entries: recentEntries },
    { id: 'quick', get label() { return tr('快捷访问') }, entries: quickEntries },
    build(
      'page',
      tr('页面'),
      props.pages,
      (item) => item.icon,
      (item) => (props.currentPage && item.id === props.currentPage ? tr('当前') : pageKeyHint(item.id)),
      () => false,
      () => undefined,
    ),
    build(
      'setting',
      tr('设置'),
      settings.value,
      (item) => item.icon,
      (item) => item.description,
      () => false,
      () => undefined,
    ),
    build(
      'action',
      tr('动作'),
      actionItems,
      (item) => item.icon,
      (item) => item.hint,
      (item) => Boolean(item.disabled),
      (item) => item.reason,
    ),
    { id: 'profile', get label() { return tr('配置') }, entries: profileEntries },
    { id: 'proxy', get label() { return tr('代理组与节点') }, entries: proxyEntries },
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
  recordRecent(entry)
  if (entry.kind === 'page') emit('navigate', entry.id)
  // Traffic stats are a dialog opened from the general settings section (R43).
  else if (entry.kind === 'setting' && entry.id === 'traffic-stats') emit('open-settings', 'general', 'traffic-history')
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

const PaletteTrap = defineComponent({
  name: 'PaletteTrap',
  props: {
    getPanel: { type: Function as PropType<() => HTMLElement | null>, required: true },
    onClose: { type: Function as PropType<() => void>, required: true },
    initialFocus: { type: Function as PropType<() => HTMLElement | null | undefined>, required: true },
  },
  setup(trapProps) {
    useFocusTrap(trapProps.getPanel, {
      onClose: trapProps.onClose,
      initialFocus: trapProps.initialFocus,
    })
    return () => null
  },
})

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) {
      const stored = readRecent()
      if (stored !== null) recentRecords.value = stored
      query.value = ''
      active.value = 0
    }
  },
)

function requestClose() {
  if (!props.open) return
  emit('close')
}

function getPanel(): HTMLElement | null {
  return panel.value
}

function resolveInitialFocus(): HTMLElement | null {
  return inputEl.value ?? getFocusable(panel.value)[0] ?? null
}
</script>

<template>
  <Teleport to="body">
    <Transition name="overlay-fade" appear>
      <div v-if="open" class="overlay palette-overlay" @mousedown.self="requestClose">
        <section
          ref="panel"
          class="palette"
          role="dialog"
          aria-modal="true"
          :aria-labelledby="titleId"
          @keydown="onKeydown"
        >
          <h2 :id="titleId" class="sr-only">{{ tr('命令面板') }}</h2>
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
              :aria-label="tr('搜索命令')"
              :placeholder="tr('搜索页面、设置、节点或动作')"
              autocomplete="off"
              spellcheck="false"
              @input="active = 0"
            />
            <button
              v-if="query"
              type="button"
              class="icon-btn sm"
              :aria-label="tr('清空搜索')"
              data-testid="palette-clear"
              @click="query = ''; inputEl?.focus()"
            >
              <Icon name="x" :size="14" />
            </button>
            <kbd class="palette-kbd">{{ paletteKey }}</kbd>
            <button type="button" class="icon-btn sm" :aria-label="tr('关闭')" @click="requestClose">
              <Icon name="x" :size="15" />
            </button>
          </div>

          <div :id="listId" class="palette-list" role="listbox" :aria-label="tr('命令')">
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
                <span v-else-if="entry.hint" class="palette-hint" :class="{ current: entry.hint === tr('当前') || entry.hint.endsWith(tr('· 当前')) }">{{ entry.hint }}</span>
              </div>
            </div>
            <p v-if="!groups.length" class="palette-empty">{{ tr('没有匹配的命令') }}</p>
          </div>

          <footer class="palette-foot">
            <span>{{ tr('↑↓ 选择') }}</span>
            <span>{{ tr('Enter 执行') }}</span>
            <span>{{ tr('Esc 关闭') }}</span>
          </footer>
        </section>
      </div>
    </Transition>
  </Teleport>
  <PaletteTrap
    v-if="open"
    :get-panel="getPanel"
    :on-close="requestClose"
    :initial-focus="resolveInitialFocus"
  />
</template>
