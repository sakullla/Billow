<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import Icon from '../components/Icon.vue'
import Segmented from '../components/Segmented.vue'
import { delayText, delayTone, protocolLabel } from '../lib/format'
import { useStore } from '../lib/store'
import type { Mode, NodeGroup, NodeItem } from '../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

type Sort = 'default' | 'delay' | 'name'
const SORTS: { id: Sort; label: string }[] = [
  { id: 'default', label: '默认' },
  { id: 'delay', label: '延迟' },
  { id: 'name', label: '名称' },
]
const MODES: { id: Mode; label: string }[] = [
  { id: 'rule', label: '规则' },
  { id: 'global', label: '全局' },
  { id: 'direct', label: '直连' },
]

function readPref<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(`billow:${key}`)
    return raw == null ? fallback : (JSON.parse(raw) as T)
  } catch {
    return fallback
  }
}
function writePref(key: string, value: unknown) {
  try {
    localStorage.setItem(`billow:${key}`, JSON.stringify(value))
  } catch {
    /* storage unavailable */
  }
}

const query = ref('')
const sort = ref<Sort>(readPref('proxy-sort', 'default'))
const dense = ref<boolean>(readPref('proxy-dense', false))
const open = ref<Set<string>>(new Set(readPref<string[]>('proxy-open', [])))
const hideAuto = ref<boolean>(readPref('proxy-hide-auto', false))

watch(sort, (value) => writePref('proxy-sort', value))
watch(dense, (value) => writePref('proxy-dense', value))
watch(hideAuto, (value) => writePref('proxy-hide-auto', value))

function toggle(name: string) {
  const next = new Set(open.value)
  if (next.has(name)) next.delete(name)
  else next.add(name)
  open.value = next
  writePref('proxy-open', [...next])
}

function sorted(nodes: NodeItem[]): NodeItem[] {
  const list = nodes.map((node, index) => ({ node, index }))
  if (sort.value === 'name') list.sort((a, b) => a.node.name.localeCompare(b.node.name, 'zh-CN') || a.index - b.index)
  if (sort.value === 'delay') {
    const key = (node: NodeItem) => (node.failed ? 2e9 : node.delay_ms == null ? 1e9 : node.delay_ms)
    list.sort((a, b) => key(a.node) - key(b.node) || a.index - b.index)
  }
  return list.map((item) => item.node)
}

const groups = computed(() => {
  const needle = query.value.trim().toLowerCase()
  const source = snap.value.mode === 'global'
    ? snap.value.node_catalog
    : snap.value.node_catalog.filter((group) => group.name !== 'GLOBAL')
  return source
    .filter((group) => !(hideAuto.value && group.kind === 'auto'))
    .map((group) => ({
      ...group,
      nodes: sorted(needle ? group.nodes.filter((node) => node.name.toLowerCase().includes(needle)) : group.nodes),
    }))
    .filter((group) => !needle || group.nodes.length > 0 || group.name.toLowerCase().includes(needle))
})

const testedCount = computed(() => {
  const seen = new Map<string, NodeItem>()
  snap.value.node_catalog.forEach((group) => group.nodes.forEach((node) => seen.set(node.name, node)))
  const all = [...seen.values()].filter((node) => node.delay_ms != null)
  return { total: seen.size, ok: all.length }
})

function groupTone(group: NodeGroup) {
  const now = group.nodes.find((node) => node.name === group.now)
  return now ? delayTone(now.delay_ms, now.failed) : 'none'
}

function pick(group: NodeGroup, node: NodeItem) {
  if (group.kind !== 'manual' || node.selected) return
  void store.selectNode(group.name, node.name)
}

function isOpen(name: string) {
  return query.value.trim().length > 0 || open.value.has(name)
}

async function locate(name: string | null) {
  if (!name) return
  if (!open.value.has(name)) toggle(name)
  await nextTick()
  const el = document.querySelector(`[data-group-card="${CSS.escape(name)}"]`)
  if (el instanceof HTMLElement) el.scrollIntoView?.({ block: 'start', behavior: 'smooth' })
}

onMounted(() => void locate(store.focusGroup.value))
watch(() => store.focusGroup.value, (name) => void locate(name))
</script>

<template>
  <div class="page proxies">
    <header class="page-head">
      <div>
        <h1>代理</h1>
        <p class="muted small">
          <template v-if="snap.node_catalog.length">{{ snap.node_catalog.length }} 个代理组 · {{ testedCount.total }} 个节点</template>
          <template v-else>{{ snap.nodes_notice ?? '没有代理组' }}</template>
        </p>
      </div>
      <div class="head-actions">
        <Segmented
          v-if="snap.active_id"
          :model-value="snap.mode"
          :options="MODES"
          size="sm"
          label="出站模式"
          :disabled="store.busy.mode"
          @update:model-value="store.setMode"
        />
        <button
          type="button"
          class="btn primary sm"
          :disabled="store.busy.testAll || !snap.kernel_running"
          :title="snap.kernel_running ? '测试全部节点延迟' : '连接后才能测速'"
          data-testid="test-all"
          @click="store.testAll()"
        >
          <span v-if="store.busy.testAll" class="spinner sm" />
          <Icon v-else name="zap" :size="15" />
          全部测速
        </button>
      </div>
    </header>

    <div v-if="snap.node_catalog.length" class="toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" placeholder="搜索节点" data-testid="node-search" data-page-search />
        <button v-if="query" type="button" class="icon-btn sm" aria-label="清空" @click="query = ''"><Icon name="x" :size="14" /></button>
      </div>
      <Segmented v-model="sort" :options="SORTS" size="sm" label="排序" />
      <button type="button" class="icon-btn" :class="{ active: hideAuto }" :title="hideAuto ? '显示自动组' : '隐藏自动组'" @click="hideAuto = !hideAuto">
        <Icon name="cpu" />
      </button>
      <button type="button" class="icon-btn" :title="dense ? '卡片视图' : '紧凑视图'" @click="dense = !dense">
        <Icon :name="dense ? 'grid' : 'list'" />
      </button>
    </div>

    <div v-if="!snap.node_catalog.length" class="empty">
      <Icon name="globe" :size="40" :stroke="1.4" />
      <h3>{{ snap.nodes_notice ?? '没有代理组' }}</h3>
      <p class="muted">添加并启用一份配置后，这里会列出它的代理组与节点。</p>
      <button type="button" class="btn primary" @click="store.go('profiles')">前往配置</button>
    </div>
    <div v-else-if="!groups.length" class="empty small">
      <h3>没有匹配的节点</h3>
      <button type="button" class="btn ghost" @click="query = ''">清空搜索</button>
    </div>

    <section
      v-for="group in groups"
      :key="group.name"
      class="card group"
      :class="{ open: isOpen(group.name), located: store.focusGroup.value === group.name }"
      :data-group-card="group.name"
    >
      <header class="group-head" role="button" tabindex="0" :aria-expanded="isOpen(group.name)" @click="toggle(group.name)" @keydown.enter.prevent="toggle(group.name)" @keydown.space.prevent="toggle(group.name)">
        <span class="group-badge" :class="groupTone(group)" />
        <div class="group-title">
          <div class="group-name">
            <strong>{{ group.name }}</strong>
            <span class="tag">{{ protocolLabel(group.group_type) || (group.kind === 'manual' ? '手选' : '自动') }}</span>
            <span class="muted small">{{ group.nodes.length }}</span>
          </div>
          <div class="group-now small">
            <Icon v-if="group.kind === 'auto'" name="cpu" :size="13" />
            <span>{{ group.now || (group.kind === 'auto' ? '连接后显示' : '—') }}</span>
          </div>
        </div>
        <button
          type="button"
          class="icon-btn"
          :title="snap.kernel_running ? '测试该组延迟' : '连接后才能测速'"
          :disabled="!snap.kernel_running || store.busy[`test:${group.name}`]"
          @click.stop="store.testGroup(group.name)"
        >
          <span v-if="store.busy[`test:${group.name}`]" class="spinner sm" />
          <Icon v-else name="zap" />
        </button>
        <Icon name="chevron-down" class="chevron" />
      </header>

      <div v-if="isOpen(group.name)" class="nodes" :class="{ dense }">
        <div
          v-for="node in group.nodes"
          :key="node.name"
          class="node"
          :class="{ selected: node.selected, locked: group.kind !== 'manual' }"
          :role="group.kind === 'manual' ? 'button' : undefined"
          :tabindex="group.kind === 'manual' ? 0 : undefined"
          :aria-pressed="group.kind === 'manual' ? node.selected : undefined"
          :data-node="node.name"
          @click="pick(group, node)"
          @keydown.enter.prevent="pick(group, node)"
        >
          <div class="node-main">
            <span class="node-name" :title="node.name">{{ node.name }}</span>
            <span v-if="!dense" class="node-type">{{ protocolLabel(node.node_type) || ' ' }}</span>
          </div>
          <button
            type="button"
            class="delay"
            :class="[delayTone(node.delay_ms, node.failed), { busy: store.busy[`node:${node.name}`] }]"
            :disabled="!snap.kernel_running"
            :title="snap.kernel_running ? '测试延迟' : '连接后才能测速'"
            @click.stop="store.testNode(node.name)"
          >
            <span v-if="store.busy[`node:${node.name}`]" class="spinner xs" />
            <template v-else>{{ delayText(node.delay_ms, node.failed) || '测速' }}</template>
          </button>
          <Icon v-if="node.selected" name="check" :size="14" class="node-check" :stroke="2.6" />
        </div>
      </div>
    </section>
  </div>
</template>
