<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import ChainPath from './ChainPath.vue'
import EmptyState from './EmptyState.vue'
import GroupIcon from './GroupIcon.vue'
import Icon from './Icon.vue'
import Modal from './Modal.vue'
import {
  autoTypeLabel,
  canPickNode,
  delayText,
  delayTone,
  effectiveGroupDelay,
  groupTypeLabel,
  isInfoNode,
  protocolLabel,
  resolveChain,
} from '../lib/format'
import { tr } from '../lib/i18n'
import { highlightTokens, matchesTokens, splitQueryTokens } from '../lib/search'
import { useStore } from '../lib/store'
import type { NodeGroup, NodeItem } from '../lib/types'

const BUILTIN_POLICIES = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS'])

const props = withDefaults(
  defineProps<{
    open?: boolean
    group: NodeGroup | null
    compact?: boolean
  }>(),
  { open: true },
)
const emit = defineEmits<{ close: [] }>()

const store = useStore()
const snap = computed(() => store.snapshot.value)
const modalOpen = computed(() => props.open && Boolean(props.group))

const query = ref('')
const switchingNode = ref<string | null>(null)
const unfixing = ref(false)
const failedNode = ref<{ name: string; reason: string } | null>(null)

watch(
  () => [props.open, props.group?.name] as const,
  ([isOpen], prev) => {
    if (isOpen || (prev && prev[1] !== props.group?.name)) {
      query.value = ''
      switchingNode.value = null
      unfixing.value = false
      failedNode.value = null
    }
  },
)

const isSwitching = computed(
  () =>
    switchingNode.value !== null ||
    unfixing.value ||
    Boolean(props.group && store.busy[`select:${props.group.name}`]),
)
const offlineAutoGroup = computed(() => Boolean(props.group) && !snap.value.kernel_running && props.group!.kind !== 'manual')
const rowDisabled = computed(() => isSwitching.value || offlineAutoGroup.value)

const catalogByName = computed(() => new Map(snap.value.node_catalog.map((item) => [item.name, item])))
const groupNames = computed(() => new Set(snap.value.node_catalog.map((item) => item.name)))

function nestedGroupOf(node: NodeItem): NodeGroup | null {
  return catalogByName.value.get(node.name) ?? null
}

function viaOf(node: NodeItem): string {
  const chain = resolveChain(node.name, snap.value.node_catalog)
  return chain[chain.length - 1] ?? catalogByName.value.get(node.name)?.now ?? ''
}

function tagLabel(node: NodeItem, tag: string): string {
  if (tag === 'chained') {
    return node.dialer_proxy ? tr('链式 · {0}', { 0: node.dialer_proxy }) : tr('链式')
  }
  return tag
}

const currentHops = computed(() => {
  const group = props.group
  if (!group) return []
  const chain = resolveChain(group.name, snap.value.node_catalog)
  return chain.length ? chain : group.now ? [group.now] : []
})

const currentDelay = computed(() => {
  const none = { text: '—', tone: 'none' }
  const group = props.group
  if (!group || !snap.value.connected) return none
  const state = effectiveGroupDelay(group, snap.value.node_catalog, store.testResults.value)
  if (!state.target || (!state.failed && state.delay == null)) return none
  return { text: delayText(state.delay, state.failed), tone: delayTone(state.delay, state.failed) }
})

const subtitle = computed(() => {
  const group = props.group
  if (!group) return ''
  if (group.fixed) return tr('当前已固定为 {0}。', { 0: group.fixed })
  if (group.kind !== 'manual') return tr('点选后固定使用该节点，可随时恢复自动')
  return tr('选择后立即切换，无需离开首页')
})

function nodeState(node: NodeItem): { delay: number | null; failed: boolean } {
  const live = store.testResults.value[node.name]
  return live ? { delay: live.delay, failed: live.failed } : { delay: node.delay_ms, failed: node.failed }
}

function isSelected(node: NodeItem): boolean {
  return node.selected || props.group?.now === node.name
}

const queryTokens = computed(() => splitQueryTokens(query.value))

const filteredNodes = computed(() => {
  const group = props.group
  if (!group) return []
  const tokens = queryTokens.value
  return group.nodes.filter((node) => {
    if (!tokens.length && !node.selected && isInfoNode(node.name)) return false
    if (!tokens.length) return true
    const haystack = [
      node.name,
      node.node_type,
      protocolLabel(node.node_type),
      node.dialer_proxy ?? '',
      viaOf(node),
      ...node.tags,
      ...node.tags.map((tag) => tagLabel(node, tag)),
    ].join(' ')
    return matchesTokens(haystack, tokens)
  })
})

const fastestCandidate = computed<{ node: NodeItem; delay: number } | null>(() => {
  const group = props.group
  if (!group || !canPickNode(group) || !snap.value.kernel_running) return null
  let best: { node: NodeItem; delay: number } | null = null
  for (const node of group.nodes) {
    if (groupNames.value.has(node.name)) continue
    if (BUILTIN_POLICIES.has(node.name.toUpperCase()) || isInfoNode(node.name)) continue
    const state = nodeState(node)
    if (state.failed || state.delay == null || state.delay <= 0) continue
    if (!best || state.delay < best.delay) {
      best = { node, delay: state.delay }
    }
  }
  if (!best) return null
  if (group.kind === 'manual' ? isSelected(best.node) : group.fixed === best.node.name || (!group.fixed && isSelected(best.node))) {
    return null
  }
  return best
})

const testingGroup = computed(
  () => Boolean(props.group) && (store.activeTest.value?.group === props.group!.name || Boolean(store.busy[`test:${props.group!.name}`])),
)
const testDisabled = computed(() => !snap.value.kernel_running || store.testing.value || isSwitching.value)
const unfixDisabled = computed(() => !snap.value.kernel_running || isSwitching.value)

function requestClose() {
  if (isSwitching.value) return
  emit('close')
}

function initialFocus(): HTMLElement | null | undefined {
  const group = props.group
  if (!group) return undefined
  if (typeof window !== 'undefined' && window.matchMedia?.('(pointer: coarse)').matches === true) {
    return undefined
  }
  const activeName = group.fixed || group.now || filteredNodes.value[0]?.name
  if (!activeName) return undefined
  return document.querySelector<HTMLElement>(`[data-picker-node="${CSS.escape(activeName)}"]`)
}

async function pickNode(node: NodeItem, fastestDelay?: number) {
  const group = props.group
  if (!group || !canPickNode(group) || isSwitching.value || offlineAutoGroup.value) return
  const alreadyNoop = group.kind === 'manual' ? isSelected(node) : group.fixed === node.name
  if (alreadyNoop) {
    failedNode.value = null
    emit('close')
    return
  }

  switchingNode.value = node.name
  failedNode.value = null
  const beforeFailure = snap.value.failure
  const beforeNodesError = snap.value.nodes_error
  try {
    const result = await store.selectNode(group.name, node.name)
    const afterGroup = result?.node_catalog.find((item) => item.name === group.name)
    const afterNode = afterGroup?.nodes.find((item) => item.name === node.name)
    const targetActive = Boolean(
      afterGroup &&
        (group.kind === 'manual'
          ? afterGroup.now === node.name || afterNode?.selected
          : afterGroup.fixed === node.name || afterGroup.now === node.name || afterNode?.selected),
    )
    const newErr =
      (result?.nodes_error && result.nodes_error !== beforeNodesError ? result.nodes_error : null) ||
      (result?.failure && result.failure !== beforeFailure ? result.failure : null)

    if (result && !newErr && targetActive) {
      failedNode.value = null
      if (fastestDelay != null) {
        store.toast(tr('已切至最快节点：{0} ({1})', { 0: node.name, 1: delayText(fastestDelay, false) }), 'success')
      }
      emit('close')
      return
    }
    const reason =
      newErr ||
      result?.nodes_error ||
      result?.failure ||
      result?.notice ||
      store.lastRunError.value ||
      tr('节点切换失败')
    failedNode.value = { name: node.name, reason }
  } finally {
    switchingNode.value = null
  }
}

function pickFastest() {
  const best = fastestCandidate.value
  if (!best) return
  void pickNode(best.node, best.delay)
}

async function unfix() {
  const group = props.group
  if (!group || !group.fixed || unfixDisabled.value) return
  unfixing.value = true
  failedNode.value = null
  const beforeFailure = snap.value.failure
  const beforeNodesError = snap.value.nodes_error
  try {
    const result = await store.unfixGroup(group.name)
    const afterGroup = result?.node_catalog.find((item) => item.name === group.name)
    const newErr =
      (result?.nodes_error && result.nodes_error !== beforeNodesError ? result.nodes_error : null) ||
      (result?.failure && result.failure !== beforeFailure ? result.failure : null)
    if (result && !newErr && !afterGroup?.fixed) {
      emit('close')
    }
  } finally {
    unfixing.value = false
  }
}

function openInProxies() {
  const group = props.group
  if (!group || isSwitching.value) return
  emit('close')
  store.go('proxies', group.name)
}

function onSearchKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape' && query.value) {
    event.preventDefault()
    event.stopPropagation()
    query.value = ''
    return
  }
  if (event.key === 'ArrowDown') {
    const first = document.querySelector<HTMLElement>('[data-testid="node-picker-list"] [data-picker-node]:not(:disabled)')
    if (first) {
      event.preventDefault()
      first.focus({ preventScroll: true })
    }
    return
  }
  if (event.key === 'Enter' && queryTokens.value.length > 0 && filteredNodes.value.length > 0) {
    event.preventDefault()
    if (filteredNodes.value.length === 1 && !rowDisabled.value) {
      void pickNode(filteredNodes.value[0]!)
      return
    }
    document.querySelector<HTMLElement>('[data-testid="node-picker-list"] [data-picker-node]:not(:disabled)')?.focus({ preventScroll: true })
  }
}
</script>

<template>
  <Modal
    :open="modalOpen"
    :title="group?.name ?? ''"
    :subtitle="subtitle"
    :before-close="() => !isSwitching"
    :initial-focus="initialFocus"
    @close="requestClose"
  >
    <div v-if="group" class="node-picker" data-testid="home-node-picker" :data-group="group.name">
      <div class="node-picker-summary">
        <span class="group-row-icon"><GroupIcon :icon="group.icon" :type="group.group_type" :size="18" /></span>
        <div class="node-picker-summary-body">
          <div class="node-picker-summary-head">
            <span v-if="autoTypeLabel(group)" class="tag sm">{{ autoTypeLabel(group) }}</span>
            <span v-if="group.fixed" class="tag sm accent" data-testid="node-picker-fixed-tag">{{ tr('已固定') }}</span>
            <ChainPath
              v-if="currentHops.length"
              class="node-picker-chain"
              :hops="currentHops"
              :groups="groupNames"
              fold
            />
            <span v-else class="muted small">{{ tr('未选择节点') }}</span>
          </div>
        </div>
        <span
          v-if="currentDelay.tone !== 'none'"
          class="delay mono"
          :class="currentDelay.tone"
          data-testid="node-picker-current-delay"
        >{{ currentDelay.text }}</span>
      </div>

      <div class="node-picker-toolbar">
        <label class="search node-picker-search">
          <Icon name="search" :size="15" />
          <input
            v-model="query"
            type="search"
            :placeholder="tr('搜索节点、协议或 UDP')"
            :aria-label="tr('搜索节点、协议或 UDP')"
            :disabled="isSwitching"
            data-testid="node-picker-search"
            @keydown="onSearchKeydown"
          />
          <button
            v-if="query"
            type="button"
            class="icon-btn xs"
            :aria-label="tr('清空筛选')"
            data-testid="node-picker-search-clear"
            @click="query = ''"
          >
            <Icon name="x" :size="13" />
          </button>
        </label>

        <div class="node-picker-actions">
          <button
            type="button"
            class="btn ghost sm"
            :disabled="testDisabled"
            :aria-busy="testingGroup || undefined"
            :title="snap.kernel_running ? tr('测试该组延迟') : tr('连接后才能测速')"
            data-testid="node-picker-test"
            @click="store.testGroup(group.name)"
          >
            <span v-if="testingGroup" class="spinner xs" aria-hidden="true" />
            <Icon v-else name="zap" :size="14" />
            <template v-if="testingGroup && store.testProgress.value.total > 0">
              {{ tr('测速中 ({0}/{1})', { 0: store.testProgress.value.tested, 1: store.testProgress.value.total }) }}
            </template>
            <template v-else>{{ testingGroup ? tr('测速中') : tr('测速') }}</template>
          </button>

          <button
            v-if="fastestCandidate"
            type="button"
            class="btn ghost sm group-fastest"
            :disabled="isSwitching"
            :title="tr('切换至当前最快的节点：{0} ({1})', { 0: fastestCandidate.node.name, 1: delayText(fastestCandidate.delay, false) })"
            data-testid="node-picker-fastest"
            @click="pickFastest"
          >
            <Icon name="zap" :size="13" />
            {{ compact ? tr('最快') : tr('选最快') }}
          </button>

          <button
            v-if="group.fixed"
            type="button"
            class="btn ghost sm"
            :disabled="unfixDisabled"
            :aria-busy="unfixing || undefined"
            :title="snap.kernel_running ? tr('解除固定，由组策略重新选择节点') : tr('内核没有运行')"
            data-testid="node-picker-unfix"
            @click="unfix"
          >
            <span v-if="unfixing" class="spinner xs" aria-hidden="true" />
            {{ tr('恢复自动') }}
          </button>
        </div>
      </div>

      <p v-if="!snap.kernel_running" class="muted small node-picker-offline" data-testid="node-picker-offline-hint">
        {{ offlineAutoGroup ? tr('内核没有运行，连接后才能固定节点、测速或恢复自动。') : tr('未连接时无法测速或恢复自动，连接后可用。') }}
      </p>

      <EmptyState
        v-if="!filteredNodes.length && queryTokens.length"
        variant="no-match"
        compact
        data-testid="node-picker-empty"
      >
        <template #action>
          <button type="button" class="btn ghost sm" data-testid="node-picker-clear-filter" @click="query = ''">
            {{ tr('清空筛选') }}
          </button>
        </template>
      </EmptyState>
      <EmptyState
        v-else-if="!filteredNodes.length"
        variant="no-data"
        compact
        :title="tr('没有可选节点')"
        :description="tr('当前代理组暂无可切换的节点。')"
        data-testid="node-picker-empty"
      />
      <div v-else class="option-list node-picker-list" data-testid="node-picker-list">
        <div
          v-for="(node, index) in filteredNodes"
          :key="node.name"
          class="node-picker-item"
          :class="{
            active: isSelected(node),
            switching: switchingNode === node.name,
            failed: failedNode?.name === node.name,
          }"
          :data-node-item="node.name"
        >
          <button
            type="button"
            class="option-row node-picker-row"
            :class="{ active: isSelected(node), switching: switchingNode === node.name }"
            :data-picker-node="node.name"
            :data-testid="`picker-node-${node.name}`"
            :disabled="offlineAutoGroup"
            :title="offlineAutoGroup ? tr('内核没有运行，连接后才能固定节点') : undefined"
            :aria-current="isSelected(node) ? 'true' : undefined"
            :aria-busy="switchingNode === node.name || undefined"
            :aria-disabled="rowDisabled || undefined"
            :aria-describedby="failedNode?.name === node.name ? `picker-error-${index}` : undefined"
            @click="pickNode(node)"
          >
            <span class="node-picker-body">
              <span class="node-picker-title-row">
                <span class="option-label node-picker-name" :title="node.name">
                  <template v-for="(part, partIdx) in highlightTokens(node.name, query)" :key="partIdx">
                    <mark v-if="part.hit">{{ part.text }}</mark>
                    <template v-else>{{ part.text }}</template>
                  </template>
                </span>
                <span v-if="group.fixed === node.name" class="tag accent sm">{{ tr('已固定') }}</span>
                <span v-else-if="isSelected(node)" class="tag accent sm" data-testid="picker-current-tag">{{ tr('当前') }}</span>
              </span>
              <span v-if="nestedGroupOf(node)" class="node-picker-meta muted small" data-testid="picker-node-via">
                <span class="node-picker-strategy">{{ groupTypeLabel(nestedGroupOf(node)!) }}</span>
                <span class="node-picker-via-target" :title="viaOf(node) || undefined">
                  {{ viaOf(node) ? `→ ${viaOf(node)}` : snap.kernel_running ? tr('→ 等待测速') : tr('→ 连接后显示') }}
                </span>
              </span>
              <span v-else class="node-picker-meta muted small" data-testid="picker-node-meta">
                <span v-if="protocolLabel(node.node_type)">{{ protocolLabel(node.node_type) }}</span>
                <span
                  v-for="tag in node.tags"
                  :key="tag"
                  class="udp"
                  :class="{ chained: tag === 'chained' }"
                >{{ tagLabel(node, tag) }}</span>
                <span
                  v-if="node.dialer_proxy && !node.tags.includes('chained')"
                  class="udp chained"
                >{{ tr('链式 · {0}', { 0: node.dialer_proxy }) }}</span>
              </span>
            </span>

            <span
              v-if="switchingNode === node.name"
              class="node-picker-state pending"
              role="status"
              data-testid="node-picker-switching"
            >
              <span class="spinner xs" aria-hidden="true" />
              <span>{{ tr('切换中') }}</span>
            </span>
            <span v-else class="node-picker-side">
              <span
                v-if="delayText(nodeState(node).delay, nodeState(node).failed)"
                class="delay mono"
                :class="delayTone(nodeState(node).delay, nodeState(node).failed)"
              >{{ delayText(nodeState(node).delay, nodeState(node).failed) }}</span>
              <Icon v-if="isSelected(node)" name="check" :size="17" class="option-check" aria-hidden="true" />
            </span>
          </button>

          <div
            v-if="failedNode?.name === node.name"
            :id="`picker-error-${index}`"
            class="node-picker-error field-error small"
            role="alert"
            data-testid="node-picker-error"
          >
            <Icon name="alert" :size="14" />
            <span class="grow">{{ tr(failedNode.reason) }}</span>
            <button
              type="button"
              class="btn ghost sm"
              :disabled="isSwitching"
              data-testid="node-picker-retry"
              @click="pickNode(node)"
            >{{ tr('重试') }}</button>
          </div>
        </div>
      </div>
    </div>

    <template #footer>
      <button
        type="button"
        class="btn ghost"
        :disabled="isSwitching"
        data-testid="node-picker-open-proxies"
        @click="openInProxies"
      >
        {{ tr('前往代理页') }}<Icon name="chevron-right" :size="14" />
      </button>
    </template>
  </Modal>
</template>
