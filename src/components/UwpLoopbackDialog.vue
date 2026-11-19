<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed, onMounted, ref, shallowRef } from 'vue'
import { highlightTokens, matchesTokens, splitQueryTokens } from '../lib/search'
import { useStore } from '../lib/store'
import type { UwpApp } from '../lib/types'
import EmptyState from './EmptyState.vue'
import Icon from './Icon.vue'
import Modal from './Modal.vue'
import Segmented from './Segmented.vue'
import Skeleton from './Skeleton.vue'

const emit = defineEmits<{ close: [] }>()
const store = useStore()

type Filter = 'all' | 'exempted' | 'unexempted'

const apps = shallowRef<UwpApp[]>([])
const selected = ref<Set<string>>(new Set())
const loading = ref(false)
const saving = ref(false)
const error = ref<string | null>(null)
const query = ref('')
const filter = ref<Filter>('all')
const searchEl = ref<HTMLInputElement | null>(null)

const keyOf = (familyName: string) => familyName.toLowerCase()

function syncSelected(list: readonly UwpApp[]) {
  const next = new Set<string>()
  for (const app of list) {
    if (app.exempted) next.add(keyOf(app.family_name))
  }
  selected.value = next
}

async function load() {
  if (loading.value || saving.value) return
  loading.value = true
  error.value = null
  try {
    const list = await store.backend.listUwpApps()
    apps.value = list
    syncSelected(list)
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

const isSelected = (app: UwpApp) => selected.value.has(keyOf(app.family_name))

function toggleApp(app: UwpApp) {
  if (saving.value) return
  const key = keyOf(app.family_name)
  const next = new Set(selected.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  selected.value = next
}

const queryTokens = computed(() => splitQueryTokens(query.value))

const selectedCount = computed(() => apps.value.filter(isSelected).length)
const unexemptedCount = computed(() => apps.value.length - selectedCount.value)

const filterOptions = computed<{ id: Filter; label: string }[]>(() => [
  { id: 'all', label: tr('全部 {0}', { 0: apps.value.length }) },
  { id: 'exempted', label: tr('已豁免 {0}', { 0: selectedCount.value }) },
  { id: 'unexempted', label: tr('未豁免 {0}', { 0: unexemptedCount.value }) },
])

const visibleApps = computed(() => {
  const tokens = queryTokens.value
  return apps.value.filter((app) => {
    const checked = isSelected(app)
    if (filter.value === 'exempted' && !checked) return false
    if (filter.value === 'unexempted' && checked) return false
    if (!tokens.length) return true
    return matchesTokens(`${app.display_name} ${app.name} ${app.family_name}`, tokens)
  })
})

const diffCount = computed(() => {
  let changes = 0
  for (const app of apps.value) {
    if (isSelected(app) !== app.exempted) changes += 1
  }
  return changes
})

const allVisibleSelected = computed(
  () => visibleApps.value.length > 0 && visibleApps.value.every((app) => isSelected(app)),
)

function toggleSelectVisible() {
  if (saving.value || !visibleApps.value.length) return
  const next = new Set(selected.value)
  if (allVisibleSelected.value) {
    for (const app of visibleApps.value) next.delete(keyOf(app.family_name))
  } else {
    for (const app of visibleApps.value) next.add(keyOf(app.family_name))
  }
  selected.value = next
}

function resetDraft() {
  syncSelected(apps.value)
}

function clearFilters() {
  query.value = ''
  filter.value = 'all'
}

async function save() {
  if (saving.value || diffCount.value === 0) return
  saving.value = true
  error.value = null
  try {
    const families = apps.value
      .filter((app) => isSelected(app))
      .map((app) => app.family_name)
    const updated = await store.backend.saveUwpExemptions(families)
    apps.value = updated
    syncSelected(updated)
    store.toast(tr('已保存 UWP 回环豁免（共 {0} 个应用）', { 0: updated.filter((a) => a.exempted).length }), 'success')
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err)
    error.value = reason
    store.toast(reason, 'error')
  } finally {
    saving.value = false
  }
}

function appChangeState(app: UwpApp): 'add' | 'remove' | null {
  const checked = isSelected(app)
  if (checked && !app.exempted) return 'add'
  if (!checked && app.exempted) return 'remove'
  return null
}

function highlight(text: string) {
  return highlightTokens(text, query.value)
}

onMounted(() => {
  void load()
})
</script>

<template>
  <Modal
    wide
    :title="tr('UWP 应用回环豁免')"
    :subtitle="tr('允许选中的 Windows 商店应用连接本机代理（127.0.0.1），保存时可能需要管理员授权')"
    :before-close="() => !saving"
    :initial-focus="() => searchEl"
    @close="emit('close')"
  >
    <div class="uwp-dialog" data-testid="uwp-dialog">
      <div class="uwp-toolbar">
        <div class="search grow">
          <Icon name="search" :size="15" />
          <input
            ref="searchEl"
            v-model="query"
            type="search"
            :placeholder="tr('搜索应用名称或包名')"
            :aria-label="tr('搜索 UWP 应用')"
            data-testid="uwp-search"
          />
          <button
            v-if="query"
            type="button"
            class="icon-btn sm"
            :aria-label="tr('清空搜索')"
            data-testid="uwp-clear-search"
            @click="query = ''; searchEl?.focus()"
          >
            <Icon name="x" :size="14" />
          </button>
        </div>
        <Segmented v-model="filter" :options="filterOptions" size="sm" :label="tr('按豁免状态筛选')" data-testid="uwp-filter" />
        <div class="uwp-actions">
          <button
            type="button"
            class="btn ghost sm"
            :disabled="loading || saving || !visibleApps.length"
            data-testid="uwp-toggle-all"
            @click="toggleSelectVisible"
          >
            {{ allVisibleSelected ? tr('取消全选') : tr('全选当前') }}
          </button>
          <button
            type="button"
            class="icon-btn sm"
            :disabled="loading || saving"
            :aria-label="tr('刷新列表')"
            :title="tr('刷新列表')"
            data-testid="uwp-refresh"
            @click="load"
          >
            <Icon name="refresh" :size="15" :class="{ spin: loading }" />
          </button>
        </div>
      </div>

      <p v-if="error && apps.length" class="field-error small" role="alert" data-testid="uwp-error">
        <Icon name="alert" :size="14" />
        <span>{{ error }}</span>
      </p>

      <Skeleton v-if="loading && !apps.length" variant="list" :rows="6" />

      <EmptyState
        v-else-if="error && !apps.length"
        compact
        variant="error"
        :title="tr('无法读取 UWP 应用')"
        :description="error"
        data-testid="uwp-empty-error"
      >
        <template #action>
          <button type="button" class="btn ghost sm" @click="load">{{ tr('重试') }}</button>
        </template>
      </EmptyState>

      <EmptyState
        v-else-if="!apps.length"
        compact
        variant="no-data"
        icon="layers"
        :title="tr('未检测到 UWP 应用')"
        :description="tr('当前系统没有可配置本地回环豁免的 Windows 商店应用。')"
      />

      <EmptyState
        v-else-if="!visibleApps.length"
        compact
        variant="no-match"
        :title="tr('没有匹配的应用')"
        :description="tr('换一个关键词，或切换筛选条件。')"
      >
        <template #action>
          <button type="button" class="btn ghost sm" @click="clearFilters">{{ tr('清空筛选') }}</button>
        </template>
      </EmptyState>

      <ul v-else class="uwp-list" role="list" data-testid="uwp-list">
        <li v-for="app in visibleApps" :key="app.family_name">
          <button
            type="button"
            class="uwp-row"
            :class="{ selected: isSelected(app), changed: appChangeState(app) !== null }"
            :aria-pressed="isSelected(app)"
            :disabled="saving"
            :data-uwp-family="app.family_name"
            data-testid="uwp-row"
            @click="toggleApp(app)"
          >
            <span class="uwp-check" :class="{ checked: isSelected(app) }" aria-hidden="true">
              <Icon v-if="isSelected(app)" name="check" :size="13" :stroke="2.8" />
            </span>
            <span class="uwp-info grow min0">
              <span class="uwp-name ellipsis">
                <template v-for="(part, idx) in highlight(app.display_name)" :key="idx">
                  <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                </template>
              </span>
              <span class="uwp-family mono muted small ellipsis">
                <template v-for="(part, idx) in highlight(app.family_name)" :key="idx">
                  <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                </template>
              </span>
            </span>
            <span v-if="appChangeState(app) === 'add'" class="tag accent sm">{{ tr('待添加') }}</span>
            <span v-else-if="appChangeState(app) === 'remove'" class="tag warn sm">{{ tr('待移除') }}</span>
            <span v-else-if="app.exempted" class="tag ok sm">{{ tr('已豁免') }}</span>
          </button>
        </li>
      </ul>
    </div>

    <template #footer>
      <div class="uwp-foot-meta small muted">
        <span>{{ tr('已选') }} {{ selectedCount }} / {{ apps.length }}</span>
        <span v-if="diffCount > 0" class="uwp-dirty-badge" data-testid="uwp-dirty-count">{{ tr('已修改') }} {{ diffCount }} {{ tr('项') }}</span>
      </div>
      <button v-if="diffCount > 0" type="button" class="btn ghost sm" :disabled="saving" data-testid="uwp-reset" @click="resetDraft"> {{ tr('还原') }} </button>
      <button type="button" class="btn ghost" :disabled="saving" @click="emit('close')">{{ tr('关闭') }}</button>
      <button
        type="button"
        class="btn primary"
        :disabled="saving || loading || diffCount === 0"
        data-testid="uwp-save"
        @click="save"
      >
        <span v-if="saving" class="spinner sm" aria-hidden="true" />
        {{ saving ? tr('保存中…') : tr('保存修改') }}
      </button>
    </template>
  </Modal>
</template>

<style scoped>
.uwp-dialog {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 300px;
}

.uwp-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.uwp-toolbar .search {
  min-width: 180px;
}

.uwp-actions {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.uwp-list {
  list-style: none;
  margin: 0;
  padding: 2px 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
  max-height: min(52vh, 420px);
  overflow-y: auto;
  overscroll-behavior: contain;
}

.uwp-row {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
  padding: 10px 12px;
  border-radius: 12px;
  border: 1px solid var(--border);
  background: var(--surface-2);
  text-align: left;
  transition: background var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
}

.uwp-row:hover:not(:disabled) {
  background: var(--surface);
  border-color: var(--border-input);
}

.uwp-row.selected {
  background: color-mix(in srgb, var(--accent-soft) 55%, var(--surface));
  border-color: color-mix(in srgb, var(--accent) 34%, var(--border));
}

.uwp-row.changed {
  border-style: dashed;
}

.uwp-check {
  display: inline-grid;
  place-items: center;
  width: 18px;
  height: 18px;
  flex: none;
  border-radius: 6px;
  border: 1.5px solid var(--border-input);
  background: var(--surface);
  color: var(--on-accent);
  transition: background var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
}

.uwp-check.checked {
  background: var(--accent);
  border-color: var(--accent);
}

.uwp-info {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.uwp-name {
  font-weight: 600;
  color: var(--text);
}

.uwp-family {
  font-size: var(--text-xs);
}

.uwp-foot-meta {
  margin-right: auto;
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.uwp-dirty-badge {
  padding: 2px 8px;
  border-radius: var(--radius-pill);
  background: var(--accent-soft);
  color: var(--accent-ink);
  font-weight: 620;
  font-size: var(--text-xs);
}
</style>
