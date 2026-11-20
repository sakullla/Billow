<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed, onMounted, ref, shallowRef, watch } from 'vue'
import Icon from './Icon.vue'
import Modal from './Modal.vue'
import Segmented from './Segmented.vue'
import YamlEditor from './YamlEditor.vue'
import {
  buildOverview,
  filterOverview,
  type OverviewRow,
  type OverviewSource,
  type OverviewTarget,
} from '../lib/configOverview'
import { highlightTokens } from '../lib/search'
import { rememberConfigTab, useStore, type ConfigViewTab } from '../lib/store'
import type { ConfigOverview } from '../lib/types'

/**
 * Read-only view of the config the kernel runs: a labelled overview that says
 * where each value comes from, and the full YAML one tab away.
 */
const store = useStore()
const snap = computed(() => store.snapshot.value)
const tab = computed(() => store.configView.value ?? 'overview')

const TABS: { id: ConfigViewTab; label: string }[] = [
  { id: 'overview', get label() { return tr('概览') } },
  { id: 'yaml', label: 'YAML' },
]

const overview = shallowRef<ConfigOverview | null>(null)
const overviewError = ref<string | null>(null)
const yamlText = ref<string | null>(null)
const yamlError = ref<string | null>(null)
const query = ref('')
const sourceFilter = ref<OverviewSource | 'all'>('all')

const errorText = (error: unknown) => String((error as Error)?.message ?? error)

async function loadOverview() {
  overviewError.value = null
  try {
    overview.value = await store.backend.configOverview()
  } catch (error) {
    overviewError.value = errorText(error)
  }
}

async function loadYaml() {
  yamlError.value = null
  try {
    yamlText.value = await store.backend.effectiveConfig()
  } catch (error) {
    yamlError.value = errorText(error)
  }
}

// Each tab loads on first visit; the other one costs nothing until asked for.
function ensureLoaded(next: ConfigViewTab) {
  if (next === 'overview' && !overview.value && !overviewError.value) void loadOverview()
  if (next === 'yaml' && yamlText.value == null && !yamlError.value) void loadYaml()
}
onMounted(() => ensureLoaded(tab.value))
watch(tab, ensureLoaded)

function setTab(next: ConfigViewTab) {
  store.configView.value = next
  rememberConfigTab(next)
}

const sections = computed(() => (overview.value ? buildOverview(overview.value, { android: store.isAndroid.value }) : []))
const counts = computed(() => {
  const rows = sections.value.flatMap((section) => section.rows)
  return {
    billow: rows.filter((row) => row.source === 'billow').length,
    override: rows.filter((row) => row.source === 'override').length,
  }
})
const sourceOptions = computed(() => [
  { id: 'all' as const, label: tr('全部') },
  ...(counts.value.billow ? [{ id: 'billow' as const, label: tr('Billow 设置 {0}', { 0: counts.value.billow }) }] : []),
  ...(counts.value.override ? [{ id: 'override' as const, label: tr('覆写 {0}', { 0: counts.value.override }) }] : []),
])
// A filter that no longer has rows (settings changed underneath) falls back to all.
watch(sourceOptions, (options) => {
  if (!options.some((option) => option.id === sourceFilter.value)) sourceFilter.value = 'all'
})
const visible = computed(() => filterOverview(sections.value, query.value, sourceFilter.value))

const subtitle = computed(() =>
  (overview.value?.running ?? snap.value.kernel_running)
    ? tr('内核正在运行的配置：订阅内容、覆写与 Billow 设置合并后的结果，只读')
    : tr('下次连接时使用的配置：订阅内容、覆写与 Billow 设置合并后的结果，只读'),
)

function close() {
  store.configView.value = null
}

function follow(to: OverviewTarget) {
  close()
  if (to.tab) store.openSettings(to.tab, to.focus)
  else store.go(to.page)
}

function sourceTitle(row: OverviewRow): string | undefined {
  if (row.source === 'billow') return tr('由 Billow 设置覆盖；配置中为 {0}', { 0: row.before ?? tr('未设置') })
  if (row.source === 'override') return tr('由覆写修改；订阅原文为 {0}', { 0: row.before ?? tr('未设置') })
  if (row.source === 'default') return tr('配置未设置，使用内核默认值')
  return undefined
}

async function copyYaml() {
  if (yamlText.value == null) await loadYaml()
  if (yamlText.value) await store.copyText(yamlText.value, tr('已复制生效配置'))
}

const yamlLines = computed(() => (yamlText.value ? yamlText.value.split('\n').length : 0))
</script>

<template>
  <Modal wide :title="tr('生效配置')" :subtitle="subtitle" @close="close">
    <div class="cfg-bar">
      <Segmented :model-value="tab" :options="TABS" size="sm" :label="tr('查看方式')" data-testid="config-tabs" @update:model-value="setTab" />
      <div v-if="tab === 'overview' && overview" class="search grow cfg-search">
        <Icon name="search" :size="15" />
        <input v-model="query" type="search" :placeholder="tr('搜索选项或 YAML 键名')" :aria-label="tr('搜索配置项')" data-testid="config-search" />
        <button v-if="query" type="button" class="icon-btn sm" :aria-label="tr('清空搜索')" @click="query = ''">
          <Icon name="x" :size="13" />
        </button>
      </div>
    </div>

    <!-- Same height as the YAML editor, so switching tabs never makes the dialog jump. -->
    <div v-if="tab === 'overview'" class="cfg-pane">
      <p v-if="overviewError" class="field-error" role="alert">{{ overviewError }}</p>
      <div v-else-if="!overview" class="cfg-loading muted small"><span class="spinner xs" /> {{ tr('正在读取…') }}</div>
      <template v-else>
        <Segmented
          v-if="sourceOptions.length > 1"
          v-model="sourceFilter"
          :options="sourceOptions"
          size="sm"
          :label="tr('按来源筛选')"
          class="cfg-sources"
          data-testid="config-sources"
        />
        <p v-if="!visible.length" class="cfg-empty muted small">{{ tr('没有匹配的配置项') }}</p>
        <div class="cfg-overview" data-testid="config-overview">
          <component
            :is="section.folded && !query ? 'details' : 'section'"
            v-for="section in visible"
            :key="section.id"
            class="cfg-section"
            :data-section="section.id"
          >
            <component :is="section.folded && !query ? 'summary' : 'h3'" class="cfg-section-title">
              <Icon v-if="section.folded && !query" name="chevron-right" :size="13" class="cfg-fold-icon" />
              {{ section.title }}
              <span v-if="section.folded" class="muted">{{ section.rows.length }}</span>
            </component>
            <dl class="cfg-rows">
              <div
                v-for="row in section.rows"
                :key="row.path"
                class="cfg-row"
                :class="{ link: row.to }"
                :data-path="row.path"
                :data-source="row.source"
                @click="row.to && follow(row.to)"
              >
                <dt :title="row.path">
                  <template v-for="(part, idx) in highlightTokens(row.label, query)" :key="idx">
                    <mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                  </template>
                </dt>
                <dd>
                  <span class="cfg-value" :class="{ muted: row.source === 'default' }" :title="row.title">
                    <template v-if="row.source === 'default'">{{ tr('默认 ·') }} </template><template v-for="(part, idx) in highlightTokens(row.value, query)" :key="idx"><mark v-if="part.hit">{{ part.text }}</mark><template v-else>{{ part.text }}</template></template>
                  </span>
                  <span v-if="row.source === 'billow'" class="tag accent sm" :title="sourceTitle(row)">Billow</span>
                  <span v-else-if="row.source === 'override'" class="tag sm" :title="sourceTitle(row)">{{ tr('覆写') }}</span>
                  <button
                    v-if="row.to"
                    type="button"
                    class="icon-btn sm cfg-go"
                    :aria-label="tr('前往修改{0}', { 0: row.label })"
                    :title="row.to.tab ? tr('前往设置修改') : tr('前往查看')"
                    @click.stop="follow(row.to)"
                  >
                    <Icon name="chevron-right" :size="14" />
                  </button>
                </dd>
              </div>
            </dl>
          </component>
        </div>
      </template>
    </div>

    <template v-else>
      <p v-if="yamlError" class="field-error" role="alert">{{ yamlError }}</p>
      <div v-else-if="yamlText == null" class="editor yaml-editor-loading muted small"><span class="spinner xs" /> {{ tr('正在生成…') }}</div>
      <YamlEditor v-else class="editor" :model-value="yamlText" readonly :label="tr('生效配置')" data-testid="effective-config" />
    </template>

    <template #footer>
      <span class="muted small grow">
        <template v-if="tab === 'yaml'">{{ yamlLines ? tr('{0} 行 · Ctrl+F 查找', { 0: yamlLines }) : '' }}</template>
        <template v-else-if="overview">{{ tr('密码与密钥已隐藏；节点与规则见对应页面') }}</template>
      </span>
      <button type="button" class="btn ghost" data-testid="copy-effective" @click="copyYaml"><Icon name="copy" :size="15" />{{ tr('复制 YAML') }}</button>
      <button type="button" class="btn primary" @click="close">{{ tr('关闭') }}</button>
    </template>
  </Modal>
</template>
