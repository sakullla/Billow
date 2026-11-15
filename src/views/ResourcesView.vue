<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import Icon from '../components/Icon.vue'
import { formatBytes, formatDate, formatRelative, usagePercent } from '../lib/format'
import { useStore } from '../lib/store'
import type { ProviderRow } from '../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

const providers = ref<ProviderRow[]>([])
const error = ref<string | null>(null)
const loading = ref(false)
const working = reactive<Record<string, boolean>>({})

const proxySets = computed(() => providers.value.filter((item) => item.kind === 'proxy'))
const ruleSets = computed(() => providers.value.filter((item) => item.kind === 'rule'))

async function load() {
  loading.value = true
  try {
    const result = await store.backend.providers()
    providers.value = result.providers
    error.value = result.error
  } catch (err) {
    error.value = String(err)
  } finally {
    loading.value = false
  }
}

const keyOf = (row: ProviderRow, action: string) => `${row.kind}:${row.name}:${action}`
const updatedMs = (row: ProviderRow) => {
  const ms = Date.parse(row.updated_at)
  return Number.isNaN(ms) || ms < 86_400_000 ? null : ms
}

async function act(row: ProviderRow, action: 'update' | 'healthcheck', quiet = false) {
  const key = keyOf(row, action)
  working[key] = true
  try {
    await store.backend.providerAction(row.kind, row.name, action)
    if (!quiet) store.toast(action === 'update' ? `${row.name} 已更新` : `${row.name} 健康检查完成`, 'success')
    return true
  } catch (err) {
    store.toast(`${row.name}：${String(err)}`, 'error')
    return false
  } finally {
    delete working[key]
  }
}

async function updateAll(rows: ProviderRow[], kind: 'proxy' | 'rule') {
  working[`all:${kind}`] = true
  const updatable = rows.filter((row) => row.vehicle.toLowerCase() !== 'inline')
  const results = await Promise.all(updatable.map((row) => act(row, 'update', true)))
  delete working[`all:${kind}`]
  const ok = results.filter(Boolean).length
  store.toast(`已更新 ${ok}/${updatable.length} 个${kind === 'proxy' ? '代理集' : '规则集'}`, ok === updatable.length ? 'success' : 'error')
  await load()
}

async function upgradeGeo() {
  working.geo = true
  try {
    await store.backend.upgradeGeo()
    store.toast('GEO 数据库已更新', 'success')
  } catch (err) {
    store.toast(String(err), 'error')
  } finally {
    delete working.geo
  }
}

async function single(row: ProviderRow, action: 'update' | 'healthcheck') {
  if (await act(row, action)) await load()
  if (action === 'healthcheck') void store.refresh()
}

watch(() => snap.value.kernel_running, (running) => running && void load())
onMounted(load)
</script>

<template>
  <div class="page resources">
    <header class="page-head">
      <div>
        <h1>外部资源</h1>
        <p class="muted small">配置中引用的代理集、规则集与 GEO 数据库</p>
      </div>
      <div class="head-actions">
        <button type="button" class="btn ghost sm" :disabled="loading" @click="load">
          <Icon name="refresh" :size="15" :class="{ spin: loading }" />刷新
        </button>
      </div>
    </header>

    <section class="card">
      <div class="setting-row">
        <span class="row-icon"><Icon name="database" /></span>
        <div class="grow">
          <strong>GEO 数据库</strong>
          <p class="muted small">重新下载 GeoIP、GeoSite、MMDB 与 ASN 数据，地址取自配置中的 geox-url</p>
        </div>
        <button type="button" class="btn sm" :disabled="!snap.kernel_running || working.geo" data-testid="upgrade-geo" @click="upgradeGeo">
          <span v-if="working.geo" class="spinner sm" />
          <Icon v-else name="download" :size="15" />更新
        </button>
      </div>
    </section>

    <div v-if="!snap.kernel_running" class="empty">
      <Icon name="database" :size="40" :stroke="1.4" />
      <h3>内核未运行</h3>
      <p class="muted">连接后可以查看并更新配置中的 proxy-providers 与 rule-providers。</p>
    </div>
    <div v-else-if="!providers.length && !loading" class="empty small">
      <h3>{{ error ?? '这份配置没有使用外部资源' }}</h3>
      <p class="muted">配置里的 proxy-providers 和 rule-providers 会显示在这里。</p>
    </div>

    <template v-for="section in [
      { kind: 'proxy' as const, title: '代理集', rows: proxySets },
      { kind: 'rule' as const, title: '规则集', rows: ruleSets },
    ]" :key="section.kind">
      <section v-if="section.rows.length" class="card provider-card">
        <header class="card-head">
          <h2>{{ section.title }} <span class="muted">{{ section.rows.length }}</span></h2>
          <button type="button" class="btn ghost sm" :disabled="working[`all:${section.kind}`]" @click="updateAll(section.rows, section.kind)">
            <Icon name="refresh" :size="15" :class="{ spin: working[`all:${section.kind}`] }" />全部更新
          </button>
        </header>
        <div v-for="row in section.rows" :key="row.name" class="provider" :data-provider="row.name">
          <div class="provider-main">
            <div class="provider-title">
              <strong class="ellipsis">{{ row.name }}</strong>
              <span class="tag">{{ row.vehicle || '—' }}</span>
              <span v-if="row.behavior" class="tag accent">{{ row.behavior }}</span>
              <span v-if="row.format" class="tag">{{ row.format }}</span>
            </div>
            <p class="muted small">
              {{ row.kind === 'proxy' ? `${row.count} 个节点` : `${row.count.toLocaleString()} 条规则` }}
              · 更新于 {{ formatRelative(updatedMs(row)) }}
              <template v-if="row.expire"> · {{ formatDate(row.expire) }} 到期</template>
            </p>
            <div v-if="usagePercent(row.used, row.total) != null" class="usage compact-usage">
              <div class="usage-bar"><span :style="{ width: `${usagePercent(row.used, row.total)}%` }" /></div>
              <span class="small mono muted">{{ formatBytes(row.used) }} / {{ formatBytes(row.total) }}</span>
            </div>
          </div>
          <div class="provider-actions">
            <button
              v-if="row.kind === 'proxy'"
              type="button"
              class="icon-btn"
              title="健康检查"
              :disabled="working[keyOf(row, 'healthcheck')]"
              @click="single(row, 'healthcheck')"
            >
              <span v-if="working[keyOf(row, 'healthcheck')]" class="spinner sm" />
              <Icon v-else name="zap" />
            </button>
            <button
              type="button"
              class="icon-btn"
              :title="row.vehicle.toLowerCase() === 'inline' ? '内联资源无需更新' : '更新'"
              :disabled="row.vehicle.toLowerCase() === 'inline' || working[keyOf(row, 'update')]"
              @click="single(row, 'update')"
            >
              <Icon name="refresh" :class="{ spin: working[keyOf(row, 'update')] }" />
            </button>
          </div>
        </div>
      </section>
    </template>
  </div>
</template>
