<script setup lang="ts">
import { computed, ref, shallowRef, watch } from 'vue'
import Icon from '../components/Icon.vue'
import Modal from '../components/Modal.vue'
import Segmented from '../components/Segmented.vue'
import { formatBytes, formatDuration, formatSpeed } from '../lib/format'
import { useStore } from '../lib/store'
import type { ConnectionRow } from '../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

type SortKey = 'time' | 'speed' | 'download' | 'upload' | 'host'
const SORTS: { id: SortKey; label: string }[] = [
  { id: 'time', label: '时间' },
  { id: 'speed', label: '速度' },
  { id: 'download', label: '下载' },
  { id: 'host', label: '主机' },
]

const query = ref('')
const sortKey = ref<SortKey>('time')
const paused = ref(false)
const frozen = shallowRef<ConnectionRow[]>([])
const selected = ref<ConnectionRow | null>(null)
const rates = shallowRef(new Map<string, { up: number; down: number }>())
let previous = new Map<string, { upload: number; download: number; at: number }>()

watch(
  () => snap.value.connections,
  (rows) => {
    const now = Date.now()
    const next = new Map<string, { upload: number; download: number; at: number }>()
    const speed = new Map<string, { up: number; down: number }>()
    for (const row of rows) {
      const key = row.id || `${row.host}|${row.source}`
      const before = previous.get(key)
      next.set(key, { upload: row.upload, download: row.download, at: now })
      if (before) {
        const seconds = Math.max(0.25, (now - before.at) / 1000)
        speed.set(key, {
          up: Math.max(0, (row.upload - before.upload) / seconds),
          down: Math.max(0, (row.download - before.download) / seconds),
        })
      }
    }
    previous = next
    rates.value = speed
  },
  { immediate: true },
)

watch(paused, (on) => {
  if (on) frozen.value = snap.value.connections
})

const rateOf = (row: ConnectionRow) => rates.value.get(row.id || `${row.host}|${row.source}`) ?? { up: 0, down: 0 }

const rows = computed(() => {
  const source = paused.value ? frozen.value : snap.value.connections
  const needle = query.value.trim().toLowerCase()
  const list = needle
    ? source.filter((row) =>
        [row.host, row.destination, row.process, row.rule, row.rule_payload, row.chains.join(' '), row.network]
          .some((text) => text.toLowerCase().includes(needle)),
      )
    : [...source]
  switch (sortKey.value) {
    case 'speed':
      list.sort((a, b) => rateOf(b).down + rateOf(b).up - (rateOf(a).down + rateOf(a).up))
      break
    case 'download':
      list.sort((a, b) => b.download - a.download)
      break
    case 'upload':
      list.sort((a, b) => b.upload - a.upload)
      break
    case 'host':
      list.sort((a, b) => a.host.localeCompare(b.host))
      break
    default:
      list.sort((a, b) => Date.parse(b.start || '0') - Date.parse(a.start || '0'))
  }
  return list
})

const detail = computed(() => {
  const row = selected.value
  if (!row) return []
  return [
    ['主机', row.host],
    ['目标地址', row.destination],
    ['来源', row.source],
    ['进程', row.process],
    ['网络', `${row.network.toUpperCase()}${row.conn_type ? ` · ${row.conn_type}` : ''}`],
    ['规则', row.rule ? `${row.rule}${row.rule_payload ? ` (${row.rule_payload})` : ''}` : ''],
    ['代理链', [...row.chains].reverse().join(' → ')],
    ['上传', formatBytes(row.upload)],
    ['下载', formatBytes(row.download)],
    ['持续', formatDuration(row.start)],
  ].filter(([, value]) => value)
})

async function closeOne(row: ConnectionRow) {
  await store.closeConnection(row.id)
  if (selected.value?.id === row.id) selected.value = null
}
</script>

<template>
  <div class="page connections">
    <header class="page-head">
      <div>
        <h1>连接</h1>
        <p class="muted small mono">
          {{ snap.connected ? `${snap.connections.length} 个活动连接` : '未连接' }}
          <template v-if="snap.connected">
            · <Icon name="up" :size="11" />{{ formatBytes(snap.upload_total) }}
            · <Icon name="down" :size="11" />{{ formatBytes(snap.download_total) }}
          </template>
        </p>
      </div>
      <div class="head-actions">
        <button type="button" class="btn ghost sm" :class="{ active: paused }" :disabled="!snap.connected" @click="paused = !paused">
          <Icon :name="paused ? 'play' : 'pause'" :size="14" />{{ paused ? '继续' : '暂停' }}
        </button>
        <button type="button" class="btn ghost sm danger-text" :disabled="!snap.connections.length" @click="store.closeConnection(null)">
          <Icon name="x" :size="15" />全部断开
        </button>
      </div>
    </header>

    <div class="toolbar">
      <div class="search grow">
        <Icon name="search" :size="16" />
        <input v-model="query" type="search" placeholder="按主机、进程、规则或节点筛选" data-testid="connection-search" />
      </div>
      <Segmented v-model="sortKey" :options="SORTS" size="sm" label="排序" />
    </div>

    <div v-if="!snap.connected" class="empty">
      <Icon name="activity" :size="40" :stroke="1.4" />
      <h3>未连接</h3>
      <p class="muted">连接后这里会实时显示经过 Billow 的连接。</p>
    </div>
    <div v-else-if="!rows.length" class="empty small">
      <h3>{{ query ? '没有匹配的连接' : '没有当前连接' }}</h3>
    </div>

    <div v-else-if="!compact" class="card table-card">
      <table class="table">
        <thead>
          <tr>
            <th>主机</th>
            <th>进程</th>
            <th>规则</th>
            <th>代理链</th>
            <th class="num">速度</th>
            <th class="num">下载</th>
            <th class="num">上传</th>
            <th class="num">时长</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.id || row.host + row.source" data-testid="connection-row" @click="selected = row">
            <td>
              <div class="cell-host">
                <span class="net" :class="row.network">{{ row.network.toUpperCase() || 'TCP' }}</span>
                <span class="ellipsis" :title="row.host">{{ row.host }}</span>
              </div>
            </td>
            <td class="muted ellipsis">{{ row.process || '—' }}</td>
            <td class="ellipsis"><span class="muted">{{ row.rule }}</span><span v-if="row.rule_payload" class="rule-payload-inline">{{ row.rule_payload }}</span></td>
            <td class="ellipsis">{{ row.outbound }}</td>
            <td class="num mono">{{ formatSpeed(rateOf(row).down) }}</td>
            <td class="num mono">{{ formatBytes(row.download) }}</td>
            <td class="num mono muted">{{ formatBytes(row.upload) }}</td>
            <td class="num muted">{{ formatDuration(row.start) }}</td>
            <td class="num">
              <button type="button" class="icon-btn sm" title="断开" @click.stop="closeOne(row)"><Icon name="x" :size="14" /></button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <ul v-else class="conn-list">
      <li v-for="row in rows" :key="row.id || row.host + row.source" class="card conn" data-testid="connection-row" @click="selected = row">
        <div class="conn-top">
          <span class="net" :class="row.network">{{ row.network.toUpperCase() || 'TCP' }}</span>
          <strong class="ellipsis grow">{{ row.host }}</strong>
          <span class="mono small">{{ formatSpeed(rateOf(row).down) }}</span>
        </div>
        <div class="conn-meta small muted">
          <span class="ellipsis">{{ row.outbound }}</span>
          <span v-if="row.process">· {{ row.process }}</span>
          <span class="grow" />
          <span class="mono">↓{{ formatBytes(row.download) }}</span>
        </div>
      </li>
    </ul>

    <Modal v-if="selected" title="连接详情" :subtitle="selected.host" @close="selected = null">
      <dl class="detail">
        <template v-for="[label, value] in detail" :key="label">
          <dt>{{ label }}</dt>
          <dd class="mono">{{ value }}</dd>
        </template>
      </dl>
      <template #footer>
        <button type="button" class="btn ghost" @click="selected = null">关闭</button>
        <button type="button" class="btn danger" @click="closeOne(selected)">断开连接</button>
      </template>
    </Modal>
  </div>
</template>
