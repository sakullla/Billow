<script setup lang="ts">import { tr } from '../lib/i18n'

import { computed } from 'vue'
import BrandMark from './BrandMark.vue'
import Icon from './Icon.vue'
import { useStore } from '../lib/store'

/** `card` is the desktop settings card; `row` sits inside the phone grouped list. */
withDefaults(defineProps<{ variant?: 'card' | 'row' }>(), { variant: 'card' })

const store = useStore()
const update = store.appUpdate
const status = update.status
const offer = update.offer
const percent = computed(() => update.total.value
  ? Math.min(100, Math.round(update.downloaded.value / update.total.value * 100)) : null)
const description = computed(() => {
  if (!store.backend.live) return tr('应用更新在安装版中可用')
  if (status.value === 'checking') return tr('正在检查新版本…')
  if (status.value === 'current') return tr('当前已是最新版本')
  if (status.value === 'downloading') return percent.value === null ? tr('正在下载更新…') : tr('正在下载更新 {0}%', { 0: percent.value })
  if (status.value === 'installing') return tr('正在安装更新…')
  if (status.value === 'ready') return tr('更新已安装，重启后生效')
  if (offer.value) return tr('发现新版本 v{0}', { 0: offer.value.version })
  return tr('启动时自动检查 Billow 新版本')
})
</script>

<template>
  <div v-if="variant === 'row'" class="update-row" data-testid="app-update">
    <div class="nav-row static">
      <BrandMark class="nav-row-brand" />
      <div class="grow min0" aria-live="polite">
        <span class="nav-row-title">Billow <span class="muted mono update-version">v{{ store.app.value?.version ?? '—' }}</span></span>
        <p class="small" :class="offer || status === 'ready' ? 'update-fresh' : 'muted'">{{ description }}</p>
      </div>
      <button v-if="status === 'ready'" type="button" class="btn primary sm" @click="update.restart()">{{ tr('重启') }}</button>
      <button v-else-if="offer" type="button" class="btn primary sm" :disabled="update.busy.value" @click="update.install()">
        {{ offer.kind === 'android' ? tr('下载') : tr('安装') }}
      </button>
      <button
        v-else-if="store.backend.live"
        type="button"
        class="btn ghost sm"
        :disabled="update.busy.value"
        @click="update.check()"
      >
        <Icon name="refresh" :size="15" :class="{ spin: status === 'checking' }" />{{ tr('检查') }} </button>
    </div>
    <div v-if="offer || update.error.value" class="update-row-notes small">
      <p v-if="offer?.kind === 'android'" class="muted">{{ tr('下载新版 APK 后由 Android 确认安装，已有配置会保留。') }}</p>
      <p v-else-if="offer" class="muted">{{ tr('下载完成后会断开代理连接并安装。') }}</p>
      <p v-if="update.error.value" class="field-error" role="alert">{{ tr('更新失败：') }}{{ update.error.value }}</p>
      <details v-if="offer?.body"><summary>{{ tr('版本说明') }}</summary><p>{{ offer.body }}</p></details>
    </div>
  </div>
  <section v-else class="card" data-testid="app-update">
    <header class="card-head"><h2>{{ tr('应用更新') }}</h2><span class="muted small">v{{ store.app.value?.version ?? '—' }}</span></header>
    <div class="setting-row">
      <div class="grow min0" aria-live="polite">
        <strong>{{ description }}</strong>
        <p v-if="offer?.kind === 'android'" class="muted small">{{ tr('下载新版 APK 后，由 Android 确认安装，已有配置会保留。') }}</p>
        <p v-else-if="offer" class="muted small">{{ tr('更新下载完成后会断开代理连接并安装，请先保存正在进行的工作。') }}</p>
        <p v-if="update.error.value" class="small" role="alert">{{ tr('更新失败：') }}{{ update.error.value }}</p>
      </div>
      <button v-if="status === 'ready'" type="button" class="btn primary sm" @click="update.restart()">{{ tr('重启应用') }}</button>
      <button v-else-if="offer" type="button" class="btn primary sm" :disabled="update.busy.value" @click="update.install()">
        {{ offer.kind === 'android' ? tr('下载新版 APK') : tr('下载并安装') }}
      </button>
      <button v-else type="button" class="btn ghost sm" :disabled="!store.backend.live || update.busy.value" @click="update.check()">
        <Icon name="refresh" :size="15" :class="{ spin: status === 'checking' }" />{{ tr('检查更新') }} </button>
    </div>
    <div v-if="offer?.body" class="update-notes small"><details><summary>{{ tr('版本说明') }}</summary><p>{{ offer.body }}</p></details></div>
  </section>
</template>

<style scoped>
.update-notes { padding: 0 20px 16px; }
.update-notes p,
.update-row-notes details p { white-space: pre-wrap; overflow-wrap: anywhere; max-height: 240px; overflow: auto; }
.update-version { font-size: var(--text-sm); font-weight: 500; margin-left: 4px; }
.update-fresh { color: var(--accent-ink); font-weight: 560; }
.update-row-notes {
  display: grid;
  gap: 6px;
  padding: 0 var(--space-4) var(--space-3) 60px;
}
.update-row-notes summary { cursor: pointer; color: var(--text-2); font-weight: 600; }
</style>
