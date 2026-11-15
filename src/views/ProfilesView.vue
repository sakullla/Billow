<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import Icon from '../components/Icon.vue'
import Modal from '../components/Modal.vue'
import { daysLeft, formatBytes, formatDate, formatRelative, hostOf, usagePercent } from '../lib/format'
import { registerLayer } from '../lib/ui/focus'
import { useStore } from '../lib/store'
import type { ProfileItem } from '../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

const ordered = computed(() =>
  [...snap.value.profiles].sort((a, b) => Number(b.current) - Number(a.current)),
)
const subscriptions = computed(() => snap.value.profiles.filter((item) => item.kind === 'subscription').length)

const quickUrl = ref('')
async function quickImport() {
  const value = quickUrl.value.trim()
  if (!value) return
  const before = snap.value.profiles.length
  await store.addSubscription(value)
  if (snap.value.profiles.length > before) {
    quickUrl.value = ''
    store.toast('已添加订阅', 'success')
  }
}

// Card menu
const menuFor = ref<string | null>(null)
let menuLayer: (() => void) | null = null

function closeProfileMenu(restoreFocus = false) {
  const id = menuFor.value
  if (restoreFocus && id) {
    document.querySelector<HTMLElement>(`[data-menu-trigger="${CSS.escape(id)}"]`)?.focus({ preventScroll: true })
  }
  menuFor.value = null
}

function closeMenu(event: MouseEvent) {
  if (!(event.target as HTMLElement).closest?.('.menu-anchor')) closeProfileMenu()
}

watch(menuFor, (id) => {
  menuLayer?.()
  menuLayer = null
  // The inline menu participates in the shared layer stack so Android back and
  // global shortcut guards can dismiss it (R30).
  if (id) menuLayer = registerLayer(() => closeProfileMenu(true))
})

onMounted(() => document.addEventListener('click', closeMenu))
onBeforeUnmount(() => {
  document.removeEventListener('click', closeMenu)
  menuLayer?.()
  menuLayer = null
})

// Edit info
const editing = ref<ProfileItem | null>(null)
const form = ref({ name: '', url: '', interval: 0 })
const INTERVALS = [
  { hours: 0, label: '不自动更新' },
  { hours: 6, label: '每 6 小时' },
  { hours: 12, label: '每 12 小时' },
  { hours: 24, label: '每天' },
  { hours: 72, label: '每 3 天' },
  { hours: 168, label: '每周' },
]
function openEdit(profile: ProfileItem) {
  menuFor.value = null
  editing.value = profile
  form.value = { name: profile.name, url: profile.source, interval: profile.interval_hours }
}
async function saveEdit() {
  const profile = editing.value
  if (!profile) return
  if (form.value.name.trim() && form.value.name.trim() !== profile.name) await store.rename(profile.id, form.value.name)
  if (profile.kind === 'subscription' && form.value.url.trim() !== profile.source) {
    await store.setSource(profile.id, form.value.url)
    if (snap.value.input_error) return
  }
  if (form.value.interval !== profile.interval_hours) await store.setInterval(profile.id, form.value.interval)
  editing.value = null
  store.toast('已保存', 'success')
}

// YAML editors
const yaml = ref<{ profile: ProfileItem; mode: 'content' | 'override'; text: string; dirty: boolean } | null>(null)
async function openYaml(profile: ProfileItem, mode: 'content' | 'override') {
  menuFor.value = null
  const text = mode === 'content' ? await store.backend.content(profile.id) : profile.override_text
  yaml.value = { profile, mode, text, dirty: false }
}
const yamlProfile = computed(() =>
  yaml.value ? snap.value.profiles.find((item) => item.id === yaml.value!.profile.id) ?? null : null,
)
const yamlLines = computed(() => (yaml.value ? yaml.value.text.split('\n').length : 0))
async function saveYaml() {
  if (!yaml.value) return
  const { profile, mode, text } = yaml.value
  if (mode === 'content') {
    await store.saveContent(profile.id, text)
    if (!snap.value.input_error) yaml.value = null
  } else {
    await store.saveOverride(profile.id, text)
    const after = snap.value.profiles.find((item) => item.id === profile.id)
    if (!after?.override_error) {
      yaml.value = null
      store.toast(profile.current ? '覆写已保存，重新启用该配置后生效' : '覆写已保存', 'success')
    }
  }
}
function onTab(event: KeyboardEvent) {
  const el = event.target as HTMLTextAreaElement
  const start = el.selectionStart
  const end = el.selectionEnd
  el.setRangeText('  ', start, end, 'end')
  if (yaml.value) {
    yaml.value.text = el.value
    yaml.value.dirty = true
  }
}

// Delete
const removing = ref<ProfileItem | null>(null)
async function confirmRemove() {
  const profile = removing.value
  if (!profile) return
  await store.remove(profile.id)
  removing.value = null
}

async function copyLink(profile: ProfileItem) {
  menuFor.value = null
  try {
    await navigator.clipboard.writeText(profile.source)
    store.toast('订阅链接已复制', 'success')
  } catch {
    store.toast('无法写入剪贴板', 'error')
  }
}

function activate(profile: ProfileItem) {
  if (profile.current || store.busy[`enable:${profile.id}`]) return
  void store.enable(profile.id)
}
</script>

<template>
  <div class="page profiles">
    <header class="page-head">
      <div>
        <h1>配置</h1>
        <p class="muted small">{{ snap.profiles.length }} 份配置 · 同一时间启用一份</p>
      </div>
      <div class="head-actions">
        <button
          v-if="subscriptions"
          type="button"
          class="btn ghost sm"
          :disabled="store.busy.refreshAll"
          @click="store.refreshAll()"
        >
          <Icon name="refresh" :size="15" :class="{ spin: store.busy.refreshAll }" />
          全部更新
        </button>
        <button type="button" class="btn primary sm" data-testid="add-profile" @click="store.adding.value = true">
          <Icon name="plus" :size="15" /> 添加
        </button>
      </div>
    </header>

    <form class="quick-import" @submit.prevent="quickImport">
      <Icon name="link" :size="16" class="muted" />
      <input v-model="quickUrl" type="url" placeholder="粘贴订阅链接，回车导入" spellcheck="false" />
      <button type="submit" class="btn sm" :disabled="!quickUrl.trim() || store.busy.add">导入</button>
    </form>

    <div v-if="!snap.profiles.length" class="empty">
      <Icon name="layers" :size="40" :stroke="1.4" />
      <h3>还没有配置</h3>
      <p class="muted">添加机场订阅链接，或导入本地 Clash / Mihomo 配置文件。</p>
      <button type="button" class="btn primary" @click="store.adding.value = true"><Icon name="plus" :size="16" /> 添加配置</button>
    </div>

    <div class="profile-grid">
      <article
        v-for="profile in ordered"
        :key="profile.id"
        class="card profile"
        :class="{ current: profile.current, failed: profile.failure, busy: store.busy[`enable:${profile.id}`] }"
        :data-profile="profile.id"
        @click="activate(profile)"
      >
        <header class="profile-head">
          <span class="sub-icon"><Icon :name="profile.kind === 'local' ? 'file' : 'link'" /></span>
          <div class="grow min0">
            <div class="profile-name">
              <strong :title="profile.name">{{ profile.name }}</strong>
              <span v-if="profile.current" class="tag accent">使用中</span>
            </div>
            <p class="muted small ellipsis">
              {{ profile.kind === 'local' ? '本地文件' : hostOf(profile.source) }}
            </p>
          </div>
          <span v-if="store.busy[`enable:${profile.id}`]" class="spinner sm" />
          <button
            v-if="profile.kind === 'subscription'"
            type="button"
            class="icon-btn"
            title="更新订阅"
            :disabled="store.busy[`update:${profile.id}`]"
            @click.stop="store.update(profile.id)"
          >
            <Icon name="refresh" :class="{ spin: store.busy[`update:${profile.id}`] }" />
          </button>
          <div class="menu-anchor" @click.stop @keydown.esc.stop.prevent="closeProfileMenu(true)">
            <button type="button" class="icon-btn" aria-label="更多操作" :aria-expanded="menuFor === profile.id" :data-menu-trigger="profile.id" @click="menuFor = menuFor === profile.id ? null : profile.id">
              <Icon name="more" />
            </button>
            <div v-if="menuFor === profile.id" class="menu" role="menu" @keydown.esc.stop.prevent="closeProfileMenu(true)">
              <button type="button" role="menuitem" @click="openEdit(profile)"><Icon name="edit" :size="15" />编辑信息</button>
              <button type="button" role="menuitem" @click="openYaml(profile, 'content')"><Icon name="code" :size="15" />编辑配置文件</button>
              <button type="button" role="menuitem" @click="openYaml(profile, 'override')"><Icon name="layers" :size="15" />覆写<span v-if="profile.override_text.trim()" class="dot-mark" /></button>
              <button v-if="profile.kind === 'subscription'" type="button" role="menuitem" @click="copyLink(profile)"><Icon name="copy" :size="15" />复制链接</button>
              <hr />
              <button type="button" role="menuitem" class="danger" @click="(menuFor = null), (removing = profile)"><Icon name="trash" :size="15" />删除</button>
            </div>
          </div>
        </header>

        <div v-if="usagePercent(profile.used, profile.total) != null" class="usage">
          <div class="usage-bar"><span :style="{ width: `${usagePercent(profile.used, profile.total)}%` }" :class="{ warn: (usagePercent(profile.used, profile.total) ?? 0) > 85 }" /></div>
          <div class="usage-text small">
            <span class="mono">{{ formatBytes(profile.used) }} / {{ formatBytes(profile.total) }}</span>
            <span v-if="profile.expire" :class="{ 'text-warn': daysLeft(profile.expire) <= 7 }">
              {{ daysLeft(profile.expire) < 0 ? '已过期' : `${formatDate(profile.expire)} 到期` }}
            </span>
          </div>
        </div>

        <footer class="profile-foot small muted">
          <span><Icon name="clock" :size="13" />{{ formatRelative(profile.updated_ms ?? profile.last_success_ms) }}</span>
          <span v-if="profile.proxy_count"><Icon name="globe" :size="13" />{{ profile.proxy_count }} 节点</span>
          <span v-if="profile.interval_hours"><Icon name="refresh" :size="13" />{{ profile.interval_hours >= 24 && profile.interval_hours % 24 === 0 ? `${profile.interval_hours / 24} 天` : `${profile.interval_hours} 时` }}</span>
          <span v-if="profile.override_text.trim()" class="tag">覆写</span>
        </footer>
        <p v-if="profile.failure" class="field-error small"><Icon name="alert" :size="13" /> {{ profile.failure }}</p>
        <p v-if="profile.override_error" class="field-error small"><Icon name="alert" :size="13" /> {{ profile.override_error }}</p>
      </article>
    </div>

    <Modal v-if="editing" title="编辑配置信息" @close="editing = null">
      <form class="stack" @submit.prevent="saveEdit">
        <label class="field">
          <span>名称</span>
          <input v-model="form.name" type="text" maxlength="80" />
        </label>
        <template v-if="editing.kind === 'subscription'">
          <label class="field">
            <span>订阅链接</span>
            <input v-model="form.url" type="url" spellcheck="false" />
          </label>
          <label class="field">
            <span>自动更新</span>
            <select v-model.number="form.interval">
              <option v-for="option in INTERVALS" :key="option.hours" :value="option.hours">{{ option.label }}</option>
            </select>
          </label>
        </template>
        <p v-if="snap.input_error" class="field-error">{{ snap.input_error }}</p>
      </form>
      <template #footer>
        <button type="button" class="btn ghost" @click="editing = null">取消</button>
        <button type="button" class="btn primary" @click="saveEdit">保存</button>
      </template>
    </Modal>

    <Modal
      v-if="yaml"
      wide
      :title="yaml.mode === 'content' ? `编辑 · ${yaml.profile.name}` : `覆写 · ${yaml.profile.name}`"
      :subtitle="yaml.mode === 'content'
        ? (yaml.profile.kind === 'subscription' ? '订阅更新时会覆盖这里的修改；长期修改请使用覆写' : '保存后立即替换这份配置')
        : '以 YAML 深度合并到配置之上，例如修改 dns、rules 或端口；启用该配置时生效'"
      @close="yaml = null"
    >
      <div class="editor">
        <div class="editor-gutter mono" aria-hidden="true"><span v-for="n in yamlLines" :key="n">{{ n }}</span></div>
        <textarea
          v-model="yaml.text"
          class="editor-text mono"
          spellcheck="false"
          autocapitalize="off"
          :placeholder="yaml.mode === 'override' ? 'mixed-port: 7890\ndns:\n  enable: true' : ''"
          @input="yaml && (yaml.dirty = true)"
          @keydown.tab.prevent="onTab"
        />
      </div>
      <p v-if="yaml.mode === 'override' && yamlProfile?.override_error" class="field-error">{{ yamlProfile.override_error }}</p>
      <p v-if="yaml.mode === 'content' && snap.input_error" class="field-error">{{ snap.input_error }}</p>
      <template #footer>
        <span class="muted small grow">{{ yamlLines }} 行{{ yaml.dirty ? ' · 未保存' : '' }}</span>
        <button type="button" class="btn ghost" @click="yaml = null">取消</button>
        <button type="button" class="btn primary" :disabled="store.busy.content || store.busy.override" @click="saveYaml">保存</button>
      </template>
    </Modal>

    <Modal v-if="removing" title="删除配置" @close="removing = null">
      <p>确定删除「{{ removing.name }}」？此操作无法撤销。</p>
      <template #footer>
        <button type="button" class="btn ghost" @click="removing = null">取消</button>
        <button type="button" class="btn danger" @click="confirmRemove">删除</button>
      </template>
    </Modal>
  </div>
</template>
