<script setup lang="ts">
import { computed, nextTick, ref } from 'vue'
import Icon from '../components/Icon.vue'
import Menu, { type MenuItem } from '../components/Menu.vue'
import Modal from '../components/Modal.vue'
import SelectField from '../components/SelectField.vue'
import YamlEditor from '../components/YamlEditor.vue'
import { daysLeft, formatBytes, formatDate, formatRelative, hostOf, usagePercent } from '../lib/format'
import { useStore } from '../lib/store'
import type { ProfileItem } from '../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const snap = computed(() => store.snapshot.value)

const ordered = computed(() =>
  [...snap.value.profiles].sort((a, b) => Number(b.current) - Number(a.current)),
)
const subscriptions = computed(() => snap.value.profiles.filter((item) => item.kind === 'subscription').length)

const DUPLICATE_HINT = '该订阅已存在'
const quickUrl = ref('')
const quickError = ref<string | null>(null)
const quickInputEl = ref<HTMLInputElement | null>(null)
const pageDragging = ref(false)

async function importLocalFile(file: File | undefined) {
  if (!file) return
  const before = snap.value.profiles.length
  await store.addLocal(file.name.replace(/\.(ya?ml|txt)$/i, ''), await file.text())
  if (snap.value.profiles.length > before) {
    store.toast(`已导入 ${file.name}`, 'success')
    const added = snap.value.profiles[snap.value.profiles.length - 1]
    if (!snap.value.active_id && added) void store.enable(added.id)
  }
}

function onQuickFile(event: Event) {
  const input = event.target as HTMLInputElement
  void importLocalFile(input.files?.[0])
  input.value = ''
}

function onPageDrop(event: DragEvent) {
  pageDragging.value = false
  void importLocalFile(event.dataTransfer?.files?.[0])
}

async function pasteQuickUrl() {
  try {
    const text = await navigator.clipboard.readText()
    if (text && text.trim()) {
      quickUrl.value = text.trim()
      quickError.value = null
      quickInputEl.value?.focus()
    } else {
      store.toast('剪贴板为空', 'info')
    }
  } catch {
    store.toast('无法读取剪贴板，请手动粘贴', 'error')
  }
}

/** Move focus and the viewport to the profile that already owns this link (R27). */
async function focusProfileCard(id: string) {
  await nextTick()
  const card = document.querySelector<HTMLElement>(`[data-profile="${id}"]`)
  if (!card) return
  card.scrollIntoView?.({ block: 'nearest' })
  card.focus({ preventScroll: true })
}

async function quickImport() {
  const value = quickUrl.value.trim()
  if (!value) return
  quickError.value = null
  // Trimmed comparison first, so a duplicate never creates a card or a request.
  const existing = snap.value.profiles.find(
    (item) => item.kind === 'subscription' && item.source.trim() === value,
  )
  if (existing) {
    quickError.value = DUPLICATE_HINT
    await focusProfileCard(existing.id)
    return
  }
  const before = snap.value.profiles.length
  await store.addSubscription(value)
  if (snap.value.profiles.length > before) {
    quickUrl.value = ''
    store.toast('已添加订阅', 'success')
  } else {
    quickError.value = snap.value.input_error ?? '订阅没有添加'
  }
}

// Card menu — the shared Menu owns keyboard navigation and focus restore (R27, R30).
const menuFor = ref<string | null>(null)

function closeProfileMenu(restoreFocus = false) {
  const id = menuFor.value
  if (restoreFocus && id) {
    document.querySelector<HTMLElement>(`[data-menu-trigger="${id}"]`)?.focus({ preventScroll: true })
  }
  menuFor.value = null
}

function menuItems(profile: ProfileItem): MenuItem[] {
  const items: MenuItem[] = []
  // Card clicks are pointer-only; the menu gives keyboard and screen-reader users the same switch.
  if (!profile.current) items.push({ id: 'enable', label: '启用此配置', icon: 'check' })
  items.push(
    { id: 'edit', label: '编辑信息', icon: 'edit' },
    { id: 'content', label: '编辑配置文件', icon: 'code' },
    { id: 'override', label: '覆写', icon: 'layers', mark: profile.override_text.trim().length > 0 },
  )
  // Quiet entry: only the profile that runs has a final config worth reading.
  if (profile.current) items.push({ id: 'effective', label: '查看生效配置', icon: 'file' })
  if (profile.kind === 'subscription') items.push({ id: 'copy', label: '复制链接', icon: 'copy' })
  items.push({ id: 'remove', label: '删除', icon: 'trash', danger: true })
  return items
}

function selectMenuItem(profile: ProfileItem, item: MenuItem) {
  menuFor.value = null
  if (item.id === 'enable') activate(profile)
  else if (item.id === 'edit') openEdit(profile)
  else if (item.id === 'content') void openYaml(profile, 'content')
  else if (item.id === 'override') void openYaml(profile, 'override')
  else if (item.id === 'effective') void openEffective()
  else if (item.id === 'copy') void copyLink(profile)
  else if (item.id === 'remove') removing.value = profile
}

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
interface YamlDraft {
  profile: ProfileItem
  mode: 'content' | 'override'
  text: string
  dirty: boolean
}

const yaml = ref<YamlDraft | null>(null)
const yamlError = ref<string | null>(null)
const discardOpen = ref(false)
const editorRef = ref<InstanceType<typeof YamlEditor> | null>(null)

async function openYaml(profile: ProfileItem, mode: 'content' | 'override') {
  menuFor.value = null
  yamlError.value = null
  discardOpen.value = false
  const text = mode === 'content' ? await store.backend.content(profile.id) : profile.override_text
  yaml.value = { profile, mode, text, dirty: false }
}

const yamlLines = computed(() => (yaml.value ? yaml.value.text.split('\n').length : 0))

function onYamlInput(text: string) {
  if (!yaml.value) return
  yaml.value.text = text
  yaml.value.dirty = true
}

/** Names the override can point at: the groups and nodes of the profile it applies to. */
const knownNames = computed(() => {
  if (!yaml.value?.profile.current) return {}
  const catalog = snap.value.node_catalog
  return {
    groups: catalog.map((group) => group.name),
    proxies: [...new Set(catalog.flatMap((group) => group.nodes.map((node) => node.name)))],
  }
})

/** Ask before dropping unsaved YAML; the editor keeps its own caret and history (R27). */
function beforeYamlClose() {
  if (!yaml.value?.dirty) return true
  discardOpen.value = true
  return false
}

function requestYamlClose() {
  if (!yaml.value) return
  if (yaml.value.dirty) {
    discardOpen.value = true
    return
  }
  yaml.value = null
}

async function keepEditing() {
  discardOpen.value = false
  await nextTick()
  editorRef.value?.focus()
}

async function discardChanges() {
  discardOpen.value = false
  await nextTick()
  yaml.value = null
}

// Effective config: read-only view of what the kernel runs.
const effective = ref<{ text: string; error: string | null; loading: boolean } | null>(null)

async function openEffective() {
  menuFor.value = null
  effective.value = { text: '', error: null, loading: true }
  try {
    const text = await store.backend.effectiveConfig()
    if (effective.value) effective.value = { text, error: null, loading: false }
  } catch (error) {
    if (effective.value) effective.value = { text: '', error: String((error as Error)?.message ?? error), loading: false }
  }
}

async function copyEffective() {
  if (!effective.value?.text) return
  try {
    await navigator.clipboard.writeText(effective.value.text)
    store.toast('已复制生效配置', 'success')
  } catch {
    store.toast('无法写入剪贴板', 'error')
  }
}

async function saveYaml() {
  if (!yaml.value) return
  const { profile, mode, text } = yaml.value
  yamlError.value = null
  if (mode === 'content') {
    const result = await store.saveContent(profile.id, text)
    const reason = result ? result.input_error : store.lastRunError.value ?? '配置没有保存'
    if (reason) {
      yamlError.value = reason
      return
    }
    yaml.value = null
    return
  }
  const result = await store.saveOverride(profile.id, text)
  const after = result?.profiles.find((item) => item.id === profile.id)
  const reason = result ? after?.override_error ?? null : store.lastRunError.value ?? '覆写没有保存'
  if (reason) {
    yamlError.value = reason
    return
  }
  yaml.value = null
  store.toast(profile.current ? '覆写已保存，重新启用该配置后生效' : '覆写已保存', 'success')
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

/** "正在更新 x/y" while running, then the kept result so a page switch loses nothing (R27). */
const updateAllLabel = computed(() => {
  const progress = store.refreshProgress.value
  if (store.busy.refreshAll) return `正在更新 ${Math.min(progress.done + 1, Math.max(progress.total, 1))}/${progress.total}`
  if (progress.total && progress.done >= progress.total) {
    return progress.failed ? `已完成 ${progress.done}/${progress.total} · ${progress.failed} 个失败` : `已完成 ${progress.done}/${progress.total}`
  }
  return '全部更新'
})
</script>

<template>
  <div
    class="page profiles"
    :class="{ 'drop-active': pageDragging }"
    @dragover.prevent="pageDragging = true"
    @dragleave.self="pageDragging = false"
    @drop.prevent="onPageDrop"
  >
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
          data-testid="update-all-profiles"
          :disabled="store.busy.refreshAll"
          :aria-busy="store.busy.refreshAll || undefined"
          @click="store.refreshAll()"
        >
          <Icon name="refresh" :size="15" />
          {{ updateAllLabel }}
        </button>
        <button type="button" class="btn primary sm" data-testid="add-profile" @click="store.adding.value = true">
          <Icon name="plus" :size="15" /> 添加
        </button>
      </div>
    </header>

    <form class="quick-import" @submit.prevent="quickImport">
      <Icon name="link" :size="16" class="muted" />
      <input
        ref="quickInputEl"
        v-model="quickUrl"
        type="url"
        placeholder="粘贴订阅链接回车导入，或直接拖入 YAML 文件"
        spellcheck="false"
        :aria-invalid="quickError ? 'true' : undefined"
        :aria-describedby="quickError ? 'quick-import-error' : undefined"
        @input="quickError = null"
      />
      <template v-if="!quickUrl">
        <button
          type="button"
          class="btn ghost sm"
          title="从剪贴板粘贴订阅链接"
          data-testid="quick-paste"
          @click="pasteQuickUrl"
        >
          <Icon name="clipboard" :size="14" />粘贴
        </button>
        <label v-if="!compact" class="btn ghost sm quick-file-btn" title="选择本地 YAML 配置文件">
          <Icon name="file" :size="14" />本地文件
          <input type="file" accept=".yaml,.yml,.txt,text/yaml" hidden @change="onQuickFile" />
        </label>
      </template>
      <button
        v-else
        type="button"
        class="icon-btn sm"
        aria-label="清空输入"
        title="清空"
        data-testid="quick-clear"
        @click="quickUrl = ''; quickError = null; quickInputEl?.focus()"
      >
        <Icon name="x" :size="14" />
      </button>
      <button type="submit" class="btn primary sm" :disabled="!quickUrl.trim() || store.busy.add">导入</button>
    </form>
    <p v-if="quickError" id="quick-import-error" class="field-error small" role="alert">{{ quickError }}</p>

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
        tabindex="-1"
        :aria-current="profile.current ? 'true' : undefined"
        @click="activate(profile)"
      >
        <header class="profile-head">
          <span class="sub-icon"><Icon :name="profile.kind === 'local' ? 'file' : 'link'" /></span>
          <div class="grow min0">
            <div class="profile-name">
              <strong :title="profile.name">{{ profile.name }}</strong>
              <span v-if="profile.current" class="tag accent">使用中</span>
              <span v-else-if="compact" class="tag profile-touch-cue" aria-hidden="true">启用</span>
              <span v-else class="profile-switch-hint" aria-hidden="true">点击启用</span>
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
            :title="store.busy[`update:${profile.id}`] ? '更新中' : '更新订阅'"
            :aria-label="store.busy[`update:${profile.id}`] ? '更新中' : '更新订阅'"
            :aria-busy="store.busy[`update:${profile.id}`] || undefined"
            :disabled="store.busy[`update:${profile.id}`]"
            @click.stop="store.update(profile.id)"
          >
            <Icon name="refresh" />
          </button>
          <div class="menu-anchor" @click.stop @keydown.esc.stop.prevent="closeProfileMenu(true)">
            <button
              type="button"
              class="icon-btn"
              aria-label="更多操作"
              aria-haspopup="menu"
              :aria-expanded="menuFor === profile.id"
              :data-menu-trigger="profile.id"
              @click="menuFor = menuFor === profile.id ? null : profile.id"
            >
              <Icon name="more" />
            </button>
            <Menu
              v-if="menuFor === profile.id"
              :items="menuItems(profile)"
              label="配置操作"
              @select="(item) => selectMenuItem(profile, item)"
              @close="closeProfileMenu(false)"
            />
          </div>
        </header>

        <div v-if="usagePercent(profile.used, profile.total) != null" class="usage">
          <div class="usage-bar"><span :style="{ width: `${usagePercent(profile.used, profile.total)}%` }" :class="{ warn: (usagePercent(profile.used, profile.total) ?? 0) > 85 }" /></div>
          <div class="usage-text small">
            <span class="mono">
              {{ formatBytes(profile.used) }} / {{ formatBytes(profile.total) }}
              <span v-if="profile.total != null && profile.used != null && profile.total > 0" class="muted">
                · 剩 {{ formatBytes(Math.max(0, profile.total - profile.used)) }}
              </span>
            </span>
            <span
              v-if="profile.expire"
              :class="{
                'text-error': daysLeft(profile.expire) < 0,
                'text-warn': daysLeft(profile.expire) >= 0 && daysLeft(profile.expire) <= 7,
              }"
            >
              {{
                daysLeft(profile.expire) < 0
                  ? '已过期'
                  : daysLeft(profile.expire) <= 14
                    ? `${formatDate(profile.expire)} 到期 · 剩 ${daysLeft(profile.expire)} 天`
                    : `${formatDate(profile.expire)} 到期`
              }}
            </span>
          </div>
        </div>

        <footer class="profile-foot small muted">
          <span><Icon name="clock" :size="13" />{{ formatRelative(profile.updated_ms ?? profile.last_success_ms) }}</span>
          <span v-if="profile.proxy_count"><Icon name="globe" :size="13" />{{ profile.proxy_count }} 节点</span>
          <span v-if="profile.interval_hours"><Icon name="refresh" :size="13" />{{ profile.interval_hours >= 24 && profile.interval_hours % 24 === 0 ? `${profile.interval_hours / 24} 天` : `${profile.interval_hours} 时` }}</span>
          <span v-if="profile.override_text.trim()" class="tag">覆写</span>
        </footer>
        <p v-if="profile.failure && store.profileUpdates[profile.id]?.state !== 'failure'" class="field-error small">
          <Icon name="alert" :size="13" /> {{ profile.failure }}
        </p>
        <p v-if="profile.override_error" class="field-error small"><Icon name="alert" :size="13" /> {{ profile.override_error }}</p>
        <div
          v-if="store.profileUpdates[profile.id]"
          class="profile-update small"
          :data-update-state="store.profileUpdates[profile.id]?.state"
          aria-live="polite"
        >
          <template v-if="store.profileUpdates[profile.id]?.state === 'updating'">
            <span class="muted">更新中</span>
          </template>
          <template v-else-if="store.profileUpdates[profile.id]?.state === 'success'">
            <span class="text-ok"><Icon name="check" :size="13" /> 已更新</span>
          </template>
          <template v-else>
            <span class="field-error" role="alert"><Icon name="alert" :size="13" /> {{ store.profileUpdates[profile.id]?.reason }}</span>
            <button type="button" class="btn ghost sm" data-testid="retry-update" @click.stop="store.update(profile.id)">重试</button>
          </template>
        </div>
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
            <SelectField
              :model-value="form.interval"
              :options="INTERVALS.map((option) => ({ value: option.hours, label: option.label }))"
              :sheet="compact"
              label="自动更新"
              class="field-select"
              @update:model-value="(value) => (form.interval = Number(value))"
            />
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
      :before-close="beforeYamlClose"
      @close="yaml = null"
    >
      <YamlEditor
        ref="editorRef"
        class="editor"
        :model-value="yaml.text"
        :names="knownNames"
        :label="yaml.mode === 'content' ? '配置文件' : '覆写'"
        :placeholder="yaml.mode === 'override' ? '# 只写需要改的部分，例如：\nmixed-port: 7890\ndns:\n  enable: true' : ''"
        :aria-invalid="yamlError ? 'true' : undefined"
        @update:model-value="onYamlInput"
        @save="saveYaml"
      />
      <p v-if="yamlError" class="field-error editor-error" role="alert">{{ yamlError }}</p>
      <template #footer>
        <span class="muted small grow editor-meta">
          {{ yamlLines }} 行{{ yaml.dirty ? ' · 未保存' : '' }}
          <span class="editor-hint">· Ctrl+Space 补全 · Ctrl+F 查找</span>
          <button
            v-if="yaml.profile.current"
            type="button"
            class="link-btn"
            data-testid="open-effective"
            @click="openEffective"
          >查看生效配置</button>
        </span>
        <button type="button" class="btn ghost" data-testid="cancel-editor" @click="requestYamlClose">取消</button>
        <button type="button" class="btn primary" :disabled="store.busy.content || store.busy.override" @click="saveYaml">保存</button>
      </template>
    </Modal>

    <Modal
      v-if="effective"
      wide
      title="生效配置"
      :subtitle="snap.kernel_running ? '内核正在运行的配置：订阅内容、覆写与应用设置合并后的结果，只读' : '下次连接时将使用的配置：订阅内容、覆写与应用设置合并后的结果，只读'"
      @close="effective = null"
    >
      <p v-if="effective.error" class="field-error" role="alert">{{ effective.error }}</p>
      <div v-else-if="effective.loading" class="editor yaml-editor-loading muted small"><span class="spinner xs" /> 正在生成…</div>
      <YamlEditor v-else class="editor" :model-value="effective.text" readonly label="生效配置" data-testid="effective-config" />
      <template #footer>
        <span class="muted small grow">{{ effective.text ? `${effective.text.split('\n').length} 行` : '' }}</span>
        <button type="button" class="btn ghost" :disabled="!effective.text" @click="copyEffective"><Icon name="copy" :size="15" />复制</button>
        <button type="button" class="btn primary" @click="effective = null">关闭</button>
      </template>
    </Modal>

    <Modal v-if="discardOpen" title="放弃未保存的修改？" @close="keepEditing">
      <p>关闭后，这次对「{{ yaml?.profile.name }}」的修改不会保存。</p>
      <template #footer>
        <button type="button" class="btn ghost" data-testid="keep-editing" @click="keepEditing">继续编辑</button>
        <button type="button" class="btn danger" data-testid="discard-edits" @click="discardChanges">放弃修改</button>
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
