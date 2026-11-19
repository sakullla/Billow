<script setup lang="ts">
import { computed, nextTick, onMounted, reactive, ref } from 'vue'
import EmptyState from '../components/EmptyState.vue'
import Icon from '../components/Icon.vue'
import Menu, { type MenuItem } from '../components/Menu.vue'
import Modal from '../components/Modal.vue'
import Segmented from '../components/Segmented.vue'
import SelectField from '../components/SelectField.vue'
import YamlEditor from '../components/YamlEditor.vue'
import { daysLeft, formatBytes, formatDate, formatRelative, hostOf, usagePercent } from '../lib/format'
import { useStore } from '../lib/store'
import { subscriptionUserAgent } from '../lib/subscription'
import type { OverridePreview, ProfileItem } from '../lib/types'
import { shortcutKeyLabel } from '../lib/ui/shortcuts'
import { mergeOverrideAppend } from '../lib/yaml/mergeOverride'
import { overrideLanguage, SCRIPT_TEMPLATE, YAML_TEMPLATE, type OverrideLanguage } from '../lib/yaml/script'

const findShortcut = shortcutKeyLabel('mod+f').replace(/\s+/g, '')
const saveShortcut = shortcutKeyLabel('mod+s').replace(/\s+/g, '')

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

function onPageDragLeave(event: DragEvent) {
  const current = event.currentTarget as HTMLElement | null
  const next = event.relatedTarget as Node | null
  if (!next || !current?.contains(next)) {
    pageDragging.value = false
  }
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
  else if (item.id === 'effective') openEffective()
  else if (item.id === 'copy') void copyLink(profile)
  else if (item.id === 'remove') removing.value = profile
}

// Edit info
type EditFieldKey = 'name' | 'url' | 'interval' | 'age' | 'userAgent'
const EDIT_FIELD_ORDER: readonly EditFieldKey[] = ['name', 'url', 'interval', 'age', 'userAgent']
const EDIT_FIELD_LABELS: Record<EditFieldKey, string> = {
  name: '名称',
  url: '订阅链接',
  interval: '自动更新',
  age: 'age 私钥',
  userAgent: 'User-Agent',
}
const AGE_KEY_FORMAT_ERROR = 'age 私钥格式不正确：每行一个以 AGE-SECRET-KEY-1 开头的私钥，# 开头的行视为注释'

const editingId = ref<string | null>(null)
const editingFallback = ref<ProfileItem | null>(null)
const editing = computed<ProfileItem | null>(() => {
  if (!editingId.value) return null
  return snap.value.profiles.find((item) => item.id === editingId.value) ?? editingFallback.value
})
const inheritedUserAgent = computed(() => subscriptionUserAgent(store.kernel.value.version, snap.value.settings.subscription_user_agent))
const form = ref({ name: '', url: '', userAgent: '', interval: 0 })
const nameInput = ref<HTMLInputElement | null>(null)
const urlInput = ref<HTMLInputElement | null>(null)
const uaInput = ref<HTMLInputElement | null>(null)
/**
 * age identities for encrypted subscriptions (age 私钥). The backend only returns
 * public keys, so the field starts empty: typing replaces the key, 「清除」 removes it,
 * leaving it untouched keeps the current one.
 */
const ageKey = ref('')
const ageEditing = ref(false)
const ageClear = ref(false)
const ageInput = ref<HTMLTextAreaElement | null>(null)
/** Opened from an age failure: the dialog lands on the key field instead of the close button. */
const ageFocus = ref(false)
/** age key and User-Agent are rarely touched; they fold away unless set or needed right now. */
const advancedOpen = ref(false)
const savingEdit = ref(false)
const saveAttemptFailed = ref(false)
const fieldErrors = reactive<Partial<Record<EditFieldKey, string>>>({})
const savedFields = reactive<Partial<Record<EditFieldKey, boolean>>>({})
const sessionAgeSecretSaved = ref(false)
const initialNeedsAgeRefresh = ref(false)
const AGE_FAILURE = /age/i

/** Obvious paste mistakes are named before the backend's strict check. */
const ageHint = computed(() => {
  const text = ageKey.value.trim()
  if (!text) return null
  if (/^age1[0-9a-z]+$/m.test(text) && !/AGE-SECRET-KEY-1/i.test(text)) {
    return '这是公钥（age1…），请填写对应的私钥 AGE-SECRET-KEY-1…'
  }
  if (/-----BEGIN AGE ENCRYPTED FILE-----/.test(text)) return '这是加密后的内容，请填写解密用的私钥'
  return null
})

const ageErrorMessage = computed(() => fieldErrors.age ?? ageHint.value)

function cleanProfileName(raw: string): string {
  return raw.trim().replace(/[/\\\r\n]/g, '').slice(0, 80)
}

function validateSubscriptionUrl(raw: string): string | null {
  const url = raw.trim()
  if (!url) return '请填写订阅链接'
  if (!/^https?:\/\//i.test(url) || /[\s\x00-\x1f\x7f]/.test(url)) {
    return '请输入以 http:// 或 https:// 开头的有效订阅链接'
  }
  try {
    const parsed = new URL(url)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return '请输入以 http:// 或 https:// 开头的有效订阅链接'
    }
    const host = parsed.hostname
    if (!host || (!host.includes('.') && host !== 'localhost' && !host.startsWith('['))) {
      return '请输入有效的订阅链接域名或地址'
    }
    return null
  } catch {
    return '请输入以 http:// 或 https:// 开头的有效订阅链接'
  }
}

function validateAgeInput(raw: string): string | null {
  if (ageHint.value) return ageHint.value
  const lines = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
  if (!lines.length) return null
  if (lines.some((line) => !/^AGE-SECRET-KEY-1[0-9A-Z]{58}$/.test(line))) {
    return AGE_KEY_FORMAT_ERROR
  }
  return null
}

function validateUserAgentInput(raw: string): string | null {
  if (raw.length > 256 || /[^\x20-\x7e]/.test(raw)) {
    return 'User-Agent 只能包含可打印的 ASCII 字符，长度不能超过 256，不能含换行'
  }
  return null
}

function shortKey(key: string): string {
  return key.length > 22 ? `${key.slice(0, 12)}…${key.slice(-8)}` : key
}

function ageFailure(profile: ProfileItem): boolean {
  return profile.kind === 'subscription' && AGE_FAILURE.test(profile.failure ?? '')
}
const INTERVALS = [
  { hours: 0, label: '不自动更新' },
  { hours: 6, label: '每 6 小时' },
  { hours: 12, label: '每 12 小时' },
  { hours: 24, label: '每天' },
  { hours: 72, label: '每 3 天' },
  { hours: 168, label: '每周' },
]

function clearEditTracking() {
  for (const key of EDIT_FIELD_ORDER) {
    delete fieldErrors[key]
    delete savedFields[key]
  }
  saveAttemptFailed.value = false
}

function isFieldDirty(key: EditFieldKey, base: ProfileItem | null = editing.value): boolean {
  if (!base) return false
  if (key === 'name') return cleanProfileName(form.value.name) !== base.name
  if (base.kind !== 'subscription') return false
  if (key === 'url') return form.value.url.trim() !== base.source
  if (key === 'interval') return form.value.interval !== base.interval_hours
  if (key === 'age') return Boolean(ageKey.value.trim()) || (ageClear.value && base.age_recipients.length > 0)
  if (key === 'userAgent') return form.value.userAgent.trim() !== base.user_agent
  return false
}

function editFieldStatus(key: EditFieldKey): 'saved' | 'failed' | 'pending' | null {
  if (!saveAttemptFailed.value) return null
  if (fieldErrors[key]) return 'failed'
  if (isFieldDirty(key)) return 'pending'
  if (savedFields[key]) return 'saved'
  return null
}

const partialSaveGroups = computed(() => {
  if (!saveAttemptFailed.value) return { saved: [] as string[], failed: [] as string[], pending: [] as string[] }
  const saved: string[] = []
  const failed: string[] = []
  const pending: string[] = []
  for (const key of EDIT_FIELD_ORDER) {
    const status = editFieldStatus(key)
    const label = EDIT_FIELD_LABELS[key]
    if (status === 'saved') saved.push(label)
    else if (status === 'failed') failed.push(label)
    else if (status === 'pending') pending.push(label)
  }
  return { saved, failed, pending }
})

function onEditFieldChange(key: EditFieldKey) {
  delete fieldErrors[key]
}

async function focusEditField(key: EditFieldKey) {
  if (key === 'age' || key === 'userAgent') {
    advancedOpen.value = true
    if (key === 'age' && !ageClear.value) ageEditing.value = true
  }
  await nextTick()
  let target: HTMLElement | null = null
  if (key === 'name') target = nameInput.value
  else if (key === 'url') target = urlInput.value
  else if (key === 'interval') {
    target = document.querySelector<HTMLElement>('[data-testid="profile-interval-field"] button')
  } else if (key === 'age') target = ageInput.value
  else if (key === 'userAgent') target = uaInput.value
  target?.scrollIntoView?.({ block: 'nearest' })
  target?.focus({ preventScroll: true })
}

function openEdit(profile: ProfileItem, focusAge = false) {
  menuFor.value = null
  clearEditTracking()
  editingFallback.value = profile
  editingId.value = profile.id
  form.value = { name: profile.name, url: profile.source, userAgent: profile.user_agent, interval: profile.interval_hours }
  ageKey.value = ''
  ageClear.value = false
  ageEditing.value = focusAge || profile.age_recipients.length === 0
  ageFocus.value = focusAge
  advancedOpen.value = focusAge || Boolean(profile.user_agent)
  sessionAgeSecretSaved.value = false
  initialNeedsAgeRefresh.value = ageFailure(profile) || !profile.last_success_ms
}

function closeEdit() {
  if (savingEdit.value) return
  editingId.value = null
  editingFallback.value = null
  clearEditTracking()
}

function changeAgeKey() {
  ageEditing.value = true
  ageClear.value = false
  delete fieldErrors.age
  void nextTick(() => ageInput.value?.focus())
}

async function saveEdit() {
  if (savingEdit.value) return
  const profile = editing.value
  if (!profile) return

  // Validate the whole form before submitting anything, including modified advanced options (R2).
  const preErrors: Partial<Record<EditFieldKey, string>> = {}
  if (!cleanProfileName(form.value.name)) {
    preErrors.name = '请填写配置名称'
  }
  if (profile.kind === 'subscription') {
    if (isFieldDirty('url', profile) || !form.value.url.trim()) {
      const urlErr = validateSubscriptionUrl(form.value.url)
      if (urlErr) preErrors.url = urlErr
    }
    if (isFieldDirty('age', profile) && !ageClear.value) {
      const ageErr = validateAgeInput(ageKey.value)
      if (ageErr) preErrors.age = ageErr
    }
    if (isFieldDirty('userAgent', profile)) {
      const uaErr = validateUserAgentInput(form.value.userAgent)
      if (uaErr) preErrors.userAgent = uaErr
    }
  }

  for (const key of EDIT_FIELD_ORDER) delete fieldErrors[key]
  const firstInvalid = EDIT_FIELD_ORDER.find((key) => Boolean(preErrors[key]))
  if (firstInvalid) {
    Object.assign(fieldErrors, preErrors)
    if (preErrors.age || preErrors.userAgent) advancedOpen.value = true
    await focusEditField(firstInvalid)
    return
  }

  const id = profile.id
  savingEdit.value = true
  try {
    if (isFieldDirty('name')) {
      const expectedName = cleanProfileName(form.value.name)
      const result = await store.rename(id, form.value.name)
      const after = result?.profiles.find((item) => item.id === id)
      if (!result || result.input_error || after?.name !== expectedName) {
        fieldErrors.name = result?.input_error || store.lastRunError.value || '名称未能保存'
        saveAttemptFailed.value = true
        await focusEditField('name')
        return
      }
      savedFields.name = true
    }

    if (profile.kind === 'subscription' && isFieldDirty('url')) {
      const expectedUrl = form.value.url.trim()
      const result = await store.setSource(id, form.value.url)
      const after = result?.profiles.find((item) => item.id === id)
      if (!result || result.input_error || after?.source !== expectedUrl) {
        fieldErrors.url = result?.input_error || store.lastRunError.value || '订阅链接未能保存'
        saveAttemptFailed.value = true
        await focusEditField('url')
        return
      }
      savedFields.url = true
    }

    if (profile.kind === 'subscription' && isFieldDirty('interval')) {
      const expectedHours = Math.min(form.value.interval, 24 * 30)
      const result = await store.setInterval(id, form.value.interval)
      const after = result?.profiles.find((item) => item.id === id)
      if (!result || result.input_error || after?.interval_hours !== expectedHours) {
        fieldErrors.interval = result?.input_error || store.lastRunError.value || '自动更新间隔未能保存'
        saveAttemptFailed.value = true
        await focusEditField('interval')
        return
      }
      savedFields.interval = true
    }

    if (profile.kind === 'subscription' && isFieldDirty('age')) {
      const clearing = ageClear.value
      const result = await store.setAgeKey(id, clearing ? '' : ageKey.value)
      if (!result || result.input_error) {
        fieldErrors.age = result?.input_error || store.lastRunError.value || 'age 私钥未能保存'
        saveAttemptFailed.value = true
        advancedOpen.value = true
        await focusEditField('age')
        return
      }
      savedFields.age = true
      if (clearing) {
        ageClear.value = false
        ageKey.value = ''
        ageEditing.value = true
      } else {
        sessionAgeSecretSaved.value = true
        ageKey.value = ''
        ageClear.value = false
        ageEditing.value = false
      }
    }

    if (profile.kind === 'subscription' && isFieldDirty('userAgent')) {
      const expectedUa = form.value.userAgent.trim()
      const result = await store.setUserAgent(id, form.value.userAgent)
      const after = result?.profiles.find((item) => item.id === id)
      if (!result || result.input_error || after?.user_agent !== expectedUa) {
        fieldErrors.userAgent = result?.input_error || store.lastRunError.value || 'User-Agent 未能保存'
        saveAttemptFailed.value = true
        advancedOpen.value = true
        await focusEditField('userAgent')
        return
      }
      savedFields.userAgent = true
    }

    const needAgeRefresh = sessionAgeSecretSaved.value && initialNeedsAgeRefresh.value
    editingId.value = null
    editingFallback.value = null
    clearEditTracking()
    // A new key is only useful once the subscription is fetched again with it.
    if (needAgeRefresh) {
      store.toast('已保存，正在用新私钥更新订阅', 'success')
      void store.update(id)
      return
    }
    store.toast('已保存', 'success')
  } finally {
    savingEdit.value = false
    if (
      saveAttemptFailed.value &&
      (editFieldStatus('age') === 'failed' ||
        editFieldStatus('age') === 'pending' ||
        editFieldStatus('userAgent') === 'failed' ||
        editFieldStatus('userAgent') === 'pending')
    ) {
      advancedOpen.value = true
    }
  }
}

// YAML editors
interface YamlDraft {
  profile: ProfileItem
  mode: 'content' | 'override'
  text: string
  dirty: boolean
  /** Override only: YAML merge or a `main(config)` script. */
  language: OverrideLanguage
}

const OVERRIDE_LANGUAGES: { id: OverrideLanguage; label: string }[] = [
  { id: 'yaml', label: 'YAML' },
  { id: 'javascript', label: 'JavaScript' },
]
const TEMPLATES: Record<OverrideLanguage, string> = { yaml: YAML_TEMPLATE, javascript: SCRIPT_TEMPLATE }

const yaml = ref<YamlDraft | null>(null)
const syntaxOpen = ref(false)
const languageSwitch = ref<OverrideLanguage | null>(null)
const preview = ref<(OverridePreview & { error: string | null }) | null>(null)
const previewing = ref(false)
const yamlError = ref<string | null>(null)
const discardOpen = ref(false)
const editorRef = ref<InstanceType<typeof YamlEditor> | null>(null)

async function openYaml(profile: ProfileItem, mode: 'content' | 'override') {
  menuFor.value = null
  yamlError.value = null
  discardOpen.value = false
  const text = mode === 'content' ? await store.backend.content(profile.id) : profile.override_text
  preview.value = null
  syntaxOpen.value = false
  yaml.value = { profile, mode, text, dirty: false, language: overrideLanguage(text) }
}

/** Another page (system proxy bypass or Home error banner) opens or appends to the 覆写 editor. */
onMounted(async () => {
  const request = store.overrideRequest.value
  store.overrideRequest.value = null
  const profile = request ? snap.value.profiles.find((item) => item.id === request.id) : undefined
  if (!request || !profile) return
  await openYaml(profile, 'override')
  if (!request.append) return
  const draft = yaml.value
  if (!draft) return
  if (draft.language === 'javascript') {
    yamlError.value = '当前覆写是脚本，请在 main 中用 config.rules.unshift(...) 加入这些规则：\n' + request.append
    return
  }
  const merged = mergeOverrideAppend(draft.text, request.append)
  if (!merged.changed) {
    store.toast('该规则已在覆写列表中', 'info')
    return
  }
  draft.text = merged.text
  draft.dirty = true
})

/** Switching form keeps work: an empty or untouched template is swapped silently, anything else asks first. */
function chooseLanguage(next: OverrideLanguage) {
  const draft = yaml.value
  if (!draft || draft.language === next) return
  const text = draft.text.trim()
  if (!text || text === TEMPLATES[draft.language].trim()) {
    applyLanguage(next)
    return
  }
  languageSwitch.value = next
}

function applyLanguage(next: OverrideLanguage) {
  const draft = yaml.value
  languageSwitch.value = null
  if (!draft) return
  draft.language = next
  draft.text = TEMPLATES[next]
  draft.dirty = true
  preview.value = null
  void nextTick(() => editorRef.value?.focus())
}

function insertTemplate() {
  const draft = yaml.value
  if (!draft) return
  draft.text = TEMPLATES[draft.language]
  draft.dirty = true
  void nextTick(() => editorRef.value?.focus())
}

/** Run the unsaved 覆写 against the profile and show the merged result (and script logs). */
async function runPreview() {
  const draft = yaml.value
  if (!draft || previewing.value) return
  previewing.value = true
  try {
    const result = await store.backend.previewOverride(draft.profile.id, draft.text)
    if (yaml.value === draft) preview.value = { ...result, error: null }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    if (yaml.value === draft) preview.value = { yaml: '', logs: [], error: message }
  } finally {
    previewing.value = false
  }
}

const yamlLines = computed(() => (yaml.value ? yaml.value.text.split('\n').length : 0))

function onYamlInput(text: string) {
  if (!yaml.value) return
  yaml.value.text = text
  yaml.value.dirty = true
  // Pasting or typing `function main(` turns the draft into a script without a mode click.
  if (yaml.value.mode === 'override' && overrideLanguage(text) === 'javascript') yaml.value.language = 'javascript'
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

// Effective config lives in the app-wide viewer; the editor link opens its YAML tab.
function openEffective(tab?: 'overview' | 'yaml') {
  menuFor.value = null
  store.openConfig(tab)
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
  if (!after?.current) {
    store.toast('覆写已保存，启用该配置时生效', 'success')
    return
  }
  // The active profile picks the override up right away (hot reload, connections stay).
  const applied = await store.applyOverride(profile.id)
  const failure = applied?.profiles.find((item) => item.id === profile.id)
  if (!applied) return
  if (failure?.override_error) store.toast(failure.override_error, 'error')
  else if (!failure?.failure) store.toast('覆写已保存并生效', 'success')
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

const failedSubscriptionIds = computed(() =>
  snap.value.profiles
    .filter((item) => item.kind === 'subscription' && store.profileUpdates[item.id]?.state === 'failure')
    .map((item) => item.id),
)
</script>

<template>
  <div
    class="page profiles"
    :class="{ 'drop-active': pageDragging }"
    @dragover.prevent="pageDragging = true"
    @dragleave="onPageDragLeave"
    @drop.prevent="onPageDrop"
  >
    <div v-if="pageDragging" class="drop-banner" aria-hidden="true">
      <Icon name="download" :size="16" />
      <span>释放即可导入 YAML 配置文件</span>
    </div>
    <header class="page-head">
      <div>
        <h1>配置</h1>
        <p class="muted small meta-line"><span>{{ snap.profiles.length }} 份配置</span><span>同一时间启用一份</span></p>
      </div>
      <div class="head-actions">
        <button
          v-if="failedSubscriptionIds.length && !store.busy.refreshAll"
          type="button"
          class="btn ghost sm danger-text"
          data-testid="retry-failed-profiles"
          @click="store.refreshAll(failedSubscriptionIds)"
        >
          <Icon name="refresh" :size="15" />
          重试失败 ({{ failedSubscriptionIds.length }})
        </button>
        <button
          v-if="subscriptions"
          type="button"
          class="btn ghost sm"
          data-testid="update-all-profiles"
          :disabled="store.busy.refreshAll"
          :aria-busy="store.busy.refreshAll || undefined"
          @click="store.refreshAll()"
        >
          <span v-if="store.busy.refreshAll" class="spinner sm" aria-hidden="true" />
          <Icon v-else name="refresh" :size="15" />
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
        :placeholder="compact ? '粘贴订阅链接' : '粘贴订阅链接回车导入，或直接拖入 YAML 文件'"
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

    <EmptyState
      v-if="!snap.profiles.length"
      variant="no-data"
      icon="layers"
      title="还没有配置"
      description="添加机场订阅链接，或导入本地 Clash / Mihomo 配置文件。"
    >
      <template #action>
        <button type="button" class="btn primary sm" @click="store.adding.value = true"><Icon name="plus" :size="15" /> 添加配置</button>
      </template>
    </EmptyState>

    <div class="profile-grid">
      <article
        v-for="profile in ordered"
        :key="profile.id"
        class="card profile"
        :class="{ current: profile.current, failed: profile.failure || profile.override_error, busy: store.busy[`enable:${profile.id}`] }"
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
            <span v-if="store.busy[`update:${profile.id}`]" class="spinner sm" aria-hidden="true" />
            <Icon v-else name="refresh" />
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

        <div v-if="usagePercent(profile.used, profile.total) != null || profile.expire" class="usage">
          <div v-if="usagePercent(profile.used, profile.total) != null" class="usage-bar">
            <span
              :style="{ width: `${(usagePercent(profile.used, profile.total) ?? 0) > 0 ? Math.max(usagePercent(profile.used, profile.total) ?? 0, 1.5) : 0}%` }"
              :class="{
                danger: (usagePercent(profile.used, profile.total) ?? 0) >= 98 || (Boolean(profile.expire) && daysLeft(profile.expire!) < 0),
                warn: (usagePercent(profile.used, profile.total) ?? 0) > 85 && (usagePercent(profile.used, profile.total) ?? 0) < 98 && (!profile.expire || daysLeft(profile.expire) >= 0),
              }"
            />
          </div>
          <div class="usage-text small">
            <span v-if="usagePercent(profile.used, profile.total) != null" class="mono">
              {{ formatBytes(profile.used) }} / {{ formatBytes(profile.total) }}
              <span v-if="profile.total != null && profile.used != null && profile.total > 0" class="muted">
                · 剩 {{ formatBytes(Math.max(0, profile.total - profile.used)) }}
              </span>
            </span>
            <span v-else class="muted">不限流量</span>
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
          <button
            v-if="profile.override_text.trim()"
            type="button"
            class="tag tag-btn"
            title="点击编辑覆写"
            data-testid="quick-override"
            @click.stop="openYaml(profile, 'override')"
          >
            覆写
          </button>
          <span v-if="profile.age_recipients.length" class="tag" title="订阅内容使用 age 私钥解密"><Icon name="shield" :size="11" />age</span>
        </footer>
        <p v-if="profile.failure && store.profileUpdates[profile.id]?.state !== 'failure'" class="field-error small">
          <Icon name="alert" :size="13" /> {{ profile.failure }}
          <button
            v-if="ageFailure(profile)"
            type="button"
            class="btn ghost sm"
            data-testid="age-fix"
            @click.stop="openEdit(profile, true)"
          >
            {{ profile.age_recipients.length ? '更换私钥' : '填写私钥' }}
          </button>
        </p>
        <p v-if="profile.override_error" class="field-error small">
          <Icon name="alert" :size="13" /> {{ profile.override_error }}
          <button
            type="button"
            class="btn ghost sm"
            data-testid="override-fix"
            @click.stop="openYaml(profile, 'override')"
          >
            修改覆写
          </button>
        </p>
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
            <button
              v-if="/age/i.test(store.profileUpdates[profile.id]?.reason ?? '')"
              type="button"
              class="btn ghost sm"
              data-testid="age-fix-update"
              @click.stop="openEdit(profile, true)"
            >
              {{ profile.age_recipients.length ? '更换私钥' : '填写私钥' }}
            </button>
            <button v-else type="button" class="btn ghost sm" data-testid="retry-update" @click.stop="store.update(profile.id)">重试</button>
          </template>
        </div>
      </article>
    </div>

    <Modal
      v-if="editing"
      title="编辑配置信息"
      :before-close="() => !savingEdit"
      :initial-focus="ageFocus ? () => ageInput : undefined"
      @close="closeEdit"
    >
      <form class="stack" novalidate @submit.prevent="saveEdit">
        <div
          v-if="saveAttemptFailed && (partialSaveGroups.saved.length || partialSaveGroups.pending.length)"
          class="banner warn small edit-save-summary"
          role="status"
          aria-live="polite"
          data-testid="edit-save-summary"
        >
          <Icon name="alert" :size="15" />
          <div class="grow edit-save-summary-body">
            <span v-if="partialSaveGroups.saved.length">已保存：{{ partialSaveGroups.saved.join('、') }}</span>
            <span v-if="partialSaveGroups.failed.length">保存失败：{{ partialSaveGroups.failed.join('、') }}</span>
            <span v-if="partialSaveGroups.pending.length">待保存：{{ partialSaveGroups.pending.join('、') }}</span>
            <span class="muted">修正后再次点击保存，将仅提交尚未保存的修改。</span>
          </div>
        </div>

        <label class="field">
          <span class="field-label-row">
            <span>名称</span>
            <span v-if="editFieldStatus('name') === 'saved'" class="tag ok sm" data-testid="field-state-name"><Icon name="check" :size="11" />已保存</span>
            <span v-else-if="editFieldStatus('name') === 'failed'" class="tag danger sm" data-testid="field-state-name"><Icon name="alert" :size="11" />保存失败</span>
            <span v-else-if="editFieldStatus('name') === 'pending'" class="tag warn sm" data-testid="field-state-name"><Icon name="clock" :size="11" />待保存</span>
          </span>
          <input
            ref="nameInput"
            v-model="form.name"
            type="text"
            maxlength="80"
            data-testid="profile-edit-name"
            :aria-invalid="fieldErrors.name ? 'true' : undefined"
            :aria-describedby="fieldErrors.name ? 'edit-name-error' : undefined"
            @input="onEditFieldChange('name')"
          />
          <p v-if="fieldErrors.name" id="edit-name-error" class="field-error small" role="alert" data-testid="field-error-name">
            <Icon name="alert" :size="13" />
            <span>{{ fieldErrors.name }}</span>
          </p>
        </label>
        <template v-if="editing.kind === 'subscription'">
          <label class="field">
            <span class="field-label-row">
              <span>订阅链接</span>
              <span v-if="editFieldStatus('url') === 'saved'" class="tag ok sm" data-testid="field-state-url"><Icon name="check" :size="11" />已保存</span>
              <span v-else-if="editFieldStatus('url') === 'failed'" class="tag danger sm" data-testid="field-state-url"><Icon name="alert" :size="11" />保存失败</span>
              <span v-else-if="editFieldStatus('url') === 'pending'" class="tag warn sm" data-testid="field-state-url"><Icon name="clock" :size="11" />待保存</span>
            </span>
            <input
              ref="urlInput"
              v-model="form.url"
              type="url"
              spellcheck="false"
              data-testid="profile-edit-url"
              :aria-invalid="fieldErrors.url ? 'true' : undefined"
              :aria-describedby="fieldErrors.url ? 'edit-url-error' : undefined"
              @input="onEditFieldChange('url')"
            />
            <p v-if="fieldErrors.url" id="edit-url-error" class="field-error small" role="alert" data-testid="field-error-url">
              <Icon name="alert" :size="13" />
              <span>{{ fieldErrors.url }}</span>
            </p>
          </label>
          <div class="field" data-testid="profile-interval-field">
            <span class="field-label-row">
              <span>自动更新</span>
              <span v-if="editFieldStatus('interval') === 'saved'" class="tag ok sm" data-testid="field-state-interval"><Icon name="check" :size="11" />已保存</span>
              <span v-else-if="editFieldStatus('interval') === 'failed'" class="tag danger sm" data-testid="field-state-interval"><Icon name="alert" :size="11" />保存失败</span>
              <span v-else-if="editFieldStatus('interval') === 'pending'" class="tag warn sm" data-testid="field-state-interval"><Icon name="clock" :size="11" />待保存</span>
            </span>
            <SelectField
              :model-value="form.interval"
              :options="INTERVALS.map((option) => ({ value: option.hours, label: option.label }))"
              :sheet="compact"
              label="自动更新"
              class="field-select"
              @update:model-value="(value) => { form.interval = Number(value); onEditFieldChange('interval') }"
            />
            <p v-if="fieldErrors.interval" id="edit-interval-error" class="field-error small" role="alert" data-testid="field-error-interval">
              <Icon name="alert" :size="13" />
              <span>{{ fieldErrors.interval }}</span>
            </p>
          </div>
          <details class="form-fold" data-testid="profile-advanced" :open="advancedOpen || undefined" @toggle="advancedOpen = ($event.target as HTMLDetailsElement).open">
            <summary>
              <Icon name="chevron-right" :size="14" />
              <span class="grow">高级选项</span>
              <span v-if="editing.age_recipients.length && !ageClear" class="tag sm">已配置私钥</span>
              <span v-if="form.userAgent.trim()" class="tag accent sm">已自定义 UA</span>
            </summary>
            <div class="field age-field" data-testid="age-field">
              <span class="age-field-label field-label-row">
                <span>age 私钥</span>
                <span v-if="editFieldStatus('age') === 'saved'" class="tag ok sm" data-testid="field-state-age"><Icon name="check" :size="11" />已保存</span>
                <span v-else-if="editFieldStatus('age') === 'failed'" class="tag danger sm" data-testid="field-state-age"><Icon name="alert" :size="11" />保存失败</span>
                <span v-else-if="editFieldStatus('age') === 'pending'" class="tag warn sm" data-testid="field-state-age"><Icon name="clock" :size="11" />待保存</span>
              </span>
              <div v-if="editing.age_recipients.length && !ageEditing" class="age-status" :class="{ clearing: ageClear }" data-testid="age-status">
                <Icon :name="ageClear ? 'trash' : 'shield'" :size="15" />
                <span class="grow min0">
                  <template v-if="ageClear">保存后将清除私钥，加密订阅将无法更新</template>
                  <template v-else>
                    已配置 {{ editing.age_recipients.length }} 个 ·
                    <span class="mono" :title="editing.age_recipients.join('\n')">{{ editing.age_recipients.map(shortKey).join('、') }}</span>
                  </template>
                </span>
                <template v-if="ageClear">
                  <button type="button" class="btn ghost sm" data-testid="age-undo-clear" @click="ageClear = false; onEditFieldChange('age')">撤销</button>
                </template>
                <template v-else>
                  <button type="button" class="btn ghost sm" data-testid="age-change" @click="changeAgeKey">更换</button>
                  <button type="button" class="btn ghost sm danger-text" data-testid="age-clear" @click="ageClear = true; onEditFieldChange('age')">清除</button>
                </template>
              </div>
              <template v-else>
                <textarea
                  ref="ageInput"
                  v-model="ageKey"
                  class="age-input mono"
                  rows="2"
                  spellcheck="false"
                  autocomplete="off"
                  autocapitalize="off"
                  placeholder="AGE-SECRET-KEY-1…  订阅内容经 age 加密时填写，可多行"
                  :aria-invalid="ageErrorMessage ? 'true' : undefined"
                  :aria-describedby="ageErrorMessage ? 'edit-age-error age-help' : 'age-help'"
                  data-testid="age-input"
                  @input="onEditFieldChange('age')"
                />
                <button
                  v-if="editing.age_recipients.length"
                  type="button"
                  class="btn ghost sm age-cancel"
                  @click="ageEditing = false; ageKey = ''; onEditFieldChange('age')"
                >
                  保留原私钥
                </button>
              </template>
              <p
                v-if="ageErrorMessage"
                id="edit-age-error"
                class="field-error small"
                role="alert"
                :data-testid="ageHint ? 'age-hint' : 'field-error-age'"
              >
                <Icon name="alert" :size="13" />
                <span>{{ ageErrorMessage }}</span>
              </p>
              <p id="age-help" class="muted small">私钥只保存在本机，用于在更新时解密订阅；界面只显示对应的公钥。</p>
            </div>
            <label class="field">
              <span class="field-label-row">
                <span>User-Agent</span>
                <span v-if="editFieldStatus('userAgent') === 'saved'" class="tag ok sm" data-testid="field-state-userAgent"><Icon name="check" :size="11" />已保存</span>
                <span v-else-if="editFieldStatus('userAgent') === 'failed'" class="tag danger sm" data-testid="field-state-userAgent"><Icon name="alert" :size="11" />保存失败</span>
                <span v-else-if="editFieldStatus('userAgent') === 'pending'" class="tag warn sm" data-testid="field-state-userAgent"><Icon name="clock" :size="11" />待保存</span>
              </span>
              <input
                ref="uaInput"
                v-model="form.userAgent"
                type="text"
                maxlength="256"
                :placeholder="inheritedUserAgent"
                spellcheck="false"
                autocomplete="off"
                data-testid="profile-user-agent"
                :aria-invalid="fieldErrors.userAgent ? 'true' : undefined"
                :aria-describedby="fieldErrors.userAgent ? 'edit-ua-error profile-user-agent-help' : 'profile-user-agent-help'"
                @input="onEditFieldChange('userAgent')"
              />
              <p v-if="fieldErrors.userAgent" id="edit-ua-error" class="field-error small" role="alert" data-testid="field-error-userAgent">
                <Icon name="alert" :size="13" />
                <span>{{ fieldErrors.userAgent }}</span>
              </p>
              <span id="profile-user-agent-help" class="muted small">留空使用默认值，下次更新订阅时生效。</span>
            </label>
          </details>
        </template>
      </form>
      <template #footer>
        <button type="button" class="btn ghost" :disabled="savingEdit" @click="closeEdit">取消</button>
        <button
          type="button"
          class="btn primary"
          :aria-disabled="savingEdit || undefined"
          :aria-busy="savingEdit || undefined"
          data-testid="save-profile-edit"
          @click="saveEdit"
        >
          <span v-if="savingEdit" class="spinner xs" aria-hidden="true" />
          {{ savingEdit ? '保存中' : '保存' }}
        </button>
      </template>
    </Modal>

    <Modal
      v-if="yaml"
      wide
      :title="yaml.mode === 'content' ? `编辑 · ${yaml.profile.name}` : `覆写 · ${yaml.profile.name}`"
      :subtitle="yaml.mode === 'content'
        ? (yaml.profile.kind === 'subscription' ? '订阅更新时会覆盖这里的修改；长期修改请使用覆写' : '保存后立即替换这份配置')
        : yaml.language === 'yaml'
          ? '以 YAML 深度合并到配置之上，订阅更新后依然保留'
          : '用 JavaScript 的 main(config) 修改配置并返回，订阅更新后依然保留'"
      :before-close="beforeYamlClose"
      @close="yaml = null"
    >
      <div v-if="yaml.mode === 'override'" class="override-bar">
        <Segmented
          :model-value="yaml.language"
          :options="OVERRIDE_LANGUAGES"
          size="sm"
          label="覆写类型"
          data-testid="override-language"
          @update:model-value="chooseLanguage"
        />
        <button
          type="button"
          class="btn ghost sm"
          :aria-expanded="syntaxOpen"
          data-testid="override-syntax"
          @click="syntaxOpen = !syntaxOpen"
        >
          <Icon name="info" :size="14" />语法
        </button>
        <button v-if="!yaml.text.trim()" type="button" class="btn ghost sm" data-testid="override-template" @click="insertTemplate">
          <Icon name="plus" :size="14" />插入示例
        </button>
        <span class="grow" />
        <button
          type="button"
          class="btn sm"
          :disabled="previewing || !yaml.text.trim()"
          data-testid="override-preview"
          @click="runPreview"
        >
          <span v-if="previewing" class="spinner xs" /><Icon v-else name="play" :size="14" />预览结果
        </button>
      </div>
      <div v-if="yaml.mode === 'override' && syntaxOpen" class="override-syntax small" data-testid="override-syntax-help">
        <template v-if="yaml.language === 'yaml'">
          <dl>
            <div><dt><code>key: 值</code></dt><dd>深度合并：对象逐层合并，列表与其他值直接替换</dd></div>
            <div><dt><code>+rules:</code></dt><dd>插入到原列表最前面（规则优先匹配）</dd></div>
            <div><dt><code>rules+:</code></dt><dd>追加到原列表末尾</dd></div>
            <div><dt><code>dns!:</code></dt><dd>整体替换该对象，不与原配置合并</dd></div>
            <div><dt><code>&lt;+.a.com&gt;:</code></dt><dd>键名本身以 + 开头或结尾时用尖括号包裹，也可写 <code>+&lt;+.a.com&gt;</code></dd></div>
            <div><dt><code>prepend-rules:</code></dt><dd>兼容 Clash Verge 写法（rules / proxies / proxy-groups 的 prepend- 与 append-）</dd></div>
          </dl>
        </template>
        <template v-else>
          <dl>
            <div><dt><code>main(config, profileName)</code></dt><dd>入口函数，修改 config 后返回；未返回时沿用修改后的 config</dd></div>
            <div><dt><code>console.log()</code></dt><dd>输出显示在“预览结果”中</dd></div>
            <div><dt>运行环境</dt><dd>独立沙箱，没有网络、文件与定时器；超过 10 秒自动中止</dd></div>
            <div><dt>补全</dt><dd>输入 <code>config.</code> 列出配置项，Ctrl+Space 列出常用片段，Tab 接受并跳到下一处</dd></div>
          </dl>
        </template>
      </div>
      <YamlEditor
        ref="editorRef"
        class="editor"
        :class="{ 'with-preview': preview }"
        :model-value="yaml.text"
        :names="knownNames"
        :override="yaml.mode === 'override'"
        :language="yaml.mode === 'override' ? yaml.language : 'yaml'"
        :label="yaml.mode === 'content' ? '配置文件' : '覆写'"
        :placeholder="yaml.mode === 'override'
          ? (yaml.language === 'yaml' ? '# 只写需要改的部分，例如：\n+rules:\n  - DOMAIN-SUFFIX,corp.example,DIRECT' : '// function main(config) { … return config }')
          : ''"
        :aria-invalid="yamlError ? 'true' : undefined"
        @update:model-value="onYamlInput"
        @save="saveYaml"
      />
      <section v-if="preview" class="override-preview" data-testid="override-preview-panel" aria-live="polite">
        <header>
          <strong class="small">{{ preview.error ? '无法应用' : '合并结果' }}</strong>
          <span v-if="!preview.error" class="muted small">保存前的预览，不影响当前连接</span>
          <span class="grow" />
          <button type="button" class="icon-btn sm" title="关闭预览" aria-label="关闭预览" @click="preview = null">
            <Icon name="x" :size="14" />
          </button>
        </header>
        <p v-if="preview.error" class="field-error small" role="alert"><Icon name="alert" :size="13" /> {{ preview.error }}</p>
        <ol v-if="preview.logs.length" class="override-logs mono small" aria-label="脚本输出">
          <li v-for="(line, index) in preview.logs" :key="index">{{ line }}</li>
        </ol>
        <YamlEditor v-if="!preview.error" class="editor preview-editor readonly" :model-value="preview.yaml" readonly label="合并结果" />
      </section>
      <p v-if="yamlError" class="field-error editor-error" role="alert">{{ yamlError }}</p>
      <template #footer>
        <span class="muted small grow editor-meta">
          <span>{{ yamlLines }} 行{{ yaml.dirty ? ' · 未保存' : '' }}</span>
          <span class="editor-hint">· Ctrl+Space 补全 · Tab 接受 · {{ findShortcut }} 查找 · {{ saveShortcut }} 保存</span>
          <template v-if="yaml.profile.current">
            <span aria-hidden="true">·</span>
            <button
              type="button"
              class="link-btn"
              data-testid="open-effective"
              @click="openEffective('yaml')"
            >查看生效配置</button>
          </template>
        </span>
        <button type="button" class="btn ghost" data-testid="cancel-editor" @click="requestYamlClose">取消</button>
        <button type="button" class="btn primary" :disabled="store.busy.content || store.busy.override" @click="saveYaml">
          {{ yaml.mode === 'override' && yaml.profile.current ? '保存并生效' : '保存' }}
        </button>
      </template>
    </Modal>

    <Modal v-if="languageSwitch" :title="`切换为 ${languageSwitch === 'javascript' ? 'JavaScript' : 'YAML'} 覆写？`" @close="languageSwitch = null">
      <p>两种写法不能混用，切换后当前内容会被示例替换。需要保留的话，可以先复制出来。</p>
      <template #footer>
        <button type="button" class="btn ghost" @click="languageSwitch = null">取消</button>
        <button type="button" class="btn danger" data-testid="confirm-language" @click="applyLanguage(languageSwitch)">替换内容</button>
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
