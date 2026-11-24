<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import Icon from './Icon.vue'
import Modal from './Modal.vue'
import SettingsRow from './settings/SettingsRow.vue'
import SettingsSection from './settings/SettingsSection.vue'
import { formatRelative } from '../lib/format'
import { t } from '../lib/i18n'
import { useStore } from '../lib/store'
import type { RemoteBackup, WebdavSettings } from '../lib/types'

/**
 * 备份与恢复 (R38): a local file next to the other exports, and a WebDAV
 * folder where uploading and restoring only happen when the user presses a
 * button (R45). Every restore is confirmed first and names the sensitive data
 * the file carries.
 */
defineProps<{ compact?: boolean }>()

const store = useStore()

const fileInput = ref<HTMLInputElement | null>(null)
const exporting = ref(false)
const exported = ref<string | null>(null)
const copiedPath = ref(false)
const localError = ref<string | null>(null)

type PendingRestore =
  | { kind: 'local'; name: string; file: File }
  | { kind: 'remote'; name: string; device?: string; modified?: string | null; size?: number | null }
const pending = ref<PendingRestore | null>(null)
const restoring = ref(false)

const form = ref<WebdavSettings>({ url: '', username: '', password: '', available: false })
const available = ref(false)
const editingAccount = ref(true)
const showPassword = ref(false)
const testing = ref(false)
const uploading = ref(false)
const listing = ref(false)
const testError = ref<string | null>(null)
const listError = ref<string | null>(null)
const uploaded = ref<string | null>(null)
const remote = ref<RemoteBackup[]>([])
const listed = ref(false)

function reason(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

onMounted(async () => {
  try {
    const info = await store.backend.webdavSettings()
    form.value = { ...info }
    available.value = info.available
    // Verified accounts open in summary mode so upload & cloud backups stay above the fold.
    editingAccount.value = !info.available
    if (info.available) await refreshList()
  } catch (error) {
    testError.value = reason(error)
    editingAccount.value = true
  }
})

const canTest = computed(() => Boolean(form.value.url.trim()))

/** Short human-readable endpoint for the collapsed account summary row. */
const endpointLabel = computed(() => {
  const raw = form.value.url.trim()
  if (!raw) return '—'
  try {
    const parsed = new URL(raw)
    const path = parsed.pathname.replace(/\/+$/, '')
    return path && path !== '/' ? `${parsed.host}${path}` : parsed.host
  } catch {
    return raw.replace(/^https?:\/\//i, '').replace(/\/+$/, '')
  }
})

async function onExport() {
  if (exporting.value) return
  exporting.value = true
  localError.value = null
  copiedPath.value = false
  try {
    const path = await store.exportBackup()
    if (path) exported.value = path
  } finally {
    exporting.value = false
  }
}

async function copyExportedPath() {
  if (!exported.value) return
  try {
    await navigator.clipboard?.writeText(exported.value)
    copiedPath.value = true
    store.toast(t('backup.pathCopied'), 'success')
    setTimeout(() => {
      copiedPath.value = false
    }, 1800)
  } catch {
    // Clipboard may be unavailable in restricted contexts; title tooltip still exposes the path.
  }
}

function pickFile() {
  localError.value = null
  fileInput.value?.click()
}

function onFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  // Let the same file be picked again after a cancelled confirmation.
  input.value = ''
  if (file) pending.value = { kind: 'local', name: file.name, file }
}

/** Save the account first so the test uses exactly what is on screen. */
async function saveAccount(): Promise<boolean> {
  try {
    const saved = await store.backend.setWebdav(form.value.url, form.value.username, form.value.password)
    // Any change makes a previous test result stale.
    available.value = saved.available
    return saved.available
  } catch (error) {
    testError.value = reason(error)
    available.value = false
    return false
  }
}

async function refreshList() {
  listing.value = true
  listError.value = null
  try {
    remote.value = await store.backend.listRemoteBackups()
    listed.value = true
  } catch (error) {
    listError.value = reason(error)
    remote.value = []
  } finally {
    listing.value = false
  }
}

async function onTest() {
  if (testing.value) return
  testing.value = true
  testError.value = null
  try {
    await saveAccount()
    const result = await store.backend.testWebdav()
    available.value = result.available
    testError.value = result.error
    if (result.available) {
      editingAccount.value = false
      showPassword.value = false
      await refreshList()
    } else {
      remote.value = []
    }
  } catch (error) {
    available.value = false
    testError.value = reason(error)
  } finally {
    testing.value = false
  }
}

async function onUpload() {
  if (uploading.value || !available.value) return
  uploading.value = true
  testError.value = null
  try {
    await saveAccount()
    const name = await store.backend.uploadBackup()
    uploaded.value = name
    await refreshList()
  } catch (error) {
    testError.value = reason(error)
  } finally {
    uploading.value = false
  }
}

async function onAccountChange() {
  testError.value = null
  await saveAccount()
  uploaded.value = null
  if (!available.value) {
    remote.value = []
    listed.value = false
  }
}

function askRestore(item: PendingRestore) {
  uploaded.value = null
  pending.value = item
}

async function confirmRestore() {
  const target = pending.value
  if (!target || restoring.value) return
  restoring.value = true
  try {
    if (target.kind === 'local') {
      let text: string
      try {
        text = await target.file.text()
      } catch (error) {
        pending.value = null
        localError.value = t('backup.readError', { reason: reason(error) })
        return
      }
      await store.restoreBackup(text)
    } else {
      await store.restoreRemoteBackup(target.name)
    }
    pending.value = null
    exported.value = null
  } finally {
    restoring.value = false
  }
}

function formatModified(value: string | null | undefined): string {
  if (!value) return ''
  const time = Date.parse(value)
  return Number.isNaN(time) ? value : formatRelative(time)
}

function formatExactTime(value: string | null | undefined): string {
  if (!value) return ''
  const time = Date.parse(value)
  if (Number.isNaN(time)) return ''
  const date = new Date(time)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function formatSize(size: number | null): string {
  if (size == null) return '—'
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  return `${(size / 1024 / 1024).toFixed(1)} MB`
}

function backupTitle(item: RemoteBackup): string {
  if (item.device && item.device.trim()) return item.device.trim()
  return item.name.replace(/^billow-backup-/, '').replace(/\.json$/i, '') || item.name
}
</script>

<template>
  <SettingsSection :title="t('backup.local.title')" data-testid="backup-settings">
    <SettingsRow :title="t('backup.export')" :description="t('backup.local.detail')" setting="backup-file">
      <button
        type="button"
        class="btn sm backup-row-btn"
        data-testid="backup-export"
        :disabled="exporting"
        @click="onExport"
      >
        <span v-if="exporting" class="spinner xs" aria-hidden="true" />
        <Icon v-else name="download" :size="15" />{{ exporting ? t('backup.exporting') : t('backup.exportShort') }}
      </button>
    </SettingsRow>
    <SettingsRow :title="t('backup.importTitle')" :description="t('backup.importDetail')">
      <button
        type="button"
        class="btn sm backup-row-btn"
        data-testid="backup-import"
        :disabled="restoring"
        @click="pickFile"
      >
        <Icon name="upload" :size="15" />{{ t('backup.importShort') }}
      </button>
    </SettingsRow>
    <div v-if="exported || localError" class="srow srow-info backup-feedback-row">
      <div v-if="exported" class="backup-banner ok small" data-testid="backup-exported">
        <Icon name="check" :size="14" />
        <span class="ellipsis" :title="exported">{{ t('backup.exported', { path: exported }) }}</span>
        <button
          type="button"
          class="icon-btn xs"
          :title="copiedPath ? t('backup.pathCopied') : t('backup.copyPath')"
          :aria-label="t('backup.copyPath')"
          data-testid="backup-copy-path"
          @click="copyExportedPath"
        >
          <Icon :name="copiedPath ? 'check' : 'copy'" :size="13" />
        </button>
      </div>
      <p v-if="localError" class="field-error small backup-note" role="alert" data-testid="backup-error">
        <Icon name="alert" :size="14" /><span>{{ localError }}</span>
      </p>
    </div>
    <template #footnote>
      <span class="backup-note" data-testid="backup-warning">
        <Icon name="shield" :size="13" /><span>{{ t('backup.warning') }}</span>
      </span>
    </template>
  </SettingsSection>
  <input
    ref="fileInput"
    class="sr-only"
    type="file"
    accept="application/json,.json"
    tabindex="-1"
    aria-hidden="true"
    data-testid="backup-file"
    @change="onFile"
  />

  <SettingsSection title="WebDAV" :description="t('backup.webdav.detail')" data-testid="backup-webdav">
    <template #action>
      <span
        class="tag backup-status"
        :class="available ? 'ok' : ''"
        aria-live="polite"
        data-testid="webdav-status"
      >{{ available ? t('backup.webdav.available') : t('backup.webdav.unavailable') }}</span>
    </template>

    <!-- Verified & collapsed: compact account summary + primary upload action above the fold. -->
    <div v-if="available && !editingAccount" class="srow backup-account-bar" data-setting="webdav" data-testid="webdav-summary">
      <span class="backup-row-icon accent" aria-hidden="true"><Icon name="globe" :size="15" /></span>
      <div class="srow-main">
        <span class="srow-title ellipsis" :title="form.url">{{ endpointLabel }}</span>
        <span v-if="form.username" class="srow-desc ellipsis">{{ form.username }}</span>
      </div>
      <div class="backup-summary-actions">
        <button
          type="button"
          class="btn sm"
          data-testid="webdav-edit"
          @click="editingAccount = true"
        >
          <Icon name="edit" :size="14" />{{ t('backup.webdav.edit') }}
        </button>
        <button
          type="button"
          class="btn sm primary"
          data-testid="webdav-upload"
          :disabled="uploading"
          @click="onUpload"
        >
          <span v-if="uploading" class="spinner xs" aria-hidden="true" />
          <Icon v-else name="upload" :size="15" />{{ uploading ? t('backup.webdav.uploading') : t('backup.webdav.upload') }}
        </button>
      </div>
    </div>

    <!-- Account form: open by default until verified, or when user chooses to edit. -->
    <form v-else class="srow srow-form backup-grid" data-setting="webdav" @submit.prevent="onTest">
      <label class="field backup-url">
        <span>{{ t('backup.webdav.url') }}</span>
        <input
          v-model.trim="form.url"
          class="input"
          type="url"
          inputmode="url"
          spellcheck="false"
          autocomplete="off"
          autocapitalize="off"
          :placeholder="t('backup.webdav.urlPlaceholder')"
          data-testid="webdav-url"
          @change="onAccountChange"
        />
      </label>
      <label class="field">
        <span>{{ t('backup.webdav.username') }}</span>
        <input
          v-model.trim="form.username"
          class="input"
          type="text"
          spellcheck="false"
          autocomplete="username"
          autocapitalize="off"
          data-testid="webdav-username"
          @change="onAccountChange"
        />
      </label>
      <label class="field">
        <span>{{ t('backup.webdav.password') }}</span>
        <div class="input-with-action">
          <input
            v-model="form.password"
            class="input"
            :type="showPassword ? 'text' : 'password'"
            autocomplete="current-password"
            data-testid="webdav-password"
            @change="onAccountChange"
          />
          <button
            type="button"
            class="icon-btn xs"
            :title="showPassword ? t('backup.webdav.hidePassword') : t('backup.webdav.showPassword')"
            :aria-label="showPassword ? t('backup.webdav.hidePassword') : t('backup.webdav.showPassword')"
            :aria-pressed="showPassword"
            data-testid="webdav-toggle-password"
            @click="showPassword = !showPassword"
          >
            <Icon :name="showPassword ? 'eye-off' : 'eye'" :size="15" />
          </button>
        </div>
      </label>
      <div class="backup-toolbar">
        <div class="grow min0" aria-live="polite">
          <p v-if="testError" class="field-error small" role="alert" data-testid="webdav-error">
            <Icon name="alert" :size="14" /><span>{{ testError }}</span>
          </p>
          <p v-else-if="uploaded" class="backup-note ok small" data-testid="webdav-uploaded">
            <Icon name="check" :size="14" /><span class="ellipsis">{{ t('backup.webdav.uploaded', { name: uploaded }) }}</span>
          </p>
          <p v-else-if="!available" class="muted small">{{ t('backup.webdav.needTest') }}</p>
        </div>
        <div class="backup-actions">
          <button
            v-if="available"
            type="button"
            class="btn ghost sm"
            data-testid="webdav-collapse"
            @click="editingAccount = false"
          >
            {{ t('backup.webdav.done') }}
          </button>
          <button
            type="button"
            class="btn sm"
            data-testid="webdav-test"
            :disabled="testing || !canTest"
            @click="onTest"
          >
            <span v-if="testing" class="spinner xs" aria-hidden="true" />
            {{ testing ? t('backup.webdav.testing') : t('backup.webdav.test') }}
          </button>
          <button
            type="button"
            class="btn sm"
            :class="{ primary: available }"
            data-testid="webdav-upload"
            :disabled="!available || uploading"
            @click="onUpload"
          >
            <span v-if="uploading" class="spinner xs" aria-hidden="true" />
            <Icon v-else name="upload" :size="15" />{{ uploading ? t('backup.webdav.uploading') : t('backup.webdav.upload') }}
          </button>
        </div>
      </div>
    </form>

    <!-- Inline status banner when summary bar is collapsed and user uploads or hits an error. -->
    <div v-if="available && !editingAccount && (testError || uploaded)" class="srow srow-info backup-feedback-row" aria-live="polite">
      <p v-if="testError" class="field-error small backup-note" role="alert" data-testid="webdav-error">
        <Icon name="alert" :size="14" /><span>{{ testError }}</span>
      </p>
      <div v-else-if="uploaded" class="backup-banner ok small" data-testid="webdav-uploaded">
        <Icon name="check" :size="14" />
        <span class="ellipsis" :title="uploaded">{{ t('backup.webdav.uploaded', { name: uploaded }) }}</span>
      </div>
    </div>

    <!-- Cloud backups only appear once the account works; restoring always asks first. -->
    <template v-if="available || listed">
      <div class="srow backup-cloud-head">
        <div class="srow-main">
          <span class="srow-title">
            {{ t('backup.webdav.list') }}
            <span v-if="listed && remote.length" class="backup-count">{{ remote.length }}</span>
          </span>
        </div>
        <button
          type="button"
          class="icon-btn sm"
          data-testid="webdav-refresh"
          :disabled="!available || listing"
          :title="t('backup.webdav.refresh')"
          :aria-label="t('backup.webdav.refresh')"
          @click="refreshList"
        >
          <Icon name="refresh" :size="14" :class="{ spin: listing }" />
        </button>
      </div>
      <p v-if="listError" class="srow field-error small" role="alert" data-testid="webdav-list-error">
        <Icon name="alert" :size="14" /><span>{{ listError }}</span>
      </p>
      <div v-if="listing && !remote.length" class="srow muted small backup-loading" data-testid="webdav-loading">
        <span class="spinner xs" aria-hidden="true" />
        <span>{{ t('backup.webdav.loading') }}</span>
      </div>
      <ul v-else-if="listed" class="backup-list" data-testid="webdav-list">
        <li v-if="!remote.length" class="srow backup-empty">
          <div class="srow-main">
            <span class="muted small">{{ t('backup.webdav.empty') }}</span>
            <span class="backup-empty-hint">{{ t('backup.webdav.emptyHint') }}</span>
          </div>
        </li>
        <li v-for="(item, index) in remote" :key="item.name" class="srow backup-row" data-testid="webdav-item">
          <span class="backup-row-icon" :class="{ latest: index === 0 }" aria-hidden="true">
            <Icon name="file" :size="15" />
          </span>
          <div class="srow-main">
            <span class="srow-title backup-item-title" :title="item.name">
              <span class="ellipsis">{{ backupTitle(item) }}</span>
              <span v-if="index === 0" class="srow-badge">{{ t('backup.webdav.latest') }}</span>
            </span>
            <span class="srow-desc backup-item-meta" :title="item.name">
              <template v-if="item.modified">
                <span>{{ formatModified(item.modified) }}</span>
                <span v-if="!compact && formatExactTime(item.modified)" class="backup-item-exact"> · {{ formatExactTime(item.modified) }}</span>
              </template>
              <template v-if="item.size != null">
                <template v-if="item.modified"> · </template>{{ formatSize(item.size) }}
              </template>
            </span>
          </div>
          <button
            type="button"
            class="btn sm backup-row-btn"
            data-testid="webdav-restore"
            @click="askRestore({ kind: 'remote', name: item.name, device: item.device, modified: item.modified, size: item.size })"
          >
            {{ t('backup.webdav.restore') }}
          </button>
        </li>
      </ul>
    </template>
  </SettingsSection>

  <Modal v-if="pending" :title="t('backup.confirm.title')" :before-close="() => !restoring" @close="pending = null">
    <div class="backup-confirm">
      <p>{{ t('backup.confirm.body') }}</p>
      <div class="backup-confirm-card" data-testid="backup-confirm-file">
        <div class="backup-confirm-head small">
          <span class="srow-badge">{{ pending.kind === 'remote' ? t('backup.confirm.sourceRemote') : t('backup.confirm.sourceLocal') }}</span>
          <span v-if="pending.kind === 'remote' && pending.device" class="backup-confirm-device ellipsis">{{ pending.device }}</span>
          <span v-if="pending.kind === 'remote' && pending.modified" class="muted">{{ formatModified(pending.modified) }}</span>
          <span v-if="pending.kind === 'remote' && pending.size != null" class="muted">{{ formatSize(pending.size) }}</span>
        </div>
        <p class="backup-confirm-file small">
          <Icon name="file" :size="14" /><span class="ellipsis mono" :title="pending.name">{{ t('backup.confirm.file', { name: pending.name }) }}</span>
        </p>
      </div>
      <p class="backup-note warn small" data-testid="backup-confirm-warning">
        <Icon name="alert" :size="14" /><span>{{ t('backup.confirm.sensitive') }}</span>
      </p>
    </div>
    <template #footer>
      <button type="button" class="btn ghost" data-testid="backup-confirm-cancel" :disabled="restoring" @click="pending = null">
        {{ t('backup.confirm.cancel') }}
      </button>
      <button
        type="button"
        class="btn danger"
        data-testid="backup-confirm-restore"
        :disabled="restoring"
        @click="confirmRestore"
      >
        <span v-if="restoring" class="spinner xs" aria-hidden="true" />
        {{ restoring ? t('backup.importing') : t('backup.confirm.restore') }}
      </button>
    </template>
  </Modal>
</template>

<style scoped>
.backup-row-btn {
  min-width: 72px;
  justify-content: center;
}
.backup-status {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  align-self: center;
  flex: none;
}
.backup-account-bar {
  flex-wrap: wrap;
  gap: 12px;
  min-height: 62px;
}
.backup-summary-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: none;
  margin-left: auto;
}
.backup-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: flex-end;
  margin-left: auto;
}
.backup-grid {
  display: grid;
  gap: 12px;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  align-items: start;
}
.backup-url,
.backup-toolbar {
  grid-column: 1 / -1;
}
.backup-feedback-row {
  padding-top: 8px;
  padding-bottom: 10px;
}
.backup-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  min-width: 0;
  padding: 7px 10px;
  border-radius: var(--radius-control);
}
.backup-banner > svg {
  flex: none;
}
.backup-banner > span {
  flex: 1;
  min-width: 0;
}
.backup-banner.ok {
  background: var(--good-soft);
  color: var(--good-ink);
}
.backup-note {
  display: inline-flex;
  gap: 6px;
  align-items: flex-start;
  margin: 0;
}
.backup-note > svg {
  flex: none;
  margin-top: 2px;
}
.backup-note > span {
  flex: 1;
  min-width: 0;
}
.backup-note.ok {
  color: var(--good-ink);
}
.backup-note.warn {
  display: flex;
  padding: 9px 11px;
  border-radius: var(--radius-control);
  background: var(--fair-soft);
  color: var(--fair-ink);
}
.backup-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  padding-top: 2px;
}
.backup-cloud-head {
  min-height: 46px;
  padding-top: 8px;
  padding-bottom: 8px;
  background: var(--surface-2);
}
.backup-count {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 20px;
  height: 18px;
  padding: 0 6px;
  border-radius: var(--radius-pill);
  background: var(--sunken);
  color: var(--text-2);
  font-size: var(--text-xs);
  font-weight: 620;
  font-variant-numeric: tabular-nums;
}
.backup-loading {
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 52px;
}
.backup-empty {
  min-height: 56px;
}
.backup-empty-hint {
  font-size: var(--text-xs);
  color: var(--text-3);
}
.backup-list {
  list-style: none;
  margin: 0;
  padding: 0;
}
.backup-row {
  transition: background var(--dur-fast) var(--ease);
}
.backup-row:hover {
  background: var(--hover);
}
.backup-row-icon {
  display: grid;
  place-items: center;
  width: 34px;
  height: 34px;
  border-radius: 10px;
  background: var(--sunken);
  color: var(--text-2);
  flex: none;
}
.backup-row-icon.accent,
.backup-row-icon.latest {
  background: var(--accent-soft);
  color: var(--accent-ink);
}
.backup-item-title {
  flex-wrap: nowrap;
  min-width: 0;
}
.backup-item-title > .ellipsis {
  min-width: 0;
}
.backup-item-meta {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0 2px;
  font-variant-numeric: tabular-nums;
}
.backup-confirm {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.backup-confirm-card {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 10px 12px;
  border-radius: var(--radius-control);
  border: 1px solid var(--border);
  background: var(--sunken);
}
.backup-confirm-head {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px 8px;
}
.backup-confirm-device {
  font-weight: 620;
  color: var(--text);
}
.backup-confirm-file {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 0;
  color: var(--text-2);
}
.backup-confirm-file > svg {
  flex: none;
}
.backup-confirm-file > span {
  flex: 1;
  min-width: 0;
}
@media (max-width: 560px) {
  .backup-grid {
    grid-template-columns: minmax(0, 1fr);
  }
  .backup-summary-actions {
    width: 100%;
    justify-content: flex-end;
    padding-top: 2px;
  }
  .backup-summary-actions > .btn {
    flex: 1;
    justify-content: center;
  }
  .backup-actions {
    width: 100%;
  }
  .backup-actions > .btn {
    flex: 1;
    justify-content: center;
  }
  .backup-item-exact {
    display: none;
  }
}
</style>
