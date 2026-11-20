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
const localError = ref<string | null>(null)

type PendingRestore = { kind: 'local'; name: string; text: string } | { kind: 'remote'; name: string }
const pending = ref<PendingRestore | null>(null)
const restoring = ref(false)

const form = ref<WebdavSettings>({ url: '', username: '', password: '', available: false })
const available = ref(false)
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
    // A verified account shows its cloud backups right away instead of behind another click.
    if (info.available) await refreshList()
  } catch (error) {
    testError.value = reason(error)
  }
})

const canTest = computed(() => Boolean(form.value.url.trim()))

async function onExport() {
  if (exporting.value) return
  exporting.value = true
  localError.value = null
  try {
    const path = await store.exportBackup()
    if (path) exported.value = path
  } finally {
    exporting.value = false
  }
}

function pickFile() {
  localError.value = null
  fileInput.value?.click()
}

async function onFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  // Let the same file be picked again after a cancelled confirmation.
  input.value = ''
  if (!file) return
  try {
    const text = await file.text()
    pending.value = { kind: 'local', name: file.name, text }
  } catch (error) {
    localError.value = t('backup.readError', { reason: reason(error) })
  }
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
    if (result.available) await refreshList()
    else remote.value = []
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
    if (target.kind === 'local') await store.restoreBackup(target.text)
    else await store.restoreRemoteBackup(target.name)
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

function formatSize(size: number | null): string {
  if (size == null) return '—'
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  return `${(size / 1024 / 1024).toFixed(1)} MB`
}
</script>

<template>
  <SettingsSection :title="t('backup.local.title')" data-testid="backup-settings">
    <SettingsRow :title="t('backup.export')" :description="t('backup.local.detail')" setting="backup-file">
      <button
        type="button"
        class="btn sm"
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
        class="btn sm"
        data-testid="backup-import"
        :disabled="restoring"
        @click="pickFile"
      >
        <Icon name="upload" :size="15" />{{ t('backup.importShort') }}
      </button>
    </SettingsRow>
    <div v-if="exported || localError" class="srow srow-info">
      <p v-if="exported" class="backup-note ok small" data-testid="backup-exported">
        <Icon name="check" :size="14" /><span class="ellipsis" :title="exported">{{ t('backup.exported', { path: exported }) }}</span>
      </p>
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
        class="tag"
        :class="available ? 'ok' : ''"
        aria-live="polite"
        data-testid="webdav-status"
      >{{ available ? t('backup.webdav.available') : t('backup.webdav.unavailable') }}</span>
    </template>
    <form class="srow srow-form backup-grid" data-setting="webdav" @submit.prevent="onTest">
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
        <input
          v-model="form.password"
          class="input"
          type="password"
          autocomplete="current-password"
          data-testid="webdav-password"
          @change="onAccountChange"
        />
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
            type="button"
            class="btn ghost sm"
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

    <!-- Cloud backups only appear once the account works; restoring always asks first. -->
    <template v-if="available || listed">
      <div class="srow backup-cloud-head">
        <div class="srow-main">
          <span class="srow-title">
            {{ t('backup.webdav.list') }}
            <span v-if="listed && remote.length" class="muted">{{ remote.length }}</span>
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
      <p v-if="listing && !remote.length" class="srow muted small" data-testid="webdav-loading">
        {{ t('backup.webdav.loading') }}
      </p>
      <ul v-else-if="listed" class="backup-list" data-testid="webdav-list">
        <li v-if="!remote.length" class="srow muted small">{{ t('backup.webdav.empty') }}</li>
        <li v-for="item in remote" :key="item.name" class="srow backup-row" data-testid="webdav-item">
          <span class="backup-row-icon" aria-hidden="true"><Icon name="file" :size="15" /></span>
          <div class="srow-main">
            <span class="srow-title ellipsis" :title="item.name">{{ item.name }}</span>
            <span class="srow-desc ellipsis">
              {{ item.device || '—' }}<template v-if="item.modified"> · {{ formatModified(item.modified) }}</template>
              <template v-if="item.size != null"> · {{ formatSize(item.size) }}</template>
            </span>
          </div>
          <button
            type="button"
            class="btn ghost sm"
            data-testid="webdav-restore"
            @click="askRestore({ kind: 'remote', name: item.name })"
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
      <p class="backup-confirm-file small" data-testid="backup-confirm-file">
        <Icon name="file" :size="14" /><span class="ellipsis mono">{{ t('backup.confirm.file', { name: pending.name }) }}</span>
      </p>
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
  padding: 8px 10px;
  border-radius: var(--radius-control);
  background: var(--fair-soft);
  color: var(--fair-ink);
}
.backup-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}
.backup-cloud-head .srow-title .muted {
  margin-left: 4px;
  font-weight: 500;
}
.backup-list {
  list-style: none;
  margin: 0;
  padding: 0;
}
.backup-row-icon {
  display: grid;
  place-items: center;
  width: 30px;
  height: 30px;
  border-radius: 8px;
  background: var(--sunken);
  color: var(--text-2);
  flex: none;
}
.backup-confirm {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.backup-confirm-file {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 10px;
  border-radius: var(--radius-control);
  background: var(--sunken);
  color: var(--text-2);
}
.backup-confirm-file > span {
  flex: 1;
  min-width: 0;
}
@media (max-width: 560px) {
  .backup-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
