<script setup lang="ts">
import { onMounted, ref } from 'vue'
import Icon from './Icon.vue'
import Modal from './Modal.vue'
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
  } catch (error) {
    testError.value = reason(error)
  }
})

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

function formatSize(size: number | null): string {
  if (size == null) return '—'
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  return `${(size / 1024 / 1024).toFixed(1)} MB`
}
</script>

<template>
  <section class="card" data-testid="backup-settings">
    <header v-if="!compact" class="card-head">
      <h2>{{ t('settings.backup.title') }}</h2>
      <span class="muted small">{{ t('settings.backup.detail') }}</span>
    </header>
    <div class="setting-row">
      <div class="grow">
        <strong>{{ t('backup.local.title') }}</strong>
        <p class="muted small">{{ t('backup.local.detail') }}</p>
      </div>
      <div class="backup-actions">
        <button
          type="button"
          class="btn sm"
          data-testid="backup-export"
          :disabled="exporting"
          @click="onExport"
        >
          <Icon name="download" :size="15" />{{ exporting ? t('backup.exporting') : t('backup.export') }}
        </button>
        <button type="button" class="btn ghost sm" data-testid="backup-import" @click="pickFile">
          <Icon name="upload" :size="15" />{{ t('backup.import') }}
        </button>
      </div>
    </div>
    <p v-if="exported" class="muted small backup-note ellipsis" data-testid="backup-exported">
      {{ t('backup.exported', { path: exported }) }}
    </p>
    <p v-if="localError" class="field-error small backup-note" role="alert" data-testid="backup-error">
      <Icon name="alert" :size="14" />{{ localError }}
    </p>
    <p class="backup-warning small" data-testid="backup-warning">
      <Icon name="alert" :size="14" /><span>{{ t('backup.warning') }}</span>
    </p>
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
  </section>

  <section class="card" data-testid="backup-webdav">
    <header class="card-head">
      <h2>{{ t('backup.webdav.title') }}</h2>
      <span class="muted small">{{ t('backup.webdav.detail') }}</span>
    </header>
    <div class="backup-grid">
      <label class="field">
        <span>{{ t('backup.webdav.url') }}</span>
        <input
          v-model.trim="form.url"
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
          type="password"
          autocomplete="current-password"
          data-testid="webdav-password"
          @change="onAccountChange"
        />
      </label>
    </div>

    <div class="setting-row">
      <div class="grow min0" aria-live="polite">
        <strong :class="available ? 'backup-ok' : 'muted'">
          {{ available ? t('backup.webdav.available') : t('backup.webdav.unavailable') }}
        </strong>
        <p v-if="testError" class="field-error small" role="alert" data-testid="webdav-error">
          <Icon name="alert" :size="14" />{{ testError }}
        </p>
      </div>
      <button
        type="button"
        class="btn sm"
        data-testid="webdav-test"
        :disabled="testing"
        @click="onTest"
      >
        <Icon name="refresh" :size="15" :class="{ spin: testing }" />{{ testing ? t('backup.webdav.testing') : t('backup.webdav.test') }}
      </button>
    </div>

    <div class="setting-row">
      <div class="grow">
        <p class="muted small">{{ t('backup.webdav.needTest') }}</p>
        <p v-if="uploaded" class="small backup-ok" data-testid="webdav-uploaded">
          {{ t('backup.webdav.uploaded', { name: uploaded }) }}
        </p>
      </div>
      <div class="backup-actions">
        <button
          type="button"
          class="btn ghost sm"
          data-testid="webdav-upload"
          :disabled="!available || uploading"
          @click="onUpload"
        >
          <Icon name="upload" :size="15" />{{ uploading ? t('backup.webdav.uploading') : t('backup.webdav.upload') }}
        </button>
        <button
          type="button"
          class="btn ghost sm"
          data-testid="webdav-refresh"
          :disabled="!available || listing"
          @click="refreshList"
        >
          <Icon name="refresh" :size="15" :class="{ spin: listing }" />{{ t('backup.webdav.refresh') }}
        </button>
      </div>
    </div>

    <p v-if="listError" class="field-error small backup-note" role="alert" data-testid="webdav-list-error">
      <Icon name="alert" :size="14" />{{ listError }}
    </p>
    <p v-if="listing" class="muted small backup-note" data-testid="webdav-loading">
      {{ t('backup.webdav.loading') }}
    </p>
    <ul v-else-if="listed" class="backup-list" data-testid="webdav-list">
      <li v-if="!remote.length" class="backup-empty muted small">{{ t('backup.webdav.empty') }}</li>
      <li v-for="item in remote" :key="item.name" class="backup-row" data-testid="webdav-item">
        <div class="grow min0">
          <strong class="ellipsis">{{ item.name }}</strong>
          <p class="muted small ellipsis">
            {{ t('backup.webdav.device') }} {{ item.device || '—' }}<template v-if="item.modified"> · {{ item.modified }}</template>
            <template v-if="item.size != null"> · {{ formatSize(item.size) }}</template>
          </p>
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
  </section>

  <Modal v-if="pending" :title="t('backup.confirm.title')" @close="pending = null">
    <p class="small">{{ t('backup.confirm.body') }}</p>
    <p class="small mono ellipsis" data-testid="backup-confirm-file">
      {{ t('backup.confirm.file', { name: pending.name }) }}
    </p>
    <p class="backup-warning small" data-testid="backup-confirm-warning">
      <Icon name="alert" :size="14" /><span>{{ t('backup.confirm.sensitive') }}</span>
    </p>
    <template #footer>
      <button type="button" class="btn ghost" data-testid="backup-confirm-cancel" @click="pending = null">
        {{ t('backup.confirm.cancel') }}
      </button>
      <button
        type="button"
        class="btn danger"
        data-testid="backup-confirm-restore"
        :disabled="restoring"
        @click="confirmRestore"
      >
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
}
.backup-grid {
  display: grid;
  gap: 12px;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  padding: 0 20px 8px;
}
.backup-note {
  padding: 0 20px 8px;
}
.backup-warning {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  padding: 0 20px 16px;
  margin: 0;
  color: var(--poor-ink);
}
.backup-warning span {
  flex: 1;
}
.backup-ok {
  color: var(--good-ink);
}
.backup-list {
  list-style: none;
  margin: 0;
  padding: 0 20px 8px;
}
.backup-empty {
  padding: 4px 0 12px;
}
.backup-row {
  display: flex;
  gap: 12px;
  align-items: center;
  padding: 10px 0;
  border-top: 1px solid var(--border);
}
.backup-row:first-of-type {
  border-top: none;
}
</style>
