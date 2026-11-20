<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import Icon from '../../components/Icon.vue'
import Modal from '../../components/Modal.vue'
import Segmented from '../../components/Segmented.vue'
import Toggle from '../../components/Toggle.vue'
import UwpLoopbackDialog from '../../components/UwpLoopbackDialog.vue'
import EditorDialog from '../../components/settings/EditorDialog.vue'
import SettingsRow from '../../components/settings/SettingsRow.vue'
import SettingsSection from '../../components/settings/SettingsSection.vue'
import { bypassOverride } from '../../lib/bypass'
import { tr } from '../../lib/i18n'
import { useSettingsSave } from '../../lib/settings/save'
import { useStore } from '../../lib/store'
import {
  DEFAULT_PAC_SCRIPT,
  DEFAULT_PROXY_BYPASS,
  defaultSystemProxy,
  type SystemProxyMode,
  type SystemProxySettings,
} from '../../lib/types'

defineProps<{ compact?: boolean }>()
const store = useStore()
const { current, save } = useSettingsSave()
const snap = computed(() => store.snapshot.value)
const proxy = computed(() => current.value.system_proxy)
const busy = computed(() => Boolean(store.busy.settings))

const isWindows = computed(
  () => store.app.value?.platform === 'windows' || (typeof navigator !== 'undefined' && /Windows/i.test(navigator.userAgent)),
)

const PROXY_MODES = computed<{ id: SystemProxyMode; label: string }[]>(() => [
  { id: 'manual', label: tr('手动') },
  { id: 'pac', label: 'PAC' },
])

function saveProxy(patch: Partial<SystemProxySettings>) {
  return save({ system_proxy: { ...proxy.value, ...patch } })
}

const statusText = computed(() => {
  if (!snap.value.system_proxy) return tr('浏览器和大多数应用会读取这项系统设置')
  return snap.value.mixed_port
    ? tr('已指向 {0}', { 0: `${proxy.value.host || '127.0.0.1'}:${snap.value.mixed_port}` })
    : tr('已开启，连接后生效')
})

// ── 代理主机: a single field, saved when it loses focus or on Enter.
const host = ref(proxy.value.host)
const hostFocused = ref(false)
watch(() => proxy.value.host, (value) => {
  if (!hostFocused.value) host.value = value
})
function commitHost() {
  const value = host.value.trim()
  host.value = value
  if (value !== proxy.value.host) void saveProxy({ host: value })
}

// ── PAC script editor
const pacOpen = ref(false)
const pacDraft = ref('')
function openPac() {
  pacDraft.value = proxy.value.pac_script || DEFAULT_PAC_SCRIPT
  pacOpen.value = true
}
async function savePac() {
  await saveProxy({ pac_script: pacDraft.value.trim() || DEFAULT_PAC_SCRIPT })
  pacOpen.value = false
}

// ── Bypass list editor: a list with quick add, or the whole thing as text.
const bypassOpen = ref(false)
const bypassItems = ref<string[]>([])
const bypassBatchMode = ref(false)
const bypassBatchText = ref('')
const newBypassItem = ref('')

function parseBypassText(text: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of text.split(/[\r\n;,]+/)) {
    const item = raw.trim()
    if (item && !seen.has(item)) {
      seen.add(item)
      out.push(item)
    }
  }
  return out
}

function openBypass() {
  bypassItems.value = [...proxy.value.bypass]
  bypassBatchText.value = proxy.value.bypass.join('\n')
  bypassBatchMode.value = false
  newBypassItem.value = ''
  bypassOpen.value = true
}

const bypassDraft = computed(() => {
  const base = bypassBatchMode.value ? parseBypassText(bypassBatchText.value) : [...bypassItems.value]
  for (const item of parseBypassText(newBypassItem.value)) if (!base.includes(item)) base.push(item)
  return base
})
const bypassDirty = computed(() => JSON.stringify(bypassDraft.value) !== JSON.stringify(proxy.value.bypass))

watch(bypassBatchText, (text) => {
  if (bypassBatchMode.value) bypassItems.value = parseBypassText(text)
})

function toggleBypassBatch() {
  if (bypassBatchMode.value) {
    bypassItems.value = parseBypassText(bypassBatchText.value)
    bypassBatchMode.value = false
  } else {
    bypassBatchText.value = bypassItems.value.join('\n')
    bypassBatchMode.value = true
  }
}

function addBypassItem() {
  const entries = parseBypassText(newBypassItem.value)
  if (!entries.length) return
  for (const item of entries) if (!bypassItems.value.includes(item)) bypassItems.value.push(item)
  bypassBatchText.value = bypassItems.value.join('\n')
  newBypassItem.value = ''
}

function removeBypassItem(index: number) {
  bypassItems.value.splice(index, 1)
  bypassBatchText.value = bypassItems.value.join('\n')
}

function clearBypass() {
  bypassItems.value = []
  bypassBatchText.value = ''
  newBypassItem.value = ''
}

function addDefaultBypass() {
  const list = bypassBatchMode.value ? parseBypassText(bypassBatchText.value) : [...bypassItems.value]
  let added = 0
  for (const item of DEFAULT_PROXY_BYPASS) {
    if (!list.includes(item)) {
      list.push(item)
      added += 1
    }
  }
  bypassItems.value = list
  bypassBatchText.value = list.join('\n')
  if (!added) store.toast(tr('默认代理绕过规则已全部包含'))
}

async function saveBypass() {
  const list = bypassDraft.value
  await saveProxy({ bypass: list })
  bypassOpen.value = false
}

/** TUN sends every app to the kernel; bypass entries need DIRECT rules there. */
function bypassToOverride() {
  const append = bypassOverride(bypassDraft.value)
  const id = snap.value.active_id
  if (!append) {
    store.toast(tr('列表中没有可以转换的地址'), 'info')
    return
  }
  if (!id) {
    store.toast(tr('请先启用一个配置'), 'info')
    return
  }
  bypassOpen.value = false
  store.overrideRequest.value = { id, append }
  store.go('profiles')
}

// ── Restore defaults (host, mode, PAC and bypass) after a confirmation.
const confirmReset = ref(false)
async function resetProxy() {
  confirmReset.value = false
  host.value = defaultSystemProxy().host
  await save({ system_proxy: defaultSystemProxy() }, tr('已恢复默认设置'))
}

const uwpOpen = ref(false)
</script>

<template>
  <div class="pane-root" data-testid="proxy-settings">
    <SettingsSection>
      <SettingsRow :title="tr('启用系统代理')" setting="system-proxy" class="srow-master" :class="{ on: snap.system_proxy }">
        <template #description>{{ statusText }}</template>
        <Toggle :model-value="snap.system_proxy" :busy="store.busy.proxy" :label="tr('启用系统代理')" @update:model-value="store.setSystemProxy" />
      </SettingsRow>
    </SettingsSection>

    <SettingsSection :title="tr('代理方式')">
      <SettingsRow
        :title="tr('代理模式')"
        :description="proxy.mode === 'pac' ? tr('PAC：由脚本按网址决定是否走代理') : tr('手动：HTTP / HTTPS / SOCKS 都指向混合端口')"
        setting="proxy-mode"
        :stacked="compact"
      >
        <Segmented
          :model-value="proxy.mode"
          :options="PROXY_MODES"
          size="sm"
          :label="tr('代理模式')"
          :disabled="busy"
          data-testid="proxy-mode"
          @update:model-value="(mode) => saveProxy({ mode })"
        />
      </SettingsRow>
      <SettingsRow
        v-if="proxy.mode === 'pac'"
        nav
        nested
        :title="tr('PAC 脚本')"
        :description="tr('决定哪些网址走代理的 JavaScript 脚本')"
        :value="proxy.pac_script && proxy.pac_script !== DEFAULT_PAC_SCRIPT ? tr('已自定义') : tr('默认')"
        setting="pac-script"
        data-testid="open-pac"
        @open="openPac"
      />
      <SettingsRow :title="tr('代理主机')" :description="tr('一般无需修改；留空使用 127.0.0.1')" setting="proxy-host">
        <input
          v-model="host"
          class="input sm mono srow-input"
          placeholder="127.0.0.1"
          spellcheck="false"
          :aria-label="tr('代理主机')"
          data-testid="proxy-host-input"
          @focus="hostFocused = true"
          @blur="hostFocused = false; commitHost()"
          @keydown.enter.prevent="($event.target as HTMLInputElement).blur()"
        />
      </SettingsRow>
    </SettingsSection>

    <SettingsSection :title="tr('例外')">
      <SettingsRow
        nav
        :title="tr('代理绕过列表')"
        :description="tr('访问这些地址时不经过代理，例如局域网与本机')"
        :value="tr('{0} 条', { 0: proxy.bypass.length })"
        setting="proxy-bypass"
        data-testid="open-bypass"
        @open="openBypass"
      />
      <SettingsRow
        v-if="isWindows"
        nav
        :title="tr('UWP 工具')"
        :description="tr('解除 Windows 商店（UWP）应用的本地回环代理限制')"
        setting="uwp"
        data-testid="open-uwp-tool"
        @open="uwpOpen = true"
      />
    </SettingsSection>

    <div class="settings-pane-foot">
      <button type="button" class="btn ghost sm" data-testid="reset-proxy" @click="confirmReset = true">
        <Icon name="refresh" :size="14" />{{ tr('恢复默认设置') }}
      </button>
    </div>

    <EditorDialog
      v-if="pacOpen"
      :title="tr('PAC 脚本')"
      wide
      :dirty="pacDraft.trim() !== (proxy.pac_script || DEFAULT_PAC_SCRIPT).trim()"
      :saving="busy"
      save-testid="save-pac"
      @save="savePac"
      @close="pacOpen = false"
    >
      <p class="muted small">{{ tr('支持') }} <code>%proxy-host%</code> {{ tr('与') }} <code>%mixed-port%</code> {{ tr('占位符') }}</p>
      <textarea
        v-model="pacDraft"
        class="input list-input mono editor-area"
        rows="14"
        spellcheck="false"
        :aria-label="tr('PAC 脚本')"
        data-testid="pac-script-input"
      />
      <template #footer-start>
        <button type="button" class="btn ghost sm" @click="pacDraft = DEFAULT_PAC_SCRIPT">{{ tr('恢复默认脚本') }}</button>
      </template>
    </EditorDialog>

    <EditorDialog
      v-if="bypassOpen"
      :title="tr('代理绕过列表')"
      :subtitle="tr('遵循系统代理的应用访问这些地址时直接连接，不经过内核')"
      :dirty="bypassDirty"
      :saving="busy"
      save-testid="save-bypass"
      @save="saveBypass"
      @close="bypassOpen = false"
    >
      <div class="bypass-editor" data-testid="proxy-bypass-card">
        <div v-if="snap.tun || snap.tun_wanted" class="hint-box small bypass-tun-note" data-testid="bypass-tun-note">
          <Icon name="info" :size="15" />
          <p class="grow">{{ tr('TUN 已开启：所有应用的流量都会进入内核，命令行工具等不读系统代理的程序不受绕过列表影响。需要直连请在当前配置的覆写里添加 DIRECT 规则。') }}</p>
          <button type="button" class="btn sm" data-testid="bypass-to-override" @click="bypassToOverride">{{ tr('生成直连规则') }}</button>
        </div>
        <div class="bypass-toolbar">
          <span class="muted small">{{ tr('{0} 条', { 0: bypassDraft.length }) }}</span>
          <span class="grow" />
          <button type="button" class="btn ghost sm" data-testid="add-default-bypass" @click="addDefaultBypass">
            <Icon name="plus" :size="14" />{{ tr('添加默认项') }}
          </button>
          <button
            v-if="bypassItems.length && !bypassBatchMode"
            type="button"
            class="btn ghost sm danger-text"
            data-testid="clear-bypass"
            @click="clearBypass"
          >{{ tr('清空') }}</button>
          <button type="button" class="btn ghost sm" data-testid="toggle-bypass-batch" @click="toggleBypassBatch">
            {{ bypassBatchMode ? tr('列表视图') : tr('批量编辑') }}
          </button>
        </div>
        <template v-if="!bypassBatchMode">
          <div class="bypass-add-row">
            <input
              v-model="newBypassItem"
              class="input sm mono grow"
              :placeholder="tr('域名、IP 或网段，如 *.corp.local 或 10.*')"
              :aria-label="tr('新增代理绕过地址')"
              data-testid="bypass-add-input"
              @keydown.enter.prevent="addBypassItem"
            />
            <button type="button" class="btn sm" :disabled="!newBypassItem.trim()" data-testid="bypass-add-btn" @click="addBypassItem">
              <Icon name="plus" :size="14" />{{ tr('添加') }}
            </button>
          </div>
          <ul v-if="bypassItems.length" class="bypass-list" data-testid="bypass-list">
            <li v-for="(item, index) in bypassItems" :key="`${item}-${index}`" class="bypass-item">
              <span class="mono small ellipsis grow" :title="item">{{ item }}</span>
              <button
                type="button"
                class="icon-btn sm"
                :title="tr('删除 {0}', { 0: item })"
                :aria-label="tr('删除 {0}', { 0: item })"
                @click="removeBypassItem(index)"
              >
                <Icon name="x" :size="14" />
              </button>
            </li>
          </ul>
          <p v-else class="muted small empty-hint">{{ tr('列表是空的。点“添加默认项”可填入局域网与本机地址。') }}</p>
        </template>
        <template v-else>
          <p class="muted small">{{ tr('每行一条，也支持分号或逗号分隔') }}</p>
          <textarea
            v-model="bypassBatchText"
            class="input list-input mono editor-area"
            rows="12"
            spellcheck="false"
            :aria-label="tr('代理绕过列表批量编辑')"
            data-testid="bypass-batch-textarea"
          />
        </template>
      </div>
    </EditorDialog>

    <Modal v-if="confirmReset" :title="tr('恢复系统代理默认设置')" @close="confirmReset = false">
      <p class="small">{{ tr('代理主机、代理模式、PAC 脚本和绕过列表都会恢复为默认值。系统代理的开关状态不变。') }}</p>
      <template #footer>
        <button type="button" class="btn ghost" @click="confirmReset = false">{{ tr('取消') }}</button>
        <button type="button" class="btn primary" data-testid="confirm-reset-proxy" @click="resetProxy">{{ tr('恢复默认') }}</button>
      </template>
    </Modal>
    <UwpLoopbackDialog v-if="uwpOpen" @close="uwpOpen = false" />
  </div>
</template>
