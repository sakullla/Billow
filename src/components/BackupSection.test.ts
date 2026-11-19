import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h, provide } from 'vue'
import { createDemoBackend } from '../lib/demo'
import { createStore, STORE } from '../lib/store'
import BackupSection from './BackupSection.vue'

const cleanups: (() => void)[] = []
afterEach(() => {
  cleanups.splice(0).forEach((stop) => stop())
  document.body.innerHTML = ''
})

async function setup() {
  const backend = createDemoBackend()
  const store = createStore(backend)
  const Harness = defineComponent({
    setup() {
      provide(STORE, store)
      return () => h(BackupSection)
    },
  })
  const wrapper = mount(Harness, { attachTo: document.body })
  await flushPromises()
  cleanups.push(() => {
    wrapper.unmount()
    store.stop()
  })
  return { backend, store }
}

function find<T extends HTMLElement = HTMLElement>(selector: string): T {
  const element = document.querySelector<T>(selector)
  if (!element) throw new Error(`missing ${selector}`)
  return element
}

async function type(testid: string, value: string) {
  const input = find<HTMLInputElement>(`[data-testid="${testid}"]`)
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  input.dispatchEvent(new Event('change', { bubbles: true }))
  await flushPromises()
}

async function click(testid: string) {
  find(`[data-testid="${testid}"]`).click()
  await flushPromises()
}

/** The file picker cannot be driven, so hand the change handler a readable file. */
async function chooseFile(text: string, name = 'billow-backup-test.json') {
  const input = find<HTMLInputElement>('[data-testid="backup-file"]')
  Object.defineProperty(input, 'files', {
    configurable: true,
    value: [{ name, text: async () => text }] as unknown as FileList,
  })
  input.dispatchEvent(new Event('change', { bubbles: true }))
  await flushPromises()
}

interface BackupShape {
  names?: string[]
  version?: number
  activeId?: string | null
}

function backupText(shape: BackupShape = {}): string {
  const names = shape.names ?? ['备份 A', '备份 B']
  return JSON.stringify({
    format: 'billow-backup',
    version: shape.version ?? 1,
    app_version: '0.2.0',
    platform: 'desktop',
    device: 'test-pc',
    created_ms: 1_700_000_000_000,
    profiles: {
      next_id: names.length + 1,
      active_id: shape.activeId === undefined ? 'p1' : shape.activeId,
      profiles: names.map((name, index) => ({
        id: `p${index + 1}`,
        name,
        kind: 'local',
        source: '',
        user_agent: '',
        content: '',
        override_text: '',
      })),
      settings: {},
      tun_wanted: false,
      excluded_packages: [],
      included_packages: [],
      app_mode: 'exclude',
      chosen_mode: 'rule',
    },
    shell: { theme: 'dark', close_to_tray: true, silent_start: false, language: 'zh-CN' },
  })
}

describe('BackupSection', () => {
  it('exports a backup and warns that the file carries sensitive data', async () => {
    await setup()
    await click('backup-export')
    await vi.waitFor(() => {
      expect(find('[data-testid="backup-exported"]').textContent).toContain('billow-backup-')
    })
    expect(find('[data-testid="backup-exported"]').textContent).toContain('.json')
    const warning = find('[data-testid="backup-warning"]').textContent ?? ''
    expect(warning).toContain('敏感信息')
    expect(find<HTMLInputElement>('[data-testid="backup-file"]').accept).toContain('.json')
  })

  it('confirms with the sensitive-information warning before replacing the state', async () => {
    const { store } = await setup()
    const before = store.snapshot.value.profiles.map((profile) => profile.name)

    await chooseFile(backupText({ names: ['来自文件'] }))
    expect(document.querySelector('[data-testid="backup-confirm-restore"]')).not.toBeNull()
    expect(find('[data-testid="backup-confirm-file"]').textContent).toContain('billow-backup-test.json')
    expect(find('[data-testid="backup-confirm-warning"]').textContent).toContain('敏感信息')
    expect(store.snapshot.value.profiles.map((profile) => profile.name)).toEqual(before)

    await click('backup-confirm-cancel')
    expect(document.querySelector('[data-testid="backup-confirm-restore"]')).toBeNull()
    expect(store.snapshot.value.profiles.map((profile) => profile.name)).toEqual(before)

    await chooseFile(backupText({ names: ['来自文件'] }))
    await click('backup-confirm-restore')
    await vi.waitFor(() => {
      expect(store.snapshot.value.profiles.map((profile) => profile.name)).toEqual(['来自文件'])
    })
    expect(store.snapshot.value.active_id).toBe('p1')
  })

  it('refuses a backup from a newer version and keeps the current state', async () => {
    const { store } = await setup()
    const before = store.snapshot.value.profiles.map((profile) => profile.name)
    await chooseFile(backupText({ version: 2, names: ['不该出现'] }))
    await click('backup-confirm-restore')
    await vi.waitFor(() => {
      expect(store.lastRunError.value ?? '').toContain('更新的版本')
    })
    expect(store.snapshot.value.profiles.map((profile) => profile.name)).toEqual(before)
  })

  it('shows a WebDAV 401 with its status code and keeps the account unusable', async () => {
    await setup()
    await type('webdav-url', 'https://dav.example.com/remote.php/dav/files/me')
    await type('webdav-username', 'me')
    await type('webdav-password', 'bad')

    expect((find('[data-testid="webdav-upload"]') as HTMLButtonElement).disabled).toBe(true)
    expect(find('[data-testid="backup-webdav"]').textContent).toContain('尚未测试连接')

    await click('webdav-test')
    await vi.waitFor(() => {
      expect(find('[data-testid="webdav-error"]').textContent).toContain('401')
    })
    expect(find('[data-testid="webdav-error"]').textContent).toContain('认证失败')
    expect((find('[data-testid="webdav-upload"]') as HTMLButtonElement).disabled).toBe(true)
    expect(document.querySelector('[data-testid="webdav-list"]')).toBeNull()
  })

  it('uploads, lists and restores a cloud backup only after a successful test', async () => {
    const { store } = await setup()
    await type('webdav-url', 'https://dav.example.com/billow')
    await type('webdav-username', 'me')
    await type('webdav-password', 'pw')

    await click('webdav-test')
    await vi.waitFor(() => {
      expect(find('[data-testid="backup-webdav"]').textContent).toContain('连接可用')
    })
    await vi.waitFor(() => {
      expect(find('[data-testid="webdav-list"]').textContent).toContain('云端还没有备份')
    })
    expect((find('[data-testid="webdav-upload"]') as HTMLButtonElement).disabled).toBe(false)

    await click('webdav-upload')
    await vi.waitFor(() => {
      expect(document.querySelectorAll('[data-testid="webdav-item"]')).toHaveLength(1)
    })
    expect(find('[data-testid="webdav-uploaded"]').textContent).toContain('billow-backup-demo-')
    const item = find('[data-testid="webdav-item"]')
    expect(item.textContent).toContain('demo')

    find('[data-testid="webdav-restore"]').click()
    await flushPromises()
    expect(find('[data-testid="backup-confirm-warning"]').textContent).toContain('敏感信息')
    await click('backup-confirm-restore')
    await vi.waitFor(() => {
      expect(store.snapshot.value.profiles.length).toBeGreaterThan(0)
    })
    expect(store.snapshot.value.profiles.map((profile) => profile.name)).toEqual(
      (await store.backend.state()).profiles.map((profile) => profile.name),
    )
  })

  it('has no automatic sync control anywhere (R45)', async () => {
    setup()
    const text = document.body.textContent ?? ''
    expect(text).not.toContain('自动同步')
    expect(text).not.toContain('Auto sync')
    // Uploading and restoring are buttons; nothing switches background syncing on.
    expect(document.querySelectorAll('[data-testid="backup-webdav"] input[type="checkbox"]')).toHaveLength(0)
    expect(document.querySelectorAll('[data-testid="backup-webdav"] [role="switch"]')).toHaveLength(0)
    expect(find('[data-testid="webdav-upload"]').tagName).toBe('BUTTON')
    expect(find('[data-testid="webdav-restore"], [data-testid="webdav-test"]')).toBeTruthy()
  })
})
