import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import App from './App.vue'
import GroupIcon from './components/GroupIcon.vue'
import { createDemoBackend } from './lib/demo'
import type { Store } from './lib/store'
import type { ConnectionRow, LogLine } from './lib/types'

async function settle(ms = 1000) {
  await vi.advanceTimersByTimeAsync(ms)
  await flushPromises()
}

const mounted: { unmount: () => void }[] = []

// The YAML editor is a lazy chunk; load it once so fake timers do not race the import.
beforeAll(async () => {
  await import('./lib/yaml/editor')
}, 20_000)

async function mountApp(options: Parameters<typeof createDemoBackend>[0] = {}, width = 1200) {
  vi.useFakeTimers()
  const backend = createDemoBackend(options)
  const wrapper = mount(App, { props: { backend, width }, attachTo: document.body })
  mounted.push(wrapper)
  await settle(50)
  return { wrapper, backend }
}

/** Mount a backend that a test has already wrapped with its own state. */
async function mountWith(backend: ReturnType<typeof createDemoBackend>, width = 1200) {
  vi.useFakeTimers()
  const wrapper = mount(App, { props: { backend, width }, attachTo: document.body })
  mounted.push(wrapper)
  await settle(50)
  return wrapper
}

/** The CodeMirror view of the open YAML dialog, once its lazy chunk has mounted. */
async function editorView() {
  const { EditorView } = await import('@codemirror/view')
  for (let attempt = 0; attempt < 50; attempt += 1) {
    await flushPromises()
    const editors = document.body.querySelectorAll<HTMLElement>('.cm-editor')
    const element = editors[editors.length - 1]
    const view = element ? EditorView.findFromDOM(element) : null
    if (view) return view
    await vi.advanceTimersByTimeAsync(20)
  }
  throw new Error('editor did not mount')
}

async function openPage(
  wrapper: Awaited<ReturnType<typeof mountApp>>['wrapper'],
  page: string,
) {
  await wrapper.find(`.sidebar [data-page="${page}"]`).trigger('click')
  await flushPromises()
}

function stubClipboard(ok = true) {
  const writeText = ok
    ? vi.fn(async (_text: string) => undefined)
    : vi.fn(async (_text: string) => {
        throw new Error('denied')
      })
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
  return writeText
}

function storeOf(wrapper: Awaited<ReturnType<typeof mountApp>>['wrapper']) {
  return (wrapper.vm as unknown as { store: Store }).store
}

function press(target: EventTarget, key: string, init: KeyboardEventInit = {}) {
  const event = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...init })
  target.dispatchEvent(event)
  return event
}

async function openPalette() {
  press(document, 'k', { ctrlKey: true })
  await flushPromises()
  await nextTick()
  await flushPromises()
}

function paletteOption(key: string) {
  return document.body.querySelector<HTMLElement>(`[data-command="${key}"]`)
}

function paletteInput() {
  return document.body.querySelector<HTMLInputElement>('.palette-search input')
}

async function searchPalette(value: string) {
  const input = paletteInput()
  if (!input) throw new Error('palette input missing')
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await nextTick()
  await flushPromises()
  return input
}

/** Drive the real WebView history the way a back button does. */
async function goBack() {
  window.history.back()
  await settle(20)
}

/** Pretend the sticky proxy toolbar is `height` tall so scroll offsets can be asserted. */
function stubToolbarHeight(height: number) {
  const proto = HTMLElement.prototype as unknown as { getBoundingClientRect: () => DOMRect }
  const original = proto.getBoundingClientRect
  proto.getBoundingClientRect = function (this: HTMLElement) {
    const rect = original.call(this)
    if (this.classList?.contains('proxies-toolbar')) {
      return { ...rect, height, bottom: rect.top + height } as DOMRect
    }
    return rect
  }
  return () => {
    proto.getBoundingClientRect = original
  }
}

/** Record which group cards ask to be scrolled into view. */
function recordScrollTargets() {
  const proto = Element.prototype as unknown as { scrollIntoView?: (options?: ScrollIntoViewOptions) => void }
  const original = proto.scrollIntoView
  const targets: string[] = []
  proto.scrollIntoView = function (this: Element) {
    targets.push(this.getAttribute('data-group-card') ?? '')
  }
  return {
    targets,
    restore() {
      proto.scrollIntoView = original
    },
  }
}

afterEach(() => {
  while (mounted.length) {
    try {
      mounted.pop()?.unmount()
    } catch {
      /* already unmounted */
    }
  }
  vi.useRealTimers()
  localStorage.clear()
  document.body.innerHTML = ''
})

describe('App', () => {
  it('shows the sidebar with every page on desktop and a tab bar on narrow screens', async () => {
    const { wrapper } = await mountApp()
    const pages = wrapper.findAll('.sidebar [data-page]').map((item) => item.attributes('data-page'))
    expect(pages).toEqual(['home', 'proxies', 'profiles', 'connections', 'rules', 'resources', 'logs', 'settings'])
    expect(wrapper.find('.tabbar').exists()).toBe(false)
    wrapper.unmount()

    const narrow = await mountApp({}, 390)
    expect(narrow.wrapper.find('.sidebar').exists()).toBe(false)
    // Phones keep four tabs; connections moves behind Settings with the other tools.
    expect(narrow.wrapper.findAll('.tabbar [data-page]').map((item) => item.attributes('data-page'))).toEqual([
      'home',
      'proxies',
      'profiles',
      'settings',
    ])
  })

  it('connects from the power button and shows live rates', async () => {
    const { wrapper } = await mountApp()
    expect(wrapper.find('[data-testid="status"]').text()).toBe('未连接')
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="status"]').text()).toBe('已连接')
    expect(wrapper.find('[data-testid="rates"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="toggle-proxy"]').attributes('aria-checked')).toBe('true')
    expect(wrapper.find('[data-testid="toggle-tun"]').attributes('aria-checked')).toBe('false')
  })

  it('says in the hero whether traffic is taken over, not only that the kernel runs', async () => {
    const { wrapper } = await mountApp()
    expect(wrapper.find('[data-testid="hero-eyebrow"]').text()).toBe('代理未运行')
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="hero-eyebrow"]').text()).toContain('系统代理')
    await wrapper.find('[data-testid="toggle-proxy"]').trigger('click')
    await settle(500)
    expect(wrapper.find('[data-testid="hero-eyebrow"]').text()).toContain('未接管系统流量')
    expect(wrapper.find('[data-testid="home-status"]').classes()).toContain('bare')
  })

  it('connects and disconnects from the sidebar on any page', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="rules"]').trigger('click')
    await settle(50)
    expect(wrapper.find('[data-testid="side-status"]').text()).toContain('未连接')
    await wrapper.find('[data-testid="side-power"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="side-status"]').text()).toContain('已连接')
    expect(wrapper.find('[data-testid="side-power"]').attributes('aria-label')).toBe('断开')
    await wrapper.find('[data-testid="side-power"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="side-status"]').text()).toContain('未连接')
  })

  it('marks untested nodes with a quiet test glyph instead of repeating 测速', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await settle(50)
    const pill = wrapper.find('[data-group-card="节点选择"] [data-node="日本 02"] .delay')
    expect(pill.classes()).toContain('untested')
    expect(pill.text()).toBe('')
    expect(pill.attributes('aria-label')).toBe('测速 日本 02')
  })

  it('hides the side connect control until a profile exists', async () => {
    const { wrapper } = await mountApp({ profiles: false })
    expect(wrapper.find('[data-testid="side-power"]').exists()).toBe(false)
  })

  it('opens the add dialog straight from home when no profile exists', async () => {
    const { wrapper } = await mountApp({ profiles: false })
    expect(wrapper.find('[data-testid="status"]').text()).toBe('欢迎使用 Billow')
    await wrapper.find('[data-testid="power"]').trigger('click')
    await flushPromises()
    expect(document.body.querySelector('[data-testid="add-url"]')).not.toBeNull()
  })

  it('switches outbound mode', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="mode-segmented"] [data-value="global"]').trigger('click')
    await settle(300)
    expect(wrapper.find('[data-testid="mode-segmented"] [data-value="global"]').attributes('aria-checked')).toBe('true')
  })

  it('selects a node in a manual group and filters by name', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-group-card="节点选择"]').classes()).toContain('open')
    await wrapper.find('[data-group-card="节点选择"] [data-node="日本 02"] .node-select').trigger('click')
    await settle(200)
    expect(wrapper.find('[data-group-card="节点选择"] [data-node="日本 02"]').classes()).toContain('selected')

    await wrapper.find('[data-testid="node-search"]').setValue('新加坡')
    const visible = wrapper.findAll('[data-group-card="节点选择"] [data-node]').map((node) => node.attributes('data-node'))
    expect(visible.length).toBeGreaterThan(0)
    expect(visible.every((name) => name?.includes('新加坡'))).toBe(true)
  })

  it('lists profiles with the active one first and switches on click', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="profiles"]').trigger('click')
    await flushPromises()
    const cards = wrapper.findAll('[data-profile]')
    expect(cards[0].attributes('data-profile')).toBe('p1')
    expect(cards[0].classes()).toContain('current')
    await cards[1].trigger('click')
    await settle(800)
    expect(wrapper.find('[data-profile="p2"]').classes()).toContain('current')
    expect(wrapper.findAll('[data-profile]')[0].attributes('data-profile')).toBe('p2')
  })

  async function openProfiles(wrapper: Awaited<ReturnType<typeof mountApp>>['wrapper']) {
    await wrapper.find('.sidebar [data-page="profiles"]').trigger('click')
    await flushPromises()
  }

  async function openProfileMenu(wrapper: Awaited<ReturnType<typeof mountApp>>['wrapper'], id = 'p1') {
    await wrapper.find(`[data-profile="${id}"] [aria-label="更多操作"]`).trigger('click')
    await flushPromises()
    await nextTick()
    await flushPromises()
  }

  /** Dialogs are teleported to <body>, so their controls are outside the wrapper. */
  function bodyClick(selector: string) {
    const element = document.body.querySelector<HTMLElement>(selector)
    if (!element) throw new Error(`missing ${selector}`)
    element.click()
  }

  it('rejects a duplicate subscription import and focuses the existing card', async () => {
    const { wrapper, backend } = await mountApp()
    await openProfiles(wrapper)
    const before = wrapper.findAll('[data-profile]').length

    // The demo backend mirrors the Rust guard, so deep links cannot bypass it either.
    const directTask = backend.addSubscription(
      ' https://sub.example.com/api/v1/client/subscribe?token=demo ',
    )
    await vi.advanceTimersByTimeAsync(200)
    const direct = await directTask
    await flushPromises()
    expect(direct.profiles).toHaveLength(before)
    expect(direct.input_error).toBe('该订阅已存在')

    const add = vi.spyOn(backend, 'addSubscription')
    const form = wrapper.find('.quick-import')
    await form
      .find('input')
      .setValue('  https://sub.example.com/api/v1/client/subscribe?token=demo  ')
    await form.trigger('submit')
    await flushPromises()
    await nextTick()

    expect(wrapper.find('.quick-import + .field-error').text()).toContain('该订阅已存在')
    expect(wrapper.findAll('[data-profile]')).toHaveLength(before)
    expect(add).not.toHaveBeenCalled()
    expect(document.activeElement).toBe(wrapper.find('[data-profile="p1"]').element)
  })

  it('shows update-all progress, keeps partial failures after a page switch, and retries', async () => {
    const { wrapper, backend } = await mountApp({ failRefreshId: 'p2' })
    await openProfiles(wrapper)
    const button = () => wrapper.find('[data-testid="update-all-profiles"]')
    expect(button().text()).toContain('全部更新')

    await button().trigger('click')
    await settle(50)
    expect(button().text()).toContain('正在更新 1/2')
    expect(button().attributes('aria-busy')).toBe('true')
    expect(button().find('.spin').exists()).toBe(false)
    expect(wrapper.find('[data-profile="p1"] [data-update-state]').attributes('data-update-state')).toBe('updating')

    // Leaving the page mid-run must not lose progress or results.
    await wrapper.find('.sidebar [data-page="home"]').trigger('click')
    await settle(2200)
    await openProfiles(wrapper)
    expect(button().text()).toContain('已完成 2/2')
    expect(button().text()).toContain('1 个失败')
    expect(wrapper.find('[data-profile="p1"] [data-update-state]').attributes('data-update-state')).toBe('success')
    expect(wrapper.find('[data-profile="p1"] [data-update-state]').text()).toContain('已更新')
    const failed = wrapper.find('[data-profile="p2"] [data-update-state]')
    expect(failed.attributes('data-update-state')).toBe('failure')
    expect(failed.text()).toContain('订阅没有取回')
    expect(wrapper.find('[data-profile="p1"]').find('[data-testid="retry-update"]').exists()).toBe(false)

    // Retrying the failed card succeeds once the source is reachable again.
    const readState = backend.state
    backend.refresh = vi.fn(async () => {
      const snap = await readState()
      return {
        ...snap,
        profiles: snap.profiles.map((item) =>
          item.id === 'p2'
            ? { ...item, failure: null, updated_ms: Date.now(), last_success_ms: Date.now() }
            : item,
        ),
      }
    })
    await wrapper.find('[data-profile="p2"] [data-testid="retry-update"]').trigger('click')
    await settle(1000)
    expect(backend.refresh).toHaveBeenCalledWith('p2')
    expect(wrapper.find('[data-profile="p2"] [data-update-state]').attributes('data-update-state')).toBe('success')
    expect(wrapper.find('[data-profile="p2"] [data-testid="retry-update"]').exists()).toBe(false)
    expect(wrapper.find('[data-profile="p2"]').text()).not.toContain('订阅没有取回')
  })

  it('guards unsaved editor changes and keeps text and caret when cancelling', async () => {
    const { wrapper } = await mountApp()
    await openProfiles(wrapper)
    await openProfileMenu(wrapper, 'p1')
    await wrapper.find('[data-profile="p1"] [data-menu-item="content"]').trigger('click')
    const view = await editorView()
    expect(view.state.doc.toString()).toContain('proxies')
    view.dispatch({ changes: { from: view.state.doc.length, insert: '\n# draft' }, selection: { anchor: 2, head: 5 } })
    await nextTick()
    expect(document.body.textContent).toContain('未保存')

    bodyClick('[data-testid="cancel-editor"]')
    await flushPromises()
    expect(document.body.textContent).toContain('放弃未保存的修改')
    expect(document.body.querySelector('.cm-editor')).not.toBeNull()

    bodyClick('[data-testid="keep-editing"]')
    await flushPromises()
    await nextTick()
    expect(document.body.textContent).not.toContain('放弃未保存的修改')
    const kept = await editorView()
    expect(kept).toBe(view)
    expect(kept.state.doc.toString()).toContain('# draft')
    expect(kept.state.selection.main.from).toBe(2)
    expect(kept.state.selection.main.to).toBe(5)
    expect(document.body.textContent).toContain('未保存')

    // Escape goes through the Modal close guard as well.
    press(document, 'Escape')
    await flushPromises()
    expect(document.body.textContent).toContain('放弃未保存的修改')
    bodyClick('[data-testid="keep-editing"]')
    await flushPromises()
    await nextTick()
    expect(document.body.querySelector('.cm-editor')).not.toBeNull()

    bodyClick('[data-testid="cancel-editor"]')
    await flushPromises()
    bodyClick('[data-testid="discard-edits"]')
    await flushPromises()
    await nextTick()
    expect(document.body.querySelector('.cm-editor')).toBeNull()
    expect(document.activeElement).toBe(
      wrapper.find('[data-profile="p1"] [aria-label="更多操作"]').element,
    )
  })

  it('shows a save failure under the editor and keeps the dialog open', async () => {
    const { wrapper, backend } = await mountApp()
    const originalSave = backend.saveContent
    backend.saveContent = vi.fn(async (id: string) => {
      const snapshot = await originalSave(id, '')
      return { ...snapshot, input_error: '配置无法应用' }
    })
    await openProfiles(wrapper)
    await openProfileMenu(wrapper, 'p1')
    await wrapper.find('[data-profile="p1"] [data-menu-item="content"]').trigger('click')
    await editorView()

    bodyClick('.modal-foot .btn.primary')
    await settle(200)
    const error = document.body.querySelector('.editor-error')
    expect(error?.textContent).toContain('配置无法应用')
    expect(document.body.querySelector('.cm-editor')).not.toBeNull()
    expect(document.body.querySelector('.editor-error')?.getAttribute('role')).toBe('alert')
  })

  it('saves from the editor with Ctrl+S and highlights YAML', async () => {
    const { wrapper, backend } = await mountApp()
    const save = vi.spyOn(backend, 'saveOverride')
    await openProfiles(wrapper)
    await openProfileMenu(wrapper, 'p1')
    await wrapper.find('[data-profile="p1"] [data-menu-item="override"]').trigger('click')
    const view = await editorView()
    view.dispatch({ changes: { from: 0, insert: 'mixed-port: 7891\n' } })
    await nextTick()
    expect(document.body.querySelector('.cm-content')?.textContent).toContain('mixed-port')
    view.contentDOM.dispatchEvent(new KeyboardEvent('keydown', { key: 's', ctrlKey: true, bubbles: true, cancelable: true }))
    await settle(200)
    expect(save).toHaveBeenCalledWith('p1', 'mixed-port: 7891\n')
  })

  it('opens the effective config read-only from the running profile only', async () => {
    const { wrapper } = await mountApp()
    await openProfiles(wrapper)
    await openProfileMenu(wrapper, 'p2')
    expect(wrapper.find('[data-profile="p2"] [data-menu-item="effective"]').exists()).toBe(false)
    press(document, 'Escape')
    await flushPromises()

    await openProfileMenu(wrapper, 'p1')
    await wrapper.find('[data-profile="p1"] [data-menu-item="effective"]').trigger('click')
    const view = await editorView()
    expect(document.body.textContent).toContain('生效配置')
    expect(view.state.readOnly).toBe(true)
    expect(view.state.doc.toString()).toContain('mixed-port')

    // The override editor links to the same view, quietly.
    bodyClick('.modal-foot .btn.primary')
    await flushPromises()
    await openProfileMenu(wrapper, 'p1')
    await wrapper.find('[data-profile="p1"] [data-menu-item="override"]').trigger('click')
    await editorView()
    expect(document.body.querySelector('[data-testid="open-effective"]')?.textContent).toBe('查看生效配置')
  })

  it('switches to another profile from its menu, without a pointer', async () => {
    const { wrapper } = await mountApp()
    await openProfiles(wrapper)
    await openProfileMenu(wrapper, 'p1')
    expect(wrapper.find('[data-profile="p1"] [data-menu-item="enable"]').exists()).toBe(false)
    press(wrapper.find('[role="menu"]').element, 'Escape')
    await flushPromises()

    await openProfileMenu(wrapper, 'p2')
    await wrapper.find('[data-profile="p2"] [data-menu-item="enable"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-profile="p2"]').attributes('aria-current')).toBe('true')
    expect(wrapper.find('[data-profile="p1"]').attributes('aria-current')).toBeUndefined()
  })

  it('moves through the profile menu with keys and returns focus to 更多操作', async () => {
    const { wrapper } = await mountApp()
    await openProfiles(wrapper)
    const more = wrapper.find('[data-profile="p1"] [aria-label="更多操作"]')
    await openProfileMenu(wrapper, 'p1')
    const menu = wrapper.find('[role="menu"]')
    expect(menu.exists()).toBe(true)
    const items = () => menu.findAll('[role="menuitem"]')
    // edit, content, override, effective config (current profile only), copy, remove
    expect(items().length).toBe(6)
    expect(document.activeElement).toBe(items()[0].element)

    press(menu.element, 'ArrowDown')
    expect(document.activeElement).toBe(items()[1].element)
    press(menu.element, 'ArrowDown')
    expect(document.activeElement).toBe(items()[2].element)
    press(menu.element, 'ArrowUp')
    expect(document.activeElement).toBe(items()[1].element)
    press(menu.element, 'End')
    expect(document.activeElement).toBe(items()[items().length - 1].element)
    press(menu.element, 'Home')
    expect(document.activeElement).toBe(items()[0].element)

    press(menu.element, 'Escape')
    await flushPromises()
    await nextTick()
    expect(wrapper.find('[role="menu"]').exists()).toBe(false)
    expect(document.activeElement).toBe(more.element)

    await openProfileMenu(wrapper, 'p1')
    await wrapper.find('[data-profile="p1"] [data-menu-item="remove"]').trigger('click')
    await flushPromises()
    expect(document.body.textContent).toContain('确定删除')
    bodyClick('.modal-foot .btn.ghost')
    await flushPromises()
    expect(wrapper.find('[data-profile="p1"]').exists()).toBe(true)
  })

  it('keeps content-tight profile cards readable at 390px', async () => {
    const { wrapper } = await mountApp({}, 390)
    await wrapper.find('.tabbar [data-page="profiles"]').trigger('click')
    await flushPromises()
    const cards = wrapper.findAll('[data-profile]')
    expect(cards).toHaveLength(3)
    expect(cards[0].attributes('data-profile')).toBe('p1')
    expect(cards[0].classes()).toContain('current')
    expect(wrapper.find('.shell').classes()).toContain('compact')
    expect(cards[0].attributes('style')).toBeUndefined()

    const first = cards[0].text()
    expect(first).toContain('星河云')
    expect(first).toContain('sub.example.com')
    expect(first).toContain('86.4 GB / 200 GB')
    expect(first).toContain('节点')
    for (const card of cards) {
      expect(card.find('[aria-label="更多操作"]').exists()).toBe(true)
    }
  })

  it('shows connections after connecting and filters them', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await wrapper.find('.sidebar [data-page="connections"]').trigger('click')
    await settle(1100)
    expect(wrapper.findAll('[data-testid="connection-row"]').length).toBeGreaterThan(0)
    await wrapper.find('[data-testid="connection-search"]').setValue('zzz-no-such-host')
    expect(wrapper.findAll('[data-testid="connection-row"]')).toHaveLength(0)
    expect(wrapper.text()).toContain('没有匹配的连接')
  })

  it('keeps Android access control in Settings with bypass and allowlist modes', async () => {
    const { wrapper, backend } = await mountApp({ platform: 'android' }, 390)
    const save = vi.spyOn(backend, 'setAppRules')
    // Home carries neither desktop takeover switches nor the per-app entry.
    expect(wrapper.find('[data-testid="toggle-proxy"]').exists()).toBe(false)
    expect(wrapper.find('.home [data-testid="open-apps"]').exists()).toBe(false)

    await wrapper.find('.tabbar [data-page="settings"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="open-apps"]').text()).toContain('绕过 1 个')
    await wrapper.find('[data-testid="open-apps"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('apps')
    expect(wrapper.find('[data-testid="page-back"]').text()).toBe('设置')

    // Selected apps lead; system apps stay hidden until asked for.
    const rows = () => wrapper.findAll('.app-row').map((row) => row.attributes('data-app'))
    expect(rows()[0]).toBe('com.tencent.mm')
    expect(rows()).not.toContain('com.android.systemui')
    await wrapper.find('[data-testid="apps-system"]').trigger('click')
    expect(rows()).toContain('com.android.systemui')

    // Taps batch into one save; the row under the finger does not move.
    await wrapper.find('.app-row[data-app="org.telegram.messenger"]').trigger('click')
    await wrapper.find('.app-row[data-app="tv.danmaku.bili"]').trigger('click')
    const order = rows()
    expect(save).not.toHaveBeenCalled()
    await settle(800)
    expect(save).toHaveBeenCalledTimes(1)
    expect(save).toHaveBeenLastCalledWith('exclude', ['com.tencent.mm', 'org.telegram.messenger', 'tv.danmaku.bili'])
    expect(rows()).toEqual(order)
    expect(wrapper.find('[data-testid="apps-summary"]').text()).toContain('3 个应用绕过 VPN')

    // The allowlist keeps its own (empty) list and says what an empty allowlist means.
    await wrapper.find('[data-testid="apps-mode"] [data-value="include"]').trigger('click')
    await settle(300)
    expect(save).toHaveBeenLastCalledWith('include', [])
    expect(wrapper.find('[data-testid="apps-summary"]').text()).toContain('所有应用都经过 VPN')
    await wrapper.find('.app-row[data-app="com.android.chrome"]').trigger('click')
    expect(wrapper.find('.app-row[data-app="com.android.chrome"]').attributes('aria-checked')).toBe('true')
    expect(wrapper.find('.app-row[data-app="com.tencent.mm"]').attributes('aria-checked')).toBe('false')
    await settle(800)
    expect(save).toHaveBeenLastCalledWith('include', ['com.android.chrome'])
    expect(storeOf(wrapper).snapshot.value.excluded).toEqual(['com.tencent.mm', 'org.telegram.messenger', 'tv.danmaku.bili'])
  })

  it('preserves edits and mode changes while an earlier app save is in flight', async () => {
    const { wrapper, backend } = await mountApp({ platform: 'android' }, 390)
    const original = backend.setAppRules.bind(backend)
    let finish!: () => void
    const save = vi.spyOn(backend, 'setAppRules').mockImplementationOnce(async (mode, packages) => {
      await new Promise<void>((resolve) => { finish = resolve })
      return original(mode, packages)
    })
    await wrapper.find('.tabbar [data-page="settings"]').trigger('click')
    await wrapper.find('[data-testid="open-apps"]').trigger('click')
    await wrapper.find('.app-row[data-app="org.telegram.messenger"]').trigger('click')
    await settle(750)
    await wrapper.find('.app-row[data-app="tv.danmaku.bili"]').trigger('click')
    await wrapper.find('[data-testid="apps-mode"] [data-value="include"]').trigger('click')
    await settle(20)
    expect(save).toHaveBeenCalledTimes(1)
    finish()
    await settle(1000)
    expect(save).toHaveBeenNthCalledWith(2, 'exclude', ['com.tencent.mm', 'org.telegram.messenger', 'tv.danmaku.bili'])
    expect(save).toHaveBeenLastCalledWith('include', [])
    expect(storeOf(wrapper).snapshot.value.app_mode).toBe('include')
    expect(storeOf(wrapper).snapshot.value.excluded).toContain('tv.danmaku.bili')
  })

  it('bounds mounted app rows and still finds apps near the end of a large list', async () => {
    const { wrapper } = await mountApp({ platform: 'android' }, 390)
    await wrapper.find('.tabbar [data-page="settings"]').trigger('click')
    await wrapper.find('[data-testid="open-apps"]').trigger('click')
    const store = storeOf(wrapper)
    store.stop()
    store.snapshot.value = { ...store.snapshot.value, installed: Array.from({ length: 700 }, (_, i) => ({
      name: `Application ${i}`, package_name: `com.example.app${i}`, system: false,
    })) }
    await nextTick()
    expect(wrapper.findAll('.app-row').length).toBeLessThan(30)
    await wrapper.find('[data-testid="apps-search"]').setValue('com.example.app699')
    await nextTick()
    expect(wrapper.findAll('.app-row')).toHaveLength(1)
    expect(wrapper.find('.app-row').attributes('data-app')).toBe('com.example.app699')
  })

  it('activates the only imported profile before the first connection', async () => {
    const { wrapper, backend } = await mountApp({ platform: 'android' }, 390)
    const originalEnable = backend.enable.bind(backend)
    let resume = () => {}
    const gate = new Promise<void>((resolve) => { resume = resolve })
    const enable = vi.spyOn(backend, 'enable').mockImplementation(async (id) => {
      await gate
      return originalEnable(id)
    })
    const connect = vi.spyOn(backend, 'connect')
    const store = storeOf(wrapper)
    store.stop()
    const only = { ...store.snapshot.value.profiles[0]!, current: false }
    store.snapshot.value = { ...store.snapshot.value, active_id: null, profiles: [only] }
    await wrapper.find('[data-testid="power"]').trigger('click')
    await nextTick()
    expect(wrapper.find('[role="status"]').text()).toContain('正在初始化内核')
    resume()
    await settle(1500)
    expect(enable).toHaveBeenCalledWith(only.id)
    expect(connect).toHaveBeenCalledOnce()
    expect(store.snapshot.value.connected).toBe(true)
  })

  it('drills into phone settings sections and comes back to the list', async () => {
    const { wrapper } = await mountApp({}, 390)
    await wrapper.find('.tabbar [data-page="settings"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="settings-tabs"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="open-dns"]').text()).toContain('跟随配置')
    await wrapper.find('[data-testid="open-dns"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('.settings-subhead h1').text()).toBe('DNS')
    expect(wrapper.find('[data-testid="dns-settings"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="settings-network"]').exists()).toBe(false)
    await wrapper.find('[data-testid="settings-back"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="settings-network"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="open-tun"]').text()).toContain('关闭')
  })

  it('opens TUN settings from home and saves a changed stack', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="tun-settings-link"]').trigger('click')
    await flushPromises()
    const tunCard = wrapper.find('[data-testid="tun-settings"]')
    expect(tunCard.exists()).toBe(true)
    expect(tunCard.find('[data-value="mixed"]').attributes('aria-checked')).toBe('true')
    await tunCard.find('[data-value="gvisor"]').trigger('click')
    await wrapper.find('[data-testid="save-tun"]').trigger('click')
    await settle(600)
    expect(wrapper.find('[data-testid="save-tun"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="tun-settings"] [data-value="gvisor"]').attributes('aria-checked')).toBe('true')
  })

  it('turns on DNS override and edits fake-ip settings', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="settings"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-testid="settings-tabs"] [data-value="dns"]').trigger('click')
    await flushPromises()
    const toggle = wrapper.find('[data-testid="dns-override"]')
    expect(toggle.attributes('aria-checked')).toBe('false')
    await toggle.trigger('click')
    await settle(600)
    expect(wrapper.find('[data-testid="dns-override"]').attributes('aria-checked')).toBe('true')
    expect(wrapper.text()).toContain('Fake-IP 过滤')
    await wrapper.find('[data-testid="dns-settings"] [data-value="redir-host"]').trigger('click')
    expect(wrapper.text()).not.toContain('Fake-IP 过滤')
    await wrapper.find('[data-testid="save-dns"]').trigger('click')
    await settle(600)
    expect(wrapper.find('[data-testid="save-dns"]').exists()).toBe(false)
  })

  it('lists proxy and rule providers once connected', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await wrapper.find('.sidebar [data-page="resources"]').trigger('click')
    await settle(500)
    expect(wrapper.find('[data-provider="机场订阅"]').exists()).toBe(true)
    expect(wrapper.find('[data-provider="cn-domains"]').text()).toContain('112,480 条规则')
    expect(wrapper.find('[data-testid="upgrade-geo"]').attributes('disabled')).toBeUndefined()
  })

  it('groups the desktop sidebar into core and tools with settings pinned last', async () => {
    const { wrapper } = await mountApp()
    expect(wrapper.findAll('.sidebar .nav-group-label').map((label) => label.text())).toEqual(['核心', '工具'])
    expect(wrapper.findAll('.nav-group').map((group) => group.findAll('[data-page]').length)).toEqual([4, 3])
    expect(wrapper.find('.side-foot [data-page="settings"]').exists()).toBe(true)
    expect(wrapper.find('.nav [data-page="settings"]').exists()).toBe(false)
    const order = wrapper.findAll('.sidebar [data-page]').map((item) => item.attributes('data-page'))
    expect(order).toEqual(['home', 'proxies', 'profiles', 'connections', 'rules', 'resources', 'logs', 'settings'])
    expect(order[order.length - 1]).toBe('settings')
  })

  it('marks the mobile settings tab current while a tools page is open', async () => {
    const { wrapper } = await mountApp({}, 390)
    const settingsTab = () => wrapper.find('.tabbar [data-page="settings"]')
    expect(settingsTab().attributes('aria-current')).toBeUndefined()
    await settingsTab().trigger('click')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('settings')
    const tools = wrapper.findAll('[data-testid="tool-grid"] [data-tool]').map((tile) => tile.attributes('data-tool'))
    expect(tools).toEqual(['connections', 'logs', 'rules', 'resources'])
    await wrapper.find('[data-tool="rules"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('rules')
    expect(settingsTab().attributes('aria-current')).toBe('page')
    expect(wrapper.find('.main .page').exists()).toBe(true)

    // A visible back control returns to the page the tool was opened from.
    const back = wrapper.find('[data-testid="page-back"]')
    expect(back.text()).toBe('设置')
    await back.trigger('click')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('settings')
    expect(wrapper.find('[data-testid="page-back"]').exists()).toBe(false)
  })

  it('keeps the back control off desktop pages', async () => {
    const { wrapper } = await mountApp()
    await openPage(wrapper, 'rules')
    expect(wrapper.find('[data-testid="page-back"]').exists()).toBe(false)
  })

  it('opens the command palette with Ctrl+K, filters and executes a page', async () => {
    const { wrapper } = await mountApp()
    await openPalette()
    expect(paletteInput()).not.toBeNull()
    expect(paletteOption('action:test-all')?.textContent).toContain('连接后可测速')
    expect(document.body.textContent).not.toContain('删除配置')

    const input = await searchPalette('代理')
    expect(paletteOption('page:proxies')).not.toBeNull()
    expect(paletteOption('page:home')).toBeNull()
    press(input, 'Enter')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('proxies')
    expect(document.body.querySelector('.palette')).toBeNull()
  })

  it('lists page, settings and non-destructive actions and hides TUN on Android', async () => {
    const { wrapper } = await mountApp({ platform: 'android' }, 1200)
    await openPalette()
    expect(paletteOption('page:logs')).not.toBeNull()
    expect(paletteOption('setting:dns')).not.toBeNull()
    expect(paletteOption('setting:tun')).toBeNull()
    for (const id of ['connect', 'disconnect', 'test-all', 'refresh-profiles', 'add-profile', 'toggle-theme', 'open-logs']) {
      expect(paletteOption(`action:${id}`)).not.toBeNull()
    }
    expect(paletteOption('action:remove')).toBeNull()
    expect(wrapper.find('.main').attributes('data-page')).toBe('home')
  })

  it('executes palette actions and opens a settings category', async () => {
    const { wrapper } = await mountApp()
    await openPalette()
    let input = await searchPalette('打开日志')
    press(input, 'Enter')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('logs')

    await openPalette()
    input = await searchPalette('Fake-IP')
    press(input, 'Enter')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('settings')
    expect(wrapper.find('[data-testid="dns-settings"]').exists()).toBe(true)
  })

  it('closes the palette with Escape and returns focus to the opener', async () => {
    const { wrapper } = await mountApp()
    const trigger = wrapper.find('.sidebar [data-page="home"]').element as HTMLElement
    trigger.focus()
    await openPalette()
    expect(document.activeElement).toBe(paletteInput())
    press(document.activeElement ?? document, 'Escape')
    await flushPromises()
    await nextTick()
    await flushPromises()
    expect(document.body.querySelector('.palette')).toBeNull()
    expect(document.activeElement).toBe(trigger)
  })

  it('focuses the page search with / but leaves the key alone inside inputs', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="logs"]').trigger('click')
    await flushPromises()
    const search = wrapper.find('[data-page-search]').element as HTMLInputElement
    search.focus()
    const inside = press(search, '/')
    expect(inside.defaultPrevented).toBe(false)
    expect(document.activeElement).toBe(search)

    search.blur()
    press(document.body, '/')
    expect(document.activeElement).toBe(search)
  })

  it('opens the shortcut sheet with ? outside inputs and clears search with Escape', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="logs"]').trigger('click')
    await flushPromises()
    const search = wrapper.find('[data-page-search]').element as HTMLInputElement
    search.focus()
    press(search, '?')
    await flushPromises()
    expect(document.body.querySelector('.shortcut-list')).toBeNull()

    search.value = 'error'
    search.dispatchEvent(new Event('input', { bubbles: true }))
    await nextTick()
    press(search, 'Escape')
    await flushPromises()
    expect(search.value).toBe('')

    search.blur()
    press(document.body, '?')
    await flushPromises()
    expect(document.body.querySelector('.shortcut-list')).not.toBeNull()
    press(document.activeElement ?? document, 'Escape')
    await flushPromises()
    expect(document.body.querySelector('.shortcut-list')).toBeNull()
  })

  it('restores per-page scroll but lets a proxy group target win', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    const main = wrapper.find('.main').element as HTMLElement
    main.scrollTop = 260
    await wrapper.find('.sidebar [data-page="home"]').trigger('click')
    await flushPromises()
    expect(main.scrollTop).toBe(0)
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(main.scrollTop).toBe(260)

    await wrapper.find('.sidebar [data-page="home"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-testid="groups-card"] [data-group="节点选择"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('proxies')
    expect(main.scrollTop).toBe(0)
  })

  it('top-scrolls when the requested proxy group cannot be found', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    const main = wrapper.find('.main').element as HTMLElement
    main.scrollTop = 240
    await wrapper.find('.sidebar [data-page="home"]').trigger('click')
    await flushPromises()

    const store = (wrapper.vm as unknown as { store: { go: (page: string, group?: string) => void } }).store
    store.go('proxies', '不存在的组')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('proxies')
    expect(main.scrollTop).toBe(0)
  })

  it('resets scroll on width changes but keeps it on height-only resizes', async () => {
    const original = window.innerWidth
    try {
      vi.useFakeTimers()
      const backend = createDemoBackend()
      const wrapper = mount(App, { props: { backend }, attachTo: document.body })
      mounted.push(wrapper)
      await settle(50)
      await wrapper.find('.sidebar [data-page="logs"]').trigger('click')
      await flushPromises()
      const main = wrapper.find('.main').element as HTMLElement
      main.scrollTop = 180
      window.dispatchEvent(new Event('resize'))
      expect(main.scrollTop).toBe(180)

      window.innerWidth = original - 400
      window.dispatchEvent(new Event('resize'))
      expect(main.scrollTop).toBe(0)
    } finally {
      window.innerWidth = original
    }
  })

  it('closes an open menu on back, then returns to the previous page on the next back', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="profiles"]').trigger('click')
    await flushPromises()
    const more = wrapper.find('[aria-label="更多操作"]')
    await more.trigger('click')
    await flushPromises()
    expect(wrapper.find('[role="menu"]').exists()).toBe(true)
    press(document, 'k', { ctrlKey: true })
    await flushPromises()
    expect(document.body.querySelector('.palette')).toBeNull()

    const moreEl = more.element as HTMLElement
    moreEl.focus()
    press(moreEl, 'Escape')
    await flushPromises()
    expect(wrapper.find('[role="menu"]').exists()).toBe(false)
    expect(document.activeElement).toBe(moreEl)

    await more.trigger('click')
    await flushPromises()
    expect(wrapper.find('[role="menu"]').exists()).toBe(true)
    await goBack()
    expect(wrapper.find('[role="menu"]').exists()).toBe(false)
    expect(wrapper.find('.main').attributes('data-page')).toBe('profiles')

    await goBack()
    expect(wrapper.find('.main').attributes('data-page')).toBe('home')
  })

  it('closes a dialog on back and keeps the page history for the next back', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="logs"]').trigger('click')
    await flushPromises()
    await openPalette()
    expect(document.body.querySelector('.palette')).not.toBeNull()

    await goBack()
    expect(document.body.querySelector('.palette')).toBeNull()
    expect(wrapper.find('.main').attributes('data-page')).toBe('logs')

    await goBack()
    expect(wrapper.find('.main').attributes('data-page')).toBe('home')
  })

  it('keeps one control for connect, disconnect and add-config', async () => {
    const { wrapper } = await mountApp()
    const power = wrapper.find('[data-testid="power"]')
    expect(power.element.tagName).toBe('BUTTON')
    expect(power.find('.connect-glyph .icon').exists()).toBe(true)
    expect(power.text()).toBe('连接')
    // The glyph and the label live in the same button; no second connect entry exists.
    const duplicate = wrapper
      .findAll('.home button')
      .filter((button) => button.element !== power.element && ['连接', '断开'].includes(button.text().trim()))
    expect(duplicate).toHaveLength(0)

    await power.trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="power"]').text()).toBe('断开')
    expect(wrapper.find('[data-testid="rates"]').exists()).toBe(true)

    wrapper.unmount()
    const welcome = await mountApp({ profiles: false }, 390)
    expect(welcome.wrapper.find('[data-testid="power"]').text()).toBe('添加配置')
  })

  it('reports Android VPN state in the hero instead of a second, disabled switch', async () => {
    const { wrapper } = await mountApp({ platform: 'android' }, 390)
    expect(wrapper.find('[data-testid="toggle-vpn"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="takeover-card"]').exists()).toBe(false)
    expect(wrapper.findAll('[data-testid="power"]')).toHaveLength(1)
    expect(wrapper.find('[data-testid="hero-eyebrow"]').text()).toBe('代理未运行')

    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="hero-eyebrow"]').text()).toBe('VPN 已接管设备流量')
  })

  it('shows the mode row with one live sentence on phones and desktop alike', async () => {
    for (const width of [390, 1200]) {
      const { wrapper } = await mountApp({}, width)
      const segments = wrapper.findAll('[data-testid="mode-segmented"] .segment')
      expect(segments.map((segment) => segment.text())).toEqual(['规则', '全局', '直连'])
      const hint = wrapper.find('[data-testid="mode-hint"]')
      expect(hint.attributes('aria-live')).toBe('polite')
      expect(hint.text()).toBe('按配置中的规则分流')

      await wrapper.find('[data-testid="mode-segmented"] [data-value="direct"]').trigger('click')
      await settle(300)
      expect(wrapper.find('[data-testid="mode-hint"]').text()).toBe('新连接都不经过代理')
      expect(wrapper.find('[data-testid="mode-segmented"] [data-value="direct"]').attributes('aria-checked')).toBe('true')
      wrapper.unmount()
    }
  })

  it('shows only the welcome, add-config and import hint without a profile', async () => {
    const { wrapper } = await mountApp({ profiles: false }, 390)
    expect(wrapper.find('[data-testid="welcome"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="status"]').text()).toBe('欢迎使用 Billow')
    expect(wrapper.find('[data-testid="power"]').text()).toBe('添加配置')
    expect(wrapper.find('[data-testid="import-hint"]').text()).toContain('YAML')
    for (const id of ['mode-card', 'takeover-card', 'traffic-card', 'groups-card', 'profile-card', 'runtime']) {
      expect(wrapper.find(`[data-testid="${id}"]`).exists()).toBe(false)
    }
  })

  it('shows the connect failure with retry and clears it after the retry succeeds', async () => {
    const { wrapper, backend } = await mountApp()
    const original = backend.connect
    let calls = 0
    backend.connect = vi.fn(async () => {
      calls += 1
      if (calls === 1) throw new Error('内核没有启动')
      return original()
    })

    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    const banner = wrapper.find('[data-testid="home-failure"]')
    expect(banner.exists()).toBe(true)
    expect(banner.text()).toContain('内核没有启动')
    expect(banner.text()).toContain('重试')
    expect(banner.text()).toContain('查看日志')
    expect(wrapper.find('[data-testid="status"]').text()).toBe('未连接')

    await wrapper.find('[data-testid="retry"]').trigger('click')
    await settle(1500)
    expect(backend.connect).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[data-testid="home-failure"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="status"]').text()).toBe('已连接')
  })

  it('retries the failed mode switch with the same mode', async () => {
    const { wrapper, backend } = await mountApp()
    const original = backend.setMode
    let calls = 0
    backend.setMode = vi.fn(async (mode: Parameters<typeof original>[0]) => {
      calls += 1
      if (calls === 1) throw new Error('模式没有切换')
      return original(mode)
    })

    await wrapper.find('[data-testid="mode-segmented"] [data-value="direct"]').trigger('click')
    await settle(300)
    expect(wrapper.find('[data-testid="home-failure"]').text()).toContain('模式没有切换')
    expect(wrapper.find('[data-testid="home-failure"]').text()).toContain('重试')

    await wrapper.find('[data-testid="retry"]').trigger('click')
    await settle(300)
    expect(backend.setMode).toHaveBeenCalledTimes(2)
    expect(backend.setMode).toHaveBeenLastCalledWith('direct')
    expect(wrapper.find('[data-testid="home-failure"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="mode-segmented"] [data-value="direct"]').attributes('aria-checked')).toBe('true')
  })

  it('hides runtime rows the kernel does not report and never shows a dash', async () => {
    const demo = createDemoBackend()
    const readState = demo.state
    demo.state = async () => ({ ...(await readState.call(demo)), kernel_memory: null, kernel_uptime_secs: null })
    vi.useFakeTimers()
    const wrapper = mount(App, { props: { backend: demo, width: 1200 }, attachTo: document.body })
    mounted.push(wrapper)
    await settle(50)
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)

    expect(wrapper.find('[data-testid="runtime-kernel"]').text()).toContain('v1.19.17')
    expect(wrapper.find('[data-testid="runtime-connections"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="runtime-memory"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="runtime-uptime"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="runtime"]').text()).not.toContain('—')
    wrapper.unmount()

    const full = await mountApp()
    await full.wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    expect(full.wrapper.find('[data-testid="runtime-memory"]').text()).toContain('128 MB')
    expect(full.wrapper.find('[data-testid="runtime-uptime"]').text()).toBeTruthy()
  })

  it('orders the phone first screen before the mode switch', async () => {
    const { wrapper } = await mountApp({}, 390)
    const layout = wrapper.findAll('.home-layout > *').map((element) => element.attributes('data-testid') ?? element.classes()[0])
    expect(layout).toEqual(['home-status', 'home-columns'])
    // The connect control lives inside the hero, next to the state it changes.
    expect(wrapper.find('[data-testid="home-status"] [data-testid="home-action"] [data-testid="power"]').exists()).toBe(true)
    // Mode and takeover share one control card, mode first.
    const control = wrapper.findAll('[data-testid="control-card"] > *').map((element) => element.attributes('data-testid'))
    expect(control).toEqual(['mode-card', 'takeover-card'])

    // Live traffic and runtime live inside the hero only, so no number is shown twice.
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    for (const id of ['rates', 'traffic-card', 'runtime']) {
      expect(wrapper.find(`[data-testid="home-status"] [data-testid="${id}"]`).exists()).toBe(true)
    }
    expect(wrapper.find('[data-testid="home-status"]').text()).toContain('星河云')
    expect(wrapper.find('[data-testid="groups-card"]').text()).toContain('查看全部')
  })

  it('offers a retry when disconnecting fails', async () => {
    const { wrapper, backend } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="status"]').text()).toBe('已连接')

    const original = backend.disconnect
    let calls = 0
    backend.disconnect = vi.fn(async () => {
      calls += 1
      if (calls === 1) throw new Error('系统代理没有关闭')
      return original()
    })

    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="home-failure"]').text()).toContain('系统代理没有关闭')
    expect(wrapper.find('[data-testid="status"]').text()).toBe('已连接')

    await wrapper.find('[data-testid="retry"]').trigger('click')
    await settle(1500)
    expect(backend.disconnect).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[data-testid="home-failure"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="status"]').text()).toBe('未连接')
  })

  it('replaces the spinning refresh glyph with update progress text', async () => {
    const { wrapper } = await mountApp()
    const button = () => wrapper.find('[data-testid="update-subscription"]')
    expect(button().text()).toBe('更新')
    await button().trigger('click')
    await settle(100)
    expect(button().text()).toContain('更新中')
    expect(button().attributes('aria-busy')).toBe('true')
    expect(button().find('.spin').exists()).toBe(false)
    await settle(1200)
    expect(button().text()).toBe('更新')
    expect(button().attributes('aria-busy')).toBeUndefined()
  })

  it('opens the current manual group on the first proxy visit and restores the saved set', async () => {
    localStorage.clear()
    const card = (wrapper: Awaited<ReturnType<typeof mountApp>>['wrapper'], name: string) =>
      wrapper.find(`[data-group-card="${name}"]`).classes()

    const first = await mountApp()
    await first.wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(card(first.wrapper, '节点选择')).toContain('open')
    expect(card(first.wrapper, '流媒体')).not.toContain('open')

    await first.wrapper.find('[data-group-card="节点选择"] .group-toggle').trigger('click')
    await first.wrapper.find('[data-group-card="流媒体"] .group-toggle').trigger('click')
    await flushPromises()
    expect(card(first.wrapper, '节点选择')).not.toContain('open')
    expect(card(first.wrapper, '流媒体')).toContain('open')
    first.wrapper.unmount()

    const second = await mountApp()
    await second.wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(card(second.wrapper, '流媒体')).toContain('open')
    expect(card(second.wrapper, '节点选择')).not.toContain('open')
    second.wrapper.unmount()

    localStorage.setItem('billow:proxy-open', '{ this is not json')
    const third = await mountApp()
    await third.wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(card(third.wrapper, '节点选择')).toContain('open')
    third.wrapper.unmount()

    localStorage.setItem('billow:proxy-open', JSON.stringify(['已删除的组']))
    const fourth = await mountApp()
    await fourth.wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(card(fourth.wrapper, '节点选择')).toContain('open')
  })

  it('locates the group requested from home and drops a filter that hides it', async () => {
    const { wrapper } = await mountApp()
    const scroll = recordScrollTargets()
    try {
      await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
      await flushPromises()
      await wrapper.find('[data-testid="toggle-hide-auto"]').trigger('click')
      await flushPromises()
      expect(wrapper.find('[data-group-card="自动选择"]').exists()).toBe(false)

      const store = (wrapper.vm as unknown as { store: Store }).store
      store.go('home')
      await flushPromises()
      store.go('proxies', '自动选择')
      await flushPromises()

      expect(wrapper.find('[data-group-card="自动选择"]').classes()).toContain('open')
      expect(wrapper.find('[data-testid="toggle-hide-auto"]').attributes('aria-pressed')).toBe('false')
      expect(scroll.targets).toContain('自动选择')
    } finally {
      scroll.restore()
    }
  })

  it('keeps a located group header below the sticky toolbar', async () => {
    localStorage.clear()
    const restoreRect = stubToolbarHeight(83)
    const scroll = recordScrollTargets()
    try {
      const first = await mountApp()
      await first.wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
      await flushPromises()
      // The default group already leads the list: no scroll, so the page head stays visible.
      expect(first.wrapper.find('[data-group-card]').attributes('data-group-card')).toBe('节点选择')
      expect(scroll.targets).not.toContain('节点选择')
      first.wrapper.unmount()

      localStorage.setItem('billow:proxy-open', JSON.stringify(['流媒体']))
      const second = await mountApp()
      await second.wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
      await flushPromises()
      await second.wrapper.find('.sidebar [data-page="home"]').trigger('click')
      await flushPromises()
      await second.wrapper.find('[data-testid="groups-card"] [data-group="流媒体"]').trigger('click')
      await flushPromises()
      const target = second.wrapper.find('[data-group-card="流媒体"]').element as HTMLElement
      expect(target.style.scrollMarginTop).toBe('95px')
      expect(scroll.targets).toContain('流媒体')
    } finally {
      scroll.restore()
      restoreRect()
    }
  })

  it('lands on a group from home instantly and lets the located cue fade', async () => {
    localStorage.clear()
    const proto = Element.prototype as unknown as { scrollIntoView?: (options?: ScrollIntoViewOptions) => void }
    const original = proto.scrollIntoView
    const calls: (ScrollIntoViewOptions | undefined)[] = []
    proto.scrollIntoView = function (options?: ScrollIntoViewOptions) {
      calls.push(options)
    }
    try {
      const { wrapper } = await mountApp({}, 390)
      await wrapper.find('[data-testid="groups-card"] [data-group="OpenAI"]').trigger('click')
      await flushPromises()
      const card = () => wrapper.find('[data-group-card="OpenAI"]')
      expect(card().classes()).toEqual(expect.arrayContaining(['open', 'located']))
      // A page switch must not animate through every card above the target.
      expect(calls.at(-1)?.behavior).toBe('instant')
      await settle(1700)
      expect(card().classes()).not.toContain('located')
      expect(storeOf(wrapper).focusGroup.value).toBeNull()
    } finally {
      proto.scrollIntoView = original
    }
  })

  it('filters rules on phones through a themed sheet instead of the native picker', async () => {
    const { wrapper } = await mountApp({}, 390)
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    storeOf(wrapper).go('rules')
    await settle(400)
    const trigger = wrapper.find('[data-testid="rule-kind-filter"]')
    expect(trigger.element.tagName).toBe('BUTTON')
    await trigger.trigger('click')
    await flushPromises()
    const option = [...document.body.querySelectorAll<HTMLElement>('.option-row')].find((row) => row.textContent?.includes('GeoIP'))
    expect(option).toBeTruthy()
    option!.click()
    await flushPromises()
    expect(document.body.querySelector('.option-list')).toBeNull()
    expect(wrapper.find('[data-testid="rule-kind-filter"]').text()).toContain('GeoIP')
    const rows = wrapper.findAll('[data-testid="rule-row"]')
    expect(rows.length).toBeGreaterThan(0)
    expect(rows.every((row) => row.text().includes('GeoIP'))).toBe(true)
  })

  it('keeps an intentionally collapsed set when returning to the proxies page', async () => {
    localStorage.clear()
    const { wrapper } = await mountApp()
    const opened = () => wrapper.findAll('[data-group-card].open').map((card) => card.attributes('data-group-card'))
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(opened()).toEqual(['节点选择'])

    await wrapper.find('[data-group-card="节点选择"] .group-toggle').trigger('click')
    await flushPromises()
    expect(opened()).toEqual([])
    expect(JSON.parse(localStorage.getItem('billow:proxy-open') ?? 'null')).toEqual([])

    await wrapper.find('.sidebar [data-page="home"]').trigger('click')
    await flushPromises()
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(opened()).toEqual([])
    expect(JSON.parse(localStorage.getItem('billow:proxy-open') ?? 'null')).toEqual([])
  })

  it('counts nodes shared by several groups once in the page summary', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('.page-head p').text()).toBe('7 个代理组 · 23 个节点')
  })

  it('highlights search matches and reports how many nodes match', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-testid="node-search"]').setValue('新加坡')
    await flushPromises()

    expect(wrapper.find('[data-testid="match-count"]').text()).toBe('匹配 10 个节点')
    const marks = wrapper.findAll('[data-group-card] mark')
    expect(marks).toHaveLength(10)
    expect(marks.every((mark) => mark.text() === '新加坡')).toBe(true)

    await wrapper.find('[data-testid="clear-search"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="match-count"]').exists()).toBe(false)
    expect(wrapper.findAll('[data-group-card] mark')).toHaveLength(0)
    expect(wrapper.findAll('[data-group-card="节点选择"] [data-node]')).toHaveLength(22)
  })

  it('selects a manual node with Space while auto-group rows stay inert', async () => {
    const { wrapper, backend } = await mountApp()
    const select = vi.spyOn(backend, 'selectNode')
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()

    const manual = wrapper.find('[data-group-card="节点选择"] [data-node="日本 02"] .node-select')
    expect(manual.element.tagName).toBe('BUTTON')
    press(manual.element, ' ')
    await settle(200)
    expect(select).toHaveBeenCalledWith('节点选择', '日本 02')
    expect(wrapper.find('[data-group-card="节点选择"] [data-node="日本 02"]').classes()).toContain('selected')

    await wrapper.find('[data-group-card="自动选择"] .group-toggle').trigger('click')
    await flushPromises()
    const auto = wrapper.find('[data-group-card="自动选择"] [data-node="香港 01"] .node-select')
    expect(auto.attributes('aria-disabled')).toBe('true')
    expect(auto.attributes('tabindex')).toBe('-1')
    await auto.trigger('click')
    await settle(100)
    expect(select).toHaveBeenCalledTimes(1)
  })

  it('shows test-all progress and marks only failed nodes as timed out', async () => {
    const { wrapper } = await mountApp()
    const store = (wrapper.vm as unknown as { store: Store }).store
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="test-hint"]').exists()).toBe(false)
    expect(wrapper.find('[data-group-card="节点选择"] .group-tested').exists()).toBe(false)

    await wrapper.find('[data-testid="test-all"]').trigger('click')
    await settle(400)
    const progress = wrapper.find('[data-testid="test-progress"]')
    expect(progress.exists()).toBe(true)
    expect(progress.text()).toMatch(/^已测 \d+\/23$/)
    expect(progress.text()).not.toBe('已测 23/23')
    // Live stream results drive the rows while the test runs.
    expect(Object.keys(store.testResults.value).length).toBeGreaterThan(0)

    await settle(1600)
    // The counter only lives while the run does; a summary toast reports the result.
    expect(wrapper.find('[data-testid="test-progress"]').exists()).toBe(false)
    expect(wrapper.find('.toasts').text()).toMatch(/测速完成：\d+ 个可用/)
    expect(wrapper.find('[data-group-card="节点选择"] [data-node="新加坡 01"] .delay').text()).toBe('超时')
    expect(wrapper.find('[data-group-card="节点选择"] [data-node="香港 01"] .delay').text()).toMatch(/^\d+ ms$/)
    expect(wrapper.find('[data-group-card="节点选择"] .group-tested').text()).toContain('测速')
    // The overlay is dropped so later polled delays are not shadowed by old ones.
    expect(store.testResults.value).toEqual({})
    expect(store.testTimes.value['香港 01']).toBeGreaterThan(0)
  })

  it('does not claim a test time when the kernel only reports it is unavailable', async () => {
    const { wrapper } = await mountApp()
    const store = (wrapper.vm as unknown as { store: Store }).store
    store.go('proxies')
    await flushPromises()

    const pending = store.testAll()
    await settle(100)
    await pending
    await flushPromises()
    expect(store.testTimes.value).toEqual({})
    expect(store.testResults.value).toEqual({})
    expect(wrapper.find('[data-group-card] .group-tested').exists()).toBe(false)
    expect(wrapper.find('[data-testid="test-progress"]').exists()).toBe(false)
  })

  it('tests one group without toggling it and stamps the header result time', async () => {
    const { wrapper, backend } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    const groupTest = vi.spyOn(backend, 'testGroup')

    await wrapper.find('[data-testid="test-group-节点选择"]').trigger('click')
    await settle(900)
    expect(groupTest).toHaveBeenCalledWith('节点选择')
    expect(wrapper.find('[data-group-card="节点选择"]').classes()).toContain('open')
    const tested = wrapper.find('[data-group-card="节点选择"] .group-tested')
    expect(tested.exists()).toBe(true)
    expect(tested.text()).toContain('测速')
  })

  it('renders configured group icons and falls back to the type glyph', async () => {
    const { wrapper } = await mountApp()
    const homeIcon = wrapper.find('[data-testid="groups-card"] [data-group="流媒体"] .group-icon img')
    expect(homeIcon.exists()).toBe(true)
    expect(homeIcon.attributes('src')).toBe('https://icons.example.com/media.png')
    expect(homeIcon.attributes('alt')).toBe('')
    expect(homeIcon.attributes('aria-hidden')).toBe('true')
    expect(homeIcon.attributes('tabindex')).toBeUndefined()
    expect(wrapper.find('[data-testid="groups-card"] [data-group="流媒体"] .group-icon').attributes('style')).toContain('width: 20px')

    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    const media = wrapper.find('[data-group-card="流媒体"] .group-toggle img')
    expect(media.exists()).toBe(true)
    expect(media.attributes('src')).toBe('https://icons.example.com/media.png')
    expect(media.attributes('loading')).toBe('lazy')
    expect(media.attributes('decoding')).toBe('async')
    expect(wrapper.find('[data-group-card="流媒体"] .group-toggle .group-icon').attributes('style')).toContain('width: 24px')

    const unreachable = wrapper.find('[data-group-card="国内网站"] .group-toggle img')
    expect(unreachable.attributes('src')).toBe('https://unreachable.invalid/cn.png')
    await unreachable.trigger('error')
    await nextTick()
    const fallback = wrapper.find('[data-group-card="国内网站"] .group-toggle .group-icon svg path')
    expect(fallback.exists()).toBe(true)
    expect(fallback.attributes('d')).toContain('M6 19a2 2')
  })

  it('swaps a group icon with the config URL and picks a fallback glyph per group type', async () => {
    const view = mount(GroupIcon, { props: { icon: 'https://a.example.com/a.png', type: 'relay', size: 24 } })
    expect(view.find('img').attributes('src')).toBe('https://a.example.com/a.png')
    await view.find('img').trigger('error')
    expect(view.find('svg path').attributes('d')).toContain('m12 3 9 5')
    await view.setProps({ icon: 'data:image/png;base64,AAAA' })
    expect(view.find('img').attributes('src')).toBe('data:image/png;base64,AAAA')
    view.unmount()

    for (const [type, shape] of [
      ['select', 'M6 19a2 2'],
      ['selector', 'M6 19a2 2'],
      ['url-test', 'M9 3h6v5'],
      ['urltest', 'M9 3h6v5'],
      ['fallback', 'M9 3h6v5'],
      ['load-balance', 'M9 3h6v5'],
      ['relay', 'm12 3 9 5'],
      ['unknown', 'M12 21a9 9'],
    ] as const) {
      const icon = mount(GroupIcon, { props: { type, size: 20 } })
      expect(icon.attributes('style')).toContain('width: 20px')
      expect(icon.find('svg path').attributes('d')).toContain(shape)
      icon.unmount()
    }
  })

  it('shows protocol and capability tags quietly and finds nodes by tag', async () => {
    const { wrapper } = await mountApp()
    await openPage(wrapper, 'proxies')
    const meta = wrapper.find('[data-group-card="节点选择"] [data-node="香港 01"] [data-testid="node-meta"]')
    expect(meta.findAll('.node-tag').map((tag) => tag.text())).toEqual(['UDP', 'Reality', 'Vision'])
    expect(meta.attributes('title')).toBe('VLESS · UDP · Reality · Vision')
    expect(meta.find('.node-tag.udp').exists()).toBe(true)

    await wrapper.find('[data-testid="node-search"]').setValue('grpc')
    await flushPromises()
    const names = wrapper.findAll('[data-group-card="节点选择"] [data-node]').map((node) => node.attributes('data-node'))
    expect(names.length).toBeGreaterThan(0)
    for (const name of names) expect(['日本 02', '美国 02', '德国 02']).toContain(name)
  })

  it('opens provider details: nodes with tags, rules, and a notice for binary sets', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(wrapper, 'resources')
    await settle(400)

    await wrapper.find('[data-testid="open-provider-机场订阅"]').trigger('click')
    await settle(300)
    const sheet = () => document.body.querySelector('[data-testid="provider-detail"]')
    expect(sheet()?.querySelectorAll('.detail-proxy')).toHaveLength(19)
    expect(sheet()?.querySelector('.detail-proxy .node-tag.udp')?.textContent).toBe('UDP')
    const search = sheet()!.querySelector<HTMLInputElement>('input[type="search"]')!
    search.value = 'grpc'
    search.dispatchEvent(new Event('input', { bubbles: true }))
    await nextTick()
    expect(sheet()?.querySelectorAll('.detail-proxy').length).toBeGreaterThan(0)
    for (const row of sheet()!.querySelectorAll('.detail-proxy')) expect(row.textContent).toContain('gRPC')
    // The work action leads the footer; closing is the quiet secondary button.
    expect(document.body.querySelector('.modal-foot .btn.primary')?.textContent).toContain('健康检查')
    bodyClick('[data-testid="close-provider-detail"]')
    await flushPromises()

    await wrapper.find('[data-testid="open-provider-private"]').trigger('click')
    await settle(300)
    expect(sheet()?.querySelectorAll('.detail-rules li')).toHaveLength(6)
    expect(sheet()?.querySelector('.detail-rules .rule-type')?.textContent).toBe('DOMAIN-SUFFIX')
    // Inline sets have nothing to fetch, so no update action is offered.
    expect(document.body.querySelector('.modal-foot .btn.primary')).toBeNull()
    bodyClick('[data-testid="close-provider-detail"]')
    await flushPromises()

    await wrapper.find('[data-testid="open-provider-cn-domains"]').trigger('click')
    await settle(300)
    expect(document.body.querySelector('[data-testid="provider-notice"]')?.textContent).toContain('MRS')
  })

  it('discards provider results and an open detail after the kernel stops', async () => {
    const { wrapper, backend } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(wrapper, 'resources')
    await settle(400)
    let finish!: (value: Awaited<ReturnType<typeof backend.providers>>) => void
    vi.spyOn(backend, 'providers').mockImplementationOnce(() => new Promise((resolve) => { finish = resolve }))
    await wrapper.find('[data-testid="refresh-providers"]').trigger('click')
    const store = storeOf(wrapper)
    store.stop()
    store.snapshot.value = { ...store.snapshot.value, kernel_running: false }
    await nextTick()
    finish({ providers: [{ name: 'obsolete', kind: 'proxy' } as never], error: null })
    await flushPromises()
    expect(wrapper.find('[data-provider="obsolete"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('内核未运行')
  })

  it('summarises GEO on one strip and keeps per-file updates and options in the GEO sheet', async () => {
    const { wrapper, backend } = await mountApp()
    const save = vi.spyOn(backend, 'saveSettings')
    const upgrade = vi.spyOn(backend, 'upgradeGeo')
    await openPage(wrapper, 'resources')
    await settle(300)
    const items = wrapper.findAll('[data-testid="geo-files"] li')
    expect(items.map((item) => item.find('strong').text())).toEqual(['GeoIP', 'GeoSite', 'MMDB', 'ASN'])
    expect(items[3].text()).toContain('未下载')
    expect(wrapper.find('[data-testid="geo-summary"]').text()).toContain('1 个尚未下载')
    expect(wrapper.find('[data-testid="upgrade-geo"]').attributes('disabled')).toBeUndefined()
    // Options stay out of the page until asked for.
    expect(document.body.querySelector('[data-testid="geo-settings"]')).toBeNull()

    await wrapper.find('[data-testid="open-geo-settings"]').trigger('click')
    await flushPromises()
    const q = <T extends HTMLElement = HTMLElement>(selector: string) => document.body.querySelector<T>(selector)!
    expect(q('[data-testid="geo-settings"]')).not.toBeNull()

    // Download ASN individually while disconnected: turns "尚未下载" into downloaded size/time
    q('[data-testid="upgrade-geo-asn"]').click()
    await settle(500)
    expect(upgrade).toHaveBeenCalledWith('asn')
    expect(document.body.querySelectorAll('[data-testid="geo-file-list"] li')[3].textContent).not.toContain('尚未下载')
    expect(wrapper.find('[data-testid="geo-summary"]').text()).toContain('全部就绪')

    q('[data-testid="geodata-mode"] [data-value="db"]').click()
    await settle(200)
    expect(save).toHaveBeenLastCalledWith(expect.objectContaining({ geodata_mode: false }))

    q('[data-testid="geo-auto-update"]').click()
    await settle(500)
    expect(save).toHaveBeenLastCalledWith(expect.objectContaining({ geo_auto_update: true, geo_update_interval: 24 }))
    q('[data-testid="geo-source"] [data-value="jsdelivr"]').click()
    await settle(200)
    expect(save).toHaveBeenLastCalledWith(expect.objectContaining({ geo_source: 'jsdelivr', geo_auto_update: true }))

    // Configure an individual database URL and save it
    const asnUrlInput = q<HTMLInputElement>('[data-testid="geo-url-asn"]')
    asnUrlInput.value = 'https://mirror.example.com/ASN.mmdb'
    asnUrlInput.dispatchEvent(new Event('input'))
    asnUrlInput.dispatchEvent(new Event('blur'))
    await settle(300)
    expect(save).toHaveBeenLastCalledWith(
      expect.objectContaining({
        geo_urls: expect.objectContaining({ asn: 'https://mirror.example.com/ASN.mmdb' }),
      }),
    )
  })

  it('keeps every proxy toolbar control reachable on a 390px screen', async () => {
    const { wrapper } = await mountApp({}, 390)
    await wrapper.find('.tabbar [data-page="proxies"]').trigger('click')
    await flushPromises()
    const toolbar = wrapper.find('[data-testid="proxy-toolbar"]')
    expect(toolbar.exists()).toBe(true)
    expect(toolbar.find('[data-testid="node-search"]').exists()).toBe(true)
    // Sort and view options fold behind one button so the sticky bar is a single row.
    const options = toolbar.find('[data-testid="toggle-options"]')
    expect(options.attributes('aria-expanded')).toBe('false')
    expect(toolbar.find('[data-testid="toggle-dense"]').exists()).toBe(false)
    await options.trigger('click')
    expect(options.attributes('aria-expanded')).toBe('true')
    expect(toolbar.findAll('.segment')).toHaveLength(3)
    for (const id of ['toggle-hide-auto', 'toggle-dense', 'toggle-all']) {
      const button = toolbar.find(`[data-testid="${id}"]`)
      expect(button.exists()).toBe(true)
      expect(button.attributes('aria-label') ?? button.text()).toBeTruthy()
    }

    const head = wrapper.find('[data-group-card="节点选择"] .group-head')
    const buttons = head.findAll('button')
    expect(buttons).toHaveLength(2)
    for (const button of buttons) expect(button.findAll('button')).toHaveLength(0)
    expect(head.find('.group-toggle .group-icon').exists()).toBe(true)
    expect(head.find('.group-toggle .group-name strong').exists()).toBe(true)
  })

  it('keeps an open connection detail live, shows 已断开 and copies the summary', async () => {
    const demo = createDemoBackend()
    const read = demo.state
    let download = 2048
    let gone = false
    demo.state = async () => {
      const snap = await read.call(demo)
      const seed = snap.connections[0]
      if (!seed) return snap
      download += 1024 * 1024
      return {
        ...snap,
        connected: true,
        connections: gone
          ? []
          : [
              {
                ...seed,
                upload: 1024,
                download: seed.download + download,
                process: 'chrome',
                rule: 'Match',
                rule_payload: '',
                chains: ['节点选择', '香港 01'],
              },
            ],
        connection_total: gone ? 0 : 1,
      }
    }
    const wrapper = await mountWith(demo)
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(wrapper, 'connections')
    await settle(100)

    const row = wrapper.find('[data-testid="connection-row"]')
    expect(row.exists()).toBe(true)
    await row.trigger('click')
    await flushPromises()
    const modalText = () => document.body.querySelector('.modal')?.textContent ?? ''
    expect(modalText()).toContain('连接详情')

    const first = modalText()
    await storeOf(wrapper).refresh()
    await flushPromises()
    expect(modalText()).not.toBe(first)

    const clipboard = stubClipboard()
    bodyClick('[data-testid="copy-connection"]')
    await flushPromises()
    const copied = String(clipboard.mock.calls[0]?.[0] ?? '')
    expect(copied).toContain('主机')
    expect(copied).toContain('进程: chrome')
    expect(copied).toContain('规则: Match')
    expect(copied).toContain('代理链: 香港 01 → 节点选择')
    expect(copied).toMatch(/上传: [\d.]+ (B|KB|MB)/)
    expect(copied).toMatch(/下载: [\d.]+ (B|KB|MB)/)
    expect(copied).toMatch(/持续: \d+ (秒|分)/)

    gone = true
    await storeOf(wrapper).refresh()
    await flushPromises()
    const disconnected = document.body.querySelector('[data-testid="detail-disconnected"]')
    expect(disconnected?.textContent).toContain('已断开')
    expect(
      document.body.querySelector<HTMLButtonElement>('[data-testid="disconnect-connection"]')?.disabled,
    ).toBe(true)

    stubClipboard(false)
    bodyClick('[data-testid="copy-connection"]')
    await flushPromises()
    expect(wrapper.findAll('.toast.error').at(-1)?.text()).toContain('无法写入剪贴板')
  })

  it('freezes connections, totals and the count while paused and catches up on resume', async () => {
    const demo = createDemoBackend()
    const read = demo.state
    let extra = 0
    demo.state = async () => {
      const snap = await read.call(demo)
      extra += 1
      const seed = snap.connections[0]
      const added = seed ? [{ ...seed, id: `extra-${extra}`, host: `extra-${extra}.example.com` }] : []
      return {
        ...snap,
        connections: [...snap.connections, ...added],
        connection_total: snap.connection_total + 1,
      }
    }
    const wrapper = await mountWith(demo)
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(wrapper, 'connections')
    await settle(100)

    const summary = wrapper.find('[data-testid="connection-summary"]')
    await wrapper.find('[data-testid="pause-connections"]').trigger('click')
    await flushPromises()
    // The new-connection badge is the one field that is expected to grow while frozen.
    const frozen = summary.text().replace(/ · \d+ 条新连接/, '')
    expect(frozen).toContain('暂停于')
    expect(wrapper.find('[data-testid="pause-connections"]').attributes('aria-pressed')).toBe('true')

    await settle(3000)
    expect(summary.text().replace(/ · \d+ 条新连接/, '')).toBe(frozen)
    expect(wrapper.find('[data-testid="new-connections"]').text()).toMatch(/^\d+ 条新连接$/)

    await wrapper.find('[data-testid="pause-connections"]').trigger('click')
    await flushPromises()
    expect(summary.text()).not.toContain('暂停于')
    expect(wrapper.find('[data-testid="new-connections"]').exists()).toBe(false)
    expect(summary.text()).toContain(`${storeOf(wrapper).snapshot.value.connection_total} 个活动连接`)
  })

  it('shows upload, download and duration on phone connection cards', async () => {
    const { wrapper } = await mountApp({}, 390)
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await wrapper.find('.tabbar [data-page="settings"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-tool="connections"]').trigger('click')
    await settle(1100)

    const card = wrapper.find('.conn')
    expect(card.exists()).toBe(true)
    const traffic = card.find('[data-testid="connection-traffic"]').text()
    expect(traffic).toContain('↑')
    expect(traffic).toContain('↓')
    expect(traffic).toMatch(/\d+ (秒|分|时|天)/)
  })

  it('confirms before disconnecting every connection', async () => {
    const { wrapper, backend } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(wrapper, 'connections')
    await settle(1100)

    const close = vi.spyOn(backend, 'closeConnection')
    await wrapper.find('[data-testid="disconnect-all"]').trigger('click')
    await flushPromises()
    expect(document.body.textContent).toContain('已建立的连接会立即中断')
    bodyClick('[data-testid="cancel-disconnect-all"]')
    await flushPromises()
    expect(close).not.toHaveBeenCalled()
    expect(wrapper.findAll('[data-testid="connection-row"]').length).toBeGreaterThan(0)

    await wrapper.find('[data-testid="disconnect-all"]').trigger('click')
    await flushPromises()
    bodyClick('[data-testid="confirm-disconnect-all"]')
    await settle(200)
    expect(close).toHaveBeenCalledWith(null)
    expect(document.body.querySelector('.modal')).toBeNull()
    expect(wrapper.findAll('.toast.success').at(-1)?.text()).toContain('已断开全部连接')
  })

  it('distinguishes unconnected, empty and failed connection reads', async () => {
    const first = await mountApp()
    await openPage(first.wrapper, 'connections')
    expect(first.wrapper.text()).toContain('未连接')
    expect(first.wrapper.text()).toContain('立即连接')
    // The empty state connects in place instead of sending the user back home.
    await first.wrapper.find('[data-testid="empty-connect"]').trigger('click')
    await settle(1500)
    expect(first.wrapper.find('.main').attributes('data-page')).toBe('connections')
    expect(first.wrapper.find('[data-testid="connection-summary"]').text()).not.toBe('未连接')
    first.wrapper.unmount()

    const demo = createDemoBackend()
    const read = demo.state
    demo.state = async () => ({
      ...(await read.call(demo)),
      connected: true,
      kernel_running: true,
      connections: [],
      connection_total: 0,
    })
    const empty = await mountWith(demo)
    await openPage(empty, 'connections')
    expect(empty.text()).toContain('没有当前连接')

    const fail = await mountApp({ connectionsFailure: true })
    await fail.wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(fail.wrapper, 'connections')
    await settle(1100)
    expect(fail.wrapper.text()).toContain('读取失败')
    expect(fail.wrapper.find('[data-testid="retry-connections"]').exists()).toBe(true)
    expect(fail.wrapper.findAll('[data-testid="connection-row"]')).toHaveLength(0)
  })

  it('shows a rule skeleton before the first payload arrives', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await wrapper.find('.sidebar [data-page="rules"]').trigger('click')
    expect(wrapper.find('.skeleton').exists()).toBe(true)

    await settle(400)
    expect(wrapper.find('.skeleton').exists()).toBe(false)
    expect(wrapper.findAll('[data-testid="rule-row"]').length).toBeGreaterThan(0)
  })

  it('shows rule hits, sorts by them and disables a rule temporarily', async () => {
    const { wrapper, backend } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(wrapper, 'rules')
    await settle(400)

    expect(wrapper.find('[data-testid="rules-no-hits"]').exists()).toBe(false)
    expect(wrapper.findAll('[data-rule-hit]').length).toBeGreaterThan(5)
    await wrapper.find('.toolbar [data-value="hits"]').trigger('click')
    await flushPromises()
    expect(wrapper.findAll('[data-rule-hit]')[0].text()).toBe('1,204')

    await wrapper.find('[data-testid="rule-kind-filter"]').setValue('GeoIP')
    await flushPromises()
    expect(wrapper.findAll('[data-testid="rule-row"]')).toHaveLength(2)
    expect(
      wrapper.findAll('[data-testid="rule-row"]').every((item) => item.text().includes('GeoIP')),
    ).toBe(true)
    await wrapper.find('[data-testid="rule-proxy-filter"]').setValue('DIRECT')
    await flushPromises()
    expect(wrapper.findAll('[data-testid="rule-row"]')).toHaveLength(1)
    await wrapper.find('[data-testid="rule-kind-filter"]').setValue('all')
    await wrapper.find('[data-testid="rule-proxy-filter"]').setValue('all')
    await flushPromises()
    expect(wrapper.findAll('[data-testid="rule-row"]').length).toBeGreaterThan(5)

    const row = wrapper.findAll('[data-testid="rule-row"]')[0]
    const key = row.attributes('data-rule-key')!
    const toggle = vi.spyOn(backend, 'setRuleDisabled')
    await row.find('[data-testid="rule-toggle"]').trigger('click')
    await settle(300)
    expect(toggle).toHaveBeenCalledWith(key, true)

    const disabled = wrapper
      .findAll('[data-testid="rule-row"]')
      .find((item) => item.attributes('data-rule-key') === key)!
    expect(disabled.classes()).toContain('disabled')
    expect(disabled.text()).toContain('临时，重启后恢复')
    expect(disabled.find('[data-testid="rule-toggle"]').text()).toBe('启用')

    await wrapper
      .findAll('[data-testid="rule-row"]')
      .find((item) => item.attributes('data-rule-key') === key)!
      .find('[data-testid="rule-toggle"]')
      .trigger('click')
    await settle(300)
    const restored = wrapper
      .findAll('[data-testid="rule-row"]')
      .find((item) => item.attributes('data-rule-key') === key)!
    expect(restored.classes()).not.toContain('disabled')
    expect(toggle).toHaveBeenLastCalledWith(key, false)

    backend.setRuleDisabled = vi.fn(async () => {
      throw new Error('重载失败')
    })
    const other = wrapper.findAll('[data-testid="rule-row"]')[1]
    const otherKey = other.attributes('data-rule-key')!
    await other.find('[data-testid="rule-toggle"]').trigger('click')
    await settle(200)
    const untouched = wrapper
      .findAll('[data-testid="rule-row"]')
      .find((item) => item.attributes('data-rule-key') === otherKey)!
    expect(untouched.classes()).not.toContain('disabled')
    expect(wrapper.findAll('.toast.error').at(-1)?.text()).toContain('规则没有修改：重载失败')
  })

  it('hides the hit column when the kernel reports no hit data', async () => {
    const { wrapper } = await mountApp({ rulesExtra: false })
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(wrapper, 'rules')
    await settle(400)

    expect(wrapper.findAll('[data-rule-hit]')).toHaveLength(0)
    expect(wrapper.find('[data-testid="rules-no-hits"]').text()).toContain('不提供命中信息')
    expect(wrapper.find('.toolbar [data-value="hits"]').exists()).toBe(false)
  })

  it('freezes logs while paused, counts new lines and copies the chosen range', async () => {
    const demo = createDemoBackend()
    const read = demo.state
    let logs: LogLine[] = Array.from({ length: 20 }, (_, index) => ({
      level: index % 5 === 0 ? 'error' : 'info',
      message: `line-${index}`,
      time_ms: 1000 + index,
    }))
    demo.state = async () => ({ ...(await read.call(demo)), logs: logs.map((line) => ({ ...line })) })
    const wrapper = await mountWith(demo)
    await openPage(wrapper, 'logs')
    await flushPromises()
    expect(wrapper.findAll('.log-line')).toHaveLength(20)

    await wrapper.find('[data-testid="pause-logs"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="log-count"]').text()).toBe('20 条')
    const frozenHeader = wrapper.find('.page-head p').text()

    logs = [...logs, { level: 'error', message: 'new-line', time_ms: 2000 }]
    await storeOf(wrapper).refresh()
    await flushPromises()
    expect(wrapper.find('[data-testid="log-count"]').text()).toBe('20 条')
    expect(wrapper.find('.page-head p').text()).toBe(frozenHeader)
    expect(wrapper.find('[data-testid="log-new"]').text()).toBe('1')
    expect(wrapper.findAll('.log-line')).toHaveLength(20)

    const clipboard = stubClipboard()
    await wrapper.findAll('[data-testid="copy-log-line"]')[0].trigger('click')
    await flushPromises()
    expect(String(clipboard.mock.calls[0]?.[0])).toContain('line-0')

    await wrapper.find('.toolbar [data-value="error"]').trigger('click')
    await flushPromises()
    const visibleErrors = wrapper.findAll('[data-testid="copy-log-line"]').length
    expect(visibleErrors).toBe(4)
    await wrapper.find('[data-testid="copy-logs"]').trigger('click')
    await flushPromises()
    const copied = String(clipboard.mock.calls.at(-1)?.[0])
    expect(copied.split('\n')).toHaveLength(visibleErrors)
    expect(copied.split('\n').every((line) => line.includes('[error]'))).toBe(true)
    expect(copied).not.toContain('new-line')

    await wrapper.find('.toolbar [data-value="all"]').trigger('click')
    await wrapper.find('[data-testid="pause-logs"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="log-count"]').text()).toBe('21 条')
    expect(wrapper.find('[data-testid="log-paused"]').exists()).toBe(false)
    expect(wrapper.findAll('.log-line')).toHaveLength(21)
  })

  it('keeps follow-tail and user position at the 1000-line cap', async () => {
    const demo = createDemoBackend()
    const read = demo.state
    let logs: LogLine[] = Array.from({ length: 1000 }, (_, index) => ({
      level: 'info',
      message: `cap-${index}`,
      time_ms: 1000 + index,
    }))
    demo.state = async () => ({ ...(await read.call(demo)), logs: logs.map((line) => ({ ...line })) })
    const wrapper = await mountWith(demo)
    await openPage(wrapper, 'logs')
    await flushPromises()

    const scroller = () => wrapper.find('[data-testid="log-scroll"]')
    const element = () => scroller().element as HTMLElement
    let scrollTopValue = 0
    const layout = () => {
      const el = element()
      Object.defineProperty(el, 'scrollHeight', { value: 28000, configurable: true })
      Object.defineProperty(el, 'clientHeight', { value: 500, configurable: true })
      // Browsers clamp scrollTop to scrollHeight - clientHeight.
      Object.defineProperty(el, 'scrollTop', {
        configurable: true,
        get: () => scrollTopValue,
        set: (value: number) => {
          scrollTopValue = Math.max(0, Math.min(value, 28000 - 500))
        },
      })
    }
    const gap = () => Math.max(0, 28000 - element().scrollTop - 500)
    const appendOne = async (index: number) => {
      logs = [...logs.slice(1), { level: 'info', message: `cap-new-${index}`, time_ms: 9000 + index }]
      await storeOf(wrapper).refresh()
      await flushPromises()
      await nextTick()
    }

    layout()
    expect(wrapper.find('[data-testid="log-jump"]').exists()).toBe(false)

    // The count is pinned at 1000, so only a row-list watcher can re-pin the tail.
    // Leaving scrollTop short of the bottom proves the follow path actually ran.
    for (let index = 0; index < 3; index += 1) {
      await appendOne(index)
      expect(gap()).toBe(0)
      expect(wrapper.find('[data-testid="log-jump"]').exists()).toBe(false)
      expect(wrapper.findAll('.log-line')).toHaveLength(1000)
    }
    expect(wrapper.findAll('.log-line').at(-1)!.text()).toContain('cap-new-2')

    element().scrollTop = 1200
    await scroller().trigger('scroll')
    expect(wrapper.find('[data-testid="log-jump"]').exists()).toBe(true)
    await appendOne(3)
    expect(element().scrollTop).toBe(1200)
    expect(gap()).toBeGreaterThan(0)
    expect(wrapper.find('[data-testid="log-jump"]').exists()).toBe(true)

    // The jump control returns to the live tail.
    await wrapper.find('[data-testid="log-jump"]').trigger('click')
    await flushPromises()
    expect(gap()).toBe(0)
    expect(wrapper.find('[data-testid="log-jump"]').exists()).toBe(false)

    // Reaching the bottom re-engages follow, and the next append pins the tail again.
    element().scrollTop = 1200
    await scroller().trigger('scroll')
    element().scrollTop = 27500
    await scroller().trigger('scroll')
    await appendOne(4)
    expect(gap()).toBe(0)
    expect(wrapper.find('[data-testid="log-jump"]').exists()).toBe(false)
  })

  it('exports logs, toggles wrapping and confirms before clearing', async () => {
    const demo = createDemoBackend()
    const read = demo.state
    const originalClear = demo.clearLogs.bind(demo)
    let logs: LogLine[] = Array.from({ length: 20 }, (_, index) => ({
      level: index % 4 === 0 ? 'error' : 'info',
      message: `entry-${index}`,
      time_ms: 1000 + index,
    }))
    demo.state = async () => ({ ...(await read.call(demo)), logs: logs.map((line) => ({ ...line })) })
    demo.clearLogs = async () => {
      logs = []
      return originalClear()
    }
    const wrapper = await mountWith(demo)
    await openPage(wrapper, 'logs')
    await flushPromises()
    expect(wrapper.findAll('.log-line')).toHaveLength(20)

    const wrapToggle = wrapper.find('[data-testid="wrap-field"] .toggle')
    expect(wrapToggle.attributes('aria-checked')).toBe('true')
    expect(wrapper.find('[data-testid="log-scroll"]').classes()).not.toContain('no-wrap')
    await wrapToggle.trigger('click')
    expect(wrapper.find('[data-testid="log-scroll"]').classes()).toContain('no-wrap')

    const exported = vi.spyOn(demo, 'exportLogs')
    await wrapper.find('[data-testid="export-logs"]').trigger('click')
    await settle(200)
    expect(exported).toHaveBeenCalled()
    expect(wrapper.findAll('.toast').at(-1)?.text()).toContain('billow-logs')

    await wrapper.find('[data-testid="clear-logs"]').trigger('click')
    await flushPromises()
    expect(document.body.textContent).toContain('操作无法撤销')
    bodyClick('[data-testid="cancel-clear-logs"]')
    await flushPromises()
    expect(wrapper.findAll('.log-line').length).toBeGreaterThan(0)

    await wrapper.find('[data-testid="clear-logs"]').trigger('click')
    await flushPromises()
    bodyClick('[data-testid="confirm-clear-logs"]')
    await settle(50)
    expect(wrapper.find('[data-testid="log-count"]').text()).toBe('0 条')
    expect(wrapper.text()).toContain('暂无日志')
  })

  it('keeps the log scroll still when lines append while scrolled up', async () => {
    const demo = createDemoBackend()
    const read = demo.state
    let logs: LogLine[] = Array.from({ length: 50 }, (_, index) => ({
      level: 'info',
      message: `m-${index}`,
      time_ms: 1000 + index,
    }))
    demo.state = async () => ({ ...(await read.call(demo)), logs: logs.map((line) => ({ ...line })) })
    const wrapper = await mountWith(demo)
    await openPage(wrapper, 'logs')
    await flushPromises()

    const scroller = wrapper.find('[data-testid="log-scroll"]')
    const element = scroller.element as HTMLElement
    Object.defineProperty(element, 'scrollHeight', { value: 4000, configurable: true })
    Object.defineProperty(element, 'clientHeight', { value: 500, configurable: true })
    element.scrollTop = 1200
    await scroller.trigger('scroll')
    expect(wrapper.find('[data-testid="log-jump"]').exists()).toBe(true)

    logs = [...logs, { level: 'info', message: 'tail', time_ms: 2000 }]
    await storeOf(wrapper).refresh()
    await flushPromises()
    expect(wrapper.findAll('.log-line')).toHaveLength(51)
    expect((wrapper.find('[data-testid="log-scroll"]').element as HTMLElement).scrollTop).toBe(1200)
    expect(wrapper.find('[data-testid="log-jump"]').exists()).toBe(true)
  })

  it('keeps a 1000-line log buffer usable for filtering', async () => {
    const demo = createDemoBackend()
    const read = demo.state
    const logs: LogLine[] = Array.from({ length: 1000 }, (_, index) => ({
      level: index % 10 === 0 ? 'warning' : 'info',
      message: `bulk-${index}`,
      time_ms: 1000 + index,
    }))
    demo.state = async () => ({ ...(await read.call(demo)), logs: logs.map((line) => ({ ...line })) })
    const wrapper = await mountWith(demo)
    await openPage(wrapper, 'logs')
    await flushPromises()
    expect(wrapper.findAll('.log-line')).toHaveLength(1000)
    expect(wrapper.find('[data-testid="log-count"]').text()).toBe('1000 条')

    await wrapper.find('.toolbar [data-value="warning"]').trigger('click')
    await flushPromises()
    expect(wrapper.findAll('.log-line')).toHaveLength(100)

    await wrapper.find('.toolbar [data-value="all"]').trigger('click')
    await flushPromises()
    expect(wrapper.findAll('.log-line')).toHaveLength(1000)
  })

  it('keeps log row keys stable when the capped buffer trims from the front', async () => {
    const demo = createDemoBackend()
    const read = demo.state
    const logs: LogLine[] = Array.from({ length: 1005 }, (_, index) => ({
      level: 'info',
      message: `row-${index}`,
      time_ms: 1000 + index,
    }))
    logs.push({ level: 'info', message: 'repeat', time_ms: 4000 })
    logs.push({ level: 'info', message: 'repeat', time_ms: 4000 })
    demo.state = async () => ({ ...(await read.call(demo)), logs: logs.map((line) => ({ ...line })) })
    const wrapper = await mountWith(demo)
    await openPage(wrapper, 'logs')
    await flushPromises()

    const repeats = wrapper.findAll('[data-log-key^="4000|info|repeat#"]')
    expect(repeats.map((row) => row.attributes('data-log-key'))).toEqual([
      '4000|info|repeat#0',
      '4000|info|repeat#1',
    ])

    const target = wrapper.find('[data-log-key="1900|info|row-900#0"]')
    expect(target.exists()).toBe(true)
    const element = target.element

    logs.splice(0, 10)
    await storeOf(wrapper).refresh()
    await flushPromises()
    expect(wrapper.findAll('.log-line')).toHaveLength(997)
    const moved = wrapper.find('[data-log-key="1900|info|row-900#0"]')
    expect(moved.exists()).toBe(true)
    // The surviving row keeps its DOM node even though its index shifted by ten.
    expect(moved.element).toBe(element)
  })

  it('labels inline providers as no-update and retries a failed row in place', async () => {
    const { wrapper, backend } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(wrapper, 'resources')
    await settle(500)

    const inline = wrapper.find('[data-provider="private"]')
    expect(inline.text()).toContain('无需更新')
    expect(inline.findAll('.provider-actions button')).toHaveLength(1)
    expect(inline.find('.provider-actions button').attributes('disabled')).not.toBeUndefined()

    const action = vi.spyOn(backend, 'providerAction')
    action.mockImplementationOnce(async () => {
      await new Promise((resolve) => setTimeout(resolve, 300))
      throw new Error('订阅地址不可达')
    })
    const row = wrapper.find('[data-provider="机场订阅"]')
    await row.findAll('button').at(-1)!.trigger('click')
    await flushPromises()
    expect(
      wrapper.find('[data-provider="机场订阅"] [data-provider-state="pending"]').text(),
    ).toContain('更新中')
    await settle(400)
    expect(wrapper.find('[data-provider="机场订阅"] [data-provider-state="error"]').text()).toContain(
      '更新失败：订阅地址不可达',
    )
    expect(wrapper.find('[data-provider="自建节点"] [data-provider-state]').exists()).toBe(false)

    await wrapper.find('[data-provider="机场订阅"] [data-testid="retry-provider"]').trigger('click')
    await settle(1300)
    expect(wrapper.find('[data-provider="机场订阅"] [data-provider-state="success"]').text()).toContain('已更新')
    expect(wrapper.find('[data-provider="机场订阅"] [data-testid="retry-provider"]').exists()).toBe(false)
  })

  it('updates providers sequentially with a done/total counter', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(wrapper, 'resources')
    await settle(500)

    await wrapper.find('[data-testid="update-all-proxy"]').trigger('click')
    await settle(950)
    const button = wrapper.find('[data-testid="update-all-proxy"]')
    expect(button.text()).toContain('更新中 1/2')
    expect(button.attributes('aria-busy')).toBe('true')
    expect(wrapper.find('[data-provider="自建节点"] [data-provider-state="pending"]').exists()).toBe(true)

    await settle(2500)
    expect(wrapper.find('[data-testid="update-all-proxy"]').text()).toBe('全部更新')
    expect(wrapper.findAll('.toast').at(-1)?.text()).toContain('2/2')
  })

  it('keeps a health check on its own row', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(wrapper, 'resources')
    await settle(500)

    const row = wrapper.find('[data-provider="机场订阅"]')
    await row.findAll('.provider-actions button').at(0)!.trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-provider="机场订阅"] [data-provider-state="pending"]').text()).toContain('检查中')
    expect(wrapper.find('[data-provider="自建节点"] [data-provider-state]').exists()).toBe(false)

    await settle(1000)
    expect(wrapper.find('[data-provider="机场订阅"] [data-provider-state="success"]').text()).toContain('检查通过')
    expect(wrapper.find('[data-provider="自建节点"] [data-provider-state]').exists()).toBe(false)
  })

  it('shows a retry error and drops stale rows when providers cannot be read', async () => {
    const demo = createDemoBackend()
    const readProviders = demo.providers.bind(demo)
    demo.providers = async () => {
      throw new Error('读取规则集失败')
    }
    const wrapper = await mountWith(demo)
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(wrapper, 'resources')
    await settle(100)

    expect(wrapper.text()).toContain('读取失败')
    expect(wrapper.text()).toContain('读取规则集失败')
    expect(wrapper.findAll('[data-provider]')).toHaveLength(0)

    demo.providers = readProviders
    await wrapper.find('[data-testid="retry-providers"]').trigger('click')
    await settle(300)
    expect(wrapper.findAll('[data-provider]').length).toBeGreaterThan(0)
    expect(wrapper.text()).not.toContain('读取规则集失败')
  })

  it('reloads rules when the active profile changes and ignores a late previous response', async () => {
    const { wrapper, backend } = await mountApp()
    const store = storeOf(wrapper)
    store.stop()
    store.snapshot.value = { ...store.snapshot.value, kernel_running: true, active_id: 'first' }
    type Result = Awaited<ReturnType<typeof backend.rules>>
    let finishOld!: (value: Result) => void
    const pending = new Promise<Result>((resolve) => { finishOld = resolve })
    const result = (payload: string): Result => ({ rules: [{ kind: 'Domain', payload, proxy: 'DIRECT', hit_count: null,
      last_hit: null, key: payload, disabled: false }], error: null, disabled: [] })
    const read = vi.spyOn(backend, 'rules').mockReturnValueOnce(pending).mockResolvedValue(result('new.example'))
    await openPage(wrapper, 'rules')
    store.snapshot.value = { ...store.snapshot.value, active_id: 'second' }
    await flushPromises()
    expect(read).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('new.example')
    finishOld(result('old.example'))
    await flushPromises()
    expect(wrapper.text()).not.toContain('old.example')
    store.snapshot.value = { ...store.snapshot.value, upload: 123 }
    await flushPromises()
    expect(read).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('new.example')
  })

  it('windows 500 connections and 300 rules to keep the DOM small', async () => {
    const demo = createDemoBackend()
    const read = demo.state
    const now = Date.now()
    const connections: ConnectionRow[] = Array.from({ length: 500 }, (_, index) => ({
      id: `c${index}`,
      host: `host${index}.example.com`,
      outbound: '节点选择',
      network: 'tcp',
      conn_type: 'HTTP Connect',
      destination: `10.0.${Math.floor(index / 250)}.${index % 250}:443`,
      source: `127.0.0.1:${10000 + index}`,
      process: 'chrome',
      rule: 'Match',
      rule_payload: '',
      chains: ['节点选择'],
      upload: index,
      download: index * 10,
      start: new Date(now - index * 1000).toISOString(),
    }))
    demo.state = async () => ({
      ...(await read.call(demo)),
      connected: true,
      kernel_running: true,
      connections,
      connection_total: 500,
    })
    demo.rules = async () => ({
      rules: Array.from({ length: 300 }, (_, index) => ({
        kind: index % 2 ? 'DomainSuffix' : 'GeoIP',
        payload: `rule-${index}.com`,
        proxy: index % 3 ? '节点选择' : 'DIRECT',
        hit_count: index,
        last_hit: new Date(now - index * 60_000).toISOString(),
        key: `k${index}`,
        disabled: false,
      })),
      error: null,
      disabled: [],
    })

    const wrapper = await mountWith(demo)
    await openPage(wrapper, 'connections')
    const rendered = wrapper.findAll('[data-testid="connection-row"]')
    expect(rendered.length).toBeGreaterThan(10)
    expect(rendered.length).toBeLessThan(80)
    expect(wrapper.find('[data-testid="connection-summary"]').text()).toContain('500 个活动连接')

    const scroller = wrapper.find('[data-testid="connection-scroll"]')
    ;(scroller.element as HTMLElement).scrollTop = 4000
    await scroller.trigger('scroll')
    const firstIndex = Number(
      wrapper.find('[data-testid="connection-row"]').attributes('data-row-index'),
    )
    expect(firstIndex).toBeGreaterThan(80)

    await openPage(wrapper, 'rules')
    await settle(400)
    const rows = wrapper.findAll('[data-testid="rule-row"]')
    expect(rows.length).toBeGreaterThan(10)
    expect(rows.length).toBeLessThan(80)
    expect(wrapper.findAll('[data-rule-hit]').length).toBe(rows.length)
  })

  it('resets windowed lists after filters, empty states and a reconnect', async () => {
    const demo = createDemoBackend()
    const read = demo.state
    const now = Date.now()
    const connections: ConnectionRow[] = Array.from({ length: 200 }, (_, index) => ({
      id: `c${index}`,
      host: `${index < 120 ? 'keep' : 'other'}-${index}.example.com`,
      outbound: '节点选择',
      network: 'tcp',
      conn_type: 'HTTP Connect',
      destination: `10.0.0.${index % 250}:443`,
      source: `127.0.0.1:${11000 + index}`,
      process: 'chrome',
      rule: 'Match',
      rule_payload: '',
      chains: ['节点选择'],
      upload: index,
      download: index * 10,
      start: new Date(now - index * 1000).toISOString(),
    }))
    let online = true
    demo.state = async () => ({
      ...(await read.call(demo)),
      connected: online,
      kernel_running: online,
      connections: online ? connections : [],
      connection_total: online ? connections.length : 0,
    })
    demo.rules = async () => ({
      rules: Array.from({ length: 300 }, (_, index) => ({
        kind: index % 2 ? 'DomainSuffix' : 'GeoIP',
        payload: `rule-${index}.com`,
        proxy: index % 3 ? '节点选择' : 'DIRECT',
        hit_count: index,
        last_hit: new Date(now - index * 60_000).toISOString(),
        key: `k${index}`,
        disabled: false,
      })),
      error: null,
      disabled: [],
    })

    const wrapper = await mountWith(demo)
    await openPage(wrapper, 'connections')
    const scroller = () => wrapper.find('[data-testid="connection-scroll"]')
    ;(scroller().element as HTMLElement).scrollTop = 3000
    await scroller().trigger('scroll')
    expect(
      Number(wrapper.find('[data-testid="connection-row"]').attributes('data-row-index')),
    ).toBeGreaterThan(50)

    await wrapper.find('[data-testid="connection-search"]').setValue('keep')
    await flushPromises()
    expect((scroller().element as HTMLElement).scrollTop).toBe(0)
    expect(wrapper.find('[data-testid="connection-row"]').attributes('data-row-index')).toBe('0')

    await wrapper.find('[data-testid="connection-search"]').setValue('zzz-nothing')
    await flushPromises()
    expect(wrapper.text()).toContain('没有匹配的连接')
    await wrapper.find('[data-testid="clear-connection-filter"]').trigger('click')
    await flushPromises()
    expect(scroller().exists()).toBe(true)
    expect((scroller().element as HTMLElement).scrollTop).toBe(0)
    expect(wrapper.find('[data-testid="connection-row"]').attributes('data-row-index')).toBe('0')

    ;(scroller().element as HTMLElement).scrollTop = 3000
    await scroller().trigger('scroll')
    online = false
    await storeOf(wrapper).refresh()
    await flushPromises()
    expect(wrapper.text()).toContain('未连接')
    online = true
    await storeOf(wrapper).refresh()
    await flushPromises()
    await nextTick()
    expect((scroller().element as HTMLElement).scrollTop).toBe(0)
    expect(wrapper.find('[data-testid="connection-row"]').attributes('data-row-index')).toBe('0')

    await openPage(wrapper, 'rules')
    await settle(400)
    const ruleScroller = () => wrapper.find('[data-testid="rule-scroll"]')
    ;(ruleScroller().element as HTMLElement).scrollTop = 5000
    await ruleScroller().trigger('scroll')
    expect(
      Number(wrapper.find('[data-testid="rule-row"]').attributes('data-row-index')),
    ).toBeGreaterThan(50)

    await wrapper.find('[data-testid="rule-kind-filter"]').setValue('GeoIP')
    await flushPromises()
    expect((ruleScroller().element as HTMLElement).scrollTop).toBe(0)
    expect(wrapper.find('[data-testid="rule-row"]').attributes('data-row-index')).toBe('0')

    await wrapper.find('.toolbar input[type="search"]').setValue('nothing-matches')
    await flushPromises()
    expect(wrapper.text()).toContain('没有匹配的规则')
    await wrapper.find('[data-testid="clear-rule-filter"]').trigger('click')
    await flushPromises()
    expect(ruleScroller().exists()).toBe(true)
    expect(wrapper.find('[data-testid="rule-row"]').attributes('data-row-index')).toBe('0')
  })

  it('drops frozen rows and rules when the kernel stops', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    await openPage(wrapper, 'connections')
    await settle(1100)
    await wrapper.find('[data-testid="pause-connections"]').trigger('click')
    await flushPromises()

    await openPage(wrapper, 'home')
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(600)

    await openPage(wrapper, 'connections')
    expect(wrapper.text()).toContain('未连接')
    expect(wrapper.findAll('[data-testid="connection-row"]')).toHaveLength(0)
    // Nothing to pause or close while disconnected.
    expect(wrapper.find('[data-testid="pause-connections"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="disconnect-all"]').exists()).toBe(false)
    await wrapper.find('[data-testid="empty-connect"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('[data-testid="pause-connections"]').attributes('aria-pressed')).toBe('false')

    await openPage(wrapper, 'home')
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(600)
    await openPage(wrapper, 'rules')
    await settle(300)
    expect(wrapper.text()).toContain('内核未运行')
    expect(wrapper.findAll('[data-testid="rule-row"]')).toHaveLength(0)
  })

  it('opens the command palette from the sidebar, switches modes and copies terminal proxy env', async () => {
    const { wrapper, backend } = await mountApp()
    const clipboard = stubClipboard()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)

    // Home port button copies OS-aware proxy environment variables.
    await wrapper.find('[data-testid="copy-proxy-cmd"]').trigger('click')
    await flushPromises()
    expect(String(clipboard.mock.calls.at(-1)?.[0])).toContain('127.0.0.1:7890')

    // Sidebar trigger opens Command Palette and switches mode to Direct.
    const setMode = vi.spyOn(backend, 'setMode')
    await wrapper.find('[data-testid="open-palette"]').trigger('click')
    await flushPromises()
    await nextTick()
    expect(paletteInput()).not.toBeNull()
    paletteOption('action:mode-direct')?.click()
    await settle(200)
    expect(setMode).toHaveBeenCalledWith('direct')
    expect(wrapper.find('[data-testid="groups-card"]').classes()).toContain('direct-dim')
    expect(wrapper.find('[data-testid="groups-card"]').text()).toContain('直连中')
  })

  it('pauses toasts on hover and dismisses them on click', async () => {
    const { wrapper } = await mountApp()
    const store = storeOf(wrapper)
    store.toast('悬停暂停提示', 'info')
    await flushPromises()

    const toast = wrapper.find('.toast')
    expect(toast.exists()).toBe(true)
    await toast.trigger('mouseenter')
    await settle(4000)
    expect(wrapper.find('.toast').exists()).toBe(true)

    await wrapper.find('.toast').trigger('click')
    await flushPromises()
    expect(wrapper.find('.toast').exists()).toBe(false)
  })

  it('locates the active proxy node and pastes or clears quick subscription URLs', async () => {
    const { wrapper } = await mountApp()
    await openPage(wrapper, 'proxies')
    await flushPromises()

    // Collapse the first group, then click locate-active-node to re-expand and highlight it.
    await wrapper.find('[data-testid="group-toggle-节点选择"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-group-card="节点选择"]').classes()).not.toContain('open')

    await wrapper.find('[data-testid="locate-active-node"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-group-card="节点选择"]').classes()).toContain('open')
    expect(wrapper.find('[data-group-card="节点选择"] .node.located').exists()).toBe(true)

    // Quick-import clipboard paste and inline clear on Profiles.
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        readText: vi.fn(async () => 'https://sub.example.com/clash.yaml\n'),
        writeText: vi.fn(async () => undefined),
      },
      configurable: true,
    })
    await openPage(wrapper, 'profiles')
    await flushPromises()
    await wrapper.find('[data-testid="quick-paste"]').trigger('click')
    await flushPromises()
    const urlInput = wrapper.find('.quick-import input')
    expect((urlInput.element as HTMLInputElement).value).toBe('https://sub.example.com/clash.yaml')
    await wrapper.find('[data-testid="quick-clear"]').trigger('click')
    await flushPromises()
    expect((urlInput.element as HTMLInputElement).value).toBe('')
  })

  it('sorts connections by table headers, filters from connection detail and highlights rule/log matches', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)

    await openPage(wrapper, 'connections')
    await settle(1100)
    const hostHeader = wrapper.find('th .th-sort')
    await hostHeader.trigger('click')
    await flushPromises()
    expect(wrapper.find('th').attributes('aria-sort')).toBe('ascending')
    await hostHeader.trigger('click')
    await flushPromises()
    expect(wrapper.find('th').attributes('aria-sort')).toBe('descending')

    // Open connection detail and filter by host chip.
    await wrapper.find('[data-testid="connection-row"]').trigger('click')
    await flushPromises()
    const filterHostBtn = document.body.querySelector<HTMLButtonElement>('[data-testid="filter-conn-host"]')
    expect(filterHostBtn).not.toBeNull()
    filterHostBtn?.click()
    await flushPromises()
    expect((wrapper.find('[data-testid="connection-search"]').element as HTMLInputElement).value).not.toBe('')
    await wrapper.find('[data-testid="clear-connection-search"]').trigger('click')
    await flushPromises()
    expect((wrapper.find('[data-testid="connection-search"]').element as HTMLInputElement).value).toBe('')

    // Rules search highlight & inline clear.
    await openPage(wrapper, 'rules')
    await settle(400)
    await wrapper.find('.toolbar input[type="search"]').setValue('openai')
    await flushPromises()
    expect(wrapper.findAll('[data-testid="rule-row"] mark').length).toBeGreaterThan(0)
    await wrapper.find('[data-testid="clear-rule-search"]').trigger('click')
    await flushPromises()
    expect((wrapper.find('.toolbar input[type="search"]').element as HTMLInputElement).value).toBe('')

    // Logs search highlight & inline clear.
    await openPage(wrapper, 'logs')
    await flushPromises()
    const firstMsg = wrapper.find('.log-msg').text().slice(0, 4)
    if (firstMsg) {
      await wrapper.find('.toolbar input[type="search"]').setValue(firstMsg)
      await flushPromises()
      expect(wrapper.findAll('.log-msg mark').length).toBeGreaterThan(0)
      await wrapper.find('[data-testid="clear-log-search"]').trigger('click')
      await flushPromises()
      expect((wrapper.find('.toolbar input[type="search"]').element as HTMLInputElement).value).toBe('')
    }
  })

  it('preserves kernel port, TUN and DNS input drafts across polling ticks without resetting', async () => {
    const { wrapper, backend } = await mountApp()
    const saveSpy = vi.spyOn(backend, 'saveSettings')
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)

    await openPage(wrapper, 'settings')
    await wrapper.find('[data-testid="settings-tabs"] [data-value="kernel"]').trigger('click')
    await flushPromises()

    const portInput = wrapper.find('[data-testid="mixed-port-input"]')
    await portInput.trigger('focus')
    await portInput.setValue('7891')
    expect(wrapper.find('[data-testid="save-port"]').exists()).toBe(true)

    // Multiple 1s live-traffic polling ticks must never reset the focused or dirty port input.
    await settle(3500)
    expect((portInput.element as HTMLInputElement).value).toBe('7891')
    expect(wrapper.find('[data-testid="save-port"]').exists()).toBe(true)

    await wrapper.find('[data-testid="save-port"]').trigger('click')
    await settle(600)
    expect(saveSpy).toHaveBeenCalledWith(expect.objectContaining({ mixed_port: 7891 }))
    expect((portInput.element as HTMLInputElement).value).toBe('7891')
    expect(wrapper.find('[data-testid="save-port"]').exists()).toBe(false)

    // TUN drafts survive polling ticks too.
    await wrapper.find('[data-testid="settings-tabs"] [data-value="tun"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-testid="tun-settings"] [data-value="gvisor"]').trigger('click')
    const mtuInput = wrapper.find('input[aria-label="MTU"]')
    await mtuInput.setValue('1420')
    await settle(3500)
    expect((mtuInput.element as HTMLInputElement).value).toBe('1420')
    expect(wrapper.find('[data-testid="tun-settings"] [data-value="gvisor"]').attributes('aria-checked')).toBe('true')
    expect(wrapper.find('[data-testid="save-tun"]').exists()).toBe(true)
    await wrapper.find('[data-testid="save-tun"]').trigger('click')
    await settle(600)
    expect(saveSpy).toHaveBeenCalledWith(
      expect.objectContaining({ tun: expect.objectContaining({ stack: 'gvisor', mtu: 1420 }) }),
    )

    // DNS drafts survive polling ticks too.
    await wrapper.find('[data-testid="settings-tabs"] [data-value="dns"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-testid="dns-settings"] [data-value="redir-host"]').trigger('click')
    const nsInput = wrapper.find('textarea[aria-label="主 DNS 服务器"]')
    await nsInput.setValue('https://1.1.1.1/dns-query')
    await settle(3500)
    expect((nsInput.element as HTMLTextAreaElement).value).toBe('https://1.1.1.1/dns-query')
    expect(wrapper.find('[data-testid="save-dns"]').exists()).toBe(true)
    await wrapper.find('[data-testid="save-dns"]').trigger('click')
    await settle(600)
    expect(saveSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        dns: expect.objectContaining({ enhanced_mode: 'redir-host', nameserver: ['https://1.1.1.1/dns-query'] }),
      }),
    )
  })

  it('offers one-click jump to kernel port settings when a port conflict occurs', async () => {
    const conflictMsg =
      '端口 127.0.0.1:7890 已被其他程序占用，内核无法启动。请关闭占用它的程序（例如另一个 Clash / mihomo 客户端），或在设置中更换混合端口后重试。'
    const demo = createDemoBackend()
    const readState = demo.state.bind(demo)
    let conflicted = false
    demo.connect = async () => {
      conflicted = true
      throw new Error(conflictMsg)
    }
    demo.state = async () => {
      const snap = await readState()
      if (!conflicted) return snap
      return {
        ...snap,
        logs: [...snap.logs, { time_ms: Date.now(), level: 'error' as const, message: conflictMsg }],
      }
    }

    const wrapper = await mountWith(demo)
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)

    expect(wrapper.find('[data-testid="home-failure"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="failure-open-settings"]').text()).toBe('更换端口')

    await openPage(wrapper, 'logs')
    await settle(3200)
    expect(wrapper.find('[data-testid="log-conflict"]').exists()).toBe(true)
    await wrapper.find('[data-testid="logs-open-settings"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('settings')
    expect(wrapper.find('[data-testid="mixed-port-input"]').exists()).toBe(true)
  })

  it('jumps directly to a collapsed proxy group from the quick group strip on phones', async () => {
    const { wrapper } = await mountApp({}, 360)
    await wrapper.find('.tabbar [data-page="proxies"]').trigger('click')
    await flushPromises()

    const strip = wrapper.find('[data-testid="group-jump-bar"]')
    expect(strip.exists()).toBe(true)
    // Pick a group that starts collapsed
    const pills = strip.findAll('button')
    expect(pills.length).toBeGreaterThan(2)
    const collapsed = pills.find((pill) => !pill.classes('open'))
    expect(collapsed).toBeDefined()
    const testId = collapsed!.attributes('data-testid')!
    const targetName = testId.replace('jump-group-', '')
    expect(wrapper.find(`[data-group-card="${targetName}"]`).classes('open')).toBe(false)

    await collapsed!.trigger('click')
    await flushPromises()
    expect(wrapper.find(`[data-group-card="${targetName}"]`).classes('open')).toBe(true)
    expect(wrapper.find(`[data-testid="${testId}"]`).classes('open')).toBe(true)
  })

  it('recovers from a GEO upgrade failure by switching to jsDelivr and retrying', async () => {
    const { wrapper, backend } = await mountApp({}, 360)
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    storeOf(wrapper).go('resources')
    await settle(300)

    const saveSpy = vi.spyOn(backend, 'saveSettings')
    let calls = 0
    vi.spyOn(backend, 'upgradeGeo').mockImplementation(async () => {
      calls += 1
      if (calls === 1) {
        throw new Error('GEO 数据库下载超时或连接受阻，可切换下载源为「jsDelivr 加速」后重试')
      }
      return backend.geoFiles()
    })

    await wrapper.find('[data-testid="upgrade-geo"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="geo-error"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="geo-error"]').text()).toContain('jsDelivr')
    expect(wrapper.find('[data-testid="geo-switch-jsdelivr"]').exists()).toBe(true)

    await wrapper.find('[data-testid="geo-switch-jsdelivr"]').trigger('click')
    await settle(500)
    expect(saveSpy).toHaveBeenCalledWith(expect.objectContaining({ geo_source: 'jsdelivr' }))
    expect(calls).toBe(2)
    expect(wrapper.find('[data-testid="geo-error"]').exists()).toBe(false)
  })

  it('switches profiles from the mobile home sheet and jumps straight to the active node group', async () => {
    const { wrapper, backend } = await mountApp({ platform: 'android' }, 375)
    const enableSpy = vi.spyOn(backend, 'enable')

    // Disconnected: dock has no live dot yet; profile trigger opens the quick switcher sheet
    expect(wrapper.find('.tabbar [data-page="home"] .tab-live-dot').exists()).toBe(false)
    expect(wrapper.find('[data-testid="mobile-profile-trigger"]').exists()).toBe(true)
    await wrapper.find('[data-testid="mobile-profile-trigger"]').trigger('click')
    await flushPromises()
    expect(document.body.querySelector('[data-testid="home-profile-sheet"]')).not.toBeNull()

    document.body.querySelector<HTMLElement>('[data-testid="sheet-profile-p2"]')?.click()
    await settle(300)
    expect(enableSpy).toHaveBeenCalledWith('p2')
    expect(document.body.querySelector('[data-testid="home-profile-sheet"]')).toBeNull()
    expect(wrapper.find('.main').attributes('data-page')).toBe('home')

    // Connect and verify the dock live indicator lights up even after switching tabs
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    expect(wrapper.find('.tabbar [data-page="home"] .tab-live-dot').exists()).toBe(true)

    // Tapping the active node capsule jumps directly to its group on ProxiesView
    const nodePill = wrapper.find('[data-testid="hero-node-pill"]')
    expect(nodePill.exists()).toBe(true)
    await nodePill.trigger('click')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('proxies')
    expect(wrapper.find('.tabbar [data-page="home"] .tab-live-dot').exists()).toBe(true)
  })

  it('connects inline from mobile proxies when disconnected and focuses one group per pill tap', async () => {
    localStorage.clear()
    const { wrapper, backend } = await mountApp({ platform: 'android' }, 360)
    const connectSpy = vi.spyOn(backend, 'connect')

    await wrapper.find('.tabbar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="proxies-connect-bar"]').exists()).toBe(true)

    // Tapping a second group pill on mobile collapses the previously open group for zero clutter
    expect(wrapper.find('[data-group-card="节点选择"]').classes('open')).toBe(true)
    await wrapper.find('[data-testid="jump-group-OpenAI"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-group-card="OpenAI"]').classes('open')).toBe(true)
    expect(wrapper.find('[data-group-card="节点选择"]').classes('open')).toBe(false)

    // 1-tap connect directly from ProxiesView enables testing without going back to Home
    await wrapper.find('[data-testid="proxies-connect"]').trigger('click')
    await settle(1500)
    expect(connectSpy).toHaveBeenCalled()
    expect(wrapper.find('[data-testid="proxies-connect-bar"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="test-all"]').attributes('disabled')).toBeUndefined()
  })

  it('opens system proxy settings from Home and saves host, PAC mode and bypass list', async () => {
    const { wrapper, backend } = await mountApp()
    const saveSpy = vi.spyOn(backend, 'saveSettings')

    await wrapper.find('[data-testid="proxy-settings-link"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('settings')
    expect(wrapper.find('[data-testid="proxy-settings"]').exists()).toBe(true)

    await wrapper.find('[data-testid="proxy-host-input"]').setValue('127.0.0.2')
    await wrapper.find('[data-testid="proxy-mode"] [data-value="pac"]').trigger('click')
    expect(wrapper.find('[data-testid="pac-script-input"]').exists()).toBe(true)

    await wrapper.find('[data-testid="bypass-add-input"]').setValue('*.corp.internal')
    await wrapper.find('[data-testid="bypass-add-btn"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="bypass-list"]').text()).toContain('*.corp.internal')

    await wrapper.find('[data-testid="save-proxy"]').trigger('click')
    await settle(500)
    expect(saveSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        system_proxy: expect.objectContaining({
          host: '127.0.0.2',
          mode: 'pac',
          bypass: expect.arrayContaining(['*.corp.internal', 'localhost']),
        }),
      }),
    )
    expect(wrapper.find('[data-testid="save-proxy"]').exists()).toBe(false)
  })

  it('saves complete DNS overrides including filter mode, nameserver-policy and custom hosts', async () => {
    const { wrapper, backend } = await mountApp()
    const saveSpy = vi.spyOn(backend, 'saveSettings')

    await wrapper.find('.sidebar [data-page="settings"]').trigger('click')
    await flushPromises()
    await wrapper.find('[data-testid="settings-tabs"] [data-value="dns"]').trigger('click')
    await flushPromises()

    await wrapper.find('[data-testid="dns-filter-mode"] [data-value="whitelist"]').trigger('click')
    await wrapper.find('[data-testid="dns-listen"]').setValue('127.0.0.1:1053')
    await wrapper.find('[data-testid="dns-prefer-h3"]').trigger('click')
    await wrapper.find('[data-testid="dns-cache-algorithm"] [data-value="arc"]').trigger('click')

    // Add CN preset + custom policy
    await wrapper.find('[data-testid="preset-cn-policy"]').trigger('click')
    await wrapper.find('[data-testid="policy-pattern-input"]').setValue('+.corp.local')
    await wrapper.find('[data-testid="policy-servers-input"]').setValue('10.0.0.53')
    await wrapper.find('[data-testid="add-policy-btn"]').trigger('click')

    // Add custom host mapping and toggle system hosts
    await wrapper.find('[data-testid="dns-system-hosts"]').trigger('click')
    await wrapper.find('[data-testid="host-domain-input"]').setValue('router.local')
    await wrapper.find('[data-testid="host-target-input"]').setValue('192.168.1.1')
    await wrapper.find('[data-testid="add-host-btn"]').trigger('click')

    await wrapper.find('[data-testid="save-dns"]').trigger('click')
    await settle(500)

    expect(saveSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        dns: expect.objectContaining({
          listen: '127.0.0.1:1053',
          fake_ip_filter_mode: 'whitelist',
          prefer_h3: true,
          cache_algorithm: 'arc',
          use_system_hosts: false,
          nameserver_policy: {
            'geosite:cn,private': ['https://doh.pub/dns-query', '223.5.5.5'],
            '+.corp.local': ['10.0.0.53'],
          },
          hosts: {
            'router.local': ['192.168.1.1'],
          },
        }),
      }),
    )
  })

  it('switches GEO download source while connected without dropping active session or provider cards', async () => {
    const { wrapper } = await mountApp()
    const store = storeOf(wrapper)
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    expect(store.snapshot.value.connected).toBe(true)

    await openPage(wrapper, 'resources')
    await settle(500)
    expect(wrapper.find('[data-provider="机场订阅"]').exists()).toBe(true)

    await wrapper.find('[data-testid="open-geo-settings"]').trigger('click')
    await flushPromises()
    document.body.querySelector<HTMLElement>('[data-testid="geo-source"] [data-value="jsdelivr"]')!.click()
    await settle(400)
    expect(store.snapshot.value.connected).toBe(true)
    expect(store.snapshot.value.kernel_running).toBe(true)
    expect(wrapper.find('[data-provider="机场订阅"]').exists()).toBe(true)
  })

  it('collapses and expands the desktop sidebar and persists the state', async () => {
    localStorage.clear()
    const { wrapper } = await mountApp()
    const toggle = wrapper.find('[data-testid="sidebar-toggle"]')
    expect(toggle.exists()).toBe(true)
    expect(toggle.attributes('aria-expanded')).toBe('true')
    expect(wrapper.find('.shell').classes()).not.toContain('sidebar-collapsed')

    await toggle.trigger('click')
    await flushPromises()
    expect(wrapper.find('.shell').classes()).toContain('sidebar-collapsed')
    expect(wrapper.find('.sidebar').classes()).toContain('collapsed')
    expect(toggle.attributes('aria-expanded')).toBe('false')
    expect(localStorage.getItem('billow.sidebarCollapsed')).toBe('1')

    // Navigation continues to work seamlessly while collapsed
    await wrapper.find('.sidebar [data-page="proxies"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('proxies')

    // Keyboard shortcut (Ctrl+B) expands the sidebar again
    press(document, 'b', { ctrlKey: true })
    await flushPromises()
    expect(wrapper.find('.shell').classes()).not.toContain('sidebar-collapsed')
    expect(localStorage.getItem('billow.sidebarCollapsed')).toBe('0')
    localStorage.clear()
  })
})
