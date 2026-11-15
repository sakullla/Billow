import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from '../App.vue'
import { createDemoBackend } from '../lib/demo'
import { detectChrome } from '../lib/ui/windowChrome'

const win = vi.hoisted(() => ({
  minimize: vi.fn(async () => {}),
  toggleMaximize: vi.fn(async () => {}),
  close: vi.fn(async () => {}),
  isMaximized: vi.fn(async () => false),
  onResized: vi.fn(async () => () => {}),
}))
vi.mock('@tauri-apps/api/window', () => ({ getCurrentWindow: () => win }))

const mounted: { unmount: () => void }[] = []
afterEach(() => {
  mounted.splice(0).forEach((wrapper) => wrapper.unmount())
  vi.clearAllMocks()
})

async function mountApp(chrome: 'windows' | 'macos' | null, width = 1200, backend = createDemoBackend()) {
  const wrapper = mount(App, { props: { backend, width, chrome }, attachTo: document.body })
  mounted.push(wrapper)
  await flushPromises()
  return wrapper
}

describe('desktop window chrome', () => {
  it('draws Windows caption buttons over the content column and routes them to the window', async () => {
    const wrapper = await mountApp('windows')
    const bar = wrapper.find('[data-testid="titlebar"]')
    expect(bar.attributes('data-tauri-drag-region')).toBeDefined()
    expect(wrapper.find('.shell').classes()).toContain('chrome-windows')
    // The sidebar still carries the brand; the strip only adds a name on narrow windows.
    expect(bar.find('.titlebar-brand').exists()).toBe(false)

    await bar.find('[data-testid="window-minimize"]').trigger('click')
    await bar.find('[data-testid="window-maximize"]').trigger('click')
    await bar.find('[data-testid="window-close"]').trigger('click')
    await flushPromises()
    expect(win.minimize).toHaveBeenCalledOnce()
    expect(win.toggleMaximize).toHaveBeenCalledOnce()
    expect(win.close).toHaveBeenCalledOnce()
  })

  it('shows the restore glyph label while maximized', async () => {
    win.isMaximized.mockResolvedValueOnce(true)
    const wrapper = await mountApp('windows')
    expect(wrapper.find('[data-testid="window-maximize"]').attributes('aria-label')).toBe('还原')
  })

  it('keeps native traffic lights on macOS and leaves room for them', async () => {
    const wrapper = await mountApp('macos')
    expect(wrapper.find('[data-testid="titlebar"]').exists()).toBe(true)
    expect(wrapper.find('.caption-buttons').exists()).toBe(false)
    expect(wrapper.find('.sidebar .sidebar-drag').exists()).toBe(true)

    const narrow = await mountApp('macos', 600)
    expect(narrow.find('[data-testid="titlebar"] .titlebar-brand').text()).toBe('Billow')
  })

  it('keeps the system frame without a platform chrome', async () => {
    const wrapper = await mountApp(null)
    expect(wrapper.find('[data-testid="titlebar"]').exists()).toBe(false)
  })

  it('opens the page or add dialog the tray asks for', async () => {
    const backend = createDemoBackend()
    let navigate: ((target: string) => void) | null = null
    backend.onTrayNavigate = async (handler) => {
      navigate = handler
      return () => {}
    }
    const wrapper = await mountApp(null, 1200, backend)
    navigate!('settings')
    await flushPromises()
    expect(wrapper.find('.main').attributes('data-page')).toBe('settings')
    navigate!('add-profile')
    await flushPromises()
    expect(document.body.textContent).toContain('订阅链接或 Clash / Mihomo YAML 文件')
  })

  it('detects the platform chrome only inside Tauri', () => {
    const fake = (agent: string, tauri = true, search = '') =>
      ({
        location: { search },
        navigator: { userAgent: agent },
        ...(tauri ? { __TAURI_INTERNALS__: {} } : {}),
      }) as unknown as Window
    expect(detectChrome(fake('Mozilla/5.0 (Windows NT 10.0; Win64; x64)'))).toBe('windows')
    expect(detectChrome(fake('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)'))).toBe('macos')
    expect(detectChrome(fake('Mozilla/5.0 (X11; Linux x86_64)'))).toBeNull()
    expect(detectChrome(fake('Mozilla/5.0 (Windows NT 10.0)', false))).toBeNull()
    expect(detectChrome(fake('Mozilla/5.0 (X11; Linux)', false, '?chrome=macos'))).toBe('macos')
  })
})
