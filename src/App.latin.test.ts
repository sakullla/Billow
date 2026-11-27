import { DOMWrapper, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import { applyLocale } from './lib/i18n'

/**
 * T8: the whole interface in English with the Latin demo (?demo=latin).
 *
 * Everything must be English except kernel log lines and kernel error text,
 * which stay as the kernel reports them. The language names in the picker are
 * also kept in their own language ("简体中文").
 */

const mounted: { unmount: () => void }[] = []

async function settle(ms = 1000) {
  await vi.advanceTimersByTimeAsync(ms)
  await flushPromises()
}

async function mountApp(options: Parameters<typeof createDemoBackend>[0], width = 1200) {
  vi.useFakeTimers()
  const backend = createDemoBackend({ latin: true, systemLocale: 'en', ...options })
  const wrapper = mount(App, { props: { backend, width }, attachTo: document.body })
  mounted.push(wrapper)
  await settle(50)
  return wrapper
}

const CJK = /[\u3400-\u9fff]/

/** Body text without the parts the requirement exempts (kernel logs and errors). */
function visibleText(): string {
  const clone = document.body.cloneNode(true) as HTMLElement
  clone
    .querySelectorAll(
      [
        '[data-testid="language-select"]',
        '[data-testid="log-scroll"]',
        '.cm-content',
      ].join(','),
    )
    .forEach((node) => node.remove())
  return clone.textContent ?? ''
}

function chineseSnippets(): string[] {
  const text = visibleText().replace(/\s+/g, ' ')
  const out = new Set<string>()
  for (const match of text.matchAll(new RegExp(`.{0,24}${CJK.source}.{0,24}`, 'g'))) {
    const snippet = match[0]?.trim()
    if (snippet) out.add(snippet)
  }
  return [...out]
}

function expectEnglish(label: string) {
  const snippets = chineseSnippets()
  expect(snippets, `${label} still shows Chinese: ${snippets.join(' | ')}`).toEqual([])
  // An unsubstituted placeholder is the same kind of leak as a key or blank (R42).
  expect(visibleText(), `${label} still shows a placeholder`).not.toMatch(/\{\d+\}/)
}

afterEach(() => {
  mounted.splice(0).forEach((wrapper) => wrapper.unmount())
  applyLocale('zh-CN')
  document.body.innerHTML = ''
})

vi.setConfig({ testTimeout: 40_000 })

describe('T8 Latin demo', () => {
  it('renders every page and settings tab without Chinese text', async () => {
    const wrapper = await mountApp({})
    const store = (wrapper.vm as unknown as { store: any }).store
    const pages = ['home', 'proxies', 'profiles', 'connections', 'rules', 'resources', 'logs', 'settings']
    for (const page of pages) {
      store.go(page)
      await settle(80)
      expectEnglish(`page ${page}`)
    }
    for (const tab of ['general', 'proxy', 'kernel', 'tun', 'dns', 'backup']) {
      store.go('settings')
      store.settingsTab.value = tab
      await settle(80)
      expectEnglish(`settings ${tab}`)
    }
  })

  it('renders the iOS extension selector in English', async () => {
    const wrapper = await mountApp({ os: 'ios' }, 390)
    const store = (wrapper.vm as unknown as { store: any }).store
    store.go('settings')
    store.settingsTab.value = 'kernel'
    await settle(50)

    const card = wrapper.get('[data-testid="ios-vpn-card"]')
    await card.get('[data-value="rust"]').trigger('click')
    await settle(50)
    expect(card.get('[data-value="rust"]').attributes('aria-checked')).toBe('true')
    expectEnglish('iOS kernel settings')
  })

  it('renders the merged shortcut dialog in English', async () => {
    const wrapper = await mountApp({})
    const store = (wrapper.vm as unknown as { store: any }).store
    store.go('settings')
    store.settingsTab.value = 'general'
    await settle(40)
    await wrapper.find('[data-testid="settings-shortcuts"]').trigger('click')
    await settle(40)
    expectEnglish('shortcut dialog')
  })

  it('renders the command palette, help, add-profile, config and DNS dialogs in English', async () => {
    const wrapper = await mountApp({})
    const body = () => new DOMWrapper(document.body)

    await wrapper.find('[data-testid="open-palette"]').trigger('click')
    await settle(20)
    expectEnglish('command palette')

    await body().find('[data-command="action:open-shortcuts"]').trigger('click')
    await settle(20)
    expectEnglish('shortcuts dialog')
    await body().find('.modal-head button').trigger('click')
    await settle(10)

    await wrapper.find('[data-testid="open-palette"]').trigger('click')
    await settle(20)
    await body().find('[data-command="action:add-profile"]').trigger('click')
    await settle(20)
    expectEnglish('add profile dialog')
    await body().find('.modal-head button').trigger('click')
    await settle(10)

    await wrapper.find('[data-testid="open-palette"]').trigger('click')
    await settle(20)
    await body().find('[data-command="action:open-config"]').trigger('click')
    await settle(120)
    expectEnglish('config viewer')
    await body().find('.modal-head button').trigger('click')
    await settle(10)

    const store = (wrapper.vm as unknown as { store: any }).store
    store.go('settings')
    store.settingsTab.value = 'dns'
    await settle(20)
    await wrapper.find('[data-testid="open-dns-query"]').trigger('click')
    await settle(20)
    expectEnglish('DNS query dialog')
  })

  it('renders the traffic stats dialog in English', async () => {
    const wrapper = await mountApp({})
    const store = (wrapper.vm as unknown as { store: any }).store
    store.go('settings')
    store.settingsTab.value = 'general'
    await settle(20)
    await wrapper.find('[data-testid="open-traffic-stats"]').trigger('click')
    await settle(120)
    expectEnglish('traffic stats dialog')
  })

  it('renders the exit IP card in English once auto-query is on', async () => {
    const wrapper = await mountApp({})
    const store = (wrapper.vm as unknown as { store: any }).store
    // The card only exists while the option is on (R40), so the default home
    // page no longer exercises its English text.
    await store.setAutoExitIp(true)
    await settle(20)
    store.go('home')
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)

    const card = wrapper.find('[data-testid="exit-ip-card"]')
    expect(card.exists()).toBe(true)
    expect(card.text()).toContain('Exit IP')
    expectEnglish('home exit IP card')
  })

  it('renders the UWP tool and Android app list in English', async () => {
    const windows = await mountApp({ os: 'windows' })
    const windowsStore = (windows.vm as unknown as { store: any }).store
    windowsStore.go('settings')
    windowsStore.settingsTab.value = 'proxy'
    await settle(20)
    await windows.find('[data-testid="open-uwp-tool"]').trigger('click')
    await settle(60)
    expectEnglish('UWP dialog')
    windows.unmount()
    mounted.splice(0, mounted.length)
    document.body.innerHTML = ''

    const android = await mountApp({ platform: 'android' })
    const androidStore = (android.vm as unknown as { store: any }).store
    androidStore.go('apps')
    await settle(80)
    expectEnglish('apps page')
  })

  it('renders the empty proxies state in English', async () => {
    const wrapper = await mountApp({ profiles: false })
    const store = (wrapper.vm as unknown as { store: any }).store
    store.go('proxies')
    await settle(80)
    expectEnglish('proxies empty state')
  })

  it('updates an already mounted settings tab when the language changes', async () => {
    const wrapper = await mountApp({ systemLocale: 'zh-CN' })
    const store = (wrapper.vm as unknown as { store: any }).store
    store.go('settings')
    store.settingsTab.value = 'kernel'
    await settle(80)
    // The English dictionary is applied without a remount: every label in the
    // mounted tab must follow immediately (R42).
    applyLocale('en')
    await settle(30)
    expectEnglish('settings kernel after switching')
  })

  it('renders diagnostic tool panels (connections, rules matcher, logs, resources) in English', async () => {
    const wrapper = await mountApp({})
    const store = (wrapper.vm as unknown as { store: any }).store
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)

    store.go('connections')
    await settle(100)
    const toggleFilters = wrapper.find('[data-testid="toggle-conn-filters"]')
    if (toggleFilters.exists()) {
      await toggleFilters.trigger('click')
      await settle(40)
    }
    expectEnglish('connections with quick filters')

    store.go('rules')
    await settle(100)
    await wrapper.find('[data-testid="rule-match-toggle"]').trigger('click')
    await settle(40)
    await wrapper.find('[data-testid="rule-match-target"]').setValue('api.github.com')
    await wrapper.find('[data-testid="rule-match-form"]').trigger('submit')
    await settle(80)
    expectEnglish('rules match tester')

    store.go('logs')
    await settle(100)
    const issuesBtn = wrapper.find('.log-level-filter [data-value="issues"]')
    if (issuesBtn.exists()) {
      await issuesBtn.trigger('click')
      await settle(40)
    }
    expectEnglish('logs issues filter')

    store.go('resources')
    await settle(100)
    expectEnglish('resources permanent toolbar')
  })
})
