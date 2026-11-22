import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { defineComponent, h, provide } from 'vue'
import { createDemoBackend } from '../lib/demo'
import { createStore, PAGES, STORE } from '../lib/store'
import { CUSTOM_PROFILE_ID } from '../lib/types'
import ProfilesView from '../views/ProfilesView.vue'

const cleanups: (() => void)[] = []

afterEach(() => {
  cleanups.splice(0).forEach((stop) => stop())
  document.body.innerHTML = ''
})

async function waitDemo(ms = 90) {
  await new Promise((resolve) => setTimeout(resolve, ms))
  await flushPromises()
}

async function setupProfiles(options?: { profiles?: boolean }) {
  const backend = createDemoBackend({ profiles: options?.profiles })
  const store = createStore(backend)
  await store.start()
  const Harness = defineComponent({
    setup() {
      provide(STORE, store)
      return () => h(ProfilesView)
    },
  })
  const wrapper = mount(Harness, { attachTo: document.body })
  await flushPromises()
  cleanups.push(() => {
    wrapper.unmount()
    store.stop()
  })
  return { backend, store, wrapper }
}

function find<T extends HTMLElement = HTMLElement>(selector: string): T {
  const element = document.querySelector<T>(selector)
  if (!element) throw new Error(`missing ${selector}`)
  return element
}

async function setInput(selector: string, value: string) {
  const input = find<HTMLInputElement | HTMLTextAreaElement>(selector)
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  input.dispatchEvent(new Event('change', { bubbles: true }))
  await flushPromises()
}

async function click(selector: string) {
  find(selector).click()
  await flushPromises()
}

describe('CustomNodesPanel & ProfilesView integration (R1–R7, R9)', () => {
  it('keeps top-level navigation unchanged with zero new primary menu entries (R9)', () => {
    const coreAndTools = PAGES.filter((p) => p.group !== null).map((p) => p.id)
    expect(coreAndTools).toEqual(['home', 'proxies', 'profiles', 'connections', 'rules', 'resources', 'logs'])
    const mobileTabs = PAGES.filter((p) => p.mobile).map((p) => p.id)
    expect(mobileTabs).toEqual(['home', 'proxies', 'profiles', 'settings'])
  })

  it('hides custom-node card by default for pure subscription users (zero clutter)', async () => {
    const { store } = await setupProfiles()
    expect(store.hasProfiles.value).toBe(true)
    expect(store.hasCustomNodes.value).toBe(false)
    expect(document.querySelector('[data-testid="custom-nodes-panel"]')).toBeNull()
  })

  it('auto-detects share links in quick-import and batch-imports with partial error isolation (including anytls://)', async () => {
    const { store } = await setupProfiles()

    // Single anytls:// link pasted in quick-import auto-opens the import modal with live preview
    const quickInput = find<HTMLInputElement>('.quick-import input')
    quickInput.value = 'anytls://secret-pass@any.example.com:443?sni=any.example.com#AnyTLS-US'
    quickInput.dispatchEvent(new Event('input', { bubbles: true }))
    find<HTMLFormElement>('.quick-import').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
    await flushPromises()

    expect(find('[data-testid="custom-import-preview"]').textContent).toContain('AnyTLS-US')

    // Multi-line batch input in the modal textarea isolates malformed lines while importing valid nodes
    await setInput(
      '[data-testid="custom-node-import-input"]',
      [
        'anytls://secret-pass@any.example.com:443?sni=any.example.com#AnyTLS-US',
        'not-a-valid-uri-line',
        'vless://11111111-1111-1111-1111-111111111111@vless.example.com:443?security=tls&sni=vless.example.com#VLESS-JP',
      ].join('\n'),
    )
    await waitDemo(160)

    expect(find('[data-testid="custom-import-preview"]').textContent).toContain('AnyTLS-US')
    expect(find('[data-testid="custom-import-preview"]').textContent).toContain('VLESS-JP')
    expect(find('[data-testid="custom-import-errors"]').textContent).toContain('1')

    await click('[data-testid="custom-node-import-confirm"]')
    await waitDemo()

    expect(store.customNodes.value.nodes.map((n) => n.name)).toEqual(['AnyTLS-US', 'VLESS-JP'])
    expect(store.customNodes.value.nodes[0]?.protocol).toBe('anytls')
    const panel = find('[data-testid="custom-nodes-panel"]')
    expect(panel.textContent).toContain('AnyTLS-US')
    expect(panel.textContent).toContain('ANYTLS')
    expect(panel.textContent).toContain('通过当前订阅中转')
  })

  it('creates a SOCKS5 node via quick form and toggles subscription overlay off/on', async () => {
    const { store } = await setupProfiles()

    await click('[data-testid="add-custom-node-entry"]')
    await click('[data-testid="custom-import-to-form"]')

    await setInput('[data-testid="custom-node-name"]', '美国家宽')
    await setInput('[data-testid="custom-node-server"]', '203.0.113.10')
    await setInput('[data-testid="custom-node-port"]', '10808')
    await setInput('[data-testid="custom-node-username"]', 'alice')
    await setInput('[data-testid="custom-node-password"]', 'pass123')
    await setInput('[data-testid="custom-node-note"]', 'AI 专用')

    await click('[data-testid="custom-node-save"]')
    await waitDemo()

    expect(store.customNodes.value.nodes).toHaveLength(1)
    expect(store.customNodes.value.nodes[0]?.name).toBe('美国家宽')
    expect(store.customNodes.value.nodes[0]?.protocol).toBe('socks5')
    expect(store.customNodes.value.overlay_enabled).toBe(true)

    await click('[data-testid="custom-overlay-toggle"]')
    await waitDemo()
    expect(store.customNodes.value.overlay_enabled).toBe(false)

    await click('[data-testid="custom-overlay-toggle"]')
    await waitDemo()
    expect(store.customNodes.value.overlay_enabled).toBe(true)
  })

  it('rejects chain proxy cycles and surfaces an inline error without closing the modal', async () => {
    const { store } = await setupProfiles()

    await store.importCustomNodes(
      [
        'socks5://1.1.1.1:1080#Hop-A',
        'socks5://2.2.2.2:1080#Hop-B',
      ].join('\n'),
      { kind: 'direct' },
    )
    await waitDemo()

    const [nodeA, nodeB] = store.customNodes.value.nodes
    expect(nodeA).toBeTruthy()
    expect(nodeB).toBeTruthy()

    // Chain A -> B succeeds
    await store.saveCustomNode({
      id: nodeA!.id,
      name: nodeA!.name,
      enabled: true,
      note: '',
      dialer: { kind: 'custom_node', id: nodeB!.id },
      raw_yaml: nodeA!.raw_yaml,
    })
    await waitDemo()
    expect(find('[data-testid="custom-nodes-panel"]').textContent).toContain('经自建节点「Hop-B」中转')

    // Now edit B -> A via modal; backend must reject the cycle and keep modal open with error
    await click(`[data-testid="edit-custom-node-${nodeB!.id}"]`)
    const dialerTrigger = find('[data-testid="custom-node-dialer"] button')
    dialerTrigger.click()
    await flushPromises()
    const options = [...document.querySelectorAll<HTMLElement>('[role="option"]')]
    const hopAOption = options.find((el) => el.textContent?.includes('Hop-A'))
    expect(hopAOption).toBeTruthy()
    hopAOption!.click()
    await flushPromises()

    await click('[data-testid="custom-node-save"]')
    await waitDemo()

    const errorEl = find('[data-testid="custom-node-edit-error"]')
    expect(errorEl.textContent).toContain('循环')
    // Modal stays open and B remains direct
    expect(store.customNodes.value.nodes.find((n) => n.id === nodeB!.id)?.dialer.kind).toBe('direct')
  })

  it('activates standalone zero-YAML custom profile mode and hides empty-profile state when no subscriptions exist', async () => {
    const { store } = await setupProfiles({ profiles: false })
    expect(store.hasProfiles.value).toBe(false)

    await store.importCustomNodes('anytls://pw@solo.example.com:443#Solo-AnyTLS', { kind: 'direct' })
    await waitDemo()

    expect(store.customProfileActive.value).toBe(true)
    expect(store.snapshot.value.active_id).toBe(CUSTOM_PROFILE_ID)
    expect(find('[data-testid="custom-profile-active-badge"]').textContent).toContain('当前正在使用纯自建节点')
    expect(document.body.textContent).not.toContain('还没有配置')

    // Switching from subscription mode to standalone mode via button works too
    cleanups.splice(0).forEach((stop) => stop())
    document.body.innerHTML = ''
    const sub = await setupProfiles()
    await sub.store.importCustomNodes('anytls://pw@solo2.example.com:443#Solo-2', { kind: 'direct' })
    await waitDemo()
    expect(sub.store.customProfileActive.value).toBe(false)

    await click('[data-testid="use-custom-profile"]')
    await waitDemo()
    expect(sub.store.customProfileActive.value).toBe(true)
    expect(sub.store.snapshot.value.active_id).toBe(CUSTOM_PROFILE_ID)
  })

  it('configures AI preset and custom domain landing rules in LandingRulesModal', async () => {
    const { store } = await setupProfiles()
    await store.importCustomNodes('socks5://1.2.3.4:1080#Landing-US', { kind: 'profile_group', group: null })
    await waitDemo()

    await click('[data-testid="open-landing-rules"]')
    await click('[data-testid="landing-preset-ai"]')
    await setInput('[data-testid="landing-domain-input"]', 'api.custom-ai.example')
    await click('[data-testid="landing-domain-add"]')
    await click('[data-testid="landing-rules-save"]')
    await waitDemo()

    const rules = store.customNodes.value.rules
    expect(store.customNodes.value.rules_enabled).toBe(true)
    expect(rules.some((r) => r.rule.kind === 'preset' && r.rule.id === 'ai')).toBe(true)
    expect(rules.some((r) => r.rule.kind === 'domain' && r.rule.pattern === 'api.custom-ai.example')).toBe(true)
  })
})
