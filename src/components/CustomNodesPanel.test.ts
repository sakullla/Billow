import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h, provide } from 'vue'
import { createDemoBackend } from '../lib/demo'
import { createStore, PAGES, STORE } from '../lib/store'
import { CUSTOM_PROFILE_ID } from '../lib/types'
import App from '../App.vue'
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

  it('supports per-rule toggle/edit and highlights disabled or deleted landing targets (R6)', async () => {
    const { store } = await setupProfiles()
    await store.importCustomNodes('socks5://1.2.3.4:1080#Landing-US', { kind: 'direct' })
    await waitDemo()
    const node = store.customNodes.value.nodes[0]!

    await store.saveLandingRules(true, [
      { id: '', enabled: true, rule: { kind: 'preset', id: 'ai' }, target: { kind: 'custom_node', id: node.id } },
      { id: '', enabled: true, rule: { kind: 'domain', pattern: 'old.example.com' }, target: { kind: 'custom_node', id: node.id } },
    ])
    await waitDemo()

    // Edit domain pattern and toggle off single domain rule
    await click('[data-testid="open-landing-rules"]')
    await click('[data-testid="landing-rule-edit-0"]')
    await setInput('[data-testid="landing-rule-edit-input-0"]', 'new.example.com')
    await click('[data-testid="landing-rule-edit-save-0"]')
    await click('[data-testid="landing-rule-toggle-0"]')
    await click('[data-testid="landing-rules-save"]')
    await waitDemo()

    const savedDomain = store.customNodes.value.rules.find((r) => r.rule.kind === 'domain')
    expect(savedDomain?.rule).toEqual({ kind: 'domain', pattern: 'new.example.com' })
    expect(savedDomain?.enabled).toBe(false)

    // Re-enable rule, then disable target node -> LandingRulesModal highlights disabled target on both preset and domain
    await store.saveLandingRules(true, [
      { id: '', enabled: true, rule: { kind: 'preset', id: 'ai' }, target: { kind: 'custom_node', id: node.id } },
      { id: '', enabled: true, rule: { kind: 'domain', pattern: 'new.example.com' }, target: { kind: 'custom_node', id: node.id } },
    ])
    await waitDemo()
    await store.setCustomNodeEnabled(node.id, false)
    await waitDemo()

    await click('[data-testid="open-landing-rules"]')
    expect(find('[data-testid="landing-preset-warning-ai"]').textContent).toContain('已停用')
    expect(find('[data-testid="landing-rule-warning-0"]').textContent).toContain('已停用')
    expect(find('[data-testid="landing-rule-target-tag-0"]').textContent).toContain('已停用')

    // Close, delete target node -> LandingRulesModal shows deleted target warning instead of fallback group
    find('[aria-label="关闭"]').click()
    await flushPromises()
    await store.deleteCustomNode(node.id)
    await waitDemo()
    // Re-import a second node so CustomNodesPanel stays visible and we can reopen LandingRulesModal
    await store.importCustomNodes('socks5://5.6.7.8:1080#Landing-JP', { kind: 'direct' })
    await waitDemo()

    await click('[data-testid="open-landing-rules"]')
    expect(find('[data-testid="landing-preset-warning-ai"]').textContent).toContain('已删除')
    expect(find('[data-testid="landing-rule-warning-0"]').textContent).toContain('已删除')
    expect(find('[data-testid="landing-rule-target-tag-0"]').textContent).toContain('已删除')
  })

  it('warns about affected chained nodes and landing rules before disabling or deleting a referenced node, and preserves missing dialer in edit modal (R1, R3)', async () => {
    const { store } = await setupProfiles()
    await store.importCustomNodes(
      [
        'socks5://1.1.1.1:1080#Exit-A',
        'socks5://2.2.2.2:1080#Relay-B',
      ].join('\n'),
      { kind: 'direct' },
    )
    await waitDemo()

    const [exitA, relayB] = store.customNodes.value.nodes
    // Exit-A chains through Relay-B, and a landing rule also targets Relay-B
    await store.saveCustomNode({
      id: exitA!.id,
      name: exitA!.name,
      enabled: true,
      note: '',
      dialer: { kind: 'custom_node', id: relayB!.id },
      raw_yaml: exitA!.raw_yaml,
    })
    await store.saveLandingRules(true, [
      { id: '', enabled: true, rule: { kind: 'domain', pattern: 'openai.com' }, target: { kind: 'custom_node', id: relayB!.id } },
    ])
    await waitDemo()

    // Disabling Relay-B prompts with impacted chained node and landing rule
    await click(`[data-testid="toggle-custom-node-${relayB!.id}"]`)
    const disableImpact = find('[data-testid="disable-custom-node-impact"]')
    expect(disableImpact.textContent).toContain('Exit-A')
    expect(disableImpact.textContent).toContain('openai.com')
    await click('[data-testid="confirm-disable-custom-node"]')
    await waitDemo()
    expect(store.customNodes.value.nodes.find((n) => n.id === relayB!.id)?.enabled).toBe(false)

    // Deleting Relay-B prompts with impacted chained node and landing rule
    await click(`[data-testid="delete-custom-node-${relayB!.id}"]`)
    const deleteImpact = find('[data-testid="delete-custom-node-impact"]')
    expect(deleteImpact.textContent).toContain('Exit-A')
    expect(deleteImpact.textContent).toContain('openai.com')
    await click('[data-testid="confirm-delete-custom-node"]')
    await waitDemo()
    expect(store.customNodes.value.nodes.some((n) => n.id === relayB!.id)).toBe(false)

    // Editing Exit-A preserves the deleted dialer label instead of showing 未选择 and displays a warning
    await click(`[data-testid="edit-custom-node-${exitA!.id}"]`)
    expect(find('[data-testid="custom-node-dialer"] button').textContent).toContain('已删除')
    expect(find('[data-testid="custom-node-dialer-warning"]').textContent).toContain('已删除')
  })

  it('connects from HomeView and sidebar in zero-subscription standalone custom-node mode and shows failure banner when all custom nodes are disabled (R5, R9)', async () => {
    const backend = createDemoBackend({ profiles: false })
    const wrapper = mount(App, { props: { backend, width: 1200 }, attachTo: document.body })
    cleanups.push(() => wrapper.unmount())
    await waitDemo()

    // Pure empty state still shows welcome screen
    expect(document.querySelector('[data-testid="welcome"]')).not.toBeNull()

    // Import one custom node with zero subscriptions -> auto-activates standalone custom profile
    await backend.importCustomNodes('anytls://pw@jp-opt.example.com:443?sni=jp-opt.example.com#JP-Opt')
    await waitDemo()

    // Re-mount App to pick up backend state (or navigate to profiles & back to home)
    wrapper.unmount()
    const wrapper2 = mount(App, { props: { backend, width: 1200 }, attachTo: document.body })
    cleanups.push(() => wrapper2.unmount())
    await waitDemo()

    // HomeView leaves welcome state, shows standalone profile name and sidebar power button
    expect(document.querySelector('[data-testid="welcome"]')).toBeNull()
    expect(find('[data-testid="mobile-profile-trigger"]').textContent).toContain('纯自建节点')
    expect(document.querySelector('[data-testid="side-power"]')).not.toBeNull()

    // Clicking Home power button connects directly without opening Add Profile modal
    await click('[data-testid="power"]')
    await vi.waitFor(() => {
      expect(find('[data-testid="status"]').textContent).toContain('已连接')
    }, { timeout: 3000 })
    expect(document.querySelector('[data-testid="add-profile-modal"]')).toBeNull()

    // Disconnect, disable the only custom node, and verify connecting shows clear error banner
    await click('[data-testid="power"]')
    await vi.waitFor(() => {
      expect(find('[data-testid="status"]').textContent).toContain('未连接')
    }, { timeout: 3000 })
    const state = await backend.state()
    const onlyNode = state.custom_nodes.nodes[0]!
    await backend.setCustomNodeEnabled(onlyNode.id, false)
    await click('[data-testid="power"]')
    await vi.waitFor(() => {
      expect(find('[data-testid="home-failure"]').textContent).toContain('还没有启用的自建节点')
    }, { timeout: 3000 })
  })
})
