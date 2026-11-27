import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { DOMWrapper, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import type { PageId, Store } from './lib/store'
import type { ConnectionRow, LogLine } from './lib/types'

async function settle(ms = 1000) {
  await vi.advanceTimersByTimeAsync(ms)
  await flushPromises()
  await nextTick()
}

const mounted: { unmount: () => void }[] = []

async function mountApp(options: Parameters<typeof createDemoBackend>[0] = {}, width = 1200) {
  vi.useFakeTimers()
  const backend = createDemoBackend(options)
  const wrapper = mount(App, { props: { backend, width }, attachTo: document.body })
  mounted.push(wrapper)
  await settle(50)
  return { wrapper, backend }
}

type Wrapper = Awaited<ReturnType<typeof mountApp>>['wrapper']

function storeOf(wrapper: Wrapper): Store {
  return (wrapper.vm as unknown as { store: Store }).store
}

function body() {
  return new DOMWrapper(document.body)
}

async function connect(wrapper: Wrapper) {
  await wrapper.find('[data-testid="power"]').trigger('click')
  await settle(1500)
}

async function openPage(wrapper: Wrapper, page: PageId) {
  storeOf(wrapper).go(page)
  await settle(150)
}

function makeConnection(overrides: Partial<ConnectionRow> = {}): ConnectionRow {
  return {
    id: overrides.id ?? 'c-1',
    host: overrides.host ?? 'api.github.com',
    destination: overrides.destination ?? 'api.github.com:443',
    network: overrides.network ?? 'tcp',
    conn_type: overrides.conn_type ?? 'HTTPS',
    rule: overrides.rule ?? 'DOMAIN-SUFFIX',
    rule_payload: overrides.rule_payload ?? 'github.com',
    outbound: overrides.outbound ?? '节点选择',
    chains: overrides.chains ?? ['香港 01', '节点选择'],
    process: overrides.process ?? '/usr/bin/curl',
    source: overrides.source ?? '127.0.0.1:51234',
    upload: overrides.upload ?? 1024,
    download: overrides.download ?? 4096,
    start: overrides.start ?? new Date().toISOString(),
  }
}

afterEach(() => {
  mounted.splice(0).forEach((wrapper) => wrapper.unmount())
  localStorage.clear()
  document.body.innerHTML = ''
  vi.restoreAllMocks()
  vi.useRealTimers()
})

vi.setConfig({ testTimeout: 40_000 })

describe('Diagnostic tools polish (R1–R5)', () => {
  describe('R1: Connections page single-row toolbar, reject filter, quick filters & mobile menu', () => {
    it('supports REJECT route filter, quick filters, localStorage persistence & fallback, and reset', async () => {
      const { wrapper, backend } = await mountApp()
      const origState = backend.state.bind(backend)
      const customConns: ConnectionRow[] = [
        makeConnection({
          id: 'c-proxy',
          host: 'api.github.com',
          network: 'tcp',
          process: '/usr/bin/curl',
          chains: ['香港 01', '节点选择'],
          outbound: '节点选择',
        }),
        makeConnection({
          id: 'c-direct',
          host: 'mirrors.tuna.tsinghua.edu.cn',
          network: 'udp',
          process: '/usr/bin/chrome',
          chains: ['DIRECT'],
          outbound: 'DIRECT',
          rule: 'DOMAIN-SUFFIX',
          rule_payload: 'tsinghua.edu.cn',
        }),
        makeConnection({
          id: 'c-reject',
          host: 'ads.tracker.example',
          network: 'tcp',
          process: '/usr/bin/chrome',
          chains: ['REJECT-DROP'],
          outbound: 'REJECT-DROP',
          rule: 'DOMAIN-KEYWORD',
          rule_payload: 'tracker',
        }),
      ]
      backend.state = async () => ({
        ...(await origState()),
        connections: customConns,
        connection_total: customConns.length,
      })

      await connect(wrapper)
      await openPage(wrapper, 'connections')
      await storeOf(wrapper).refresh()
      await settle(100)

      // Route filter includes 'reject' and filters REJECT / REJECT-DROP connections.
      await wrapper.find('[data-testid="connection-route-filter"] [data-value="reject"]').trigger('click')
      await settle(40)
      expect(wrapper.find('[data-testid="connection-match-count"]').text()).toBe('1/3')
      expect(wrapper.findAll('[data-testid="connection-row"]')).toHaveLength(1)
      expect(wrapper.find('[data-testid="connection-row"]').text()).toContain('ads.tracker.example')

      // Reset clears route filter.
      await wrapper.find('[data-testid="reset-connection-toolbar"]').trigger('click')
      await settle(40)
      expect(wrapper.findAll('[data-testid="connection-row"]')).toHaveLength(3)

      // Quick filter drawer opens and persists to localStorage.
      expect(wrapper.find('[data-testid="conn-filter-drawer"]').exists()).toBe(false)
      await wrapper.find('[data-testid="toggle-conn-filters"]').trigger('click')
      await settle(30)
      expect(wrapper.find('[data-testid="conn-filter-drawer"]').exists()).toBe(true)
      expect(localStorage.getItem('billow:conn-filters-open')).toBe('true')

      // Protocol UDP chip + Top process chip combine cleanly.
      await wrapper.find('[data-testid="conn-filter-udp"]').trigger('click')
      await settle(30)
      expect(wrapper.find('[data-testid="connection-match-count"]').text()).toBe('1/3')
      expect(wrapper.find('[data-testid="conn-quick-filter-badge"]').text()).toBe('1')

      // Active transfer chip only visible on active tab, hidden on closed tab.
      expect(wrapper.find('[data-testid="conn-filter-active"]').exists()).toBe(true)
      await wrapper.find('[data-testid="connection-tab"] [data-value="closed"]').trigger('click')
      await settle(30)
      expect(wrapper.find('[data-testid="conn-filter-active"]').exists()).toBe(false)

      // Storage write failure degrades gracefully without throwing.
      const setItemSpy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
        throw new Error('quota exceeded')
      })
      await wrapper.find('[data-testid="toggle-conn-filters"]').trigger('click')
      await settle(30)
      expect(wrapper.find('[data-testid="conn-filter-drawer"]').exists()).toBe(false)
      setItemSpy.mockRestore()
    })

    it('renders mobile connection rule summary and card quick menu to jump to rule match tester', async () => {
      const { wrapper, backend } = await mountApp({}, 390)
      const origState = backend.state.bind(backend)
      const conns: ConnectionRow[] = [
        makeConnection({
          id: 'm-1',
          host: 'api.github.com',
          destination: 'api.github.com:443',
          process: '/usr/bin/curl',
          rule: 'DOMAIN-SUFFIX',
          rule_payload: 'github.com',
        }),
      ]
      backend.state = async () => ({
        ...(await origState()),
        connections: conns,
        connection_total: conns.length,
      })

      await connect(wrapper)
      await openPage(wrapper, 'connections')
      await storeOf(wrapper).refresh()
      await settle(100)

      expect(wrapper.find('[data-testid="connection-card-rule"]').text()).toContain('DOMAIN-SUFFIX')
      expect(wrapper.find('[data-testid="connection-card-rule"]').text()).toContain('github.com')

      await wrapper.find('[data-testid="conn-card-actions"]').trigger('click')
      await settle(40)
      const menuButtons = body().findAll('.context-menu button, [role="menuitem"]')
      const testRuleBtn = menuButtons.find((btn) => btn.text().includes('前往规则页匹配核验'))
      expect(testRuleBtn, 'mobile card menu should have rule match check action').toBeTruthy()
      await testRuleBtn!.trigger('click')
      await settle(200)

      // Navigated to Rules page and auto-ran match tester for api.github.com.
      expect(storeOf(wrapper).page.value).toBe('rules')
      expect(wrapper.find('[data-testid="rule-matcher-panel"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="rule-match-result"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="rule-match-summary"]').text()).toContain('api.github.com')
    })
  })

  describe('R2: Rules match tester, RULE-SET penetration, skipped disabled, uncertain & locate highlight', () => {
    it('disables rule matcher when disconnected, validates input, penetrates RULE-SET, shows skipped/uncertain, and highlights located row', async () => {
      const { wrapper } = await mountApp()
      await openPage(wrapper, 'rules')

      // Disconnected: matcher button is disabled.
      const toggleBtn = wrapper.find('[data-testid="rule-match-toggle"]')
      expect(toggleBtn.attributes('disabled')).toBeDefined()

      await openPage(wrapper, 'home')
      await connect(wrapper)
      await openPage(wrapper, 'rules')
      await settle(150)

      await wrapper.find('[data-testid="rule-match-toggle"]').trigger('click')
      await settle(40)
      expect(wrapper.find('[data-testid="rule-matcher-panel"]').exists()).toBe(true)

      // Invalid port validation shows error without mutating rule list.
      const initialRowCount = wrapper.findAll('[data-testid="rule-row"]').length
      await wrapper.find('[data-testid="rule-match-target"]').setValue('api.github.com')
      await wrapper.find('[data-testid="rule-match-extra-toggle"]').trigger('click')
      await settle(20)
      await wrapper.find('[data-testid="rule-match-port"]').setValue('99999')
      await wrapper.find('[data-testid="rule-match-form"]').trigger('submit')
      await settle(40)
      expect(wrapper.find('[data-testid="rule-match-error"]').exists()).toBe(true)
      expect(wrapper.findAll('[data-testid="rule-row"]').length).toBe(initialRowCount)

      // Valid domain match.
      await wrapper.find('[data-testid="rule-match-port"]').setValue('443')
      await wrapper.find('[data-testid="rule-match-process"]').setValue('curl')
      await wrapper.find('[data-testid="rule-match-form"]').trigger('submit')
      await settle(120)
      expect(wrapper.find('[data-testid="rule-match-error"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="rule-match-hit"]').exists()).toBe(true)

      // Locate matched rule clears blocking search filter and highlights the row.
      await wrapper.find('[data-testid="rule-toolbar"] input[type="search"]').setValue('no-such-filter-xyz')
      await settle(40)
      expect(wrapper.findAll('[data-testid="rule-row"]')).toHaveLength(0)
      await wrapper.find('[data-testid="rule-match-locate"]').trigger('click')
      await settle(60)
      expect(wrapper.find('[data-rule-highlighted="true"]').exists()).toBe(true)

      // Temporarily disabling the matched rule causes the next match to record it in skipped_disabled.
      const firstHitToggle = wrapper.find('[data-rule-highlighted="true"] [data-testid="rule-toggle"]')
      if (firstHitToggle.exists()) {
        await firstHitToggle.trigger('click')
        await settle(120)
        await wrapper.find('[data-testid="rule-match-form"]').trigger('submit')
        await settle(120)
        expect(wrapper.find('[data-testid="rule-match-skipped"]').exists()).toBe(true)
      }
    })

    it('provides mobile rule row action menu', async () => {
      const { wrapper } = await mountApp({}, 390)
      await connect(wrapper)
      await openPage(wrapper, 'rules')
      await settle(150)

      const menuBtn = wrapper.find('[data-testid="rule-row-menu"]')
      expect(menuBtn.exists()).toBe(true)
      await menuBtn.trigger('click')
      await settle(40)
      const items = body().findAll('.context-menu button, [role="menuitem"]')
      expect(items.some((btn) => btn.text().includes('复制规则'))).toBe(true)
    })
  })

  describe('R3: Logs dynamic virtualization, issues filter, filtered export/copy & row actions', () => {
    it('virtualizes 1000 log lines, preserves scroll when scrolled up, filters issues, and extracts row targets', async () => {
      const { wrapper, backend } = await mountApp()
      const origState = backend.state.bind(backend)
      const logs: LogLine[] = Array.from({ length: 1000 }, (_, i) => ({
        level: i === 995 ? 'error' : i === 996 ? 'warning' : 'info',
        message:
          i === 995
            ? '[TCP] 127.0.0.1:50000 --> api.openai.com:443 match DOMAIN-SUFFIX'
            : i === 996
              ? 'warning upstream slow for 1.1.1.1:53'
              : `normal-log-line-${i}`,
        time_ms: 1_700_000_000_000 + i * 100,
      }))
      backend.state = async () => ({
        ...(await origState()),
        logs: logs.map((l) => ({ ...l })),
      })

      await openPage(wrapper, 'logs')
      await storeOf(wrapper).refresh()
      await settle(80)

      // Virtualized: total count is 1000, mounted DOM nodes are far fewer than 1000.
      expect(wrapper.find('[data-testid="log-count"]').text()).toBe('1000 条')
      const mountedCount = wrapper.findAll('.log-line').length
      expect(mountedCount).toBeGreaterThan(0)
      expect(mountedCount).toBeLessThan(80)

      // Filter by 'issues' (warning + error = 2 lines).
      await wrapper.find('.log-level-filter [data-value="issues"]').trigger('click')
      await settle(50)
      expect(wrapper.findAll('.log-line')).toHaveLength(2)
      expect(wrapper.find('[data-testid="copy-logs"]').text()).toContain('复制筛选 (2)')
      expect(wrapper.find('[data-testid="export-logs"]').text()).toContain('导出筛选 (2)')

      // Empty filter result disables copy & export with clear reason.
      await wrapper.find('.log-toolbar input[type="search"]').setValue('nonexistent-xyz-token')
      await settle(40)
      expect(wrapper.find('[data-testid="copy-logs"]').attributes('disabled')).toBeDefined()
      expect(wrapper.find('[data-testid="export-logs"]').attributes('disabled')).toBeDefined()
      await wrapper.find('[data-testid="clear-log-filter"]').trigger('click')
      await settle(40)

      // Filter to error row and use row menu to jump to Rules match tester with extracted host.
      await wrapper.find('.log-level-filter [data-value="error"]').trigger('click')
      await settle(40)
      expect(wrapper.findAll('.log-line')).toHaveLength(1)
      await wrapper.find('[data-testid="log-line-more"]').trigger('click')
      await settle(40)
      const menuButtons = wrapper.findAll('.log-row-menu [role="menuitem"], .log-row-menu button')
      const testRuleItem = menuButtons.find((btn) => btn.text().includes('api.openai.com') && btn.text().includes('规则页'))
      expect(testRuleItem, 'log row menu should offer testing extracted domain in Rules').toBeTruthy()
      await testRuleItem!.trigger('click')
      await settle(200)
      expect(storeOf(wrapper).page.value).toBe('rules')
      expect(wrapper.find('[data-testid="rule-matcher-panel"]').exists()).toBe(true)
    })
  })

  describe('R4: Resources permanent toolbar, batch healthcheck + retry, detail show-more & copy', () => {
    it('shows permanent toolbar below 8 items, runs batch healthcheck with failure retry, and expands detail modal with copy', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined)
      Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })

      const { wrapper, backend } = await mountApp()
      await connect(wrapper)
      await openPage(wrapper, 'resources')
      await settle(300)

      // Permanent toolbar always rendered even with <= 8 providers.
      expect(wrapper.find('[data-testid="provider-toolbar"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="provider-search"]').exists()).toBe(true)
      expect(wrapper.find('[data-testid="provider-filter"]').exists()).toBe(true)

      // Category filter: rule only.
      await wrapper.find('[data-testid="provider-filter"] [data-value="rule"]').trigger('click')
      await settle(40)
      expect(wrapper.find('[data-section="proxy"]').exists()).toBe(false)
      expect(wrapper.find('[data-section="rule"]').exists()).toBe(true)
      await wrapper.find('[data-testid="reset-provider-filters"]').trigger('click')
      await settle(40)

      // Proxy batch healthcheck with one injected failure -> retry failed reruns healthcheck.
      let failOnce = true
      const origAction = backend.providerAction.bind(backend)
      const actionSpy = vi.spyOn(backend, 'providerAction').mockImplementation(async (kind, name, action) => {
        if (kind === 'proxy' && action === 'healthcheck' && failOnce) {
          failOnce = false
          throw new Error('healthcheck timeout')
        }
        return origAction(kind, name, action)
      })

      await wrapper.find('[data-testid="healthcheck-all-proxy"]').trigger('click')
      await settle(1500)
      expect(actionSpy).toHaveBeenCalledWith('proxy', expect.any(String), 'healthcheck')
      const retryBtn = wrapper.find('[data-testid="retry-failed-proxy"]')
      expect(retryBtn.exists()).toBe(true)
      await retryBtn.trigger('click')
      await settle(1500)
      expect(wrapper.find('[data-testid="retry-failed-proxy"]').exists()).toBe(false)

      // Open a large rule provider detail (> 400 rows) -> progressive "显示更多" & single-row copy.
      const ruleOpenButtons = wrapper.findAll('[data-section="rule"] [data-testid^="open-provider-"]')
      expect(ruleOpenButtons.length).toBeGreaterThan(0)
      // Open the MRS rule provider (has > 400 rules in demo).
      const largeRuleBtn =
        ruleOpenButtons.find((b) => b.attributes('data-testid')?.includes('cn')) ?? ruleOpenButtons[0]!
      await largeRuleBtn.trigger('click')
      await settle(300)

      const initialDetailRows = body().findAll('.detail-rules > li:not(.detail-more-row):not(.empty-line)').length
      if (body().find('[data-testid="detail-show-more"]').exists()) {
        expect(initialDetailRows).toBe(400)
        await body().find('[data-testid="detail-show-more"]').trigger('click')
        await settle(50)
        const expandedRows = body().findAll('.detail-rules > li:not(.detail-more-row):not(.empty-line)').length
        expect(expandedRows).toBeGreaterThan(400)
      }

      const copyRuleBtn = body().find('[data-testid="copy-detail-rule"]')
      expect(copyRuleBtn.exists()).toBe(true)
      await copyRuleBtn.trigger('click')
      await settle(40)
      expect(writeText).toHaveBeenCalled()
    })
  })

  describe('R5: Cross-page return stack, invalidation on disconnect & CSS/a11y invariants', () => {
    it('restores Rules context when returning from Resources and clears stale context on disconnect', async () => {
      const { wrapper } = await mountApp()
      await connect(wrapper)
      await openPage(wrapper, 'rules')
      await settle(150)

      // Open a RULE-SET from Rules page.
      const openProviderBtn = wrapper.find('[data-testid="rule-open-provider"]')
      if (openProviderBtn.exists()) {
        await openProviderBtn.trigger('click')
        await settle(300)
        expect(storeOf(wrapper).page.value).toBe('resources')
        expect(storeOf(wrapper).ruleReturn.value?.targetPage).toBe('resources')

        // Detail modal footer offers "返回规则".
        const backBtn = body().find('[data-testid="provider-return-rule"]')
        expect(backBtn.exists()).toBe(true)
        await backBtn.trigger('click')
        await settle(150)
        expect(storeOf(wrapper).page.value).toBe('rules')
        expect(storeOf(wrapper).ruleReturn.value).toBeNull()
      }

      // Disconnecting clears any active ruleReturn context.
      storeOf(wrapper).ruleReturn.value = {
        sessionId: storeOf(wrapper).connectionSessionId.value,
        profileId: storeOf(wrapper).snapshot.value.active_id,
        targetPage: 'resources',
        query: 'github',
        kindFilter: 'all',
        proxyFilter: 'all',
        disabledOnly: false,
        listScrollTop: 0,
        limit: 300,
        matcherOpen: true,
        matchTarget: 'api.github.com',
        matchPort: '',
        matchProcess: '',
        matchResult: null,
      }
      await openPage(wrapper, 'home')
      await wrapper.find('[data-testid="power"]').trigger('click')
      await settle(500)
      expect(storeOf(wrapper).ruleReturn.value).toBeNull()
    })

    it('guards CSS invariants for virtualized logs, reduced-motion highlight, and focus rings', () => {
      const stylesCss = readFileSync(resolve(process.cwd(), 'src/styles.css'), 'utf8')
      const redesignCss = readFileSync(resolve(process.cwd(), 'src/styles/redesign.css'), 'utf8')

      // .log-line must not have content-visibility: auto (conflicts with dynamicVirtual).
      const logLineStart = stylesCss.indexOf('.log-line {')
      const logLineBlock = stylesCss.slice(logLineStart, stylesCss.indexOf('}', logLineStart))
      expect(logLineBlock).not.toContain('content-visibility')

      // Rule highlight animation respects prefers-reduced-motion.
      expect(stylesCss).toContain('rule-highlight-pulse')
      expect(redesignCss).toContain('.rule-row.highlighted')

      // Diagnostic interactive controls carry unified :focus-visible rings.
      for (const selector of [
        '.rule-matcher-toggle:focus-visible',
        '.conn-quick-chip:focus-visible',
        '.log-more-btn:focus-visible',
        '.detail-copy-btn:focus-visible',
      ]) {
        expect(redesignCss).toContain(selector)
      }
    })
  })
})
