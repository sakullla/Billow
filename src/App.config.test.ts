import { DOMWrapper, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import type { Store } from './lib/store'
import type { KernelSettings } from './lib/types'

// Regression coverage for docs/requirements/2026-11-08-mihomo-config.md (R22–R26).

async function settle(ms = 1000) {
  await vi.advanceTimersByTimeAsync(ms)
  await flushPromises()
}

const mounted: { unmount: () => void }[] = []

async function mountApp(options: Parameters<typeof createDemoBackend>[0] = {}, width = 1200) {
  vi.useFakeTimers()
  const backend = createDemoBackend(options)
  const saved: KernelSettings[] = []
  const save = backend.saveSettings.bind(backend)
  backend.saveSettings = (settings) => {
    saved.push(JSON.parse(JSON.stringify(settings)))
    return save(settings)
  }
  const wrapper = mount(App, { props: { backend, width }, attachTo: document.body })
  mounted.push(wrapper)
  await settle(50)
  return { wrapper, backend, saved }
}

type Wrapper = Awaited<ReturnType<typeof mountApp>>['wrapper']

const body = () => new DOMWrapper(document.body)
const storeOf = (wrapper: Wrapper) => (wrapper.vm as unknown as { store: Store }).store

async function openKernelSettings(wrapper: Wrapper) {
  storeOf(wrapper).openSettings('kernel')
  await flushPromises()
}

function rowWith(wrapper: Wrapper, title: string) {
  return wrapper.findAll('.setting-row').find((row) => row.find('strong').text().startsWith(title))!
}

async function pickSelect(wrapper: Wrapper, selector: string, value: string) {
  await wrapper.find(selector).trigger('click')
  await flushPromises()
  const option = body().find(`[data-testid="select-popover"] [data-option-value="${value}"]`)
  expect(option.exists()).toBe(true)
  await option.trigger('click')
  await flushPromises()
}

afterEach(() => {
  mounted.splice(0).forEach((wrapper) => wrapper.unmount())
  localStorage.clear()
  document.body.innerHTML = ''
  vi.useRealTimers()
})

describe('effective config viewer', () => {
  it('R22: opens from kernel settings with each value labelled by where it comes from', async () => {
    const { wrapper } = await mountApp()
    await openKernelSettings(wrapper)
    await rowWith(wrapper, '局域网连接').find('[role="switch"]').trigger('click')
    await settle(400)

    await wrapper.find('[data-testid="settings-open-config"]').trigger('click')
    await settle(300)
    const lan = body().find('.cfg-row[data-path="allow-lan"]')
    expect(lan.text()).toContain('开启')
    expect(lan.attributes('data-source')).toBe('billow')
    expect(lan.find('.tag').attributes('title')).toBe('由 Billow 设置覆盖；配置中为 关闭')
    // Values the profile sets itself carry no tag.
    expect(body().find('.cfg-row[data-path="log-level"]').attributes('data-source')).toBe('profile')
    expect(body().find('.cfg-row[data-path="log-level"] .tag').exists()).toBe(false)
    expect(body().text()).toContain('密码与密钥已隐藏')

    // The source filter narrows the list to what Billow changed.
    const billow = body().findAll('[data-testid="config-sources"] button').find((button) => button.text().startsWith('Billow'))!
    await billow.trigger('click')
    const sources = body().findAll('.cfg-row').map((row) => row.attributes('data-source'))
    expect(sources.length).toBeGreaterThan(0)
    expect(sources.every((source) => source === 'billow')).toBe(true)
  })

  it('R22: search matches YAML keys and a row leads to the setting that changes it', async () => {
    const { wrapper } = await mountApp()
    const store = storeOf(wrapper)
    store.openConfig('overview')
    await settle(300)

    await body().find('[data-testid="config-search"]').setValue('enhanced-mode')
    const rows = body().findAll('.cfg-row')
    expect(rows.map((row) => row.attributes('data-path'))).toEqual(['dns.enhanced-mode'])

    await rows[0]!.trigger('click')
    await flushPromises()
    expect(store.configView.value).toBeNull()
    expect(store.page.value).toBe('settings')
    expect(store.settingsTab.value).toBe('dns')
  })

  it('R22: remembers the last tab and is reachable from the command palette', async () => {
    const { wrapper } = await mountApp()
    await wrapper.find('[data-testid="open-palette"]').trigger('click')
    await flushPromises()
    await body().find('[data-command="action:open-config"]').trigger('click')
    await settle(300)
    expect(body().find('[data-testid="config-overview"]').exists()).toBe(true)

    await body().find('[data-testid="config-tabs"] [data-value="yaml"]').trigger('click')
    await settle(300)
    expect(body().find('[data-testid="effective-config"]').exists()).toBe(true)
    await body().find('.modal-foot .btn.primary').trigger('click')
    await flushPromises()

    storeOf(wrapper).openConfig()
    await settle(300)
    expect(body().find('[data-testid="effective-config"]').exists()).toBe(true)
  })

  it('R22: the settings entry waits for an enabled profile', async () => {
    const { wrapper } = await mountApp({ profiles: false })
    await openKernelSettings(wrapper)
    const open = wrapper.find('[data-testid="settings-open-config"]')
    expect(open.attributes('disabled')).toBeDefined()
    expect(rowWith(wrapper, '生效配置').text()).toContain('启用一份配置后可查看')
  })
})

describe('LAN sharing', () => {
  it('R23: stays out of sight until 局域网连接 is on, then shows where to point other devices', async () => {
    const { wrapper } = await mountApp()
    await openKernelSettings(wrapper)
    expect(wrapper.find('[data-testid="lan-block"]').exists()).toBe(false)

    await rowWith(wrapper, '局域网连接').find('[role="switch"]').trigger('click')
    await settle(400)
    expect(wrapper.find('[data-testid="lan-address"]').text()).toBe('192.168.1.23:7890')
  })

  it('R23: saves a user and an allow-list, and refuses half-filled or unreadable input', async () => {
    const { wrapper, saved } = await mountApp()
    await openKernelSettings(wrapper)
    await rowWith(wrapper, '局域网连接').find('[role="switch"]').trigger('click')
    await settle(400)
    const before = saved.length

    await wrapper.find('[data-testid="lan-user"]').setValue('alice')
    await wrapper.find('[data-testid="save-lan"]').trigger('click')
    await flushPromises()
    expect(saved.length).toBe(before)
    expect(body().findAll('.toast').map((toast) => toast.text()).join('\n')).toContain('用户名和密码需要同时填写')

    await wrapper.find('[data-testid="lan-pass"]').setValue('s3cret')
    await wrapper.find('[data-testid="lan-ips"]').setValue('192.168.1.0/24, phone')
    await wrapper.find('[data-testid="save-lan"]').trigger('click')
    await flushPromises()
    expect(saved.length).toBe(before)
    expect(body().text()).toContain('无法识别「phone」')

    await wrapper.find('[data-testid="lan-ips"]').setValue('192.168.1.0/24，10.0.0.8')
    await wrapper.find('[data-testid="save-lan"]').trigger('click')
    await settle(400)
    const last = saved[saved.length - 1]!
    expect(last.lan_auth).toEqual(['alice:s3cret'])
    expect(last.lan_allowed_ips).toEqual(['192.168.1.0/24', '10.0.0.8'])
    expect(wrapper.find('[data-testid="save-lan"]').exists()).toBe(false)
    expect(wrapper.find('.lan-label .tag').text()).toBe('已开启')
  })

  it('R23: 撤销 restores the saved values', async () => {
    const { wrapper } = await mountApp()
    await openKernelSettings(wrapper)
    await rowWith(wrapper, '局域网连接').find('[role="switch"]').trigger('click')
    await settle(400)
    await wrapper.find('[data-testid="lan-ips"]').setValue('10.0.0.0/8')
    await wrapper.find('[data-testid="undo-lan"]').trigger('click')
    await flushPromises()
    expect((wrapper.find('[data-testid="lan-ips"]').element as HTMLInputElement).value).toBe('')
    expect(wrapper.find('[data-testid="save-lan"]').exists()).toBe(false)
  })
})

describe('options aligned with mihomo v1.19.34', () => {
  it('R24: TCP keep-alive follows the profile until chosen, and stays off the phone', async () => {
    const { wrapper, saved } = await mountApp()
    await openKernelSettings(wrapper)
    expect(wrapper.text()).not.toContain('TLS 客户端指纹')
    expect(rowWith(wrapper, 'TCP 保活').text()).toContain('配置未设置，默认 15 秒')

    await pickSelect(wrapper, '[data-testid="keep-alive-select"]', '0')
    await settle(400)
    expect(saved[saved.length - 1]!.keep_alive_interval).toBe(0)
    expect(rowWith(wrapper, 'TCP 保活').find('.tag').text()).toBe('已覆盖')

    await pickSelect(wrapper, '[data-testid="keep-alive-select"]', '')
    await settle(400)
    expect(saved[saved.length - 1]!.keep_alive_interval).toBeNull()

    // 全部跟随配置 clears the newer options too.
    await pickSelect(wrapper, '[data-testid="keep-alive-select"]', '60')
    await settle(400)
    const reset = wrapper.findAll('button').find((button) => button.text() === '全部跟随配置')!
    await reset.trigger('click')
    await settle(400)
    const last = saved[saved.length - 1]!
    expect(last.keep_alive_interval).toBeNull()
    expect(last.lan_auth).toEqual([])

    const phone = await mountApp({ platform: 'android' }, 390)
    storeOf(phone.wrapper).openSettings('kernel')
    await flushPromises()
    expect(phone.wrapper.find('[data-testid="keep-alive-select"]').exists()).toBe(false)
    expect(phone.wrapper.find('.settings-fold summary').text()).not.toContain('保活')
  })

  it('R25: GEO files load low-memory by default and the loader can be pinned', async () => {
    const { wrapper, saved } = await mountApp()
    await wrapper.find('[data-testid="power"]').trigger('click')
    await settle(1500)
    storeOf(wrapper).go('resources')
    await settle(500)
    await wrapper.find('[data-testid="open-geo-settings"]').trigger('click')
    await flushPromises()
    const loader = () => body().find('[data-testid="geodata-loader"]')
    expect(loader().find('[aria-checked="true"]').text()).toBe('默认')
    expect(body().text()).toContain('未设置时内核默认低内存模式')

    await loader().find('[data-value="standard"]').trigger('click')
    await settle(400)
    expect(saved[saved.length - 1]!.geodata_loader).toBe('standard')
    expect(body().text()).toContain('一次读入整个 GEO 文件')

    storeOf(wrapper).openConfig('overview')
    await settle(300)
    const row = body().find('.cfg-row[data-path="geodata-loader"]')
    expect(row.text()).toContain('标准')
    expect(row.attributes('data-source')).toBe('billow')
  })

  it('R26: TUN defaults to the kernel stack (Mips), and a removed global fingerprint is called out', async () => {
    const { wrapper } = await mountApp()
    storeOf(wrapper).openSettings('tun')
    await flushPromises()
    const stack = wrapper.find('[data-testid="tun-stack"]')
    expect(stack.find('[aria-checked="true"]').text()).toBe('默认')
    expect(rowWith(wrapper, '协议栈').text()).toContain('Mips')

    storeOf(wrapper).openConfig('overview')
    await settle(300)
    expect(body().find('.cfg-row[data-path="tun.stack"]').text()).toContain('内核默认（Mips）')
    expect(body().find('.cfg-row[data-path="global-client-fingerprint"]').text()).toContain('内核已移除，不生效')
  })

  it('R26: DNS offers the rule filter mode with its own hint', async () => {
    const { wrapper, saved } = await mountApp()
    storeOf(wrapper).openSettings('dns')
    await flushPromises()
    for (const fold of wrapper.findAll<HTMLDetailsElement>('details')) fold.element.open = true
    const mode = wrapper.find('[data-testid="dns-filter-mode"]')
    expect(mode.exists()).toBe(true)
    await mode.find('[data-value="rule"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('MATCH,fake-ip')
    const save = wrapper.findAll('button').find((button) => button.text() === '保存' && !button.attributes('disabled'))!
    await save.trigger('click')
    await settle(400)
    expect(saved[saved.length - 1]!.dns.fake_ip_filter_mode).toBe('rule')
  })
})

describe('batch editors', () => {
  async function openDns(wrapper: Wrapper) {
    storeOf(wrapper).openSettings('dns')
    await flushPromises()
  }

  it('keeps batch-edited DNS policies when switching back to the list, including YAML and #suffix servers', async () => {
    const { wrapper, saved } = await mountApp()
    await openDns(wrapper)
    await wrapper.find('[data-testid="toggle-policy-batch"]').trigger('click')
    await wrapper.find('[data-testid="policy-batch-textarea"]').setValue(
      "+.corp.example = 180.76.76.76, 223.5.5.5\n'+.e6yun.com': [180.76.76.76]\ngeosite:cn = https://doh.pub/dns-query#DIRECT # note",
    )
    await wrapper.find('[data-testid="toggle-policy-batch"]').trigger('click')
    const values = wrapper.findAll('[data-testid="policy-list"] input').map((input) => (input.element as HTMLInputElement).value)
    expect(values).toEqual([
      '+.corp.example', '180.76.76.76, 223.5.5.5',
      '+.e6yun.com', '180.76.76.76',
      'geosite:cn', 'https://doh.pub/dns-query#DIRECT',
    ])
    await wrapper.find('[data-testid="save-dns"]').trigger('click')
    await settle(400)
    expect(saved.at(-1)?.dns.nameserver_policy['+.e6yun.com']).toEqual(['180.76.76.76'])
  })

  it('refuses to leave batch mode while a line cannot be read', async () => {
    const { wrapper } = await mountApp()
    await openDns(wrapper)
    await wrapper.find('[data-testid="toggle-policy-batch"]').trigger('click')
    await wrapper.find('[data-testid="policy-batch-textarea"]').setValue('+.ok.com = 1.1.1.1\n+.missing.com')
    expect(wrapper.find('[data-testid="policy-batch-invalid"]').text()).toContain('第 2 行')
    await wrapper.find('[data-testid="toggle-policy-batch"]').trigger('click')
    expect(wrapper.find('[data-testid="policy-batch-textarea"]').exists()).toBe(true)
  })

  it('keeps batch-edited bypass entries when switching back to the list', async () => {
    const { wrapper } = await mountApp()
    storeOf(wrapper).openSettings('proxy')
    await flushPromises()
    await wrapper.find('[data-testid="toggle-bypass-batch"]').trigger('click')
    await wrapper.find('[data-testid="bypass-batch-textarea"]').setValue('localhost\ng7e6ai.com;*.corp.local')
    await wrapper.find('[data-testid="toggle-bypass-batch"]').trigger('click')
    expect(wrapper.findAll('[data-testid="bypass-list"] li').map((item) => item.text())).toEqual(['localhost', 'g7e6ai.com', '*.corp.local'])
  })
})
