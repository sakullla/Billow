import { DOMWrapper, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App.vue'
import { createDemoBackend } from './lib/demo'
import type { Store } from './lib/store'
import type { KernelSettings } from './lib/types'

// Regression coverage for docs/requirements/2026-11-08-mihomo-config.md (R22–R26)
// and docs/requirements/2026-11-19-mihomo-support-gaps.md (R32–R35).

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

async function openPane(wrapper: Wrapper, tab: Parameters<Store['openSettings']>[0]) {
  storeOf(wrapper).openSettings(tab)
  await flushPromises()
}

const openKernelSettings = (wrapper: Wrapper) => openPane(wrapper, 'kernel')

/** Opens an editor dialog from its settings row; the dialog renders into <body>. */
async function openEditor(wrapper: Wrapper, testid: string) {
  await wrapper.find(`[data-testid="${testid}"]`).trigger('click')
  await flushPromises()
}

function rowWith(wrapper: Wrapper, title: string) {
  return wrapper.findAll('.srow').find((row) => row.find('.srow-title').exists() && row.find('.srow-title').text().startsWith(title))!
}

/** 全部跟随配置 lives on the kernel page behind a confirmation. */
async function resetAllOverrides(wrapper: Wrapper) {
  await openKernelSettings(wrapper)
  await wrapper.find('[data-testid="reset-overrides"]').trigger('click')
  await flushPromises()
  await body().find('[data-testid="confirm-reset-overrides"]').trigger('click')
  await settle(400)
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
    await openPane(wrapper, 'network')
    await rowWith(wrapper, '局域网连接').find('[role="switch"]').trigger('click')
    await settle(400)

    await openKernelSettings(wrapper)
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
    await openPane(wrapper, 'network')
    expect(wrapper.find('[data-testid="lan-block"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="open-lan-access"]').exists()).toBe(false)

    await rowWith(wrapper, '局域网连接').find('[role="switch"]').trigger('click')
    await settle(400)
    expect(wrapper.find('[data-testid="lan-address"]').text()).toBe('192.168.1.23:7890')
  })

  it('R23: saves a user and an allow-list, and refuses half-filled or unreadable input', async () => {
    const { wrapper, saved } = await mountApp()
    await openPane(wrapper, 'network')
    await rowWith(wrapper, '局域网连接').find('[role="switch"]').trigger('click')
    await settle(400)
    const before = saved.length
    await openEditor(wrapper, 'open-lan-access')

    await body().find('[data-testid="lan-user"]').setValue('alice')
    await body().find('[data-testid="save-lan"]').trigger('click')
    await flushPromises()
    expect(saved.length).toBe(before)
    expect(body().find('[data-testid="lan-error"]').text()).toContain('用户名和密码需要同时填写')

    await body().find('[data-testid="lan-pass"]').setValue('s3cret')
    await body().find('[data-testid="lan-ips"]').setValue('192.168.1.0/24, phone')
    await body().find('[data-testid="save-lan"]').trigger('click')
    await flushPromises()
    expect(saved.length).toBe(before)
    expect(body().text()).toContain('无法识别「phone」')

    await body().find('[data-testid="lan-ips"]').setValue('192.168.1.0/24，10.0.0.8')
    await body().find('[data-testid="save-lan"]').trigger('click')
    await settle(400)
    const last = saved[saved.length - 1]!
    expect(last.lan_auth).toEqual(['alice:s3cret'])
    expect(last.lan_allowed_ips).toEqual(['192.168.1.0/24', '10.0.0.8'])
    expect(body().find('[data-testid="save-lan"]').exists()).toBe(false)
    expect(rowWith(wrapper, '访问控制').find('.srow-badge').text()).toBe('已开启')
    expect(rowWith(wrapper, '访问控制').text()).toContain('需要密码 · 限 2 个地址')
  })

  it('R23: 撤销 restores the saved values', async () => {
    const { wrapper, saved } = await mountApp()
    await openPane(wrapper, 'network')
    await rowWith(wrapper, '局域网连接').find('[role="switch"]').trigger('click')
    await settle(400)
    const before = saved.length
    await openEditor(wrapper, 'open-lan-access')
    await body().find('[data-testid="lan-ips"]').setValue('10.0.0.0/8')
    await body().find('[data-testid="undo-lan"]').trigger('click')
    await flushPromises()
    expect(body().find('[data-testid="save-lan"]').exists()).toBe(false)
    expect(saved.length).toBe(before)
    await openEditor(wrapper, 'open-lan-access')
    expect((body().find('[data-testid="lan-ips"]').element as HTMLInputElement).value).toBe('')
  })
})

describe('options aligned with mihomo v1.19.34', () => {
  it('R24: TCP keep-alive follows the profile until chosen, and stays off the phone', async () => {
    const { wrapper, saved } = await mountApp()
    await openPane(wrapper, 'network')
    expect(wrapper.text()).not.toContain('TLS 客户端指纹')
    expect(rowWith(wrapper, 'TCP 保活').text()).toContain('配置未设置，默认 15 秒')

    await pickSelect(wrapper, '[data-testid="keep-alive-select"]', '0')
    await settle(400)
    expect(saved[saved.length - 1]!.keep_alive_interval).toBe(0)
    expect(rowWith(wrapper, 'TCP 保活').find('.srow-badge').text()).toBe('已覆盖')

    await pickSelect(wrapper, '[data-testid="keep-alive-select"]', '')
    await settle(400)
    expect(saved[saved.length - 1]!.keep_alive_interval).toBeNull()

    // 全部跟随配置 clears the newer options too.
    await pickSelect(wrapper, '[data-testid="keep-alive-select"]', '60')
    await settle(400)
    await resetAllOverrides(wrapper)
    const last = saved[saved.length - 1]!
    expect(last.keep_alive_interval).toBeNull()
    expect(last.lan_auth).toEqual([])

    const phone = await mountApp({ platform: 'android' }, 390)
    storeOf(phone.wrapper).openSettings('network')
    await flushPromises()
    expect(phone.wrapper.find('[data-testid="keep-alive-select"]').exists()).toBe(false)
    expect(phone.wrapper.text()).not.toContain('保活')
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
    await settle(400)
    expect(wrapper.text()).toContain('MATCH,fake-ip')
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
    await openEditor(wrapper, 'open-dns-policy')
    await body().find('[data-testid="toggle-policy-batch"]').trigger('click')
    await body().find('[data-testid="policy-batch-textarea"]').setValue(
      "+.corp.example = 180.76.76.76, 223.5.5.5\n'+.e6yun.com': [180.76.76.76]\ngeosite:cn = https://doh.pub/dns-query#DIRECT # note",
    )
    await body().find('[data-testid="toggle-policy-batch"]').trigger('click')
    const values = body().findAll('[data-testid="policy-list"] input').map((input) => (input.element as HTMLInputElement).value)
    expect(values).toEqual([
      '+.corp.example', '180.76.76.76, 223.5.5.5',
      '+.e6yun.com', '180.76.76.76',
      'geosite:cn', 'https://doh.pub/dns-query#DIRECT',
    ])
    await body().find('[data-testid="save-dns-policy"]').trigger('click')
    await settle(400)
    expect(saved.at(-1)?.dns.nameserver_policy['+.e6yun.com']).toEqual(['180.76.76.76'])
  })

  it('refuses to leave batch mode while a line cannot be read', async () => {
    const { wrapper } = await mountApp()
    await openDns(wrapper)
    await openEditor(wrapper, 'open-dns-policy')
    await body().find('[data-testid="toggle-policy-batch"]').trigger('click')
    await body().find('[data-testid="policy-batch-textarea"]').setValue('+.ok.com = 1.1.1.1\n+.missing.com')
    expect(body().find('[data-testid="policy-batch-invalid"]').text()).toContain('第 2 行')
    await body().find('[data-testid="toggle-policy-batch"]').trigger('click')
    expect(body().find('[data-testid="policy-batch-textarea"]').exists()).toBe(true)
  })

  it('keeps batch-edited bypass entries when switching back to the list', async () => {
    const { wrapper } = await mountApp()
    storeOf(wrapper).openSettings('proxy')
    await flushPromises()
    await openEditor(wrapper, 'open-bypass')
    await body().find('[data-testid="toggle-bypass-batch"]').trigger('click')
    await body().find('[data-testid="bypass-batch-textarea"]').setValue('localhost\ng7e6ai.com;*.corp.local')
    await body().find('[data-testid="toggle-bypass-batch"]').trigger('click')
    expect(body().findAll('[data-testid="bypass-list"] li').map((item) => item.text())).toEqual(['localhost', 'g7e6ai.com', '*.corp.local'])
  })
})

describe('kernel maintenance (R35)', () => {
  it('offers 回收内存 only at log level debug and toasts 已回收', async () => {
    const { wrapper, backend } = await mountApp()
    const gc = vi.spyOn(backend, 'gcKernel')
    void storeOf(wrapper).connect()
    await settle(1000)
    await openKernelSettings(wrapper)
    expect(wrapper.find('[data-testid="kernel-gc-row"]').exists()).toBe(false)

    await pickSelect(wrapper, '[data-testid="log-level-select"]', 'debug')
    await settle(400)
    const button = wrapper.find('[data-testid="kernel-gc"]')
    expect(button.exists()).toBe(true)
    expect(button.attributes('disabled')).toBeUndefined()
    await button.trigger('click')
    await settle(300)
    expect(gc).toHaveBeenCalledTimes(1)
    expect(body().findAll('.toast').map((toast) => toast.text()).join('\n')).toContain('已回收')

    await pickSelect(wrapper, '[data-testid="log-level-select"]', 'info')
    await settle(400)
    expect(wrapper.find('[data-testid="kernel-gc-row"]').exists()).toBe(false)
  })
})

/** The demo overview waits on a timer; fake timers must run it. */
async function overviewOf(backend: ReturnType<typeof createDemoBackend>) {
  const pending = backend.configOverview()
  await settle(200)
  return pending
}

describe('TUN route addresses (R32)', () => {
  async function openTun(wrapper: Wrapper) {
    storeOf(wrapper).openSettings('tun')
    await flushPromises()
  }

  it('saves 不走 TUN 的地址 into the running config, refuses an unreadable entry and is cleared by both resets', async () => {
    const { wrapper, backend, saved } = await mountApp()
    await openTun(wrapper)
    expect(wrapper.find('[data-testid="open-tun-route-exclude"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="open-tun-route-include"]').exists()).toBe(true)
    const editExclude = async (value: string) => {
      await openEditor(wrapper, 'open-tun-route-exclude')
      await body().find('[data-testid="tun-route-exclude-address-input"]').setValue(value)
      await body().find('[data-testid="tun-route-exclude-address-save"]').trigger('click')
      await settle(400)
    }

    await editExclude('192.168.0.0/16')
    expect(saved.at(-1)!.tun.route_exclude_address).toEqual(['192.168.0.0/16'])
    expect(saved.at(-1)!.tun.route_address).toBeNull()
    expect(rowWith(wrapper, '不走 TUN 的地址').find('.srow-badge').text()).toBe('已覆盖')
    expect(rowWith(wrapper, '不走 TUN 的地址').text()).toContain('192.168.0.0/16')
    const overview = await overviewOf(backend)
    expect((overview.effective.tun as Record<string, unknown>)['route-exclude-address']).toEqual(['192.168.0.0/16'])
    storeOf(wrapper).openConfig('overview')
    await settle(300)
    const row = body().find('.cfg-row[data-path="tun.route-exclude-address"]')
    expect(row.text()).toContain('192.168.0.0/16')
    expect(row.attributes('data-source')).toBe('billow')
    await body().find('.modal-foot .btn.primary').trigger('click')
    await flushPromises()

    // An unreadable entry keeps the dialog open and names the line.
    const count = saved.length
    await editExclude('300.1.1.0/24')
    expect(saved.length).toBe(count)
    expect(body().find('[data-testid="tun-route-exclude-address-error"]').text()).toContain('「300.1.1.0/24」')
    const unchanged = await overviewOf(backend)
    expect((unchanged.effective.tun as Record<string, unknown>)['route-exclude-address']).toEqual(['192.168.0.0/16'])
    await body().find('[data-testid="editor-cancel"]').trigger('click')
    await flushPromises()

    // TUN 恢复默认 drops the override.
    await wrapper.find('[data-testid="reset-tun"]').trigger('click')
    await flushPromises()
    await body().find('[data-testid="confirm-reset-tun"]').trigger('click')
    await settle(400)
    expect(saved.at(-1)!.tun.route_exclude_address).toBeNull()

    // 全部跟随配置 on the kernel page clears it too.
    await editExclude('10.0.0.0/8')
    expect(saved.at(-1)!.tun.route_exclude_address).toEqual(['10.0.0.0/8'])
    await resetAllOverrides(wrapper)
    expect(saved.at(-1)!.tun.route_exclude_address).toBeNull()
    expect(saved.at(-1)!.tun.route_address).toBeNull()
  })

  it('stays out of sight on Android', async () => {
    const { wrapper } = await mountApp({ platform: 'android' }, 390)
    await openTun(wrapper)
    expect(wrapper.find('[data-testid="open-tun-route-exclude"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="open-tun-route-include"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('不走 TUN 的地址')
  })
})

describe('sniffer details (R33)', () => {
  it('shows the profile value while following, and a fold with per-protocol ports only while sniffing is on', async () => {
    const { wrapper, backend, saved } = await mountApp()
    await openPane(wrapper, 'behavior')
    // The demo profile enables sniffing, so following it shows the switch on.
    expect(rowWith(wrapper, '域名嗅探').find('[role="switch"]').attributes('aria-checked')).toBe('true')
    expect(wrapper.find('[data-testid="sniff-advanced"]').exists()).toBe(true)
    await openEditor(wrapper, 'sniff-advanced')
    const tls = () => body().find('[data-testid="sniff-ports-tls"]')
    // Following the profile shows its value as the placeholder.
    expect(tls().attributes('placeholder')).toBe('443')

    await tls().setValue('443,8443')
    await body().find('[data-testid="save-sniff"]').trigger('click')
    await settle(400)
    expect(saved.at(-1)!.sniff_ports).toEqual({ http: null, tls: ['443', '8443'], quic: null })
    expect(rowWith(wrapper, '嗅探选项').text()).toContain('已自定义')
    const overview = await overviewOf(backend)
    const sniff = (overview.effective.sniffer as { sniff: Record<string, { ports: unknown }> }).sniff
    expect(sniff.TLS!.ports).toEqual([443, 8443])
    expect(sniff.HTTP!.ports).toEqual([80])

    const count = saved.length
    await openEditor(wrapper, 'sniff-advanced')
    await tls().setValue('70000')
    await body().find('[data-testid="save-sniff"]').trigger('click')
    await settle(400)
    expect(saved.length).toBe(count)
    expect(body().find('[data-testid="sniff-error"]').text()).toContain('「70000」')
    expect(((await overviewOf(backend)).effective.sniffer as { sniff: Record<string, { ports: unknown }> }).sniff.TLS!.ports).toEqual([443, 8443])
    await body().find('[data-testid="undo-sniff"]').trigger('click')
    await flushPromises()

    // Off hides the options but keeps what was saved, so turning it back on restores the ports.
    await rowWith(wrapper, '域名嗅探').find('[role="switch"]').trigger('click')
    await settle(400)
    expect(saved.at(-1)!.sniffer).toBe(false)
    expect(saved.at(-1)!.sniff_ports.tls).toEqual(['443', '8443'])
    expect(wrapper.find('[data-testid="sniff-advanced"]').exists()).toBe(false)
    expect((await overviewOf(backend)).effective.sniffer).toEqual({ enable: false })
    await rowWith(wrapper, '域名嗅探').find('[role="switch"]').trigger('click')
    await settle(400)
    await openEditor(wrapper, 'sniff-advanced')
    expect((tls().element as HTMLInputElement).value).toBe('443, 8443')
    await body().find('[data-testid="undo-sniff"]').trigger('click')
    await flushPromises()

    // 全部跟随配置 clears the details along with the switch.
    await resetAllOverrides(wrapper)
    expect(saved.at(-1)!.sniffer).toBeNull()
    expect(saved.at(-1)!.sniff_ports).toEqual({ http: null, tls: null, quic: null })
  })
})

describe('extra listeners, outbound interface and routing mark (R34)', () => {
  const net = (testid: string) => body().find(`[data-testid="${testid}"]`)

  it('saves a SOCKS port into the running config, lists it for LAN devices and refuses a clash with the mixed port', async () => {
    const { wrapper, backend, saved } = await mountApp()
    await openPane(wrapper, 'network')
    await openEditor(wrapper, 'open-extra-ports')
    await net('port-socks_port').setValue('7891')
    await net('save-net').trigger('click')
    await settle(400)
    expect(saved.at(-1)!.socks_port).toBe(7891)
    expect((await overviewOf(backend)).effective['socks-port']).toBe(7891)
    expect(rowWith(wrapper, '更多端口与出口').text()).toContain('已自定义 1 项')

    await rowWith(wrapper, '局域网连接').find('[role="switch"]').trigger('click')
    await settle(400)
    expect(wrapper.find('[data-testid="lan-extra-address"]').text()).toContain('SOCKS')
    expect(wrapper.find('[data-testid="lan-extra-address"]').text()).toContain('192.168.1.23:7891')

    const count = saved.length
    await openEditor(wrapper, 'open-extra-ports')
    await net('port-http_port').setValue('7890')
    await net('save-net').trigger('click')
    await settle(400)
    expect(saved.length).toBe(count)
    expect(net('net-error').text()).toContain('HTTP 端口 7890 与混合端口重复')
    expect((await overviewOf(backend)).effective.port).toBeUndefined()
    await net('undo-net').trigger('click')
    await flushPromises()

    storeOf(wrapper).openConfig('overview')
    await settle(300)
    const row = body().find('.cfg-row[data-path="socks-port"]')
    expect(row.text()).toContain('7891')
    expect(row.attributes('data-source')).toBe('billow')
    await body().find('.modal-foot .btn.primary').trigger('click')
    await flushPromises()

    // An interface name with a space is refused; 全部跟随配置 clears every new item.
    await openEditor(wrapper, 'open-extra-ports')
    await net('interface-choice').find('[data-value="custom"]').trigger('click')
    await net('interface-name').setValue('Wi Fi')
    await net('save-net').trigger('click')
    await flushPromises()
    expect(net('net-error').text()).toContain('不能包含空格')
    await net('interface-name').setValue('en0')
    await net('save-net').trigger('click')
    await settle(400)
    expect(saved.at(-1)!.interface_name).toBe('en0')
    await resetAllOverrides(wrapper)
    const last = saved.at(-1)!
    expect([last.socks_port, last.http_port, last.redir_port, last.tproxy_port, last.interface_name, last.routing_mark]).toEqual([
      null, null, null, null, null, null,
    ])
  })

  it('warns on a saved port that later equals the mixed port in effect', async () => {
    const { wrapper, saved } = await mountApp()
    await openPane(wrapper, 'network')
    await openEditor(wrapper, 'open-extra-ports')
    await net('port-socks_port').setValue('7891')
    await net('save-net').trigger('click')
    await settle(400)
    expect(saved.at(-1)!.socks_port).toBe(7891)
    expect(rowWith(wrapper, '更多端口与出口').text()).not.toContain('端口冲突')

    // Another profile brings its own mixed-port 7891; the saved SOCKS port now collides.
    const snapshot = storeOf(wrapper).snapshot
    snapshot.value = { ...snapshot.value, mixed_port: 7891 }
    await flushPromises()
    expect(rowWith(wrapper, '更多端口与出口').text()).toContain('端口冲突')
    await openEditor(wrapper, 'open-extra-ports')
    const warning = net('port-clash-socks_port')
    expect(warning.exists()).toBe(true)
    expect(warning.text()).toContain('与当前混合端口 7891 相同')
    expect(net('port-clash-http_port').exists()).toBe(false)
  })

  it('shows each item only on the platforms mihomo supports it', async () => {
    const visible = async (options: Parameters<typeof createDemoBackend>[0], width = 1200) => {
      const { wrapper } = await mountApp(options, width)
      await settle(50)
      await openPane(wrapper, 'network')
      const entry = wrapper.find('[data-testid="open-extra-ports"]')
      if (entry.exists()) await openEditor(wrapper, 'open-extra-ports')
      const has = (id: string) => net(id).exists()
      const result = {
        socks: has('port-socks_port'),
        http: has('port-http_port'),
        redir: has('port-redir_port'),
        tproxy: has('port-tproxy_port'),
        iface: has('interface-choice'),
        mark: has('routing-mark'),
      }
      if (entry.exists()) {
        await net('undo-net').trigger('click')
        await flushPromises()
      }
      return result
    }
    expect(await visible({ os: 'windows' })).toEqual({ socks: true, http: true, redir: false, tproxy: false, iface: true, mark: false })
    expect(await visible({ os: 'macos' })).toEqual({ socks: true, http: true, redir: true, tproxy: false, iface: true, mark: false })
    expect(await visible({ os: 'linux' })).toEqual({ socks: true, http: true, redir: true, tproxy: true, iface: true, mark: true })
    expect(await visible({ platform: 'android' }, 390)).toEqual({ socks: false, http: false, redir: false, tproxy: false, iface: false, mark: false })
  })
})

describe('lightweight mode (R44)', () => {
  const releaseRow = () => body().find('[data-testid="release-ui-setting"]')

  it('is offered only while the window stays in the tray and is off by default', async () => {
    const { wrapper } = await mountApp()
    storeOf(wrapper).openSettings('general')
    await settle(50)
    expect(releaseRow().exists()).toBe(true)
    expect(releaseRow().text()).toContain('关闭窗口时释放界面')
    expect(storeOf(wrapper).app.value?.release_ui_on_close).toBe(false)
  })

  it('disappears and stops applying once "close to tray" is turned off', async () => {
    const { wrapper } = await mountApp()
    storeOf(wrapper).openSettings('general')
    await settle(50)

    // Turn the release option on, then turn stay-in-tray off.
    await releaseRow().find('[role="switch"]').trigger('click')
    await settle(50)
    expect(storeOf(wrapper).app.value?.release_ui_on_close).toBe(true)

    await rowWith(wrapper, '关闭时最小化到托盘').find('[role="switch"]').trigger('click')
    await settle(50)
    expect(releaseRow().exists()).toBe(false)
    expect(storeOf(wrapper).app.value?.close_to_tray).toBe(false)
    // The stored choice is kept, but has no effect while stay-in-tray is off.
    expect(storeOf(wrapper).app.value?.release_ui_on_close).toBe(true)
  })

  it('never appears on Android', async () => {
    // Phones have no tray and no window to release.
    const { wrapper } = await mountApp({ platform: 'android' }, 390)
    storeOf(wrapper).openSettings('general')
    await settle(50)
    expect(releaseRow().exists()).toBe(false)
  })
})
