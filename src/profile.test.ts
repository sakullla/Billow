import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import App from './App.vue'
import { createMemoryProfilePort, type ProfilePort } from './profile-port'
import { showsExpire, showsUsage, type ProfileItem } from './profile'
import { createMemoryPort } from './port'

function profile(partial: Partial<ProfileItem> & Pick<ProfileItem, 'id' | 'name'>): ProfileItem {
  return {
    kind: 'local',
    source: '',
    current: false,
    failure: null,
    override_text: '',
    override_error: null,
    used: null,
    total: null,
    expire: null,
    last_success_ms: null,
    ...partial,
  }
}

async function mountApp(profilePort: ProfilePort = createMemoryProfilePort()) {
  const wrapper = mount(App, {
    props: { initialWidth: 900, port: createMemoryPort(), profilePort },
  })
  await (wrapper.vm as unknown as { ready: Promise<void> }).ready
  await flushPromises()
  return wrapper
}

describe('配置', () => {
  it('两份配置分别启用后只有一份当前标记', async () => {
    const profilePort = createMemoryProfilePort({
      profiles: [
        profile({ id: 'p1', name: '甲', source: 'mixed-port: 7890' }),
        profile({ id: 'p2', name: '乙', source: 'mixed-port: 7891' }),
      ],
    })
    const wrapper = await mountApp(profilePort)
    await wrapper.get('[data-entry="settings"]').trigger('click')
    const rows = () => wrapper.findAll('[data-testid="profile-row"]')
    expect(rows()).toHaveLength(2)
    await rows()[0]!.get('[data-action="enable"]').trigger('click')
    await flushPromises()
    expect(wrapper.findAll('[data-testid="profile-current"]')).toHaveLength(1)
    expect(wrapper.get('[data-profile-id="p1"]').attributes('data-current')).toBe('true')
    expect(wrapper.get('[data-testid="effective-value"]').text()).toContain('7890')

    await rows()[1]!.get('[data-action="enable"]').trigger('click')
    await flushPromises()
    expect(wrapper.findAll('[data-testid="profile-current"]')).toHaveLength(1)
    expect(wrapper.get('[data-profile-id="p2"]').attributes('data-current')).toBe('true')
    expect(wrapper.get('[data-profile-id="p1"]').attributes('data-current')).toBe('false')
    expect(wrapper.get('[data-testid="effective-value"]').text()).toContain('7891')
    expect((await profilePort.load()).active_id).toBe('p2')
  })

  it('总量大于 0 时显示已用和总量，到期值为 0 时不显示到期', async () => {
    expect(showsUsage(30, 100)).toBe(true)
    expect(showsUsage(0, 0)).toBe(false)
    expect(showsExpire(0)).toBe(false)
    expect(showsExpire(null)).toBe(false)
    expect(showsExpire(1700000000)).toBe(true)

    const profilePort = createMemoryProfilePort({
      mixed_port: 7890,
      profiles: [
        profile({
          id: 'p1',
          name: '有余量',
          current: true,
          used: 30,
          total: 100,
          expire: 0,
        }),
        profile({ id: 'p2', name: '无余量', used: 0, total: 0, expire: 0 }),
      ],
    })
    const wrapper = await mountApp(profilePort)
    expect(wrapper.get('[data-testid="home-usage"]').text()).toContain('已用 30')
    expect(wrapper.get('[data-testid="home-usage"]').text()).toContain('总量 100')
    expect(wrapper.text()).not.toContain('到期')

    await wrapper.get('[data-entry="settings"]').trigger('click')
    const first = wrapper.get('[data-profile-id="p1"]')
    expect(first.get('[data-testid="profile-usage"]').text()).toContain('已用 30')
    expect(first.get('[data-testid="profile-usage"]').text()).toContain('总量 100')
    expect(wrapper.get('[data-profile-id="p2"]').text()).not.toContain('已用')
    expect(wrapper.get('[data-profile-id="p2"]').text()).not.toContain('总量')
    expect(wrapper.text()).not.toContain('到期')

    const dated = createMemoryProfilePort({
      profiles: [
        profile({
          id: 'p1',
          name: '有到期',
          current: true,
          used: 1,
          total: 2,
          expire: 1700000000,
        }),
      ],
    })
    const again = await mountApp(dated)
    expect(again.get('[data-testid="home-expire"]').text()).toContain('到期')
    expect(again.get('[data-testid="home-expire"]').text()).toMatch(/20\d{2}/)
  })

  it('导入链接确认后才新增，取消不新增，订阅和本地文件是两个入口', async () => {
    const cancelled = createMemoryProfilePort({ pending_url: 'https://example.com/sub' })
    const wrapper = await mountApp(cancelled)
    expect(wrapper.get('[data-testid="install-url"]').text()).toBe('https://example.com/sub')
    await wrapper.get('[data-testid="install-cancel"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="install-confirm"]').exists()).toBe(false)
    expect((await cancelled.load()).profiles).toHaveLength(0)

    const confirmed = createMemoryProfilePort({ pending_url: 'https://example.com/other' })
    const added = await mountApp(confirmed)
    await added.get('[data-testid="install-confirm-yes"]').trigger('click')
    await flushPromises()
    const saved = await confirmed.load()
    expect(saved.profiles).toHaveLength(1)
    expect(saved.profiles[0]?.kind).toBe('subscription')
    expect(saved.profiles[0]?.current).toBe(false)
    expect(saved.active_id).toBeNull()
    await added.get('[data-entry="settings"]').trigger('click')
    expect(added.findAll('[data-testid="profile-row"]')).toHaveLength(1)
    expect(added.find('[data-testid="profile-current"]').exists()).toBe(false)

    const entries = await mountApp()
    await entries.get('[data-entry="settings"]').trigger('click')
    await entries.get('[data-testid="open-add-profile"]').trigger('click')
    const subscription = entries.get('[data-testid="add-subscription"]')
    const local = entries.get('[data-testid="add-local"]')
    expect(subscription.text()).toContain('订阅链接')
    expect(local.text()).toContain('本地文件')
    expect(subscription.find('input[type="url"]').exists()).toBe(true)
    expect(local.find('input[type="file"]').exists()).toBe(true)
    expect(subscription.element.contains(local.element)).toBe(false)

    await subscription.get('input').setValue('https://manual.example/a')
    await subscription.trigger('submit')
    await flushPromises()
    expect(entries.findAll('[data-testid="profile-row"]')).toHaveLength(1)
    expect(entries.find('[data-testid="profile-current"]').exists()).toBe(false)

    const input = local.get('input')
    const file = new File(['mixed-port: 42\n'], '家里.yaml', { type: 'text/yaml' })
    Object.defineProperty(input.element, 'files', {
      configurable: true,
      value: {
        0: file,
        length: 1,
        item: (index: number) => (index === 0 ? file : null),
      },
    })
    await input.trigger('change')
    await flushPromises()
    expect(entries.findAll('[data-testid="profile-row"]')).toHaveLength(2)
    expect(entries.find('[data-testid="profile-current"]').exists()).toBe(false)
  })

  it('无法取回的订阅启用失败时接管关闭，失败原因留在该配置上', async () => {
    const profilePort = createMemoryProfilePort({
      system_proxy: true,
      tun: true,
      vpn: true,
      profiles: [
        profile({ id: 'p1', name: '原来的', source: 'mixed-port: 7890', current: true }),
      ],
    })
    await profilePort.addSubscription('https://down.example/missing')
    const wrapper = await mountApp(profilePort)
    expect(wrapper.get('[data-testid="home-takeover"]').attributes('data-system-proxy')).toBe('on')
    await wrapper.get('[data-entry="settings"]').trigger('click')
    await wrapper.get('[data-profile-id="p2"] [data-action="enable"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-profile-id="p2"] [data-testid="profile-failure"]').text()).toContain('订阅没有取回')
    expect(wrapper.get('[data-testid="takeover"]').attributes('data-system-proxy')).toBe('off')
    expect(wrapper.get('[data-testid="takeover"]').attributes('data-tun')).toBe('off')
    expect(wrapper.get('[data-testid="takeover"]').attributes('data-vpn')).toBe('off')
    expect(wrapper.get('[data-testid="takeover"]').text()).toContain('系统代理关闭')
    expect(wrapper.get('[data-testid="takeover"]').text()).toContain('TUN关闭')
    expect(wrapper.get('[data-testid="takeover"]').text()).toContain('VPN关闭')
    expect(wrapper.get('[data-profile-id="p1"]').attributes('data-current')).toBe('true')
    expect(wrapper.get('[data-profile-id="p2"]').attributes('data-current')).toBe('false')
    expect(wrapper.find('[data-testid="home-failure"]').exists()).toBe(false)
    await wrapper.get('[data-entry="home"]').trigger('click')
    expect(wrapper.get('[data-testid="home-failure"]').text()).toContain('订阅没有取回')
    expect(wrapper.get('[data-testid="home-takeover"]').attributes('data-vpn')).toBe('off')
  })

  it('切换前无法应用的覆写不替换生效配置，有效覆写会改变生效值', async () => {
    const profilePort = createMemoryProfilePort({
      mixed_port: 7890,
      system_proxy: true,
      tun: false,
      vpn: true,
      profiles: [
        profile({ id: 'p1', name: '甲', source: 'mixed-port: 7890', current: true }),
        profile({ id: 'p2', name: '乙', source: 'mixed-port: 7891' }),
      ],
    })
    const saved: string[] = []
    const saveOverride = profilePort.saveOverride.bind(profilePort)
    profilePort.saveOverride = async (id, text) => {
      saved.push(text)
      return saveOverride(id, text)
    }
    const wrapper = await mountApp(profilePort)
    await wrapper.get('[data-entry="settings"]').trigger('click')
    expect(wrapper.get('[data-testid="effective-value"]').text()).toContain('7890')
    expect(wrapper.get('[data-profile-id="p1"] [data-testid="profile-actions"]').text()).not.toContain('覆写')

    await wrapper.get('[data-profile-id="p2"] [data-action="advanced"]').trigger('click')
    await wrapper.get('[data-testid="override-editor"] textarea').setValue('mixed-port: 1\n未保存')
    await wrapper.get('[data-testid="override-close"]').trigger('click')
    expect(saved).toEqual([])
    expect(wrapper.find('[data-testid="override-editor"]').exists()).toBe(false)

    await wrapper.get('[data-profile-id="p2"] [data-action="advanced"]').trigger('click')
    expect((wrapper.get('[data-testid="override-editor"] textarea').element as HTMLTextAreaElement).value).toBe('')
    await wrapper.get('[data-testid="override-editor"] textarea').setValue(':::')
    await wrapper.get('[data-testid="override-save"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-profile-id="p2"] [data-action="enable"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-profile-id="p1"]').attributes('data-current')).toBe('true')
    expect(wrapper.get('[data-profile-id="p2"]').attributes('data-current')).toBe('false')
    expect(wrapper.get('[data-testid="effective-value"]').text()).toContain('7890')
    expect(wrapper.get('[data-testid="takeover"]').attributes('data-system-proxy')).toBe('on')
    expect(wrapper.get('[data-testid="takeover"]').attributes('data-tun')).toBe('off')
    expect(wrapper.get('[data-testid="takeover"]').attributes('data-vpn')).toBe('on')
    expect(wrapper.get('[data-testid="override-error"]').text()).toContain('覆写无法应用')

    await wrapper.get('[data-testid="override-editor"] textarea').setValue('mixed-port: 8001')
    await wrapper.get('[data-testid="override-save"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="effective-value"]').text()).toContain('7890')
    await wrapper.get('[data-profile-id="p2"] [data-action="enable"]').trigger('click')
    await flushPromises()
    expect(wrapper.findAll('[data-testid="profile-current"]')).toHaveLength(1)
    expect(wrapper.get('[data-profile-id="p2"]').attributes('data-current')).toBe('true')
    expect(wrapper.get('[data-testid="effective-value"]').text()).toContain('8001')
    expect(saved).toEqual([':::', 'mixed-port: 8001'])
  })
})
