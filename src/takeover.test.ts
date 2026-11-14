import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import App from './App.vue'
import { PROXY_HINT, TUN_HINT } from './copy'
import { createMemoryProfilePort, type ProfilePort } from './profile-port'
import { createMemoryPort } from './port'

async function mountApp(profilePort: ProfilePort) {
  const wrapper = mount(App, {
    props: { initialWidth: 900, port: createMemoryPort(), profilePort },
  })
  await (wrapper.vm as unknown as { ready: Promise<void> }).ready
  await flushPromises()
  return wrapper
}

describe('接管界面', () => {
  it('桌面首页说明系统代理和 TUN，并且没有按应用排除', async () => {
    const wrapper = await mountApp(createMemoryProfilePort())
    expect(wrapper.get('[data-testid="link-status"]').text()).toBe('未连接')
    expect(wrapper.get('[data-testid="system-proxy-hint"]').text()).toBe(PROXY_HINT)
    expect(wrapper.get('[data-testid="tun-hint"]').text()).toBe(TUN_HINT)
    expect(PROXY_HINT).toBe('浏览器和遵守系统设置的应用')
    expect(TUN_HINT).toBe('不遵守系统代理的应用也走代理，并需要系统授权')
    expect(wrapper.find('[data-testid="open-exclusions"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="exclude-panel"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="desktop-controls"]').text()).toContain('系统代理')
    expect(wrapper.get('[data-testid="desktop-controls"]').text()).toContain('TUN')
  })

  it('Android 首页只有 VPN 和按应用排除', async () => {
    const wrapper = await mountApp(
      createMemoryProfilePort({
        platform: 'android',
        excluded: ['com.example.mail'],
      }),
    )
    expect(wrapper.find('[data-testid="desktop-controls"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="system-proxy-hint"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="tun-hint"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="home-takeover"]').text()).not.toContain('系统代理')
    expect(wrapper.get('[data-testid="home-takeover"]').text()).not.toContain('TUN')
    expect(wrapper.get('[data-testid="android-controls"]').text()).toContain('VPN')
    await wrapper.get('[data-testid="open-exclusions"]').trigger('click')
    const row = wrapper.get('[data-package="com.example.mail"]')
    expect(row.attributes('data-excluded')).toBe('true')
    expect(row.text()).toContain('已排除')
    await wrapper.get('[data-testid="exclude-search"]').setValue('com.example.browser')
    expect(wrapper.find('[data-package="com.example.mail"]').exists()).toBe(false)
    const candidate = wrapper.get('[data-package="com.example.browser"]')
    expect(candidate.attributes('data-excluded')).toBe('false')
    expect(candidate.text()).toContain('未排除')
    expect((await wrapper.find('[data-testid="exclude-search"]')).exists()).toBe(true)
  })

  it('失败时不显示已连接', async () => {
    const wrapper = await mountApp(
      createMemoryProfilePort({
        system_proxy: true,
        connected: false,
        failure: '系统授权被拒绝',
      }),
    )
    expect(wrapper.get('[data-testid="link-status"]').text()).toBe('未连接')
    expect(wrapper.get('[data-testid="home-failure"]').text()).toContain('系统授权被拒绝')
    expect(wrapper.get('[data-testid="link-status"]').attributes('data-connected')).toBe('false')
  })
})
