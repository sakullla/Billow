import { mount } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import App from './App.vue'
import {
  ABOUT_TEXT,
  HOME_HINT,
  HOME_STATUS,
  KERNEL_OPTIONS,
  KERNEL_TITLE,
  LICENSE_NAME,
  NAV_ITEMS,
  NODES_EMPTY,
  PRODUCT_NAME,
  SETTINGS_TITLE,
  THEME_OPTIONS,
  WINDOW_TITLE,
} from './copy'
import { createMemoryPort } from './port'

const FORBIDDEN = ['轻澜', 'Zephyr', 'FlClash', 'Sparkle', 'Clash Verge', '观澜', 'mihomo']

const visible = [
  ...NAV_ITEMS.map((item) => item.label),
  ...THEME_OPTIONS.map((option) => option.label),
  ...KERNEL_OPTIONS.map((option) => option.label),
  KERNEL_TITLE,
  HOME_STATUS,
  HOME_HINT,
  NODES_EMPTY,
  SETTINGS_TITLE,
  ABOUT_TEXT,
]

describe('简体中文主文案', () => {
  it('主文案是简体中文，产品名只有 Billow，关于信息包含 GPL-3', async () => {
    expect(PRODUCT_NAME).toBe('Billow')
    expect(WINDOW_TITLE).toBe('Billow')
    expect(LICENSE_NAME).toBe('GPL-3')
    expect(ABOUT_TEXT).toContain('Billow')
    expect(ABOUT_TEXT).toContain('GPL-3')
    expect(NAV_ITEMS.map((item) => item.label)).toEqual(['首页', '节点', '配置'])
    expect(HOME_STATUS).toBe('未连接')

    for (const text of visible) {
      const latin = text.replaceAll(PRODUCT_NAME, '').replaceAll(LICENSE_NAME, '')
      expect(latin).not.toMatch(/[A-Za-z]/)
      expect(text).toMatch(/[\u4e00-\u9fff]/)
    }

    const wrapper = mount(App, { props: { initialWidth: 900, port: createMemoryPort() } })
    await (wrapper.vm as unknown as { ready: Promise<void> }).ready
    expect(wrapper.text()).toContain('首页')
    expect(wrapper.text()).toContain('节点')
    expect(wrapper.text()).toContain('配置')
    expect(wrapper.text()).toContain('未连接')
    expect(wrapper.text()).toContain('Billow')
    await wrapper.get('[data-entry="settings"]').trigger('click')
    const about = wrapper.get('[data-testid="about"]').text()
    expect(about).toContain('Billow')
    expect(about).toContain('GPL-3')
    expect(wrapper.text()).toContain('跟随系统')
    expect(wrapper.text()).toContain('始终浅色')
    expect(wrapper.text()).toContain('始终深色')
    expect(wrapper.text()).toContain('内核渠道')
    expect(wrapper.text()).toContain('稳定版')
    expect(wrapper.text()).toContain('预览版')
    expect(wrapper.find('[data-testid="kernel-channel"] input[type="text"]').exists()).toBe(false)
  })

  it('窗口标题和构建入口使用 Billow，且不使用其他客户端名称', () => {
    const files = [
      'index.html',
      'package.json',
      'src/copy.ts',
      'src/App.vue',
      'src/styles.css',
      'src/views/HomeView.vue',
      'src/views/NodesView.vue',
      'src/views/SettingsView.vue',
      'src-tauri/tauri.conf.json',
      'src-tauri/Cargo.toml',
    ]
    const html = readFileSync('index.html', 'utf8')
    const config = readFileSync('src-tauri/tauri.conf.json', 'utf8')
    const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as {
      scripts: Record<string, string>
    }
    expect(html).toContain('<title>Billow</title>')
    expect(html).toContain('lang="zh-CN"')
    expect(config).toContain('"productName": "Billow"')
    expect(config).toContain('"title": "Billow"')
    expect(config).toContain('GPL-3')
    expect(pkg.scripts['build:macos']).toContain('tauri build')
    expect(pkg.scripts['build:windows']).toContain('--target x86_64-pc-windows-msvc')
    expect(pkg.scripts['build:linux']).toContain('--target x86_64-unknown-linux-gnu')
    expect(pkg.scripts['build:android']).toContain('tauri android build')
    expect(pkg.scripts.test).toContain('vitest run')

    const joined = files.map((file) => readFileSync(file, 'utf8')).join('\n')
    for (const name of FORBIDDEN) {
      expect(joined.toLowerCase()).not.toContain(name.toLowerCase())
    }
  })
})
