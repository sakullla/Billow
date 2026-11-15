import { afterEach, describe, expect, it, vi } from 'vitest'
import { applyInsets, installInsets, syncSystemBars } from './insets'

const root = () => document.documentElement

afterEach(() => {
  delete window.BillowInsets
  delete window.__billowInsets
  root().removeAttribute('style')
  root().removeAttribute('data-keyboard')
})

describe('insets bridge', () => {
  it('writes native insets as CSS pixels and flags an open keyboard', () => {
    applyInsets({ top: 32.4, right: 0, bottom: 24, left: -3, ime: 280 })
    expect(root().style.getPropertyValue('--native-top')).toBe('32px')
    expect(root().style.getPropertyValue('--native-bottom')).toBe('24px')
    expect(root().style.getPropertyValue('--native-left')).toBe('0px')
    expect(root().style.getPropertyValue('--native-ime')).toBe('280px')
    expect(root().hasAttribute('data-keyboard')).toBe(true)

    applyInsets({ top: 32, bottom: 24, ime: 0 })
    expect(root().hasAttribute('data-keyboard')).toBe(false)
  })

  it('reads the current insets on install and follows native pushes', () => {
    window.BillowInsets = { get: () => JSON.stringify({ top: 40, right: 0, bottom: 16, left: 0, ime: 0 }) }
    const dispose = installInsets()
    expect(root().style.getPropertyValue('--native-top')).toBe('40px')

    window.__billowInsets?.({ top: 40, bottom: 0, ime: 300 })
    expect(root().style.getPropertyValue('--native-bottom')).toBe('0px')
    expect(root().hasAttribute('data-keyboard')).toBe(true)

    dispose()
    expect(window.__billowInsets).toBeUndefined()
  })

  it('ignores a broken bridge payload and works without a native shell', () => {
    window.BillowInsets = { get: () => 'not json' }
    expect(() => installInsets()).not.toThrow()
    delete window.BillowInsets
    expect(() => syncSystemBars(true)).not.toThrow()
  })

  it('asks for dark system bar icons on a light page', () => {
    const setLightBars = vi.fn()
    window.BillowInsets = { get: () => '{}', setLightBars }
    syncSystemBars(false)
    expect(setLightBars).toHaveBeenLastCalledWith(true)
    syncSystemBars(true)
    expect(setLightBars).toHaveBeenLastCalledWith(false)
  })
})
