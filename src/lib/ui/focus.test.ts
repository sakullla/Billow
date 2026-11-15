import { describe, expect, it } from 'vitest'
import { getFocusable, isEditableElement, topLevelElement } from './focus'

describe('focus utilities', () => {
  it('lists focusable descendants in DOM order and skips disabled or hidden controls', () => {
    const container = document.createElement('div')
    container.innerHTML = `
      <button id="one">one</button>
      <button id="disabled" disabled>disabled</button>
      <input id="hidden" type="hidden" />
      <div id="programmatic" tabindex="0">programmatic</div>
      <div id="skipped" tabindex="-1">skipped</div>
      <div id="hidden-attr" hidden><button id="inside-hidden">inside</button></div>
      <a id="link" href="#x">link</a>
    `
    expect(getFocusable(container).map((element) => element.id)).toEqual(['one', 'programmatic', 'link'])
  })

  it('recognises text fields but not ordinary buttons', () => {
    const input = document.createElement('input')
    const textarea = document.createElement('textarea')
    const editable = document.createElement('div')
    editable.setAttribute('contenteditable', 'true')
    const button = document.createElement('button')
    expect(isEditableElement(input)).toBe(true)
    expect(isEditableElement(textarea)).toBe(true)
    expect(isEditableElement(editable)).toBe(true)
    expect(isEditableElement(button)).toBe(false)
    expect(isEditableElement(null)).toBe(false)
  })

  it('walks to the direct child of body', () => {
    const root = document.createElement('div')
    const overlay = document.createElement('div')
    const dialog = document.createElement('section')
    overlay.appendChild(dialog)
    root.appendChild(overlay)
    document.body.appendChild(root)
    expect(topLevelElement(dialog)).toBe(root)
    root.remove()
  })
})
