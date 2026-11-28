import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

function vueFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return vueFiles(path)
    return path.endsWith('.vue') ? [path] : []
  })
}

describe('scoped styles', () => {
  it('never follow a bare :global() with more selector text', () => {
    // Vue compiles `:global(.a) .b` to just `.a`, silently styling every `.a`
    // (this once gave the whole compact shell a pill radius). Wrap the full
    // selector instead: `:global(.a .b)`.
    const offenders = vueFiles(join(__dirname))
      .flatMap((file) =>
        readFileSync(file, 'utf8')
          .split('\n')
          .map((line, index) => ({ file, line: index + 1, text: line }))
          .filter(({ text }) => /:global\([^)]*\)\s*[^\s,{]/.test(text)),
      )
      .map(({ file, line, text }) => `${file}:${line} ${text.trim()}`)
    expect(offenders).toEqual([])
  })
})
