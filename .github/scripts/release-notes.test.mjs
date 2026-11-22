import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import cp from 'node:child_process'
import {
  INSTALLER_NOTES,
  buildReleaseNotes,
  findPreviousTag,
  formatCommitsAsReleaseNotes,
} from './release-notes.mjs'
import { createManifest } from './release-manifest.mjs'

function runGit(cwd, args) {
  return cp.execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Billow Test',
      GIT_AUTHOR_EMAIL: 'test@example.com',
      GIT_COMMITTER_NAME: 'Billow Test',
      GIT_COMMITTER_EMAIL: 'test@example.com',
    },
  }).trim()
}

function withTempRepo(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'billow-release-notes-'))
  try {
    runGit(dir, ['init', '-b', 'main'])
    return fn(dir)
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
}

function commitFile(dir, relPath, content, message) {
  const fullPath = path.join(dir, relPath)
  fs.mkdirSync(path.dirname(fullPath), { recursive: true })
  fs.writeFileSync(fullPath, content, 'utf8')
  runGit(dir, ['add', relPath])
  runGit(dir, ['commit', '-m', message])
}

test('prefers non-empty docs/releases/v<version>.md and flows into latest.json notes', () => {
  withTempRepo((dir) => {
    commitFile(dir, 'README.md', 'v1\n', 'feat: 初始版本')
    runGit(dir, ['tag', 'v0.1.42'])

    commitFile(
      dir,
      'docs/releases/v0.1.43.md',
      '### 新功能\n- 新增自建节点导入与可视化链式代理\n\n### 问题修复\n- 修复部分场景下配置重载失败问题\n',
      'feat: 支持自建节点与链式代理',
    )
    runGit(dir, ['tag', 'v0.1.43'])

    const notes = buildReleaseNotes({
      repoDir: dir,
      repo: 'sakullla/Billow',
      tag: 'v0.1.43',
      sha: 'HEAD',
    })

    assert.ok(notes.startsWith('### 新功能\n- 新增自建节点导入与可视化链式代理'))
    assert.ok(notes.includes('### 问题修复\n- 修复部分场景下配置重载失败问题'))
    assert.ok(notes.includes(INSTALLER_NOTES))
    assert.ok(notes.includes('https://github.com/sakullla/Billow/compare/v0.1.42...v0.1.43'))

    const names = [
      'Billow_0.1.43_x64-setup.exe',
      'Billow_0.1.43_aarch64.dmg',
      'Billow_0.1.43_aarch64.app.tar.gz',
      'Billow_0.1.43_amd64.AppImage',
      'Billow_0.1.43_amd64.deb',
      'Billow_0.1.43_arm64.apk',
    ]
    const signed = names.filter((name) => !/\.(dmg|apk)$/.test(name))
    const assets = [...names, ...signed.map((name) => `${name}.sig`)].map((name) => ({
      name,
      size: 100,
      browser_download_url: `https://github.com/sakullla/Billow/releases/download/v0.1.43/${name}`,
    }))
    const signatures = Object.fromEntries(signed.map((name) => [`${name}.sig`, 'c2lnbmF0dXJl']))
    const manifest = createManifest(
      { draft: true, tag_name: 'v0.1.43', assets, body: notes },
      signatures,
      'sakullla/Billow',
      '0.1.43',
    )
    assert.equal(manifest.notes, notes)
  })
})

test('falls back to grouped Chinese commit notes when authored file is missing', () => {
  withTempRepo((dir) => {
    commitFile(dir, 'a.txt', '1\n', 'feat: 旧版本功能不应出现在本次说明')
    runGit(dir, ['tag', 'v0.1.42'])

    commitFile(dir, 'b.txt', '2\n', 'feat: 支持 anytls 节点链接解析')
    commitFile(dir, 'c.txt', '3\n', 'fix(proxy): 修复链式节点测速异常')
    commitFile(dir, 'd.txt', '4\n', 'docs: 更新发版说明文档')
    runGit(dir, ['tag', 'v0.1.43'])

    assert.equal(findPreviousTag(dir, 'v0.1.43', 'HEAD'), 'v0.1.42')

    const notes = buildReleaseNotes({
      repoDir: dir,
      repo: 'sakullla/Billow',
      tag: 'v0.1.43',
      sha: 'HEAD',
    })

    assert.ok(!notes.includes('旧版本功能不应出现在本次说明'))
    assert.ok(notes.includes('### 新功能\n- 支持 anytls 节点链接解析'))
    assert.ok(notes.includes('### 问题修复\n- proxy: 修复链式节点测速异常'))
    assert.ok(notes.includes('### 其他改动\n- docs: 更新发版说明文档'))
    assert.ok(notes.includes(INSTALLER_NOTES))
    assert.ok(notes.includes('https://github.com/sakullla/Billow/compare/v0.1.42...v0.1.43'))
  })
})

test('falls back to git commits when authored release file is empty or whitespace', () => {
  withTempRepo((dir) => {
    commitFile(dir, 'a.txt', '1\n', 'feat: 初始提交')
    runGit(dir, ['tag', 'v0.1.42'])

    commitFile(dir, 'docs/releases/v0.1.43.md', '   \n\t\n', 'fix: 修复订阅切换状态不同步')
    runGit(dir, ['tag', 'v0.1.43'])

    const notes = buildReleaseNotes({
      repoDir: dir,
      repo: 'sakullla/Billow',
      tag: 'v0.1.43',
      sha: 'HEAD',
    })

    assert.ok(notes.includes('### 问题修复\n- 修复订阅切换状态不同步'))
    assert.ok(!notes.includes('### 新功能'))
  })
})

test('handles first tag with no previous tag cleanly without compare link', () => {
  withTempRepo((dir) => {
    commitFile(dir, 'a.txt', '1\n', 'feat: 首次发布核心功能')
    commitFile(dir, 'b.txt', '2\n', 'fix: 修复启动闪烁问题')
    runGit(dir, ['tag', 'v0.1.0'])

    assert.equal(findPreviousTag(dir, 'v0.1.0', 'HEAD'), null)

    const notes = buildReleaseNotes({
      repoDir: dir,
      repo: 'sakullla/Billow',
      tag: 'v0.1.0',
      sha: 'HEAD',
    })

    assert.ok(notes.includes('### 新功能\n- 首次发布核心功能'))
    assert.ok(notes.includes('### 问题修复\n- 修复启动闪烁问题'))
    assert.ok(notes.includes(INSTALLER_NOTES))
    assert.ok(!notes.includes('/compare/'))
  })
})

test('formatCommitsAsReleaseNotes deduplicates and handles empty commit lists', () => {
  assert.equal(formatCommitsAsReleaseNotes([]), '本次发布包含维护更新与构建调整。')

  const formatted = formatCommitsAsReleaseNotes([
    'feat!: 支持纯自建零配置模式',
    'feat: 支持纯自建零配置模式',
    'fix(android): 修复通知栏断开按钮无响应',
    'chore: 升级依赖',
    '   ',
  ])
  assert.equal(
    formatted,
    [
      '### 新功能\n- 支持纯自建零配置模式',
      '### 问题修复\n- android: 修复通知栏断开按钮无响应',
      '### 其他改动\n- chore: 升级依赖',
    ].join('\n\n'),
  )
})
