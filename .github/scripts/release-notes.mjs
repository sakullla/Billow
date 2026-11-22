import fs from 'node:fs'
import path from 'node:path'
import cp from 'node:child_process'

export const INSTALLER_NOTES = [
  'Windows x64: NSIS · macOS Apple Silicon: DMG · Linux x64: deb/AppImage · Android ARM64: APK。',
  '',
  'macOS 使用 ad-hoc 签名，未经过 Apple 公证。',
].join('\n')

function normalizeTag(tag) {
  const value = String(tag ?? '').trim()
  if (!value) throw new Error('Release tag is required')
  return value.startsWith('v') ? value : `v${value}`
}

function runGit(repoDir, args) {
  return cp.execFileSync('git', ['-C', repoDir, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
}

export function findPreviousTag(repoDir, tag, sha = 'HEAD') {
  const currentTag = normalizeTag(tag)
  let output = ''
  try {
    output = runGit(repoDir, ['tag', '--merged', sha, '--list', 'v*', '--sort=-v:refname'])
  } catch {
    return null
  }
  const tags = output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^v\d+\.\d+\.\d+$/.test(line) && line !== currentTag)
  return tags[0] ?? null
}

export function formatCommitsAsReleaseNotes(subjects) {
  const groups = {
    feat: [],
    fix: [],
    other: [],
  }
  const seen = new Set()

  for (const rawSubject of subjects) {
    const subject = String(rawSubject ?? '').trim()
    if (!subject) continue
    const match = /^(feat|fix)(?:\(([^)]+)\))?(!)?:\s*(.+)$/i.exec(subject)
    if (match) {
      const kind = match[1].toLowerCase()
      const scope = match[2]?.trim()
      const desc = match[4].trim()
      if (!desc) continue
      const entry = scope ? `${scope}: ${desc}` : desc
      const key = `${kind}:${entry}`
      if (!seen.has(key)) {
        seen.add(key)
        groups[kind].push(entry)
      }
    } else {
      const key = `other:${subject}`
      if (!seen.has(key)) {
        seen.add(key)
        groups.other.push(subject)
      }
    }
  }

  const sections = []
  if (groups.feat.length > 0) {
    sections.push(['### 新功能', ...groups.feat.map((item) => `- ${item}`)].join('\n'))
  }
  if (groups.fix.length > 0) {
    sections.push(['### 问题修复', ...groups.fix.map((item) => `- ${item}`)].join('\n'))
  }
  if (groups.other.length > 0) {
    sections.push(['### 其他改动', ...groups.other.map((item) => `- ${item}`)].join('\n'))
  }

  if (sections.length === 0) {
    return '本次发布包含维护更新与构建调整。'
  }
  return sections.join('\n\n')
}

function readAuthoredNotes(repoDir, tag) {
  const filePath = path.join(repoDir, 'docs', 'releases', `${tag}.md`)
  if (!fs.existsSync(filePath)) return ''
  return fs.readFileSync(filePath, 'utf8').trim()
}

function readCommitSubjects(repoDir, previousTag, sha) {
  const range = previousTag ? `${previousTag}..${sha}` : sha
  let output = ''
  try {
    output = runGit(repoDir, ['log', '--no-merges', '--pretty=format:%s', range])
  } catch {
    return []
  }
  if (!output) return []
  return output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
}

export function buildReleaseNotes({ repoDir = process.cwd(), repo = '', tag, sha = 'HEAD', previousTag } = {}) {
  const currentTag = normalizeTag(tag)
  const resolvedPreviousTag = previousTag === undefined
    ? findPreviousTag(repoDir, currentTag, sha)
    : (previousTag ? normalizeTag(previousTag) : null)

  const authored = readAuthoredNotes(repoDir, currentTag)
  const mainBody = authored || formatCommitsAsReleaseNotes(readCommitSubjects(repoDir, resolvedPreviousTag, sha))

  const parts = [mainBody]
  if (!mainBody.includes('Windows x64: NSIS')) {
    parts.push(INSTALLER_NOTES)
  }
  if (repo && resolvedPreviousTag) {
    const compareUrl = `https://github.com/${repo}/compare/${resolvedPreviousTag}...${currentTag}`
    if (!mainBody.includes(compareUrl)) {
      parts.push(`**完整变更**: ${compareUrl}`)
    }
  }

  return parts.join('\n\n')
}
