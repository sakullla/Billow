const targets = [
  { os: 'windows-latest', platform: 'windows', target: 'x86_64-pc-windows-msvc', mobile: '', args: '--target x86_64-pc-windows-msvc --bundles nsis -- --locked' },
  { os: 'macos-15', platform: 'macos', target: 'aarch64-apple-darwin', mobile: '', args: '--target aarch64-apple-darwin --bundles app,dmg -- --locked' },
  { os: 'ubuntu-22.04', platform: 'linux', target: 'x86_64-unknown-linux-gnu', mobile: '', args: '--target x86_64-unknown-linux-gnu --bundles deb,appimage -- --locked' },
  { os: 'ubuntu-22.04', platform: 'android', target: 'aarch64-linux-android', mobile: 'android', args: '--target aarch64 --apk --split-per-abi' },
]

function releaseRequest({ eventName, ref, inputs = {}, version }) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('Only stable SemVer releases are supported')
  const tag = `v${version}`
  if (eventName === 'push') {
    if (ref !== `refs/tags/${tag}`) throw new Error('Release requires the matching version tag')
  } else if (eventName === 'workflow_dispatch') {
    if (inputs.tag !== tag) throw new Error('Recovery requires the matching existing version tag')
  } else throw new Error('Unsupported release event')
  const names = eventName === 'workflow_dispatch' && inputs.platforms && inputs.platforms !== 'all'
    ? [...new Set(inputs.platforms.split(',').map(value => value.trim()))]
    : targets.map(target => target.platform)
  if (!names.length || names.some(name => !targets.some(target => target.platform === name))) throw new Error('Unknown release platform')
  const compression = inputs.appimage_compression || 'gzip'
  if (!['gzip', 'xz'].includes(compression)) throw new Error('Unknown AppImage compression')
  const macosRunner = inputs.macos_runner || 'macos-15'
  if (!['macos-15', 'macos-latest'].includes(macosRunner)) throw new Error('Unsupported macOS runner')
  const matrix = targets.filter(target => names.includes(target.platform)).map(target => ({
    ...target,
    os: target.platform === 'macos' ? macosRunner : target.os,
    appimageCompression: compression,
  }))
  return { tag, matrix }
}

module.exports = { releaseRequest }
