const platform = process.env.TAURI_ENV_PLATFORM
if (platform === 'android' || platform === 'androideabi') {
  await import('./prepare_android_kernel.mjs')
} else if (platform || process.argv.includes('--desktop')) {
  const { prepareDesktop } = await import('./prepare_desktop_runtime.mjs')
  await prepareDesktop({
    platform: platform || process.platform,
    arch: process.env.TAURI_ENV_ARCH || (platform ? undefined : process.arch),
  })
}
