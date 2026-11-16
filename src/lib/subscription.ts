/** Subscription override → global override → the installed core's actual version. */
export function subscriptionUserAgent(version: string | null, global = '', profile = ''): string {
  return profile.trim() || global.trim() || (version?.trim() ? `clash.meta/${version.trim()}` : 'clash.meta')
}
