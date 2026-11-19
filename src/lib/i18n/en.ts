import type { MessageKey } from './zh-CN'

/**
 * English text per key. It is deliberately partial: any key left out renders its
 * Chinese base text instead of a key name or a blank line (R42).
 */
export const EN: Partial<Record<MessageKey, string>> = {
  'settings.language.title': 'Language',
  'settings.language.detail':
    'Applied immediately; Follow system uses Simplified Chinese on Chinese systems and English otherwise',
  'language.system': 'Follow system',

  // Backup and restore (R38)
  'settings.backup.title': 'Backup and restore',
  'settings.backup.group': 'Backup',
  'settings.backup.detail':
    'Export one backup file, or restore from a file or WebDAV; backups hold sensitive data, so keep them safe',
  'backup.local.title': 'Local file',
  'backup.local.detail':
    'Write every profile, override, age key and setting into one JSON backup',
  'backup.export': 'Export backup',
  'backup.exporting': 'Exporting…',
  'backup.import': 'Import backup…',
  'backup.importing': 'Restoring…',
  'backup.exported': 'Exported to {path}',
  'backup.readError': 'This file could not be read: {reason}',
  'backup.warning':
    'A backup contains sensitive data such as subscription links and age keys. Keep it safe and do not share it.',
  'backup.webdav.title': 'WebDAV',
  'backup.webdav.detail':
    'Uploading and restoring only happen when you press a button; Billow never changes the cloud files in the background',
  'backup.webdav.url': 'Server address',
  'backup.webdav.urlPlaceholder': 'https://dav.example.com/remote.php/dav/files/me',
  'backup.webdav.username': 'Username',
  'backup.webdav.password': 'Password',
  'backup.webdav.test': 'Test connection',
  'backup.webdav.testing': 'Testing…',
  'backup.webdav.available': 'Connected; you can upload or restore from the cloud',
  'backup.webdav.unavailable': 'Connection not tested yet',
  'backup.webdav.upload': 'Upload backup',
  'backup.webdav.uploading': 'Uploading…',
  'backup.webdav.uploaded': 'Uploaded {name}',
  'backup.webdav.refresh': 'Refresh list',
  'backup.webdav.loading': 'Reading cloud backups…',
  'backup.webdav.empty': 'No backups in the cloud yet',
  'backup.webdav.needTest': 'Test the connection first; uploading and restoring unlock after it succeeds',
  'backup.webdav.modified': 'Modified',
  'backup.webdav.device': 'From',
  'backup.webdav.size': 'Size',
  'backup.webdav.restore': 'Restore',
  'backup.confirm.title': 'Restore backup',
  'backup.confirm.body':
    'Restoring replaces every current profile and setting and reconnects with the restored profile.',
  'backup.confirm.file': 'File: {name}',
  'backup.confirm.sensitive':
    'The backup contains sensitive data such as subscription links and age keys. Make sure it came from a source you trust.',
  'backup.confirm.cancel': 'Cancel',
  'backup.confirm.restore': 'Replace and restore',
  'backup.restored': 'Backup restored',

  // Global shortcuts (R39)
  'settings.hotkey.title': 'Global shortcuts',
  'settings.hotkey.detail':
    'Works while the window is in the background or hidden; nothing is bound by default',
  'hotkey.connect': 'Connect / disconnect',
  'hotkey.proxy': 'Toggle system proxy',
  'hotkey.tun': 'Toggle TUN',
  'hotkey.modeRule': 'Switch to rule mode',
  'hotkey.modeGlobal': 'Switch to global mode',
  'hotkey.modeDirect': 'Switch to direct mode',
  'hotkey.window': 'Show / hide window',
  'hotkey.record': 'Record',
  'hotkey.recording': 'Press the combination…',
  'hotkey.clear': 'Clear',
  'hotkey.empty': 'Not bound',
  'hotkey.hint': 'Click Record, then press a combination with at least one modifier (Ctrl / Alt / Shift)',
  'hotkey.modifierOnly': 'Only modifiers were pressed; add a letter or function key',
  'hotkey.plainKey': 'Hold Ctrl / Alt / Shift first, then press the key to bind',
  'hotkey.unavailable': 'Global shortcuts are unavailable: {reason}',
  'hotkey.conflict.window': '{combo} conflicts with the in-window shortcut “{action}”; nothing was saved',
  'hotkey.inWindow.save': 'Save settings',
  'hotkey.inactive': 'Not active: {reason}',

  // Lightweight mode (R44)
  'settings.behavior.releaseUi': 'Release the window on close',
  'settings.behavior.releaseUiDetail':
    'Destroys the interface after the window closes to free its memory; the tray, global shortcuts and background tasks keep running, and reopening returns to the last page',

  // Exit IP (R40; streaming unlock checks are out of scope, R47)
  'settings.exitIp.auto': 'Query the exit IP automatically',
  'settings.exitIp.detail':
    'Off by default; when on, queries after connecting and after a node, mode or profile switch. Uses ip.sb through the current proxy, then ipinfo.io if it fails',
  'exitIp.title': 'Exit IP',
  'exitIp.query': 'Query exit IP',
  'exitIp.querying': 'Querying…',
  'exitIp.refresh': 'Refresh',
  'exitIp.changed': 'May have changed',
  'exitIp.offline': 'Not connected yet; connect before querying the exit IP',
  'exitIp.region': 'Region: {region}',
  'exitIp.isp': 'ISP: {isp}',
  'exitIp.meta': '{service} · queried at {time}',
  'exitIp.badResponse': 'The exit IP service returned an unexpected response',

  // Traffic history (R43)
  'settings.traffic.title': 'Traffic history',
  'settings.traffic.detail':
    'Off by default; when on, the backend totals uploads and downloads per day, profile, proxy group and node and keeps {days} days. Turning it off stops recording and keeps the existing rows',
  'settings.traffic.record': 'Record traffic history',
  'settings.traffic.open': 'View stats',
  'settings.traffic.retention': 'Only the last {days} days are kept',
  'traffic.title': 'Traffic stats',
  'traffic.subtitle':
    'Uploads and downloads per day; rows stay readable and can be cleared after recording is turned off',
  'traffic.off': 'Traffic recording is off',
  'traffic.offDetail': 'Recording starts when you turn it on; traffic from before is not counted',
  'traffic.enable': 'Turn on recording',
  'traffic.range.today': 'Today',
  'traffic.range.7d': 'Last 7 days',
  'traffic.range.30d': 'Last 30 days',
  'traffic.range.custom': 'Custom',
  'traffic.from': 'Start date',
  'traffic.to': 'End date',
  'traffic.group.profile': 'By profile',
  'traffic.group.group': 'By proxy group',
  'traffic.group.node': 'By node',
  'traffic.upload': 'Upload',
  'traffic.download': 'Download',
  'traffic.total': 'Total',
  'traffic.daily': 'Daily traffic',
  'traffic.empty': 'Nothing recorded in this period',
  'traffic.direct': 'Direct',
  'traffic.unknown': 'Unknown',
  'traffic.loading': 'Reading…',
  'traffic.loadError': 'Traffic stats could not be read: {reason}',
  'traffic.clear': 'Clear all stats',
  'traffic.clearConfirm': 'This cannot be undone. Clear every traffic record?',
  'traffic.clearCancel': 'Cancel',
  'traffic.clearConfirmAction': 'Clear',
  'traffic.cleared': 'Traffic stats cleared',
  'traffic.recordStarted': 'Traffic history recording started',
  'traffic.recordStopped': 'Recording stopped; existing rows are kept',
}
