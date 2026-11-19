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
}
