/**
 * Simplified Chinese is the base dictionary (R42): every message starts here and
 * English entries are optional, so a missing translation falls back to Chinese.
 */
export const ZH_CN = {
  'settings.language.title': '界面语言',
  'settings.language.detail': '切换后立即生效；跟随系统时，中文系统用简体中文，其他语言用英文',
  'language.system': '跟随系统',

  // 备份与恢复 (R38)
  'settings.backup.title': '备份与恢复',
  'settings.backup.group': '备份',
  'settings.backup.detail': '导出一份备份文件，或从文件与 WebDAV 恢复；备份含敏感信息，请妥善保管',
  'backup.local.title': '本地文件',
  'backup.local.detail': '把当前全部配置、覆写、age 私钥与设置写成一份 JSON 备份',
  'backup.export': '导出备份',
  'backup.exporting': '正在导出…',
  'backup.import': '导入备份…',
  'backup.importing': '正在恢复…',
  'backup.exported': '已导出到 {path}',
  'backup.readError': '读不到这个文件：{reason}',
  'backup.warning': '备份文件包含订阅链接和 age 私钥等敏感信息，请妥善保管，不要公开分享。',
  'backup.webdav.title': 'WebDAV',
  'backup.webdav.detail': '上传与恢复都由你手动触发，Billow 不会在后台改动云端文件',
  'backup.webdav.url': '服务器地址',
  'backup.webdav.urlPlaceholder': 'https://dav.example.com/remote.php/dav/files/me',
  'backup.webdav.username': '用户名',
  'backup.webdav.password': '密码',
  'backup.webdav.test': '测试连接',
  'backup.webdav.testing': '正在测试…',
  'backup.webdav.available': '连接可用，可以上传或从云端恢复',
  'backup.webdav.unavailable': '尚未测试连接',
  'backup.webdav.upload': '上传备份',
  'backup.webdav.uploading': '正在上传…',
  'backup.webdav.uploaded': '已上传 {name}',
  'backup.webdav.refresh': '刷新列表',
  'backup.webdav.loading': '正在读取云端备份…',
  'backup.webdav.empty': '云端还没有备份',
  'backup.webdav.needTest': '先测试连接，成功后即可上传与恢复',
  'backup.webdav.modified': '修改时间',
  'backup.webdav.device': '来源设备',
  'backup.webdav.size': '大小',
  'backup.webdav.restore': '恢复',
  'backup.confirm.title': '恢复备份',
  'backup.confirm.body': '恢复会覆盖当前全部配置与设置，并按恢复后的配置重新启用。',
  'backup.confirm.file': '文件：{name}',
  'backup.confirm.sensitive': '备份中含有订阅链接和 age 私钥等敏感信息，请确认来源可靠。',
  'backup.confirm.cancel': '取消',
  'backup.confirm.restore': '覆盖并恢复',
  'backup.restored': '已恢复备份',
} as const

export type MessageKey = keyof typeof ZH_CN
