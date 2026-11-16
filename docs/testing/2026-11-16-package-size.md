# 内核与附属资源体积优化

## 同机实测

macOS arm64，版本 0.1.14，前后均使用 release 构建及同一份 Mihomo/GEO 内容。两次通过 `tauri bundle --bundles app,dmg --ci` 生成本地包，关闭更新器签名产物生成以免依赖发布密钥，保留应用 ad-hoc 签名。

| 对象 | 优化前 | 优化后 | 降幅 |
| --- | ---: | ---: | ---: |
| 主程序 | 20,610,848 B | 13,066,000 B | 36.61% |
| .app 文件合计 | 80,448,752 B（76.72 MiB） | 38,432,988 B（36.65 MiB） | 52.23% |
| DMG | 43,529,015 B（41.51 MiB） | 31,725,125 B（30.26 MiB） | 27.12% |
| 内核随包资源 | 20,649,699 B | 14,764,488 B | 28.50% |
| 四份 GEO 随包资源 | 38,302,222 B | 9,671,188 B | 74.75% |

这些是同机实际生成的包，不是预计值。Windows、Linux、Android 的最终包体积尚未在对应平台测量。

## 改动

- 已验证的上游内核归档先提取唯一可执行文件，再以 Brotli 压缩入包。解压后的字节、内核功能和已有签名不变；清理旧的 kernel.gz/kernel.zip，防止重复打包。
- 四份 GEO 全部保留并压缩，桌面与 Android 共用。APK 中 .br 不再重复压缩。Android 原生内核仍走 jniLibs 原有安装路径，保持可执行权限机制。
- 原始文件与压缩文件分别记录长度和 SHA-256；运行时流式解压到临时文件，全部校验后再替换目标。解码失败清理临时文件并保留旧数据。旧格式归档和资源仍可读取；用户已更新的有效 GEO 不会被覆盖。
- 发布构建使用 `opt-level = "s"`、thin LTO、单 codegen unit 和符号剥离；保留现有 panic 行为。
- Linux 本地打包命令及发布任务设置 XZ AppImage 压缩，覆盖随包 WebKit/GTK。此设置来自 [linuxdeploy 官方参数处理](https://github.com/linuxdeploy/linuxdeploy-plugin-appimage/blob/master/src/main.cpp)，尚待 Linux 安装包运行验证。
- 压缩结果按原始内容哈希缓存，每次复用前解压比对；缓存或输出损坏会重建。首次高压缩率构建较慢，同内容再次构建不再重新压缩。

## 验证

- Rust 全量：148 项通过、6 项环境测试跳过（另增加的一项 provider URL 转换检查也单独通过）。
- Node 打包/发布测试：22 项通过。
- 前端生产构建、`git diff --check` 通过。
- 实际压缩包在断开 GEO 下载源的条件下完成首次安装、GEO 加载、内核启动和热重载。使用优化版 .app 中的资源执行 release 冒烟测试，整个测试耗时 1.38 秒。
- `codesign --verify --deep --strict` 验证本地优化版 .app 通过。
- Windows 相关 Rust 模块的独立交叉类型检查通过；完整 Windows 构建及 Android APK 安装尚未在本机执行。
- APK 结构的单元测试覆盖压缩资源读取、完整性校验和保留用户更新。
