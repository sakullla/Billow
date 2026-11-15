# Billow 发布与更新

`CI` 在 main 提交与 PR 上运行前端测试、生产构建、发布清单测试和 Rust 测试。
`Release` 先运行这些检查，再并行构建 Windows x64 NSIS、macOS Apple Silicon DMG、
Linux x64 deb/AppImage 和 Android ARM64 APK。全部成功后，由一个任务生成 `latest.json`，
检查安装包与签名齐全，最后发布。任一平台失败时保留草稿，不影响已有稳定版。

## 发布新版本

1. 同步修改 `package.json`、`package-lock.json`、`src-tauri/Cargo.toml`、
   `src-tauri/Cargo.lock` 和 `src-tauri/tauri.conf.json` 的应用版本。
2. 提交并推送代码，然后推送相同版本的 tag，如 `v0.2.0`。
3. 在 Actions 查看 Release；成功后安装包与更新清单出现在 GitHub Releases。

也可手动运行 Release，默认 `publish=false`，用于验证构建并保留草稿。
同一提交的失败任务可以重跑；已有正式版本或不同提交的同版本草稿会被拒绝覆盖。
修订已构建版本时请使用新版本号，或删除尚未发布、无需保留的旧草稿再重新运行。

## 签名材料

仓库需要以下 Actions Secrets：

- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
- `ANDROID_KEY_BASE64`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

首次初始化：`python tool/configure_release_secrets.py`。该脚本调用 gh 上传密钥，
私钥与密码保存在当前用户目录 `.codex/keys/billow`，不进入 Git。
请将该目录做离线备份；丢失 updater 私钥或 Android keystore 会破坏旧安装的升级链。
公钥写入 `src-tauri/tauri.conf.json`，允许随代码公开。
`GITHUB_TOKEN` 由 Actions 自动提供，无需额外个人令牌。

macOS 使用 ad-hoc 签名，没有 Apple Developer ID 公证；Windows 未配置 Authenticode。
Tauri 更新签名用于校验更新包来源，与操作系统安装器证书是不同的签名。

## 应用更新行为

- 桌面安装版启动时自动检查，设置页也能手动检查；后台检查失败不会弹窗。
- 用户选择下载并安装后，先下载并验证签名，再关闭代理连接，然后安装。
  代理未能关闭会阻止安装。Windows 安装器会重启应用；macOS/Linux 显示重启按钮。
- Android 自动检查 GitHub 稳定版，提供官方 ARM64 APK 下载入口；下载和系统安装需要用户操作。
  不使用桌面 updater 安装 Android 包。
- 更新端点：`https://github.com/sakullla/Billow/releases/latest/download/latest.json`。
  草稿不可作为公开更新端点；必须至少有一次完整正式发布，才能验证端到端升级。
- Linux deb/AppImage 分别使用对应更新包；当前没有 Intel Mac 和 Linux ARM64 构建。

## 图标

生成入口：`python tool/generate_app_icons.py --force`，默认 `gpt-image-2.6`。
沿用 Rillight 脚本的本地 Codex provider 配置和 Responses 图像工具调用方式。
原图为 `assets/icon-source.png`，标准图为 `assets/icon.png`，提示词记录在 `assets/icon-prompt.txt`。
`npm run icons` 从标准图生成原生、Android、网页图标，不调用图像 API。
