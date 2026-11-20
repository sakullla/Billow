---
format: exploration
summary: "现有四平台依赖外部 Mihomo v1.19.34，已有配置覆写与部分差分样例。iOS 双内核嵌入、Rust 数据面、完整行为对照和真机内存证据均待建立。"
---
# 内核、配置与移动端现状

## 当前连接路径（R1）

桌面后端把安装路径交给进程运行时，创建 Mihomo 子进程或调用提权助手，再检查监听端口。停止时处理进程、控制器和 PID。配置准备、控制通道、进程所有权和系统代理/TUN 接管均在连接路径上。现有内核选择调整的是 Mihomo 发布频道。可定位于 `src-tauri/src/lib.rs:349`、`src-tauri/src/lib.rs:395`、`src-tauri/src/profile.rs:1358`、`src-tauri/src/profile.rs:1661`、`src-tauri/src/profile.rs:1735`。

Android 现有 VPN 服务设定应用过滤并建立 TUN，将可继承的 FD 交给运行时；内核以打包在原生库目录的 ELF 运行。权限拒绝与启动失败会影响接管及连接状态。见 `src-tauri/gen/android/app/src/main/java/app/billow/client/BillowVpnService.kt:66`、`src-tauri/src/kernel.rs:718`、`src-tauri/src/profile.rs:5497`。

节点选择、测速、连接诊断还消费 Mihomo 控制器的响应。监听端口可达仅说明有服务应答，不能由此认定选中的引擎完成了实际转发。见 `src-tauri/src/nodes.rs:741`、`src-tauri/src/nodes.rs:763`、`src-tauri/src/diagnostics.rs:610`。已查模块入口和依赖中未定位到可替换的原生 Rust 转发内核（`src-tauri/src/lib.rs:1`、`src-tauri/Cargo.toml:17`）。

## 兼容基准和目前可复用的证据（R2）

桌面资产清单固定 v1.19.34 及各架构 SHA-256；Android 固定同版本源码提交 `0455d0d28c4526937380505153e65a843d8612e8`，包含 Android 构建标签。清单中的架构多于现有发行矩阵。见 `src-tauri/desktop-kernel.json:2`、`src-tauri/android-kernel.json:2`、`tool/prepare_android_kernel.mjs:40`、`.github/scripts/release-request.cjs:2`。

配置准备与 YAML 覆写、非法 provider URL、MRS 导出顺序和发行包离线启动均有局部样例。见 `src-tauri/src/profile.rs:6056`、`docs/testing/2026-11-16-provider-url-compatibility.md:15`、`docs/resource-performance.md:12`、`.github/workflows/release.yml:236`。上述路径未提供两个内核在同条件下完成握手、解析、分流、实际出站的端到端证据。

对应上游标签的配置包含监听器、隧道、DNS、TLS、嗅探、代理与规则提供方等；兼容面大于现有 UI 的可编辑字段。上游该版本还包含具体协议版本变化。[Mihomo 配置模型](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/config/config.go) · [发布记录](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.34)

## iOS 工程与可观测性（R1、R3、R4）

现有 Rust 库声明静态库类型并带 Tauri 移动入口，但在原生工程、应用脚本和发布矩阵中只定位到 Android 的移动端接入；未找到 iOS 宿主、Packet Tunnel 扩展、嵌入的 iOS Mihomo 制品或真机测量入口。见 `src-tauri/Cargo.toml:11`、`src-tauri/src/lib.rs:1487`、`package.json:14`、`.github/workflows/release.yml:13`。

Apple 的 Packet Tunnel Provider 以独立扩展目标嵌入宿主，通过 packetFlow 收发 IP 包，需相应的 Network Extension entitlement。Xcode 可展示进程内存和最高观测值，Instruments 支持按分配代次追踪存活对象。模拟器的内存压力行为与真机不同。[Packet Tunnel Provider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider) · [Xcode 内存测量](https://developer.apple.com/documentation/xcode/gathering-information-about-memory-use)

当前 macOS 约 25 MiB 的结果测的是隔离 MRS 解码进程 RSS（`docs/resource-performance.md:13`）。它没有覆盖扩展、转发、并发缓冲和重载重叠，不能外推 iOS 峰值或证明资源释放。40,000,000 字节来自本项目 R3。

## 未知及影响

- 已查清单和测试未提供全部配置选项及其组合的端到端一致性记录，iOS Mihomo 的嵌入构建、平台支持范围和实际出口尚待实证。
- 当前为 Windows 环境，PATH 未找到 xcodebuild、xcrun、xctrace。尚未验证外部 Mac、签名权限、iPhone 和测量条件；R1 的 iOS 实流量、R3 和 R4 均无真机结果。
- 配置规模、并发与更新时的新旧数据重叠会影响可实现的峰值。已有样本未给出全兼容输入在 40 MB 内运行的可行性证明。
