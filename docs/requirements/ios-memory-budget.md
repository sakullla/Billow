# iOS 内存目标与当前优化范围

调研日期：2026-11-15。用户确认本轮按目标优化，暂不接入 iOS。

## 50 MiB 的含义

Apple DTS 工程师公布的 Packet Tunnel Provider 扩展进程限制为 **50 MiB**，并于 2025 年 10 月表示 iOS 26 的限制未变。它不是主应用、安装包或 JavaScript 堆的大小限制。50 MiB = 52,428,800 字节。Apple 同时强调设备与系统版本可能不同，不能把这一数值当成永久保证，必须覆盖多种真机组合测试。

来源：[Apple Developer Forums：Network Extension memory limits](https://developer.apple.com/forums/thread/73148?page=2)。

## 后续 iOS 设计约束

- 主应用负责界面、订阅编辑、测速展示与诊断；VPN 扩展只保留转发所需的核心、有效配置和有限状态。扩展中不载入 Vue、WebView 或桌面管理功能。
- 通过 `NEPacketTunnelProvider` 与 `NETunnelProviderManager` 管理隧道，内核需要可嵌入库，不能直接沿用当前的外部可执行文件启动方式。Tauri iOS 编译要求 macOS 和 Xcode。
- 扩展内存的**暂定工程目标**为常态不超过 35 MiB、压力场景峰值低于 45 MiB，以便给系统开销留余量。这些是待真机验证的项目预算，不是 Apple 的额外规定，也不是当前已经达到的数据。
- 以扩展进程的物理内存占用、峰值和 Jetsam 日志验收。Mihomo `/memory` 的口径取决于内核版本和平台：当前上游 Windows 实现使用工作集、Darwin 使用 RSS，不能笼统称为 Go 堆，也不能据此证明 iOS 扩展的 physical footprint 低于系统限制。参见 [Mihomo 内存统计](https://github.com/MetaCubeX/mihomo/blob/Meta/tunnel/statistic/manager.go) 和 [Windows 实现](https://github.com/MetaCubeX/mihomo/blob/Meta/component/memory/memory_windows.go)。
- Go 的 `GOMEMLIMIT` / `debug.SetMemoryLimit` 是运行时软限制，不包含所有原生分配，压力下也可能超出。不可设置成 50 MiB 后宣称达标；后续需要依据 Swift、网络栈、Go 栈与原生库实测占用，为 Go 留更小预算。
- 大型规则集、代理提供者、并发连接与测速必须分别测峰值。配置更新、连接回收、Wi-Fi/蜂窝切换、前后台切换与长时间运行也必须覆盖。不能用裁掉有效规则或静默丢弃节点的方式达标。
- 后续评估轻量网络栈、按需加载规则、可回收缓存和有界队列；不能默认把桌面的网络监听服务直接搬进扩展。Apple TN3120 对 Packet Tunnel 的用途和流量处理有明确边界。

参考：[NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)、[NETunnelProviderManager](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager)、[Tauri iOS prerequisites](https://v2.tauri.app/start/prerequisites/#ios)、[Go GC guide](https://go.dev/doc/gc-guide)、[Apple TN3120](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers)。

## 本轮已实现的通用优化

- 内核网络请求和会话锁等待离开窗口事件线程，托盘内核操作也在后台执行。
- 配置只缓存节点组、协议类型和设置摘要；编辑、订阅更新与成功应用覆写时使缓存失效，避免每秒重新解析 YAML。
- `/proxies` 按需解码成员、当前选择和协议，跳过测速历史等字段；IPC 只发送一份节点目录。
- 后端直接借用缓存中的节点成员与协议映射，不再创建前端未使用的第二份排序目录。
- `/memory` 与 `/traffic` 都在后台订阅，状态刷新只读取最近样本；内存接口的首个零样本不显示为实际占用。移除了原先每次刷新等待读取内存流而触发的 800 ms 超时。
- 前端复用未变的节点组和日志，规则列表采用浅层状态；连接、规则列表保留虚拟滚动，恢复实时连接时释放暂停快照。
- Android 已安装应用列表缓存 60 秒，避免每秒跨 JNI 扫描全部应用。
- 已有内核不再被启动时的在线版本检查阻塞；配置和内核未变时复用进程，普通系统代理断开不再重启内核。

这些优化改善现有 Windows/Android 客户端，不代表已支持 iOS，或已满足 iOS 扩展内存预算。本轮不修改 iOS 构建、签名或发布流程，也不对桌面核心强加 50 MiB 上限。

## 复核方式

- `npm test`、`npm run build`。
- `cargo test --manifest-path src-tauri/Cargo.toml --locked`。
- `cargo test --manifest-path src-tauri/Cargo.toml benchmark_cached_snapshot -- --ignored --nocapture`：对合成的 16 组 × 500 节点比较缓存与重新解析 YAML 的快照生成和 JSON 序列化耗时。仅比较相同构建下的结果，不作为系统进程内存测试。
- Windows TUN 的 UAC 同意/取消、驱动加载与真实联网需在安装包上验证；单元测试覆盖取消后保留连接、实际监听就绪和状态切换，但不能替代系统交互测试。

2026-11-15 Windows debug 构建的本地合成基准：8,000 个节点，100 次快照及 JSON 序列化，启用元数据缓存平均 **54.12 ms/次**，每次重新解析 YAML 平均 **198.07 ms/次**，耗时降低约 **73%**；序列化结果为 681,934 字节。这不是 release 性能、真实订阅端到端延迟或进程内存测量。

后续仅本地优化进一步移除了排序目录和成员映射副本，同一合成基准测得 **42.64 ms/次**（重新解析 YAML 为 189.61 ms/次），输出字节数不变。运行中的真实内核 `/memory` 只读采样也确认：首个零样本在约 1,059 ms 到达，第二个有效样本在约 2,033 ms 到达；800 ms 的普通请求无法读取这个流。新的流式回归测试在服务端保持连接打开时即可读到有效内存值。
