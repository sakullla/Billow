# iOS Rust 扩展内存与回收验证入口（R3/R4，T7）

- 状态：**入口已就绪，真机测量未执行**。
- 需求：`docs/requirements/2026-11-20-native-rust-kernel.md` 的 R3（整个 VPN 系统扩展峰值 ≤ 40,000,000 字节，十进制）与 R4（重复使用后资源可回收、空闲基线稳定）。
- 本次环境：macOS 27.2 / Xcode 27.2 / iOS 27.2 SDK。`xcrun devicectl list devices` 显示 iPhone 15 Pro Max 未连接（unavailable），模拟器 iPhone 18 Pro（iOS 27.0）已启动。
- 因此：**没有任何真机峰值、系统终止或逐轮基线数字**。已执行的构建、宿主测试与模拟器 smoke 见 `tool/kernel-compat/evidence/t7-ios-ffi.md`；模拟器 smoke 进程的 `peakRssBytes`（约 25–28 MB）是 smoke 二进制本身的读数，不是扩展峰值，不能作为 R3 依据。

## 1. 被测对象与身份

| 项 | 值 |
| --- | --- |
| 扩展 target | `BillowRust`（`app.billow.client.rust`，packet-tunnel-provider） |
| 内核 archive | `src-tauri/gen/apple/Externals/arm64/device/rust/libapp.a`（`billow-kernel` staticlib，`--features ios-vpn`） |
| 内核版本串 | `billow_ios_vpn_version` → `billow-rust 0.1.0`（进程内以 `billow_ios_vpn_stats` 的 `version` 字段记录） |
| 引擎身份 | 控制接口 `/version` 与 `Kernel::identity()`（uuid/pid/version/config digest/listen） |
| 配置代次 | `billow_ios_vpn_stats` 的 `generation`、`reloads` |
| 进程 | 扩展进程名 `BillowRust`；PID 从 `xcrun devicectl device info processes` 或 Xcode 的 Debug Navigator 记录 |
| 配置 | `<AppGroup>/versions/<version>/config.yaml` 的 manifest 版本号与 SHA-256（`versions/<version>/manifest.json`） |

记录每次测量都必须带上：iPhone 型号、iOS 版本、App 构建号、manifest 版本、PID、`billow-rust 0.1.0`、当前配置代次。

## 2. 采样接口

内核提供两条互补的采样路径，两者都要记录，因为它们回答不同问题：

1. **`billow_ios_vpn_stats`（JSON，无 Instruments 也能取）**
   - 扩展 `handleAppMessage` 的 `status` 回复把同一对象放在 `stats` 键（`RustTunnelProvider.swift`）。
   - 含 `peakRssBytes`（`getrusage(RUSAGE_SELF).ru_maxrss`，Darwin 为字节）、`tcpFlows/tcpFlowHigh`、`udpFlows/udpFlowHigh`、`queuedPackets/queueHigh`、`droppedInbound/droppedEgress`、`dnsQueries`、`generation/reloads`。
   - 用途：逐轮对比空闲基线、确认连接/队列归零、关联配置代次。
2. **系统指标 `phys_footprint`（判定 R3 的口径）**
   - 系统因内存压力终止扩展看的是该进程的 physical footprint，不是 RSS。
   - 采集：`xcrun xctrace record --device <UDID> --template 'VM Tracker' --attach BillowRust --time-limit <N>s --output t7-<scenario>.trace`，在 Instruments 里读 `Physical Footprint` 峰值；或 Xcode Debug Navigator 的 Memory gauge（连接真机运行时）。
   - 用途：每个场景的峰值与 R3 比较。

不得用模拟器、宿主进程或 `.appex` 体积冒充上述指标。

## 3. 场景表（每项都必须单独记录峰值并提交原始 trace/状态 JSON）

| # | 场景 | 负载 | 采样点 | R3 判据 | R4 判据 |
| --- | --- | --- | --- | --- | --- |
| 1 | 启动与配置加载 | 真实用户配置（含 rules、proxy-groups、rule-providers、dns） | `startTunnel` 完成前 0.2 s 内每 100 ms；完成时 | 峰值 ≤ 40,000,000 | — |
| 2 | 锁屏空闲 | 隧道已连接 10 分钟，无流量 | 第 1/5/10 分钟 | 峰值 ≤ 40,000,000 | 空闲值平稳 |
| 3 | 并发连接与持续转发 | 8 条 TCP（HTTPS 下载/上传）+ 20 个 UDP 目标（含 DNS），持续 ≥ 60 s | 每 5 s | 峰值 ≤ 40,000,000 | 关闭后 `tcpFlows==0`、`queuedPackets==0` |
| 4 | 规则集更新 | 重载同一 `config.yaml` 20 次（含 rule-provider 更新） | 每次 reload 前后 | 任一瞬时峰值 ≤ 40,000,000 | `generation` 递增而空闲值不抬升；旧代次无残留 |
| 5 | 网络切换与重连 | Wi-Fi ↔ 蜂窝 各 5 次 | 切换后 10 s 内 | 峰值 ≤ 40,000,000 | 重连后连接/队列归零 |
| 6 | R4 循环 | 建连/关闭 ×50、reload ×20、断网重连 ×10，每轮回到等价空闲 | 每轮结束 | 每轮峰值 ≤ 40,000,000 | 末轮空闲与首轮空闲之差不超过测量噪声；连接列表与队列为 0 |

系统终止检查：每个场景后在主机执行

```sh
xcrun devicectl device info processes --device <UDID> | grep -i billowrust
log collect --device <UDID> --last 30m --output t7-jetsam.logarchive
log show t7-jetsam.logarchive --predicate 'eventMessage CONTAINS[c] "jetsam" AND eventMessage CONTAINS[c] "BillowRust"' --last 30m
```

出现超预算、因内存压力被终止，或更新/重连后无法继续转发，即 R3 失败；已结束连接、已替换规则集或缓冲区持续累积、空闲基线逐轮抬升，即 R4 失败。

## 4. 复现命令

```sh
# 1) 构建内核 archive（离线；Cargo.lock 为准）与扩展
node tool/ios/build-rust-kernel.mjs --platform device
node tool/ios/build-mihomo-ios.mjs --platform device        # BillowMihomo（对照扩展）
(cd src-tauri/gen/apple && xcodegen generate)
# 2) 宿主 + 双扩展（需要 Team 与已注册的 UDID/App Group）
npx tauri ios build --export-method debugging --ci
xcrun devicectl device install app --device <UDID> "<ipa 或 .app>"
# 3) 宿主准备资源并选择 rust 引擎（设置页或测试入口）
#    prepare(config.yaml + geo assets) -> setSelected(rust) -> connect
# 4) 真机采样
xcrun xctrace record --device <UDID> --template 'VM Tracker' --attach BillowRust \
  --time-limit 600s --output t7-scenario3.trace
# 5) 结构化计数（status 回复里的 stats，或命令行走宿主测试入口）
```

无 Instruments 时的最小记录：`status` 回复的 `stats` JSON（含 `peakRssBytes`）+ 场景时间戳 + `generation`。有 Instruments 时以其 `Physical Footprint` 为 R3 数值，`peakRssBytes` 作为旁证。

## 5. 设备要求

- 物理 iPhone（本次要求的 iPhone 15 Pro Max 或同级），iOS 版本与记录一致。
- Apple Developer Team：`packet-tunnel-provider` 能力 + App Group `group.app.billow.client` 已为 `app.billow.client`、`app.billow.client.mihomo`、`app.billow.client.rust` 注册。
- 受控流量目标：自建 TCP/UDP echo 与 DNS 解析器（记录服务端观测到的载荷），用于确认转发未中断。
- 每个场景的原始 trace、status JSON、jetsam 查询输出，按 `<日期>-<场景>-<PID>.trace|json` 归档，并在本文件追加结果表。

## 6. 当前结论

- R3：**未验证**（无真机数字）。
- R4：**未验证**（无逐轮基线）。
- 代码侧的输入已就绪：缓冲/队列上限见 `tool/kernel-compat/evidence/t7-ios-ffi.md` 的 Bounds 表；reload 会关闭全部流与关联并递增 `generation`；`stats` 暴露高水位与丢弃计数。
- 待补：宿主设置入口（`ios_vpn_*` 命令与 TS 调用）与 Rust 引擎资源准备路径；两者完成后才能从真实设置页启动两个扩展并按本表测量。
