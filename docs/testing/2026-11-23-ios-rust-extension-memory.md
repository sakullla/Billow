# iOS Rust 扩展内存与回收验证入口（R3/R4，T7 / T29）

- 状态：**入口已就绪，真机测量未执行**（T29 于 2026-11-24 复核，物理 iPhone/iPad 仍为 `unavailable`）。
- 需求：`docs/requirements/2026-11-20-native-rust-kernel.md` 的 R3（整个 VPN 系统扩展峰值 ≤ 40,000,000 字节，十进制）与 R4（重复使用后资源可回收、空闲基线稳定）。
- 本次环境（T29）：macOS 27.0 / Xcode 27.2 / iOS 27.2 SDK；模拟器 iPhone 18 Pro（iOS 27.0）已启动。`xcrun devicectl list devices` 显示 iPhone 15 Pro Max 与 iPad 均为 `unavailable`。
- T29 复核候选：`billow-kernel 0.1.0`，sha256 `be00302e352abc51d36cb040183d2f9a927b04719e79e7261893a6f6a3e51521`；模拟器 C ABI smoke、宿主源集 typecheck 与两个扩展的 simulator/device unsigned 构建均通过，但**仍没有真机峰值、系统终止或逐轮基线数字**。
- 模拟器 smoke 进程的 `peakRssBytes`（T29 为 28,491,776）是 smoke 二进制本身的读数，不是扩展峰值，不能作为 R3 依据。已执行的构建与 smoke 见 `tool/kernel-compat/evidence/t7-ios-ffi.md` 与 `tool/kernel-compat/evidence/t29-platform-matrix.md`。

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

## 2. 采样接口（按 2026-11-24 当前代码）

内核提供两条互补的采样路径：

1. **`billow_ios_vpn_stats` C ABI（扩展进程内）**
   - 头文件 `RustExtension/include/billow_ios_vpn.h`；扩展桥接层导出为 `billow_rust_kernel_stats`（`RustKernelBridge.c`），`BillowRustEngine.statsJSON()` 调用它。
   - 返回一个 JSON 对象，当前键：`running`、`version`、`generation`、`reloads`、`peakRssBytes`（`getrusage(RUSAGE_SELF).ru_maxrss`，Darwin 为字节）、`inPackets/inBytes/outPackets/outBytes`、`tcpOpened/tcpClosed/tcpRejected/tcpFlows/tcpFlowHigh`、`udpDatagrams/udpReplies/udpFlows/udpFlowHigh`、`dnsQueries/dnsFailures`、`invalidPackets/fragments/unsupportedProtocols/icmpDropped`、`droppedInbound/droppedEgress`、`queueHigh/queuedPackets`。
   - 扩展的 `RustTunnelProvider.handleAppMessage` 处理 `command == "status"` 时，把该对象放在回复的 `stats` 键下。
   - **宿主透传（T26-A4 已接通）**：宿主 `BillowVPNManager.status(of:)` 把扩展 status 回复解码为 `ProviderStatusReply`，与 `status/<engine>.json` 的 `ProviderStatus` 合并（身份、`startedAt` 取文件，运行态取回复），把 `stats` 保留到 `ProviderStatus.stats`；`BillowMobileBridge.statusDictionary` 输出 `stats` 对象，并把它写回 `status/rust.json`。因此 `ios_vpn_status("rust")` 现在返回嵌套的 `stats`（`tcpFlows/queuedPackets/generation/reloads/peakRssBytes` 等），Tauri 命令的 JSON 与设置页/诊断读到的是同一份数据；Mihomo 回复没有 `stats`，字段保持 `null`，旧 status 文件也照常解码。
   - 用途与限制：`tcpFlows/queuedPackets/generation/reloads` 可从宿主命令与 `status/rust.json` 直接核对；`peakRssBytes` 仍是扩展进程的 RSS 旁证，R3 判定仍以系统 `phys_footprint` 为准。
2. **系统指标 `phys_footprint`（判定 R3 的口径）**
   - 系统因内存压力终止扩展看的是该进程的 physical footprint，不是 RSS。
   - 采集：用 Instruments 的 **VM Tracker instrument**（它属于 instrument，不是 template）配合 `Allocations` 模板；`xctrace list templates` 中没有名为 `VM Tracker` 的模板。命令见 §4，在 Instruments 里读 `Physical Footprint` 峰值；或 Xcode Debug Navigator 的 Memory gauge（连接真机运行时）。
   - 用途：每个场景的峰值与 R3 比较。

不得用模拟器、宿主进程、`.appex` 体积或 `peakRssBytes` 冒充 `phys_footprint` 的 R3 数值。

## 3. 场景表（每项都必须单独记录峰值并提交原始 trace/状态 JSON）

| # | 场景 | 负载 | 采样点 | R3 判据 | R4 判据 |
| --- | --- | --- | --- | --- | --- |
| 1 | 启动与配置加载 | 真实用户配置（含 rules、proxy-groups、rule-providers、dns） | `startTunnel` 完成前 0.2 s 内每 100 ms；完成时 | 峰值 ≤ 40,000,000 | — |
| 2 | 锁屏空闲 | 隧道已连接 10 分钟，无流量 | 第 1/5/10 分钟 | 峰值 ≤ 40,000,000 | 空闲值平稳 |
| 3 | 并发连接与持续转发 | 8 条 TCP（HTTPS 下载/上传）+ 20 个 UDP 目标（含 DNS），持续 ≥ 60 s | 每 5 s | 峰值 ≤ 40,000,000 | 关闭后 `tcpFlows==0`、`queuedPackets==0` |
| 4 | 规则集更新 | 重载同一 `config.yaml` 20 次（含 rule-provider 更新） | 每次 reload 前后 | 任一瞬时峰值 ≤ 40,000,000 | `generation` 递增而空闲值不抬升；旧代次无残留 |
| 5 | 网络切换与重连 | Wi-Fi ↔ 蜂窝 各 5 次 | 切换后 10 s 内 | 峰值 ≤ 40,000,000 | 重连后连接/队列归零 |
| 6 | R4 循环 | 建连/关闭 ×50、reload ×20、断网重连 ×10，每轮回到等价空闲 | 每轮结束 | 每轮峰值 ≤ 40,000,000 | 末轮空闲与首轮空闲之差不超过测量噪声；连接列表与队列为 0 |

R4 列的 `tcpFlows/queuedPackets/generation` 来自扩展 status 回复的 `stats`，T26-A4 起由宿主透传到 `ios_vpn_status("rust")` 与 `status/rust.json`（见 §2），可以在场景表中直接核对；`peakRssBytes` 仍只作 RSS 旁证，R3 以 `phys_footprint` 为准。

系统终止检查：每个场景后在主机执行（注意 zsh 的 `log` 是内建命令，必须写 `/usr/bin/log`；`log collect` 的真机参数是 `--device-udid`）

```sh
xcrun devicectl device info processes --device <UDID> --search BillowRust
/usr/bin/log collect --device-udid <UDID> --last 30m --output t29-jetsam.logarchive
/usr/bin/log show --archive t29-jetsam.logarchive \
  --predicate 'eventMessage CONTAINS[c] "jetsam" AND eventMessage CONTAINS[c] "BillowRust"'
```

出现超预算、因内存压力被终止，或更新/重连后无法继续转发，即 R3 失败；已结束连接、已替换规则集或缓冲区持续累积、空闲基线逐轮抬升，即 R4 失败。

## 4. 复现命令

```sh
# 1) 构建两个平台的内核 archive（离线；Cargo.lock 为准）
node tool/ios/build-rust-kernel.mjs --platform all
node tool/ios/build-mihomo-ios.mjs --platform device        # BillowMihomo（对照扩展）
(cd src-tauri/gen/apple && xcodegen generate)

# 2) 宿主 + 双扩展（需要 Team 与已注册的 UDID/App Group）
npx tauri ios build --export-method debugging --ci
xcrun devicectl device install app --device <UDID> "<ipa 或 .app>"

# 3) 宿主准备资源并选择 rust 引擎（设置页或测试入口）
#    prepare(config.yaml + geo assets) -> setSelected(rust) -> connect
#    ios_vpn_status("rust") 返回身份/状态/错误，以及嵌套的 stats（见 §2）

# 4) 真机 R3 采样：VM Tracker 是 instrument，不是 template
#    先用 devicectl 取 BillowRust 的 PID，再 attach；--attach 也接受进程名
xcrun devicectl device info processes --device <UDID> --search BillowRust
xcrun xctrace record --device <UDID> --template 'Allocations' --instrument 'VM Tracker' \
  --attach <BillowRust-PID> --time-limit 600s --output t29-scenario3.trace

# 5) 结构化计数：ios_vpn_status("rust").stats 或 status/rust.json 的 stats
#    已由宿主透传，可直接记录 tcpFlows/queuedPackets/generation/peakRssBytes。
```

无 Instruments 时的最小记录：扩展 status 回复的 `stats` JSON（含 `peakRssBytes`）+ 场景时间戳 + `generation`；宿主透传已接通后，这条路径可直接由 `ios_vpn_status("rust")` / `status/rust.json` 取得。有 Instruments 时以其 `Physical Footprint` 为 R3 数值，`peakRssBytes` 仅作旁证。

## 5. 设备要求

- 物理 iPhone（本次要求的 iPhone 15 Pro Max 或同级），iOS 版本与记录一致。
- Apple Developer Team：`packet-tunnel-provider` 能力 + App Group `group.app.billow.client` 已为 `app.billow.client`、`app.billow.client.mihomo`、`app.billow.client.rust` 注册。
- 受控流量目标：自建 TCP/UDP echo 与 DNS 解析器（记录服务端观测到的载荷），用于确认转发未中断。
- 每个场景的原始 trace、宿主可见的 status JSON（`ProviderStatus` 字段 + `stats` 计数）、jetsam 查询输出，按 `<日期>-<场景>-<PID>.trace|json` 归档，并在本文件追加结果表。

## 6. 当前结论

- R3：**未验证**（无真机数字；T29 只重跑模拟器 smoke 与 unsigned 构建）。补证责任：具备 Apple Team、签名权限与物理 iPhone 的执行者；入口为本文件 §4 与 `tool/ios/verify-device.md`。
- R4：**未验证**（无逐轮基线）。宿主接口已补齐：扩展 status 回复的 `stats` 于 T26-A4 起透传到 `ios_vpn_status("rust")` 与 `status/rust.json`，真机执行时可据此核对 `tcpFlows/queuedPackets/generation`。
- 代码侧的输入已就绪：缓冲/队列上限见 `tool/kernel-compat/evidence/t7-ios-ffi.md` 的 Bounds 表；reload 会关闭全部流与关联并递增 `generation`；`stats` 暴露高水位与丢弃计数。
- 宿主设置入口与资源准备已接通（T7-A2）：设置 → 内核 → iOS 扩展可读取两个扩展、选择、准备当前配置、连接/断开/重载并显示错误码；`ios_vpn_prepare_active` 负责 staging，`ResourcesInstaller` 对同一版本同时保留 mihomo/rust manifest。
- T7-A3 修正：宿主 target 使用独立条件 `BILLOW_ENGINE_HOST`，`Shared/PacketPump.swift` 只在两个扩展 target 编译；`tool/ios/verify-host-sources.sh` 用真实源集同时 typecheck 宿主/两个扩展。准备后调用 `ios_vpn_prune`（保留新版本与运行中扩展报告的版本）避免 `versions/<hash>` 累积；扩展 `installed` 改为检查 Bundle/PlugIns 中的 `.appex`，未启动时设置页显示“已安装（未启动）”；staging 也会移除 `sniffer.enable: true`（本内核未实现嗅探，域名规则退化为目标 IP/DNS 结果）。
- T29 复核（2026-11-24）：候选 `billow-kernel 0.1.0` sha256 `be00302e…`；模拟器 C ABI smoke 20/20、宿主/双扩展 typecheck、四个 unsigned 扩展构建均通过；物理设备仍 unavailable，**不能把模拟器结果当作 R3/R4**。详见 `tool/kernel-compat/evidence/t29-platform-matrix.md`。
- 下一步：在真机执行本表并附原始 trace/状态 JSON；`ios_vpn_status("rust").stats` 与 `status/rust.json` 已可直接取 R4 计数。
