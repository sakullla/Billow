# T29 — 五平台与真机交付证据（2026-11-25，T29-A5 刷新）

- Workflow：`2026-11-20-native-rust-kernel` / T29-A5（证据/验证任务，不改产品功能）
- 候选：`billow-kernel 0.1.0`，sha256 `ae77c74b16f9844714ec165e1d35ec7925cfb533184912d1f997125ec7fdfa06`，12,164,944 B；git HEAD `e1a53f95610d287b3d7db83d3d5192503277b4df`（T8-A2 证据提交 `68e2615` 只在其上增加日志/文档；工作树只有 workflow state 与本证据更新）
- 宿主：macOS 27.0 (26A428) arm64，Xcode 27.2 (27B52)，iOS 27.2 SDK，cargo/rustc 1.98.1，Node 26.13.0
- 结论：**macOS 在当前候选通过（引用 T8-A2 实跑）；Windows/Linux/Android/iOS 真机/R3/R4 仍 blocked/unverified。本任务不评估 R2。**
- 相对 A3：A3 记录的是 `ec862c2` / `c4467fe9…`。本轮不重建内核、不重跑长命令，macOS 与当前候选内核身份引用 T8-A2（`t8-a2-*`）；iOS archive/构建日志与三平台 `cargo check` 错误仍是 A3 在 `ec862c2` 上的记录，已在每处标注。A1/A3 日志保留，不删除。

完整机读版本：[`t29-platform-matrix.json`](t29-platform-matrix.json)。当前候选复跑明细另见 [`t8-delivery.json`](t8-delivery.json) 与 `docs/testing/2026-11-23-delivery-verification.md`。

## 平台总表

| 平台 | 结果 | 当前候选已有证据 | 原始日志 | 缺失条件 / 补证责任 |
| --- | --- | --- | --- | --- |
| macOS | **passed** | T8-A2 在 `e1a53f9` 重建 release 内核（12,164,944 B，`ae77c74b…`）；`packaged_engines_switch_both_ways_with_a_marked_request` 1 passed/0 failed（7.89 s）；`desktop_packaged_runtime_starts_offline` 1 passed/0 failed（5.70 s） | `t8-a2-build.log`、`t8-a2-candidate.log`、`t8-a2-macos-switch.log` | 未构建完整 `.app`/DMG；仅回环、不改系统代理/TUN。macOS 切换无需补证 |
| iOS | **blocked**（当前候选仅宿主 typecheck；模拟器/构建证据属于 A3 候选） | `e1a53f9`：宿主/双扩展 typecheck（含 `ProviderStatus` stats 编解码 smoke）与 App Group manifest 通过。`ec862c2`（A3）：两个 kernel archive、C ABI smoke 20/20、四个 unsigned simulator/device 构建 | `t8-a2-ios-host-typecheck.log`、`t8-a2-ios-app-group.log`、`t8-a2-environment.log`；A3 的 `t29-a3-ios-*.log` | 物理 iPhone/iPad `unavailable`；无 Team/签名；未安装、未建立系统 VPN、无真机流量；R3/R4 无采样。责任：T3/T7/T29 设备执行者 |
| Android | **blocked** | `e1a53f9` 环境复核：NDK/SDK/adb/emulator/gradle/JDK 21 仍缺失（`t8-a2-environment.log`）。`ec862c2`（A3）：`cargo check --features android-vpn --target aarch64-linux-android` exit 101。T26-A6 只读复核 `--tun-fd` 进程路径仍成立（非真机） | `t8-a2-environment.log`、`t29-a3-android-check.log`、`t26-a6-review.md` | 无 NDK/SDK/adb/emulator、JDK 8（需 21）、无 keystore、无设备。责任：Android 环境 owner 或真机手动执行 |
| Windows | **blocked** | `e1a53f9` 环境复核：`cl.exe`/Windows SDK 仍缺失。`ec862c2`（A3）：`cargo check --target x86_64-pc-windows-msvc` exit 101（`ring` 缺 `assert.h`）；release.yml 入口已核对 | `t8-a2-environment.log`、`t29-a3-windows-check.log` | 无 MSVC 工具链/Windows 主机。责任：Windows release runner |
| Linux | **blocked** | `e1a53f9` 环境复核：`x86_64-linux-gnu-gcc` 仍缺失。`ec862c2`（A3）：`cargo check --target x86_64-unknown-linux-gnu` exit 101；release.yml 入口已核对 | `t8-a2-environment.log`、`t29-a3-linux-check.log` | 无 `x86_64-linux-gnu-gcc`、无 Linux 运行环境。责任：ubuntu release runner |

## 1. macOS（passed，T8-A2 于 `e1a53f9`）

```sh
cargo build --release --locked -p billow-kernel-cli --manifest-path native-kernel/Cargo.toml
BILLOW_TEST_RESOURCES=<t8-a2>/runtime-package \
  cargo test --manifest-path src-tauri/Cargo.toml --locked \
  packaged_engines_switch_both_ways_with_a_marked_request -- --ignored --nocapture
BILLOW_TEST_RESOURCES=<t8-a2>/runtime-package \
  cargo test --manifest-path src-tauri/Cargo.toml --locked \
  desktop_packaged_runtime_starts_offline -- --ignored --nocapture
```

- `<t8-a2>/runtime-package` 与 `tool/prepare_desktop_runtime.mjs` 输出同布局：复制既有 `kernel.br`（sha256 `70998f8b…`，Mihomo v1.19.34 未变）/`kernel.json`/`geo`/`mihomo-LICENSE`，换成本轮构建的 `billow-kernel`（`ae77c74b…`）与 `rust-kernel.json`；仓库内 `src-tauri/resources/runtime` 未被改动。
- 候选身份：`sha256 ae77c74b…`（12,164,944 B）、`billow-kernel 0.1.0`；`--check --port 63810` 对 `mixed-port/mode:rule/MATCH,DIRECT` 输出 `configuration accepted`，instance/pid/version=0.1.0（`t8-a2-candidate.log`）。
- 用例断言标记序列 `mihomo-1 → rust-1 → mihomo-2 → mihomo-3`；负例 `sniffer.enable: true` 被具名拒绝后仍由 Mihomo 承载 `mihomo-3`，快照保持 mihomo。
- `desktop_packaged_runtime_starts_offline` 同候选通过，说明后续返修没有破坏随包离线启动。
- 限制不变：未构建完整 `.app`/DMG，未改系统代理/TUN；测的是当前候选临时打包目录，不是仓库内既有的随包 Mihomo 二进制。

## 2. iOS（当前候选仅宿主检查通过 / 真机 blocked）

当前候选 `e1a53f9` 已执行：

- `tool/ios/verify-host-sources.sh`：host / BillowMihomo / BillowRust / `main.mm` 全部 typecheck 通过；其中包含 T7-A4 新增的 `ProviderStatus` stats 编解码 smoke（reply 携带 `stats` 时能解码并重编码为 camelCase 键）。
- `bash tool/ios/verify-app-group.sh`：同一版本同时保留 mihomo/rust manifest。
- 这两项只是编译/编解码检查，**不是**扩展启动或真机流量证据。

A3 在 `ec862c2` 上的构建证据（本轮未重建，不得写成当前二进制）：

- `node tool/ios/build-rust-kernel.mjs --platform all`：device `cc3a2723…`（93,541,328 B），simulator `b1029ab4…`（93,491,088 B）。
- `tool/ios/verify-rust-kernel.sh`：20/20 PASS；`peakRssBytes 28,524,544` 只是 smoke 进程读数，**不用于 R3**。
- 四个 unsigned 构建全部 `BUILD SUCCEEDED`：`BillowRust`/`BillowMihomo`（simulator debug）与先 `resolve-mihomo.sh`（`SDKROOT=iphoneos`）后的 `BillowRust`/`BillowMihomo`（device release）。
- A1 的 `simctl` 单独 `.appex` 启动以 `NSExtensionMain`/`EXC_BREAKPOINT` 崩溃，证明不构成扩展运行验证，本轮未重复。

真机缺失：`xcrun devicectl list devices` 中 iPhone 15 Pro Max（`00008130-000E65482883401C`）与 iPad Pro 11"（`00008112-000959682203401E`）均为 `unavailable`；无 Apple Team、无 provisioning、无受控流量端点。**R3/R4 的模拟器数字不得代替真机。**

两处接口/工具事实：

1. **stats 读取链路已落地，但无真机采样（R4 仍未验证）**：T7-A4 已把扩展 `stats` 透传到 Swift `ProviderStatus.stats`、`BillowMobileBridge.statusDictionary`、`ProviderSupport.writeStatus`/`status/<engine>.json` 与 TS `IosVpnStatus.stats`；宿主 typecheck + 编解码 smoke 在当前候选通过。所以 `ios_vpn_status("rust").stats` 的代码入口存在，但**没有任何真机 `tcpFlows/queuedPackets/generation/peakRssBytes` 读数**；仍需签名宿主 + 物理设备采样。
2. **`linked.xcconfig` 会被构建改写**：`src-tauri/gen/apple/build/rust-kernel/linked.xcconfig` 是仓库跟踪的“未链接”占位文件，`resolve-mihomo.sh` 会把它改成实际 archive 路径。device 构建前若残留 simulator 路径，首次链接会失败（A1 实测 `t29-ios-xcodebuild-rust-device-stale.log`）；入口已写入 `tool/ios/verify-device.md`。

## 3. Android（blocked）

```sh
# ec862c2 (A3)，当前候选未重跑；e1a53f9 环境复核确认工具仍缺失
CARGO_TARGET_DIR=<t29-a3>/android-target cargo check --locked -p billow-kernel-cli \
  --features android-vpn --target aarch64-linux-android --manifest-path native-kernel/Cargo.toml
# → exit 101: cc-rs failed to find tool "aarch64-linux-android-clang"
```

- `aarch64-linux-android` Rust target 已装，但 `ANDROID_HOME`/`ANDROID_NDK_HOME`/`NDK_HOME` 均未设置，`~/Library/Android/sdk` 不存在。
- `adb`/`emulator`/`sdkmanager`/`gradle`/`aarch64-linux-android-clang` 均缺失；`java` 为 1.8.0_492（release job 用 21）；无 `keystore.properties`。T8-A2 在 `e1a53f9` 复核结论相同。
- APK、VpnService TUN fd 移交、设置页双向切换与标记流量都未执行；未用宿主单测冒充。
- T26-A6 只读复核了 HEAD 的 `--tun-fd` 进程路径（仍由宿主单测/进程 smoke 覆盖），不是真机 TUN 运行。
- `release.yml` 的 android job 只安装 NDK 28.2.13676358/SDK 36 并构建/上传 APK，**没有** packaged-switch 步骤；真机证据需按 `tool/engine-switch.md` 手动执行。

补证入口：安装 NDK/SDK/platform-tools/JDK 21 + 签名材料，执行
`TAURI_ENV_PLATFORM=android node tool/prepare_android_kernel.mjs --force`、
`npm run tauri -- android build --target aarch64 --apk --split-per-abi`，再按 `tool/engine-switch.md` 的 adb/标记端点步骤记录。

## 4. Windows / Linux（blocked，CI 入口兼容）

| 平台 | 检查 | 精确错误 | 当前候选环境复核 | CI 入口 |
| --- | --- | --- | --- | --- |
| Windows | `cargo check -p billow-kernel-cli --target x86_64-pc-windows-msvc`（A3, `ec862c2`） | exit 101，`ring 0.17.14` C 编译：`fatal error: 'assert.h' file not found`（无 MSVC/Windows SDK） | `e1a53f9`：`cl.exe` 与 Windows SDK 仍缺失 | release.yml 238–247 行同样执行 offline + switch 两条命令 |
| Linux | `cargo check -p billow-kernel-cli --target x86_64-unknown-linux-gnu`（A3, `ec862c2`） | exit 101，`failed to find tool "x86_64-linux-gnu-gcc"` | `e1a53f9`：`x86_64-linux-gnu-gcc` 仍缺失 | 同上（ubuntu-22.04 runner） |

- 本机虽有 `x86_64-w64-mingw32-gcc`，但没有 `x86_64-pc-windows-gnu` Rust target；release 目标为 MSVC，不用 mingw 冒充。
- Docker 29.5.2 可用但**未**用来跑 Linux 打包切换：容器不是 release runner，按 T29-A2 评审保留为“未尝试、不计入”的说明，不把容器结果当发布证据。

**负例兼容性**：`release.yml` 的切换命令仍是
`packaged_engines_switch_both_ways_with_a_marked_request`；负例为 `sniffer.enable: true`
（`src-tauri/src/profile.rs`），macOS 在当前候选用同一命令实跑通过，因此 Windows/Linux CI 条目无需改动。
`ci.yml` 三平台 `cargo test` 只跑默认用例（ignored 跳过），打包后切换仍以 `release.yml` 为唯一入口。

## 5. R1–R4 判定

| 需求 | 判定 | 依据 |
| --- | --- | --- |
| R1 | **partial** | macOS 双向切换 + 标记流量在当前候选 `e1a53f9` 通过（T8-A2）；Windows/Linux/Android 与 iOS 真机未执行 |
| R2 | **not assessed（T29 不评估）** | 切换夹具仅 `MATCH,DIRECT`，本文件不提供 R2 平台级证据。R2 由 T28/T8 承担：T8-A2 记录选项矩阵 **291 no-op / 88 implemented / 119 enabled，problems 0**，仍有 **76 条 enabled 具名拒绝**；引用 `t28-option-parity.md` / `t8-delivery.json`，不可引用本文件 |
| R3 | **unverified** | 无真机 `phys_footprint`；A3 模拟器 28,524,544 B 的 `peakRssBytes` 不计入 |
| R4 | **unverified** | 无真机逐轮基线；stats 读取链路已由 T7-A4 落地并通过编解码 smoke，但从未在签名真机上采样计数 |

## 6. 待补证清单

1. Windows runner：打包后跑 release.yml 的两条命令，附标记序列与服务端观测。
2. Linux runner：同上。
3. Android：NDK/SDK/JDK 21/签名/设备，构建 APK 后双向切换并核对 `--tun-fd` 数据面（release.yml 无此步，需手动）。
4. iPhone：Team + 签名宿主 + 物理设备，采集 R3 `Physical Footprint`（Allocations + VM Tracker instrument，`--template 'Allocations' --instrument 'VM Tracker'`）与 R4 逐轮 trace；R4 计数从 `ios_vpn_status("rust").stats` 读取。
5. iOS 当前候选：下次真机运行前重建 device/simulator archive 并在 `e1a53f9` 之后的首个设备候选上重跑 unsigned 构建（本轮只有 A3 的 `ec862c2` 构建记录）。
