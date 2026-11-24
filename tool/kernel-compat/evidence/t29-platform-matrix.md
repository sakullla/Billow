# T29 — 五平台与真机交付证据（2026-11-24，T29-A3 刷新）

- Workflow：`2026-11-20-native-rust-kernel` / T29-A3（证据/验证任务，不改产品功能）
- 候选：`billow-kernel 0.1.0`，sha256 `c4467fe99d524635e079d79c09a7125bd58d7f76331af9a8c2698eab04d3400b`；git HEAD `ec862c289b2003d9253e0c01dbd7057a21dc3638`（工作树只有本任务证据新增）
- 宿主：macOS 27.0 (26A428) arm64，Xcode 27.2 (27B52)，iOS 27.2 SDK，cargo/rustc 1.98.1
- 结论：**macOS 打包后双向切换在当前候选再次通过；Windows/Linux/Android/iOS 真机/R3/R4 仍 blocked/unverified，不用模拟器或构建成功替代。**
- 相对 T29-A1/A2：A1/A2 记录的是 `39df438` / `be00302e…`；T26/T28 返修（Android fd/stats、groups flake、ss cipher、cwnd、StopSignals）之后本轮全部命令在 `ec862c2` 上重跑，A1 日志同日录保留，不删除。

完整机读版本：[`t29-platform-matrix.json`](t29-platform-matrix.json)。

## 平台总表

| 平台 | 结果 | 已执行（本轮） | 原始日志 | 缺失条件 / 补证责任 |
| --- | --- | --- | --- | --- |
| macOS | **passed** | 重新构建 release 内核（11,345,712 B）；`packaged_engines_switch_both_ways_with_a_marked_request` 1 passed/0 failed（6.63 s）；`desktop_packaged_runtime_starts_offline` 1 passed/0 failed（6.26 s） | `t29-a3-macos-build.log`、`t29-a3-candidate.log`、`t29-a3-macos-switch.log`、`t29-a3-macos-offline.log` | 未构建完整 `.app`/DMG；仅回环、不改系统代理/TUN。macOS 切换无需补证 |
| iOS | **blocked**（模拟器侧 passed） | 重建两个 kernel archive；宿主/双扩展 typecheck；C ABI smoke 20/20；四个 `BillowRust`/`BillowMihomo` simulator/device unsigned 构建 | `t29-a3-ios-*.log`、`t29-a3-environment.log`；A1 的 `t29-ios-BillowRust-crash.ips` | 物理 iPhone/iPad `unavailable`；无 Team/签名；宿主 stats 未透传（R4）。责任：T3/T7 设备执行者 + 产品 owner |
| Android | **blocked** | `cargo check --features android-vpn --target aarch64-linux-android`（exit 101）；NDK/SDK/adb/JDK 探测 | `t29-a3-android-check.log`、`t29-a3-environment.log` | 无 NDK/SDK/adb/emulator/gradle、JDK 8（需 21）、无 keystore、无设备。责任：Android 环境 owner 或真机手动执行 |
| Windows | **blocked** | `cargo check --target x86_64-pc-windows-msvc`（exit 101）；工具链探测；release.yml 入口核对 | `t29-a3-windows-check.log`、`t29-a3-environment.log` | 无 MSVC `cl.exe`/Windows SDK；`ring` 报 `assert.h` not found。责任：Windows release runner |
| Linux | **blocked** | `cargo check --target x86_64-unknown-linux-gnu`（exit 101）；工具链探测；release.yml 入口核对 | `t29-a3-linux-check.log`、`t29-a3-environment.log` | 无 `x86_64-linux-gnu-gcc`；无 Linux 运行环境。责任：ubuntu release runner |

## 1. macOS（passed）

```sh
CARGO_TARGET_DIR=<t29-a3>/target cargo build --release --locked \
  -p billow-kernel-cli --manifest-path native-kernel/Cargo.toml --target aarch64-apple-darwin
CARGO_TARGET_DIR=<t29-a3>/src-tauri-target \
BILLOW_TEST_RESOURCES=<t29-a3>/runtime-package \
  cargo test --manifest-path src-tauri/Cargo.toml --locked \
  packaged_engines_switch_both_ways_with_a_marked_request -- --ignored --nocapture
CARGO_TARGET_DIR=<t29-a3>/src-tauri-target \
BILLOW_TEST_RESOURCES=<t29-a3>/runtime-package \
  cargo test --manifest-path src-tauri/Cargo.toml --locked \
  desktop_packaged_runtime_starts_offline -- --ignored --nocapture
```

- `runtime-package` 与 `tool/prepare_desktop_runtime.mjs` 输出同布局：复制既有 `kernel.br`（sha256 `70998f8b…`，Mihomo v1.19.34 未变）/`kernel.json`/`geo`/`mihomo-LICENSE`，换成本轮构建的 `billow-kernel` 与生成的 `rust-kernel.json`；仓库内 `src-tauri/resources/runtime` 未被改动。
- 候选身份：`sha256 c4467fe9…`（11,345,712 B）、`billow-kernel 0.1.0`；`--check` 对 `mixed-port/mode:rule/MATCH,DIRECT` 输出 `configuration accepted` 与 instance/pid/version=0.1.0（`t29-a3-candidate.log`）。
- 用例断言标记序列 `mihomo-1 → rust-1 → mihomo-2 → mihomo-3`；负例 `sniffer.enable: true` 被拒绝后仍由 Mihomo 承载 `mihomo-3`，快照保持 mihomo。
- `desktop_packaged_runtime_starts_offline` 同候选通过，说明 T28 的 groups/cipher/cwnd 返修没有破坏随包离线启动。

## 2. iOS（simulator passed / device blocked）

本轮已执行：

- `CARGO_TARGET_DIR=<t29-a3>/ios-target node tool/ios/build-rust-kernel.mjs --platform all`：device `cc3a2723…`（93,541,328 B），simulator `b1029ab4…`（93,491,088 B）。
- `tool/ios/verify-host-sources.sh`：host / BillowMihomo / BillowRust / `main.mm` 全部 typecheck 通过。
- `tool/ios/verify-rust-kernel.sh`：20/20 PASS；`peakRssBytes 28,524,544` **只是 smoke 进程读数，不用于 R3**。
- 四个 unsigned 构建全部 `BUILD SUCCEEDED`：`BillowRust`/`BillowMihomo`（simulator debug）与先 `resolve-mihomo.sh`（`SDKROOT=iphoneos`）后的 `BillowRust`/`BillowMihomo`（device release）。Rust 扩展分别 `linking Rust kernel …/simulator/rust/libapp.a` 与 `…/device/rust/libapp.a`。
- 未重复 A1 的 `simctl` 单独 `.appex` 启动实验：其 `NSExtensionMain`/`EXC_BREAKPOINT` 崩溃已证明不构成扩展运行验证。

真机缺失：`xcrun devicectl list devices` 中 iPhone 15 Pro Max（`00008130-000E65482883401C`）与 iPad Pro 11"（`00008112-000959682203401E`）均为 `unavailable`；无 Apple Team、无 provisioning、无受控流量端点。**R3/R4 的模拟器数字不得代替真机。**

三处接口/工具事实（已同步文档）：

1. **stats 未透传宿主（R4 直接相关）**：扩展 `status` 回复带 `stats`（`billow_ios_vpn_stats`），Rust 宿主侧 `src-tauri/src/ios_vpn.rs` 的 `IosStatus`/`IosStats` 已能解码（T26-A4 只做了这一层），但 Swift 宿主 `ProviderStatus`（`Shared/BillowVPNError.swift`）没有 `stats` 字段，`BillowMobileBridge.statusDictionary`、`ProviderSupport.writeStatus` 也只输出既有 10 个键，前端 `src/lib/types.ts` 的 `IosVpnStatus` 同样没有 `stats`。所以在当前候选 `ec862c2` 上 `ios_vpn_status("rust").stats` 仍是 `None`、`status/rust.json` 没有 counts。**不得声称可从宿主命令自动读取 `tcpFlows/queuedPackets/generation/peakRssBytes`**；补证需产品改动（宿主 + TS 类型），责任在 T7 之后的宿主侧 owner。
2. **`xctrace` 模板名**：当前 Xcode 没有名为 `VM Tracker` 的 template；它是 instrument。R3 命令应为 `--template 'Allocations' --instrument 'VM Tracker'`。`log collect` 真机参数为 `--device-udid`，且 zsh 下要写 `/usr/bin/log`。
3. **linked.xcconfig 会被构建改写**：`src-tauri/gen/apple/build/rust-kernel/linked.xcconfig` 是仓库跟踪的“未链接”占位文件，`resolve-mihomo.sh` 会把它改成实际 archive 路径（工程加载时读取）。device 构建前若残留 simulator 路径，首次链接会失败（A1 实测 `t29-ios-xcodebuild-rust-device-stale.log`）；本轮先按 `SDKROOT=iphoneos` 运行 `resolve-mihomo.sh` 再构建成功，之后已把该文件恢复为 HEAD 内容。入口已写入 `tool/ios/verify-device.md`。

## 3. Android（blocked）

```sh
CARGO_TARGET_DIR=<t29-a3>/android-target cargo check --locked -p billow-kernel-cli \
  --features android-vpn --target aarch64-linux-android --manifest-path native-kernel/Cargo.toml
# → exit 101: cc-rs failed to find tool "aarch64-linux-android-clang"
```

- `aarch64-linux-android` Rust target 已装，但 `ANDROID_HOME`/`ANDROID_NDK_HOME`/`NDK_HOME` 均未设置，`~/Library/Android/sdk` 不存在。
- `adb`/`emulator`/`sdkmanager`/`gradle`/`aarch64-linux-android-clang` 均缺失；`java` 为 1.8.0_492（release job 用 21）；无 `keystore.properties`。
- APK、VpnService TUN fd 移交、设置页双向切换与标记流量都未执行；未用宿主单测冒充。
- `release.yml` 的 android job 只安装 NDK 28.2.13676358/SDK 36 并构建/上传 APK，**没有** packaged-switch 步骤；真机证据需按 `tool/engine-switch.md` 手动执行。

补证入口：安装 NDK/SDK/platform-tools/JDK 21 + 签名材料，执行
`TAURI_ENV_PLATFORM=android node tool/prepare_android_kernel.mjs --force`、
`npm run tauri -- android build --target aarch64 --apk --split-per-abi`，再按 `tool/engine-switch.md` 的 adb/标记端点步骤记录。

## 4. Windows / Linux（blocked，CI 入口兼容）

| 平台 | 本轮检查 | 精确错误 | CI 入口 |
| --- | --- | --- | --- |
| Windows | `cargo check -p billow-kernel-cli --target x86_64-pc-windows-msvc` | exit 101，`ring 0.17.14` C 编译：`fatal error: 'assert.h' file not found`（无 MSVC/Windows SDK） | release.yml 238–247 行同样执行 offline + switch 两条命令 |
| Linux | `cargo check -p billow-kernel-cli --target x86_64-unknown-linux-gnu` | exit 101，`failed to find tool "x86_64-linux-gnu-gcc"` | 同上（ubuntu-22.04 runner） |

- 本机虽有 `x86_64-w64-mingw32-gcc`，但没有 `x86_64-pc-windows-gnu` Rust target；release 目标为 MSVC，不用 mingw 冒充。
- Docker 29.5.2 可用但**未**用来跑 Linux 打包切换：容器不是 release runner，按 T29-A2 评审保留为“未尝试、不计入”的说明，不把容器结果当发布证据。

**负例兼容性**：`release.yml` 的切换命令仍是
`packaged_engines_switch_both_ways_with_a_marked_request`；负例为 `sniffer.enable: true`
（`src-tauri/src/profile.rs`），macOS 本轮用同一命令实跑通过，因此 Windows/Linux CI 条目无需改动。
`ci.yml` 三平台 `cargo test` 只跑默认用例（ignored 跳过），打包后切换仍以 `release.yml` 为唯一入口。

## 5. R1–R4 判定

| 需求 | 判定 | 依据 |
| --- | --- | --- |
| R1 | **partial** | macOS 双向切换 + 标记流量在当前候选通过；Windows/Linux/Android 与 iOS 真机未执行 |
| R2 | **not assessed（由 T28 承担）** | 本任务不重跑全量兼容；切换夹具仅 `MATCH,DIRECT`。R2 证据归 T28 选项矩阵/差分，不可引用本文件 |
| R3 | **unverified** | 无真机 `phys_footprint`；模拟器 28,524,544 B 的 `peakRssBytes` 不计入 |
| R4 | **unverified** | 无真机逐轮基线；且宿主 Swift/TS 未透传 `stats`，`ios_vpn_status("rust").stats` 仍为 `None` |

## 6. 待补证清单

1. Windows runner：打包后跑 release.yml 的两条命令，附标记序列与服务端观测。
2. Linux runner：同上。
3. Android：NDK/SDK/JDK 21/签名/设备，构建 APK 后双向切换并核对 `--tun-fd` 数据面（release.yml 无此步，需手动）。
4. iPhone：Team + 签名宿主 + 物理设备，采集 R3 `Physical Footprint`（Allocations + VM Tracker instrument）与 R4 逐轮 trace。
5. 产品改动：把扩展 `stats` 加入 Swift `ProviderStatus`/`statusDictionary`/`writeStatus` 与 TS `IosVpnStatus`，否则 R4 的计数证据无法通过 `ios_vpn_status` 取得（当前候选仍未落地）。
