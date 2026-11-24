# T29 — 五平台与真机交付证据（2026-11-24）

- Workflow：`2026-11-20-native-rust-kernel` / T29-A1（证据/验证任务，不改产品功能）
- 候选：`billow-kernel 0.1.0`，sha256 `be00302e352abc51d36cb040183d2f9a927b04719e79e7261893a6f6a3e51521`；git HEAD `39df43851e32cb78b51d76ecfa42f10fc3ff1082`（工作树无产品源码改动）
- 宿主：macOS 27.0 (26A428) arm64，Xcode 27.2 (27B52)，iOS 27.2 SDK，cargo/rustc 1.98.1
- 结论：**macOS 打包后双向切换通过；Windows/Linux/Android/iOS 真机/R3/R4 均未通过，按 blocked/unverified 返回，不用模拟器或构建成功替代。**

完整机读版本：[`t29-platform-matrix.json`](t29-platform-matrix.json)。

## 平台总表

| 平台 | 结果 | 已执行 | 原始日志 | 缺失条件 / 补证责任 |
| --- | --- | --- | --- | --- |
| macOS | **passed** | 当前候选 release 构建；`packaged_engines_switch_both_ways_with_a_marked_request` 1 passed/0 failed（7.37 s）；`desktop_packaged_runtime_starts_offline` 1 passed/0 failed（6.29 s） | `t29-macos-build.log`、`t29-candidate.log`、`t29-macos-switch.log`、`t29-macos-offline.log` | 未构建完整 `.app`/DMG；测试仅回环、不改系统代理/TUN。无需补证 macOS 切换 |
| iOS | **blocked**（模拟器侧 passed） | 两个 kernel archive；宿主/双扩展 typecheck；C ABI smoke 20/20；四个 `BillowRust`/`BillowMihomo` simulator/device unsigned 构建 | `t29-ios-*.log`、`t29-ios-BillowRust-crash.ips` | 物理 iPhone/iPad `unavailable`；无 Team/签名；另缺宿主 stats 透传（R4）。责任：T3/T7 设备执行者 + 产品 owner |
| Android | **blocked** | `cargo check --features android-vpn --target aarch64-linux-android`；NDK/SDK/adb/JDK 探测 | `t29-android-check.log`、`t29-environment.log` | 无 NDK/SDK/adb/emulator、JDK 8（需 21）、无 keystore、无设备。责任：Android 环境 owner 或 release CI |
| Windows | **blocked** | `cargo check --target x86_64-pc-windows-msvc`；工具链探测；release.yml 入口核对 | `t29-windows-check.log`、`t29-environment.log` | 无 MSVC `cl.exe`/Windows SDK；`ring` C 编译报 `assert.h` not found。责任：Windows release runner |
| Linux | **blocked** | `cargo check --target x86_64-unknown-linux-gnu`；工具链探测；release.yml 入口核对 | `t29-linux-check.log`、`t29-environment.log` | 无 `x86_64-linux-gnu-gcc`；无 Linux 运行环境。责任：ubuntu release runner |

## 1. macOS（passed）

```sh
CARGO_TARGET_DIR=<t29>/target cargo build --release --locked \
  -p billow-kernel-cli --manifest-path native-kernel/Cargo.toml --target aarch64-apple-darwin
CARGO_TARGET_DIR=<t29>/src-tauri-target \
BILLOW_TEST_RESOURCES=<t29>/runtime-package \
  cargo test --manifest-path src-tauri/Cargo.toml --locked \
  packaged_engines_switch_both_ways_with_a_marked_request -- --ignored --nocapture
```

- `runtime-package` 与 `tool/prepare_desktop_runtime.mjs` 的输出同布局：既有 `kernel.br`/`kernel.json`/`geo`/`mihomo-LICENSE`，加上本候选新构建的 `billow-kernel` 与生成的 `rust-kernel.json`；未覆盖仓库内 `src-tauri/resources/runtime`。
- 候选身份：`sha256 be00302e…`、`billow-kernel 0.1.0`；`billow-kernel --check` 成功并输出 instance/`version=0.1.0`（`t29-candidate.log`）。
- 用例断言标记序列 `mihomo-1 → rust-1 → mihomo-2 → mihomo-3`，并在负例（`sniffer.enable: true`）被拒绝后确认仍由 Mihomo 承载 `mihomo-3`。
- 同一命令即计划的 `switch_acceptance`；`desktop_packaged_runtime_starts_offline` 也通过，说明当前负例修复与 release 入口兼容。

## 2. iOS（simulator passed / device blocked）

已执行（详见 JSON 与日志）：

- `node tool/ios/build-rust-kernel.mjs --platform all`：device `c220ffec…`（93,494,456 B），simulator `c4151642…`（93,444,304 B）。
- `tool/ios/verify-host-sources.sh`：host / BillowMihomo / BillowRust / `main.mm` 全部 typecheck 通过。
- `tool/ios/verify-rust-kernel.sh`：20/20，PASS；`peakRssBytes 28,491,776` **只是 smoke 进程读数，不用于 R3**。
- 四个 unsigned 构建全部 `BUILD SUCCEEDED`；Rust 扩展分别 `-force_load` 正确的 simulator/device archive。
- 单独 `simctl install BillowRust.appex` 后启动 bundle id 会在 `NSExtensionMain`/XPC 处 `EXC_BREAKPOINT` 崩溃；没有签名宿主时，这不构成扩展运行验证。

真机缺失：`xcrun devicectl list devices` 中 iPhone 15 Pro Max 与 iPad 均为 `unavailable`；无 Apple Team、无 provisioning、无受控流量端点。**R3/R4 的模拟器数字不得代替真机。**

另发现三处接口/工具事实（已同步到文档）：

1. **stats 未透传宿主**：扩展 `status` 回复有 `stats`（`billow_ios_vpn_stats` 的 JSON），但 `ProviderStatus` 没有该字段，`ProviderSupport.decodeStatus` 与 `BillowMobileBridge.statusDictionary` 都丢弃它，`status/rust.json` 也不含；因此 `ios_vpn_status("rust")` 只有身份/状态/错误，R4 的 `tcpFlows/queuedPackets/generation/reloads` 目前不能从宿主读取。补证需产品改动（T7 owner）。
2. **`xctrace` 模板名**：当前 Xcode 没有名为 `VM Tracker` 的 template；它是 instrument。R3 命令应为 `--template 'Allocations' --instrument 'VM Tracker'`。`log collect` 真机参数为 `--device-udid`，且 zsh 下要写 `/usr/bin/log`。
3. **linked.xcconfig 跨 SDK 复用**：该文件在工程加载时读取，device 构建前若残留 simulator 路径，首次链接会失败（T29 实测 `linking ... built for 'iOS-simulator'`，见 `t29-ios-xcodebuild-rust-device-stale.log`）；先按 `SDKROOT=iphoneos` 运行 `resolve-mihomo.sh` 后成功。已写入 `tool/ios/verify-device.md`。

## 3. Android（blocked）

```sh
CARGO_TARGET_DIR=<t29>/android-target cargo check --locked -p billow-kernel-cli \
  --features android-vpn --target aarch64-linux-android --manifest-path native-kernel/Cargo.toml
# → error: cc-rs failed to find tool "aarch64-linux-android-clang"
```

- `aarch64-linux-android` Rust target 已安装，但 `ANDROID_HOME`/`ANDROID_NDK_HOME`/`NDK_HOME` 均未设置，`~/Library/Android/sdk` 不存在。
- `adb`/`emulator`/`sdkmanager`/`aarch64-linux-android-clang` 均缺失；`gradle` 未安装（项目有 gradlew）；`java` 为 1.8（release 需要 21）；无 `keystore.properties`。
- 因此 APK、VpnService TUN fd 移交、设置页双向切换与标记流量都未执行；未用宿主单测冒充。

补证入口：安装 NDK 28.2.13676358/SDK/platform-tools/JDK 21 + 签名材料，执行
`TAURI_ENV_PLATFORM=android node tool/prepare_android_kernel.mjs --force`、
`npm run tauri -- android build --target aarch64 --apk --split-per-abi`，再按 `tool/engine-switch.md` 的 adb/标记端点步骤记录。

## 4. Windows / Linux（blocked，CI 入口兼容）

| 平台 | 本机检查 | 精确错误 | CI 入口 |
| --- | --- | --- | --- |
| Windows | `cargo check -p billow-kernel-cli --target x86_64-pc-windows-msvc` | `ring` C 编译：`fatal error: 'assert.h' file not found`（无 MSVC/Windows SDK） | release.yml 238–247 行同样执行 offline + switch 两条命令 |
| Linux | `cargo check -p billow-kernel-cli --target x86_64-unknown-linux-gnu` | `failed to find tool "x86_64-linux-gnu-gcc"` | 同上（ubuntu-22.04 runner） |

- 本机虽装有 `x86_64-w64-mingw32-gcc`，但没有 `x86_64-pc-windows-gnu` Rust 目标；release 目标为 MSVC，不能用 mingw 冒充。
- 未使用 Docker 运行 Linux 打包切换；本任务只按 Recipe 记录交叉工具链与 CI 入口，避免把容器结果当作发布 runner 证据。

**负例兼容性**：`release.yml` 的切换命令仍是
`packaged_engines_switch_both_ways_with_a_marked_request`；测试负例已从 proxy-groups 改为
`sniffer.enable: true`（`src-tauri/src/profile.rs`），macOS 用同一命令实跑通过，因此 Windows/Linux
CI 条目无需改动。CI 的 `ci.yml` 三平台 `cargo test` 只跑默认用例（ignored 跳过），打包后切换仍以
`release.yml` 为唯一入口。

## 5. R1–R4 判定

| 需求 | 判定 | 依据 |
| --- | --- | --- |
| R1 | **partial** | macOS 双向切换 + 标记流量通过；Windows/Linux/Android 与 iOS 真机未执行 |
| R2 | **not assessed** | 本任务不重跑全量兼容；切换夹具仅 `MATCH,DIRECT`。T28 结果不外推为平台运行证据 |
| R3 | **unverified** | 无真机 `phys_footprint`；模拟器 28,491,776 B 的 `peakRssBytes` 不计入 |
| R4 | **unverified** | 无真机逐轮基线；且宿主未透传 `stats`，计数归零无法按表核对 |

## 6. 待补证清单

1. Windows runner：打包后跑 release.yml 的两条命令，附标记序列与服务端观测。
2. Linux runner：同上。
3. Android：NDK/SDK/JDK 21/签名/设备，构建 APK 后双向切换并核对 `--tun-fd` 数据面。
4. iPhone：Team + 签名宿主 + 物理设备，采集 R3 `Physical Footprint`（Allocations + VM Tracker instrument）与 R4 逐轮 trace。
5. 产品改动：把扩展 `stats` 加入 `ProviderStatus`/宿主 bridge/`status/rust.json`，否则 R4 的计数证据无法通过 `ios_vpn_status` 取得。
