# 交付核验报告：五平台行为与完整基准（T8 / T8-A2）

- 日期：2026-11-25（T8-A2 最终候选核验；T8-A1 复核记录保留在文末）
- Workflow：`2026-11-20-native-rust-kernel` / Task T8 / Attempt T8-A2 / message `T8-A2-M1`
- 候选：git HEAD `e1a53f95610d287b3d7db83d3d5192503277b4df`（T31-A6、T7-A4、T26-A6 之后的最终候选；工作树只有 workflow state 变更，无产品代码改动）
- 候选内核：`billow-kernel 0.1.0`，release 构建（2026-11-25 08:46 CST，`Finished release profile in 3m 01s`），**12,164,944 字节**，SHA-256 `ae77c74b16f9844714ec165e1d35ec7925cfb533184912d1f997125ec7fdfa06`
- 环境：macOS 27.0 (26A428) arm64；Xcode 27.2 (27B52) / iOS 27.2 SDK；rustc 1.98.1；Node 26.13.0
- 对照基准：随包 Mihomo **v1.19.34**（`Mihomo Meta v1.19.34 darwin arm64 with go1.26.11`，二进制 `tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7`，SHA-256 `a55a9073f9b7b1fa596a82c034d2dae3407ec34732102b6e42c5513ce3033f34`）
- 前序平台证据：`tool/kernel-compat/evidence/t29-platform-matrix.{json,md}`（T29-A3，候选 `ec862c2`；macOS 通过，其余平台 blocked）

机器可读汇总：[`tool/kernel-compat/evidence/t8-delivery.json`](../../tool/kernel-compat/evidence/t8-delivery.json)。本次新增的原始日志/JSON 均以 `t8-a2-*` 前缀保存在 `tool/kernel-compat/evidence/`。

## 结论（先给判定）

**当前候选不得出具交付通过结论。** macOS 在当前候选上实跑通过；其余平台与 R3/R4 缺设备/工具链/真机数据，按 T8 recipe 不得通过。

| 需求 | 结论 | 原因摘要 |
| --- | --- | --- |
| **R1** 各平台双向切换 | **未通过（仅 macOS 当前候选通过）** | macOS：当前候选 `packaged_engines_switch_both_ways_with_a_marked_request` **1 passed / 0 failed**（7.89 s），标记序列 `mihomo-1 → rust-1 → mihomo-2 → mihomo-3` 全部断言；Windows/Linux/Android 无工具链/设备，未实跑；iOS 物理设备 `unavailable`，只有模拟器 smoke 与 unsigned 构建。 |
| **R2** 完整兼容随附 Mihomo 有效配置 | **未通过（已覆盖子集通过）** | 当前候选：默认套件 452 passed / 0 failed / 123 ignored；T22 22 pass + 1 known difference；T23 28/28；T24 38/38（9 个 framing difference，0 differ）；T25 47/49 equal + 2 recorded divergence；T5 12/12；选项矩阵 **291 no-op / 88 implemented / 119 enabled，problems 0**。但仍有 **76 条 enabled 具名拒绝**（12 个族，见 §3）以及 TUN/sniffer/设备族 `dial()`、`client-fingerprint` 近似等有效配置缺口；其他平台行为未运行。 |
| **R3** iOS 扩展峰值 ≤ 40,000,000 字节 | **未验证** | 物理 iPhone（`00008130-000E65482883401C`）仍 `unavailable`；没有任何扩展进程 `phys_footprint` 真机峰值。模拟器 smoke 的 `peakRssBytes` 是 smoke 进程读数，不能作为 R3 依据。 |
| **R4** 重复使用后资源可回收、基线稳定 | **未验证** | 无真机逐轮建连/重载/断网重连基线与失效对象检查。T7-A4 已把 `stats` 透传代码接通（宿主 typecheck + 编解码 smoke 通过），但没有真机采样数字。 |

按 T8 recipe：“缺基准、设备或关键记录不得出具通过结论”。下文所有“通过”只指明确写出的已执行子项，不代表 R1–R4 任一需求整体通过。模拟器、构建成功、功能子集或单次采样均未写成平台通过。

## 1. 五平台状态总表

| 平台 | R1 双向切换 | 构建/模拟器证据 | 阻塞条件与补证入口 |
| --- | --- | --- | --- |
| macOS arm64 | **passed（当前候选 A2 实跑）** | release 内核构建通过；打包切换 1 passed；离线打包启动 1 passed | 无。原始：`t8-a2-build.log`、`t8-a2-candidate.log`、`t8-a2-macos-switch.log` |
| iOS | **blocked** | 模拟器 C ABI smoke 20/20、宿主/双扩展 typecheck、四个 unsigned 扩展构建（T29-A3，候选 `ec862c2`）；A2 在 HEAD 复核宿主 typecheck + `ProviderStatus` stats 编解码 + App Group manifest | 物理 iPhone/iPad `unavailable`，无 Team/签名；未安装、未建立系统 VPN、无真机流量。补证入口：`tool/ios/verify-device.md`、`docs/testing/2026-11-23-ios-rust-extension-memory.md` |
| Windows x86_64 | **blocked** | `cargo check --target x86_64-pc-windows-msvc` exit 101（`ring` 的 C 编译找不到 `assert.h`；无 `cl.exe`/Windows SDK），T29-A3 记录 | 无 MSVC 工具链/Windows 主机。补证入口：release.yml 两条切换命令在 Windows runner 执行 |
| Linux x86_64 | **blocked** | `cargo check --target x86_64-unknown-linux-gnu` exit 101（找不到 `x86_64-linux-gnu-gcc`），T29-A3 记录 | 无 Linux 工具链/运行环境。补证入口：release.yml 在 ubuntu runner 执行 |
| Android arm64 | **blocked** | `cargo check --target aarch64-linux-android --features android-vpn` exit 101（找不到 `aarch64-linux-android-clang`；无 NDK/SDK/adb/JDK 21），T29-A3 记录；T26-A6 复核 HEAD 的 `--tun-fd` 进程路径仍由宿主单测/进程 smoke 覆盖 | 无 NDK/SDK/adb/设备/签名。补证入口：`tool/engine-switch.md` + `tool/prepare_android_kernel.mjs` |

A2 环境复核（`t8-a2-environment.log`）：HEAD 上 `cl.exe`、`x86_64-linux-gnu-gcc`、`aarch64-linux-android-clang`、`adb`、`emulator`、`sdkmanager`、`gradle` 仍全部缺失，`ANDROID_HOME`/`ANDROID_NDK_HOME`/`NDK_HOME` 未设置，`java` 仍为 1.8；物理 iPhone/iPad 仍 `unavailable`。因此 Windows/Linux/Android 的阻塞与 T29-A3 相同，未用其他平台或容器结果冒充。

## 2. 当前候选复跑证据（A2）

公共参数：`--mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 --rust <T8-A2>/target/release/billow-kernel`；Rust 构建与测试均使用独立临时 `CARGO_TARGET_DIR`，未占用共享 target，未修改仓库内 runtime。

| # | 命令/入口 | 结果 | 原始证据 |
| --- | --- | --- | --- |
| 1 | `cargo build --release --locked -p billow-kernel-cli --manifest-path native-kernel/Cargo.toml` | exit 0，`Finished release profile in 3m 01s`；sha256 `ae77c74b…`，12,164,944 B | `t8-a2-build.log`、`t8-a2-candidate.log` |
| 2 | `billow-kernel --check --port 63810 <mixed-port/mode:rule/MATCH,DIRECT>` | `configuration accepted`，exit 0；identity 输出版本 0.1.0 | `t8-a2-candidate.log` |
| 3 | `cargo test --manifest-path native-kernel/Cargo.toml --locked` | **452 passed / 0 failed / 123 ignored**，19 个 test result（含 doc-test） | `t8-a2-default-tests.log` |
| 4 | `BILLOW_TEST_RESOURCES=<A2 runtime> cargo test --manifest-path src-tauri/Cargo.toml --locked packaged_engines_switch_both_ways_with_a_marked_request -- --ignored --nocapture` | **1 passed / 0 failed**（7.89 s）；标记序列与负例见 §4 | `t8-a2-macos-switch.log` |
| 5 | `BILLOW_TEST_RESOURCES=<A2 runtime> cargo test … desktop_packaged_runtime_starts_offline -- --ignored` | **1 passed / 0 failed**（5.70 s） | `t8-a2-macos-switch.log` |
| 6 | `node --test tool/kernel-compat/runner.test.mjs` | **10/10 pass**，exit 0 | `t8-a2-runner.log` |
| 7 | `node tool/kernel-compat/option-probe.mjs …` | **291 no-op / 88 implemented / 119 enabled，problems 0**，exit 0 | `t8-a2-option-matrix.txt`、`t8-a2-option-probe.log` |
| 8 | `node tool/kernel-compat/t22-differential.mjs … --mmdb-dir <解压 Country/ASN>` | **23 cases：22 pass + 1 known difference，0 unexpected，exit 0** | `t8-a2-t22-dns.json`、`t8-a2-t22.log` |
| 9 | `node tool/kernel-compat/t23-differential.mjs …` | **28/28 pass**（27 cases + persistence），0 differ，exit 0（耗时约 4 min） | `t8-a2-t23-differential.json`、`t8-a2-t23.log` |
| 10 | `node tool/kernel-compat/t24-differential.mjs … --mmdb-dir …` | **38/38 pass**，0 differ，0 unexpected，9 个 inbound framing difference（已归一化） | `t8-a2-t24-differential.json`、`t8-a2-t24.log` |
| 11 | `node tool/kernel-compat/t25-differential.mjs …` | **49 cases：47 equal + 2 recorded divergences，0 unexpected** | `t8-a2-t25-differential.json`、`t8-a2-t25.log` |
| 12 | `node tool/kernel-compat/t5-differential.mjs … --effective-dir <A2 effective>` | **12/12 scenarios pass，0 differ**；Billow desktop/Android effective 产物只有 `sniffer` 被具名拒绝 | `t8-a2-t5-integration.json`、`t8-a2-t5.log`、`t8-a2-t5-effective/` |
| 13 | `tool/ios/verify-host-sources.sh` | 通过：host / BillowMihomo / BillowRust + `main.mm`；`ProviderStatus` 对带 `stats` 的 reply 解码/重编码 smoke 通过 | `t8-a2-ios-host-typecheck.log` |
| 14 | `bash tool/ios/verify-app-group.sh` | 通过：同一版本同时保留 mihomo/rust manifest | `t8-a2-ios-app-group.log` |

未在 A2 重跑：iOS kernel archive 重建/模拟器 smoke（引用 T29-A3 在 `ec862c2` 的记录）；真实对端 `peer-tests.sh`（引用 T31-A6 的 97/97）；`npm test`/`npm run build`（引用 T28/T31 的 342 tests + build）。这些引用在下方按“前序候选证据”标注，不与 A2 当前二进制混写。

## 3. R2 覆盖与剩余具名缺口

### 3.1 已覆盖子集（当前候选 A2 复跑 + 前序候选）

- **默认 Rust 套件**：452 passed / 0 failed / 123 ignored（19 个 test result；ignored 主要是需 pinned 对端的 peer 用例）。
- **T22 DNS/hosts/fake-ip**：23 例，22 例与 pinned 完全一致；1 例 `fallback-geoip-code-mmdb-negated` 是已登记 `known-difference`（pinned mmdb 路径对 `!au` 的二次取反），不是未记录偏差。
- **T23 策略组/选择/健康检查**：27 例 + selection cache 持久化，28/28 通过。
- **T24 规则/provider/GEO-MRS**：38/38 通过；9 个 framing difference 已归一化，0 unexpected。
- **T25 控制接口**：49 例，47 例相等；2 例已登记差异（重载时监听器迁移、`PATCH /configs {"tun":{"enable":true}}`）。
- **T5 组合差分**：12/12 场景通过；同一 YAML 覆盖 fake-ip DNS、hosts、多载体 rule-provider、proxy-provider、select/url-test/fallback 组、controller 与 ss/trojan/ssr/shadowquic 真实出口，并核对每请求 `rule=`/`outbound=`。Billow effective 产物仅启用 `sniffer` 是剩余具名拒绝，移除后桌面/Android 产物都能加载。
- **前序候选证据**（T31-A6 构建，仅作补充，不替代当前候选）：`peer-tests.sh` 97/97 passed；上述差分当时同样 0 unexpected。

### 3.2 剩余具名拒绝族（来自 A2 `option-matrix.txt`：enabled 且 `rust=reject mihomo=accept`，共 **76** 行）

| 协议族 | 行数 | 说明 |
| --- | ---: | --- |
| easytier | 20 | 设备/mesh 路由与 tun 形态；`dial()` 需设备层 |
| wireguard | 11 | 设备族 `dial()` 需 T6/T7 用户态 IP 栈/TUN |
| tuic | 9 | TUIC v4/UDP 等未实现形态 |
| shadowquic | 7 | zero-rtt/QUIC v2/Brutal 等 |
| openvpn | 7 | 设备族 `dial()` 与选项 |
| hysteria（v1） | 6 | port hopping/XPlus/faketcp/wechat/UDP 等 |
| masque | 4 | h2/h3-l4proxy/gVisor 形态 |
| mieru | 3 | UDP/mux/traffic-pattern |
| sudoku | 3 | HTTP tunnel/UoT |
| trojan | 3 | 剩余选项（T28 已重分类） |
| trusttunnel | 2 | quic 等 |
| gost-relay | 1 | 剩余选项 |
| **合计** | **76** | 全部为“显式具名拒绝”，未静默忽略 |

此外仍有不进入选项矩阵的有效配置缺口：

- 桌面启用 `tun`、启用 `sniffer`；iOS staging 会移除 `sniffer.enable: true`（域名规则退化为目标 IP/DNS 结果）。
- 设备族 `wireguard`/`openvpn`/`tailscale`/`zerotier`/`easytier` 的 `dial()` 仍依赖设备层。
- `client-fingerprint` 的 4 个 impl 行是 **近似**（closest rustls profile，无 uTLS ClientHello），不计为字节级 parity（`t30-option-closure.md`）。
- DNS 的 DoQ/system/dhcp/overlay DNS、`#proxy`、respect-rules UDP、h3、ECS；`PROCESS-*` 进程查找；LAN auth 注入；UDP SOCKS5 关联不单独出现在 `/connections`。
- controller 的 `/configs/geo`、`/upgrade/geo`、`/group`、`/cache`、`/storage`、`/dns/query`、`/restart` 为显式 404；`/rules` 无 pinned 额外计数；TLS ALPN 仅 http/1.1。
- Windows 的 `external-controller-pipe`/`routing-mark` 等平台项为具名拒绝；平台运行时行为未验证。

完整状态见 [`rust-mapping.json`](../../tool/kernel-compat/evidence/rust-mapping.json) 与 `tool/kernel-compat/README.md`；本次未把“加载通过”等同于兼容通过。

## 4. macOS 双向切换（当前候选）

`<A2>/runtime-package` 与 `tool/prepare_desktop_runtime.mjs` 输出同布局：复制仓库 runtime 的 `kernel.br`（Mihomo v1.19.34，未变）/`kernel.json`/`geo`/`mihomo-LICENSE`，换成本轮构建的 `billow-kernel`（`ae77c74b…`）与生成的 `rust-kernel.json`；仓库内 `src-tauri/resources/runtime` 未被修改。

测试断言顺序（`src-tauri/src/profile.rs::packaged_engines_switch_both_ways_with_a_marked_request`）：

1. 启动 Mihomo，标记请求返回 `pong:mihomo-1`；
2. 切换 Rust，`engine=rust`、`running_engine=rust`、`engine_identity` 存在，标记返回 `pong:rust-1`；
3. 切回 Mihomo，标记返回 `pong:mihomo-2`；
4. 负例配置 `sniffer.enable: true` 被具名拒绝（“未接受当前配置”），Mihomo 会话保留，标记仍返回 `pong:mihomo-3`。

结果：**1 passed / 0 failed（7.89 s）**；同候选 `desktop_packaged_runtime_starts_offline` **1 passed / 0 failed（5.70 s）**，说明 T28/T31 的组、cipher、cwnd、hy2 等返修未破坏随包离线启动。原始日志：`t8-a2-macos-switch.log`。

边界：本测试只使用回环端点，不修改系统代理/TUN；未构建完整 `.app`/DMG。macOS 的桌面切换无需再补证。

## 5. iOS、R3 与 R4

已执行（模拟器/构建/宿主层）：

- T29-A3（候选 `ec862c2`）：两个 kernel archive 重建；`tool/ios/verify-rust-kernel.sh` 模拟器 C ABI smoke **20/20**；宿主/双扩展 typecheck；四个 `BillowRust`/`BillowMihomo` unsigned 构建 `BUILD SUCCEEDED`。证据：`t29-a3-ios-*.log`。
- A2（HEAD `e1a53f9`）：`tool/ios/verify-host-sources.sh` 通过，其中包含 T7-A4 新增的 `ProviderStatus` stats 编解码 smoke（reply 携带 `stats` 时能解码并重编码为 camelCase 键）；`verify-app-group.sh` 通过。证据：`t8-a2-ios-host-typecheck.log`、`t8-a2-ios-app-group.log`。
- T7-A4 已把 `stats` 透传到 `ProviderStatus.stats`、`statusDictionary`、`status/<engine>.json` 与 TS `IosVpnStatus.stats`；`ios_vpn_status("rust").stats` 在代码与编解码 smoke 上可取。**这只是 R4 的读取入口，不是真机测量。**

未执行（缺设备/签名）：

- 物理 iPhone/iPad 安装、两个扩展各自建立系统 VPN、从其他应用发起命中代理规则的请求并核对出口（R1 iOS 双向）。
- 任何扩展进程 `phys_footprint` 峰值与 R3 六类场景；任何 R4 逐轮空闲基线与失效对象检查；jetsam/系统终止检查。
- 完整 `billow_iOS` 宿主包与真实 `npx tauri ios build`（无 Team；Tauri 预构建仍阻塞 plain xcodebuild）。
- A2 未重建 iOS kernel archive / 模拟器 smoke；上述 iOS 构建证据是 T29-A3 在 `ec862c2` 上的记录，T7-A4 改动仅涉及宿主 stats 透传与 `src-tauri/src/ios_vpn.rs` 的统计解码层。**不把该构建记录写成当前二进制真机验证。**

入口与场景表见 [`2026-11-23-ios-rust-extension-memory.md`](2026-11-23-ios-rust-extension-memory.md) 与 `tool/ios/verify-device.md`。R3 以 Instruments `Physical Footprint` 为准，`peakRssBytes` 仅作旁证；R4 的 `tcpFlows/queuedPackets/generation` 从 `ios_vpn_status("rust").stats` 读取。

## 6. 修正与历史（保留 T8-A1）

- T8-A1 修正 T7 证据中的 ignored 计数：`t7-ios-ffi.md` / `t7-ios-a3.json` 的 `cargo test -p billow-kernel --features ios-vpn` 由 **1 ignored** 改为 **91 ignored**（417 passed / 91 ignored）；`--lib` 仍为 192 passed / 1 ignored，未改。
- T8-A1 返修 macOS 打包切换测试负例：不再使用 T23 已支持的 `proxy-groups`，改用仍被具名拒绝的 `sniffer.enable: true`；`tool/engine-switch.md` 同步更新。
- T8-A2 在 HEAD `e1a53f9` 上重新构建候选并复跑：默认套件、runner、选项矩阵、T22/T23/T24/T25/T5、macOS 切换/离线、iOS 宿主 typecheck/app-group。候选哈希、时间与结果均记录于 `t8-a2-*` 与 `t8-delivery.json`，不复用 A1 的 `6e708345…`/`c4467fe9…` 候选数字。
- 未改动产品代码；仅写入 `docs/testing` 与 `tool/kernel-compat/evidence`。

## 7. 交付前必须补齐

1. Windows runner：打包后执行 release.yml 的两条命令（offline + 双向切换），附标记序列与服务端观测。
2. Linux runner：同上（ubuntu-22.04）。
3. Android：NDK/SDK/JDK 21/签名/设备齐备后构建 APK，按 `tool/engine-switch.md` 双向切换并核对 `--tun-fd` 数据面（release.yml 无此步，需手动）。
4. iPhone：Team + 签名宿主 + 物理设备，完成 iOS 双向切换、R3 六类峰值（Allocations + VM Tracker instrument）、R4 逐轮 trace，并附原始 `status/rust.json` 与 jetsam 查询。
5. R2：76 条具名拒绝族与 TUN/sniffer/设备 dial 等缺口需补齐实现或由需求方收窄范围；`client-fingerprint` 近似需决定是否接受。
6. Delivery 在上述证据与 R2 缺口处理前保持未通过结论。
