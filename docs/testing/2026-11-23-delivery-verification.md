# 交付核验报告：五平台行为与完整基准（T8）

- 日期：2026-11-23
- Workflow：`2026-11-20-native-rust-kernel` / Task T8 / Attempt T8-A1
- 候选：工作树（含 T7-A3 修改），基线 `2b89bf36658ba1bbb3666e78d1eae7fb9719c292`
- 环境：macOS arm64；Xcode 27.2 / iOS 27.2 SDK；rustc 1.98.1；Node 26.13.0；Go 1.26.2
- 对照基准：随包 Mihomo **v1.19.34**（`Mihomo Meta v1.19.34 darwin arm64 with go1.26.11`，二进制 `tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7`，SHA-256 `a55a9073…033f34`）；桌面清单 `src-tauri/desktop-kernel.json`，Android 清单 `src-tauri/android-kernel.json`（commit `0455d0d…`）
- 候选内核：`billow-kernel 0.1.0`，release 构建 SHA-256 `6e708345…9ea392`

机器可读汇总：[`tool/kernel-compat/evidence/t8-delivery.json`](../../tool/kernel-compat/evidence/t8-delivery.json)。

## 结论（先给判定）

**当前候选不得出具交付通过结论。**

| 需求 | 结论 | 原因摘要 |
| --- | --- | --- |
| **R1** 各平台双向切换 | **未通过（未完成验证）** | 仅 macOS 有 T6 历史实跑；当前候选的打包切换测试在正向标记断言后因负例过时失败。Windows/Linux/Android 未实跑，iOS 无真机双向流量。 |
| **R2** 完整兼容随附 Mihomo 有效配置 | **未通过（已覆盖子集通过）** | 当前候选在 macOS 上 T22/T23/T24/T25/T5、选项矩阵与 66 个真实对端用例全部通过；但仍存在具名拒绝/降级的有效配置（TUN、sniffer、设备族 dial、masque/shadowquic/mieru/sudoku/QUIC/SS 选项等），且其他平台没有运行证据。 |
| **R3** iOS 扩展峰值 ≤ 40,000,000 字节 | **未验证** | 物理 iPhone 未连接，没有任何 `phys_footprint` 真机峰值；模拟器 smoke 的 `peakRssBytes=28,475,392` 是 smoke 进程读数，不能作为 R3 依据。 |
| **R4** 重复使用后资源可回收、基线稳定 | **未验证** | 无真机逐轮建连/重载/断网重连基线与失效对象检查。 |

按 T8 recipe：“缺基准、设备或关键记录不得出具通过结论”。本报告中的“通过”只适用于表内明确写出的已执行子项，不代表 R1–R4 任一需求整体通过。

## 1. 五平台构建与运行可达性

| 平台 | 构建/运行核验 | 结果 | 证据 |
| --- | --- | --- | --- |
| macOS arm64 | release 内核构建、前端构建、`src-tauri` 默认测试、打包双引擎切换测试 | 内核/前端/默认测试通过；**打包切换测试失败**（负例过时） | `t8-build.log`、`t8-npm-build.log`、`t8-srctauri-tests.log`、`t8-macos-switch.log` |
| Windows x86_64 | `cargo check --target x86_64-pc-windows-msvc -p billow-kernel-cli` | **失败**：`ring` 的 C 编译找不到 MSVC 头（`assert.h`），本机没有 `cl.exe`/Windows SDK；未实跑 | `t8-cross-windows.log` |
| Linux x86_64 | `cargo check --target x86_64-unknown-linux-gnu -p billow-kernel-cli` | **失败**：找不到 `x86_64-linux-gnu-gcc`；未实跑 | `t8-cross-linux.log` |
| Android arm64 | `cargo check --target aarch64-linux-android -p billow-kernel-cli` | **失败**：找不到 `aarch64-linux-android-clang`（无 `ANDROID_HOME`/NDK）；未实跑；Rust 内核未接入 VpnService TUN 数据面（T6 当时切换被具名拒绝并恢复 Mihomo，当前候选未复验） | `t8-cross-android.log` |
| iOS（模拟器/设备构建） | 宿主真实源集 typecheck、App Group smoke、`BillowRust`/`BillowMihomo` 模拟器与设备 unsigned 构建、C ABI smoke | 构建与模拟器 smoke **通过**；完整宿主 `billow_iOS` 被 Tauri 预构建阻塞；无签名安装/真机流量 | `t8-ios-*.log` |

补充：

- `xcrun devicectl list devices` 显示物理 **iPhone 15 Pro Max（00008130-000E65482883401C）为 `unavailable`**；模拟器 iPhone 18 Pro（iOS 27.0）已启动。原始输出：`t8-devicectl.log`。
- 设备版 `BillowRust` 第一次 `xcodebuild` 失败，是因为上一次模拟器构建把 `build/rust-kernel/linked.xcconfig` 留成 simulator archive；`Resolve Rust kernel` 阶段在本次构建中把它改回 device 路径，重跑后 `BUILD SUCCEEDED`。复现设备构建时应先运行 `tool/ios/build.sh`/resolve 阶段刷新 xcconfig（或连续执行两次），本次记录的是修正后的成功日志。
- 完整宿主 `billow_iOS` 的 `xcodebuild` 仍在 Tauri 预构建阶段失败：缺少 `src-tauri/gen/apple/.tauri/cli-options-server.json`（只有运行中的 `tauri ios dev/build` 会生成）。

## 2. 可复跑证据（本次在同一候选上重跑）

公共参数：`--mihomo tool/kernel-compat/.cache/baseline/mihomo-a55a9073f9b7 --rust <独立 CARGO_TARGET_DIR>/release/billow-kernel`。所有命令均在仓库根执行；Rust 构建使用独立 `CARGO_TARGET_DIR`，不占用共享 target。

| # | 命令/入口 | 结果 | 原始证据 |
| --- | --- | --- | --- |
| 1 | `cargo test --manifest-path native-kernel/Cargo.toml --locked` | **400 passed / 0 failed / 92 ignored**（19 个 test binary） | `t8-default-tests.log` |
| 2 | `cargo test --manifest-path native-kernel/Cargo.toml --locked -p billow-kernel --features ios-vpn` | **417 passed / 0 failed / 91 ignored**（17 个 test binary） | `t8-ios-tests.log` |
| 3 | `node tool/kernel-compat/t22-differential.mjs … --mmdb-dir <解压后的 Country.mmdb/ASN.mmdb>` | **23 cases：22 pass + 1 known difference，0 unexpected，exit 0** | `t8-t22-dns.json`、`t8-t22.log` |
| 4 | `node tool/kernel-compat/t23-differential.mjs …` | **28/28 pass**（27 cases + persistence），0 differ，exit 0 | `t8-t23-differential.json`、`t8-t23.log` |
| 5 | `node tool/kernel-compat/t24-differential.mjs … --mmdb-dir …` | **38/38 pass**，0 differ，0 skipped，exit 0（4 个 framing difference 已归一化） | `t8-t24-differential.json`、`t8-t24.log` |
| 6 | `node tool/kernel-compat/t25-differential.mjs …` | **49 cases：47 equal + 2 recorded divergences，0 unexpected，exit 0** | `t8-t25-differential.json`、`t8-t25.log` |
| 7 | `node tool/kernel-compat/t5-differential.mjs … --effective-dir tool/kernel-compat/evidence/t8-t5-effective` | **12/12 scenarios pass，0 differ，exit 0**；Billow 桌面/Android reduced 产物可加载，仅启用 `sniffer` 被具名拒绝 | `t8-t5-integration.json`、`t8-t5.log`、`t8-t5-effective/` |
| 8 | `node tool/kernel-compat/option-probe.mjs …` | **287 no-op / 304 enabled，problems 0，exit 0** | `t8-option-matrix.txt`、`t8-option-probe.log` |
| 9 | `KC_MIHOMO_BIN=<pinned> tool/kernel-compat/peer-tests.sh`（独立 target） | **66/66 pass，exit 0** | `t8-peer-tests.log` |
| 10 | `node --test tool/kernel-compat/runner.test.mjs` | **10/10 pass，exit 0** | `t8-runner.log` |
| 11 | `npm test` / `npm run build` | **342 tests / 27 files pass**；type-check + Vite build 通过 | `t8-npm-test.log`、`t8-npm-build.log` |
| 12 | `tool/ios/verify-host-sources.sh` | **通过**（宿主、BillowMihomo、BillowRust、`main.mm` 全部按各自条件 typecheck） | `t8-ios-host-typecheck.log` |
| 13 | `tool/ios/verify-app-group.sh` | **通过**（同一版本同时保留 mihomo/rust manifest） | `t8-ios-app-group.log` |
| 14 | `tool/ios/verify-rust-kernel.sh` | **PASS 20/20**；模拟器 smoke 进程 `peakRssBytes=28475392`（非 R3） | `t8-ios-simulator-smoke.log` |
| 15 | `xcodebuild`：BillowRust / BillowMihomo，simulator debug + device release，`CODE_SIGNING_ALLOWED=NO` | 全部 **BUILD SUCCEEDED** | `t8-ios-xcodebuild-*.log` |
| 16 | `cargo test --manifest-path src-tauri/Cargo.toml --locked` | **234 passed / 0 failed / 10 ignored** | `t8-srctauri-tests.log` |
| 17 | `BILLOW_TEST_RESOURCES=<当前候选 runtime> cargo test … packaged_engines_switch_both_ways_with_a_marked_request -- --ignored` | **PASSED（1 passed）**（交付复审后返修：负例改用仍被具名拒绝的 `sniffer.enable: true`；正向 `mihomo-1/rust-1/mihomo-2` 与拒绝后 `mihomo-3` 均通过） | `t8-macos-switch.log`（原始红）、`t8-macos-switch-rework.log`（返修后绿） |

注：`t8-*` 文件位于 `tool/kernel-compat/evidence/`。差分脚本的完整命令形式见 `tool/kernel-compat/README.md`；本次实际使用的 pinned 二进制与候选二进制路径记录在对应 JSON 的 `mihomo`/`rust` 字段。T9 记录过 306 passed / 91 ignored；当前树已包含 `controller`/`dns`/`groups`/`resources` 等测试二进制，本次 **400 passed / 92 ignored** 是当前候选的准确计数。

## 3. 差分覆盖说明（R2 已覆盖子集）

- **T22 DNS/hosts/fake-ip**：23 例。22 例与 pinned 完全一致；1 例 `fallback-geoip-code-mmdb-negated` 是已登记的 `known-difference`（pinned mmdb 路径对 `!au` 的二次取反导致回退，内核保留取反语义），不是未记录偏差。
- **T23 策略组/选择/健康检查**：27 例 + selection cache 持久化，28/28 通过；包含 startup/lazy probing、url-test 计算缓存、嵌套组懒重探、provider 快照、空 fallback 阻断、dialer-proxy 探测。
- **T24 规则/provider/GEO-MRS**：38/38 通过，含全部规则族、五类 rule-provider 载体/格式、GeoSite/GeoIP `.dat`、MRS、MaxMind Country/ASN、`MATCH` 与 uppercase `GEOSITE,CN`。
- **T25 控制接口**：49 例，47 例与 pinned 相等；2 例已登记差异：重载时监听器迁移、`PATCH /configs {"tun":{"enable":true}}`。另有 `/configs/geo`、`/upgrade/geo`、`/group`、`/cache`、`/storage`、`/dns/query`、`/restart` 为显式 404，`/rules` 无 pinned 的 extra 命中计数，TLS 只提供 HTTP/1.1 ALPN。
- **T5 组合差分**：12/12 场景通过；同一 YAML 覆盖 fake-ip DNS、hosts、多载体 rule-provider、proxy-provider、select/url-test/fallback 组、controller、ss/trojan/ssr/shadowquic 真实出口，并核对每条请求的 `rule=`/`outbound=`。Billow effective 产物中仅启用 `sniffer` 是剩余具名拒绝；移除后桌面和 Android 产物都能 `--check` 并注册策略组。
- **选项矩阵**：287 个 no-op 形式双方接受，304 个 enabled 形式由内核具名拒绝，problems 0。
- **真实对端矩阵**：66/66（覆盖 TCP/UDP、认证失败与边界；含 QUIC、shadowquic、设备/mesh 协议层、sudoku、mieru、ssr 等）。设备族（wireguard/openvpn/tailscale/zerotier/easytier）仍只验证协议层，`dial()` 需要 T6/T7 的用户态 IP 栈/TUN。

### R2 仍未达成的有效配置（具名缺口，非静默忽略）

- 桌面启用 `tun`、启用 `sniffer`；iOS staging 会移除 `sniffer.enable: true`（域名规则退化为目标 IP/DNS 结果）。
- 设备族 `wireguard`/`openvpn`/`tailscale`/`zerotier`/`easytier` 的 `dial()` 仍依赖 T6/T7 的设备层。
- `masque` 的 h2/h3-l4proxy/gVisor 形态；`shadowquic` 的 `zero-rtt`/QUIC v2/Brutal；`mieru` 的 UDP/mux/traffic-pattern；`sudoku` 的 HTTP tunnel/UoT。
- `vless`/`anytls`/`snell` 的 `udp: true`、`vmess` 的 `alterId>0`/grpc/xhttp、`ss` plugin、`trusttunnel` quic、`hysteria2` up/ports、`hysteria` v1 port hopping/XPlus/faketcp/wechat/UDP、`tuic` v4/UDP。
- DNS 的 DoQ/system/dhcp/overlay DNS、`#proxy`、respect-rules UDP、h3、ECS；`PROCESS-*` 进程查找；LAN auth 注入；UDP SOCKS5 关联不单独出现在 `/connections`。
- Windows 的 `external-controller-pipe`/`routing-mark` 等平台项为具名拒绝。

完整状态见 [`rust-mapping.json`](../../tool/kernel-compat/evidence/rust-mapping.json) 与 `tool/kernel-compat/README.md`；本次未把“加载通过”等同于兼容通过。

## 4. macOS 双向切换复跑细节

T6 的历史实跑（`tool/engine-switch.md`、`task-runs/T6-run.md`）在 macOS 上通过：真实 Mihomo/`billow-kernel` 进程，标记 `mihomo-1 → rust-1 → mihomo-2`，拒绝配置保留 `mihomo-3`。

本次用**当前候选**的 `billow-kernel` 替换临时 runtime 后复跑同一 ignored 测试：

- 测试执行到 `src-tauri/src/profile.rs:6381` 才 panic，说明此前的 `mihomo-1 → rust-1 → mihomo-2` 三条标记断言均已通过；
- 失败点在负例：测试仍用含 `proxy-groups` 的配置期望 Rust 拒绝并保留 Mihomo，但 T23 后 Rust 已接受 `proxy-groups`（快照显示切换成功，`engine=rust`、`running_engine=rust`、`engine_identity` 存在）；
- 因此该测试当前是**红**的，不能作为“当前候选 macOS 双向切换通过”的证据。建议后续任务把负例改为当前仍被具名拒绝的配置（例如启用 `sniffer`）后重跑。归属：T6/后续任务，不在 T8 静默修改。

## 5. iOS 真机与扩展（R1/R3/R4）

已执行（模拟器/构建层）：

- 宿主真实源集 typecheck（`BILLOW_ENGINE_HOST`）通过；两个扩展各自类型检查通过；`src-tauri` 的 7 个 `ios_vpn` 桥接测试通过（`t8-ios-vpn-host-tests.log`）。
- `BillowRust`/`BillowMihomo` 模拟器 debug 与设备 release unsigned 构建均成功；内核 archive 重新从当前源码构建（`t8-ios-build.log`、`t8-ios-build-device.log`）。
- 模拟器 C ABI smoke 20/20：版本、stats、start/stop/reload、设备 UDP → DIRECT → 宿主 echo → `port->write` 回包。

未执行（缺设备/签名）：

- iPhone 真机安装、两个扩展各自建立系统 VPN、从其他应用发起命中代理规则的请求并核对出口（R1 iOS 双向）。
- 任何扩展进程 `phys_footprint` 峰值与六类 R3 场景；任何 R4 逐轮空闲基线与失效对象检查。
- 完整 `billow_iOS` 宿主包与真实 `npx tauri ios build`（无 Team；且 Tauri 预构建仍阻塞 plain xcodebuild）。

入口与场景表见 [`2026-11-23-ios-rust-extension-memory.md`](2026-11-23-ios-rust-extension-memory.md) 与 `tool/ios/verify-device.md`。

## 6. 本轮修正

- 修正 T7 证据中的 ignored 计数：`tool/kernel-compat/evidence/t7-ios-ffi.md` 与 `t7-ios-a3.json` 中 `cargo test -p billow-kernel --features ios-vpn` 的 **1 ignored** 改为本次复跑的 **91 ignored**（417 passed / 91 ignored，17 个 test binary）。`--lib` 单跑仍为 192 passed / 1 ignored，未改。
- 交付复审后返修 macOS 打包双向切换测试：负例不再使用 T23 已支持的 `proxy-groups`，改用仍被具名拒绝的 `sniffer.enable: true`；`tool/engine-switch.md` 同步更新。返修后 `packaged_engines_switch_both_ways_with_a_marked_request` 为 **1 passed**（`t8-macos-switch-rework.log`）。

## 7. 交付前必须补齐

1. ~~更新并重跑 macOS 打包双引擎切换测试的负例~~（已返修：`sniffer.enable` 负例，macOS 1 passed）。
2. 在 Windows/Linux/Android 宿主实跑打包后的双向切换与标记流量；Android 需先补齐 Rust 内核的 VpnService TUN 路径。
3. 物理 iPhone 上完成 iOS 双向切换、R3 六类峰值、R4 逐轮回收，并附原始 trace/status JSON。
4. R2 仍有多项 pinned Mihomo 接受而 Rust 具名拒绝的有效配置（见选项矩阵与 rust-mapping），需补齐实现或由需求方收窄范围。
5. Delivery 在以上证据与 R2 缺口处理前保持未通过结论。
