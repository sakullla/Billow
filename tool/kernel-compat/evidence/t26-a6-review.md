# T26-A6 复核：Android VpnService 数据面在当前 HEAD 的回归检查

- workflow: `2026-11-20-native-rust-kernel` / task `T26` / attempt `T26-A6`
- 基线: `1863156`（T7-A4、T31-A6 之后）
- 日期: 2026-11-25
- 环境: macOS arm64；rustup 已装 `aarch64-linux-android` target；**无 Android NDK**
  （`NDK_HOME`/`ANDROID_NDK_HOME` 为空，`~/Library/Android/sdk/ndk` 不存在），无 `adb`/emulator。
- 结论: T30/T31 未改动 `android_vpn.rs`、Android 宿主移交或 VpnService Kotlin；当前 HEAD 的
  `--tun-fd` 进程路径与 `billow_android_vpn_*` ABI 仍由宿主单测/进程 smoke 覆盖并通过。
  **Android 目标编译与真机流量仍不可验证**（缺 NDK/设备），不将宿主结果当作 Android 验证。

## 1. 复核范围与结论

| 关注点 | 结论 | 依据 |
| --- | --- | --- |
| T31 `tunnel/udp.rs` 新增 Hysteria2 | 不破坏 Android TUN：`Transport::Hysteria2` 与既有 ss/trojan/ssr/masque/shadowquic 走同一 `association_task`；TUN 的 UDP 入队、回复映射和 fd 泵未变。Hysteria2 在 `supported` 中按 `Protocol::Hysteria2` 具名允许，`dialer-proxy` 在关联期按 `DialError::Chain` 具名拒绝。 | `native-kernel/crates/billow-kernel/src/tunnel/udp.rs`；`tests/android_tunnel.rs::udp_datagrams_cross_the_fd_in_both_directions` |
| T27/T30 的 SOCKS5 TUN UDP / anytls·vless mixed UDP | SOCKS5 TUN 关联未回归；anytls/vless 仍只在 mixed 路径，`tunnel/udp.rs` 对无 TUN transport 的族继续按名拒绝（`note_udp_unsupported`）。 | `cargo test -p billow-kernel --features ios-vpn --test ios_tunnel`（含 `socks5_udp_datagrams_cross_the_tunnel_in_both_directions`） |
| `Proxy::udp_enabled()` 变化 | 只影响 controller 展示与加载期 `validate_udp_chains`；TUN UDP 的支持判定仍是 `tunnel/udp.rs` 的独立 match，未被 `udp_enabled()` 绕过。 | `native-kernel/crates/billow-kernel/src/proxies.rs:1366,1571`；`src/tunnel/udp.rs:144` |
| T7 stats 透传 vs T26 stats ABI | 不冲突：T7 的 `ProviderStatus.stats` 走 iOS 扩展应答（`IosStatus.stats`），Android 侧 `billow_android_vpn_stats` 是独立 C ABI JSON；当前 Kotlin/Swift/TS 无 `billow_android_vpn_stats` 消费者，字段名也未与 `IosStats` 互斥。 | `src-tauri/src/ios_vpn.rs`；`src/android_vpn.rs:stats_json`；全仓 grep 无 Android stats 消费者 |
| 宿主移交顺序 | 未变：仅 `(Android, Rust)` 传 `--tun-fd`；断开/切换/重建 fd/启动失败/应用分流变化均先 `stop_android_rust_kernel`（清 `tun_fd` 并停子进程）再关闭/替换宿主 PFD；陈旧 fd 不进入下一进程。 | `src-tauri/src/profile.rs:1322-1340,1811-1822,2954-2970,3079,3329-3376,3690-3705`；`BillowVpnService.kt:92-99` |
| 自上次 T26 证据后的改动 | T30/T31 仅动 `tunnel/udp.rs`、`outbound/*`、`proxies.rs`、测试/证据；`android_vpn.rs`、`tunnel/mod.rs`/`stage.rs`、Android 宿主移交与 Kotlin 在 T26-A5（`c6d6634`）之后未再改动。 | `git log c6d6634..HEAD -- <相关路径>`；`git diff --stat c6d6634..HEAD -- <相关路径>` 为空 |

## 2. 本轮复跑（HEAD `1863156`，macOS arm64）

| 命令 | 结果 |
| --- | --- |
| `cargo test -p billow-kernel --features android-vpn` | lib 213 passed/1 ignored；`android_tunnel` 9 passed；config 53、controller 15、dns 19、groups 32、protocols 60/2 ignored、quic_peers 33、resources 15/1、sessions 11、shadowquic 1；其余需 pinned 对端的套件按 `#[ignore]` 跳过。无挂起。 |
| `cargo test -p billow-kernel --features android-vpn --test android_tunnel` | 9 passed，0 failed（TCP/UDP/DNS、stop/reload、staging、无效 fd、撤销可见性、失败启动所有权）。 |
| `cargo test -p billow-kernel --features android-vpn --lib android_vpn` | 2 passed（stats 无隧道、null home + 幂等 stop）。 |
| `cargo test -p billow-kernel`（默认 feature） | 全套件通过：lib 191/1、config 53、controller 15、dns 19、groups 32、protocols 60/2、quic_peers 33、resources 15/1、sessions 11、shadowquic 1 等。 |
| `cargo test -p billow-kernel --features ios-vpn --test ios_tunnel` | 8 passed，0 failed（共享 TUN 数据面在 T31 后不回归，含 SOCKS5 UDP）。 |
| `cargo check -p billow-kernel-cli --features android-vpn` | 通过（`--tun-fd` CLI 入口编译）。 |
| `cargo test --manifest-path src-tauri/Cargo.toml --locked` | 250 passed，0 failed，10 ignored。`android_*` 过滤 22 passed，覆盖 `--tun-fd` 参数、先停后关 fd、陈旧 fd、应用分流顺序、Mihomo fd-in-YAML。 |
| `bash tool/ios/verify-app-group.sh` | `ok: one version validates for mihomo and rust; later prepares preserve both`。 |
| `node --check tool/prepare_android_{rust_kernel,kernel,geo}.mjs` | 三个 Android 资源/内核准备脚本语法通过（真正构建仍需 NDK/网络）。 |
| `cargo build -p billow-kernel-cli --features android-vpn` + `python3 tool/kernel-compat/t26-android-smoke.py` | `ok: true`：UDP 回显穿继承 fd（proto 17/`pong`），SIGTERM 退出 0 且清理 `config.rust.yaml`；第二个进程设备侧关闭后 CLI 退出 1 并报告 `the inherited TUN fd stopped carrying packets`。 |
| `cargo check -p billow-kernel --features android-vpn --target aarch64-linux-android` | **失败（环境）**：`cc-rs` 找不到 `aarch64-linux-android-clang`；与 `t29-a3-android-check.log` 相同。 |

注：`cargo test -p billow-kernel` 需在 `native-kernel/` 下运行；`src-tauri` 测试使用仓库根目录的 manifest 路径。
本轮未改动产品代码。

## 3. 未验证边界与补证入口

- **Android 目标编译/打包未验证**：需要 NDK（`aarch64-linux-android21-clang`/`llvm-ar`）。补证命令：
  ```bash
  NDK_HOME=<ndk> node tool/prepare_android_rust_kernel.mjs --force
  # 或直接：
  NDK_HOME=<ndk> ANDROID_NDK_HOME=<ndk> \
    cargo build --release --locked -p billow-kernel-cli --features android-vpn \
      --target aarch64-linux-android --manifest-path native-kernel/Cargo.toml
  ```
  成功标志：生成 ELF 并落到 `src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/libbillow_kernel.so`。
- **真机 VpnService 双向切换未验证**：需要 `adb` + 已安装 APK + 授权。入口按
  `tool/engine-switch.md` 与 `tool/kernel-compat/evidence/t29-platform-matrix.md` §3：
  建立 VPN 后确认子进程参数含 `--tun-fd <fd>`、`logcat` 无 fd 失效错误、设备流量经代理、
  `onRevoke`/断开后子进程退出且宿主快照回到断开；Android 端 stats 只能在 in-process C ABI 或
  后续 JNI/桥接接入时读取（当前 CLI 仅在退出时打印汇总）。
- **Hysteria2 的 TUN 端到端**：本轮只验证共享 transport 与 mixed 侧既有 pinned 用例不被 Android 改动影响；
  没有 TUN+Hysteria2 的设备/对端用例，故该组合仍属“共享代码已接入、未单独实测”。
- **`billow_android_vpn_stats` 暂无宿主消费者**：Kotlin/Swift/TS 均未调用该 ABI，Android 侧目前只能从
  CLI 退出汇总或宿主既有的进程/controller 采样获得统计。与 T7 的 iOS `ProviderStatus.stats` 无冲突，
  但若 UI 需要 Android 实时计数，还需要 JNI/桥接接入（独立工作，不属本轮复核）。
- **P3（未修，遵守“无回归不改产品代码”）**：`android_vpn.rs::peak_rss_bytes` 只在
  `target_os = "linux"` 时把 `ru_maxrss` 从 KiB 转成字节；Android 的 `target_os = "android"` 会落入
  原样返回分支，`peakRssBytes` 在 Android 上会小 1024 倍。同仓 `controller.rs::rss_bytes` 已按
  `macos`/其它 unix 正确区分。最小修法：把该分支条件改为
  `#[cfg(any(target_os = "linux", target_os = "android"))]`。该问题非 T30/T31 引入，未在复核中改动。
- 证据沿用：`tool/kernel-compat/evidence/t26-android-tunnel.{json,md}`（数据面/宿主链路）、
  `t29-a3-android-check.log`（NDK 缺失）、`t29-platform-matrix.md`（Android blocked 状态）。
