# T26 Android Rust VpnService 数据面

- workflow: `2026-11-20-native-rust-kernel` / task `T26` / attempt `T26-A1`
- 环境: macOS arm64；rustup 已安装 `aarch64-linux-android` target；**无 Android NDK**（`NDK_HOME`/`ANDROID_NDK_HOME` 为空，
  `~/Library/Android/sdk/ndk` 不存在）；**无 Android 设备/模拟器**。
- 结论: 数据面、宿主移交与宿主单测已完成并在 macOS 上通过；Android 目标编译与真机双向切换**未验证**，保持待验。

## 1. 数据面通用化

`tunnel/` 从 iOS 专用改为共享设备数据面：

| feature | 内容 |
| --- | --- |
| `device-vpn` | `src/tunnel/` 用户态 IPv4/IPv6 + TCP/UDP/DNS 栈（原 T7 实现） |
| `ios-vpn` | `device-vpn` + `src/ios_vpn.rs` 的 `billow_ios_vpn_*` C ABI |
| `android-vpn` | `device-vpn` + `src/android_vpn.rs` 的 fd 泵与 `billow_android_vpn_*` ABI |

`config.rs` 对 `tun`/`file-descriptor` 的边界不变（到达加载器仍具名拒绝）；设备入口不再把它交给加载器：

- 共享的 `tunnel/stage.rs`（从 `ios_vpn.rs` 抽出）删除 `tun.enable: true` 与 `sniffer.enable: true`，并重写
  `rule-providers`/`proxy-providers` 的外部路径；
- Android 的 TUN fd 由宿主作为启动参数 `--tun-fd <fd>` 传入，不作为 YAML 键；
- `src-tauri/src/profile.rs` 对 `Engine::Rust` 在所有平台都删除 `tun` 块（包括用户自写块），
  Mihomo 仍走 `force_tun(..., file-descriptor)`。

### `src/android_vpn.rs`

- `AndroidVpn::start(fd, yaml, base_dir, options)`：先 staging，再 `Tunnel::start_at`；成功即**拥有 fd**。
- 读线程：`poll(fd)` + `libc::read`，把整包交给 `Tunnel::ingest`（TCP 被动打开、UDP 关联、`:53` DNS 劫持、规则/组/出站）。
- 写线程：`Tunnel` 的 `PacketSink` 写入有界 `sync_channel`（默认 256），写线程按 `poll(POLLOUT)` 写回 fd；满队列计为
  `fdDropped`，不会无界增长。
- `stop()`/`Drop`：置停止位 → join 读写线程 → `Tunnel::stop`（关闭全部 flow/association）→ `close(fd)`。可重复调用。
- `stats()` 返回 `TunnelStats` + fd 计数（reads/written/dropped/errors）+ `running`。
- C ABI：`billow_android_vpn_start(fd, home, error)`、`stop`、`reload`（重新 staging `home/config.yaml` 后 reload）、
  `stats`、`free_error`。`start` 同样接管 fd。

### CLI 与打包

- `billow-kernel-cli` 新增 `--features android-vpn` 与 `--tun-fd <FD>`；带 `--tun-fd` 时运行 `AndroidVpn`，
  打印 engine identity 后等待 SIGINT/SIGTERM，退出前停止并删除 `config.rust.yaml`。
- `tool/prepare_android_rust_kernel.mjs` 以 `--features android-vpn` 构建，并把 feature 纳入缓存 key。
- 桌面不启用该 feature，默认构建与行为不变。

## 2. 宿主移交

链路：

1. `BillowVpnService.establishTun` 建立 `ParcelFileDescriptor`，`fcntl(F_SETFD, 0)` 清除 `FD_CLOEXEC`，
   使子进程（Rust kernel）可继承；
2. `BillowVpnBridge.nativeTunFd(fd)` 把 fd 交给宿主 `takeover::report_vpn_fd`；
3. `profile.rs` 对 Rust 只保存该 fd 到 `ProcessRuntime::tun_fd`，启动 Rust 时追加 `--tun-fd <fd>`；
   新的 VpnService fd 会强制重启 Rust 进程（即使 fd 号复用、YAML 未变，旧进程也不能沿用旧 fd）；
   对 Mihomo 仍由 `force_tun` 写入 `tun.file-descriptor`；
4. `onRevoke`/`onDestroy` 先 `releaseTunnel()` 关闭 PFD 并上报 `-1`；切换/断开时先停旧 Rust 进程，
   其 `AndroidVpn::stop` 关闭继承的 fd，再建立新引擎的会话；目标启动失败时清理目标并恢复 Mihomo，
   失败原因进入连接状态。

## 3. 验证结果（macOS 宿主）

| 命令 | 结果 | 日志 |
| --- | --- | --- |
| `cargo test -p billow-kernel --features android-vpn --test android_tunnel` | 7 passed，0 failed | `t26-android-tests.log` |
| `cargo test -p billow-kernel --features android-vpn` | 全部套件通过（lib 182 passed/1 ignored 等） | `t26-android-tests.log` |
| `cargo test --manifest-path native-kernel/Cargo.toml --locked`（默认 feature） | 全部通过（含 CLI 11 + family_cli 10），桌面路径不回归 | `t26-default-tests.log` |
| `cargo test -p billow-kernel --features ios-vpn --test ios_tunnel` | 6 passed，iOS 数据面不回归 | `t26-ios-regression.log` |
| `cargo test --manifest-path src-tauri/Cargo.toml --locked` | 237 passed，0 failed，10 ignored | `t26-host-tests.log` |
| `python3 tool/kernel-compat/t26-android-smoke.py`（`--tun-fd` 进程入口） | UDP 回显穿过继承 fd（proto 17 / `pong`），打印 identity，SIGTERM 退出 0，staged 文件清理 | `t26-cli-smoke.log` |

`tests/android_tunnel.rs` 用 `UnixDatagram` 对模拟包式 TUN fd，覆盖：

- TCP 双向（SYN/SYN-ACK、数据回显、FIN）与 fd 读写计数；
- UDP 双向与 flow 计数；
- `:53` DNS 劫持到配置的本地 resolver；
- `stop` 关闭拥有的 fd、释放 flow、可重复调用；
- `reload` 关闭旧 flow 并继续转发；
- 用户自写 `tun.enable: true`/`sniffer.enable: true` 被 staging 移除后可启动；
- 负 fd 与已关闭 fd 在启动前被拒绝。

进程入口 smoke（`tool/kernel-compat/t26-android-smoke.py`）：用 `UnixDatagram` 对模拟 TUN fd，以 `pass_fds` 把
fd 传给真实 `billow-kernel <config> --tun-fd <fd>` 子进程；子进程打印 identity 与 `tun_fd: 4`，一个发往
`127.0.0.1` echo 的 UDP 包经 fd → tunnel → DIRECT 出站 → 原路返回（proto 17、`pong`），SIGTERM 后退出 0，
`config.rust.yaml` 被清理。该 smoke 验证的是打包进程路径，仍是 macOS 宿主，不等价于 Android 真机。

宿主单测（`src-tauri/src/profile.rs`）：

- `android_rust_connect_passes_the_vpn_fd_to_the_launcher_not_yaml`：Rust 收到 fd 参数，YAML 无 `tun`/`file-descriptor`；
- `android_mihomo_connect_keeps_the_vpn_fd_in_yaml`：Mihomo 路径保持原样（`tun.enable: true` + `file-descriptor`）；
- `the_native_kernel_never_receives_the_launcher_tun_block`：Rust 无条件剥离 `tun`；
- `stopping_preserves_the_pending_tun_fd_for_the_next_launch`：`launch` 内部先 `stop`，不能丢掉本次要移交的 fd；
- 既有的 `android_engine_switch_releases_the_vpn_descriptor_before_starting_the_target` 继续覆盖切回 Mihomo
  前的描述符释放顺序；fd 级释放见 `stop_releases_the_fd_and_every_flow`。

## 4. Android 目标编译（失败，环境原因）

```bash
CARGO_TARGET_DIR=<tmp>/t26-android-target \
  cargo build --release --locked --manifest-path native-kernel/Cargo.toml \
  -p billow-kernel-cli --features android-vpn --target aarch64-linux-android
```

结果：失败（退出非 0）。

```text
error: failed to run custom build command for `ring v0.17.14`
  cargo:warning=Compiler family detection failed due to error: ToolNotFound:
  failed to find tool "aarch64-linux-android-clang": No such file or directory (os error 2)
error occurred in cc-rs: failed to find tool "aarch64-linux-android-clang": No such file or directory (os error 2)
```

完整命令、环境探测与错误见 `t26-cross-android.log`。安装 NDK 并设置 `NDK_HOME` 后应重跑同一命令；
本环境不伪造“编译通过”。Android APK/Kotlin 同样未编译（无 Android SDK）；Kotlin 改动仅为
`releaseTunnel()`/`onRevoke` 复用与注释，未做编译器验证。

## 5. 真机待验

真机入口：安装 APK → 授予 VpnService 授权 → 设置页选择 Rust → 连接/断开/切回 Mihomo/再切回 Rust。
必须记录：设备与 Android 版本、APK 构建、两个引擎的 identity/instance/PID、带标记的 TCP/UDP/DNS 流量、
断开/撤销后的 fd 与 flow 释放、以及 Rust 目标启动失败时回退 Mihomo 与可读原因。

**未声称**：Android 真机双向切换与真实流量通过；当前仅宿主 fd 数据面与接线通过。

## 6. 已知限制

- 共享 T7 栈只实现 TCP/UDP 与 `:53` DNS 劫持，ICMP 具名丢弃，不是完整 Android 内核网络栈。
- fd 泵假设包式描述符（VpnService TUN）；若宿主给的是流式 fd，需要自行分帧。
- 进程模式依赖 `FD_CLOEXEC` 已被清除；同进程嵌入调用 `billow_android_vpn_start` 时也应保证 fd 可移交（或直接传拥有的 fd）。
