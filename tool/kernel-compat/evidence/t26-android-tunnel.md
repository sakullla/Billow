# T26 Android Rust VpnService 数据面

- workflow: `2026-11-20-native-rust-kernel` / task `T26` / attempt `T26-A3`（修复复审阻断项 P1/P3；基线 `T26-A2`）
- 环境: macOS arm64；rustup 已安装 `aarch64-linux-android` target；**无 Android NDK**（`NDK_HOME`/`ANDROID_NDK_HOME` 为空，
  `~/Library/Android/sdk/ndk` 不存在）；**无 Android 设备/模拟器**。
- 结论: 数据面、宿主移交、断开/切换的停进程顺序与宿主单测已完成并在 macOS 上通过；Android 目标编译与真机双向切换**未验证**，保持待验。

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
4. `onRevoke`/`onDestroy` 先 `releaseTunnel()` 关闭 PFD 并上报 `-1`；切换/断开/重建 fd/`restart_android` 失败清理时，
   `ProfileBook::stop_android_rust_kernel` 先停旧 Rust 进程（清空待移交 fd），其 `AndroidVpn::stop` 关闭继承的 fd，
   再关闭宿主 PFD 或建立新引擎的会话；目标启动失败时清理目标并恢复 Mihomo，失败原因进入连接状态。
   撤销时系统先使 fd 失效，子进程 fd 泵读到 EOF/错误后由 CLI 以非零码退出（见 §6）。

### 2.1 应用分流保存与停止时序（T26-A3）

`takeover::set_app_rules` / `exclude_package` / `include_package` 接收 `before_replace` 回调，只在
`refresh_vpn` 确实准备 `establish`（或用失败路径关闭接管）之前触发；`ProfileBook` 在该回调里调用
`stop_android_rust_kernel`。这样：

- 有效过滤未变化时（`include` 空列表被归一为 `{only:false, packages:[]}`，与空的 `exclude` 列表等价）只持久化
  规则，不停止子进程、不重建 fd，快照保持 connected/vpn 与子进程状态一致；
- 过滤确实变化时事件顺序仍为 `stop` → `establish` → `start`（新 fd 被重新继承），失败清理路径不变。

`stop_android_rust_kernel` 现在无论 `running()` 与否都 `set_tun_fd(None)`：子进程异常退出后残留的 fd 号不会被
下一次启动继承；只有存活子进程才 `stop_kernel()`。`connect_android` 的授权拒绝分支同样先停子进程再
`vpn.close()`。

| 宿主回归用例 | 断言 |
| --- | --- |
| `android_rust_noop_app_rule_saves_keep_the_child_and_tunnel` | include/exclude 空列表互切与重复保存不改变 stop/start/establish 计数，子进程仍活、fd 未换；旧顺序下该用例失败 |
| `android_rust_changed_app_rules_stop_the_child_before_the_new_fd_is_established` | 真实变化的日志顺序 `stop` < `establish` < `start` |
| `android_rust_stop_clears_a_stale_fd_even_after_the_child_exited` | 子进程退出后 disconnect 仍清空 `tun_fd`，且不重复 stop |
| `android_rust_denied_reconnect_stops_the_child_before_closing_vpn` | 拒绝重连：子进程先停、`tun_fd` 清空、`vpn.open` 关闭、快照 !vpn/!connected |

## 3. 验证结果（macOS 宿主）

| 命令 | 结果 | 日志 |
| --- | --- | --- |
| `cargo test -p billow-kernel --features android-vpn --test android_tunnel` | 9 passed，0 failed（新增撤销可见性与失败所有权 2 例） | `t26-android-tests.log` |
| `cargo test -p billow-kernel --features android-vpn` | 全部套件通过（lib 182 passed/1 ignored、android_tunnel 9、config 43、controller 15、dns 19、groups 32、protocols 50、quic_peers 32、resources 15、sessions 11） | `t26-android-tests.log` |
| `cargo test --manifest-path native-kernel/Cargo.toml --locked`（默认 feature） | 全部通过（lib 160 passed/1 ignored，CLI 11 + family_cli 10），桌面路径不回归 | `t26-default-tests.log` |
| `cargo test -p billow-kernel --features ios-vpn --test ios_tunnel` | 6 passed，iOS 数据面不回归 | `t26-ios-regression.log` |
| `cargo test --manifest-path src-tauri/Cargo.toml --locked` | 244 passed，0 failed，10 ignored（新增 P1 回归、先停后换顺序、陈旧 fd 清理、授权拒绝顺序 4 例） | `t26-host-tests.log` |
| `python3 tool/kernel-compat/t26-android-smoke.py`（`--tun-fd` 进程入口） | UDP 回显穿过继承 fd（proto 17 / `pong`），SIGTERM 退出 0、staged 文件清理；第二个进程关闭设备侧后 CLI 退出 1 并报告 fd 失效 | `t26-cli-smoke.log` |

`tests/android_tunnel.rs` 用 `UnixDatagram` 对模拟包式 TUN fd，覆盖：

- TCP 双向（SYN/SYN-ACK、数据回显、FIN）与 fd 读写计数；
- UDP 双向与 flow 计数；
- `:53` DNS 劫持到配置的本地 resolver；
- `stop` 关闭拥有的 fd、释放 flow、可重复调用；
- `reload` 关闭旧 flow 并继续转发；
- 用户自写 `tun.enable: true`/`sniffer.enable: true` 被 staging 移除后可启动；
- 负 fd 与已关闭 fd 在启动前被拒绝；
- 设备侧关闭（撤销）后泵停止且 `stats().running` 为 false，宿主可见；
- 失败启动不关闭调用方的 fd（所有权与文档一致）。

进程入口 smoke（`tool/kernel-compat/t26-android-smoke.py`）：用 `UnixDatagram` 对模拟 TUN fd，以 `pass_fds` 把
fd 传给真实 `billow-kernel <config> --tun-fd <fd>` 子进程；子进程打印 identity 与 `tun_fd: 4`，一个发往
`127.0.0.1` echo 的 UDP 包经 fd → tunnel → DIRECT 出站 → 原路返回（proto 17、`pong`），SIGTERM 后退出 0，
`config.rust.yaml` 被清理。第二个进程关闭设备侧模拟撤销：CLI 报告 fd 不再承载报文并以退出码 1 结束。
该 smoke 验证的是打包进程路径，仍是 macOS 宿主，不等价于 Android 真机。

宿主单测（`src-tauri/src/profile.rs`）：

- `android_rust_disconnect_stops_the_kernel_before_closing_the_vpn_fd`：Android+Rust 连接后断开，进程停止、待移交 fd 清空，且停止发生在 VPN fd 关闭之前；
- `android_switch_away_from_rust_stops_the_child_before_the_vpn_fd_closes`：Rust → Mihomo 切换时旧子进程先停再重建会话；
- `android_restart_failure_stops_the_rust_child_before_closing_the_vpn_fd`：`restart_android` 重新 establish 失败时旧子进程先停、不沿用旧 fd；
- `android_rust_connect_passes_the_vpn_fd_to_the_launcher_not_yaml`：Rust 收到 fd 参数，YAML 无 `tun`/`file-descriptor`；
- `android_mihomo_connect_keeps_the_vpn_fd_in_yaml`：Mihomo 路径保持原样（`tun.enable: true` + `file-descriptor`）；
- `the_native_kernel_never_receives_the_launcher_tun_block`：Rust 无条件剥离 `tun`；
- `stopping_preserves_the_pending_tun_fd_for_the_next_launch`：`launch` 内部先 `stop`，不能丢掉本次要移交的 fd；
- `android_engine_switch_releases_the_vpn_descriptor_before_starting_the_target`：切回 Mihomo 前的描述符释放顺序；
  fd 级释放见 `stop_releases_the_fd_and_every_flow`。

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
断开/切换后旧进程是否先退出再释放 fd、撤销后 CLI 退出码与宿主连接状态、以及 Rust 目标启动失败时回退 Mihomo
与可读原因。

**未声称**：Android 真机双向切换与真实流量通过；当前仅宿主 fd 数据面与接线通过。

## 6. T26-A2：断开/切换/失 VPN 的停进程与 fd 释放

复审阻断：Android + Rust 连接后断开时，`ProfileBook::disconnect` 走 `reload(kernel, false, None)`。Rust 配置的
`tun` 块已被 `strip_tun` 移除，断开 YAML 与连接 YAML 逐字节相同，`ProcessRuntime::launch(force=false)` 命中
“已运行且 `last_requested_yaml` 相同”、`controller=None` 因此 `listeners_ready` 为真的早退；随后
`takeover::disconnect → VpnGrant::close → BillowVpnBridge.stop` 只关闭宿主自己的 `ParcelFileDescriptor`，
子进程仍以 `--tun-fd` 持有继承的 fd 继续 poll/read，直到下次强制启动/重启/退出。`restart_android` 的
`vpn.establish` 失败清理同根因。

修复（`src-tauri/src/profile.rs`）：

- 新增 `ProfileBook::stop_android_rust_kernel`：仅 Android + `Engine::Rust` + 进程存在时执行
  `set_tun_fd(None)` + `stop_kernel()`，确保待移交 fd 不会被下一次启动复用。
- 调用点：`disconnect`（Rust 不再走无意义的同配置 reload）、`switch_engine` 释放旧接管前、`connect_android`
  重建 fd 前及 establish 失败清理、`restart_android` 建立新 fd 前及失败清理、app 规则/排除列表刷新前、
  `finish_android_fd` 失败清理。Mihomo 保持 `tun.file-descriptor` 与热 reload 语义，桌面路径不变。
- 停止发生在宿主 `vpn.close()`/新 `establish()` 之前；子进程先退出并释放其 fd 副本，宿主再关闭自己的 PFD。

数据面故障宿主可见性（P2）：

- `src/android_vpn.rs` 读写线程在 EOF/POLLHUP/POLLERR/读写错误时置 `stop_flag`，`stats().running` 随之为 false；
  新增的 `a_revoked_device_fd_stops_the_pump_and_is_visible_to_the_host` 覆盖该状态。
- CLI `--tun-fd` 路径改为同时等待信号和泵状态：泵停止即输出
  `error: android-vpn: the inherited TUN fd stopped carrying packets; exiting so the host can release the VPN`
  并以退出码 1 结束（正常 SIGINT/SIGTERM 仍为 0）。宿主只采样进程存活也能看到数据面已死，不再长期保留
  “进程活着、流量不通”的状态。
- 仍存在的边界：宿主侧没有独立的 revoke 事件回调（Kotlin 只上报 fd `-1`），依赖上述子进程退出被下一轮
  状态采样发现；host 只按进程存活 + 退出详情判断，未读取 `stats()` 的 fd 计数。真机需确认采样周期内的
  连接状态与实际释放。

C ABI 失败路径所有权（P3）：

- `AndroidVpn::start_at` 在线程创建失败时不再 `close(fd)`；失败调用把 fd 留给调用方，与文档
  “successful start takes the fd / failed start leaves it with the caller” 一致，避免宿主二次 close。
  `a_failed_start_leaves_the_descriptor_open_for_the_caller` 用无效 YAML 覆盖该失败返回路径。

桌面 Rust 不接管 TUN（P3）：

- `Engine::Rust` 在所有平台都移除 `tun` 块；桌面 TUN 属 T6/Mihomo 路径。Rust 桌面会话只服务 mixed 监听器，
  快照/状态不得读作“桌面 Rust TUN 已支持”。已登记到 `native-kernel/README.md`、`tool/engine-switch.md` 与
  `tool/kernel-compat/evidence/rust-mapping.json` 的 `configFields.tun`。

新增/更新测试（本机 macOS，独立 `CARGO_TARGET_DIR`）：

- `profile::tests::android_rust_disconnect_stops_the_kernel_before_closing_the_vpn_fd`：连接后断开，断言进程已停、
  待移交 fd 清空，且停止发生在 VPN fd 关闭之前；
- `profile::tests::android_switch_away_from_rust_stops_the_child_before_the_vpn_fd_closes`：Rust → Mihomo 切换，
  旧 Rust 子进程先停再建立新 fd；
- `profile::tests::android_restart_failure_stops_the_rust_child_before_closing_the_vpn_fd`：重新 establish 失败的
  `restart_android` 清理先停旧子进程；
- `tests/android_tunnel.rs::a_revoked_device_fd_stops_the_pump_and_is_visible_to_the_host`；
- `tests/android_tunnel.rs::a_failed_start_leaves_the_descriptor_open_for_the_caller`；
- `tests/android_tunnel.rs` 既有 stop/reload/无效 fd 用例保持通过。

## 7. 已知限制

- 共享 T7 栈只实现 TCP/UDP 与 `:53` DNS 劫持，ICMP 具名丢弃，不是完整 Android 内核网络栈。
- fd 泵假设包式描述符（VpnService TUN）；若宿主给的是流式 fd，需要自行分帧。
- 进程模式依赖 `FD_CLOEXEC` 已被清除；同进程嵌入调用 `billow_android_vpn_start` 时也应保证 fd 可移交（或直接传拥有的 fd）。
- 宿主侧 revoke 事件未直接驱动停进程：依赖子进程在 fd 失效后退出（CLI 非零）被状态采样发现；后续设备验证需确认
  采样延迟内不会显示为已连接。
- 桌面 Rust 引擎不接管 TUN；桌面 Rust 会话只有 mixed 监听器。
