# 双内核切换验证入口

Billow 在同一安装包中分发 Mihomo 与自研 Rust 内核（`billow-kernel`）。设置页和托盘通过
`set_kernel_engine` 串行切换：预备并校验目标配置 → 释放旧实例的系统代理/TUN/VPN 描述符 →
启动目标 → 按实例身份与监听器确认 → 失败时清理目标并恢复旧引擎，恢复失败则撤销接管并显示原因。

## 构建随包内核

- 桌面（当前宿主）：`node tool/prepare_runtime.mjs --desktop`
  - 下载/校验随附 Mihomo，并 `cargo build --release --locked -p billow-kernel-cli --target <triple>`。
  - 产物：`src-tauri/resources/runtime/kernel.br`、`billow-kernel(.exe)`、`rust-kernel.json`。
  - 交叉打包时可用 `BILLOW_RUST_KERNEL_TARGET` 指定 triple，或用 `BILLOW_RUST_KERNEL_BIN` 指向预构建二进制。
- Android ARM64：`TAURI_ENV_PLATFORM=android node tool/prepare_android_kernel.mjs --force`
  - 需要 `NDK_HOME`（或 `ANDROID_NDK_HOME`）与已安装的 `aarch64-linux-android` 目标。
  - 产物：`jniLibs/arm64-v8a/libmihomo.so` 与 `libbillow_kernel.so`（同 APK 内两个 PIE 进程）。
  - Rust 进程用 `-p billow-kernel-cli --features android-vpn` 构建，启用 `--tun-fd` 与 VpnService 数据面。

## 实跑验证（可用宿主）

两端都只在回环地址监听，不修改系统代理/TUN：

```bash
BILLOW_TEST_RESOURCES="$PWD/src-tauri/resources/runtime" \
  cargo test --manifest-path src-tauri/Cargo.toml --locked \
  packaged_engines_switch_both_ways_with_a_marked_request -- --ignored --nocapture
```

该用例用同一份配置：
1. Mihomo 承载带标记的 HTTP CONNECT，目标端记录 `mihomo-1`；
2. 切换到 Rust 后由 `billow-kernel` 承载，目标端记录 `rust-1`，并核对实例身份行；
3. 切回 Mihomo 后目标端记录 `mihomo-2`；
4. 换成 Rust 不接受的配置（`sniffer.enable: true`）时，切换在释放旧会话前被拒绝，Mihomo 仍承载 `mihomo-3`。

macOS 已按此入口实跑通过。Windows/Linux 由 `.github/workflows/release.yml` 在对应 runner 上执行同一命令
（`Verify both packaged engines switch with marked traffic`）；本仓库当前未在 Windows/Linux 实跑。

Android 的入口为安装 APK 后在设置页切换引擎。VpnService 的 TUN 描述符由
`BillowVpnService.establishTun` 建立并清除 `FD_CLOEXEC`，`BillowVpnBridge.nativeTunFd` 把 fd 交给宿主；
`profile.rs` 对 Rust 引擎总是移除 YAML 的 `tun` 块（含用户自写块），仅在 Android 上把 fd 作为
`--tun-fd <fd>` 启动参数交给 Rust 进程；Mihomo 路径保持 `tun.file-descriptor` 注入不变。

断开、切换引擎、重建/刷新 VpnService fd 以及 `restart_android` 的失败清理，都先停掉 Rust 子进程
（`KernelLaunch::stop_kernel` 同时清空待移交的 fd），再关闭宿主自己的 `ParcelFileDescriptor`。原因：Rust
配置里没有 fd，断开与连接的 YAML 逐字节相同，普通 reload 会命中“已运行且配置未变”的早退，子进程会继续
poll 宿主已释放的描述符。撤销（系统 `onRevoke`）则是系统先使 fd 失效：子进程的 fd 泵读到 EOF/错误后
`stats().running` 变为 false，CLI 以非零码退出（stderr 明确报告 TUN fd 不再承载报文），宿主按进程退出处理，
不会长期保留“进程活着但数据面已死”的状态。目标引擎启动失败时仍清理目标并恢复 Mihomo，失败原因写入连接状态。

应用分流保存（`set_app_rules`/`exclude_package`/`include_package`）不能沿用“先停后判”：有效 App 过滤
未变化时（例如在“绕过选中应用”与“仅代理选中应用”两个空列表之间切换，二者都归一为 `{only:false, packages:[]}`），
`takeover` 不会重建 fd，若仍先停子进程就只剩“子进程已死、宿主 PFD 仍开、快照仍 connected/vpn”的黑洞。
因此停止动作下沉到 `refresh_vpn` 的 `before_replace` 回调：只有确定会用新 fd 替换旧 fd（或重建失败并关闭
接管）时才停子进程；无变化仅持久化规则，进程与隧道保持原样。`stop_android_rust_kernel` 也不再要求
`KernelLaunch::running()` 为真才清空待移交 fd：子进程已异常退出时也要丢弃陈旧 fd 号，避免下一次启动继承
一个宿主已关闭的描述符；`connect_android` 的授权拒绝分支同样按“先停子进程、再关 PFD”的顺序处理。

验证边界：本仓库当前环境没有 Android NDK（`aarch64-linux-android-clang` 缺失）也没有设备，因此
`aarch64-linux-android` 交叉编译与真机双向切换流量均未执行；宿主单测用 `UnixDatagram` 模拟 TUN fd 覆盖
TCP/UDP/DNS、启停、reload、撤销后泵停止与错误路径，`src-tauri` 单测覆盖“断开先停子进程再关 fd”、
“从 Rust 切走先停子进程”、无变化的分流保存不杀进程、真实变化时“先停后换”的事件顺序、子进程退出后的
陈旧 fd 清理，以及授权拒绝重连的停止顺序。命令、退出码与错误原文见
`tool/kernel-compat/evidence/t26-android-tunnel.{json,md}`，真机结果保持待验。桌面 Rust 引擎不接管 TUN
（`tun` 块在所有平台都被移除，桌面 TUN 属 T6/Mihomo 路径），因此 Rust 桌面会话只走 mixed 监听器，快照不得
据此声称桌面 TUN 已支持。
