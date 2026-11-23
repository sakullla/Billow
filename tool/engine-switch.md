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
`--tun-fd <fd>` 启动参数交给 Rust 进程；Mihomo 路径保持 `tun.file-descriptor` 注入不变。切换、断开或
撤销时先停旧进程再关闭 fd（`--tun-fd` 接收方在 `AndroidVpn::stop`/`Drop` 中关闭 fd、join 收发线程并停止
引擎），目标启动失败则清理目标并恢复 Mihomo，失败原因写入连接状态。

验证边界：本仓库当前环境没有 Android NDK（`aarch64-linux-android-clang` 缺失）也没有设备，因此
`aarch64-linux-android` 交叉编译与真机双向切换流量均未执行；宿主单测用 `UnixDatagram` 模拟 TUN fd 覆盖
TCP/UDP/DNS、启停、reload 与错误路径。命令、退出码与错误原文见
`tool/kernel-compat/evidence/t26-android-tunnel.{json,md}`，真机结果保持待验。
