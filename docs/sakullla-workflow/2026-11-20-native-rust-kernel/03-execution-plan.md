---
format: execution_plan
tasks:
  - id: T1
    goal: "建立可重复的 v1.19.34 双引擎差分入口，并验证首个真实出口样例"
    depends_on: []
    covers: ["R2"]
    scope: ["tool/kernel-compat/"]
    outcomes: ["从仓库桌面和 Android 清单读取版本、校验与构建标签；锁定并核查对应上游源码，以可复核方式索引配置字段、协议、规则与适用平台，保留未映射项。","在可控的本机监听端点，用独立端口和临时目录对显式提供的两个内核执行同份配置和带标识的请求；比较实际接收数据与返回值、错误、超时，清理进程；用锁定的 Mihomo 作为基准完成至少一条正例与故障负例并记录覆盖边界。"]
    test: new
  - id: T2
    goal: "让可嵌入 Rust 库和独立进程完成首条可观测的代理会话"
    depends_on: []
    covers: ["R1","R2","R4"]
    scope: ["native-kernel/"]
    outcomes: ["实际实现可构建的 Rust 库与 CLI，读取有效 YAML，从 mixed 入站在本机完成 HTTP CONNECT 和 SOCKS5 TCP 双向转发；首条规则控制 DIRECT/REJECT 出口；未实现的配置明确返回失败，后续任务扩展至完整能力。","并发会话采用有界缓冲，关闭、半关闭、握手失败和停止后回收连接与任务；回归测试包含实际监听、双向负载、拒绝、停止/再启动，展示库与 CLI 接入路径，输出可核对的实例身份。"]
    test: new
  - id: T3
    goal: "构建 iOS 宿主及双 Packet Tunnel 目标并接入实际 Mihomo 引擎"
    depends_on: []
    covers: ["R1","R2"]
    scope: ["src-tauri/gen/apple/","tool/ios/","src-tauri/tauri.ios.conf.json"]
    outcomes: ["生成可复现的 Tauri iOS 工程、两个独立且可选择的 Packet Tunnel 扩展、App Group 版本化资源交付及启停与权限错误路径。","Mihomo 扩展从固定提交构建可嵌入库，经公开 packetFlow 适配真实 TCP/UDP 会话与 DNS；宿主选择对应扩展，Rust 扩展目标交给 T7 接线，明确 Mac 构建命令与真机受控出口验证入口。"]
    test: new
  - id: T4
    goal: "按固定版本完成代理协议、入站和传输行为"
    depends_on: ["T1","T2"]
    covers: ["R2"]
    scope: ["native-kernel/","tool/kernel-compat/"]
    outcomes: ["按 T1 能力清单将适用的入站、出站、握手、TCP/UDP、封装与传输选项实现并接入 Rust 运行时，不把未实现项当作兼容通过。","对各族使用受控实际对端核对成功出站、错误和边界用例；登记平台条件及与随附版本行为的逐项比较，并贯穿 CLI 与嵌入库入口。"]
    test: extend
  - id: T5
    goal: "完成 DNS、策略组、规则与控制接口并核对完整配置一致性"
    depends_on: ["T4"]
    covers: ["R1","R2","R4"]
    scope: ["native-kernel/","tool/kernel-compat/","src-tauri/src/mrs.rs"]
    outcomes: ["完成适用 DNS、hosts、策略组、链、资源、规则、GEO/MRS、提供方更新、覆写生效、控制器和剩余有效配置能力，通过逐项及组合差分，结果包括实际解析、命中规则和接收端出口。","重载失败保留旧资源，旧代次可回收；消费方状态与操作反映实际内核，输出完整能力及差异记录，尚有有效配置不支持则任务不通过。"]
    test: extend
  - id: T6
    goal: "在桌面和 Android 完成可恢复的内核双向切换"
    depends_on: ["T2"]
    covers: ["R1","R2"]
    scope: ["src/","src-tauri/src/","src-tauri/gen/android/","src-tauri/Cargo.toml","src-tauri/Cargo.lock","src-tauri/build.rs","src-tauri/tauri.conf.json","src-tauri/capabilities/","src-tauri/permissions/","tool/","package.json",".github/"]
    outcomes: ["设置、托盘、连接、重启共用串行生命周期，兼容旧选择与频道，实际进程和选定引擎可区分并在失败时恢复或正确断开。","安装包包括 Rust 和 Mihomo，系统代理/TUN 与 Android VPN 描述符归属唯一；通过实际进程和标记流量验证可用宿主上的双向切换。保留其余平台需要的原生验证入口。"]
    test: extend
  - id: T7
    goal: "在 iOS 接通 Rust 转发并验证整扩展峰值、回收与双向切换"
    depends_on: ["T3","T5","T6"]
    covers: ["R1","R2","R3","R4"]
    scope: ["native-kernel/","src-tauri/","src/","tool/","package.json",".github/","docs/testing/"]
    outcomes: ["在宿主真实设置入口使用同一配置启动两个不同扩展，Rust 扩展只链接 Rust 转发所需代码。公开 packetFlow 桥接双向 TCP/UDP、DNS、版本切换和网络恢复；用外部应用及实际接收端核对两个方向。","离线准备和校验资源、限制缓冲及队列、重载切换后释放旧索引；记录带有版本/设备/PID 的进程高水位、生命期、系统终止和代次证据，R3 全场景不超过 40,000,000 字节，R4 无失效对象逐轮累积；外部环境缺失则明确待验。"]
    test: extend
  - id: T8
    goal: "在最终集成版本核验五平台行为与完整基准"
    depends_on: ["T7"]
    covers: ["R1","R2","R3","R4"]
    scope: ["docs/testing/","tool/kernel-compat/"]
    outcomes: ["按同一候选版本汇总五平台两方向出口和错误场景、完整配置差分覆盖及真机峰值/恢复证据。记录各自复现命令、原始证据位置及结果，缺基准、设备或关键记录不得出具通过结论。"]
    test: extend
delivery_verification:
  frontend_tests:
    command: "npm test"
  frontend_build:
    command: "npm run build"
  backend_tests:
    command: "cargo test --manifest-path src-tauri/Cargo.toml --locked"
  native_kernel:
    command: "cargo test --manifest-path native-kernel/Cargo.toml --locked"
  compatibility_runner:
    command: "node --test tool/kernel-compat/runner.test.mjs"
---
# 双内核执行计划

T1 冻结对照并搭建可执行差分入口，T2 打通第一条真实 Rust 代理路径，T3 建立 iOS 双扩展及 Mihomo 的宿主路径。T4、T5 完成剩余上游能力。T6 将引擎接入桌面和 Android 的真实切换入口；与其他任务写入交叉时由 Runtime 串行安排。T7 负责 Rust 的 packetFlow 接入及整扩展测量，T8 对同一候选核对跨平台证据。

真机阶段由 T3/T7/T8 的执行者在具备 Xcode、签名权限和 iPhone 的环境完成；T6/T8 在对应桌面系统与 Android 验证接管、出口和失败恢复。构建成功、模拟器、功能子集或单次采样均不能代替设备结果。
