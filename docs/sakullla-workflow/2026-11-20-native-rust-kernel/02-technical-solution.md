---
format: solution
summary: "Rust 转发库与 Mihomo 复用有效配置。桌面和 Android 使用独立进程，iOS 使用两个 Packet Tunnel 扩展。按随附版本逐项差分，在 iPhone 上验收整个 Rust 扩展的 40 MB 峰值和资源回收。"
---
# 自研 Rust 内核与五平台切换方案

## 架构与实施顺序

同一 Rust 转发库提供桌面、Android 的进程入口及 iOS 静态库入口。该库承担连接、协议、DNS、规则和出站，可复用成熟的 Rust 网络、密码学和协议库。选择 Rust 时由 Rust 完成实际转发；Mihomo 保留为用户可选的独立引擎。

先冻结对照版本和测试输入，尽早用 iPhone 验证两个扩展各自的实流量、Rust 扩展基础占用及代表性规则集的重载峰值。根据测量调整数据布局，再逐项完成协议和配置兼容。中间里程碑可独立复验，首版发布仍以 R1–R4 全部通过为条件。

## 配置和转发行为（R2）

- 沿用现有导入、订阅、覆写和资源准备。两种内核消费同一份生效配置和同版本资源，平台适配层负责监听端口、隧道句柄等运行时参数。拆出现有配置准备中只适用于 Mihomo 子进程的路径、参数和探活逻辑。
- 按本版 v1.19.34 源码、构建标签与实际发布资产建立能力清单，登记字段、默认值、协议版本及选项、监听器、TCP/UDP、策略组、DNS、规则顺序、provider、GEO/MRS、重载和其余上游有效能力。每项记录适用平台、源码位置、可执行对照用例及结果。平台差异须在同平台基准上复现。随附版本更新后重新核对差异。
- 实现 Rust 配置解析、监听和会话、策略组选择、DNS、规则匹配、协议入站与出站、提供方和资源更新，并联通从接收连接到实际出站的完整路径。控制层保持 Billow 实际消费的配置操作、节点与策略组、测速、规则、连接、日志和流量语义。
- 对照环境固定有效 YAML、节点、DNS 应答、资源内容、可达性及请求序列。两个内核依次运行，比较配置接受与拒绝、协议握手、实际选组、DNS、命中规则、接收端观察到的出口及返回数据。自动选组等时序相关行为用可控的延时和故障输入比较。覆盖组合配置和更新失败。每个协议族用实际对端验证；缺对端、未实现选项、测量失败分别记入未通过项。

### 协议族交付顺序与拆分（R2）

首版验收范围仍是 v1.19.34 在对应平台支持的全部协议族，不因分批实现而缩小。实现按可独立复验的族推进：已交付 `socks5`/`http`/`ss`/`trojan`/`vless`/`anytls`，`vmess`/`snell`/`trusttunnel`，以及 `gost-relay`/`ssh`/`ssr` 的可验证子集；`ssr` 插件层与 `gost` UDP/smux 继续补齐，`mieru` 以 clean-room TCP 子集交付，`sudoku` 由单独的 clean-room 任务重做，`masque` 交付 RFC 9298 CONNECT-UDP 与 RFC 9484 CONNECT-IP 的 UDP/WARP 形状；masque 的 TCP 终结需要 TCP 状态机或 T6/T7 设备栈，由单独的后续任务承接。用户已明确授权 `sudoku`（T17）与 `easytier`（T20）直接依据锁定源码翻译实现；这两部分属于 GPL-3.0 派生作品，必须在文件与 THIRD_PARTY_NOTICES 中标注 GPL-3.0，并在分发说明中保留 GPL-3.0 合规义务；其余协议族仍按 clean-room/兼容许可实现。任何未实现族或选项必须在加载时显式拒绝并登记能力差异，不能以“加载通过”冒充兼容；最终候选由交付验证统一核对全量族。

设备型协议按层交付：`wireguard`/`openvpn` 的传输与认证由协议任务完成，设备/TUN 归属仍由平台接管任务负责；`tailscale`/`zerotier` 的 mesh 协议层由协议任务交付，设备/TUN 与完整控制面仍由平台任务承接；`easytier` 的 pinned wasm core 在内部派生 `network_secret_digest`，离线无法复现，因此整族显式拒绝并由单独任务记录该材料缺口，不能当作可用出站。

### Owner TUN/IP 交付决策（2026-11-26）

Owner 明确要求 TUN/IP 数据面首版完整交付，不再归入“设备层后续”或由 Mihomo 兜底。执行范围：

- **T34 桌面 TUN/IP**：Rust 内核在桌面直接创建并承载 TUN，解析 `tun` 配置（`enable`、`device`、`stack`、`mtu`、`auto-route`、`auto-detect-interface`、`strict-route`、`dns-hijack`、`route-address`、`route-exclude-address`），复用 T7 用户态 IP 栈处理 TCP/UDP、DNS 劫持、规则/组/出站；macOS 使用 utun，Linux 使用 `/dev/net/tun`，Windows 使用 Wintun；路由与 DNS 在启动、重载、停止和切回 Mihomo 时建立/回收；提权或驱动缺失时具名失败，不伪装成功。桌面 Rust 不再由宿主剥离 `tun` 块：配置文件保留该块，内核在 `--check` 时不创建设备。
- **T35 设备型出站接入**：`wireguard` 与 `openvpn` 的 IP 包接入 T34 的用户态栈，`dial()` 不再以“缺设备栈”拒绝；`tailscale`/`zerotier`/`easytier` 的控制面或成员交换缺口按名登记，不以 TUN 完成冒充整族兼容。出站自身的 `ip-stack.mode` 等选项按实际可选项接受或具名拒绝，不能静默忽略。
- **验证口径**：无 root/管理员/驱动的环境只验证配置、命令规划、fd 泵与受控对端；真实接管和出口需在具备权限的宿主复测，构建成功或模拟器不算通过。桌面 TUN 与设备型出站的结果计入 R2；未实跑部分在 Delivery 明确保留为 blocker。

T9 的职责是把已交付的协议子集与显式拒绝集成到同一候选，保证可构建、证据可复现、CLI 与嵌入库入口一致；R2 的“所有有效配置可用”由最终交付验证（T8/Delivery）在完整候选上判定，T9 不因仍有已登记的 partial 缺口而单独阻断。

Owner 选择在最终交付前继续清纯协议族的剩余选项：masque、mieru、sudoku、trojan、trusttunnel、gost-relay 由 T33 承接；完成后进入最终 Delivery，剩余 R2 与外部环境作为 blocker 如实记录，不出具虚假通过。

### Owner 范围决策（2026-11-25）

Owner 书面接受以下 5 项作为首版兼容的显式收窄，依据分别为：TUIC `reduce-rtt` 与 pinned 行为一致（pinned TUIC 未设 ClientSessionCache，实际不发送 0-RTT）；shadowquic `zero-rtt` 需要 JLS session-ticket/early-data（当前 rustls JLS 路径不提供）；shadowquic `quic-versions: v2` 需要替换仅支持 QUIC v1 的 quinn 传输层；hysteria v1 `protocol: faketcp` 需要 Linux raw socket/CAP_NET_RAW 栈；pinned Mihomo v1.19.34 不含 hysteria v1 listener，无法进行该项的 pinned 端到端验证。以上各项均在 `rust-mapping.json` 与 `t32-option-closure.*` 中具名登记，T32 的其余有效形式已实现；Delivery 不应把它们计为未登记缺口，但也不得声称已实现。

Owner 选择继续补齐纯协议选项：`tuic`、`shadowquic` 与 `hysteria` v1 的剩余有效形式（共 22 项）由新任务承接，优先于依赖设备/IP 栈的 easytier/wireguard/openvpn；每项按 pinned 对端验证或最终具名登记。

Owner 进一步要求：`hysteria2` 与 `vmess` 的剩余有效配置也必须在首版补齐（hysteria2 的 ports/obfs/up/realm/udp-mtu/bbr，vmess 的 mKCP/mekya/TLS-mirror），anytls 的 shadow-tls/jls 也继续补齐；由 T31 承接，按 pinned 对端验证，确实不可复现的项需最终登记并经 Owner 确认。

Owner 已明确要求：`anytls` 与 `vless` 的剩余有效配置必须在首版内补齐，包括 UDP/UoT、`packet-encoding`/`packet-addr`、anytls 的会话复用与 TLS-in-TLS（shadow-tls/jls）以及 uTLS `client-fingerprint`；由单独任务承接并用真实/受控对端验证。其余选项缺口仍按族归属或需求方收窄处理。

交付复审（changes_requested）追加两类返修：Android 上 Rust 内核需要独立的 VpnService TUN fd 数据面（复用 T7 的用户态 IP 栈，宿主直接移交 fd，而不是把 tun 作为 YAML 键注入后被拒绝）；R2 的选项矩阵仍有 pinned Mihomo 接受而 Rust 具名拒绝的有效形式，按协议族分两批以矩阵为驱动补齐，无法实现的形式由需求方书面收窄或登记。Windows/Linux/Android/iOS 的打包后实跑与 R3/R4 真机测量作为独立补证任务，在具备工具链与设备的环境执行；真机与 CI 证据缺失时交付保持未通过。

配置平面同样按可独立复验的能力拆分，避免单个任务同时承担 DNS、策略组、规则/provider 与控制接口：DNS 与 hosts（含 fake-ip、nameserver-policy、DoH/DoT）、策略组与选择/测速（select/url-test/fallback/load-balance/relay 与嵌套组）、规则与 provider/GEO-MRS/覆写/资源更新、控制接口分别作为独立任务交付，T5 只负责把这些能力与 T15/T16 协议适配集成到同一候选并做逐项与组合差分。每项仍须显式拒绝未实现形状并登记，最终完整兼容由 T8/Delivery 判定。

许可边界：`native-kernel` 工作区自 T17 起为 GPL-3.0-only；`sudoku`（T17）为 GPL-3.0 派生，`easytier`（T20）为 LGPL-3.0-or-later 派生，两者均在文件头与 `THIRD_PARTY_NOTICES.md` 标注，分发需同时满足 GPL-3.0 与 LGPL-3.0 的源码提供/重链接义务。其余协议族为 clean-room 或与 GPL-3.0 兼容的许可实现；上游对照基线仍为 pinned Mihomo v1.19.34。

## 选择、启动与系统接管（R1）

- 后端和设置 UI 区分选定引擎、实际运行引擎、版本及连接错误。Mihomo 发布频道仍只管理其版本。旧安装缺少引擎选择时沿用 Mihomo，保留配置和下载。设置、连接、托盘及重连共用一个后端生命周期入口。
- 串行执行切换。预备配置、校验目标并记录旧实例和接管状态，释放旧实例的独占资源，再启动目标。按实例身份和监听器或隧道就绪更新状态。验收另用受控请求核实出口。失败时清理目标，尝试恢复先前会话；恢复失败则撤销本次接管并显示断开及原因。允许切换时中断旧连接。并发请求、权限拒绝、启动失败和应用重启均需核对最终状态。
- 桌面按既有目标打包两种引擎，沿用系统代理、TUN 提权与退出清理。Android 保留 VpnService 权限和分应用策略，仅活动实例拥有所需 TUN 描述符，失败、重启和撤销时回收本次持有的句柄。每个平台执行两个方向的切换，核对引擎身份、接管状态和实际代理出口。

## iOS 宿主和扩展（R1、R3）

增加 Tauri iOS 宿主，随应用嵌入两个具有独立 bundle identifier 的 Packet Tunnel 扩展。宿主通过 NETunnelProviderManager 选择扩展，在 App Group 内向扩展提供版本化配置和资源，避免写日志时泄露订阅凭据。扩展使用公开的 packetFlow 接口收发 IP 包，配置路由、DNS 并处理停止、网络切换和失败。宿主把控制请求交给当前扩展。[Apple 多 Tunnel Provider 配置](https://developer.apple.com/documentation/networkextension/netunnelproviderprotocol/providerbundleidentifier)

Rust 扩展仅链接自研转发库和所需原生桥接代码。Mihomo 扩展按锁定提交构建可嵌入库，将 packetFlow 的双向收发桥接到其隧道与会话处理。优先验证签名安装、上下行 TCP/UDP、DNS 及重复启停。用其他应用发起可识别请求，核对选定扩展身份及远端收到的数据。两种扩展分别构建，使 Rust 会话无需承担 Go 运行时的内存开销。[Apple Packet Tunnel Provider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)

## 40 MB 与资源回收（R3、R4）

会话和配置代次显式拥有连接缓冲、异步任务及定时器。包批次、连接队列和缓存采用有界设计与背压。规则使用紧凑索引、按需读取；在共享存储准备并校验资源后切换版本，释放旧索引、映射和任务。更新失败时保留上一份可用资源。新旧数据的重叠与映射产生的实际开销均纳入峰值。以限制配置语义换取内存下降仍计为兼容失败。

在真机发布配置上识别 Rust 扩展 PID，记录设备、系统、构建、样本规模、并发、网络条件、进程 footprint 高水位与终止事件。以整进程高水位结合场景时间线捕捉瞬时峰值。带分配追踪的诊断轮次单独运行，使用 Instruments 代次与对象、句柄计数解释增长。预算验收使用整个扩展的实测值。[Apple 内存诊断](https://developer.apple.com/documentation/xcode/gathering-information-about-memory-use)

| 场景 | 判据 |
| --- | --- |
| 启动、加载配置、锁屏、并发和持续转发、替换规则集、Wi-Fi/蜂窝重连 | 整扩展观测峰值 ≤ 40,000,000 字节，操作完成，流量可持续或恢复，核对实例和系统终止记录。 |
| 反复建立并关闭连接、重载同一规则集和断网恢复 | 每轮回到等价空闲条件。预热后基线稳定，已结束连接、旧规则代次、任务和缓冲可释放。失效资源逐轮累积即判失败，即使总量低于预算。 |

有限测试集只证明已覆盖输入，须记录语料覆盖、并发与最差实测值。若有效配置使峰值超限，保留最小复现并优化复测；省略字段、缩小功能范围或提高预算均不能作为通过依据。

## 验证环境与交付证据

本仓库可完成差分工具、受控端点、Rust 和前端回归及平台构建接线。原生接管和签名真机测试分别需要对应操作系统、Android 和 iPhone 环境。iOS 需要 Xcode、相应签名权限、可切换网络的真机及采集条件，目前这些外部条件尚未核实。最终交付须附版本与资产摘要、兼容矩阵及差异、五平台双向切换的实流量记录、iPhone 峰值轨迹与代次回收记录。缺失的设备结果保持待验。
