---
format: execution_plan
tasks:
  - id: T1
    goal: 建立可重复的 v1.19.34 双引擎差分入口，并验证首个真实出口样例
    depends_on: []
    covers: [R2]
    outcomes:
      - 从仓库桌面和 Android 清单读取版本、校验与构建标签；锁定并核查对应上游源码，以可复核方式索引配置字段、协议、规则与适用平台，保留未映射项。
      - 在可控的本机监听端点，用独立端口和临时目录对显式提供的两个内核执行同份配置和带标识的请求；比较实际接收数据与返回值、错误、超时，清理进程；用锁定的 Mihomo 作为基准完成至少一条正例与故障负例并记录覆盖边界。
    test: new
    scope: [tool/kernel-compat]
  - id: T2
    goal: 让可嵌入 Rust 库和独立进程完成首条可观测的代理会话
    depends_on: []
    covers: [R1, R2, R4]
    outcomes:
      - 实际实现可构建的 Rust 库与 CLI，读取有效 YAML，从 mixed 入站在本机完成 HTTP CONNECT 和 SOCKS5 TCP 双向转发；首条规则控制 DIRECT/REJECT 出口；未实现的配置明确返回失败，后续任务扩展至完整能力。
      - 并发会话采用有界缓冲，关闭、半关闭、握手失败和停止后回收连接与任务；回归测试包含实际监听、双向负载、拒绝、停止/再启动，展示库与 CLI 接入路径，输出可核对的实例身份。
    test: new
    scope: [native-kernel]
  - id: T3
    goal: 构建 iOS 宿主及双 Packet Tunnel 目标并接入实际 Mihomo 引擎
    depends_on: []
    covers: [R1, R2]
    outcomes:
      - 生成可复现的 Tauri iOS 工程、两个独立且可选择的 Packet Tunnel 扩展、App Group 版本化资源交付及启停与权限错误路径。
      - Mihomo 扩展从固定提交构建可嵌入库，经公开 packetFlow 适配真实 TCP/UDP 会话与 DNS；宿主选择对应扩展，Rust 扩展目标交给 T7 接线，明确 Mac 构建命令与真机受控出口验证入口。
    test: new
    scope: [src-tauri/gen/apple, tool/ios, src-tauri/tauri.ios.conf.json]
  - id: T4
    goal: 按固定版本完成代理协议、入站和传输行为
    depends_on: [T1, T2]
    covers: [R2]
    outcomes:
      - 按 T1 能力清单将适用的入站、出站、握手、TCP/UDP、封装与传输选项实现并接入 Rust 运行时，不把未实现项当作兼容通过。
      - 对各族使用受控实际对端核对成功出站、错误和边界用例；登记平台条件及与随附版本行为的逐项比较，并贯穿 CLI 与嵌入库入口。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
  - id: T6
    goal: 在桌面和 Android 完成可恢复的内核双向切换
    depends_on: [T2]
    covers: [R1, R2]
    outcomes:
      - 设置、托盘、连接、重启共用串行生命周期，兼容旧选择与频道，实际进程和选定引擎可区分并在失败时恢复或正确断开。
      - 安装包包括 Rust 和 Mihomo，系统代理/TUN 与 Android VPN 描述符归属唯一；通过实际进程和标记流量验证可用宿主上的双向切换。保留其余平台需要的原生验证入口。
    test: extend
    scope:
      - src
      - src-tauri/src
      - src-tauri/gen/android
      - src-tauri/Cargo.toml
      - src-tauri/Cargo.lock
      - src-tauri/build.rs
      - src-tauri/tauri.conf.json
      - src-tauri/capabilities
      - src-tauri/permissions
      - tool
      - package.json
      - .github
  - id: T7
    goal: 在 iOS 接通 Rust 转发并验证整扩展峰值、回收与双向切换
    depends_on: [T3, T5, T6]
    covers: [R1, R2, R3, R4]
    outcomes:
      - 在宿主真实设置入口使用同一配置启动两个不同扩展，Rust 扩展只链接 Rust 转发所需代码。公开 packetFlow 桥接双向 TCP/UDP、DNS、版本切换和网络恢复；用外部应用及实际接收端核对两个方向。
      - 离线准备和校验资源、限制缓冲及队列、重载切换后释放旧索引；记录带有版本/设备/PID 的进程高水位、生命期、系统终止和代次证据，R3 全场景不超过 40,000,000 字节，R4 无失效对象逐轮累积；外部环境缺失则明确待验。
    test: extend
    scope: [native-kernel, src-tauri, src, tool, package.json, .github, docs/testing]
  - id: T8
    goal: 在最终集成版本核验五平台行为与完整基准
    depends_on: [T7]
    covers: [R1, R2, R3, R4]
    outcomes: [按同一候选版本汇总五平台两方向出口和错误场景、完整配置差分覆盖及真机峰值/恢复证据。记录各自复现命令、原始证据位置及结果，缺基准、设备或关键记录不得出具通过结论。]
    test: extend
    scope: [docs/testing, tool/kernel-compat]
  - id: T10
    goal: 实现 QUIC 与设备型协议族并对齐随附 Mihomo 行为
    depends_on: [T4]
    covers: [R2]
    outcomes:
      - 实现 hysteria、hysteria2、tuic、shadowquic 的 QUIC 传输及 wireguard、tailscale、zerotier、easytier、openvpn 的协议适配；设备/TUN 归属与切换由 T6/T7 接入，未实现项显式拒绝。
      - 以锁定 Mihomo 对端核对各族成功与失败路径，记录 QUIC 内存代价供 T7 预算核验；平台条件与未覆盖项如实登记。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
  - id: T9
    goal: 完成协议核心并集成剩余协议族
    depends_on: [T4, T11, T12, T13, T14, T17, T18, T19, T20, T21]
    covers: [R2]
    outcomes:
      - 集成 T11 交付的 vmess/snell/trusttunnel 与 gost-relay/ssh/ssr 子集，以及 T12/T13/T14/T17/T18/T19/T20/T21 补齐的 ssr 插件层、gost UDP/smux、mieru、CONNECT-UDP、sudoku、CONNECT-IP、Tailscale/ZeroTier、EasyTier、masque TCP，核对逐族行为并贯穿 CLI 与嵌入库入口。
      - 完整候选可构建、证据可复现；未实现项显式拒绝并登记，不以加载通过冒充兼容。T9 判定集成完整性（已交付子集逐族可用、拒绝具名、CLI 与嵌入库入口一致）；R2 的“所有有效配置可用”由 T8/Delivery 在完整候选上判定，已登记的 partial 缺口不单独阻断 T9。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
  - id: T11
    goal: 交付 gost-relay/ssh/ssr 可验证子集
    depends_on: [T4]
    covers: [R2]
    outcomes:
      - 交付 gost-relay（TCP/TLS/auth/forward）、ssh（password/内联 PEM/主机密钥固定/direct-tcpip）、ssr（origin/plain 与全部固定流密码）的库与 CLI 入口，并保留受控对端证据。
      - 未实现的 ssr 插件层、gost UDP/smux 与 mieru/masque/sudoku 显式拒绝并登记，交由 T12/T13/T14；不得以加载通过冒充兼容。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
  - id: T12
    goal: 补齐 ssr 插件层与 gost-relay UDP/smux
    depends_on: [T4]
    covers: [R2]
    outcomes:
      - 实现 ssr 的 auth_sha1_v4/auth_aes128_md5/auth_aes128_sha1/auth_chain_a/auth_chain_b 与 obfs http_simple/http_post/random_head/tls1.2_ticket_auth/tls1.2_ticket_fastauth，并支持 ssr UDP（若 Mihomo 支持）。
      - 实现 gost-relay 的 UDP association 与 smux 多路复用；每项以自建受控对端（锁定源码）验证成功与失败，更新 rust-mapping/README。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
    coordination:
      parent_task_id: T9
      owner: sakullla-worker
      integration_task_id: T9
      interface_refs: [docs/coordination/t12-handoff.md]
      evidence_refs: [docs/requirements/2026-11-20-native-rust-kernel.md]
      unresolved: [对端构建方式与依赖来源需在 evidence 中记录]
  - id: T5
    goal: 集成配置平面与剩余协议族，核对完整配置一致性
    depends_on: [T4, T9, T10, T15, T16, T22, T23, T24, T25]
    covers: [R1, R2, R4]
    outcomes:
      - 把 T22–T25 交付的 DNS/hosts、策略组、规则/provider/GEO-MRS、控制接口与 T15（shadowquic）、T16（wireguard/tailscale/zerotier/easytier/openvpn）协议适配集成到同一候选，核对逐项及组合差分，结果包括实际解析、命中规则、选组、DNS 处理和接收端出口。
      - 完整候选可构建、证据可复现；未实现项显式拒绝并登记，不以加载通过冒充兼容；重载失败保留旧资源、旧代次可回收。R2 的完整兼容由 T8/Delivery 判定，已登记的 partial 缺口不单独阻断 T5。
    test: extend
    scope: [native-kernel, tool/kernel-compat, src-tauri/src/mrs.rs]
  - id: T22
    goal: 实现 DNS 与 hosts 并通过差分核验
    depends_on: [T4]
    covers: [R2]
    outcomes:
      - 实现 v1.19.34 有效配置的 DNS 能力：hosts、nameserver/default-nameserver/fallback/fallback-filter/nameserver-policy/proxy-server-nameserver/direct-nameserver、enhanced-mode（normal/redir-host/fake-ip）、fake-ip-range/fake-ip-filter、use-hosts/use-system-hosts、respect-rules、ipv6，以及 UDP/TCP/DoH/DoT 传输；解析结果与策略命中语义与 pinned Mihomo 逐项一致。
      - 以固定应答的受控 DNS 环境对照 pinned Mihomo，覆盖成功、NXDOMAIN、超时与 fallback、fake-ip、按策略选择服务器等用例；未实现形状显式拒绝并登记。
    test: new
    scope: [native-kernel, tool/kernel-compat]
  - id: T23
    goal: 实现策略组、选择与健康检查
    depends_on: [T4]
    covers: [R2]
    outcomes:
      - 实现 select/url-test/fallback/load-balance/relay、嵌套组、include-all/include-all-proxies/include-all-providers 与 filter/exclude-filter/exclude-type、interval/tolerance/lazy/url/timeout/max-failed-times/expected-status 和选择持久化；选组结果、失败转移与测速与 pinned Mihomo 一致。
      - 以受控延时与故障输入对照自动组行为；库与控制入口暴露组列表与选择；未实现形状显式拒绝并登记。
    test: new
    scope: [native-kernel, tool/kernel-compat]
  - id: T24
    goal: 实现完整规则、规则/代理提供方、GEO/MRS 与覆写资源更新
    depends_on: [T4]
    covers: [R2, R4]
    outcomes:
      - 实现 v1.19.34 的规则类型（domain-keyword/dst-port/src-*/process*/rule-set/sub-rule/逻辑组合/network/in-type/geoip/geosite/ip-asn 等）、rule-providers（http/file/inline 与 yaml/text/mrs）、proxy-providers（http/file、filter、健康检查）、GEOIP/GEOSITE 编译库与 MRS、geodata-mode/loader，以及 Billow 覆写后的有效配置加载；规则顺序、命中与出口一致。
      - 以受控更新源对照 pinned Mihomo；更新失败保留旧资源、旧代次可回收；未实现形状显式拒绝并登记。
    test: new
    scope: [native-kernel, tool/kernel-compat, src-tauri/src/mrs.rs]
  - id: T25
    goal: 实现 Billow 消费的控制接口
    depends_on: [T4, T23]
    covers: [R1, R4]
    outcomes:
      - 实现 Billow 实际消费的 RESTful 控制语义：version、configs（GET/PATCH/PUT）、proxies 与组选择/延迟测速、rules、connections（含关闭）、providers/proxies 与 providers/rules（更新）、logs/traffic 流、secret 鉴权，以及 external-controller/external-controller-unix/external-controller-tls/CORS 形状；TCP 与 Unix socket 均可服务。
      - 以固定请求序列对照 pinned Mihomo 的响应结构、状态码与副作用；未实现端点显式拒绝并登记；重载后连接与规则代次可回收。
    test: new
    scope: [native-kernel, tool/kernel-compat]
  - id: T15
    goal: 实现 ShadowQUIC 并对齐随附 Mihomo 行为
    depends_on: [T4]
    covers: [R2]
    outcomes:
      - 实现 shadowquic 的 JLS 自定义 TLS 扩展与改版 QUIC 传输、认证与 TCP/UDP 承载；无法获得的依赖必须记录决策并显式拒绝，不得伪造线协议兼容。
      - 以锁定 Mihomo 或锁定源码构建的受控对端完成成功、认证失败与边界用例，登记平台条件与依赖来源。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
    coordination:
      parent_task_id: T5
      owner: sakullla-worker
      integration_task_id: T5
      interface_refs: [docs/coordination/t15-handoff.md]
      evidence_refs: [docs/requirements/2026-11-20-native-rust-kernel.md]
      unresolved: [依赖与对端构建方式需在 evidence 中记录]
  - id: T13
    goal: 以 clean-room 方式交付 mieru 并移除 GPL 派生的 sudoku 实现
    depends_on: [T4]
    covers: [R2]
    outcomes:
      - 以 clean-room 方式交付 mieru TCP 单会话（PBKDF2/时间盐、XChaCha20-Poly1305、metadata、open/data/close、SOCKS5、心跳），以锁定 Mihomo mieru listener 验证成功/认证失败/边界；未覆盖的 UDP/mux/traffic-pattern 显式拒绝并登记。
      - 移除 T13-A1 中由 GPL-3.0 transport/sudoku 直接派生的 sudoku 实现、测试与证据声明，恢复为显式拒绝并登记许可原因；sudoku 的 clean-room 重做归 T17。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
    coordination:
      parent_task_id: T9
      owner: sakullla-worker
      integration_task_id: T9
      interface_refs: [docs/coordination/t13-handoff.md]
      evidence_refs: [docs/requirements/2026-11-20-native-rust-kernel.md]
      unresolved: [对端构建方式与依赖来源需在 evidence 中记录]
  - id: T17
    goal: 以 clean-room 方式实现 sudoku 并保持线协议兼容
    depends_on: [T4]
    covers: [R2]
    outcomes:
      - 依据锁定 transport/sudoku 源码翻译实现必要子集（表/hint、KIP、RecordConn、legacy HTTP mask、pure/packed）；翻译代码属于 GPL-3.0 派生，必须在文件与 THIRD_PARTY_NOTICES 标注 GPL-3.0，并在分发说明保留合规义务。
      - 以锁定 Mihomo 或受控对端验证成功、认证失败与边界，记录 GPL 派生与平台条件；multiplex/HTTP tunnel/UoT 未实现则显式拒绝。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
    coordination:
      parent_task_id: T9
      owner: sakullla-worker
      integration_task_id: T9
      interface_refs: [docs/coordination/t17-handoff.md]
      evidence_refs: [docs/requirements/2026-11-20-native-rust-kernel.md]
      unresolved: [clean-room 观测来源与许可记录需在 evidence 中保存]
  - id: T14
    goal: 交付 masque CONNECT-UDP 子集并显式拒绝其余形态
    depends_on: [T4, T10]
    covers: [R2]
    outcomes:
      - 实现 RFC 9298 CONNECT-UDP over HTTP/3 子集（SETTINGS、认证、per-destination 流、capsule、证书校验、内存上限）并记录 QUIC 内存代价；CONNECT-IP/TCP/WARP 形状显式拒绝并登记。
      - 受控 HTTP/3 对端验证成功、认证失败与边界；证据可复现；完整候选可构建。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
    coordination:
      parent_task_id: T9
      owner: sakullla-worker
      integration_task_id: T9
      interface_refs: [docs/coordination/t14-handoff.md]
      evidence_refs: [docs/requirements/2026-11-20-native-rust-kernel.md]
      unresolved: [对端构建方式与依赖来源需在 evidence 中记录]
  - id: T16
    goal: 交付 wireguard/openvpn 协议层并登记设备层依赖
    depends_on: [T4, T6]
    covers: [R2]
    outcomes:
      - 交付 wireguard（Noise IK、transport、rekey）与 openvpn（控制通道、TLS 认证、AEAD 数据通道）的协议层，以锁定/受控对端验证成功、认证失败与边界；dial 的 IP 栈/TUN 由 T6/T7 接入并明确登记。
      - 未实现的 WireGuard server-initiated handshake、OpenVPN tls-auth/tls-crypt/CBC/compression 等显式拒绝并登记；许可来源与 no-copy 审计必须与仓库事实一致。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
    coordination:
      parent_task_id: T5
      owner: sakullla-worker
      integration_task_id: T5
      interface_refs: [docs/coordination/t16-handoff.md]
      evidence_refs: [docs/requirements/2026-11-20-native-rust-kernel.md]
      unresolved: [依赖与对端构建方式需在 evidence 中记录]
  - id: T19
    goal: 交付 Tailscale/ZeroTier 协议层并记录 EasyTier 材料缺口
    depends_on: [T4, T6]
    covers: [R2]
    outcomes:
      - 交付 Tailscale（control-base Noise、HTTP/2 /machine/map、DERP）与 ZeroTier（identity/PoW、planet/roots、VL1/VL2、HELLO/OK）的协议层；未接入的 registration/controller/TCP fallback 在加载期显式拒绝；设备/TUN 由 T6/T7。
      - 以锁定/受控对端验证成功与认证失败；记录离线依赖与许可；EasyTier 整族拒绝的理由与材料缺口移交 T20。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
    coordination:
      parent_task_id: T9
      owner: sakullla-worker
      integration_task_id: T9
      interface_refs: [docs/coordination/t19-handoff.md]
      evidence_refs: [docs/requirements/2026-11-20-native-rust-kernel.md]
      unresolved: [控制面对端与离线依赖记录需在 evidence 中保存]
  - id: T20
    goal: 实现 EasyTier 协议适配或记录不可复现的材料缺口
    depends_on: [T4, T6]
    covers: [R2]
    outcomes:
      - 依据锁定 EasyTier 源码翻译 network_secret_digest 的派生与 host/discovery/secure-datagram；翻译代码属于上游 GPL/LGPL 派生，必须标注相应许可；若上游源码不可复现则显式拒绝。
      - 以锁定 Mihomo 或受控对端验证成功、认证失败与边界，记录派生许可与平台条件。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
    coordination:
      parent_task_id: T9
      owner: sakullla-worker
      integration_task_id: T9
      interface_refs: [docs/coordination/t20-handoff.md]
      evidence_refs: [docs/requirements/2026-11-20-native-rust-kernel.md]
      unresolved: [network_secret_digest 的离线可复现性与对端记录需在 evidence 中保存]
  - id: T18
    goal: 交付 masque CONNECT-UDP/CONNECT-IP 的 UDP 与 WARP 形状
    depends_on: [T4, T10, T14]
    covers: [R2]
    outcomes:
      - 交付 RFC 9298 CONNECT-UDP 与 RFC 9484 CONNECT-IP 的 IPv4/IPv6 UDP、WARP key/cert pin、ip-stack/remote-dns；TCP over tunnel 显式拒绝并由 T21 承接。
      - 以受控 HTTP/3 对端验证成功、认证失败与边界；记录内存代价；masque 计 partial，T9 不得计完整兼容。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
    coordination:
      parent_task_id: T9
      owner: sakullla-worker
      integration_task_id: T9
      interface_refs: [docs/coordination/t18-handoff.md]
      evidence_refs: [docs/requirements/2026-11-20-native-rust-kernel.md]
      unresolved: [WARP 真实端点或受控 CONNECT-IP 对端与内存记录需在 evidence 中保存]
  - id: T21
    goal: 实现 masque TCP 终结并接入设备栈
    depends_on: [T4, T10, T14, T18]
    covers: [R2]
    outcomes:
      - 实现最小 TCP 状态机或接入 T6/T7 用户态 IP 栈，使 CONNECT-IP/CONNECT-UDP 的 TCP 目标可用；未实现项显式拒绝。
      - 以受控 HTTP/3 对端验证 TCP 成功、认证失败与边界，记录内存与平台条件。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
    coordination:
      parent_task_id: T9
      owner: sakullla-worker
      integration_task_id: T9
      interface_refs: [docs/coordination/t21-handoff.md]
      evidence_refs: [docs/requirements/2026-11-20-native-rust-kernel.md]
      unresolved: [TCP 状态机/设备栈选择与对端记录需在 evidence 中保存]
  - id: T26
    goal: 让 Android 上的 Rust 内核经 VpnService 承载流量
    depends_on: [T7]
    covers: [R1, R2]
    outcomes:
      - 实现 Android 的 Rust 数据面：复用 T7 的用户态 IP 栈，以 VpnService 的 TUN fd 作为收发通道（独立 feature，非 iOS 专用），VpnService 切到 Rust 时把 fd 直接交给 Rust 引擎，不再以 tun.file-descriptor 注入 YAML，也不再把 tun 作为配置键拒绝。
      - 宿主侧选择/连接/断开/切回 Mihomo 时正确移交与释放 fd；单测覆盖 fd 双向 IP 包、启停、切换释放与错误路径；Android 编译（NDK 可用时）与模拟/真机入口记录，真机流量核验待设备。
    test: new
    scope: [native-kernel, src-tauri/src, src-tauri/gen/android, tool, docs/testing]
  - id: T27
    goal: 按选项矩阵补齐高占比协议族的有效选项（第一批）
    depends_on: [T5]
    covers: [R2]
    outcomes:
      - 以 option-matrix 的 rust=reject/mihomo=accept 清单为驱动，补齐 vmess（alterId/grpc/xhttp 等）、tuic、hysteria2、trusttunnel、hysteria、anytls、vless、ss plugin、socks5/http（tfo/udp/interface-name/routing-mark）等有效选项；无法实现的项由需求方收窄或显式登记，不得静默忽略。
      - 重新生成选项矩阵并逐项差分；目标显著减少 reject 数且保持 0 problems；更新 rust-mapping/README/证据。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
  - id: T28
    goal: 按选项矩阵补齐设备/DNS/其余族选项（第二批）
    depends_on: [T5, T27]
    covers: [R2]
    outcomes:
      - 补齐 easytier、mieru、sudoku、shadowquic、masque、DNS（DoQ/system/dhcp/h3/ECS 等）与 sniffer/tun 相关有效配置形式；无法实现的项由需求方收窄或显式登记。
      - 以选项矩阵与差分验证；更新 rust-mapping/README/证据，保持 0 problems。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
  - id: T29
    goal: 补齐五平台与真机的交付证据
    depends_on: [T26, T27, T28]
    covers: [R1, R2, R3, R4]
    outcomes:
      - 在具备工具链与设备的运行环境执行 Windows/Linux/Android/iOS 的打包后双向切换与标记流量，并在物理 iPhone 上采集 R3 六类峰值与 R4 逐轮回收证据；记录设备、系统、配置、PID、原始 trace 与命令。
      - 外部环境缺失时保持未验证并记录补证责任与入口，不得以构建成功或模拟器替代；产出可直接并入交付报告的原始证据。
    test: extend
    scope: [docs/testing, tool/kernel-compat, .github]
  - id: T30
    goal: 补齐 anytls 与 vless 的剩余有效配置
    depends_on: [T27, T28]
    covers: [R2]
    outcomes:
      - anytls：实现 UDP/UoT 关联、会话复用（client-metadata、idle-session-*、min-idle-session、disable-reuse）、TLS-in-TLS（shadow-tls-opts、jls-opts）与 uTLS client-fingerprint；以真实 anytls/Mihomo 对端验证成功与认证失败，无法复现的项具名登记。
      - vless：实现 UDP/XUDP、packet-encoding、packet-addr 与 uTLS client-fingerprint；以 pinned Mihomo vless 服务端验证 TCP/UDP 出站与错误路径。
      - 更新选项矩阵并证明 anytls/vless 的 rust=reject 行降为 0（或逐项登记残留）；默认套件/差分不回归，更新 rust-mapping/README/证据。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
  - id: T31
    goal: 补齐 hysteria2/vmess/anytls 的剩余传输与混淆
    depends_on: [T30]
    covers: [R2]
    outcomes:
      - hysteria2：实现端口跳跃（ports/hop-interval）、Salamander/Gecko obfs、Brutal up、realm-opts、udp-mtu、bbr-profile；以 pinned Mihomo hysteria2 服务端验证成功与失败路径，无法复现的项具名登记。
      - vmess：实现 mKCP、mekya、TLS-mirror 传输；以 pinned 对端验证或具名登记不可复现的依赖。
      - anytls：实现 shadow-tls-opts 与 jls-opts（可复用 T15 shadowquic 的 JLS ClientHello 改写），以真实 anytls 对端验证。
      - 更新选项矩阵，使 hysteria2/vmess/anytls 的 rust=reject 行清零或逐项登记；默认套件、pinned peer、差分与 runner 不回归。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
  - id: T32
    goal: 补齐 tuic、shadowquic 与 hysteria v1 的剩余选项
    depends_on: [T31]
    covers: [R2]
    outcomes:
      - tuic：实现 v4 token/BLAKE3、udp-relay-mode、udp-over-stream、datagram 尺寸、reduce-rtt、fast-open、bbr-profile、client-fingerprint；以 pinned Mihomo tuic 服务端验证 TCP/UDP。
      - shadowquic：实现 zero-rtt、QUIC v2、Brutal congestion/cwnd/up/down、bbr-profile；以 pinned Mihomo shadowquic listener 验证。
      - hysteria v1：实现 ports/hop-interval、obfs（XPlus）、protocol faketcp/wechat、fast-open、client-fingerprint；以 pinned Mihomo hysteria listener 验证。
      - 更新选项矩阵使这三族 rust=reject 行清零或逐项具名登记；默认套件、pinned peer、差分与 runner 不回归。
      - 已由 Owner 书面接受的收窄：reduce-rtt 行为、shadowquic zero-rtt、QUIC v2、hysteria v1 faketcp、无 pinned hysteria v1 listener；均在 rust-mapping/t32-option-closure 具名登记，Delivery 不计为未登记缺口但不得声称已实现。
    test: extend
    scope: [native-kernel, tool/kernel-compat]
delivery_verification:
  frontend_tests:
    command: npm test
  frontend_build:
    command: npm run build
  backend_tests:
    command: cargo test --manifest-path src-tauri/Cargo.toml --locked
  native_kernel:
    command: cargo test --manifest-path native-kernel/Cargo.toml --locked -- --test-threads=1
  compatibility_runner:
    command: node --test tool/kernel-compat/runner.test.mjs
  switch_acceptance:
    command: BILLOW_TEST_RESOURCES="$PWD/src-tauri/resources/runtime" cargo test --manifest-path src-tauri/Cargo.toml --locked packaged_engines_switch_both_ways_with_a_marked_request -- --ignored
---
# 双内核执行计划

T1 冻结对照并搭建可执行差分入口，T2 打通第一条真实 Rust 代理路径，T3 建立 iOS 双扩展及 Mihomo 的宿主路径。T4、T5 完成剩余上游能力。T6 将引擎接入桌面和 Android 的真实切换入口；与其他任务写入交叉时由 Runtime 串行安排。T7 负责 Rust 的 packetFlow 接入及整扩展测量，T8 对同一候选核对跨平台证据。

真机阶段由 T3/T7/T8 的执行者在具备 Xcode、签名权限和 iPhone 的环境完成；T6/T8 在对应桌面系统与 Android 验证接管、出口和失败恢复。构建成功、模拟器、功能子集或单次采样均不能代替设备结果。
