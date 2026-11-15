# Android VPN 运行与构建

Android 安装包内置固定版本的 Mihomo。版本、源码提交、源码压缩包 SHA-256 和 Go 工具链固定在 `src-tauri/android-kernel.json`，`tool/prepare_android_kernel.mjs` 校验源码后使用上游 `with_gvisor,cmfa` 构建标签编译 ARM64 内核。构建需要 Node、Go 和 tar；GitHub 发布任务自动安装所需 Go 版本。

内核以 `libmihomo.so` 随 APK 安装到 `nativeLibraryDir`，由系统提取后执行。禁止从下载到应用数据目录的内核启动：Android 10 起限制这种执行方式，真机复现为 `Permission denied (os error 13)`。内核升级随应用版本进行，Android 设置页不再提供无效的独立内核渠道。

上游通用 Android 二进制会初始化读取 `/data/system/packages.xml` 的包管理器，普通应用没有权限。`cmfa` 是上游提供的 VPN 客户端构建路径，它跳过这段特权路由初始化；应用访问控制交给 `VpnService.Builder`，内核使用继承的 TUN 文件描述符。不开启内核自动路由或网卡检测，也不要求 root。

VPN 服务持有并释放 TUN 文件描述符，使用前台通知维持后台连接，并排除自身 UID 的上游流量以避免循环转发。授权界面通过当前 Activity 的主线程打开；Rust 后台线程通过应用类加载器查找桥接类，不能把 Application Context 当成 Activity 传入 JNI。

Android 默认使用本进程独立的本地代理和控制端口，避免订阅携带的桌面端口与其它客户端冲突。用户明确设置的混合端口仍受尊重。首次 GEO 初始化允许等待，已缓存数据时就绪后立即返回；启动失败保留具体系统错误。

应用列表只挂载视口附近的行，前端只保留这些行的图标，原生图标缓存上限为 2 MiB。Android UI/WebView 的内存数据不能作为 iOS Packet Tunnel Extension 的内存达标证明。

## 真机回归记录（0.1.2 调试构建）

在 ARM64 PKM110 上验证了 VPN 授权、内核启动、浏览器访问、后台恢复、连续三轮断开/重连、节点切换及恢复、节点搜索/测速、规则和九个资源提供者、资源详情、连接列表暂停/恢复、YAML 编辑器打开/取消、应用分流两种模式保存及恢复。系统日志未出现新的 AndroidRuntime 崩溃。

三轮连接耗时 340–415 ms，断开 307–442 ms。对有长列表的页面进行程序滚动抽样，主页、节点、设置和资源页 P95 帧间隔约 11 ms；132 个应用的列表只挂载 18 行，滚动 6000 CSS px 时 P95 约 22 ms、最大约 33 ms。该测量是前台调试 WebView 的有限抽样，不等同于所有设备或手势场景的流畅度保证。

这轮测试后的主进程 PSS 为 258083 KiB（约 252 MiB），其中图形内存 47044 KiB。它不是内核单独的内存，也不是 iOS 扩展的内存验收结果。

参考：

- [Android 可执行文件限制](https://developer.android.com/privacy-and-security/security-best-practices)
- [Android VPN 开发指南](https://developer.android.com/develop/connectivity/vpn)
- [上游 Android 特权包管理器](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/listener/sing_tun/server_android.go)
- [上游 cmfa 路径](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/listener/sing_tun/server_notandroid.go)
