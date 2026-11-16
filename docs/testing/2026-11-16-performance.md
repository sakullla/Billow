# 页面切换与 Windows TUN 性能验证

本轮延续首次代理页卡顿、Windows TUN 整个应用重启和内存占用的排查。工作区在中途更新为 v0.1.12；保留已提交的界面、age 订阅和策略组改动。

## 实现与证据

- 页面切换的 `set_last_entry` 原来在原生主线程写盘，前一轮已改为后台命令。本轮合并等待中的页面保存请求，并按顺序写入，避免快速切页产生重复磁盘访问或保存过期页面。
- 代理组超过 80 个节点时只挂载可见行及预留行；小组保留自然布局，跳过尺寸测量和滚动观察。离开页面取消动画帧、移除监听器并断开观察器。
- 新增策略说明和信息条使用独立头部插槽，参与虚拟列表位置测量；定位当前节点、Tab 跨渲染窗口、过滤后缩短列表均有回归覆盖。
- 快照合并改为每组一次比较，复用未变化的组，避免局部更新时重复扫描完整节点列表。
- Windows TUN 去掉 `relaunch_for_tun` 和整应用退出。UAC 只启动无界面的内核监督进程；它在 Tauri 初始化前进入监督入口，不创建第二个 WebView、托盘或更新器。
- 授权及匿名管道握手完成后才停止旧内核。取消或预检失败保留原有连接；TUN、连接、系统代理、配置启用四个入口都有取消回归测试，重试成功清除对应授权错误。
- 监督进程只接受一次启动参数，通过匿名管道转发日志。控制管道关闭或主进程退出时回收内核；内核还绑定监督进程的 Job Object。Windows 不再额外创建、删除探测网卡，实际启动仍检查监听状态和错误日志。

Windows 句柄与生命周期实现依据 Microsoft 的 [ShellExecuteEx 参数](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfow)、[DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle) 和 [Job Object 绑定要求](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject)。未在当前机器执行真实 UAC 或修改系统代理。

## 浏览器测量

macOS Chrome、本地 Vite 开发模式，注入一个包含 2,000 个节点的组，停用 demo 后台刷新，从首页进入代理页，以两个动画帧后的时间作为测量点。

| 指标 | 全量节点渲染 | 虚拟列表 |
| --- | ---: | ---: |
| 切页测量（单次） | 157.3 ms | 20.5 ms |
| 首屏节点 DOM | 2,000 | 32 |
| 页面元素总数 | 14,153 | 376 |

这些是同机合成场景的观测，不代表用户机器、少量节点场景或 Windows WebView 的保证值，也不是原生进程内存测量。

额外浏览器验证：

- 定位第 2,000 个节点后确实可见，列表总高度保持不变。
- 连续往返首页/代理页 20 次，首页代理节点 DOM 为 0，代理页约 32 个。
- 390 px 手机视口、长中文节点名、故障转移策略说明：尾部节点可见，无横向溢出，尾屏挂载 11 个节点。

## 自动验证

- `npm test -- --reporter=dot`：18 个文件、217 项通过。
- `npm run build`：类型检查和生产构建通过。
- `cargo test --manifest-path src-tauri/Cargo.toml --lib`：142 项通过、5 项既有手动测试跳过。
- `git diff --check`：通过。
- `cargo check --manifest-path src-tauri/Cargo.toml --target x86_64-pc-windows-msvc --tests`：被本机缺少 Windows C/SDK 头文件阻塞，`ring` 编译报 `assert.h` 缺失。
- 临时独立 Cargo 工程直接引用仓库的 elevation、win_process、profile、takeover、kernel、nodes、diagnostics、resources、bundled_geo、age_key 模块，关闭临时工程中 ureq 的 TLS 默认特性以绕过 ring，Windows 目标 `cargo check --tests` 通过。仓库依赖没有修改。这只能证明这些模块在 Windows 配置下通过类型检查，不能代替完整 Windows 构建或运行。

## 尚需 Windows 实机验证

在普通权限 Billow 中开启 TUN：接受 UAC 后主窗口和主进程应保留，内核完成提权切换；取消 UAC 时旧连接继续可用。然后验证关闭/重新开启 TUN、退出应用和强制结束主进程后的内核回收，以及端口冲突或驱动失败时的提示。实际启动耗时及 Billow/WebView/内核三个进程的内存峰值需要 Windows 实测，当前不宣称已验证。
