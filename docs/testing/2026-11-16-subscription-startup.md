# macOS 启动错误与订阅 User-Agent

## 已确认

用户现场为 Apple M4、macOS 15.8、Billow 0.1.13。终端运行内核 `-v` 成功，返回 Mihomo v1.19.34 darwin arm64；不能归因于架构错误或内核完全无法执行。

原实现将 stderr 丢弃；内核提前退出时只返回「内核没有启动」，随后清空启动日志。用 fatal stdout、原始 stderr、信号终止三个独立用例复现后修复：保留具体错误、退出码或信号，并在进程退出后有界等待日志读完，保证日志页收到失败现场。日志数及单行长度都有上限。

用户提供的订阅仅作私有临时样本，没有将地址、鉴权参数、节点信息写入仓库。请求结果：

| 请求 UA | 响应 |
| --- | --- |
| `Billow` | Base64 通用节点 URI 列表 |
| `mihomo` | Base64 通用节点 URI 列表 |
| `Clash.Meta` | Mihomo YAML |
| `clash.meta/v1.19.34` | Mihomo YAML |

版本化 UA 得到的 YAML 经 Billow 的配置处理后通过内核 `-t`，并在本机使用独立工作目录、随机回环端口成功启动。未启用 TUN，未修改系统代理。本机 macOS 版本为 27.0，尚未在用户的 macOS 15.8 上复验原始失败。

## UA 行为

优先级为订阅单独设置、全局设置、`clash.meta/<已安装内核版本>`。版本不可得时使用 `clash.meta`，不固定任何 alpha 版本。两个设置留空均表示继承；修改只影响后续订阅请求，不重启内核。启用、手动刷新、自动更新统一使用这套规则。

参考 [Sparkle 的订阅覆盖逻辑](https://github.com/xishang0128/sparkle/blob/master/src/main/config/profile.ts) 和 [默认 UA 生成](https://github.com/xishang0128/sparkle/blob/master/src/main/utils/userAgent.ts)。Sparkle 的固定 alpha 回退按用户要求不采用。对照的 [FlClash 默认 UA](https://github.com/chen08209/FlClash/blob/main/lib/common/package.dart) 为应用版本、clash-verge 和平台的组合，其 [globalUa 覆盖](https://github.com/chen08209/FlClash/blob/main/lib/state.dart) 与本次默认方案不同。

## 验证

- 前端 219 项测试通过；生产构建通过。
- Rust 145 项测试通过，6 项可选环境测试默认跳过。
- 真实 macOS 内核：正常启动、热重载、监听恢复、无效配置的具体错误与日志保留均通过。
- 私有订阅：配置转换、内核校验、隔离端口启动通过。
- 独立 Windows 目标模块类型检查通过；不等同完整 Windows 构建或实机测试。
- 回归覆盖 UA 优先级、旧配置迁移、保存与清空、实际 HTTP 请求头、拒绝换行注入、全局修改不重启内核。
