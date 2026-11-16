# provider URL 类型错误的源码对照

用户截图报错：`url` 应为 string，实际为 `map[string]interface {}`。截图包含两个不同问题：一份配置在解析 proxy-provider 时失败；另一份配置下载失败。UA 无法直接修复已经进入内核配置中的对象类型字段。

## 对照实现

- [Sparkle YAML 工具](https://github.com/xishang0128/sparkle/blob/master/src/main/utils/yaml.ts) 使用 YAML 文档解析并启用 merge，专门保留 Reality short-id 字符串，没有把任意 provider URL 对象还原成真实地址的规则。
- [Sparkle 配置校验](https://github.com/xishang0128/sparkle/blob/master/src/main/core/profile-check.ts) 执行内核 `-t` 并读取具体错误。
- [FlClash 配置合并](https://github.com/chen08209/FlClash/blob/main/core/profile_base.go) 保留 YAML 节点，再调用 Mihomo 的 ParseRawConfig。
- [FlClash 应用配置](https://github.com/chen08209/FlClash/blob/main/core/config.go) 在解析失败时报告错误并应用无代理的默认配置维持监听；这不等于修复了原来的订阅。

## 本地验证

新增测试覆盖普通 URL、标量锚点、`<<` 合并、显式覆盖、Billow 覆写、内核设置和控制器生成。合法 URL 在整个处理链后仍是原字符串，测试通过。

构造一份 `url: {subscription: null}` 的最小 YAML，直接交给 Mihomo v1.19.34 `-t`，不经过 Billow，得到与截图相同的类型错误。该实验确认错误机制，不能证明用户原始配置一定如此。

尚未取得截图中失败配置的完整原文和覆写内容，因此不能断言对象来自原始订阅、锚点引用、覆写还是其他尚未覆盖的转换情况。没有自动删除提供者或猜测订阅地址。
