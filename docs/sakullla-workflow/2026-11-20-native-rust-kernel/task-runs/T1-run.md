# Task T1

[任务目标与验收](../03-execution-plan.md#tasks/T1)

当前：实现结果标记为完成。

实现：双内核同配置实跑：Rust 仅 CONNECT 直连通过，其余记为未实现

验证记录：1 项。

- evidence/traces/T1-T1-A1-a16ac67aaefd4673.json

问题与关注项：5 项。

- 双内核实跑：Mihomo 5/5 通过；Rust v0.1.0 7 例中 2 例通过，hosts/proxies/proxy-groups/lan-allowed-ips 与 forward GET 属 T4/T5 未实现，报告记为 startup-failed 并保留 [unsupported] 原文，未计为兼容。
- Rust CLI 适配：配置为位置参数、校验用 --check、端口用 --port（拒绝 mixed-port 0），仅 127.0.0.1 监听且只接受 CONNECT；已写入 README，未放宽判定。
- 锁定源码参考实现仅覆盖配置解析与单条 DIRECT 中继；REJECT 与控制接口只由内核侧验证。
- DNS 由本机系统解析器回答（当前返回通配地址），SOCKS5/UDP、远端协议握手、TUN/系统代理接管及其他平台未覆盖。
- 桌面清单未声明源码提交与校验和：v1.19.34 标签归档观测 sha256 e3284a44…，内容与 Android 固定提交一致，未声明差异保留在报告。

[历史记录（1 次）](../evidence/history/5.json)

下一步：接收与审查状态以 current packet/回执为准。

## Attempt History

> Runtime 只读事实。
```yaml
format: task_attempt_history
task_id: T1
history_ref: evidence/history/5.json
history_count: 1
```

## Execution

> 已接受 Worker 的 status/concerns 由 Runtime 补齐；Owner 只补必要摘要、验证或关注项，保留身份与历史，通过 current apply_command 提交。
> status：completed | completed_with_concerns | needs_context | blocked；summary 为非空单行，最多 64 字符。
> concerns 必填：completed 用 []，其余说明关注或阻断；verification_refs 可省略，仅记录实际验证。
> integration 默认省略，由 Runtime 推导。显式申报时，使用 current packet.target.integration_guidance.example 的当前格式；写在 format: task_run 的 YAML 区域，与 execution 同级，不要写进 execution。
```yaml
format: task_run
task_id: T1
execution:
  status: completed_with_concerns
  summary: 双内核同配置实跑：Rust 仅 CONNECT 直连通过，其余记为未实现
  verification_refs: [evidence/traces/T1-T1-A1-a16ac67aaefd4673.json]
  concerns:
    - 双内核实跑：Mihomo 5/5 通过；Rust v0.1.0 7 例中 2 例通过，hosts/proxies/proxy-groups/lan-allowed-ips 与 forward GET 属 T4/T5 未实现，报告记为 startup-failed 并保留 [unsupported] 原文，未计为兼容。
    - Rust CLI 适配：配置为位置参数、校验用 --check、端口用 --port（拒绝 mixed-port 0），仅 127.0.0.1 监听且只接受 CONNECT；已写入 README，未放宽判定。
    - 锁定源码参考实现仅覆盖配置解析与单条 DIRECT 中继；REJECT 与控制接口只由内核侧验证。
    - DNS 由本机系统解析器回答（当前返回通配地址），SOCKS5/UDP、远端协议握手、TUN/系统代理接管及其他平台未覆盖。
    - 桌面清单未声明源码提交与校验和：v1.19.34 标签归档观测 sha256 e3284a44…，内容与 Android 固定提交一致，未声明差异保留在报告。
```
