# Task T2

[任务目标与验收](../03-execution-plan.md#tasks/T2)

当前：实现结果标记为完成。

实现：实现 Rust 内核混合入站首条会话、规则与生命周期

验证记录：1 项。

- evidence/traces/T2-T2-A1-7d9cc08e80e1bae3.json

问题与关注项：4 项。

- Windows 目标可编译但会话转发未实现：relay 依赖 dup(2) 复制套接字，Windows 上 duplicate() 明确返回 Unsupported 并向客户端回 502，需在 T6 提供平台路径后才能在该平台承载流量。
- 本机仅有 macOS arm64 运行验证；Linux/Android/iOS 仅做到 cargo check 与 iOS staticlib 构建，未在对应平台上跑真机/CI 测试。
- GEOSITE 只支持文本形式（domain/sub_domain/domain_keyword）与 GEOSITE,<key>[/<tag>]，MRS/protobuf 编译格式在 T5 前明确报 unsupported；同时本切片无 DNS，GEOSITE/IP-CIDR 只对请求中给出的域名/字面 IP 生效，域名需能由系统解析后才能 DIRECT 连接。
- 未实现的顶层键、规则类型、出口、mode/log-level 取值和 geosite 规则种类均返回带稳定 tag 的错误（unsupported/invalid_value/invalid_yaml），未静默忽略；协议出站、DNS、策略组、控制接口留给 T4/T5。

[历史记录（1 次）](../evidence/history/3.json)

下一步：接收与审查状态以 current packet/回执为准。

## Attempt History

> Runtime 只读事实。
```yaml
format: task_attempt_history
task_id: T2
history_ref: evidence/history/3.json
history_count: 1
```

## Execution

> 已接受 Worker 的 status/concerns 由 Runtime 补齐；Owner 只补必要摘要、验证或关注项，保留身份与历史，通过 current apply_command 提交。
> status：completed | completed_with_concerns | needs_context | blocked；summary 为非空单行，最多 64 字符。
> concerns 必填：completed 用 []，其余说明关注或阻断；verification_refs 可省略，仅记录实际验证。
> integration 默认省略，由 Runtime 推导。显式申报时，使用 current packet.target.integration_guidance.example 的当前格式；写在 format: task_run 的 YAML 区域，与 execution 同级，不要写进 execution。
```yaml
format: task_run
task_id: T2
execution:
  status: completed_with_concerns
  summary: 实现 Rust 内核混合入站首条会话、规则与生命周期
  verification_refs: [evidence/traces/T2-T2-A1-7d9cc08e80e1bae3.json]
  concerns:
    - Windows 目标可编译但会话转发未实现：relay 依赖 dup(2) 复制套接字，Windows 上 duplicate() 明确返回 Unsupported 并向客户端回 502，需在 T6 提供平台路径后才能在该平台承载流量。
    - 本机仅有 macOS arm64 运行验证；Linux/Android/iOS 仅做到 cargo check 与 iOS staticlib 构建，未在对应平台上跑真机/CI 测试。
    - GEOSITE 只支持文本形式（domain/sub_domain/domain_keyword）与 GEOSITE,<key>[/<tag>]，MRS/protobuf 编译格式在 T5 前明确报 unsupported；同时本切片无 DNS，GEOSITE/IP-CIDR 只对请求中给出的域名/字面 IP 生效，域名需能由系统解析后才能 DIRECT 连接。
    - 未实现的顶层键、规则类型、出口、mode/log-level 取值和 geosite 规则种类均返回带稳定 tag 的错误（unsupported/invalid_value/invalid_yaml），未静默忽略；协议出站、DNS、策略组、控制接口留给 T4/T5。
```
