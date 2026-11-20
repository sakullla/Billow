# Task T3

[任务目标与验收](../03-execution-plan.md#tasks/T3)

当前：实现处理中。

下一步：按 Execution 区备注填写业务结果，使用 current packet 的结果入口或 apply_command。

## Execution

> 已接受 Worker 的 status/concerns 由 Runtime 补齐；Owner 只补必要摘要、验证或关注项，保留身份与历史，通过 current apply_command 提交。
> status：completed | completed_with_concerns | needs_context | blocked；summary 为非空单行，最多 64 字符。
> concerns 必填：completed 用 []，其余说明关注或阻断；verification_refs 可省略，仅记录实际验证。
> integration 默认省略，由 Runtime 推导。显式申报时，使用 current packet.target.integration_guidance.example 的当前格式；写在 format: task_run 的 YAML 区域，与 execution 同级，不要写进 execution。
```yaml
format: task_run
task_id: T3
execution:
  status: ""
  summary: ""
  concerns: []
```
