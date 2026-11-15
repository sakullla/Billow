# Task data-layer

[任务目标与验收](../03-execution-plan.md#tasks/data-layer)

当前：实现结果标记为完成。

实现：快照与绑定扩展：组图标、内存/时长、连接总数/错误、规则命中

验证记录：4 项。

- tests:cargo test 81 passed
- tests:npm test 23 passed
- tests:npm run build
- evidence/traces/data-layer-data-layer-A1-f7fa1a28e446f99f.json

[历史记录（1 次）](../evidence/history/1.json)

下一步：接收与审查状态以 current packet/回执为准。

## Attempt History

> Runtime 只读事实。
```yaml
format: task_attempt_history
task_id: data-layer
history_ref: evidence/history/1.json
history_count: 1
```

## Execution

> 已接受 Worker 的 status/concerns 由 Runtime 补齐；Owner 只补必要摘要、验证或关注项，保留身份与历史，通过 current apply_command 提交。
> status：completed | completed_with_concerns | needs_context | blocked；summary 为非空单行，最多 64 字符。
> concerns 必填：completed 用 []，其余说明关注或阻断；verification_refs 可省略，仅记录实际验证。
> integration 默认省略，由 Runtime 推导。显式申报时，使用 current packet.target.integration_guidance.example 的当前格式；写在 format: task_run 的 YAML 区域，与 execution 同级，不要写进 execution。
```yaml
format: task_run
task_id: data-layer
execution:
  status: completed
  summary: 快照与绑定扩展：组图标、内存/时长、连接总数/错误、规则命中
  verification_refs:
    - tests:cargo test 81 passed
    - tests:npm test 23 passed
    - tests:npm run build
    - evidence/traces/data-layer-data-layer-A1-f7fa1a28e446f99f.json
  concerns: []
```
