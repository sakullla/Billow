# Task diagnostics-view

[任务目标与验收](../03-execution-plan.md#tasks/diagnostics-view)

当前：实现结果标记为完成。

实现：移除全局锚定禁用，跟随尾部与阅读位置均稳定

验证记录：5 项。

- tests:npm test 121 passed
- tests:npm run build
- browser:follow on gap 0 for 5 appends
- browser:follow off marker offset unchanged
- evidence/traces/diagnostics-view-diagnostics-view-A4-818666870c33944b.json

问题与关注项：1 项。

- 跟随关闭时原生滚动锚定会按被裁掉的行高下调 scrollTop（约 -36px/次），但标记行视口位置不变；若要同时保持 scrollTop 字面不变需顶部占位，与保留原生锚定冲突

[历史记录（4 次）](../evidence/history/17.json)

下一步：接收与审查状态以 current packet/回执为准。

## Attempt History

> Runtime 只读事实。
```yaml
format: task_attempt_history
task_id: diagnostics-view
history_ref: evidence/history/17.json
history_count: 4
```

## Execution

> 已接受 Worker 的 status/concerns 由 Runtime 补齐；Owner 只补必要摘要、验证或关注项，保留身份与历史，通过 current apply_command 提交。
> status：completed | completed_with_concerns | needs_context | blocked；summary 为非空单行，最多 64 字符。
> concerns 必填：completed 用 []，其余说明关注或阻断；verification_refs 可省略，仅记录实际验证。
> integration 默认省略，由 Runtime 推导。显式申报时，使用 current packet.target.integration_guidance.example 的当前格式；写在 format: task_run 的 YAML 区域，与 execution 同级，不要写进 execution。
```yaml
format: task_run
task_id: diagnostics-view
execution:
  status: completed_with_concerns
  summary: 移除全局锚定禁用，跟随尾部与阅读位置均稳定
  verification_refs:
    - tests:npm test 121 passed
    - tests:npm run build
    - browser:follow on gap 0 for 5 appends
    - browser:follow off marker offset unchanged
    - evidence/traces/diagnostics-view-diagnostics-view-A4-818666870c33944b.json
  concerns: [跟随关闭时原生滚动锚定会按被裁掉的行高下调 scrollTop（约 -36px/次），但标记行视口位置不变；若要同时保持 scrollTop 字面不变需顶部占位，与保留原生锚定冲突]
```
