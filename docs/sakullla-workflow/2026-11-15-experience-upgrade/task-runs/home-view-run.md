# Task home-view

[任务目标与验收](../03-execution-plan.md#tasks/home-view)

当前：实现结果标记为完成。

实现：主次列独立堆叠，断开可重试，查看全部文案完成

验证记录：6 项。

- tests:npm test 79 passed
- tests:npm run build
- measure:1440x900 gap 12px, overflowX 0
- measure:1024x768 gap 12px, overflowX 0
- measure:390x844 first-screen, overflowX 0
- 另有 1 项，见受管执行结果。

问题与关注项：3 项。

- DOM 顺序保持手机序列（接管在模式前），桌面 ≥960px 用 CSS order 把模式排到接管前，因此桌面 Tab 顺序与视觉顺序不同
- 960–1119px 侧列较窄，流量统计降为两列；≥1120px 恢复三列，以避免数值省略
- 尺寸为 Chrome + demo 后端实测；未在 Tauri/Android 实机复核安全区与触控目标

[历史记录（2 次）](../evidence/history/10.json)

下一步：接收与审查状态以 current packet/回执为准。

## Attempt History

> Runtime 只读事实。
```yaml
format: task_attempt_history
task_id: home-view
history_ref: evidence/history/10.json
history_count: 2
```

## Execution

> 已接受 Worker 的 status/concerns 由 Runtime 补齐；Owner 只补必要摘要、验证或关注项，保留身份与历史，通过 current apply_command 提交。
> status：completed | completed_with_concerns | needs_context | blocked；summary 为非空单行，最多 64 字符。
> concerns 必填：completed 用 []，其余说明关注或阻断；verification_refs 可省略，仅记录实际验证。
> integration 默认省略，由 Runtime 推导。显式申报时，使用 current packet.target.integration_guidance.example 的当前格式；写在 format: task_run 的 YAML 区域，与 execution 同级，不要写进 execution。
```yaml
format: task_run
task_id: home-view
execution:
  status: completed_with_concerns
  summary: 主次列独立堆叠，断开可重试，查看全部文案完成
  verification_refs:
    - tests:npm test 79 passed
    - tests:npm run build
    - measure:1440x900 gap 12px, overflowX 0
    - measure:1024x768 gap 12px, overflowX 0
    - measure:390x844 first-screen, overflowX 0
    - evidence/traces/home-view-home-view-A2-ad3f6bf1ad5af76d.json
  concerns:
    - DOM 顺序保持手机序列（接管在模式前），桌面 ≥960px 用 CSS order 把模式排到接管前，因此桌面 Tab 顺序与视觉顺序不同
    - 960–1119px 侧列较窄，流量统计降为两列；≥1120px 恢复三列，以避免数值省略
    - 尺寸为 Chrome + demo 后端实测；未在 Tauri/Android 实机复核安全区与触控目标
```
