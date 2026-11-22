# Task T3

[任务目标与验收](../03-execution-plan.md#tasks/T3)

当前：实现结果标记为完成。

实现：保留运行期状态快照并为宿主与扩展补齐本地网络声明

验证记录：1 项。

- evidence/traces/T3-T3-A3-3d8c4ff8166f1b3d.json

问题与关注项：6 项。

- 无签名身份与真机：启停、上下行 TCP/UDP、DNS 及受控出口实流量仍未验证，入口见 tool/ios/verify-device.md（标注未执行）
- 宿主 billow_iOS 未编译：preBuildScript 依赖 tauri ios xcode-script 活动会话，且 src-tauri/src/kernel.rs:243 current_desktop_os() 在 iOS 目标无返回值（src-tauri/src 不在 T3 范围）
- 运行期失败路径仅编译与静态核对通过；status/*.json 的结构化快照需真机（或模拟器进程内）触发失败后才能实测
- BillowRust 的可链接分支用自建 Rust 静态库（含同名 ABI，外部临时产物未入库）验证；真实 native-kernel 数据面与错误码/状态 JSON 对齐由 T7 完成
- Mihomo c-archive 165,223,072 字节且无死代码裁剪；包体积与 R3 内存需真机测量
- 其余 1 项见受管审查结果。

[历史记录（3 次）](../evidence/history/4.json)

下一步：接收与审查状态以 current packet/回执为准。

## Attempt History

> Runtime 只读事实。
```yaml
format: task_attempt_history
task_id: T3
history_ref: evidence/history/4.json
history_count: 3
```

## Execution

> 已接受 Worker 的 status/concerns 由 Runtime 补齐；Owner 只补必要摘要、验证或关注项，保留身份与历史，通过 current apply_command 提交。
> status：completed | completed_with_concerns | needs_context | blocked；summary 为非空单行，最多 64 字符。
> concerns 必填：completed 用 []，其余说明关注或阻断；verification_refs 可省略，仅记录实际验证。
> integration 默认省略，由 Runtime 推导。显式申报时，使用 current packet.target.integration_guidance.example 的当前格式；写在 format: task_run 的 YAML 区域，与 execution 同级，不要写进 execution。
```yaml
format: task_run
task_id: T3
execution:
  status: completed_with_concerns
  summary: 保留运行期状态快照并为宿主与扩展补齐本地网络声明
  verification_refs: [evidence/traces/T3-T3-A3-3d8c4ff8166f1b3d.json]
  concerns:
    - 无签名身份与真机：启停、上下行 TCP/UDP、DNS 及受控出口实流量仍未验证，入口见 tool/ios/verify-device.md（标注未执行）
    - 宿主 billow_iOS 未编译：preBuildScript 依赖 tauri ios xcode-script 活动会话，且 src-tauri/src/kernel.rs:243 current_desktop_os() 在 iOS 目标无返回值（src-tauri/src 不在 T3 范围）
    - 运行期失败路径仅编译与静态核对通过；status/*.json 的结构化快照需真机（或模拟器进程内）触发失败后才能实测
    - BillowRust 的可链接分支用自建 Rust 静态库（含同名 ABI，外部临时产物未入库）验证；真实 native-kernel 数据面与错误码/状态 JSON 对齐由 T7 完成
    - Mihomo c-archive 165,223,072 字节且无死代码裁剪；包体积与 R3 内存需真机测量
    - 本机 Go 1.26.2 与 pin 的 go1.26.11 不同，脚本按 goVersionPolicy 接受 >=1.26.0 并告警
```
