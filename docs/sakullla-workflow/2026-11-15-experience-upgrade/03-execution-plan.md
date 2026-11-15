---
# 计划字段仅在此 YAML 中填写。
format: execution_plan
tasks:
  - id: token-system
    goal: 建立统一视觉 token 并修正对比度、圆角、动效与数字呈现，使全部页面消费同一套变量。
    depends_on: []
    covers: [R23, R30]
    scope:
      - src/styles.css
      - src/components/Segmented.vue
      - src/components/Toggle.vue
      - src/components/TrafficChart.vue
      - src/components/Icon.vue
    outcomes:
      - 根与两套深色主题提供字号、行高、间距、圆角、动效与三级文字 token，页面不再新增字面量字号与圆角
      - 浅色弱文字在四种底色达到 4.5:1，焦点环与边框达到 3:1，深色主按钮与语义标签文字达到 4.5:1
      - 主按钮、分段选项与选中行统一圆角；强调色唯一，渐变只保留品牌与流量条
      - 普通过渡不超过 200ms，减少动态效果下没有无限装饰循环，scroll-behavior 回到 auto
      - 速率、延迟与流量数字使用 tabular-nums，延迟列宽度固定不抖动
    test: reuse
  - id: interaction-shell
    goal: 提供带焦点陷阱的弹层、键盘菜单、命令面板、骨架与空状态等共享交互基础。
    depends_on: [token-system]
    covers: [R25, R29, R30]
    scope:
      - src/components/Modal.vue
      - src/components/Menu.vue
      - src/components/CommandPalette.vue
      - src/components/EmptyState.vue
      - src/components/Skeleton.vue
      - src/lib/ui/focus.ts
      - src/lib/ui/hotkeys.ts
      - src/lib/ui/shortcuts.ts
      - src/styles.css
    outcomes:
      - 弹层打开后聚焦首个控件、Tab 在层内循环、背景 inert 且不滚动，Esc 关闭后焦点回到触发控件
      - Menu 支持上下键、Home/End、Esc 与外部点击关闭，关闭后焦点回到触发按钮
      - 命令面板可按页面、设置分类与动作过滤，上下键与 Enter 执行，不可执行动作显示原因且不含删除动作
      - EmptyState 区分加载、无数据、无匹配与失败并给出下一步动作；Skeleton 提供列表、卡片与详情形态
      - 快捷键注册表集中导出，斜杠、问号与 Esc 在输入框中不误触发
    test: new
  - id: shell-navigation
    goal: 桌面侧栏按核心与工具分组并固定设置，接通命令面板、每页滚动记忆与移动端当前项语义。
    depends_on: [interaction-shell]
    covers: [R25, R29, R30]
    scope:
      - src/App.vue
      - src/lib/store.ts
      - src/App.test.ts
      - src/styles.css
    outcomes:
      - 桌面侧栏显示核心与工具两个分组标题，八项顺序不变，设置固定在底部；移动端仍为五项
      - 规则、资源与日志页在移动端给设置标签 aria-current，切换后当前项立即正确且不出现空白页
      - Ctrl/Cmd+K 在任意页打开命令面板并可执行连接、断开、测速、更新订阅、添加配置、切换主题与打开日志
      - 切换页面保存并恢复滚动位置，窗口尺寸变化后回到顶部，代理组定位优先于恢复
      - Android 返回键先关闭最上层弹层或菜单，再返回上一页
    test: extend
  - id: data-layer
    goal: 扩展 Rust 快照与前端绑定，提供组图标、内核内存与运行时长、连接总数与读取错误、规则命中数据。
    depends_on: []
    covers: [R24, R26, R28, R33]
    scope:
      - src-tauri/src/nodes.rs
      - src-tauri/src/profile.rs
      - src-tauri/src/diagnostics.rs
      - src-tauri/src/lib.rs
      - src/lib/types.ts
      - src/lib/backend.ts
      - src/lib/demo.ts
      - src/lib/types.test.ts
    outcomes:
      - 配置 proxy-groups[].icon 经 http/https/data:image 校验后进入 ParsedGroup、NodeGroupView 与 NodeGroup，非法协议为 null
      - 快照含内核内存、运行时长、连接总数与连接读取错误，缺失时为 null 或 0 且不伪造占位
      - 规则行含命中次数与最后命中时间，内核不返回 extra 时两者为 null
      - 前后端 normalize 与 demo 同步，未声明字段被丢弃而不是原样透传
      - Rust 与前端类型测试覆盖 icon 解析、字段缺省与连接错误
    test: extend
  - id: rule-runtime
    goal: 支持运行时临时禁用规则与日志导出，并提供全部测速的逐节点进度事件。
    depends_on: [data-layer]
    covers: [R26, R28]
    scope:
      - src-tauri/src/profile.rs
      - src-tauri/src/diagnostics.rs
      - src-tauri/src/nodes.rs
      - src-tauri/src/lib.rs
      - src/lib/backend.ts
      - src/lib/demo.ts
    outcomes:
      - set_rule_disabled 生成过滤后的运行时配置并热重载，失败时恢复旧规则集并返回错误
      - 禁用集合只存在于内存，重启后清空，快照暴露当前禁用键
      - export_logs 写入下载目录或应用外部文档目录并返回路径，写入失败返回错误而不影响日志缓冲
      - 全部测速逐节点发出包含节点、延迟、失败、已测与总数的进度事件，demo 以定时器模拟
      - Rust 测试覆盖规则过滤、重载失败回滚、导出文件名与事件载荷
    test: new
  - id: home-view
    goal: 首页收敛为单一连接主操作，并按首屏优先级重排状态、配置、模式与接管。
    depends_on: [shell-navigation, data-layer]
    covers: [R24, R29, R30]
    scope:
      - src/views/HomeView.vue
      - src/lib/store.ts
      - src/styles.css
      - src/App.test.ts
    outcomes:
      - 390×844 首屏可见状态、当前配置、唯一主操作与网络接管摘要，连接后同时显示上传与下载速率
      - 电源图标与连接、断开或添加配置文字属于同一按钮，页面没有第二个同义主按钮
      - 手机模式为单行分段控件并在下方显示当前模式说明，桌面保留每种模式的说明
      - 无配置时只显示欢迎与添加配置；失败条显示原因、重试与查看日志，重试成功后消失
      - 运行状态显示内核版本、内存、运行时长与活动连接数，内核未提供的项整行隐藏且不出现破折号
    test: extend
  - id: proxy-view
    goal: 代理页默认展开当前组、改善搜索与测速反馈，并在组头与首页组行显示配置声明的组图标。
    depends_on: [home-view]
    covers: [R26, R30, R31, R33]
    scope:
      - src/views/ProxiesView.vue
      - src/views/HomeView.vue
      - src/components/GroupIcon.vue
      - src/lib/store.ts
      - src/styles.css
      - src/App.test.ts
      - src/lib/types.test.ts
    outcomes:
      - 首次进入展开当前手动组并在没有选择时展开第一组且滚动到位，重启后沿用展开状态，从首页进入时优先定位目标组
      - 组头与测速、节点行与测速是各自独立的焦点目标，节点行 Enter 或 Space 可选，自动组节点不可选
      - 工具栏在滚动时保持可见，搜索高亮匹配文字并显示匹配数量，支持排序、隐藏自动组、紧凑视图与展开收起全部
      - 全部测速显示已测与总数并逐节点更新，失败节点显示超时，已成功结果保留
      - 配置提供 icon 时组头与首页组行显示图片，缺失或加载失败回退内置类型图标且不改变布局与焦点
      - 390px 宽度下工具栏不横向溢出，图标不与组名重叠
    test: extend
  - id: profiles-view
    goal: 配置页增加导入去重、可见的批量更新进度与编辑器未保存保护，并补菜单键盘操作。
    depends_on: [proxy-view]
    covers: [R27, R29, R30]
    scope:
      - src/views/ProfilesView.vue
      - src/lib/store.ts
      - src-tauri/src/profile.rs
      - src/lib/demo.ts
      - src/styles.css
      - src/App.test.ts
    outcomes:
      - 导入已存在的订阅链接时提示该订阅已存在，焦点移到已有卡片且配置数量不增加
      - 全部更新显示已完成与总数以及逐卡更新中、成功或失败，失败原因留在卡片并可重试，切页后继续
      - 编辑器行号与正文滚动同步，关闭有未保存修改时先确认，取消后内容、光标与未保存标记保留
      - 保存失败时错误紧贴编辑器显示且弹层不关闭
      - 操作菜单上下键可移动，Esc 关闭后焦点回到更多操作按钮
    test: extend
  - id: diagnostics-view
    goal: 连接、规则、日志与资源页补齐实时详情、暂停冻结、命中与临时禁用、行内反馈和大列表响应。
    depends_on: [profiles-view, rule-runtime]
    covers: [R28, R29, R30, R31]
    scope:
      - src/views/ConnectionsView.vue
      - src/views/RulesView.vue
      - src/views/LogsView.vue
      - src/views/ResourcesView.vue
      - src/lib/store.ts
      - src/styles.css
      - src/App.test.ts
    outcomes:
      - 连接详情按 id 随采样更新，连接消失后显示已断开并禁用断开，复制摘要含主机、进程、规则、代理链与上下行累计和时长
      - 暂停连接列表时总数与累计流量冻结并显示暂停时刻和新增数量，继续后追平最新状态
      - 手机连接卡片同时显示上传、下载与时长
      - 规则命中字段存在时显示命中次数并可按命中排序、按类型或策略筛选，禁用后变暗标注且失败时回滚
      - 日志暂停冻结列表与级别计数并显示暂停时刻与新日志数量，支持单条复制、筛选复制、导出、换行开关与清空确认
      - 资源内联项标注无需更新且禁用更新，单个与全部更新显示进度，失败原因留在行内并可重试
      - 1000 条日志、500 条连接与 300 条规则下滚动、筛选、暂停与复制在一秒内响应，追加日志不改变滚动位置
    test: extend
delivery_verification:
  frontend_tests:
    command: npm test
  frontend_build:
    command: npm run build
  rust_tests:
    command: cargo test --manifest-path src-tauri/Cargo.toml
---
# Execution Plan

依赖链：`token-system` → `interaction-shell` → `shell-navigation` → `home-view` → `proxy-view` → `profiles-view` → `diagnostics-view`；`data-layer` 可与前三项并行，`rule-runtime` 在 `data-layer` 之后、`diagnostics-view` 之前完成。

- 共享文件（`src/lib/store.ts`、`src/styles.css`、`src/App.test.ts`）按依赖串行写入，避免并行冲突；`data-layer` 与 UI 任务写入范围互不重叠。
- 每个页面任务自带其 R29 反馈、R30 焦点与目标尺寸、R31 渲染约束，不另设纯测试或纯重构阶段。
- R32 是排除项，不产生 Task Recipe；其“无入口”要求由 D12 与各页面的范围约束保证。
- 交付验证在全部任务完成后运行三条命令；Android 返回键、安全区与触控目标仍需实机复验，属于需求已记录的非阻塞未知。
