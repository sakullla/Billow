---
# Runtime 只读取这一处文件头机器区；不要在正文重复机器字段。
format: solution
# AI 在此填写非空摘要；正文由 owner 按阶段契约组织。
summary: "方案以现行 Vue 3 + Tauri 2 结构为基础：先建立 token 与焦点/滚动/菜单/骨架等共享基础设施，再按页面落地首页单一连接主操作、导航分组与命令面板、代理组默认展开与分段测速进度、配置导入去重与编辑保护、诊断页实时详情与暂停冻结、日志/资源行内反馈、规则命中与运行时禁用；Rust 侧扩展组 icon、内核内存/运行时长、规则 extra、连接错误与总数、日志导出与规则重载；R33 以配置 icon 字段经 Rust 校验后进入快照，前端固定尺寸图片加内置图标回退。"
---
# 技术方案：Billow 体验升级（R23–R33）

## 1. 基线与约束

- 前端为 Vue 3 `<script setup>` + 单 store 注入，无 vue-router、无 CSS 框架、无图标库；页面由 `App.vue` 的静态映射切换，切页即卸载（`src/App.vue:36,143`）。
- 快照每秒整份替换，视图用 `computed` 派生；变更调用按 promise 队列串行（`src/lib/store.ts:92-148`）。所有展示逻辑应能承受“同一数据每秒换新对象”。
- Rust 侧已有配置生成、内核控制、控制器 HTTP、`/connections`、`/rules`、`/providers`、延迟探测与 76 个单测；缺 `/memory`、规则 `extra`、组 icon、连接错误与总数、内核运行起点（`docs/sakullla-workflow/2026-11-15-experience-upgrade/01-exploration.md`）。
- 构建门禁：`vue-tsc --noEmit`（strict + noUnusedLocals/Parameters）、Vite 目标 chrome105/safari13、Rust edition 2024；新增 API 不得依赖更新的运行时语法。
- 现有 demo 后端是 UI 测试的唯一数据源，新增能力必须同步 demo，并允许注入失败以便测试部分失败与回退。

## 2. 方案总览

按“共享基础 → 页面行为 → 后端数据 → 验证”的顺序推进，避免每个页面各自实现焦点、骨架、进度与错误：

1. **基础设施**：设计 token 层、`Modal` 焦点陷阱/关闭守卫/滚动锁、`Menu`、`EmptyState`、`Skeleton`、延迟进度、焦点返回、每页滚动记忆。
2. **页面**：首页、代理、配置、连接/规则/日志/资源按 R23–R28 重排；每页只保留一个主操作。
3. **数据**：Rust 快照与命令扩展，前端绑定与 demo 同步；规则临时禁用走运行时配置重载。
4. **收口**：R29 的空/错/进度统一、R30 焦点与目标尺寸、R31 虚拟化与增量渲染、R33 组图标。

## 3. 决策

### D1 设计 token 与视觉基线（R23）

**决策**：在 `src/styles.css` 的 `:root` 与两套深色块中补齐语义 token，页面只消费 token，不再新增字面量。

- 字号：`--text-xs 11px`、`--text-sm 12px`、`--text-md 13px`、`--text-base 14px`、`--text-lg 16px`、`--text-xl 20px`；行高 `--leading-tight/normal/relaxed`。
- 间距：`--space-1..6`（4/8/12/16/20/24）；密度用 `--page-pad`、`--card-pad`、`--row-gap` 在 `.compact` 下切换，桌面紧凑、手机舒适。
- 圆角：`--radius-control:10px`（主按钮、分段选项、选中行统一）、`--radius-card:12px`、`--radius-panel:16px`、`--radius-pill:999px`；删除各自的 7/8/14/18px 特例。
- 动效：`--dur-fast:120ms`、`--dur-base:160ms`、`--dur-slow:200ms`，只允许这三档；`.power`、hero、流量条改为 ≤200ms。
- 颜色：新增 `--text-3` 作为弱文字，替换浅色 `--muted` 的失败值；`--accent` 保持唯一强调色，上传紫色改为中性 `--data-up`（非强调）；删除 hero 装饰渐变与硬编码 `#3b82f6`/`#6d5dfc`，只保留品牌与流量进度渐变。
- 对比度：浅色 `--text-3` 取可在 `--bg/--surface/--surface-2/--sunken` 均 ≥4.5:1 的值（约 #5f6a79）；深色 `--text-3` 取 ≥4.5:1（约 #8b96a7）。软底强调文字改用 `--accent-ink`（浅色约 #1f56d6、深色约 #b9ccff）；语义标签使用 `--good-ink/--fair-ink/--poor-ink`。深色补 `--on-accent`（深色文字压浅蓝，≥4.5:1）。焦点环改为不透明 `--accent` 2px，保证在四种底色上 ≥3:1。
- 数字：`.mono` 继续 `tabular-nums`；`.rate`、`.stat-value`、`.chart-peak`、`.usage-text` 直接声明数字变体，延迟保留 `min-width`。
- 减少动态效果：保留功能性 spinner，但删除刷新图标等装饰性旋转；`@media (prefers-reduced-motion: reduce)` 下不再重新启用无限循环，`scroll-behavior` 改回 `auto`。

**取舍**：不引入设计 token 构建工具或 CSS-in-JS；继续单文件 CSS，按区域注释分组。消费者是所有视图与组件；删除边界是旧的 `--radius-sm`、`.mode-card` 等局部字面量。

### D2 导航、命令面板、焦点与滚动（R25、R29、R30）

**决策**：

- `PAGES` 增加 `group: 'core' | 'tools' | null`：首页/代理/配置/连接为 `core`，规则/资源/日志为 `tools`，设置为 `null` 并固定在侧栏底部。桌面渲染两个带标题的列表 + 底部设置；移动仍五项，规则/资源/日志从设置页进入，并在三页激活时给设置标签 `aria-current`。
- 新增 `CommandPalette.vue`：注册表由页面项、四个设置分类、六个动作（连接、断开、全部测速、更新全部订阅、添加配置、切换主题、打开日志）组成；`Ctrl/Cmd+K` 打开，输入过滤，↑↓ 移动、Enter 执行、Esc 关闭；不可执行项显示原因（如“连接后可测速”），不列出删除配置等不可撤销动作。面板是 `role="dialog"`，复用 D2 的焦点陷阱，关闭后焦点回到打开前元素。
- 新增 `useFocusTrap(container, { onClose, initialFocus })`，`Modal` 接入：打开时聚焦首个可聚焦项、Tab 循环、背景 `inert`、锁 `.main` 滚动、关闭后焦点返回触发控件；Esc 只作用于最上层弹层（用栈）。
- 新增 `useHotkeys`：`/` 聚焦当前页 `[data-page-search]`（输入框内不拦截），Esc 关闭弹层或清空搜索，`?` 打开快捷键说明（输入框内不触发）。
- `App.vue` 维护 `Map<PageId, number>` 滚动位置：切页前记录 `.main.scrollTop`，`nextTick` 后恢复；窗口尺寸变化或重启后清空，回到顶部。代理页 `focusGroup` 定位优先于恢复。
- 规定快捷键表集中在一处导出，命令面板与 `?` 说明共用，避免文案漂移。

**消费者**：`App.vue`、`Modal.vue`、各视图搜索框。删除边界：移除移动端仅靠设置页快捷卡的唯一入口限制仍保留，但补 aria；不新增路由。

### D3 首页（R24）

**决策**：

- 重排为“结论区 → 主操作 → 模式 → 接管 → 详情”。手机首屏顺序：状态词（含内核未运行提示）、当前配置、单一连接主控件、网络接管摘要、模式分段控件及一句说明；速率在已连接时并入主控件右侧。桌面用 CSS grid 命名为 `main`/`side`：主列状态、主操作、模式、接管；次列流量、当前节点、订阅。
- 主操作合并为一个按钮：电源图标 + 文案（连接/断开/添加配置）在同一 `<button>` 内；删除第二个文本“连接”按钮；Android VPN 开关保留为接管开关，文案注明“开启 VPN 需连接”，不再作为第二连接入口。
- 模式：手机单行 `Segmented`（规则/全局/直连）+ 下方一句 `aria-live="polite"` 说明；桌面保留三卡与逐项说明。删除三列固定网格。
- 运行状态卡：内核版本取 `store.kernel.version`，内存与运行时长取新增快照字段；任一项为 `null` 时整行隐藏，不显示破折号。活动连接数取新增 `connection_total`（未连接时隐藏）。
- 失败条：显示原因 + “重试” + “查看日志”；重试调用对应动作（连接/接管/模式）并复用原失败上下文；成功或下一次主动尝试后清空。`store` 增加 `lastFailedAction` 以决定重试目标。
- 无配置：只渲染欢迎、添加配置与导入说明；不渲染模式、接管、流量、订阅。

**消费者**：`HomeView.vue`、`store`、`Segmented.vue`。删除边界：移除 `grid-2` 平铺结构与重复连接按钮。

### D4 代理页与组图标（R26、R30、R33）

**决策**：

- 展开状态：`open` 默认包含当前手动组（无选择时第一个手动组），并滚动到该组；`focusGroup` 优先。持久化键沿用 `billow:proxy-open`，损坏 JSON 回退默认组而非空集。目标组被过滤时先取消过滤再定位。
- 组头重构：`header` 改为普通容器，内部拆成“展开按钮（组名/类型/节点数/当前节点）”与“测速按钮”两个独立焦点目标；节点行拆成“选择按钮”与“测速按钮”两个兄弟元素。组头增加固定 24×24 图标位、数字延迟与相对测速时间。
- 工具栏 sticky（`position: sticky` 于 `.main` 内），包含搜索、匹配数量、排序、隐藏自动组、紧凑视图、展开/收起全部；搜索命中用 `<mark>` 高亮并显示“匹配 N 个节点”，无命中给清空按钮。
- 键盘：节点行支持 Enter 与 Space；自动组节点行 `aria-disabled="true"`、不进入 tab 顺序。
- 测速进度：保留 Rust 并行探测，新增进度事件通道（见 D10）。前端 `store.startTestAll()` 监听 `node-test` 事件，维护 `{tested,total,results}`；组头与节点行按结果即时更新；单节点失败只标记该节点“超时”。
- 图标（R33）：Rust `ParsedGroup`/`NodeGroupView` 增 `icon: Option<String>`，只接受 `http:`、`https:`、`data:image/`；前端 `NodeGroup.icon` 与 `normalizeGroup` 二次校验（防旧后端/异常数据）。新增 `GroupIcon.vue`：固定 24×24（桌面组头 24、首页行 20），`<img loading="lazy" decoding="async" alt="" aria-hidden="true">`，`@error` 与空值回退到组类型内置图标（selector→route、url-test/fallback/load-balance→network、relay→layers、其他→globe）。图标用 `:key="icon"` 强制随配置更新；不阻塞布局、不参与焦点。
- 组图标来源为配置 `proxy-groups[].icon`；内核 `/proxies` 不读 icon。配置更新后随新快照替换，旧图标不残留。

**消费者**：`ProxiesView.vue`、`HomeView.vue`、`Icon.vue`、`nodes.rs`、`types.ts`、`demo.ts`。删除边界：移除组头内嵌按钮结构与只靠 `title` 的不可用说明。

### D5 配置页（R27）

**决策**：

- 网格只按内容高度排列（`align-items: start`），当前配置仍第一张；手机单列。
- 导入去重：前端 trim 后与 `profiles[].source` 精确比较，命中则显示 `该订阅已存在` 的字段错误、滚动并聚焦已有卡片；Rust `add_subscription` 同样拒绝重复 URL 并写 `input_error`，保证 deep link 与其他入口一致。demo 同步。
- 全部更新：由 store 编排而非单次后端批量——按订阅 id 顺序调用现有 `refresh(id)`，逐项维护 `refreshProgress {done,total,failed}` 与每卡 `update:${id}` 状态；单卡失败保留 `profile.failure` 与重试按钮，其余继续；切换页面不中断（状态在 store），回来仍显示结果。保留 Rust `refresh_all` 仅供后台线程，UI 不再调用。
- 编辑器：行号栏与 textarea 同字号/行高（13px/1.6），监听 `scroll` 同步 `transform`；`dirty` 时关闭/取消走确认层（用 Modal 的 `beforeClose` 守卫），取消后恢复焦点与 `selectionStart/End`；保存失败错误紧贴编辑器且弹层不关闭；保存成功清空 dirty。
- 操作菜单改用共享 `Menu`：ArrowUp/Down/Home/End 移动、Esc 关闭并回到触发按钮、点击外部关闭；删除确认层关闭后焦点回到“更多操作”。

**消费者**：`ProfilesView.vue`、`store`、`profile.rs`、`demo.ts`。删除边界：移除当前无守卫的 `yaml = null` 路径与手写菜单键盘逻辑。

### D6 连接、规则、日志、资源（R28）

**决策**：

- 连接：详情按 `id` 每拍从快照重查；行消失时显示“已断开”并禁用断开按钮；复制摘要用 `navigator.clipboard.writeText`，内容含主机、进程、规则、代理链、上传、下载、时长，失败 toast“无法写入剪贴板”。手机卡片补上传与时长。暂停冻结列表、总数与累计流量，记录暂停时刻，并按 id 差集显示“N 条新连接”；继续时清空冻结。
- 规则：Rust 解析 `/rules` 的 `extra.hitCount`/`extra.lastHit`（可选），快照 `RuleRow` 增加 `hit_count: number | null`、`last_hit: string | null`；任一规则有数据才显示命中列，全无则隐藏并提示“当前内核不提供命中信息”。排序按命中次数；筛选按类型与策略（从当前规则派生）。临时禁用：Rust 维护内存 `disabled_rules`（按 `type|payload|proxy|occurrence` 键），生成运行时配置时跳过对应规则并调用控制器 `PUT /configs` 热重载；失败回滚禁用集合并返回错误，UI 保持原状并 toast。重启后集合清空，符合“临时，重启后恢复”。禁用行变暗并标注“临时，重启后恢复”。
- 日志：暂停冻结列表、级别计数、记录暂停时刻与新日志数；单条复制、按当前筛选复制全部、导出（D10 的 `export_logs` 命令，桌面写 Downloads、Android 写应用外部文档目录并在 toast 显示路径）；自动换行改为显式开关（默认开）；清空前确认。跟随尾部逻辑保留，暂停时不跳动。
- 资源：内联判断改为 `vehicle` 小写包含 `inline`，并禁用更新/全量更新；每行维护 `pending/error/成功时间`，失败原因留在行内并可重试（按钮复用），全部更新显示 `已完成/总数` 并逐行推进（store 编排循环 `providerAction`）；健康检查只影响自身行。读取失败显示可重试错误态，不保留旧行；内联资源标注“无需更新”。
- 空状态统一用 `EmptyState`，区分 `loading/unavailable/no-data/no-match/error` 及下一步动作；错误附带重试。

**消费者**：四个视图、`store`、`diagnostics.rs`、`profile.rs`、`backend.ts`、`demo.ts`。删除边界：移除暂停仅冻结列表、错误只走 toast、日志固定折行等旧路径。

### D7 反馈、骨架与错误恢复（R29）

**决策**：

- 新增加载骨架组件（列表/卡片/详情三种形态），首次进入页面在数据到达前按目标布局渲染；已有数据刷新时不显示骨架，避免闪烁。
- 动作反馈：单次保存/更新按钮内联 spinner 立即显示；批量操作（测速、订阅、资源）显示计数进度；小于 1 秒完成的动作不插入骨架或占位跳动。
- 不可用原因：按钮旁渲染可见文本（不是 `title`），如“连接后可测速”；桌面与触屏一致。
- 错误就近显示：表单错误在字段/编辑器下方，列表错误在行内/卡片内，必要时加页面级提示条；动作附近提供重试或关闭。`aria-live="polite"` 用于状态，`role="alert"` 用于失败。
- 破坏性操作确认：删除配置、清空日志、关闭未保存编辑器、断开全部连接；取消后数据与焦点保持。
- store 增加 `lastActionError` 与统一的 `act` 失败信息，避免“只写 console”。

**消费者**：全部视图与 `store`。

### D8 性能与数据通道（R31）

**决策**：

- 连接表与规则列表使用窗口化渲染（固定行高 + overscan，复用同一 `useVirtualList`）；日志保留全量但用 `v-memo` 按“时间+级别+内容”键增量挂载，并加 `content-visibility: auto`，靠暂停/追加而非重排。
- store 快照替换保持，但视图派生列表使用稳定 key 与 `v-memo`；延迟/速率数字容器固定宽度，避免布局抖动。
- 轮询继续 1s/3s，隐藏窗口跳过请求（已实现）；恢复可见后下一次轮询自然追平。页面不在前台时组件已卸载，不额外轮询。
- 暂停/恢复只冻结派生源，不阻断后台缓冲；恢复时以最新快照重建。
- 内核重启或连接清空时，store 清空派生的冻结状态（用 `kernel_running`/空数组 watcher），不保留失效行。

**消费者**：`ConnectionsView`、`RulesView`、`LogsView`、`store`。

### D9 无障碍与平台边界（R30）

**决策**：

- 焦点：`Modal`/命令面板/快捷键说明/确认层统一焦点陷阱与返回；菜单实现 roving tabindex；关闭最上层只处理一次 Esc。
- 语义：图标按钮补 `aria-label`；开关 `role="switch"` + `aria-checked`（已有）；状态与错误使用 live region；列表当前项用 `aria-current`/`aria-selected`；禁用原因用 `aria-describedby` 关联可见文本。
- 目标尺寸：移动端主操作与开关 ≥44×44；其他可点目标 ≥24×24 且间距 ≥8；底部导航加 `min-height:56px` 并保留安全区。
- 键盘：导航、搜索、节点选择、连接详情、菜单、弹层全链路可完成；节点行补 Space；输入框内不拦截 `/`、`?`。
- Android 返回：在 `App.vue` 注册返回意图处理（Tauri 返回键事件/`popstate` 兜底），先关最上层弹层/菜单，否则切换上一页；无历史时交系统。实现需在 Android 实机验证（非阻塞未知）。
- 减少动态效果：只保留功能性 spinner；状态文字不依赖动画。

**消费者**：`App.vue`、`Modal.vue`、`Menu.vue`、各视图。

### D10 Rust 与绑定扩展

**决策**（新增字段均为可选，前端缺省隐藏）：

| 能力 | Rust | 前端 | 说明 |
| --- | --- | --- | --- |
| 组图标 | `parse_proxy_groups` 读 `icon`；`NodeGroupView.icon` | `NodeGroup.icon`；`normalizeGroup` 校验 | 仅 http/https/data:image |
| 内核内存 | `/memory` → `kernel_memory: Option<u64>` | 运行状态卡 | 端点不可用为 `None` |
| 运行时长 | 内核进程启动时记录 `Instant` → `kernel_uptime_secs` | 运行状态卡 | 未运行为 `None` |
| 规则命中 | `/rules` 读 `extra.hitCount/lastHit` | `RuleRow.hit_count/last_hit` | 全空隐藏列 |
| 规则禁用 | 内存禁用键集合 + 运行时配置过滤 + `PUT /configs` 重载；命令 `set_rule_disabled` | 行内开关/按钮 | 失败回滚并报错 |
| 连接总数 | `/connections` 计数后截断 500 → `connection_total` | 活动连接数 | 未连接为 0/隐藏 |
| 连接错误 | 读取失败 → `connections_error` | 连接页错误态 | 不再与空结果混淆 |
| 日志导出 | `export_logs(content) -> String` 写 Downloads/应用文档目录 | 导出按钮 | 文件名含时间戳 |
| 测速进度 | `test_all` 逐节点完成时 emit `node-test` 事件 | `store` 监听并累积 | demo 用定时器模拟 |

- 绑定层同步 `Backend` 接口、Tauri 实现、demo 实现与 normalize；新增 `onNodeTest` 订阅并返回取消函数。
- demo 增加 `DemoOptions`：`groupIcons`（含一个不可达 URL）、`failRefreshId`、`failProvider`、`connectionsFailure`、`rulesExtra: false` 用于覆盖回退与错误态。
- 规则禁用重载失败时，Rust 恢复旧配置并返回 `Err`；禁用集合与快照保持一致。

**删除边界**：不新增 HTTP 插件或前端直连内核；所有内核访问仍经 Rust。

### D11 测试与验证

- 前端：为每个视图补行为测试（现有 `App.test.ts` 扩展或新增视图测试文件），使用 demo 后端与 fake timers；覆盖：单一连接控件、模式单行与说明、命令面板快捷键与禁用原因、滚动恢复、组默认展开/深链定位/测速进度/图标回退、导入重复与编辑器守卫、连接详情实时与已断开、暂停冻结与新计数、规则命中列隐藏/排序/禁用回滚、日志暂停计数与复制范围、资源行内失败重试、骨架与空态区分、焦点陷阱与返回。
- Rust：为 icon 解析与协议过滤、规则 extra 解析、规则禁用配置过滤、内核内存/运行时长字段、连接总数/错误、导出文件名补单测；现有 76 个测试保持通过。
- 门禁：`npm test`、`npm run build`、`cargo test --manifest-path src-tauri/Cargo.toml`。
- 视觉验收：按 390×844 与 1440×900 两档、浅深主题，用浏览器/打包窗口核对首屏、对比度、目标尺寸与布局；Android 实机复验返回键、安全区与触控目标（沿用需求非阻塞未知）。

### D12 交付边界

- 不引入 WebDAV、Sub-Store、请求/DNS 明细、全局热键、快捷磁贴、主题市场、CSS 注入、云账号、遥测（R32）。
- 组图标只读配置，不提供上传/编辑/清理入口；远程图片失败只回退，不报错。
- 规则禁用是运行时、非持久化操作；重启内核或应用后恢复启用，UI 明确标注。

## 4. R 覆盖对照

| R | 主要落点 | 验证 |
| --- | --- | --- |
| R23 | D1 token、密度、动效、数字 | 对比度计算/截图、CSS 断言、reduced-motion 检查 |
| R24 | D3 首页 | 390px 首屏、单一主控件、模式、失败重试 |
| R25 | D2 导航/命令面板/滚动 | 分组标题、快捷键流、滚动保持 |
| R26 | D4 代理页 | 默认展开、定位、搜索高亮、测速进度、键盘选择 |
| R27 | D5 配置页 | 重复导入、x/y、编辑器守卫与滚动对齐、菜单键盘 |
| R28 | D6 诊断页 | 详情实时、暂停冻结、命中/禁用、日志复制、资源行内重试 |
| R29 | D7 反馈 | 骨架、可见原因、空态区分、确认层 |
| R30 | D2/D9 | 焦点陷阱、独立焦点、图标名称、44px、返回键 |
| R31 | D8 性能 | 1000 日志/500 连接/300 规则响应、暂停不跳、隐藏停轮询 |
| R32 | D12 | 无排除功能入口 |
| R33 | D4/D10 组图标 | 配置图标显示、缺失/失败回退、390px 不重叠、焦点不受影响 |

## 5. 失败边界与回滚

- 图标：非法协议或加载失败 → 内置类型图标；配置更新失败时保留旧配置，图标与旧快照一致。
- 测速：单节点失败只标记该节点；进度事件中断时以最终快照校准，已成功结果保留。
- 订阅：部分失败保留成功卡片与当前配置；全部更新可中途切页，回来后继续显示进度与结果。
- 规则禁用：重载失败恢复旧规则集与禁用集合，行状态不变并报错；重启后全部恢复启用。
- 日志导出：写文件失败 toast 错误，不清空或截断已有日志。
- 资源：更新/健康检查失败保留原行数据与更新时间，行内显示原因与重试。
- 连接详情：行消失显示“已断开”，断开会话按钮禁用；复制失败提示，不静默。
- 焦点/滚动：无法恢复的位置回顶部；尺寸变化清空记忆，不阻塞导航。

## 6. 已确认取舍与未知

- 取舍：不引入图标库与路由；不新增前端直连内核；规则禁用采用运行时重载而非持久化改写配置；订阅批量更新改由 store 串行编排，以换取逐卡进度与切页存活。
- 未知：Mihomo 是否接受并回显 `proxy-groups[].icon`（配置字段仅外部文档支持）；WebView 远程图片与明文策略未实测，失败回退已覆盖验收。
- 未知：`/memory`、规则 `extra` 在目标内核版本可用性；缺失时按需求隐藏。
- 未知：Android 返回键事件在 Tauri 2 的接口形态；以实机验证为准，实现提供兜底。
- 未知：Tauri webview 重启后 localStorage 是否保留；展开状态若有丢失，默认展开规则仍满足 R26。
