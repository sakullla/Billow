---
# Runtime 只读取这一处文件头机器区；不要在正文重复机器字段。
format: exploration
# AI 在此填写非空摘要；正文由 owner 按阶段契约组织。
summary: "Billow 现状证据：8 个 section 覆盖应用外壳、首页、代理、配置、诊断、设计系统、后端与测试、组图标链路。导航为扁平 8 项且无命令面板；首页存在三个连接触发控件；代理组无默认展开与测速进度；配置导入无重复检测、编辑器无未保存保护；连接详情为快照对象、暂停只冻结列表；规则无命中字段与禁用通道；日志无单条复制/导出/换行开关；资源失败仅提示条；颜色 token 部分集中但字号/间距/动效为字面量，浅色弱文字与焦点环对比度不足；组 icon 在 Rust 解析、前端类型、demo 与渲染四层均缺失，仓库无图片加载代码，CSP 为 null。"
---
# 探索：Billow 体验升级

范围：`docs/requirements/2026-11-15-experience-upgrade.md` 的 R23–R33。证据来自 8 个只读 section（应用外壳、首页、代理、配置、诊断、设计系统、后端与测试、组图标链路），结论按主题合并；每条结论标注仓库相对路径与位置。对比度数值由颜色 token 按 sRGB 公式计算，属于推断；390px 布局结论由 CSS 网格数值推导，未做渲染测量。

## 1. 应用外壳、导航与弹层（R25、R29、R30）

- 导航是扁平列表：`PAGES` 顺序为 home、proxies、profiles、connections、rules、resources、logs、settings，`mobile:false` 标记规则/资源/日志（`src/lib/store.ts:17-26`）。桌面侧栏用单个 `<nav aria-label="主导航">` 循环渲染，没有分组标题或分组容器，settings 只是第 8 项；侧栏状态卡在列表之后（`src/App.vue:108-139`）。移动端底部为 5 项（`src/App.vue:147-161`）。
- 当前项用 `aria-current="page"`（`src/App.vue:119-120`）。移动端在规则/资源/日志页把 settings 标签置为 active，但 `aria-current` 只按精确 id 输出，因此这三页没有任何标签带 `aria-current`（`src/App.vue:153-154`）。
- 没有命令面板或全局快捷键：`src` 内没有 Ctrl/Cmd+K、`/`、`?` 处理；唯一的 window 级 keydown 在 Modal 的 Escape（`src/components/Modal.vue:8-12`）。无 vue-router，无全局快捷键插件（`package.json:18-21`、`src-tauri/Cargo.toml:23-29`）。没有 `focus()`、`activeElement`、`inert` 等焦点管理代码。
- 页面切换为 `<component :is>`，无 KeepAlive、无 Transition、无 `:key`（`src/App.vue:36,143`），切页即卸载视图，搜索等视图内状态丢失；首次加载先显示整屏 spinner 而非骨架（`src/App.vue:144`）。
- 滚动容器是单个 `.main`（`src/styles.css:348-352`），没有按页记录/恢复 `scrollTop` 的代码；唯一的定位入口是 `store.focusGroup` + 代理页 `scrollIntoView`（`src/lib/store.ts:187-191`、`src/views/ProxiesView.vue:104-113`）。
- `Modal.vue` 有 `role="dialog"`、`aria-modal`、`aria-label` 与标题，Esc 与遮罩点击可关，但没有初始聚焦、Tab 焦点循环、关闭后焦点返回、背景滚动锁，Escape 是窗口级监听（`src/components/Modal.vue:8-36`、`src/styles.css:1866-1914`）。使用方包括添加配置、导入订阅、连接详情、分应用代理、配置编辑与删除（`src/App.vue:163,204`、`src/views/ConnectionsView.vue:205`、`src/views/HomeView.vue:264`、`src/views/ProfilesView.vue:233,259,289`）。
- 主题偏好存于 Rust `shell-state.json`，system 模式移除 `data-theme`（`src/lib/store.ts:41-45`、`src-tauri/src/lib.rs:285-297`）。最后入口同样持久化，但 `resolve_entry` 没有 `resources` 分支，资源页会被记成首页（`src-tauri/src/shell.rs:61-72`）。
- 减少动态效果只有 CSS 处理，且把 spinner 与 `.spin` 重新设为 1.2s 无限循环（`src/styles.css:2050-2062`）。
- 触控目标普遍低于 44px：`.nav-item` 38px 高、`.btn` 36/32、`.icon-btn` 34/26、`.segment` 30/26、`.toggle` 42×24、`.tab` 未设最小高度（`src/styles.css:272-282,479-508,549-561,680-697,712-720,362-377`）。
- 前端没有 Android 返回键处理；`MainActivity.kt` 只做 edge-to-edge 与 VPN 授权回调（`src-tauri/gen/android/app/src/main/java/app/billow/client/MainActivity.kt:7-20`），Tauri 侧也没有默认返回处理代码。移动端进入规则/资源/日志只有设置页「通用」中的快捷卡（`src/views/SettingsView.vue:208-225`）。

## 2. 首页（R24、R29）

- DOM 顺序：失败条（`v-if snap.failure`，只有「查看日志」）→ hero 卡 → 有配置时才渲染的 `grid-2`（模式、接管、流量、当前节点、订阅）→ Android 分应用弹层（`src/views/HomeView.vue:60-100,264`）。桌面 `grid-2` 是平铺两列，无主/次列容器（`src/styles.css:455-476`）。
- 连接入口有三个：76px 电源按钮（`aria-label` 随状态变化）、文本「连接」按钮、Android VPN 开关，均调用 `store.toggleConnection()`（`src/views/HomeView.vue:67-78,95-97,151`；`src/lib/store.ts:225-233`）。store 用 `connecting` 防重入（`src/lib/store.ts:73`）。
- 模式是三列卡片网格 `role="radiogroup"`，每卡含图标、标题和说明，`aria-checked` 完整（`src/views/HomeView.vue:101-121`）。`.mode-cards` 无条件 `repeat(3,1fr)`，没有 compact 覆盖，说明文字 11.5px（`src/styles.css:1081-1108`）；按 390px 内宽 362px 推导单卡内容约 91px，9 个汉字的说明会换行，320px 时约 68px。页面没有「当前模式一句说明」元素。
- 接管：桌面为系统代理、TUN 两个开关加 TUN 设置入口；Android 为 VPN 开关与分应用代理入口（`src/views/HomeView.vue:126-160`）。开关只有 dim/disable，没有可见的不可用原因（`src/components/Toggle.vue:14`）。
- 可用运行数据只有 `connected`、上下行速率、累计流量、`connections.length`、`kernel_running`、`mixed_port`、`node_catalog`（`src/lib/types.ts:144-173`）。首页显示速率、本次上传/下载、活动连接数；缺失值统一显示「—」（`src/lib/format.ts:4-20`）。内核版本只由 `store.kernel` 提供且仅在设置页展示（`src/lib/store.ts:166`、`src/views/SettingsView.vue:282`）；内存与运行时长在前端快照和 Rust `ProfileSnapshot` 中都不存在，`src-tauri/src` 无 `memory|uptime|started_at` 匹配（`src-tauri/src/profile.rs:333-368`）。
- 失败只在首页顶部显示原因与「查看日志」，没有重试；`src` 内无 `retry|重试` 代码（`src/views/HomeView.vue:60-64`）。另一通道是变化触发的 toast（`src/lib/store.ts:116-127`、`src/App.vue:212-214`）。
- 当前节点区取 `node_catalog` 前 8 个手动组，空的兜底文案来自 `nodes_notice`；每组整行是按钮，点击带组名进入代理页；「全部」按钮不带组名（`src/views/HomeView.vue:37,197-219`）。订阅区展示名称、更新时间、节点数、流量进度、到期日与失败信息（`src/views/HomeView.vue:228-260`）。
- 无配置时 `grid-2` 整体不渲染，hero 显示欢迎与添加配置（`src/views/HomeView.vue:80-100`）。

## 3. 代理页（R26、R30、R33）

- 组展开状态是 `Set<string>`，初值只来自 `localStorage` 的 `billow:proxy-open`；没有默认展开当前手动组的逻辑，首次进入全部收起（`src/views/ProxiesView.vue:44-57`）。搜索非空时所有组强制展开（`src/views/ProxiesView.vue:100-102`）。
- 从首页进入时仅 `focusGroup` 打开并平滑滚动到组（`src/views/ProxiesView.vue:104-113`）；`focusGroup` 不持久化（`src/lib/store.ts:53`）。若目标组被「隐藏自动组」过滤，`locate` 打开但卡片不渲染，没有回退默认展开。
- 组头是 `role="button" tabindex="0"` 的可点击 header，内部又嵌套真实的测速 `<button>`；节点行同样是 `role="button"` 内嵌 delay 按钮（`src/views/ProxiesView.vue:184-207,215-237`），与 R30 的独立焦点目标不符。组头用 4px 延迟色条、组名、类型标签、节点数、当前节点与箭头；没有数字延迟和最近测速时间（`src/views/ProxiesView.vue:185-208`）。
- 工具栏不 sticky（`src/styles.css:421-426`）；搜索为纯客户端过滤，无高亮、无匹配数量；排序只作用于当前视图；隐藏自动组与紧凑视图只有 `title`；没有展开/收起全部（`src/views/ProxiesView.vue:151-164`、`src/styles.css:1370-1385`）。排序、紧凑、隐藏自动组持久化到 `billow:proxy-*`（`src/views/ProxiesView.vue:47-49`）。
- 全部测速是单次阻塞调用，Rust 并行 16 个探测后一次性返回快照，没有逐节点进度事件（`src-tauri/src/profile.rs:2738-2771`、`src-tauri/src/nodes.rs:320-364`）。UI 只在 `busy.testAll` 时转圈，副标题统计已有延迟的节点数，不是「已测/总数」（`src/views/ProxiesView.vue:83-88,144`）。
- 失败节点记为 `delay_ms: None`、`failed: true`，显示「超时」；未运行内核时按钮禁用但原因仅在 `title`，`src` 内不存在「连接后可测速」文案（`src/lib/format.ts:77-81`、`src/views/ProxiesView.vue:139-140,200,232`）。延迟记录只在内存，重启丢失（`src-tauri/src/profile.rs:881,926`）。
- 手动节点行支持 click 与 Enter，没有 Space；自动组节点有渲染但没有 role/tabindex 且点击无效（`src/views/ProxiesView.vue:95-98,215-222`）。
- 前端未调用既有 `set_node_query`/`set_node_sort` 命令（`src-tauri/src/lib.rs:545-551`、`src/lib/backend.ts` 无对应方法）。
- 深层入口只有应用内 `go('proxies', group)`；外部 deep link 仅 `billow://install-config`（`src-tauri/src/lib.rs:232-249`）。

## 4. 配置页（R27、R29）

- `.profile-grid` 为 `auto-fill minmax(300px,1fr)`，compact 下 1 列；卡片本身无固定高度（`src/styles.css:1475-1491`）。排序把当前配置置顶，其他保持快照顺序（`src/views/ProfilesView.vue:13-15`）。
- 快速导入没有重复检测：前端比较导入前后数量后提示，Rust 与 demo 都无条件新增，`src` 内不存在「该订阅已存在」，也没有把焦点移到已有卡片（`src/views/ProfilesView.vue:19-28`、`src-tauri/src/profile.rs:1061-1076`、`src/lib/demo.ts:346-356`）。
- 全部更新串行执行并只返回最终快照，没有 x/y 进度或逐卡状态；轮询在 busy 时被跳过（`src-tauri/src/lib.rs:620-637`、`src/lib/store.ts:132-136`）。单卡更新有 `update:${id}` 的 spinner/禁用（`src/lib/store.ts:245-246`、`src/views/ProfilesView.vue:186-196`）。单卡失败写 `profile.failure` 并在卡片内显示，保留当前配置（`src-tauri/src/profile.rs:2587-2616`、`src/views/ProfilesView.vue:171,228`）。
- YAML 编辑器行号栏与 textarea 是两个独立滚动区，没有滚动监听；行号 12px、正文 12.5px，行高相同但字号不同（`src/views/ProfilesView.vue:77,268-269`、`src/styles.css:1579-1614`）。
- `dirty` 只用于底部「未保存」文字，关闭与取消都直接丢弃；没有放弃确认，也没有光标保存/恢复（`src/views/ProfilesView.vue:69-73,266,276,284`）。保存失败时错误紧贴编辑器且弹层不关闭（`src/views/ProfilesView.vue:78-91,280-281`），但 `input_error` 是全局快照字段，旧值可能影响关闭判断（`src/lib/types.ts:154`）。
- 操作菜单是真实按钮 + `menuitem`，但没有上下键、Esc、焦点返回；关闭依赖 document 外部点击（`src/views/ProfilesView.vue:31-36,198-208`）。删除有确认弹层（`src/views/ProfilesView.vue:289-295`），打开菜单项后菜单卸载，删除取消时焦点无法回到原菜单项。
- 已实现：当前配置置顶、覆写提示、删除确认、删除活动配置被拒绝、失败不改 `active_id`（`src-tauri/src/profile.rs:2482-2501,1546-1562`）。

## 5. 连接、规则、日志、资源（R28、R29、R31）

- 连接桌面为表格，移动端卡片只显示下载与出站，缺上传与时长（`src/views/ConnectionsView.vue:151-203`）。详情只持有打开时的行对象，后续轮询生成新对象，字节数冻结、时长因渲染时重算而继续走；行消失后弹层仍显示旧值，「断开」始终可用（`src/views/ConnectionsView.vue:88-108,212-215`）。复制摘要不存在。
- 暂停只冻结列表来源，顶部总数与累计流量仍取实时快照；没有暂停时刻与新连接计数（`src/views/ConnectionsView.vue:54-56,116-122`）。连接读取失败在 Rust 侧直接返回空数组，快照没有错误字段（`src-tauri/src/diagnostics.rs:492-513`、`src/lib/types.ts:144-173`）。
- 规则模型只有 kind/payload/proxy，`/rules` 解析不读 `extra`，命中次数与最后命中时间在传输层就缺失（`src/lib/types.ts:70-74`、`src-tauri/src/diagnostics.rs:446-464`）。规则页只有搜索与类型芯片，无排序、筛选下拉、命中列、单条禁用；后端也没有禁用命令（`src/views/RulesView.vue:30-92`、`src/lib/backend.ts:61-67`）。渲染上限 300 + 「显示更多」，非虚拟滚动（`src/views/RulesView.vue:15,84-91`）。
- 日志级别计数取实时快照，暂停后计数仍变化；无暂停时刻、新日志数与单条复制；复制整段只含当前筛选；无导出；自动换行是固定样式，无开关；清空无确认（`src/views/LogsView.vue:30-47,66-73,81-113`、`src/styles.css:1830-1833`）。Rust 日志上限 1000 行（`src-tauri/src/diagnostics.rs:10,134-137`）。
- 资源用 `vehicle === 'inline'` 判断内联并禁用更新、排除出全部更新；健康检查对所有代理资源可用；进度只有布尔 spinner，全部更新只给最终 toast；失败只走 toast，行内不保留原因（`src/views/ResourcesView.vue:56-62,130-171`）。内联判断依赖大小写，demo 用 `Inline`，Rust 解析车辆字段（`src/lib/demo.ts:174`、`src-tauri/src/diagnostics.rs:298-350`）。
- 四个视图都没有骨架；加载只表现为刷新按钮转圈。连接「未连接/没有当前连接/没有匹配」有区分（`src/views/ConnectionsView.vue:142-149`），规则、日志、资源的读取失败与空结果混用同一状态（`src/views/RulesView.vue:76-81`、`src/views/LogsView.vue:106`、`src/views/ResourcesView.vue:113-121`）。
- 全应用没有虚拟滚动或 IntersectionObserver；每秒整份快照替换，Rust 每次 `profile_state` 同步读取 `/connections` 与 `/traffic`（`src/lib/store.ts:92,129-148`、`src-tauri/src/lib.rs:352-360`）。Rust 截断连接 500 条（`src-tauri/src/diagnostics.rs:115`）。

## 6. 视觉系统、对比度与动效（R23、R30、R33）

- 集中 token 只有颜色、阴影、圆角、外壳尺寸和字体（`src/styles.css:2-35`，深色两份重复于 37-93）。没有字号、行高、间距、动效时长、层级 token。
- 浅色 `--muted` #7a8596 在四种底色上按公式约 3.3–3.73:1，低于 4.5；深色 `--muted` 约 4.52–5.28:1，其中 `--surface-2` 刚好压线（`src/styles.css:4-12,69-77`）。`--accent` 在 `--accent-soft` 上约 3.66–3.94（激活导航、模式卡、选中节点、accent 标签）（`src/styles.css:287-290,1112-1120,1410-1429,774-777`）；`--on-accent` 只在浅色块定义，深色主按钮为白字压 `#5b8cff`，约 3.16:1（`src/styles.css:17,513-517,1014-1019`）；`--good`/`--fair` 语义标签约 2.6–2.9:1（`src/styles.css:778-785,827-834`）。
- 边框与焦点环不足 3:1：`--border` 约 1.24，焦点环为 35–45% 透明强调色，浅色约 1.62、深色约 2.13（`src/styles.css:143-146,16,52`）。禁用态再乘 0.4–0.7 透明度，弱文字可低至约 1.6。
- 圆角不统一：主按钮 8px、分段容器 10px/选项 7px、选中节点 12px、选中模式卡 12px、弹层 18px、菜单 12/7px（`src/styles.css:486,676,686,1392,1092,1883,1546,1560`）。
- 强调色除蓝外还有上传用的紫色 `--up` 与硬编码 `#3b82f6`、`#6d5dfc`；渐变共 4 处：品牌、hero 装饰径向渐变、两处流量条（`src/styles.css:24,249,977-988,1282-1286`）。
- 动效：`.power` 0.25s、hero 渐变 0.4s、流量条 0.4s，超过 200ms；spinner 0.7–0.9s 无限循环，减少动态效果下仍保留 1.2s 循环（`src/styles.css:1004,983,1283,748,851,2050-2062`）。
- 数字：`.mono` 用 tabular-nums，速率、表格数字、日志与规则数字多数已带；`.delay` 另有 `min-width:52px` 防抖（`src/styles.css:179-182,812-819`）。`.chart-peak` 只换字体不加 tabular-nums，`.group-now` 与流量文本无数字变体（`src/styles.css:1176-1183,1349-1361,1288-1295`）。
- 图标：单一 SVG path 注册表，`aria-hidden`，按调用点传 11–40px，没有 CSS 尺寸规则或尺寸 token；没有组类型图标，未知名称回退 `info`（`src/components/Icon.vue:4-10,64,78`）。

## 7. 数据与后端能力（R24、R26、R28、R31、R33）

- `Backend` 是扁平方法表，变更调用返回整份快照；Tauri 路径统一 `normalizeSnapshot`，demo 路径直接返回类型化对象（`src/lib/backend.ts:18-73,79-169`、`src/lib/demo.ts:258`）。Rust 还有前端未使用的 `set_node_query`、`set_node_sort`、`set_connection_query`、`set_log_filter` 等命令（`src-tauri/src/lib.rs:545-571`）。
- 快照轮询：内核运行或已连接时 1s，否则 3s；`document.hidden` 时跳过请求但仍继续定时；任一 busy 键存在时跳过应用快照；变更调用经 promise 队列串行（`src/lib/store.ts:96-148`）。流量为 60 点环形缓冲（`src/lib/store.ts:39,58-61,83-90`）。
- 快照字段无内核内存、运行时长、规则命中、组图标、延迟历史；内核版本来自安装 tag 而非 `/version`（`src/lib/types.ts:144-180`、`src-tauri/src/kernel.rs:721-739`）。累计流量取 `/connections` 的 total，速率来自长连接 `/traffic` 线程（`src-tauri/src/diagnostics.rs:150-156,523-540`）。
- demo 后端有 7 组 19 节点、随机延迟约 8% 失败、固定规则/资源、1s 更新全部且从不失败；无失败注入选项，无 500/1000 上限（`src/lib/demo.ts:54-88,301-308,399-406`）。
- 测试：Vitest 配置内联于 `vite.config.ts:27-30`（happy-dom），3 个套件——`src/App.test.ts` 10 个挂载测试（侧栏/底栏、连接与速率、添加、模式、节点选择与搜索、配置排序、连接筛选、Android、TUN、DNS、资源）、`src/lib/types.test.ts` 4 个、`src/lib/format.test.ts` 5 个。每个测试用 demo 后端、fake timers 与显式 width（`src/App.test.ts:6-22`）。无 store 轮询/队列、代理组语义、规则、日志、资源失败、图标渲染、剪贴板失败测试；无视图级测试文件。Rust 有 76 个 `#[test]`（profile 26、takeover 23、kernel 8、nodes 5、diagnostics 5、shell 5）。
- 约束：`npm run build` 先 `vue-tsc --noEmit`，TS strict 且 `noUnusedLocals`/`noUnusedParameters`（`package.json:10`、`tsconfig.json:12-15`）；Vite 目标 chrome105/safari13（`vite.config.ts:21-26`）；Rust edition 2024、rust-version 1.90（`src-tauri/Cargo.toml:1-33`）。

## 8. 代理组图标链路（R33）

- 端到端缺失：`parse_proxy_groups` 只读 name、proxies、include-all 与 type，`ParsedGroup` 只有 name/manual/proxies/group_type（`src-tauri/src/nodes.rs:26-31,105-135`）；`NodeGroupView` 只有 name/kind/now/sort/nodes/group_type（`src-tauri/src/nodes.rs:42-50`）。
- 前端 `NodeGroup` 同六字段，`normalizeGroup` 白名单化，任何未列字段在 live 路径被剥离（`src/lib/types.ts:38-45,332-342`、`src/lib/backend.ts:84`）。demo 的 `groupsDef` 只有 name/type/proxies（`src/lib/demo.ts:80,182`）。
- `icon` 已随配置写入内核 YAML（`apply_settings` 只改顶层键、`prioritize_selections` 只重排成员），但没有任何读回路径；内核 `/proxies` 只被用来取 `now`（`src-tauri/src/nodes.rs:189,222,366-386`、`src-tauri/src/profile.rs:2319`）。
- 渲染侧没有图标位：代理组头首槽是 4px 延迟色条，组头是 `role="button"` 且已嵌套测速按钮；首页组行没有图标槽（`src/views/ProxiesView.vue:184-207`、`src/views/HomeView.vue:203-219`）。没有组类型→图标映射，`protocolLabel` 仅输出文字（`src/lib/format.ts:83-115`）。
- 仓库没有任何图片加载代码：无 `<img>`、`convertFileSrc`、`background-image`、`new Image` 或错误回退；`Icon.vue` 仅内联 SVG（`src/components/Icon.vue:68-81`）。`security.csp` 为 `null`，没有 `assetProtocol`，能力表只有命令权限（`src-tauri/tauri.conf.json:25-27`、`src-tauri/capabilities/default.json:8-62`）。Android manifest 声明 INTERNET 与 `usesCleartextTraffic="${usesCleartextTraffic}"`，占位值未在仓库 gradle 中定义（`src-tauri/gen/android/app/src/main/AndroidManifest.xml:3,13`）。
- 组数据每次快照都从当前配置重建，配置更新后同一份快照即反映新值；只有 `auto_now` 有跨轮缓存，读取失败时回退缓存（`src-tauri/src/profile.rs:972,2091,726`）。展开状态存于 localStorage，与快照替换无关（`src/views/ProxiesView.vue:42-57`）。
- 测试与 fixture 均无 icon 字段；`normalizeGroup` 测试只覆盖既有六字段（`src/lib/types.test.ts:17-31`）。

## 9. 冲突、推断与未知

- 推断：浅色弱文字、accent 软底文字、语义标签与焦点环的对比度数值来自 token 十六进制计算，未用浏览器或 axe 实测；390px 模式卡换行与组头拥挤由网格数值推导，未渲染测量（`src/styles.css:1081-1108,1306-1369`）。
- 冲突：需求把组图标来源定为配置 `proxy-groups[].icon`，但仓库没有任何证据表明 Mihomo 会接受/回显该键；现有内核 `/proxies` 读取只取 `now`。按配置字段实现时，回显依赖配置文件本身而非内核接口，这一点在实现前需以外部门户或实测确认。
- 未知：WebView2/WKWebView/Android WebView 是否实际加载远程 http(s) 或 data: 图片（混合内容、明文策略、防盗链）无法从仓库确认；CSP 为 null 只是不额外限制。
- 未知：Tauri 桌面与 Android 重启后 localStorage 是否保留（展开状态、排序、紧凑、隐藏自动组）；仓库只证明同一会话内写入。
- 未知：`/memory`、`/rules` 的 `extra` 命中字段、运行时长在目标内核版本是否可用；仓库无调用点，需求已将缺失列为非阻塞。
- 未知：Android 返回键由 Tauri/系统默认处理到什么程度；仓库无 `onBackPressed` 或返回事件处理。
- 未知：`resolve_entry` 不含 `resources` 是否为有意行为；资源页入口持久化会回到首页。
- 未知：`set_node_query`/`set_node_sort`/`set_connection_query`/`set_log_filter` 是否为其他客户端保留的死路径。

## 10. 验证入口

- 前端：`npm test`（Vitest + happy-dom，fake timers，demo 后端），`npm run build`（vue-tsc + vite）。
- Rust：`cargo test --manifest-path src-tauri/Cargo.toml`。
- 现有 UI 回归锚点：`src/App.test.ts:25-35`（侧栏 8 项/底栏 5 项）、`:37-45`（连接与速率）、`:63-77`（组展开、节点选择、搜索）、`:79-90`（配置置顶）、`:104-124`（Android、TUN）、`:145-154`（资源）。
- 需求文档已含 2026-11-15 的 1440px/390px 浅深色人工审查记录（`docs/requirements/2026-11-15-experience-upgrade.md:183`），作为当前视觉缺陷的既有依据；本文件未重复测量。
