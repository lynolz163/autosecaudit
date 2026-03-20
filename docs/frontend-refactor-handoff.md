# AutoSecAudit 前端重构交接文档

本文档面向准备重构 `web-console` 的开发者，重点说明当前前端的入口、状态流、页面职责、API/实时通道边界，以及推荐的重构拆分顺序。

## 1. 技术栈与启动方式

- 目录：`web-console/`
- 构建：Vite 6
- UI：React 18 + React Router 6 + TailwindCSS
- 路由模式：`HashRouter`
- 国际化：自研 `I18nProvider` + 单文件字典
- 请求：原生 `fetch`
- 测试：Vitest + Testing Library

常用命令：

```bash
cd web-console
npm install
npm run dev
npm run build
npm run test:run
```

## 2. 运行入口

### 2.1 应用入口

- `web-console/src/main.jsx`
  - 挂载 `HashRouter`
  - 挂载 `I18nProvider`
  - 渲染 `App`

### 2.2 页面壳层

- `web-console/src/App.jsx`
  - 负责懒加载页面
  - 负责路由声明
  - 负责 Shell 布局、顶部告警条、右侧搜索/健康状态
  - 通过 `useConsoleRuntime()` 获取几乎全部前端状态和行为

**现状判断**
- `App.jsx` 是前端编排层，不算最重，但已经承担：
  - 访问控制
  - 右侧工具条拼装
  - 顶部审批/系统告警
  - 页面 props 分发

后续可以保留为“路由编排层”，但应避免继续把业务逻辑塞进这里。

## 3. 当前核心状态模型

### 3.1 单一运行时 Hook

最核心文件：

- `web-console/src/hooks/useConsoleRuntime.jsx`

这是当前前端的“应用服务层 + 状态仓库 + 副作用中心”，集中处理：

- 认证状态
- JWT/refresh token 持久化
- 页面数据加载
- 周期轮询
- WebSocket 实时更新
- CRUD/提交动作
- 全局搜索
- 报告选择与基线切换
- 任务审批恢复
- 路由跳转辅助

### 3.2 Hook 中维护的主要状态

`useConsoleRuntime` 当前直接持有大量顶层状态：

- 认证：`accessToken`、`refreshToken`、`authStatus`、`currentUser`、`permissions`
- Dashboard：`summary`
- Jobs：`jobs`、`selectedJobId`、`selectedJob`、`artifacts`、`logLines`
- Reports：`reports`、`selectedReport`、`reportContent`、`reportAnalysis`、`selectedReportBaselineId`
- 资产/计划：`assets`、`schedules`
- 系统设置：`notificationConfig`、`auditEvents`、`codexConfig`、`llmSettings`
- 平台能力：`pluginCatalog`、`jobCatalog`、`systemHealth`
- 用户：`users`
- UI：`message`、`submitting`、`searchResults`、`searching`
- 实时：`selectedJobRealtimeRevision`

### 3.3 建议的第一优先级拆分

建议先把 `useConsoleRuntime.jsx` 拆为多个 hooks / service modules：

1. `useAuthSession`
   - token 持久化
   - login/bootstrap/logout
   - refresh token
   - 当前用户与权限

2. `useJobsRuntime`
   - job 列表
   - selectedJob
   - artifacts/logs
   - submit job / mission
   - approve & resume

3. `useReportsRuntime`
   - reports
   - reportContent
   - reportAnalysis
   - baseline 选择

4. `useAdminRuntime`
   - users
   - plugins
   - settings
   - notification/audit/codex/llm

5. `useGlobalSearchRuntime`
   - 搜索输入、并发控制、跳转

6. `useRealtimeJobs`
   - jobs queue websocket
   - selected job websocket

7. `usePollingRefresh`
   - dashboard/jobs/system health 的定时刷新逻辑

## 4. API 层现状

### 4.1 当前 API 文件

- `web-console/src/lib/api.js`

职责很轻，只有：

- `apiFetch`
- `buildAuthedUrl`
- `buildAuthedWebSocketUrl`

### 4.2 当前问题

所有 endpoint 字符串散落在 `useConsoleRuntime.jsx` 和少量页面里，例如：

- `/api/auth/login`
- `/api/jobs`
- `/api/jobs/:id`
- `/api/reports/:id/analysis`
- `/api/system/doctor`
- `/api/search/global`

### 4.3 推荐改造方式

建议把 endpoint 按领域拆为 API client：

- `src/api/authApi.js`
- `src/api/jobsApi.js`
- `src/api/reportsApi.js`
- `src/api/assetsApi.js`
- `src/api/schedulesApi.js`
- `src/api/settingsApi.js`
- `src/api/pluginsApi.js`
- `src/api/usersApi.js`
- `src/api/searchApi.js`

同时保留一个底层：

- `src/lib/httpClient.js`

底层负责：

- JSON 解析
- 错误格式统一
- bearer token
- refresh retry（如果你愿意，也可仍由 auth hook 负责）

## 5. 实时与轮询机制

### 5.1 实时通道

当前使用两个 WebSocket：

1. 队列级：
   - `/api/jobs/ws`
   - 用于更新 job 列表

2. 单任务级：
   - `/api/jobs/{jobId}/ws?offset=0&limit=5000`
   - 用于更新 selected job、artifacts、logs、analysis revision

### 5.2 当前副作用分布

`useConsoleRuntime.jsx` 中有多组 `useEffect`：

- 初始化认证
- 定时刷新当前视图
- 定时刷新 system health
- jobs queue websocket
- selected job websocket
- selected job fallback 轮询

### 5.3 推荐拆法

把“连接管理”和“状态写入”分开：

- `useJobQueueSocket({ accessToken, currentUser, onSnapshot })`
- `useSelectedJobSocket({ accessToken, currentUser, selectedJobId, onSnapshot, onLog, onAnalysis })`

这样页面层只关心“收到什么事件”，而不关心 socket 重连细节。

## 6. 路由与页面职责

### 6.1 路由清单

声明集中在 `web-console/src/App.jsx`：

- `/dashboard`
- `/jobs`
- `/assets`
- `/schedules`
- `/reports`
- `/rag-console`
- `/plugins`
- `/users`
- `/settings`

### 6.2 权限模型

导航和路由基于 `permissions`：

- `can_view`
- `can_operate`
- `can_admin`

当前做法：

- `navItemsFor()` 控制侧边栏展示
- `App.jsx` 路由里直接做 admin 跳转保护

这部分可以保留，但建议抽成：

- `ProtectedRoute`
- `AdminRoute`
- `OperatorActionGuard`

### 6.3 页面职责概览

#### Dashboard
- 文件：`web-console/src/pages/Dashboard.jsx`
- 职责：
  - 汇总指标
  - 审批/阻断/运行中任务概览
  - 管理层 / 安全专家双视图
- 特征：
  - 业务计算函数较多，但依赖较少
  - 适合拆出 `dashboardSelectors.js`

#### Jobs
- 文件：`web-console/src/pages/Jobs.jsx`
- 职责：
  - 任务列表
  - 任务详情
  - 提交任务 / mission
  - 日志、artifact、analysis、CVE、图谱多面板
- 当前问题：
  - 页面职责过重
  - 内部状态较多：分页、右侧 tab、artifact 详情、analysis 请求
  - 页面自己又发额外 API 请求（CVE / report analysis / artifact payload）
- 建议拆分：
  - `jobs/JobListPanel`
  - `jobs/JobDetailHeader`
  - `jobs/JobAnalysisRail`
  - `jobs/JobArtifactPanel`
  - `jobs/useSelectedJobAnalysis`

#### Reports
- 文件：`web-console/src/pages/Reports.jsx`
- 职责：
  - 报告列表
  - 管理视图 / 专家视图
  - 基线对比
  - 报告预览与分析
- 当前问题：
  - 同时处理列表、评分、diff 汇总、基线切换、详情渲染
- 建议拆分：
  - `reports/ReportListPanel`
  - `reports/ReportExecutiveSummary`
  - `reports/ReportExpertView`
  - `reports/BaselineDiffPanel`
  - `reports/reportSelectors.js`

#### Assets
- 文件：`web-console/src/pages/Assets.jsx`
- 职责简单，适合作为后续统一 CRUD 页面模板

#### Schedules
- 文件：`web-console/src/pages/Schedules.jsx`
- 与 Assets 类似，可考虑与其统一成“resource page schema”

#### Settings / Plugins / Users / RagConsole
- admin 侧页面
- 可以延后重构
- 优先把 API 和表单状态抽离后，再分目录整理

## 7. 组件层现状

### 7.1 组件热点

较大的组件：

- `web-console/src/components/ScanForm.jsx`
- `web-console/src/components/AgentTimeline.jsx`
- `web-console/src/components/ReportPreview.jsx`
- `web-console/src/components/CVEPanel.jsx`

### 7.2 组件职责概览

#### ScanForm
- 当前是“表单 + 预设 + mission overrides + payload builder”混合体
- 包含：
  - 默认表单
  - 模型预设
  - 推理强度预设
  - CSV/JSON parse
  - mission payload 构造
  - 跟系统健康联动的提示
- 建议拆分：
  - `scan-form/constants.js`
  - `scan-form/payloadBuilders.js`
  - `scan-form/ModelPresetPicker.jsx`
  - `scan-form/ReasoningLevelPicker.jsx`
  - `scan-form/AdvancedOptions.jsx`
  - `scan-form/useScanFormState.js`

#### AgentTimeline
- 目前承担日志解析与时间线渲染双职责
- 包含大量纯函数：
  - 结构化日志解析
  - ranking context 绑定
  - event 标准化
- 最适合优先抽离纯逻辑：
  - `agent-timeline/parser.js`
  - `agent-timeline/selectors.js`
  - `agent-timeline/nodes/*.jsx`

#### ReportPreview
- 负责报告导出按钮 + Markdown/HTML 预览 + 分析面板联动
- 可拆为：
  - `ReportExportBar`
  - `ReportMarkdownPane`
  - `ReportAnalysisSidebar`

### 7.3 小组件

以下组件已经比较轻：

- `MetricCard.jsx`
- `StatusBadge.jsx`
- `SystemHealthIndicator.jsx`
- `LanguageSwitcher.jsx`
- `PaginationControls.jsx`

这些不需要优先重构。

## 8. 国际化现状

### 8.1 文件

- `web-console/src/i18n.jsx`

### 8.2 问题

当前为单文件超大字典，约 40KB+，同时承载：

- 语言切换
- localStorage 持久化
- 翻译文本
- 部分消息本地化逻辑

### 8.3 建议

改造成：

- `src/i18n/index.jsx`
- `src/i18n/messages/zh-CN.js`
- `src/i18n/messages/en.js`
- `src/i18n/formatters.js`

**注意**

- 编辑时务必保持 UTF-8 编码
- 当前中文内容在部分终端中可能显示乱码，但文件本身仍应按 UTF-8 处理

## 9. 当前目录热点与建议目标结构

### 9.1 当前热点文件

按体积和复杂度看，优先级大致如下：

1. `web-console/src/hooks/useConsoleRuntime.jsx`
2. `web-console/src/components/ScanForm.jsx`
3. `web-console/src/pages/Jobs.jsx`
4. `web-console/src/pages/Reports.jsx`
5. `web-console/src/components/AgentTimeline.jsx`
6. `web-console/src/i18n.jsx`

### 9.2 推荐目标结构

建议逐步向以下结构演进：

```text
web-console/src/
  app/
    AppShell.jsx
    routes.jsx
    providers.jsx
  api/
    authApi.js
    jobsApi.js
    reportsApi.js
    assetsApi.js
    schedulesApi.js
    settingsApi.js
    pluginsApi.js
    usersApi.js
    searchApi.js
  hooks/
    auth/
      useAuthSession.js
    jobs/
      useJobsRuntime.js
      useSelectedJobSocket.js
    reports/
      useReportsRuntime.js
    admin/
      useAdminRuntime.js
    shared/
      usePollingRefresh.js
      useGlobalSearchRuntime.js
  features/
    dashboard/
    jobs/
    reports/
    assets/
    schedules/
    settings/
    plugins/
    users/
    rag-console/
  components/
    shared/
  i18n/
    index.jsx
    messages/
      zh-CN.js
      en.js
  lib/
    httpClient.js
    formatters.js
    views.js
```

## 10. 推荐重构顺序

### Phase 1：先拆基础层

先动这些，收益最大，风险最小：

1. 把 `api.js` 升级为领域 API clients
2. 把 `useConsoleRuntime.jsx` 拆成 auth / jobs / reports / admin / realtime
3. 保持 `App.jsx` 对外 props 基本不变

### Phase 2：拆重页面

1. 拆 `Jobs.jsx`
2. 拆 `Reports.jsx`
3. 抽共同的 `DisclosureSection`、列表面板、详情头部

### Phase 3：拆重组件

1. 拆 `ScanForm.jsx`
2. 拆 `AgentTimeline.jsx`
3. 拆 `ReportPreview.jsx`

### Phase 4：整理 i18n 与目录

1. 切分 `i18n.jsx`
2. 调整 import 路径
3. 合并重复文案与 selector 逻辑

## 11. 建议保留的兼容策略

为了避免一次性爆炸式修改，建议：

- 先新增模块，不立刻删除旧函数
- 在旧 hook / 旧页面中用“委托调用”方式逐步迁移
- 每拆完一块就跑一次：

```bash
cd web-console
npm run test:run
npm run build
```

## 12. 当前测试覆盖

当前前端测试较少，已看到：

- `web-console/src/components/__tests__/GlobalSearchBar.test.jsx`
- `web-console/src/pages/__tests__/Reports.test.jsx`

建议你在重构时优先补三类测试：

1. `useConsoleRuntime` 拆分后的 hook 单测
2. `Jobs` / `Reports` 容器组件测试
3. `ScanForm` payload builder 纯函数测试

## 13. 你可以直接从哪里开始

如果你准备自己动手，最推荐的入口顺序是：

### 方案 A：最稳

1. 新建 `src/api/*.js`
2. 把 `useConsoleRuntime.jsx` 中所有 `apiFetchWithAuth` 调用迁到这些 client
3. 再拆 auth/jobs/reports hooks

### 方案 B：收益最高

1. 先拆 `Jobs.jsx`
2. 把 analysis / artifact / CVE 请求逻辑抽成 hooks
3. 再回头拆 runtime

### 方案 C：UI 优先

1. 先拆 `ScanForm.jsx`
2. 再拆 `Reports.jsx`
3. 最后拆 runtime

如果目标是**长期可维护性**，优先选 **方案 A**。

