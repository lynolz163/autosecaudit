# AutoSecAudit 产品升级规划（校正版）

文档状态：V1.1  
日期：2026-03-02  
视角：产品经理 + 架构负责人

## 1. 执行摘要

AutoSecAudit 当前已经完成了从 CLI 到 Web 控制台的第一阶段产品化，但本质仍是“单机可用的安全自动化工作台”，还不是企业级平台。升级方向应当明确为：

`个人/小团队工具 -> 团队协作平台 -> 企业级私有化安全审计平台`

当前最应该做的不是一次性把 FastAPI、React、Redis、PostgreSQL、RBAC 全部堆上去，而是先完成三件事：

1. 把 `webapp` 从“单文件 HTTP 服务 + 内存任务管理”升级为“可扩展的服务层 + 持久化索引 + 实时推送”。
2. 把前端从“表单 + 轮询日志页”升级为“任务中心 + 报告中心 + 仪表盘”。
3. 保持 CLI / 文件输出兼容，避免破坏现有用户习惯和自动化脚本。

## 2. 基于仓库现状的诊断

以下判断基于当前仓库实际实现，而不是理想化假设。

| 维度 | 当前现状 | 判定 |
| --- | --- | --- |
| Web 服务 | `autosecaudit/webapp/server.py` 基于 `ThreadingHTTPServer`，文件约 1196 行，API / OAuth / 静态资源 / JobManager 全耦合在一个文件中 | 架构已到重构点 |
| 前端 | `autosecaudit/webapp/static/index.html` 约 318 行，`app.js` 约 617 行，Vanilla JS，日志依赖 2 秒轮询 | 功能可用，扩展性差 |
| 任务并发 | `JobManager` 使用线程 + 子进程，运行中任务上限默认 4（`AUTOSECAUDIT_WEB_MAX_RUNNING_JOBS`） | 单机可用，无法平滑扩容 |
| 存储 | 任务、日志、报告、工件主要落到 `output/` 文件系统；Web 任务状态保存在内存 | 缺少查询、聚合、重启恢复能力 |
| 认证 | Web API 当前只有可选单一 Token 鉴权 | 不满足团队协作 |
| 实时能力 | 无 WebSocket / SSE；日志通过 `/api/jobs/{id}/logs` 拉取 | 用户体验瓶颈 |
| 插件体系 | `core/registry.py` 为静态注册，新增插件需随进程启动加载 | 缺少热加载和版本元数据 |
| 扫描工具 | Docker 已可选预装 `nmap` / `dirsearch` / `nuclei` / `playwright` | 基础具备，但镜像管理还可优化 |
| 报告 | 已有 Markdown / JSON / HTML 工件，但缺少趋势、差异、汇总视图 | 数据价值未释放 |
| 通知 | `integrations/notifier.py` 已有通用 Webhook 与 Telegram 抽象 | 能力存在，但尚未产品化接入 |
| 前端升级基础 | `examples/ui_dashboard` 已有 React + Tailwind 的后端对齐样例 | 不需要从零设计 |

### 现阶段最关键的问题

1. Web 层把 HTTP、鉴权、OAuth、任务调度、日志管理全部揉在一个文件里，后续每加一个能力都会继续放大复杂度。
2. Web 任务状态保存在内存，服务重启后列表和状态无法可靠恢复，不具备运营能力。
3. 前端没有组件边界，也没有实时通道，导致任务中心、报告中心、资产管理都很难演进。
4. 当前企业化短板不在“没有 Redis”，而在“没有清晰的领域模型和持久化索引层”。

### 现存立即问题

- `CodexWebAuthManager.get_status()` 存在重复 `return` 与死代码，属于应立即修复的低风险问题。
- `doctor` 目前只检查 Python、工作目录、工具可用性、Web Token、LLM 配置，缺少端点连通性与工具版本识别。

## 3. 升级原则

### 3.1 兼容优先

- 保留现有 CLI 参数、`output/` 目录结构、Markdown/JSON/HTML 报告输出。
- 数据库先做“索引层”，不是先把所有工件塞进数据库。

### 3.2 分层优先于换框架

FastAPI 很重要，但真正的关键不是“把 HTTPServer 换成 FastAPI”，而是先把下面几个层次拆出来：

- `JobService`
- `ArtifactService`
- `ReportService`
- `AuthService`
- `RealtimeLogService`

如果不先拆服务层，直接迁移框架，只会把单文件问题搬到新框架里。

### 3.3 先 SQLite，后 PostgreSQL

- 单机和私有化 PoC 场景，SQLite 足够支撑。
- 等到出现多用户、多节点、复杂查询，再引入 PostgreSQL。

### 3.4 先内嵌任务池，后 Celery/Redis

- P0 不建议引入 Celery + Redis。
- 先把任务状态持久化、调度接口、取消语义、日志流标准化做好。
- 只有在“跨节点调度”成为真实需求时，再升级为分布式队列。

### 3.5 实时推送先做 SSE，WebSocket 作为增强

当前日志场景本质是服务端单向推送，SSE 更轻、更容易落地、更适合先期兼容；WebSocket 可以在 React 前端稳定后补齐。

## 4. 目标架构

```text
React + Vite Web Console
        |
        v
FastAPI Gateway
  |- REST API
  |- SSE / WebSocket
  |- Auth / RBAC
        |
        v
Application Services
  |- JobService
  |- AssetService
  |- ReportService
  |- PluginService
        |
        +--> SQLite / PostgreSQL
        |
        +--> Filesystem Artifacts
        |
        +--> Local Worker Pool / Celery Workers
        |
        +--> nmap / nuclei / dirsearch / playwright / LLM providers
```

## 5. 分阶段路线图

## P0：平台底座重构（4-6 周）

目标：把现有单机版升级为“可维护、可扩展、可恢复”的平台底座。

### P0-1 后端服务化

- 用 FastAPI 替换 `ThreadingHTTPServer`。
- 保持现有 `/api/jobs`、`/api/jobs/{id}` 等接口路径兼容。
- 抽离 `JobService` 与 `CodexAuthService`，结束 `server.py` 超大单文件。
- 增加 SSE 日志流接口：`/api/jobs/{job_id}/stream`。
- 后续预留 WebSocket：`/ws/jobs/{job_id}/logs`。

### P0-2 持久化索引层

新增最小表结构：

- `jobs`
- `findings`
- `artifacts`
- `audit_log`

原则：

- 文件仍然写入 `output/`。
- 数据库只存索引、状态、统计、查询字段。
- Web 控制台重启后可恢复历史任务列表与状态。

### P0-3 前端重构

从 `examples/ui_dashboard` 启动 React + Vite 控制台，而不是从空白项目开始。

首批页面：

- `Dashboard`
- `Jobs`
- `Reports`
- `Settings`

首批组件：

- `LogViewer`：SSE 实时日志、ANSI 颜色、关键字搜索
- `JobStatusBadge`：状态徽章 + 阶段进度
- `ReportPreview`：Markdown 在线预览
- `MetricCard`：任务数、成功率、发现数、近 7 天趋势

### P0-4 本周可并行落地的小修小补

- 修复 `get_status()` 死代码问题。
- 在现有 Web 服务上先补一版 SSE，降低前端等待成本。
- 增强 `doctor`：
  - LLM 端点连通性检查
  - `nmap` / `nuclei` / `dirsearch` 版本检测
- 补充高价值插件：
  - `ssl_expiry_check`
  - `cors_misconfiguration`
  - `port_service_scan`

### P0 验收标准

- Web 服务重启后能恢复任务索引。
- 单机默认支持 20 个并发任务排队，运行并发可配置。
- 日志推送端到端延迟小于 500ms。
- 前端不再依赖 2 秒轮询作为主要日志通道。

## P1：能力扩展（6-10 周）

目标：从“任务执行器”升级为“团队可协作的安全审计工作台”。

### P1-1 资产管理

- 目标域名 / IP / URL 清单 CRUD
- 标签、分组、负责人字段
- 从资产清单批量触发扫描

### P1-2 定时扫描

- Cron 表达式
- 周期任务模板
- 失败重试与通知策略

### P1-3 通知产品化

当前不是“完全没有通知”，而是“没有接入工作流”。

P1 需要把通知绑定到具体事件：

- 扫描完成
- HIGH / CRITICAL 发现
- 扫描失败 / 超时
- Agent 预算耗尽

首批渠道：

- 自定义 Webhook
- Slack Webhook
- 钉钉机器人
- 企业微信机器人
- 邮件 SMTP

### P1-4 报告中心

- 单次报告在线查看
- 同目标历史趋势
- 两次扫描差异比对
- 漏洞严重度统计

### P1-5 插件体系升级

在插件 ABI 稳定之后，再引入：

- YAML manifest
- 版本元数据
- 风险级别
- 热加载 / 重载

这里不建议把“插件商店”放进 P1 前半段，优先级低于资产、定时、报告。

## P2：企业化（10-16 周）

目标：从“团队工具”升级为“企业级私有化平台”。

### P2-1 RBAC 与审计

- `Admin`
- `Operator`
- `Viewer`

能力：

- JWT 认证
- 用户管理
- 审计日志查询
- 可选 LDAP / SSO

### P2-2 数据层升级

- SQLite -> PostgreSQL
- 任务、发现、资产、审计记录集中管理
- 为多节点 worker 做准备

### P2-3 分布式执行

- 只有在单节点 worker 明显不够时，再引入 Celery + Redis
- 支持优先级队列、隔离 worker、横向扩容

### P2-4 报告导出与漏洞生命周期

- HTML / PDF 导出
- 漏洞状态流转：新增、确认、修复、忽略、复测
- 面向管理层的汇总报表

## 6. 关键架构决策

| 决策点 | 推荐方案 | 结论 |
| --- | --- | --- |
| Web 框架 | FastAPI | 采用 |
| 实时推送 | SSE 先行，WebSocket 增强 | 采用 |
| 前端 | React + Vite | 采用 |
| 数据库 | SQLite 起步，PostgreSQL 扩展 | 采用 |
| 任务队列 | 进程内任务池先行 | 采用 |
| 分布式队列 | Celery + Redis | 延后到 P2 |
| 认证 | JWT + RBAC | P2 实施 |
| 插件格式 | Python 模块 + YAML manifest | P1 实施 |

## 7. 本周落地建议

如果只做一周冲刺，建议收敛为下面四项，避免“战略很大、交付很散”：

1. 修复 `server.py` 已知 bug，并补 SSE 日志流。
2. 为 Web 任务引入 SQLite 索引，至少先落 `jobs` 表。
3. 用 React + Vite 搭一个新的控制台壳，先接 `Jobs` 和 `Reports` 两页。
4. 扩展 `doctor` 与两个高价值插件，先提升可用性和可见度。

## 8. 非功能目标

| 指标 | 目标 |
| --- | --- |
| API 响应时间 | P99 < 200ms（不含扫描任务执行时间） |
| 日志实时性 | < 500ms |
| 任务排队容量 | 默认 20 |
| 运行并发 | 默认 4，支持配置提升 |
| 数据安全 | API Key / Token 不落日志 |
| 可恢复性 | Web 服务重启后保留任务索引 |

## 9. 明确不在 P0 做的事

以下内容方向没有错，但不适合作为当前第一波升级重点：

- 一上来就做多租户
- 一上来就做 PostgreSQL + Redis + Celery 全套
- 一上来就把工件完全数据库化
- 一上来就做插件商店
- 一上来就做 LDAP / SSO

先把“服务分层、任务持久化、实时日志、前端组件化”做扎实，后面的企业化才不会返工。
