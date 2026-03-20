# AutoSecAudit

AutoSecAudit 是一个面向企业内部蓝队的自动化安全审计框架，重点用于“发现（Discovery）”与“验证（Validation）”，默认遵循以下原则：

- 只读（Read-only）
- 非破坏（Non-destructive）
- 范围受限（Scope-bound）
- 可审计（Logging & Reporting）

框架同时支持传统 `CLI + Plugins` 模式与带策略约束的 `Agent` 编排模式。

## 当前功能总览

### 1. 运行模式

- `plugins`（默认）：线性插件执行模式，保持向后兼容
- `plan`：仅生成 `ActionPlan.json`，不执行 Agent 动作
- `agent`：执行完整 Agent 决策循环（计划 -> 策略校验 -> 调度执行 -> 状态更新）

### 2. 插件模式能力（`--mode plugins`）

当前内置插件（已注册）：

- `dns_discovery`
- `http_headers_validation`
- `cors_misconfiguration`
- `port_service_scan`
- `ssl_expiry_check`
- `tls_certificate_validation`

插件模式特性：

- 插件超时隔离
- 结构化日志（JSONL 操作事件）
- JSON / Markdown 报告输出
- 严格只读执行策略
- 支持通过 `--plugin-dir <dir>` 热加载额外 `.py` 插件目录（可重复传入）

### 3. Agent 编排能力（`--mode plan` / `--mode agent`）

核心组件：

- `AuditDecisionMaker`：根据 `scope / breadcrumbs / surface / history / budget` 生成行动计划
- `PolicyEngine`：执行工具白名单、目标来源、scope、预算、幂等、参数 schema 校验
- `ActionScheduler`：优先级队列、幂等去重、预算扣减、低预算限制
- `AgentOrchestrator`：主循环编排与状态/工件落盘

关键能力：

- Hardened Prompt（授权、范围、预算、幂等、工具白名单约束）
- fail-closed 域名解析校验（解析越界 IP 即阻断）
- 终态历史幂等去重（`completed / failed / error`）
- 低预算限制（`budget < 10` 时仅允许 `priority=0`）
- LLM 提示可选，调用失败自动降级，不影响主流程

### 4. 架构解耦（Tool Registry + BaseAgentTool）

Agent 工具调用已解耦为注册表架构，不再在 `orchestrator` 中硬编码 if/else 分发。

- 抽象接口：`autosecaudit/agent_core/tools.py`（`BaseAgentTool`）
- 注册表：`autosecaudit/agent_core/tool_registry.py`
- 内置适配：`autosecaudit/agent_core/builtin_tools.py`

新增 Agent 工具只需要：

1. 实现 `BaseAgentTool`
2. 使用 `@register_tool` 注册

无需修改 `orchestrator` 分发逻辑。

### 5. 内置 Agent 工具（白名单）

当前 Agent 内置并允许的工具：

- `nmap_scan`：保守端口/服务发现与版本探测
- `dynamic_crawl`：Playwright 动态爬取（含事件触发，受域名范围限制）
- `passive_config_audit`：被动配置泄露检查（GET only）
- `sql_sanitization_audit`：低风险 SQL 防护探测（最小请求、命中即停）
- `xss_protection_audit`：输出编码/反射审计（最小请求、命中即停）
- `dirsearch_scan`：保守目录/文件枚举（JSON 报告解析、只读内容发现）
- `nuclei_exploit_check`：Nuclei 模板扫描（JSONL 解析、参数白名单、安全过滤）

## 安全边界（重要）

- 仅允许对 `scope` 范围内目标执行动作
- 域名目标执行 fail-closed 解析校验（解析越界即阻断）
- 禁止破坏性操作、利用、爆破、DoS、状态变更
- SQL / XSS 审计仅允许低风险最小化探测，不做数据提取
- 所有外部命令执行使用安全方式（`subprocess` 列表参数，禁止 `shell=True`）
- 历史终态动作按幂等键去重

## 断点续跑（Resume）

Agent 模式支持从上次状态恢复：

- 参数：`--resume <state_file_or_session_dir>`
- 支持输入：
  - `agent_state.json` 文件路径
  - `output/agent/` 目录
  - `output/` 根目录（自动查找 `output/agent/agent_state.json`）

恢复后会继续复用：

- `history`
- `breadcrumbs`
- `surface`
- `budget_remaining`
- `iteration_count`

并在每次迭代结束后强制刷新状态文件，降低中断丢进度风险。

## LLM 接入（OpenClaw 风格）

框架已支持 OpenClaw 风格的模型接入方式：

- `provider/model` 模型标识（例如 `openai/gpt-4.1-mini`、`codex/your-model`）
- 主模型 + fallback 模型链
- 多 provider 配置（JSON）
- 统一 `LLMRouter` 路由层
- 失败自动降级为空建议（不打断 Agent）

支持的 provider 类型：

- `openai_sdk`
- `openai_compatible`
- `codex_oauth`

## Codex OAuth（浏览器登录）接入

支持“打开浏览器登录后即可接入模型”的方式（PKCE OAuth）：

- 启动本地回调监听（默认 `127.0.0.1:8765/callback`）
- 自动打开浏览器进行授权登录
- 回调接收授权码并换取访问令牌
- 写入缓存文件
- 写入 `auth-profiles.json`（OpenClaw 风格凭据池）
- 后续运行自动复用 token；若存在 `refresh_token` 可自动刷新

### Auth Profiles（OpenClaw 风格 Token Sink）

默认路径：

- `~/.autosecaudit/auth-profiles.json`

作用：

- 统一存储 OAuth token / refresh token / metadata
- 通过 `profile_id` 区分不同账号或环境
- 文件锁保护写入，降低并发覆盖风险

## 环境准备

### Python

- Python `>= 3.10`

### 可选依赖（按需）

- 使用 `openai_sdk` provider：`pip install openai`
- 使用 `dynamic_crawl`：`pip install playwright` 后执行 `python -m playwright install`
- 使用 `nmap_scan`：系统安装 `nmap`
- 使用 `dirsearch_scan`：系统安装 `dirsearch`（或使用下文容器镜像内置）
- 使用 `nuclei_exploit_check`：系统安装 `nuclei`

## 容器化部署（阿里云 ECS 推荐）

项目已提供：

- `Dockerfile`（内置 Python 运行环境、`nmap`、`dirsearch`）
- `docker-compose.yml`（包含 `config/output` 卷、代理环境变量、可选 OAuth 回调端口）

### 1. 在阿里云 ECS 安装 Docker / Compose

建议：

- ECS 运行 Linux（如 Ubuntu 22.04 / Alibaba Cloud Linux 3）
- 安全组默认无需开放入站端口（仅使用主动出站请求）
- 若需要 `codex_oauth` 浏览器登录回调，可临时开放/映射 `8765`（见下文说明）

### 2. 准备目录

```bash
mkdir -p config output wordlists
```

### 3. 构建镜像

默认镜像内置 `nmap + dirsearch`。若需要预装 `nuclei`，将 `docker-compose.yml` 中 `INSTALL_NUCLEI` 改为 `"1"`。
若需要 `dynamic_crawl`（Playwright）：

- 将 `INSTALL_PLAYWRIGHT` 设为 `"1"`（安装 Playwright Python 包）
- 仅在机器内存充足时再将 `INSTALL_PLAYWRIGHT_BROWSER` 设为 `"1"`（下载 Chromium 运行时）

```bash
docker compose build
```

### 4. 运行初始化向导（生成 `llm_router.json`）

```bash
docker compose run --rm autosecaudit init --output /workspace/config/llm_router.json
```

### 5. 执行审计任务（示例）

```bash
docker compose run --rm autosecaudit \
  --target https://example.com \
  --mode agent \
  --scope example.com \
  --budget 50 \
  --output /workspace/output \
  --llm-config /workspace/config/llm_router.json
```

### 6. Aliyun 场景下的 Codex OAuth 浏览器登录说明

- 服务器通常为无桌面环境，`--llm-oauth-browser-login` 不一定适合直接在 ECS 上使用
- 推荐方式：
  - 先在本地生成/缓存 OAuth token（或使用 `OPENAI_ACCESS_TOKEN` 环境变量）
  - 再通过环境变量/配置文件注入容器
- 若必须在服务器容器内走浏览器 OAuth：
  - 需要可用浏览器会话或 SSH 端口转发
  - `autosecaudit-web` 服务已映射 `8765:8765` 用于回调
  - 若使用 CLI 一次性容器执行浏览器 OAuth，请使用 `docker compose run --rm --service-ports autosecaudit ...` 临时开启端口映射（避免与 Web 服务长期端口冲突）

### 7. 启动 Web 控制台（交互式页面）

项目新增 `autosecaudit-web` 服务，会启动一个基于 `FastAPI + React + Vite` 的网页控制台（默认 `http://localhost:18080`），用于交互式发起 `agent / plan / plugins` 任务并查看实时日志、报告和输出工件。

```bash
docker compose up -d autosecaudit-web
```

打开浏览器访问：

```text
http://localhost:18080
```

说明：

- Web API 由 FastAPI 提供，自动文档可访问 `http://localhost:18080/docs`
- 前端构建源码位于 `web-console/`，构建产物会输出到 `autosecaudit/webapp/frontend_dist/`
- Web 控制台内部通过安全子进程调用 `autosecaudit.cli`（`shell=False`）
- Web 发起的任务输出默认写入 `output/web-jobs/`
- 任务、资产、计划任务、通知配置和审计事件会写入 SQLite 索引
- 用户、角色和 JWT 运行时配置也会写入同一份 SQLite 索引
- 任务队列和单任务日志支持 WebSocket 实时推送，SSE 保留为兼容回退通道
- 控制台已内置：
  - Jobs：任务发起、实时日志、工件查看
  - Assets：资产清单录入与一键发起扫描
  - Schedules：Cron 定时扫描
  - Reports：在线预览、同目标趋势、基线差异、HTML/Markdown/JSON 导出
  - Plugins：热加载目录配置、注册表清单、单插件/全量 reload

#### WebSocket 实时接口

- `/api/v1/jobs/ws`：推送任务队列变化与待审批队列
- `/api/v1/jobs/{job_id}/ws`：推送单任务状态、日志、分析刷新信号

#### E2E 烟测

- 安装浏览器运行时：`python -m playwright install chromium`
- 运行烟测：`pytest tests/e2e -q`
  - Users：管理员可创建/禁用账户并调整角色
  - Settings：通知配置、LLM 运行时和审计事件查看
- 若需要 LLM 配置，请在页面表单中填写容器内路径（例如 `/workspace/config/llm_router.json`）
- Web 端口可通过环境变量覆盖：`AUTOSECAUDIT_WEB_PORT=8088 docker compose up -d autosecaudit-web`
- 推荐开启 Web 鉴权：
  - 设置 `AUTOSECAUDIT_WEB_API_TOKEN=<strong_token>` 作为 bootstrap token
  - 设置 `AUTOSECAUDIT_WEB_BOOTSTRAP_TOKEN_TTL_SECONDS` 控制 bootstrap token 的有效期；首个用户创建后该 token 会自动失效
  - 或者直接在 `.env` / compose 环境变量中设置：
    - `AUTOSECAUDIT_WEB_DEFAULT_ADMIN_USERNAME`
    - `AUTOSECAUDIT_WEB_DEFAULT_ADMIN_PASSWORD`
    - `AUTOSECAUDIT_WEB_DEFAULT_ADMIN_DISPLAY_NAME`（可选）
  - `AUTOSECAUDIT_WEB_JWT_SECRET` 现在是必填项，且必须至少 32 个字符
  - Redis 模式请同时设置 `AUTOSECAUDIT_REDIS_PASSWORD`，并让 `AUTOSECAUDIT_REDIS_URL` 带上密码
  - `AUTOSECAUDIT_WEB_RATE_LIMIT_BACKEND=auto` 时会优先启用 Redis 共享限流；Redis 不可用时自动回退到内存限流
  - Compose 默认使用镜像内的非 root 用户 `autosec` 运行；如需兼容宿主机挂载权限，可覆盖 `AUTOSECAUDIT_CONTAINER_USER`
  - 当数据库里还没有任何用户时，Web 服务启动会自动创建这个默认管理员
  - 首次进入控制台时，用该 token 创建第一个 `admin`
  - 之后页面会通过 `/api/auth/login` 获取 `access_token + refresh_token`，并按 `admin / operator / viewer` 执行 RBAC
  - access token 过期后，前端会自动调用 `/api/auth/refresh` 获取新 token
  - SSE 和工件下载会自动携带同一份 token/JWT
  - 管理员现在可以在控制台中创建、冻结、解冻、删除其他账户
- Web 安全基线新增：
- `AUTOSECAUDIT_WEB_CORS_ALLOW_ORIGINS`：逗号分隔的允许来源列表；未设置时默认不开放跨域
- `AUTOSECAUDIT_WEB_ENABLE_METRICS`：是否暴露 Prometheus `/metrics` 端点，默认 `1`
- `AUTOSECAUDIT_WEB_ENFORCE_HTTPS`：设为 `1` 时将 HTTP 请求 307 重定向到 HTTPS
- `AUTOSECAUDIT_WEB_TRUST_PROXY_HEADERS`：设为 `1` 后信任 `X-Forwarded-Proto/Host`，适合放在 Nginx / Traefik 后面
- `AUTOSECAUDIT_WEB_HSTS_MAX_AGE_SECONDS` / `AUTOSECAUDIT_WEB_HSTS_INCLUDE_SUBDOMAINS` / `AUTOSECAUDIT_WEB_HSTS_PRELOAD`：控制 `Strict-Transport-Security`
- `AUTOSECAUDIT_WEB_RATE_LIMIT_AUTH_LOGIN`：登录/首个管理员创建限流，默认 `5/60`
- `AUTOSECAUDIT_WEB_RATE_LIMIT_AUTH_REFRESH`：token 刷新限流，默认 `20/300`
- `AUTOSECAUDIT_WEB_RATE_LIMIT_API_WRITE`：所有 `/api/*` 写操作限流，默认 `120/60`
  - `AUTOSECAUDIT_WEB_PASSWORD_MIN_LENGTH` / `AUTOSECAUDIT_WEB_PASSWORD_REQUIRE_MIXED_CASE` / `AUTOSECAUDIT_WEB_PASSWORD_REQUIRE_DIGIT` / `AUTOSECAUDIT_WEB_PASSWORD_REQUIRE_SPECIAL`
  - 默认密码策略为至少 `10` 位，且必须包含大小写字母和数字
- 通知配置支持：
  - `telegram`
  - `webhook`
  - `dingtalk`
  - `wecom`
- Web 服务新增任务保护阈值：
  - `AUTOSECAUDIT_WEB_MAX_JOBS`（默认 `200`）
  - `AUTOSECAUDIT_WEB_MAX_RUNNING_JOBS`（默认 `4`）
- 可观测性：
  - `GET /metrics`：Prometheus 指标端点，默认开启
  - 预置 Grafana 仪表盘模板位于 `ops/grafana/AutoSecAudit-Web-Dashboard.json`
  - 当前覆盖：HTTP 请求、任务状态、队列深度、资产数、计划任务数、用户数、审计事件窗口

### 8. 运行环境诊断（Doctor）

新增 `doctor` 命令用于启动前诊断：

```bash
python -m autosecaudit doctor
```

JSON 输出（便于 CI / 平台采集）：

```bash
python -m autosecaudit doctor --json
```

严格模式（有 warning 也返回非 0）：

```bash
python -m autosecaudit doctor --strict-warnings
```

## 快速开始

### 插件模式（默认）

```powershell
python -m autosecaudit.cli --target https://example.com --output .\output
```

仅执行指定插件：

```powershell
python -m autosecaudit.cli --target https://example.com --mode plugins --plugins dns_discovery,http_headers_validation
```

### 仅生成计划（不执行）

```powershell
python -m autosecaudit.cli --target https://example.com --mode plan --scope example.com --budget 50 --output .\output
```

### Agent 执行模式

```powershell
python -m autosecaudit.cli --target https://example.com --mode agent --scope example.com --budget 50 --max-iterations 3 --global-timeout 300 --output .\output
```

### 离线用户管理

```powershell
python -m autosecaudit users create-admin --username admin --password "AdminPass123!" --display-name "Security Admin"
python -m autosecaudit users list
python -m autosecaudit users freeze --username analyst
python -m autosecaudit users unfreeze --username analyst
python -m autosecaudit users delete --username analyst
```

### 断点续跑

```powershell
python -m autosecaudit.cli --target https://example.com --mode agent --resume .\output\agent --output .\output
```

## LLM 接入示例

### 示例 A：OpenAI SDK（API Key）

```powershell
$env:OPENAI_API_KEY="your_api_key"

python -m autosecaudit.cli `
  --target https://example.com `
  --mode plan `
  --scope example.com `
  --output .\output `
  --llm-model openai/gpt-4.1-mini `
  --llm-provider openai `
  --llm-provider-type openai_sdk
```

### 示例 B：OpenAI-compatible 网关 / 本地模型

```powershell
python -m autosecaudit.cli `
  --target https://example.com `
  --mode plan `
  --scope example.com `
  --output .\output `
  --llm-model local/qwen2.5 `
  --llm-provider local `
  --llm-provider-type openai_compatible `
  --llm-base-url http://localhost:11434/v1 `
  --llm-api-key-env DUMMY_KEY
```

### 示例 C：Codex OAuth（浏览器登录，CLI 参数）

以下 OAuth 参数需要替换成你实际接入服务提供的值：

```powershell
python -m autosecaudit.cli `
  --target https://example.com `
  --mode agent `
  --scope example.com `
  --output .\output `
  --llm-model codex/your-model-id `
  --llm-provider codex `
  --llm-provider-type codex_oauth `
  --llm-oauth-profile-id work `
  --llm-oauth-profiles-file .\auth-profiles.json `
  --llm-oauth-browser-login `
  --llm-oauth-authorize-url "https://<your-auth-server>/authorize" `
  --llm-oauth-token-url "https://<your-auth-server>/token" `
  --llm-oauth-client-id "<your_client_id>" `
  --llm-oauth-scope "openid" `
  --llm-oauth-scope "profile" `
  --llm-oauth-scope "offline_access"
```

### 示例 D：OpenClaw 风格 JSON 配置（推荐）

`llm_router.json` 示例：

```json
{
  "primary_model": "codex/your-model-id",
  "fallback_models": ["openai/gpt-4.1-mini"],
  "default_provider": "codex",
  "request": {
    "temperature": 0,
    "max_output_tokens": 1200
  },
  "providers": {
    "codex": {
      "type": "codex_oauth",
      "base_url": "https://api.openai.com/v1",
      "oauth_profile_id": "work",
      "oauth_profiles_file": ".\\auth-profiles.json",
      "oauth_auto_refresh": true,
      "oauth_browser_login": true,
      "oauth_authorize_url": "https://<your-auth-server>/authorize",
      "oauth_token_url": "https://<your-auth-server>/token",
      "oauth_client_id": "<your_client_id>",
      "oauth_scopes": ["openid", "profile", "offline_access"],
      "oauth_redirect_host": "127.0.0.1",
      "oauth_redirect_port": 8765,
      "oauth_redirect_path": "/callback",
      "oauth_cache_file": ".\\codex_oauth_token.json",
      "oauth_login_timeout_seconds": 180
    },
    "openai": {
      "type": "openai_sdk",
      "api_key_env": "OPENAI_API_KEY",
      "timeout_seconds": 300
    }
  }
}
```

运行：

```powershell
python -m autosecaudit.cli --target https://example.com --mode agent --scope example.com --output .\output --llm-config .\llm_router.json
```

## 常用参数

### 核心 Agent 参数

- `--target`
- `--mode plugins|plan|agent`
- `--scope`
- `--budget`
- `--max-iterations`
- `--global-timeout`
- `--resume`
- `--history-file`
- `--breadcrumbs-file`
- `--surface-file`
- `--no-llm-hints`

### LLM Router 参数

- `--llm-config`
- `--llm-model`
- `--llm-fallback`（可重复）
- `--llm-provider`
- `--llm-provider-type`
- `--llm-base-url`
- `--llm-timeout`
- `--llm-temperature`
- `--llm-max-output-tokens`

### Codex OAuth 参数（浏览器登录 / auth profiles）

- `--llm-oauth-browser-login`
- `--llm-oauth-authorize-url`
- `--llm-oauth-token-url`
- `--llm-oauth-client-id`
- `--llm-oauth-scope`（可重复）
- `--llm-oauth-redirect-host`
- `--llm-oauth-redirect-port`
- `--llm-oauth-redirect-path`
- `--llm-oauth-cache-file`
- `--llm-oauth-profile-id`
- `--llm-oauth-profiles-file`
- `--llm-oauth-no-auto-refresh`

## 输出产物

### 插件模式

- `output/logs/autosecaudit.log`
- `output/logs/operations.jsonl`
- `output/audit_report.json`
- `output/audit_report.md`

### Agent 模式

- `output/agent/ActionPlan.json`
- `output/agent/plans/iteration_XX_plan.json`
- `output/agent/agent_history.json`
- `output/agent/agent_state.json`
- `output/agent/blocked_actions.json`
- `output/agent/artifact_index.json`
- `output/agent/artifacts/*.json`
- `output/agent/agent_report.md`

## 项目结构（核心）

```text
autosecaudit/
  agent_core/
    orchestrator.py
    policy.py
    scheduler.py
    tool_registry.py
    tools.py
    builtin_tools.py
  auditors/
    sql_sanitization_auditor.py
    xss_protection_auditor.py
  crawlers/
    dynamic_web_crawler.py
  decision/
    audit_decision_maker.py
  integrations/
    llm_router.py
    auth_profiles.py
  tools/
    base_tool.py
    dirsearch_tool.py
    nmap_tool.py
    nuclei_tool.py
  plugins/
    dns_discovery.py
    http_header_validation.py
    tls_validation.py
  core/
    command.py
    logging_utils.py
    models.py
    report.py
    runner.py
```

## 已知限制 / 说明

- 本项目仅用于授权内网安全审计与靶场验证
- `codex_oauth` 浏览器登录需要你提供真实 OAuth 端点参数（`authorize_url` / `token_url` / `client_id`）
- 当前未单独提供 `auth login` 子命令，浏览器登录由 LLM 调用链按需触发
- 模型不可用或认证失败时，Agent 会自动降级为无 LLM hints 模式继续执行（安全优先）
