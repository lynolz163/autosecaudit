# AutoSecAudit

> Safe, read-only security discovery and validation for authorized environments.

AutoSecAudit 是一个面向授权环境的安全发现与验证框架，适合内部蓝队、平台安全团队、实验环境与靶场工作流。它把传统插件式执行、受约束的 Agent 编排、结构化报告输出，以及基于 FastAPI + React 的 Web 控制台放在同一套代码库里。

项目当前处于活跃开发阶段，设计目标始终围绕四个关键词：

- `read-only`
- `scope-bound`
- `non-destructive`
- `auditable`

## Why AutoSecAudit

- 支持 `plugins`、`plan`、`agent` 三种运行模式，既能做传统流程，也能做受策略约束的自动编排。
- 提供 Web 控制台，可管理 Jobs、Assets、Reports、Schedules、Plugins 和用户权限。
- 默认强调安全边界，避免把“自动化”演变成无约束的破坏性扫描。
- 报告和工件可落盘为 JSON、Markdown、HTML，便于审计、复盘和二次处理。
- LLM 规划是可选增强，不是强依赖；不可用时会回退到更保守的执行路径。

## Core Capabilities

### Execution Modes

- `plugins`: 线性插件执行，适合快速发现和兼容现有流程。
- `plan`: 仅生成 `ActionPlan.json`，不执行 Agent 动作。
- `agent`: 在预算、范围、策略和工具白名单约束下执行完整编排循环。

### Built-in Coverage

- 发现类能力：DNS、HTTP Header、CORS、端口与服务、SSL/TLS、技术栈识别、Source Map、JS Endpoint、`security.txt` 等。
- Agent 校验能力：`nmap`、动态爬取、被动配置审计、`dirsearch`、`nuclei` 模板检查、CVE 验证、最小化 SQL/XSS/Header/Cookie 审计等。
- 运行辅助能力：`doctor` 环境诊断、断点续跑、结构化日志、工件索引、用户管理 CLI。

### Web Console

- 基于 FastAPI 提供 API 与实时任务接口。
- 前端源码位于 [`web-console/`](./web-console)，构建产物输出到 [`autosecaudit/webapp/frontend_dist/`](./autosecaudit/webapp/frontend_dist)。
- 支持 JWT/RBAC、任务队列、实时日志、报告预览与导出、计划任务、插件热加载等。

## Safety Model

AutoSecAudit 不是一个“任意攻击框架”。默认安全边界包括：

- 仅用于已获授权的目标、内网环境或靶场。
- 所有动作都应受 `--scope` 约束。
- 禁止破坏性利用、DoS、爆破、任意状态变更和未授权数据提取。
- 高风险 CVE / PoC 流程需要显式开关或审批信号。
- 工具执行受策略引擎、参数校验和白名单控制。
- 外部命令调用采用更安全的子进程方式，不依赖 `shell=True`。

## Quick Start

### 1. Local Install

```bash
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -e ".[dev]"
python -m autosecaudit doctor
```

可选外部依赖：

- `nmap`：端口与服务发现
- `nuclei`：模板化安全检查
- `playwright`：动态爬取；安装后还需要执行 `python -m playwright install chromium`
- `redis`：Web 部署中的共享缓存 / 限流后端，可选

### 2. Run The CLI

插件模式：

```bash
python -m autosecaudit \
  --target https://example.com \
  --mode plugins \
  --output ./output
```

只生成计划：

```bash
python -m autosecaudit \
  --target https://example.com \
  --mode plan \
  --scope example.com \
  --budget 50 \
  --output ./output
```

受约束 Agent 模式：

```bash
python -m autosecaudit \
  --target https://example.com \
  --mode agent \
  --scope example.com \
  --budget 50 \
  --max-iterations 3 \
  --global-timeout 300 \
  --report-lang zh-CN \
  --output ./output
```

断点续跑：

```bash
python -m autosecaudit \
  --target https://example.com \
  --mode agent \
  --resume ./output/agent \
  --output ./output
```

### 3. Generate LLM Config (Optional)

生成 LLM Router 配置模板：

```bash
python -m autosecaudit init --output ./config/llm_router.json
```

当前支持的 Provider 类型：

- `openai_sdk`
- `openai_compatible`
- `codex_oauth`

如果你不需要 LLM 规划，也可以直接使用 `plugins` 模式，或在 `plan/agent` 模式下关闭提示增强。

### 4. Launch The Web Console

项目已经包含打包后的前端静态资源，因此安装完 Python 依赖后可以直接启动 Web 模式：

```bash
python -m autosecaudit web --host 0.0.0.0 --port 8080 --workspace .
```

打开浏览器访问：

```text
http://localhost:8080
```

如果你需要预先创建管理员用户：

```bash
python -m autosecaudit users create-admin \
  --username admin \
  --password "ChangeMe123!" \
  --display-name "Security Admin"
```

## Docker Compose

如果你想更快地启动完整 Web 环境，推荐直接使用 Compose：

```bash
cp .env.example .env
docker compose build
docker compose up -d autosecaudit-web
```

说明：

- 生产或公网暴露前，请先修改 [`.env.example`](./.env.example) 中对应的默认密码和密钥项。
- Compose 配置位于 [`docker-compose.yml`](./docker-compose.yml)。
- 使用模板 `.env` 时，Web 端口默认是 `18080`。
- Web 发起的任务默认输出到 `output/web-jobs/`。

## Outputs

典型输出包括：

- `output/logs/`：运行日志与 JSONL 操作记录
- `output/audit_report.json` / `output/audit_report.md`：插件模式报告
- `output/agent/`：Agent 计划、状态、历史、工件索引和报告
- `output/web-jobs/`：Web 控制台触发的任务输出

## Development

### Python

```bash
pytest -q
```

### Frontend

```bash
cd web-console
npm install
npm run test:run
npm run build
```

`vite build` 会把前端构建结果输出到 `autosecaudit/webapp/frontend_dist/`，供 Web 服务直接托管。

## Extending AutoSecAudit

- 使用 `--plugin-dir <dir>` 热加载额外插件。
- 在 `autosecaudit/agent_core/` 下基于工具注册表扩展 Agent 工具。
- 在 `autosecaudit/skills/` 下添加技能包与说明文档。
- 参考 [`docs/skill-packaging.md`](./docs/skill-packaging.md) 和 [`docs/frontend-refactor-handoff.md`](./docs/frontend-refactor-handoff.md)。

## Repository Layout

```text
autosecaudit/   core runtime, plugins, tools, web backend
web-console/    React + Vite frontend source
tests/          unit and e2e tests
docs/           project notes and handoff docs
ops/            observability assets
```

## Important Notice

AutoSecAudit 仅适用于授权的安全审计、内部验证、实验环境和靶场用途。

- 请不要对第三方系统执行未获许可的扫描或验证。
- 请在实际运行前明确 `scope`、预算和安全等级。
- 请在公开部署前替换默认口令、JWT Secret、Redis 密码和所有访问令牌。

