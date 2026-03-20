# Network Security Information Gathering Tool for AI Agents

[![CI](https://github.com/lynolz163/autosecaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/lynolz163/autosecaudit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-0f172a)
![Skills](https://img.shields.io/badge/built--in%20skills-39-1d4ed8)
![Safety](https://img.shields.io/badge/default-read--only-059669)

AutoSecAudit is an agent-facing CLI and skill pack for safe, evidence-driven network security reconnaissance. It is built for Codex, OpenClaw, Claude Code, and similar orchestration agents that need a reusable tool for structured information gathering, scoped validation, and resumable evidence collection.

This repository is optimized for one job: let another agent call a single toolchain that can discover surface area, correlate signals, choose appropriate recon skills, and emit machine-readable outputs that a parent agent can reason over.

## Why download this repository

- Agent-native: ships with `39` built-in skills and a repository-level `SKILL.md`
- Safe by design: read-only, scope-bound, non-destructive validation
- Evidence-driven: outputs `thought_stream`, `evidence_graph`, `path_graph`, `cve_validation`, and remediation hints
- Resumable: continue a prior session instead of restarting from scratch
- Practical: works as a direct CLI, a subordinate skill, or a Dockerized helper
- Auditable: produces JSON, Markdown, and structured session artifacts for humans and agents

## What it is good at

- host and web surface discovery
- HTTP/TLS/header validation
- DNS and passive recon
- service and banner collection
- conservative crawler-assisted web enumeration
- CVE and template-based validation planning
- evidence correlation for later penetration-testing decisions

## What it intentionally does not do

- destructive exploitation
- brute force or password spraying
- persistence or payload delivery
- denial of service
- unauthorized target testing

If you need an agent-callable reconnaissance substrate that stays inside safe boundaries and leaves behind structured evidence, this repository is the right fit.

## Quick start

### 1. Verify the environment

```bash
python -m autosecaudit doctor --json
```

### 2. Discover available skills

```bash
python -m autosecaudit skills list
python -m autosecaudit skills show nmap_scan
python -m autosecaudit skills show nuclei_exploit_check
```

### 3. Generate a routing config when LLM planning is needed

```bash
python -m autosecaudit init --output ./config/llm_router.json
```

### 4. Run a planning pass

```bash
python -m autosecaudit \
  --target example.com \
  --mode plan \
  --scope example.com \
  --output ./output
```

### 5. Run the agent

```bash
python -m autosecaudit \
  --target https://example.com \
  --mode agent \
  --scope example.com \
  --max-iterations 6 \
  --global-timeout 900 \
  --output ./output
```

### 6. Resume a prior run

```bash
python -m autosecaudit \
  --target https://example.com \
  --mode agent \
  --resume ./output/agent \
  --output ./output
```

## Why agents prefer this tool

Most security tools either expose raw scanner output or force the parent agent to manually sequence many separate binaries. AutoSecAudit closes that gap:

- it already knows how to choose and combine reconnaissance skills
- it emits compact structured state instead of unbounded logs
- it keeps safety policy and scope enforcement inside the tool, not the parent prompt
- it preserves intermediate evidence so the parent agent can reason incrementally

The parent agent can stay focused on planning, review, and follow-up decisions while AutoSecAudit handles the repetitive collection layer.

## Primary output artifacts

Typical outputs:

- `output/logs/`
- `output/audit_report.json`
- `output/audit_report.md`
- `output/agent/ActionPlan.json`
- `output/agent/agent_state.json`
- `output/agent/agent_history.json`
- `output/agent/agent_report.md`
- `output/agent/artifacts/*.json`

High-value structured fields:

- `thought_stream`
- `evidence_graph`
- `cve_validation`
- `remediation_priority`
- `path_graph`
- `knowledge_context`

## Built-in skill pack

The repository ships with declarative skill manifests and human-readable instructions:

- `autosecaudit/skills/*.yaml`
- `autosecaudit/skills/<skill>/SKILL.md`
- `SKILL.md`

The root `SKILL.md` is the entry point for another agent that wants to call this repository as a subordinate recon skill.

## Optional dependencies and compatibility

These dependencies are optional. Install only the ones required by the skills you intend to use.

### Recommended compatibility baseline

- Python: `3.10+`, recommended `3.11`
- `nmap`: `7.80+`
- `nuclei`: tested baseline `3.3.10`, current local detection also supports repo-local binaries such as `.tools/nuclei/nuclei.exe`
- `dirsearch`: official Python implementation from upstream
- `playwright`: current Python package with Chromium runtime for `dynamic_crawl`
- OpenAI SDK: optional, only when using `openai_sdk` model routing

### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y nmap git curl unzip

git clone --depth=1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch
python -m pip install -r /opt/dirsearch/requirements.txt

curl -fsSL -o /tmp/nuclei.zip \
  https://github.com/projectdiscovery/nuclei/releases/download/v3.3.10/nuclei_3.3.10_linux_amd64.zip
sudo unzip -q /tmp/nuclei.zip -d /usr/local/bin
sudo chmod +x /usr/local/bin/nuclei

python -m pip install playwright
python -m playwright install chromium
```

### macOS

```bash
brew install nmap

git clone --depth=1 https://github.com/maurosoria/dirsearch.git ./dirsearch
python3 -m pip install -r ./dirsearch/requirements.txt

python3 -m pip install playwright
python3 -m playwright install chromium
```

### Windows

```powershell
winget install Insecure.Nmap
git clone --depth=1 https://github.com/maurosoria/dirsearch.git .\dirsearch
py -3 -m pip install -r .\dirsearch\requirements.txt
py -3 -m pip install playwright
py -3 -m playwright install chromium
```

For Windows `nuclei`, either:

- place `nuclei.exe` on `PATH`
- set `AUTOSECAUDIT_NUCLEI_BIN`
- or place the binary at `.tools/nuclei/nuclei.exe`

### Docker build toggles

```bash
INSTALL_NUCLEI=1 INSTALL_PLAYWRIGHT=1 INSTALL_PLAYWRIGHT_BROWSER=1 docker compose build
```

### Runtime validation rule

After installing any optional dependency:

```bash
python -m autosecaudit doctor --json
```

Do not assume a tool is usable just because a binary exists. The wrappers depend on output shape, permissions, and runtime behavior.

## Docker

A minimal CLI-oriented container flow is available:

```bash
cp .env.example .env
docker compose build
docker compose run --rm autosecaudit --help
```

## For humans

Use AutoSecAudit when you want a conservative, auditable recon engine that produces outputs another analyst or another agent can continue from.

## For agents

Treat this repository as a reusable information-gathering primitive. Read `SKILL.md`, run `doctor`, prefer `plan` before `agent`, and consume `agent_state.json` plus `evidence_graph` for follow-up reasoning.

## Safety boundaries

AutoSecAudit is for authorized use only.

It is intentionally designed around:

- read-only operations
- scope-bound execution
- non-destructive validation
- auditable outputs
