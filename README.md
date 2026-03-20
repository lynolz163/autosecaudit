# Network Security Information Gathering Tool for AI Agents

AutoSecAudit is now positioned as a network security information gathering tool for AI agents, delivered as an agent-facing skill pack and CLI toolkit for safe, read-only reconnaissance and validation in authorized environments.

## What this repository is now

- a reusable CLI for evidence-driven information collection
- a packaged library of built-in audit skills under `/autosecaudit/skills`
- a planning and execution engine that can be called by another agent
- a reporting layer that produces structured and human-readable outputs

## What was removed

The repository no longer treats the Web console and frontend as a primary product surface.
This codebase is now focused on:
- CLI execution
- skill discovery
- tool orchestration
- evidence correlation
- report generation

## Core commands

### Environment readiness

```bash
python -m autosecaudit doctor
python -m autosecaudit doctor --json
```

### Skill discovery

```bash
python -m autosecaudit skills list
python -m autosecaudit skills show nmap_scan
python -m autosecaudit skills show dirsearch_scan
```

### Generate model-routing config

```bash
python -m autosecaudit init --output ./config/llm_router.json
```

### Plan-only run

```bash
python -m autosecaudit \
  --target example.com \
  --mode plan \
  --scope example.com \
  --output ./output
```

### Evidence-focused agent run

```bash
python -m autosecaudit \
  --target https://example.com \
  --mode agent \
  --scope example.com \
  --max-iterations 6 \
  --global-timeout 900 \
  --output ./output
```

### Resume a prior run

```bash
python -m autosecaudit \
  --target https://example.com \
  --mode agent \
  --resume ./output/agent \
  --output ./output
```

## Skill-pack usage

The repository ships with skill manifests and human-readable skill guides under:
- `/autosecaudit/skills/*.yaml`
- `/autosecaudit/skills/<skill>/SKILL.md`

A repository-level reference skill guide is also available at:
- `/SKILL.md`

Use that guide when another agent should treat AutoSecAudit as a reusable reconnaissance skill.

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

Important analysis structures:
- `thought_stream`
- `evidence_graph`
- `cve_validation`
- `remediation_priority`
- `path_graph`
- `knowledge_context`

## External tools

Optional but useful:
- `nmap`
- `dirsearch`
- `nuclei`
- `playwright` plus browser runtime for dynamic crawling

The `doctor` command will tell you what is missing before you run a task.

## Optional dependency install and compatibility

These dependencies are not required for every run. Install only the ones needed by the tools you want the agent to use.

### Recommended compatibility baseline

- Python: `3.10+`, recommended `3.11`
- `nmap`: `7.80+`
- `nuclei`: tested baseline `3.3.10`, keep within `3.3.x` unless you revalidate templates and output parsing
- `dirsearch`: use the official Python implementation from the upstream repository
- `playwright`: current Python package with Chromium runtime for `dynamic_crawl`
- OpenAI SDK: optional, only when using `openai_sdk` routing

### Local install examples

#### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y nmap git curl unzip

# dirsearch
git clone --depth=1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch
python -m pip install -r /opt/dirsearch/requirements.txt

# nuclei 3.3.10
curl -fsSL -o /tmp/nuclei.zip \
  https://github.com/projectdiscovery/nuclei/releases/download/v3.3.10/nuclei_3.3.10_linux_amd64.zip
sudo unzip -q /tmp/nuclei.zip -d /usr/local/bin
sudo chmod +x /usr/local/bin/nuclei

# playwright for dynamic crawling
python -m pip install playwright
python -m playwright install chromium
```

#### macOS (Homebrew)

```bash
brew install nmap
brew install --cask chromedriver || true

git clone --depth=1 https://github.com/maurosoria/dirsearch.git ./dirsearch
python3 -m pip install -r ./dirsearch/requirements.txt

python3 -m pip install playwright
python3 -m playwright install chromium
```

#### Windows

```powershell
winget install Insecure.Nmap
git clone --depth=1 https://github.com/maurosoria/dirsearch.git .\dirsearch
py -3 -m pip install -r .\dirsearch\requirements.txt
py -3 -m pip install playwright
py -3 -m playwright install chromium
```

For `nuclei` on Windows, download the matching `3.3.10` release archive from ProjectDiscovery and place `nuclei.exe` on `PATH`.

### Container build toggles

The Docker image already supports optional downloads through build arguments:

- `INSTALL_NUCLEI=1`
- `NUCLEI_VERSION=3.3.10`
- `INSTALL_PLAYWRIGHT=1`
- `INSTALL_PLAYWRIGHT_BROWSER=1`

Example:

```bash
INSTALL_NUCLEI=1 INSTALL_PLAYWRIGHT=1 INSTALL_PLAYWRIGHT_BROWSER=1 docker compose build
```

### Runtime validation rule

After installing any optional dependency, re-run:

```bash
python -m autosecaudit doctor --json
```

Do not assume a tool is usable just because the binary exists. The wrappers depend on output shape, permissions, and browser/runtime availability.

## Docker

A minimal CLI-only container flow remains available:

```bash
cp .env.example .env
docker compose build
docker compose run --rm autosecaudit --help
```

## Safety boundaries

AutoSecAudit is for authorized use only.

Do not use it for:
- destructive exploitation
- brute force
- denial of service
- persistence
- unauthorized targets

The project is intentionally designed around:
- read-only operations
- scope-bound execution
- non-destructive validation
- auditable outputs
