# AutoSecAudit Agent Invocation Skill

This file is written for agent runtimes such as OpenClaw, Codex, Claude Code, or any orchestration layer that needs to call AutoSecAudit as a subordinate reconnaissance tool.

AutoSecAudit is not a chat UI. Treat it as an execution skill that:
- accepts a target and scope
- chooses safe information-gathering actions
- emits structured evidence for follow-up reasoning

## Skill purpose

Use AutoSecAudit when the parent agent needs:
- attack-surface discovery
- safe exposure validation
- evidence correlation across DNS, HTTP, TLS, service banners, crawler output, and CVE signals
- resumable machine-readable outputs for later steps

Do not use it for:
- destructive exploitation
- persistence or payload delivery
- brute force or auth bypass
- state-changing actions
- unauthorized targets

## Invocation contract

### Required inputs

The parent agent should provide:
- `target`: one URL, hostname, IP, or CIDR seed
- `scope`: explicit scope boundary; use the target-derived domain/IP when possible
- `output_dir`: writable directory for artifacts

Optional inputs:
- `mode`: `plan` or `agent`
- `llm_config`: model-routing JSON file if LLM-assisted planning is desired
- `resume_path`: prior `output/agent` directory or `agent_state.json`
- `tools` or `skills`: only when the parent agent must hard-constrain the planner

### Preferred command patterns

#### Preflight

```bash
python -m autosecaudit doctor --json
```

Use this before planning or execution. Parse the JSON and block unsafe assumptions when required tools are missing.

#### Skill discovery

```bash
python -m autosecaudit skills list --json
python -m autosecaudit skills show nmap_scan --json
```

Use this when the parent agent needs to understand tool/skill metadata before constraining execution.

#### Planning

```bash
python -m autosecaudit \
  --target example.com \
  --mode plan \
  --scope example.com \
  --output ./output
```

Use `plan` for:
- first contact with a target
- human review gates
- explaining intended tool selection before running

#### Execution

```bash
python -m autosecaudit \
  --target https://example.com \
  --mode agent \
  --scope example.com \
  --max-iterations 6 \
  --global-timeout 900 \
  --output ./output
```

#### Resume

```bash
python -m autosecaudit \
  --target https://example.com \
  --mode agent \
  --resume ./output/agent \
  --output ./output
```

Use `resume` instead of restarting whenever the parent agent already has a prior state.

## Parent-agent decision rules

- Prefer URL targets for web-first audits.
- Prefer hostname/IP targets for service-discovery-first audits.
- Do not pass `--tools` or `--skills` unless the parent agent has a strong reason to constrain the planner.
- Let AutoSecAudit choose tools by default. The planner already reasons over scope, evidence, risk, and skill metadata.
- Treat `plan` output as intent, not ground truth.
- Treat `agent` output as evidence, not exploit proof.

## Output contract

The parent agent should read these files first:
- `output/agent/ActionPlan.json`
- `output/agent/agent_state.json`
- `output/agent/agent_history.json`
- `output/agent/agent_report.md`
- `output/agent/artifacts/*.json`

Most useful structured fields:
- `thought_stream`
- `evidence_graph`
- `cve_validation`
- `remediation_priority`
- `path_graph`
- `knowledge_context`

Recommended parent-agent use:
- read `agent_state.json` to recover current state
- read `evidence_graph` to avoid duplicate probing
- read `agent_history.json` to understand what was already attempted
- read `agent_report.md` when a human-readable summary is needed

## Optional dependency awareness

The parent agent should understand these optional tool dependencies:

- `nmap_scan` -> `nmap >= 7.80`
- `dirsearch_scan` -> official `dirsearch` Python implementation from upstream
- `nuclei_exploit_check` -> `nuclei 3.3.x`, tested baseline `3.3.10`
- `dynamic_crawl` -> `playwright` + Chromium runtime

If a dependency is missing:
- do not guess that the tool is usable
- either narrow the mission
- or report the missing dependency clearly before execution

## Optional dependency install hints

These are fallback installation hints the parent agent may surface to an operator:

### Linux

```bash
sudo apt-get update
sudo apt-get install -y nmap git curl unzip
git clone --depth=1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch
python -m pip install -r /opt/dirsearch/requirements.txt
python -m pip install playwright
python -m playwright install chromium
```

### Docker build toggles

```bash
INSTALL_NUCLEI=1 INSTALL_PLAYWRIGHT=1 INSTALL_PLAYWRIGHT_BROWSER=1 docker compose build
```

### Nuclei compatibility note

The current wrappers are validated against:
- `nuclei 3.3.10`

If the parent agent upgrades nuclei beyond `3.3.x`, it should assume output parsing may need re-validation.

## LLM guidance

An LLM is optional.

If an LLM is available:
- use it for planning and prioritization
- do not delegate scope enforcement or safety boundaries to the model
- keep temperature low for repeatable plans

Generate a config template with:

```bash
python -m autosecaudit init --output ./config/llm_router.json
```

## Failure handling

If the command exits non-zero:
- inspect logs under `output/logs/`
- inspect partial `agent_state.json` if it exists
- prefer resuming from preserved state rather than re-running blindly

If the environment cannot execute a tool:
- surface the missing dependency
- continue with narrower skills if still useful

## Safety boundaries

- authorized targets only
- read-only by default
- non-destructive validation only
- no brute force
- no auth bypass
- no persistence
- no destructive payloads
