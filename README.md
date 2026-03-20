# AutoSecAudit

AutoSecAudit is now positioned as an agent-facing skill pack and CLI toolkit for safe, read-only reconnaissance and validation in authorized environments.

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
