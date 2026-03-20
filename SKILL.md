# AutoSecAudit Agent Skill

Use this repository when a parent agent needs a subordinate skill for safe network security information gathering, scoped validation, and resumable evidence collection.

This skill is written for agent runtimes such as Codex, OpenClaw, Claude Code, and similar orchestration systems. It is a structured execution substrate that another agent can call to gather evidence and continue reasoning from machine-readable artifacts.

## What this skill provides

- attack-surface discovery from a single seed target
- evidence-driven planning and collection
- scoped, read-only validation
- resumable sessions and durable state
- outputs that are useful to both humans and agents

## When another agent should call this skill

Call AutoSecAudit when the parent agent needs:

- passive or conservative recon against an authorized target
- structured evidence before proposing a deeper penetration-testing step
- a bounded toolchain instead of manually sequencing many separate binaries
- repeatable outputs for follow-up analysis, verification, or reporting

Do not call AutoSecAudit for:

- destructive exploitation
- persistence
- brute force
- auth bypass
- state-changing actions
- unauthorized targets

## Why this skill is attractive to parent agents

Compared with calling raw binaries directly, AutoSecAudit gives the parent agent:

- one entry point instead of many ad hoc tool wrappers
- consistent scope and safety policy
- built-in tool selection and evidence correlation
- resumable state for long-running investigations
- compact structured outputs such as `evidence_graph`, `thought_stream`, and `cve_validation`

This reduces prompt complexity and makes downstream reasoning easier.

## Required inputs

The parent agent should provide:

- `target`: one URL, hostname, IP, or CIDR seed
- `scope`: explicit scope boundary; use a target-derived domain/IP when possible
- `output_dir`: writable location for artifacts

Optional inputs:

- `mode`: `plan` or `agent`
- `llm_config`: routing JSON for LLM-assisted planning
- `resume_path`: prior `output/agent` directory or `agent_state.json`
- `tools` or `skills`: only when the parent agent must hard-constrain execution

## Preferred invocation sequence

### 1. Preflight

```bash
python -m autosecaudit doctor --json
```

The parent agent should run this first and inspect:

- missing binaries
- invalid environment assumptions
- unsupported LLM routing configuration

### 2. Discover skill inventory when needed

```bash
python -m autosecaudit skills list --json
python -m autosecaudit skills show nmap_scan --json
```

Use this only when the parent agent needs to understand the shipped skill metadata or explain why a particular tool was chosen.

### 3. Plan

```bash
python -m autosecaudit \
  --target example.com \
  --mode plan \
  --scope example.com \
  --output ./output
```

Use `plan` when:

- the parent agent wants review before execution
- the mission is new and the target is not yet understood
- a human operator should approve the next step

### 4. Execute

```bash
python -m autosecaudit \
  --target https://example.com \
  --mode agent \
  --scope example.com \
  --max-iterations 6 \
  --global-timeout 900 \
  --output ./output
```

### 5. Resume

```bash
python -m autosecaudit \
  --target https://example.com \
  --mode agent \
  --resume ./output/agent \
  --output ./output
```

If a prior session exists, the parent agent should prefer resume over restarting.

## Parent-agent operating rules

- Prefer URL targets for web-first missions.
- Prefer hostname or IP targets for service-first discovery.
- Do not pass `--tools` or `--skills` unless strict determinism is required.
- Let AutoSecAudit choose tools by default. It already reasons over scope, evidence, safety, and built-in skill metadata.
- Treat `plan` output as intended action, not proof.
- Treat `agent` output as evidence, not exploitation.

## Output contract

The parent agent should read these files first:

- `output/agent/ActionPlan.json`
- `output/agent/agent_state.json`
- `output/agent/agent_history.json`
- `output/agent/agent_report.md`
- `output/agent/artifacts/*.json`

The most useful structured fields are:

- `thought_stream`
- `evidence_graph`
- `cve_validation`
- `remediation_priority`
- `path_graph`
- `knowledge_context`

Recommended downstream use:

- read `agent_state.json` to recover exact current state
- read `evidence_graph` to avoid redundant collection
- read `agent_history.json` to understand attempted actions
- read `agent_report.md` when a human-readable summary is needed

## Optional dependency awareness

Some skills require external tools. The parent agent should not assume availability without checking `doctor`.

Common mappings:

- `nmap_scan` -> `nmap >= 7.80`
- `dirsearch_scan` -> official `dirsearch` Python implementation
- `nuclei_exploit_check` -> `nuclei 3.3.x`, validated baseline `3.3.10`
- `dynamic_crawl` -> `playwright` plus Chromium runtime

For `nuclei`, AutoSecAudit can resolve the binary from:

- `PATH`
- `AUTOSECAUDIT_NUCLEI_BIN`
- `.tools/nuclei/nuclei.exe`

If a dependency is missing, the parent agent should either:

- narrow the mission
- install the dependency
- or explain clearly why that skill cannot run

## LLM guidance

LLM planning is optional.

If an LLM is used:

- use it for prioritization and planning only
- do not delegate scope enforcement or safety boundaries to the model
- keep temperature low for repeatable plans

Generate a config template with:

```bash
python -m autosecaudit init --output ./config/llm_router.json
```

## Failure handling

If execution exits non-zero:

- inspect `output/logs/`
- inspect partial `agent_state.json` if present
- prefer resuming from preserved state instead of blindly re-running

If the environment cannot execute a tool:

- surface the missing dependency explicitly
- continue with narrower skills if still useful

## Safety boundaries

- authorized targets only
- read-only by default
- non-destructive validation only
- no brute force
- no auth bypass
- no persistence
- no destructive payloads
