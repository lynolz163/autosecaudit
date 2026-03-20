# AutoSecAudit Skill Pack

Use this repository as a read-only reconnaissance and validation skill pack for an agent. The project is optimized for safe information collection, lightweight validation, and evidence-rich reporting inside authorized environments.

## When to use this skill

Use AutoSecAudit when the task is to:
- map exposed surface area for a domain, host, or IP range
- validate configuration and exposure weaknesses without destructive actions
- collect cross-checked evidence before deeper manual testing
- produce structured outputs that another agent or analyst can continue from

Do not use it for:
- destructive exploitation
- persistence, lateral movement, or payload delivery
- brute force, denial of service, or state-changing actions
- unauthorized targets

## Core operating model

AutoSecAudit works best as a two-step skill:
1. plan the run with clear scope and target constraints
2. execute the safest useful tool chain and keep the outputs for follow-up work

The CLI already exposes the useful entrypoints:
- `python -m autosecaudit --target <target> --mode plan ...`
- `python -m autosecaudit --target <target> --mode agent ...`
- `python -m autosecaudit doctor`
- `python -m autosecaudit skills list`
- `python -m autosecaudit skills show <skill-or-tool>`

## Recommended workflow for an agent

### 1. Validate environment first

Run:
```bash
python -m autosecaudit doctor --json
```

Check:
- Python version
- writable output/config paths
- tool availability (`nmap`, `dirsearch`, `nuclei`, `playwright` when needed)
- LLM config validity if one is supplied

If a required tool is unavailable, either narrow the plan or clearly state the missing dependency before execution.

### 2. Inspect available skills

Run:
```bash
python -m autosecaudit skills list
```

For a specific capability:
```bash
python -m autosecaudit skills show nmap_scan
python -m autosecaudit skills show dirsearch_scan
python -m autosecaudit skills show cve_verify
```

Use this to decide which built-in skill/tool combinations match the mission.

### 3. Generate a safe plan

Example:
```bash
python -m autosecaudit \
  --target example.com \
  --mode plan \
  --scope example.com \
  --output ./output
```

Use `plan` when:
- the target is new
- the operator wants review before execution
- you need to explain why the tool chain was selected

### 4. Execute an evidence-focused run

Example:
```bash
python -m autosecaudit \
  --target https://example.com \
  --mode agent \
  --scope example.com \
  --max-iterations 6 \
  --global-timeout 900 \
  --output ./output
```

Execution guidance:
- prefer URL targets for web-first audits
- prefer host/domain targets for service discovery first
- only pass `--tools` or `--skills` when you need to explicitly constrain the planner
- let the planner choose tools by default; it already reasons over evidence, scope, risk, and skill metadata

### 5. Read the outputs

Primary outputs:
- `output/agent/ActionPlan.json`
- `output/agent/agent_state.json`
- `output/agent/agent_history.json`
- `output/agent/agent_report.json` (when generated)
- `output/agent/agent_report.md`
- `output/agent/artifacts/*.json`

Important fields to correlate:
- `thought_stream`
- `evidence_graph`
- `cve_validation`
- `remediation_priority`
- `path_graph`
- `knowledge_context`

## LLM usage guidance

An LLM is optional. The skill should still work without one.

If a model is available:
- use it for action planning and tool prioritization
- do not delegate scope validation or safety boundaries to the model
- keep temperature low for repeatable plans

Generate a config template with:
```bash
python -m autosecaudit init --output ./config/llm_router.json
```

## Best practices for downstream agents

- treat AutoSecAudit outputs as evidence, not proof of exploitability
- confirm high-severity findings with at least two signals when possible
- use `agent_history.json` and `evidence_graph` to avoid duplicate work
- use `resume` to continue from a prior state instead of restarting from scratch
- keep a human in the loop before any high-risk validation path

## Example mission prompts

- `Audit example.com for externally exposed web risk. Stay read-only and prioritize misconfigurations.`
- `Map the attack surface for 10.10.10.0/24 and validate service exposure safely.`
- `Continue from the previous findings on app.example.com and verify only the highest-confidence weaknesses.`

## Boundaries

- authorized targets only
- read-only by default
- non-destructive validation only
- no brute force, no auth bypass, no persistence, no destructive payloads
