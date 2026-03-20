# Poc Sandbox Exec

Use this skill when the declarative manifest has already selected `poc_sandbox_exec` and an operator needs the human-readable intent behind the validation workflow.

## Intent

- Execute approved PoC code inside sandbox and return execution evidence.
- evaluate `tech_component` targets resolved from `surface.tech_stack` within the declared planner phases: verification
- keep analyst decisions aligned with the YAML manifest for triggers, risk posture, dependencies, and follow-up chaining

## Boundaries

- stay inside the declared risk posture: `high` with planner cost `18`
- verify prerequisites before trusting output: runtime `python`; related tools `rag_intel_lookup`
- treat tool execution as evidence gathering; do not infer exploitability or business impact without analyst review

## Result Semantics

- a completed run means the bound tool executed for the selected target set under the current mission constraints
- downstream investigation candidates currently declared by the manifest: `cve_verify`
- findings, surface updates, and follow-up hints should be correlated with scope, target context, and adjacent evidence before escalation

## Analyst Notes

- confirm the current target still matches `surface.tech_stack` -> `tech_component` before reviewing results
- compare the output with nearby evidence from `rag_intel_lookup` or equivalent discovery artifacts
- record whether the result is actionable, inconclusive, or likely noise before triggering more work
