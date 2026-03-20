# Rag Intel Lookup

Use this skill when the declarative manifest has already selected `rag_intel_lookup` and an operator needs the human-readable intent behind the validation workflow.

## Intent

- Retrieve exploit patterns and testing heuristics from local security knowledge corpus.
- evaluate `tech_component` targets resolved from `surface.tech_stack` within the declared planner phases: deep_testing, verification
- keep analyst decisions aligned with the YAML manifest for triggers, risk posture, dependencies, and follow-up chaining

## Boundaries

- stay inside the declared risk posture: `safe` with planner cost `3`
- verify prerequisites before trusting output: runtime `local_rag_corpus`; related tools `tech_stack_fingerprint`
- treat tool execution as evidence gathering; do not infer exploitability or business impact without analyst review

## Result Semantics

- a completed run means the bound tool executed for the selected target set under the current mission constraints
- downstream investigation candidates currently declared by the manifest: `cve_lookup, nuclei_exploit_check, poc_sandbox_exec`
- findings, surface updates, and follow-up hints should be correlated with scope, target context, and adjacent evidence before escalation

## Analyst Notes

- confirm the current target still matches `surface.tech_stack` -> `tech_component` before reviewing results
- compare the output with nearby evidence from `tech_stack_fingerprint` or equivalent discovery artifacts
- record whether the result is actionable, inconclusive, or likely noise before triggering more work
