# Sql Sanitization Audit

Use this skill when the declarative manifest has already selected `sql_sanitization_audit` and an operator needs the human-readable intent behind the testing workflow.

## Intent

- Send bounded SQL hygiene probes to parameterized endpoints and inspect responses.
- evaluate `parameterized_endpoint` targets resolved from `surface.endpoint_params` within the declared planner phases: deep_testing, verification
- keep analyst decisions aligned with the YAML manifest for triggers, risk posture, dependencies, and follow-up chaining

## Boundaries

- stay inside the declared risk posture: `medium` with planner cost `8`
- verify prerequisites before trusting output: runtime `no special runtime declared`; related tools `dynamic_crawl`
- treat tool execution as evidence gathering; do not infer exploitability or business impact without analyst review

## Result Semantics

- a completed run means the bound tool executed for the selected target set under the current mission constraints
- downstream investigation candidates currently declared by the manifest: `nuclei_exploit_check, xss_protection_audit`
- findings, surface updates, and follow-up hints should be correlated with scope, target context, and adjacent evidence before escalation

## Analyst Notes

- confirm the current target still matches `surface.endpoint_params` -> `parameterized_endpoint` before reviewing results
- compare the output with nearby evidence from `dynamic_crawl` or equivalent discovery artifacts
- record whether the result is actionable, inconclusive, or likely noise before triggering more work
