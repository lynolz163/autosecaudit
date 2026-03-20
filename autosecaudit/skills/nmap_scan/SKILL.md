# Nmap Scan

Use this skill when the declarative manifest has already selected `nmap_scan` and an operator needs the human-readable intent behind the recon workflow.

## Intent

- Use nmap for conservative service discovery on in-scope hosts.
- evaluate `host_seed` targets resolved from `scope` within the declared planner phases: passive_recon
- keep analyst decisions aligned with the YAML manifest for triggers, risk posture, dependencies, and follow-up chaining

## Boundaries

- stay inside the declared risk posture: `low` with planner cost `15`
- verify prerequisites before trusting output: runtime `nmap`; related tools `no extra tool prerequisites declared`
- treat tool execution as evidence gathering; do not infer exploitability or business impact without analyst review

## Result Semantics

- a completed run means the bound tool executed for the selected target set under the current mission constraints
- downstream investigation candidates currently declared by the manifest: `http_security_headers, passive_config_audit, ssl_expiry_check, tech_stack_fingerprint`
- findings, surface updates, and follow-up hints should be correlated with scope, target context, and adjacent evidence before escalation

## Analyst Notes

- confirm the current target still matches `scope` -> `host_seed` before reviewing results
- compare the output with nearby evidence from `no extra tool prerequisites declared` or equivalent discovery artifacts
- record whether the result is actionable, inconclusive, or likely noise before triggering more work
