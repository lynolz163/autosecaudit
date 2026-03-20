# Reverse Dns Probe

Use this skill when the declarative manifest has already selected `reverse_dns_probe` and an operator needs the human-readable intent behind the recon workflow.

## Intent

- Resolve reverse-DNS names for scoped IPs and discovered host addresses.
- evaluate `scope_host` targets resolved from `scope` within the declared planner phases: passive_recon, verification
- keep analyst decisions aligned with the YAML manifest for triggers, risk posture, dependencies, and follow-up chaining

## Boundaries

- stay inside the declared risk posture: `safe` with planner cost `2`
- verify prerequisites before trusting output: runtime `no special runtime declared`; related tools `nmap_scan`
- treat tool execution as evidence gathering; do not infer exploitability or business impact without analyst review

## Result Semantics

- a completed run means the bound tool executed for the selected target set under the current mission constraints
- downstream investigation candidates currently declared by the manifest: `dns_zone_audit`
- findings, surface updates, and follow-up hints should be correlated with scope, target context, and adjacent evidence before escalation

## Analyst Notes

- confirm the current target still matches `scope` -> `scope_host` before reviewing results
- compare the output with nearby evidence from `nmap_scan` or equivalent discovery artifacts
- record whether the result is actionable, inconclusive, or likely noise before triggering more work
