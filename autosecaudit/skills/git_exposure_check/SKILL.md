# Git Exposure Check

Use this skill when the declarative manifest has already selected `git_exposure_check` and an operator needs the human-readable intent behind the recon workflow.

## Intent

- Detect exposed repository metadata such as .git and .svn files.
- evaluate `origin_url` targets resolved from `origins` within the declared planner phases: passive_recon
- keep analyst decisions aligned with the YAML manifest for triggers, risk posture, dependencies, and follow-up chaining

## Boundaries

- stay inside the declared risk posture: `safe` with planner cost `2`
- verify prerequisites before trusting output: runtime `no special runtime declared`; related tools `no extra tool prerequisites declared`
- treat tool execution as evidence gathering; do not infer exploitability or business impact without analyst review

## Result Semantics

- a completed run means the bound tool executed for the selected target set under the current mission constraints
- downstream investigation candidates currently declared by the manifest: `passive_config_audit, source_map_detector`
- findings, surface updates, and follow-up hints should be correlated with scope, target context, and adjacent evidence before escalation

## Analyst Notes

- confirm the current target still matches `origins` -> `origin_url` before reviewing results
- compare the output with nearby evidence from `no extra tool prerequisites declared` or equivalent discovery artifacts
- record whether the result is actionable, inconclusive, or likely noise before triggering more work
