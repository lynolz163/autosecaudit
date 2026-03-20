# Active Web Crawler

Use this skill when the declarative manifest has already selected `active_web_crawler` and an operator needs the human-readable intent behind the discovery workflow.

## Intent

- Run bounded active crawling with explicit page and depth limits.
- evaluate `origin_url` targets resolved from `origins` within the declared planner phases: active_discovery
- keep analyst decisions aligned with the YAML manifest for triggers, risk posture, dependencies, and follow-up chaining

## Boundaries

- stay inside the declared risk posture: `low` with planner cost `12`
- verify prerequisites before trusting output: runtime `playwright`; related tools `dynamic_crawl`
- treat tool execution as evidence gathering; do not infer exploitability or business impact without analyst review

## Result Semantics

- a completed run means the bound tool executed for the selected target set under the current mission constraints
- downstream investigation candidates currently declared by the manifest: `no declarative follow-up tools`
- findings, surface updates, and follow-up hints should be correlated with scope, target context, and adjacent evidence before escalation

## Analyst Notes

- confirm the current target still matches `origins` -> `origin_url` before reviewing results
- compare the output with nearby evidence from `dynamic_crawl` or equivalent discovery artifacts
- record whether the result is actionable, inconclusive, or likely noise before triggering more work
