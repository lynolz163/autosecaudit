# Agent Invocation Examples

These examples show the intended usage pattern for parent agents such as Codex, Claude Code, or similar orchestration runtimes.

## Sequence

1. Run `doctor`
2. Run `plan`
3. Inspect `ActionPlan.json`
4. Run `agent`
5. Resume from `output/agent` when needed

## Files

- `run_plan.py`: minimal plan-first invocation
- `run_agent.py`: minimal agent execution and resume-aware flow

## Notes

- Keep the target authorized and scope-bound.
- Do not pass `--tools` or `--skills` unless strict determinism is required.
- Let AutoSecAudit choose tools by default.
