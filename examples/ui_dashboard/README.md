# AutoSecAudit UI Dashboard (Backend-Aligned Skeleton)

This example provides a React + Tailwind UI skeleton that aligns to the current AutoSecAudit Agent outputs:

- `audit_report.json`
- `agent_state.json`
- `ActionPlan.json`
- `blocked_actions.json`

## Intended usage

Use this with a Vite React app:

1. Create a Vite project (`npm create vite@latest`)
2. Install Tailwind CSS
3. Copy `src/` files from this folder into your app
4. Replace mock data in `src/mock/autosecauditMock.js` with real API/file loading

## Why this version

This UI is aligned to backend functionality rather than a generic dashboard:

- Planned actions (`ActionPlan.actions`)
- Policy blocked actions (`blocked_actions.json`)
- Agent history / statuses / budgets (`agent_state.json`, `audit_report.history`)
- Scope + breadcrumbs + surface (`audit_report.scope`)
- Findings + severity + remediation (`audit_report.findings`)
