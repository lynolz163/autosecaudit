# Result Semantics

- Completed: the tool ran successfully for the selected target context under current safety controls.
- Findings present: the tool observed signals worth review, not necessarily a confirmed vulnerability or exposure.
- No findings: no meaningful signal was observed under the present runtime, scope, and target conditions.
- Error or blocked: runtime, access, dependency, or safety constraints prevented a reliable conclusion.
- Follow-up interpretation: declared downstream tools are `cookie_security_audit, passive_config_audit`; treat them as investigation candidates rather than automatic proof.
