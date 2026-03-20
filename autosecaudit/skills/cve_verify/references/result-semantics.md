# Result Semantics

- Template match: the verification logic found a pattern consistent with the requested CVE candidate.
- No match: the verification logic did not observe the expected pattern under the current safe runtime constraints.
- Inconclusive: the runtime, scope, authorization level, or target behavior prevented a meaningful conclusion.
- Escalation decision: always combine the verification result with analyst review before marking exploitable impact.
