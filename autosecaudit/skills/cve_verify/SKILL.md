# CVE Verify

Use this skill when the declarative manifest has already selected `cve_verify` and an operator needs the human-readable intent behind the verification flow.

## Intent

- confirm whether a surfaced CVE candidate is worth deeper analyst attention
- keep default execution inside the authorized, safer verification boundary
- translate raw nuclei-style verification output into reviewable security evidence

## Boundaries

- do not treat template execution as proof of exploitable impact without analyst review
- do not expand beyond explicitly authorized targets or components
- prefer safe verification modes unless the mission state explicitly allows higher-risk behavior

## Result semantics

- a completed verification means the requested checks ran; it does not automatically prove exploitability
- `surface.cve_verification` should be interpreted as verification evidence, not a final severity verdict
- follow-up actions should be driven by the manifest and by analyst confirmation of the evidence quality

## Analyst notes

- validate the affected component and version mapping before escalating a finding
- compare template hits with observed service banners, package versions, and reachable attack surface
- when evidence is partial or noisy, keep the result as a candidate for manual review instead of promoting it to confirmed impact
