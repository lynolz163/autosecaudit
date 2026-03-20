# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `xss_protection_audit` output.
- Review the intended use: Probe parameterized endpoints for reflection and output-encoding weaknesses.
- Check target fit: `surface.endpoint_params` -> `parameterized_endpoint` during phases `deep_testing, verification`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `dynamic_crawl`.
- Decide whether follow-up candidates `csp_evaluator` should run automatically or wait for analyst confirmation.
