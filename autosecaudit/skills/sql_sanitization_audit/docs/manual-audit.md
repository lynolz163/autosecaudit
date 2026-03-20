# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `sql_sanitization_audit` output.
- Review the intended use: Send bounded SQL hygiene probes to parameterized endpoints and inspect responses.
- Check target fit: `surface.endpoint_params` -> `parameterized_endpoint` during phases `deep_testing, verification`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `dynamic_crawl`.
- Decide whether follow-up candidates `nuclei_exploit_check, xss_protection_audit` should run automatically or wait for analyst confirmation.
