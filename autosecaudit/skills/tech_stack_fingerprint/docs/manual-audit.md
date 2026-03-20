# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `tech_stack_fingerprint` output.
- Review the intended use: Passively fingerprint exposed technologies from headers and page content.
- Check target fit: `origins` -> `origin_url` during phases `passive_recon`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `api_schema_discovery, csp_evaluator, dirsearch_scan, http_security_headers, nuclei_exploit_check, passive_config_audit, source_map_detector` should run automatically or wait for analyst confirmation.
