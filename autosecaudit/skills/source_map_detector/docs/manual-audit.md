# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `source_map_detector` output.
- Review the intended use: Detect exposed JavaScript source maps that may reveal source code or routes.
- Check target fit: `origins` -> `origin_url` during phases `passive_recon`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `api_schema_discovery, passive_config_audit` should run automatically or wait for analyst confirmation.
