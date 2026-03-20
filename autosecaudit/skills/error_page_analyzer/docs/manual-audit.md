# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `error_page_analyzer` output.
- Review the intended use: Inspect verbose error pages for stack traces, framework markers, and debug data.
- Check target fit: `origins` -> `origin_url` during phases `passive_recon`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `passive_config_audit` should run automatically or wait for analyst confirmation.
