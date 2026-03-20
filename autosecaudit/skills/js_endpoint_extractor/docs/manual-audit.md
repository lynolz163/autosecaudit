# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `js_endpoint_extractor` output.
- Review the intended use: Inspect same-origin HTML and JavaScript to discover hidden endpoints.
- Check target fit: `origins` -> `origin_url` during phases `passive_recon, active_discovery`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `api_schema_discovery, dynamic_crawl` should run automatically or wait for analyst confirmation.
