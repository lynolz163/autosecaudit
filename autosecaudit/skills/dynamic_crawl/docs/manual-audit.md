# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `dynamic_crawl` output.
- Review the intended use: Use Playwright-based crawling to map in-scope pages and forms.
- Check target fit: `origins` -> `origin_url` during phases `active_discovery`.
- Validate prerequisites: runtime `playwright` and supporting tools `tech_stack_fingerprint`.
- Decide whether follow-up candidates `no declarative follow-up tools` should run automatically or wait for analyst confirmation.
