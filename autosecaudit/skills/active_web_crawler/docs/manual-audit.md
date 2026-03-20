# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `active_web_crawler` output.
- Review the intended use: Run bounded active crawling with explicit page and depth limits.
- Check target fit: `origins` -> `origin_url` during phases `active_discovery`.
- Validate prerequisites: runtime `playwright` and supporting tools `dynamic_crawl`.
- Decide whether follow-up candidates `no declarative follow-up tools` should run automatically or wait for analyst confirmation.
