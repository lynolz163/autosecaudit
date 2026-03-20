# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `dirsearch_scan` output.
- Review the intended use: Use dirsearch for conservative directory and file discovery.
- Check target fit: `origins` -> `origin_url` during phases `active_discovery`.
- Validate prerequisites: runtime `dirsearch` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `no declarative follow-up tools` should run automatically or wait for analyst confirmation.
