# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `passive_config_audit` output.
- Review the intended use: Check common sensitive config paths using read-only requests.
- Check target fit: `origins` -> `origin_url` during phases `passive_recon`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `no declarative follow-up tools` should run automatically or wait for analyst confirmation.
