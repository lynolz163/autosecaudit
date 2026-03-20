# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `cors_misconfiguration` output.
- Review the intended use: Probe origins for arbitrary Origin reflection and credentialed wildcard CORS behavior.
- Check target fit: `origins` -> `origin_url` during phases `deep_testing`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `no declarative follow-up tools` should run automatically or wait for analyst confirmation.
