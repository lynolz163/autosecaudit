# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `http_security_headers` output.
- Review the intended use: Validate common HTTP security headers on reachable origins.
- Check target fit: `origins` -> `origin_url` during phases `passive_recon`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `csp_evaluator` should run automatically or wait for analyst confirmation.
