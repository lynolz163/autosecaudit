# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `cookie_security_audit` output.
- Review the intended use: Audit Secure, HttpOnly, and SameSite attributes on set-cookie headers.
- Check target fit: `origins` -> `origin_url` during phases `deep_testing, verification`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `csp_evaluator` should run automatically or wait for analyst confirmation.
