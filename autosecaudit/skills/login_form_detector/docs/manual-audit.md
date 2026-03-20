# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `login_form_detector` output.
- Review the intended use: Detect login and authentication forms from passive page inspection.
- Check target fit: `origins` -> `origin_url` during phases `passive_recon`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `cookie_security_audit, passive_config_audit` should run automatically or wait for analyst confirmation.
