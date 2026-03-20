# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `waf_detector` output.
- Review the intended use: Identify common CDN and WAF protection layers from passive response markers.
- Check target fit: `origins` -> `origin_url` during phases `passive_recon`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `cors_misconfiguration, http_security_headers, passive_config_audit, security_txt_check, ssl_expiry_check` should run automatically or wait for analyst confirmation.
