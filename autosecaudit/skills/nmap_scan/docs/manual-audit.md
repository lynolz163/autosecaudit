# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `nmap_scan` output.
- Review the intended use: Use nmap for conservative service discovery on in-scope hosts.
- Check target fit: `scope` -> `host_seed` during phases `passive_recon`.
- Validate prerequisites: runtime `nmap` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `http_security_headers, passive_config_audit, ssl_expiry_check, tech_stack_fingerprint` should run automatically or wait for analyst confirmation.
