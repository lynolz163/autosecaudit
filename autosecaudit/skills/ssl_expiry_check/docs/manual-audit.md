# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `ssl_expiry_check` output.
- Review the intended use: Check TLS certificate expiry dates on HTTPS origins.
- Check target fit: `origins` -> `https_origin` during phases `passive_recon`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `no declarative follow-up tools` should run automatically or wait for analyst confirmation.
