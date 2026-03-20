# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `security_txt_check` output.
- Review the intended use: Check /.well-known/security.txt for presence and baseline completeness.
- Check target fit: `origins` -> `origin_url` during phases `passive_recon`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `no declarative follow-up tools` should run automatically or wait for analyst confirmation.
