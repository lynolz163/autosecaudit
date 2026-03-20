# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `subdomain_enum_passive` output.
- Review the intended use: Enumerate likely subdomains through passive certificate transparency sources.
- Check target fit: `scope` -> `domain` during phases `passive_recon`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `no declarative follow-up tools` should run automatically or wait for analyst confirmation.
