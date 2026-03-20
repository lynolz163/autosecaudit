# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `dns_zone_audit` output.
- Review the intended use: Resolve NS/MX/TXT/SOA records and test whether AXFR is exposed.
- Check target fit: `scope` -> `domain` during phases `passive_recon, verification`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `reverse_dns_probe, subdomain_enum_passive` should run automatically or wait for analyst confirmation.
