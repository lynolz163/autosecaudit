# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `reverse_dns_probe` output.
- Review the intended use: Resolve reverse-DNS names for scoped IPs and discovered host addresses.
- Check target fit: `scope` -> `scope_host` during phases `passive_recon, verification`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `nmap_scan`.
- Decide whether follow-up candidates `dns_zone_audit` should run automatically or wait for analyst confirmation.
