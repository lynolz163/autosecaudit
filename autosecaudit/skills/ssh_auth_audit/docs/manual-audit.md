# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `ssh_auth_audit` output.
- Review the intended use: Validate SSH authentication surface and record the exposed protocol banner.
- Check target fit: `surface` -> `service_port` during phases `passive_recon, verification`.
- Validate prerequisites: runtime `socket` and supporting tools `nmap_scan, service_banner_probe`.
- Decide whether follow-up candidates `cve_lookup, rag_intel_lookup` should run automatically or wait for analyst confirmation.
