# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `memcached_exposure_check` output.
- Review the intended use: Safely verify whether memcached answers version and stats probes without authentication.
- Check target fit: `surface` -> `service_port` during phases `passive_recon, verification`.
- Validate prerequisites: runtime `socket` and supporting tools `nmap_scan, service_banner_probe`.
- Decide whether follow-up candidates `cve_lookup, rag_intel_lookup` should run automatically or wait for analyst confirmation.
