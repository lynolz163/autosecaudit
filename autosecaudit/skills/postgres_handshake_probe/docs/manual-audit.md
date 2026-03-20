# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `postgres_handshake_probe` output.
- Review the intended use: Collect PostgreSQL startup metadata and TLS support without authenticating.
- Check target fit: `surface` -> `service_port` during phases `passive_recon, verification`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `nmap_scan, service_banner_probe`.
- Decide whether follow-up candidates `cve_lookup, rag_intel_lookup` should run automatically or wait for analyst confirmation.
