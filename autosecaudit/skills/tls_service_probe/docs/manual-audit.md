# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `tls_service_probe` output.
- Review the intended use: Collect TLS version, cipher, and certificate metadata from HTTPS services.
- Check target fit: `origins` -> `https_origin` during phases `passive_recon, verification`.
- Validate prerequisites: runtime `ssl` and supporting tools `nmap_scan`.
- Decide whether follow-up candidates `rag_intel_lookup` should run automatically or wait for analyst confirmation.
