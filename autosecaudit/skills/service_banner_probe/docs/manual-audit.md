# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `service_banner_probe` output.
- Review the intended use: Safely capture banners from nmap-discovered non-HTTP TCP services.
- Check target fit: `surface` -> `service_port` during phases `passive_recon, active_discovery`.
- Validate prerequisites: runtime `socket` and supporting tools `nmap_scan`.
- Decide whether follow-up candidates `no declarative follow-up tools` should run automatically or wait for analyst confirmation.
