# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `cve_lookup` output.
- Review the intended use: Query NVD for known CVEs based on detected technology components.
- Check target fit: `surface.tech_stack` -> `tech_component` during phases `verification`.
- Validate prerequisites: runtime `internet` and supporting tools `tech_stack_fingerprint`.
- Decide whether follow-up candidates `cve_verify` should run automatically or wait for analyst confirmation.
