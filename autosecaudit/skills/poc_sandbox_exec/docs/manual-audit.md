# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `poc_sandbox_exec` output.
- Review the intended use: Execute approved PoC code inside sandbox and return execution evidence.
- Check target fit: `surface.tech_stack` -> `tech_component` during phases `verification`.
- Validate prerequisites: runtime `python` and supporting tools `rag_intel_lookup`.
- Decide whether follow-up candidates `cve_verify` should run automatically or wait for analyst confirmation.
