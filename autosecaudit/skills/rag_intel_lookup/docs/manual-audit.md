# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `rag_intel_lookup` output.
- Review the intended use: Retrieve exploit patterns and testing heuristics from local security knowledge corpus.
- Check target fit: `surface.tech_stack` -> `tech_component` during phases `deep_testing, verification`.
- Validate prerequisites: runtime `local_rag_corpus` and supporting tools `tech_stack_fingerprint`.
- Decide whether follow-up candidates `cve_lookup, nuclei_exploit_check, poc_sandbox_exec` should run automatically or wait for analyst confirmation.
