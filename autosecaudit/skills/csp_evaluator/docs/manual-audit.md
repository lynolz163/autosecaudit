# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `csp_evaluator` output.
- Review the intended use: Evaluate Content-Security-Policy quality and risky directives.
- Check target fit: `origins` -> `origin_url` during phases `deep_testing, verification`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `no declarative follow-up tools` should run automatically or wait for analyst confirmation.
