# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `param_fuzzer` output.
- Review the intended use: Run bounded benign parameter probes against parameterized endpoints.
- Check target fit: `surface.endpoint_params` -> `parameterized_endpoint` during phases `deep_testing`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `dynamic_crawl`.
- Decide whether follow-up candidates `no declarative follow-up tools` should run automatically or wait for analyst confirmation.
