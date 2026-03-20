# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `api_schema_discovery` output.
- Review the intended use: Discover OpenAPI, Swagger, and GraphQL schema endpoints.
- Check target fit: `origins` -> `origin_url` during phases `active_discovery`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `cookie_security_audit, param_fuzzer` should run automatically or wait for analyst confirmation.
