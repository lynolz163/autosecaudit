# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `page_vision_analyzer` output.
- Review the intended use: Capture rendered screenshots and extract UI-level security cues with optional vision LLM analysis.
- Check target fit: `origins` -> `origin_url` during phases `active_discovery, verification`.
- Validate prerequisites: runtime `playwright` and supporting tools `dynamic_crawl`.
- Decide whether follow-up candidates `cookie_security_audit, login_form_detector, nuclei_exploit_check, passive_config_audit` should run automatically or wait for analyst confirmation.
