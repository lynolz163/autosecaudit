# Manual Audit Notes

- Reconfirm scope, authorization, and current mission context before reviewing `git_exposure_check` output.
- Review the intended use: Detect exposed repository metadata such as .git and .svn files.
- Check target fit: `origins` -> `origin_url` during phases `passive_recon`.
- Validate prerequisites: runtime `no special runtime declared` and supporting tools `no extra tool prerequisites declared`.
- Decide whether follow-up candidates `passive_config_audit, source_map_detector` should run automatically or wait for analyst confirmation.
