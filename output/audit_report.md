# AutoSecAudit Report

- Target: `https://ctf.360-24.com`
- Started (UTC): `2026-02-18T16:55:01.425635+00:00`
- Ended (UTC): `2026-02-18T16:55:03.632888+00:00`

## Summary

- total_plugins: `3`
- total_findings: `2`
- status_counts: `{'passed': 1, 'failed': 1, 'error': 1, 'skipped': 0}`
- severity_counts: `{'info': 1, 'low': 0, 'medium': 1, 'high': 0, 'critical': 0}`

## Plugin Results

### DNS Discovery (`dns_discovery`)

- Category: `discovery`
- Status: `passed`
- Started: `2026-02-18T16:55:01.428880+00:00`
- Ended: `2026-02-18T16:55:01.953037+00:00`

- Findings: `1`

#### DNS Addresses Discovered (`DISC-DNS-INFO-001`)

- Severity: `info`
- Description: Asset discovery succeeded and DNS addresses were resolved.
- Evidence: `{"host": "ctf.360-24.com", "addresses": ["8.130.132.231"]}`

### HTTP Header Validation (`http_headers_validation`)

- Category: `validation`
- Status: `error`
- Started: `2026-02-18T16:55:01.955024+00:00`
- Ended: `2026-02-18T16:55:03.508541+00:00`
- Error: `HTTP request failed with status 403`

- Findings: `0`

### TLS Certificate Validation (`tls_certificate_validation`)

- Category: `validation`
- Status: `failed`
- Started: `2026-02-18T16:55:03.511305+00:00`
- Ended: `2026-02-18T16:55:03.631525+00:00`

- Findings: `1`

#### TLS Certificate Expiring Soon (`VAL-TLS-EXPIRING-001`)

- Severity: `medium`
- Description: The TLS certificate expires within 30 days.
- Recommendation: Plan certificate renewal before expiration.
- Evidence: `{"host": "ctf.360-24.com", "port": 443, "days_left": 22}`
