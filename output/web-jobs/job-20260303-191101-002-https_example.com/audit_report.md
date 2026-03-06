# AutoSecAudit Report

- Target: `https://example.com`
- Started (UTC): `2026-03-03T11:11:01.406327+00:00`
- Ended (UTC): `2026-03-03T11:11:01.422894+00:00`

## Summary

- total_plugins: `1`
- total_findings: `1`
- status_counts: `{'passed': 1, 'failed': 0, 'error': 0, 'skipped': 0}`
- severity_counts: `{'info': 1, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0}`

## Plugin Results

### DNS Discovery (`dns_discovery`)

- Category: `discovery`
- Status: `passed`
- Started: `2026-03-03T11:11:01.413302+00:00`
- Ended: `2026-03-03T11:11:01.420653+00:00`

- Findings: `1`

#### DNS Addresses Discovered (`DISC-DNS-INFO-001`)

- Severity: `info`
- Description: Asset discovery succeeded and DNS addresses were resolved.
- Evidence: `{"host": "example.com", "addresses": ["104.18.26.120", "104.18.27.120"]}`
