# AutoSecAudit Report

- Target: `https://lynolz.com`
- Started (UTC): `2026-02-24T06:51:22.971053+00:00`
- Ended (UTC): `2026-02-24T06:51:26.406593+00:00`

## Summary

- total_plugins: `3`
- total_findings: `6`
- status_counts: `{'passed': 2, 'failed': 1, 'error': 0, 'skipped': 0}`
- severity_counts: `{'info': 2, 'low': 2, 'medium': 1, 'high': 1, 'critical': 0}`

## Plugin Results

### DNS Discovery (`dns_discovery`)

- Category: `discovery`
- Status: `passed`
- Started: `2026-02-24T06:51:22.976125+00:00`
- Ended: `2026-02-24T06:51:23.422982+00:00`

- Findings: `1`

#### DNS Addresses Discovered (`DISC-DNS-INFO-001`)

- Severity: `info`
- Description: Asset discovery succeeded and DNS addresses were resolved.
- Evidence: `{"host": "lynolz.com", "addresses": ["104.21.89.22", "172.67.136.81"]}`

### HTTP Header Validation (`http_headers_validation`)

- Category: `validation`
- Status: `failed`
- Started: `2026-02-24T06:51:23.425885+00:00`
- Ended: `2026-02-24T06:51:25.164737+00:00`

- Findings: `4`

#### Missing HTTP Header: strict-transport-security (`VAL-HTTP-STRICT_TRANSPORT_SECURITY`)

- Severity: `high`
- Description: Response is missing the security header `strict-transport-security`.
- Recommendation: Enable HSTS to enforce secure transport in browsers.
- Evidence: `{"url": "https://lynolz.com", "status_code": 200}`

#### Missing HTTP Header: content-security-policy (`VAL-HTTP-CONTENT_SECURITY_POLICY`)

- Severity: `medium`
- Description: Response is missing the security header `content-security-policy`.
- Recommendation: Define a restrictive CSP to reduce XSS and content injection risks.
- Evidence: `{"url": "https://lynolz.com", "status_code": 200}`

#### Missing HTTP Header: x-content-type-options (`VAL-HTTP-X_CONTENT_TYPE_OPTIONS`)

- Severity: `low`
- Description: Response is missing the security header `x-content-type-options`.
- Recommendation: Set X-Content-Type-Options to 'nosniff'.
- Evidence: `{"url": "https://lynolz.com", "status_code": 200}`

#### Missing HTTP Header: x-frame-options (`VAL-HTTP-X_FRAME_OPTIONS`)

- Severity: `low`
- Description: Response is missing the security header `x-frame-options`.
- Recommendation: Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.
- Evidence: `{"url": "https://lynolz.com", "status_code": 200}`

### TLS Certificate Validation (`tls_certificate_validation`)

- Category: `validation`
- Status: `passed`
- Started: `2026-02-24T06:51:25.167216+00:00`
- Ended: `2026-02-24T06:51:26.405603+00:00`

- Findings: `1`

#### TLS Certificate Validity Check Passed (`VAL-TLS-INFO-001`)

- Severity: `info`
- Description: TLS certificate is valid and not near expiry.
- Evidence: `{"host": "lynolz.com", "port": 443, "days_left": 35}`
