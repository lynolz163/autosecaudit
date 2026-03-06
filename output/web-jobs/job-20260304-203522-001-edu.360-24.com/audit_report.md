# AutoSecAudit Report

- Target: `edu.360-24.com`
- Started (UTC): `2026-03-04T12:35:22.824033+00:00`
- Ended (UTC): `2026-03-04T12:35:45.442699+00:00`

## Summary

- total_plugins: `6`
- total_findings: `10`
- status_counts: `{'passed': 2, 'failed': 3, 'error': 1, 'skipped': 0}`
- severity_counts: `{'info': 2, 'low': 4, 'medium': 3, 'high': 1, 'critical': 0}`

## Plugin Results

### CORS Misconfiguration Check (`cors_misconfiguration`)

- Category: `validation`
- Status: `passed`
- Started: `2026-03-04T12:35:22.834332+00:00`
- Ended: `2026-03-04T12:35:25.089555+00:00`

- Findings: `1`

#### CORS Policy Looks Restrictive (`VAL-CORS-HEALTHY-001`)

- Severity: `info`
- Description: No obvious overly permissive CORS behavior was detected in the probe response.
- Evidence: `{"url": "https://edu.360-24.com", "status_code": 405, "probe_method": "OPTIONS", "access_control_allow_origin": "", "access_control_allow_credentials": ""}`

### DNS Discovery (`dns_discovery`)

- Category: `discovery`
- Status: `passed`
- Started: `2026-03-04T12:35:25.095918+00:00`
- Ended: `2026-03-04T12:35:25.102156+00:00`

- Findings: `1`

#### DNS Addresses Discovered (`DISC-DNS-INFO-001`)

- Severity: `info`
- Description: Asset discovery succeeded and DNS addresses were resolved.
- Evidence: `{"host": "edu.360-24.com", "addresses": ["39.99.43.46"]}`

### HTTP Header Validation (`http_headers_validation`)

- Category: `validation`
- Status: `failed`
- Started: `2026-03-04T12:35:25.108803+00:00`
- Ended: `2026-03-04T12:35:27.716402+00:00`

- Findings: `6`

#### Missing HTTP Header: strict-transport-security (`VAL-HTTP-STRICT_TRANSPORT_SECURITY`)

- Severity: `high`
- Description: Response is missing the security header `strict-transport-security`.
- Recommendation: Enable HSTS to enforce secure transport in browsers.
- Evidence: `{"url": "https://edu.360-24.com", "status_code": 200}`

#### Missing HTTP Header: content-security-policy (`VAL-HTTP-CONTENT_SECURITY_POLICY`)

- Severity: `medium`
- Description: Response is missing the security header `content-security-policy`.
- Recommendation: Define a restrictive CSP to reduce XSS and content injection risks.
- Evidence: `{"url": "https://edu.360-24.com", "status_code": 200}`

#### Missing HTTP Header: x-content-type-options (`VAL-HTTP-X_CONTENT_TYPE_OPTIONS`)

- Severity: `low`
- Description: Response is missing the security header `x-content-type-options`.
- Recommendation: Set X-Content-Type-Options to 'nosniff'.
- Evidence: `{"url": "https://edu.360-24.com", "status_code": 200}`

#### Missing HTTP Header: x-frame-options (`VAL-HTTP-X_FRAME_OPTIONS`)

- Severity: `low`
- Description: Response is missing the security header `x-frame-options`.
- Recommendation: Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.
- Evidence: `{"url": "https://edu.360-24.com", "status_code": 200}`

#### Missing HTTP Header: referrer-policy (`VAL-HTTP-REFERRER_POLICY`)

- Severity: `low`
- Description: Response is missing the security header `referrer-policy`.
- Recommendation: Set Referrer-Policy (e.g. 'strict-origin-when-cross-origin') to reduce cross-origin URL leakage.
- Evidence: `{"url": "https://edu.360-24.com", "status_code": 200}`

#### Missing HTTP Header: permissions-policy (`VAL-HTTP-PERMISSIONS_POLICY`)

- Severity: `low`
- Description: Response is missing the security header `permissions-policy`.
- Recommendation: Set Permissions-Policy to restrict browser feature access (camera, microphone, geolocation, etc.).
- Evidence: `{"url": "https://edu.360-24.com", "status_code": 200}`

### Port Service Scan (`port_service_scan`)

- Category: `discovery`
- Status: `error`
- Started: `2026-03-04T12:35:27.722455+00:00`
- Ended: `2026-03-04T12:35:41.743492+00:00`
- Error: `Nmap scan timed out after 14.0s`

- Findings: `0`

### SSL Expiry Check (`ssl_expiry_check`)

- Category: `validation`
- Status: `failed`
- Started: `2026-03-04T12:35:41.749673+00:00`
- Ended: `2026-03-04T12:35:43.806714+00:00`

- Findings: `1`

#### SSL Certificate Expiring Soon (`VAL-SSL-EXPIRING-SOON-001`)

- Severity: `medium`
- Description: The TLS certificate expires within the next 30 days.
- Recommendation: Plan a certificate renewal before the expiry window is reached.
- Evidence: `{"host": "edu.360-24.com", "port": 443, "days_left": 8, "expires_at": "2026-03-12T23:59:59+00:00", "issuer": [[["countryName", "GB"]], [["stateOrProvinceName", "Greater Manchester"]], [["localityName", "Salford"]], [["organizationName", "Sectigo Limited"]], [["commonName", "Sectigo RSA Domain Validation Secure Server CA"]]], "subject": [[["commonName", "*.360-24.com"]]], "subject_alt_name": [["DNS", "*.360-24.com"], ["DNS", "360-24.com"]]}`

### TLS Certificate Validation (`tls_certificate_validation`)

- Category: `validation`
- Status: `failed`
- Started: `2026-03-04T12:35:43.812111+00:00`
- Ended: `2026-03-04T12:35:45.439789+00:00`

- Findings: `1`

#### TLS Certificate Expiring Soon (`VAL-TLS-EXPIRING-001`)

- Severity: `medium`
- Description: The TLS certificate expires within 30 days.
- Recommendation: Plan certificate renewal before expiration.
- Evidence: `{"host": "edu.360-24.com", "port": 443, "days_left": 8}`
