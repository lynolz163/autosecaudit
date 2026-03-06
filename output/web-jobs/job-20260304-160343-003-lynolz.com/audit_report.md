# AutoSecAudit Report

- Target: `lynolz.com`
- Started (UTC): `2026-03-04T08:03:44.151718+00:00`
- Ended (UTC): `2026-03-04T08:04:02.799715+00:00`

## Summary

- total_plugins: `6`
- total_findings: `10`
- status_counts: `{'passed': 4, 'failed': 1, 'error': 1, 'skipped': 0}`
- severity_counts: `{'info': 4, 'low': 4, 'medium': 1, 'high': 1, 'critical': 0}`

## Plugin Results

### CORS Misconfiguration Check (`cors_misconfiguration`)

- Category: `validation`
- Status: `passed`
- Started: `2026-03-04T08:03:44.157598+00:00`
- Ended: `2026-03-04T08:03:45.981287+00:00`

- Findings: `1`

#### CORS Policy Looks Restrictive (`VAL-CORS-HEALTHY-001`)

- Severity: `info`
- Description: No obvious overly permissive CORS behavior was detected in the probe response.
- Evidence: `{"url": "https://lynolz.com", "status_code": 405, "probe_method": "OPTIONS", "access_control_allow_origin": "", "access_control_allow_credentials": ""}`

### DNS Discovery (`dns_discovery`)

- Category: `discovery`
- Status: `passed`
- Started: `2026-03-04T08:03:45.986933+00:00`
- Ended: `2026-03-04T08:03:45.991811+00:00`

- Findings: `1`

#### DNS Addresses Discovered (`DISC-DNS-INFO-001`)

- Severity: `info`
- Description: Asset discovery succeeded and DNS addresses were resolved.
- Evidence: `{"host": "lynolz.com", "addresses": ["104.21.89.22", "172.67.136.81"]}`

### HTTP Header Validation (`http_headers_validation`)

- Category: `validation`
- Status: `failed`
- Started: `2026-03-04T08:03:45.997274+00:00`
- Ended: `2026-03-04T08:03:47.596055+00:00`

- Findings: `6`

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

#### Missing HTTP Header: referrer-policy (`VAL-HTTP-REFERRER_POLICY`)

- Severity: `low`
- Description: Response is missing the security header `referrer-policy`.
- Recommendation: Set Referrer-Policy (e.g. 'strict-origin-when-cross-origin') to reduce cross-origin URL leakage.
- Evidence: `{"url": "https://lynolz.com", "status_code": 200}`

#### Missing HTTP Header: permissions-policy (`VAL-HTTP-PERMISSIONS_POLICY`)

- Severity: `low`
- Description: Response is missing the security header `permissions-policy`.
- Recommendation: Set Permissions-Policy to restrict browser feature access (camera, microphone, geolocation, etc.).
- Evidence: `{"url": "https://lynolz.com", "status_code": 200}`

### Port Service Scan (`port_service_scan`)

- Category: `discovery`
- Status: `error`
- Started: `2026-03-04T08:03:47.603652+00:00`
- Ended: `2026-03-04T08:04:01.629575+00:00`
- Error: `Nmap scan timed out after 14.0s`

- Findings: `0`

### SSL Expiry Check (`ssl_expiry_check`)

- Category: `validation`
- Status: `passed`
- Started: `2026-03-04T08:04:01.636398+00:00`
- Ended: `2026-03-04T08:04:02.195867+00:00`

- Findings: `1`

#### SSL Certificate Expiry Healthy (`VAL-SSL-HEALTHY-001`)

- Severity: `info`
- Description: The TLS certificate is valid and not close to expiry.
- Evidence: `{"host": "lynolz.com", "port": 443, "days_left": 86, "expires_at": "2026-05-29T09:58:44+00:00", "issuer": [[["countryName", "US"]], [["organizationName", "Google Trust Services"]], [["commonName", "WE1"]]], "subject": [[["commonName", "lynolz.com"]]], "subject_alt_name": [["DNS", "lynolz.com"], ["DNS", "*.lynolz.com"]]}`

### TLS Certificate Validation (`tls_certificate_validation`)

- Category: `validation`
- Status: `passed`
- Started: `2026-03-04T08:04:02.200891+00:00`
- Ended: `2026-03-04T08:04:02.796935+00:00`

- Findings: `1`

#### TLS Certificate Validity Check Passed (`VAL-TLS-INFO-001`)

- Severity: `info`
- Description: TLS certificate is valid and not near expiry.
- Evidence: `{"host": "lynolz.com", "port": 443, "days_left": 86}`
