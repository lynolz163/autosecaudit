# Security Audit Report

- Generated (UTC): `2026-03-06T02:58:43.803108+00:00`
- Report Language: `en`
- Total Findings: `18`
- Vulnerabilities: `16`

## Decision Summary

[phase:verification] Proposed 4 safe action(s), total estimated cost 15, remaining budget after plan 156. Blocked actions: 4. Executable actions after environment checks: 0.

## Summary

- Critical: `0`
- High: `1`
- Medium: `5`
- Low: `4`
- Info: `6`
- Unique Vulnerability Types: `13`

Top Vulnerability Names:
- CSP Missing
- Content-Security-Policy Missing
- Exposed JavaScript Source Map
- HSTS Missing
- JavaScript Endpoint Extraction
- Login Form Detection
- Passive Technology Fingerprint
- Potential WAF/CDN Identified
- Referrer-Policy Missing
- TLS Certificate Expiring Within 7 Days
- X-Content-Type-Options Missing
- X-Frame-Options Missing
- security.txt Incomplete

## Runtime Profile

- Target: `edu.360-24.com`
- Safety Grade: `conservative`
- Iteration Count: `9`
- Budget Remaining: `879`
- Resumed: `False`
- Resumed From: `None`

## Execution Coverage

- Unique Tools Executed: `19`
- Completed/Failed/Error Actions: `24/0/7`
- Observed Service Origins: `9`
- API Endpoints / URL Params: `7 / 3`

Coverage Highlights:
- Observed 9 HTTP(S) service origin(s).
- Discovered 7 API endpoint candidate(s).
- Captured 3 parameter name(s) for follow-up input audits.
- Detected technology hints: nginx.

### Tool Execution Matrix

| Tool | Total | Completed | Failed | Error |
|------|------:|----------:|-------:|------:|
| cookie_security_audit | 5 | 2 | 0 | 3 |
| csp_evaluator | 5 | 2 | 0 | 3 |
| login_form_detector | 2 | 2 | 0 | 0 |
| passive_config_audit | 2 | 2 | 0 | 0 |
| tech_stack_fingerprint | 2 | 2 | 0 | 0 |
| ssl_expiry_check | 2 | 1 | 0 | 1 |
| api_schema_discovery | 1 | 1 | 0 | 0 |
| cors_misconfiguration | 1 | 1 | 0 | 0 |
| error_page_analyzer | 1 | 1 | 0 | 0 |
| git_exposure_check | 1 | 1 | 0 | 0 |
| http_security_headers | 1 | 1 | 0 | 0 |
| js_endpoint_extractor | 1 | 1 | 0 | 0 |
| nmap_scan | 1 | 1 | 0 | 0 |
| security_txt_check | 1 | 1 | 0 | 0 |
| source_map_detector | 1 | 1 | 0 | 0 |
| sql_sanitization_audit | 1 | 1 | 0 | 0 |
| subdomain_enum_passive | 1 | 1 | 0 | 0 |
| waf_detector | 1 | 1 | 0 | 0 |
| xss_protection_audit | 1 | 1 | 0 | 0 |

## Scope Snapshot

- Scope Entries: `1`
- Breadcrumb Records: `19`
- Surface Keys: `26`
- Scope Samples: `edu.360-24.com`

## Execution Timeline

| # | Tool | Target | Status | Cost | Budget Before | Budget After | Error |
|---|------|--------|--------|-----:|--------------:|-------------:|-------|
| 1 | subdomain_enum_passive | edu.360-24.com | completed | 5 | 999 | 979 | None |
| 2 | nmap_scan | edu.360-24.com | completed | 15 | 979 | 979 | None |
| 3 | passive_config_audit | https://edu.360-24.com:443 | completed | 3 | 979 | 939 | None |
| 4 | passive_config_audit | http://edu.360-24.com:80 | completed | 3 | 939 | 939 | None |
| 5 | tech_stack_fingerprint | https://edu.360-24.com:443/ | completed | 2 | 939 | 939 | None |
| 6 | tech_stack_fingerprint | http://edu.360-24.com:80/ | completed | 2 | 939 | 939 | None |
| 7 | git_exposure_check | https://edu.360-24.com:443/ | completed | 2 | 939 | 939 | None |
| 8 | source_map_detector | https://edu.360-24.com:443/ | completed | 2 | 939 | 939 | None |
| 9 | security_txt_check | https://edu.360-24.com:443/ | completed | 1 | 939 | 939 | None |
| 10 | login_form_detector | https://edu.360-24.com:443/ | completed | 3 | 939 | 939 | None |
| 11 | login_form_detector | http://edu.360-24.com:80/ | completed | 3 | 939 | 939 | None |
| 12 | http_security_headers | https://edu.360-24.com:443/ | completed | 3 | 939 | 939 | None |
| 13 | ssl_expiry_check | https://edu.360-24.com:443/ | completed | 3 | 939 | 939 | None |
| 14 | ssl_expiry_check | https://edu.360-24.com:8443/ | error | 3 | 939 | 939 | [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1016) |
| 15 | js_endpoint_extractor | https://edu.360-24.com:443/ | completed | 4 | 939 | 939 | None |
| 16 | error_page_analyzer | https://edu.360-24.com:443/ | completed | 3 | 939 | 939 | None |
| 17 | waf_detector | https://edu.360-24.com:443/ | completed | 3 | 939 | 939 | None |
| 18 | api_schema_discovery | https://edu.360-24.com:443/ | completed | 4 | 939 | 935 | None |
| 19 | csp_evaluator | https://edu.360-24.com:443/ | completed | 4 | 935 | 907 | None |
| 20 | cors_misconfiguration | https://edu.360-24.com:443/ | completed | 5 | 907 | 907 | None |
| 21 | xss_protection_audit | https://edu.360-24.com:443/ | completed | 8 | 907 | 907 | None |
| 22 | sql_sanitization_audit | https://edu.360-24.com:443/ | completed | 8 | 907 | 907 | None |
| 23 | cookie_security_audit | https://edu.360-24.com:443/ | completed | 3 | 907 | 907 | None |
| 24 | csp_evaluator | http://edu.360-24.com:80/ | completed | 4 | 907 | 900 | None |
| 25 | cookie_security_audit | http://edu.360-24.com:80/ | completed | 3 | 900 | 900 | None |
| 26 | csp_evaluator | https://edu.360-24.com:8443/ | error | 4 | 900 | 893 | <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1016)> |
| 27 | cookie_security_audit | https://edu.360-24.com:8443/ | error | 3 | 893 | 893 | <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1016)> |
| 28 | csp_evaluator | http://edu.360-24.com:8080/ | error | 4 | 893 | 886 | Remote end closed connection without response |
| 29 | cookie_security_audit | http://edu.360-24.com:8080/ | error | 3 | 886 | 886 | Remote end closed connection without response |
| 30 | csp_evaluator | http://edu.360-24.com:8000/ | error | 4 | 886 | 879 | Remote end closed connection without response |
| 31 | cookie_security_audit | http://edu.360-24.com:8000/ | error | 3 | 879 | 879 | Remote end closed connection without response |

## Blocked Actions

| # | Tool | Target | Reason | Preconditions |
|---|------|--------|--------|---------------|
| 1 | rag_intel_lookup | http://edu.360-24.com:3128/ | rag_intel_lookup_version_invalid | target_in_scope, not_already_done, tech_stack_available |
| 2 | cve_lookup | http://edu.360-24.com:3128/ | cve_lookup_version_invalid | target_in_scope, not_already_done, tech_stack_available |
| 3 | csp_evaluator | http://edu.360-24.com:8008/ | circuit_open:csp_evaluator:failures=3 | target_in_scope, not_already_done, http_service_confirmed |
| 4 | cookie_security_audit | http://edu.360-24.com:8008/ | circuit_open:cookie_security_audit:failures=3 | target_in_scope, not_already_done, http_service_confirmed |

## Reconnaissance & Information Gathering

### Target Overview

- **Target**: `edu.360-24.com`
- **Scope**: `edu.360-24.com`
- **Service Origins**: 9
  - `http://edu.360-24.com:3128`
  - `http://edu.360-24.com:5800`
  - `http://edu.360-24.com:80`
  - `http://edu.360-24.com:8000`
  - `http://edu.360-24.com:8008`
  - `http://edu.360-24.com:8080`
  - `http://edu.360-24.com:8888`
  - `https://edu.360-24.com:443`
  - `https://edu.360-24.com:8443`

### SSL/TLS Certificate

- **Host**: `edu.360-24.com:443`
- **TLS Version**: `TLSv1.3`
- **Days Until Expiry**: `6`
- **Expires At**: `2026-03-12T23:59:59+00:00`
- **SAN**: `DNS=*.360-24.com`, `DNS=360-24.com`

### HTTP Security Headers

| Header | Value |
|--------|-------|
| `server` | `nginx` |
| `date` | `Fri, 06 Mar 2026 02:56:08 GMT` |
| `content-type` | `text/html` |
| `content-length` | `13964` |
| `last-modified` | `Tue, 30 Dec 2025 17:29:06 GMT` |
| `connection` | `close` |
| `etag` | `"69540be2-368c"` |
| `accept-ranges` | `bytes` |

### Technology Stack

- `nginx`

### WAF / CDN Detection

- `akamai`

### security.txt

- **Present**: `True`
- **Has Contact**: `False`
- **Has Expires**: `False`

```text
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>用户登录 - 北京数据织梦智御科技有限公司</title>
<!-- Bootstrap 5.3 -->
<link href="bootstrap-5.3.2-dist/css/bootstrap.min.css" rel="stylesheet" />
<!-- Login Dark Theme -->
<link href="css/login-dark.css" rel="stylesheet" />
</head>
<body class="dd-login">
<!-- Animated Background -->
<div class="dd-bg" aria-hidden="true">
<div class="dd-bg__aurora"></div>
<div class=
```

### Content Security Policy (CSP)

- **Present**: `False`

### Login Form Detection

- **Action**: `https://edu.360-24.com:443/` (GET)
  - Parameters: `account`, `password`, `captcha`

### Source Map Detection

- `https://edu.360-24.com:443/bootstrap-5.3.2-dist/js/bootstrap.bundle.min.js.map`

### Crawled URLs

Total discovered URLs: **6**

- `https://edu.360-24.com:443/api`
- `https://edu.360-24.com:443/api/user/profile`
- `https://edu.360-24.com:443/auth/captcha`
- `https://edu.360-24.com:443/auth/login`
- `https://edu.360-24.com:443/auth/logout`
- `https://edu.360-24.com:443/login.html`

### API Endpoints

Total API endpoints: **7**

| URL | Method | Source |
|-----|--------|--------|
| `https://edu.360-24.com:443/` | GET | login_form |
| `https://edu.360-24.com:443/api` | GET | https://edu.360-24.com:443/js/api.js |
| `https://edu.360-24.com:443/login.html` | GET | https://edu.360-24.com:443/js/api.js |
| `https://edu.360-24.com:443/auth/captcha` | GET | https://edu.360-24.com:443/js/api.js |
| `https://edu.360-24.com:443/auth/login` | GET | https://edu.360-24.com:443/js/api.js |
| `https://edu.360-24.com:443/auth/logout` | GET | https://edu.360-24.com:443/js/api.js |
| `https://edu.360-24.com:443/api/user/profile` | GET | https://edu.360-24.com:443/js/login-dark.js |

### URL Parameters

- `account`: ``
- `password`: ``
- `captcha`: ``

## Findings Catalog

| # | Name | Type | Severity | CVE |
|---|------|------|----------|-----|
| 1 | Passive Subdomain Enumeration Results | info | Info | - |
| 2 | Passive Technology Fingerprint | vuln | Info | None |
| 3 | Passive Technology Fingerprint | vuln | Info | None |
| 4 | Exposed JavaScript Source Map | vuln | Medium | None |
| 5 | security.txt Incomplete | vuln | Low | None |
| 6 | Login Form Detection | vuln | Info | None |
| 7 | Login Form Detection | vuln | Info | None |
| 8 | HSTS Missing | vuln | Medium | None |
| 9 | CSP Missing | vuln | Medium | None |
| 10 | X-Frame-Options Missing | vuln | Low | None |
| 11 | X-Content-Type-Options Missing | vuln | Low | None |
| 12 | Referrer-Policy Missing | vuln | Low | None |
| 13 | TLS Certificate Expiring Within 7 Days | vuln | High | - |
| 14 | JavaScript Endpoint Extraction | vuln | Info | None |
| 15 | Potential WAF/CDN Identified | vuln | Info | None |
| 16 | Content-Security-Policy Missing | vuln | Medium | None |
| 17 | No Obvious CORS Misconfiguration | info | Info | - |
| 18 | Content-Security-Policy Missing | vuln | Medium | None |

## Detailed Evidence

### 1. Passive Subdomain Enumeration Results (Severity: Info)

- Type: `info`
- Category: `-`
- CVE Verified: `False`

**Evidence**

```text
{"domain": "edu.360-24.com", "count": 0, "subdomains": []}
```

**Reproduction Steps**

1. Query crt.sh for %.edu.360-24.com and review returned SAN/CN values.

**Remediation**

Review evidence, confirm impact, and apply least-privilege plus secure configuration controls.

### 2. Passive Technology Fingerprint (Severity: Info)

- Type: `vuln`
- Category: `info_leak`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"server": "nginx", "status_code": 200, "tech_stack": ["nginx"], "url": "https://edu.360-24.com:443"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Review exposed technology markers and minimize unnecessary fingerprinting signals where practical.

### 3. Passive Technology Fingerprint (Severity: Info)

- Type: `vuln`
- Category: `info_leak`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"server": "", "status_code": 503, "tech_stack": [], "url": "http://edu.360-24.com:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Review exposed technology markers and minimize unnecessary fingerprinting signals where practical.

### 4. Exposed JavaScript Source Map (Severity: Medium)

- Type: `vuln`
- Category: `info_leak`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"script_url": "https://edu.360-24.com:443/bootstrap-5.3.2-dist/js/bootstrap.bundle.min.js", "url": "https://edu.360-24.com:443/bootstrap-5.3.2-dist/js/bootstrap.bundle.min.js.map"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Disable public source map exposure in production or gate access to build artifacts.

### 5. security.txt Incomplete (Severity: Low)

- Type: `vuln`
- Category: `compliance`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"has_contact": false, "has_expires": false, "status_code": 200, "url": "https://edu.360-24.com:443/.well-known/security.txt"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Ensure security.txt includes at least Contact and Expires fields.

### 6. Login Form Detection (Severity: Info)

- Type: `vuln`
- Category: `info_leak`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"forms": [{"action": "https://edu.360-24.com:443/", "method": "GET", "params": {"account": "", "captcha": "", "password": ""}}], "status_code": 200, "url": "https://edu.360-24.com:443"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Use the discovered auth surface to drive low-risk validation of cookie and session controls.

### 7. Login Form Detection (Severity: Info)

- Type: `vuln`
- Category: `info_leak`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"forms": [], "status_code": 503, "url": "http://edu.360-24.com:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Use the discovered auth surface to drive low-risk validation of cookie and session controls.

### 8. HSTS Missing (Severity: Medium)

- Type: `vuln`
- Category: `misconfig`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"missing_header": "strict-transport-security", "status_code": 200, "url": "https://edu.360-24.com:443"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Add Strict-Transport-Security on HTTPS responses.

### 9. CSP Missing (Severity: Medium)

- Type: `vuln`
- Category: `misconfig`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"missing_header": "content-security-policy", "status_code": 200, "url": "https://edu.360-24.com:443"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Add a Content-Security-Policy to reduce XSS impact.

### 10. X-Frame-Options Missing (Severity: Low)

- Type: `vuln`
- Category: `misconfig`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"missing_header": "x-frame-options", "status_code": 200, "url": "https://edu.360-24.com:443"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Set X-Frame-Options or CSP frame-ancestors.

### 11. X-Content-Type-Options Missing (Severity: Low)

- Type: `vuln`
- Category: `misconfig`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"missing_header": "x-content-type-options", "status_code": 200, "url": "https://edu.360-24.com:443"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Set X-Content-Type-Options: nosniff.

### 12. Referrer-Policy Missing (Severity: Low)

- Type: `vuln`
- Category: `misconfig`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"missing_header": "referrer-policy", "status_code": 200, "url": "https://edu.360-24.com:443"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Set Referrer-Policy to reduce cross-origin leakage.

### 13. TLS Certificate Expiring Within 7 Days (Severity: High)

- Type: `vuln`
- Category: `-`
- CVE Verified: `False`

**Evidence**

```text
{"host": "edu.360-24.com", "port": 443, "days_left": 6, "expires_at": "2026-03-12T23:59:59+00:00", "tls_version": "TLSv1.3", "subject_alt_name": [["DNS", "*.360-24.com"], ["DNS", "360-24.com"]]}
```

**Reproduction Steps**

1. Open TLS connection to edu.360-24.com:443.
2. Observe imminent certificate expiry.

**Remediation**

Review evidence, confirm impact, and apply least-privilege plus secure configuration controls.

### 14. JavaScript Endpoint Extraction (Severity: Info)

- Type: `vuln`
- Category: `info_leak`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"count": 6, "scripts": ["https://edu.360-24.com:443/bootstrap-5.3.2-dist/js/bootstrap.bundle.min.js", "https://edu.360-24.com:443/js/security-utils.js", "https://edu.360-24.com:443/js/api.js", "https://edu.360-24.com:443/js/login-dark.js"], "url": "https://edu.360-24.com:443"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Review exposed client-side endpoints and ensure undocumented APIs are properly scoped and protected.

### 15. Potential WAF/CDN Identified (Severity: Info)

- Type: `vuln`
- Category: `misconfig`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"status_code": 200, "url": "https://edu.360-24.com:443", "vendor": "akamai"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Account for upstream WAF/CDN behavior when validating false positives or tuning scans.

### 16. Content-Security-Policy Missing (Severity: Medium)

- Type: `vuln`
- Category: `misconfig`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"status_code": 200, "url": "https://edu.360-24.com:443"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Deploy a restrictive Content-Security-Policy tailored to the application.

### 17. No Obvious CORS Misconfiguration (Severity: Info)

- Type: `info`
- Category: `-`
- CVE Verified: `False`

**Evidence**

```text
[{"origin": "https://evil.example.com", "status_code": 405, "probe_method": "OPTIONS", "allow_origin": null, "allow_credentials": null}, {"origin": "null", "status_code": 405, "probe_method": "OPTIONS", "allow_origin": null, "allow_credentials": null}, {"origin": "https://edu.360-24.com.evil.invalid", "status_code": 405, "probe_method": "OPTIONS", "allow_origin": null, "allow_credentials": null}]
```

**Reproduction Steps**

1. Probe https://edu.360-24.com:443 with untrusted Origin headers and inspect response.

**Remediation**

Remove public exposure, rotate leaked secrets, and enforce deny-by-default on sensitive files.

### 18. Content-Security-Policy Missing (Severity: Medium)

- Type: `vuln`
- Category: `misconfig`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"status_code": 503, "url": "http://edu.360-24.com:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Deploy a restrictive Content-Security-Policy tailored to the application.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `999`
