# Security Audit Report

- Generated (UTC): `2026-03-06T03:55:29.984369+00:00`
- Report Language: `en`
- Total Findings: `20`
- Vulnerabilities: `19`

## Decision Summary

[phase:verification] Proposed 4 safe action(s), total estimated cost 15, remaining budget after plan 156. Blocked actions: 4. Executable actions after environment checks: 0.

## Summary

- Critical: `0`
- High: `4`
- Medium: `6`
- Low: `4`
- Info: `5`
- Unique Vulnerability Types: `14`

Top Vulnerability Names:
- API Schema Endpoint Discovered
- CORS Allows Any Origin With Credentials
- CSP Missing
- Content-Security-Policy Missing
- Exposed JavaScript Source Map
- HSTS Missing
- JavaScript Endpoint Extraction
- Login Form Detection
- Passive Technology Fingerprint
- Referrer-Policy Missing
- TLS Certificate Expiring Within 7 Days
- X-Content-Type-Options Missing
- X-Frame-Options Missing
- security.txt Incomplete

## Runtime Profile

- Target: `360-24.com`
- Safety Grade: `conservative`
- Iteration Count: `9`
- Budget Remaining: `895`
- Resumed: `False`
- Resumed From: `None`

## Execution Coverage

- Unique Tools Executed: `17`
- Completed/Failed/Error Actions: `21/0/8`
- Observed Service Origins: `10`
- API Endpoints / URL Params: `1 / 0`

Coverage Highlights:
- Observed 10 HTTP(S) service origin(s).
- Discovered 1 API endpoint candidate(s).
- Detected technology hints: nginx.

### Tool Execution Matrix

| Tool | Total | Completed | Failed | Error |
|------|------:|----------:|-------:|------:|
| cookie_security_audit | 5 | 2 | 0 | 3 |
| csp_evaluator | 5 | 2 | 0 | 3 |
| login_form_detector | 2 | 2 | 0 | 0 |
| passive_config_audit | 2 | 2 | 0 | 0 |
| ssl_expiry_check | 2 | 1 | 0 | 1 |
| tech_stack_fingerprint | 2 | 1 | 0 | 1 |
| api_schema_discovery | 1 | 1 | 0 | 0 |
| cors_misconfiguration | 1 | 1 | 0 | 0 |
| error_page_analyzer | 1 | 1 | 0 | 0 |
| git_exposure_check | 1 | 1 | 0 | 0 |
| http_security_headers | 1 | 1 | 0 | 0 |
| js_endpoint_extractor | 1 | 1 | 0 | 0 |
| nmap_scan | 1 | 1 | 0 | 0 |
| security_txt_check | 1 | 1 | 0 | 0 |
| source_map_detector | 1 | 1 | 0 | 0 |
| subdomain_enum_passive | 1 | 1 | 0 | 0 |
| waf_detector | 1 | 1 | 0 | 0 |

## Scope Snapshot

- Scope Entries: `1`
- Breadcrumb Records: `15`
- Surface Keys: `26`
- Scope Samples: `360-24.com`

## Execution Timeline

| # | Tool | Target | Status | Cost | Budget Before | Budget After | Error |
|---|------|--------|--------|-----:|--------------:|-------------:|-------|
| 1 | subdomain_enum_passive | 360-24.com | completed | 5 | 999 | 979 | None |
| 2 | nmap_scan | 360-24.com | completed | 15 | 979 | 979 | None |
| 3 | passive_config_audit | https://360-24.com:443 | completed | 3 | 979 | 939 | None |
| 4 | passive_config_audit | http://360-24.com:80 | completed | 3 | 939 | 939 | None |
| 5 | tech_stack_fingerprint | https://360-24.com:443/ | completed | 2 | 939 | 939 | None |
| 6 | tech_stack_fingerprint | http://360-24.com:80/ | error | 2 | 939 | 939 | timed out |
| 7 | git_exposure_check | https://360-24.com:443/ | completed | 2 | 939 | 939 | None |
| 8 | source_map_detector | https://360-24.com:443/ | completed | 2 | 939 | 939 | None |
| 9 | security_txt_check | https://360-24.com:443/ | completed | 1 | 939 | 939 | None |
| 10 | login_form_detector | https://360-24.com:443/ | completed | 3 | 939 | 939 | None |
| 11 | login_form_detector | http://360-24.com:80/ | completed | 3 | 939 | 939 | None |
| 12 | http_security_headers | https://360-24.com:443/ | completed | 3 | 939 | 939 | None |
| 13 | ssl_expiry_check | https://360-24.com:443/ | completed | 3 | 939 | 939 | None |
| 14 | ssl_expiry_check | https://360-24.com:8443/ | error | 3 | 939 | 939 | [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1016) |
| 15 | js_endpoint_extractor | https://360-24.com:443/ | completed | 4 | 939 | 939 | None |
| 16 | error_page_analyzer | https://360-24.com:443/ | completed | 3 | 939 | 939 | None |
| 17 | waf_detector | https://360-24.com:443/ | completed | 3 | 939 | 939 | None |
| 18 | api_schema_discovery | https://360-24.com:443/ | completed | 4 | 939 | 935 | None |
| 19 | csp_evaluator | https://360-24.com:443/ | completed | 4 | 935 | 923 | None |
| 20 | cors_misconfiguration | https://360-24.com:443/ | completed | 5 | 923 | 923 | None |
| 21 | cookie_security_audit | https://360-24.com:443/ | completed | 3 | 923 | 923 | None |
| 22 | csp_evaluator | http://360-24.com:80/ | completed | 4 | 923 | 916 | None |
| 23 | cookie_security_audit | http://360-24.com:80/ | completed | 3 | 916 | 916 | None |
| 24 | csp_evaluator | https://360-24.com:8443/ | error | 4 | 916 | 909 | <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1016)> |
| 25 | cookie_security_audit | https://360-24.com:8443/ | error | 3 | 909 | 909 | <urlopen error [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1016)> |
| 26 | csp_evaluator | http://360-24.com:8080/ | error | 4 | 909 | 902 | Remote end closed connection without response |
| 27 | cookie_security_audit | http://360-24.com:8080/ | error | 3 | 902 | 902 | Remote end closed connection without response |
| 28 | csp_evaluator | http://360-24.com:8000/ | error | 4 | 902 | 895 | Remote end closed connection without response |
| 29 | cookie_security_audit | http://360-24.com:8000/ | error | 3 | 895 | 895 | Remote end closed connection without response |

## Blocked Actions

| # | Tool | Target | Reason | Preconditions |
|---|------|--------|--------|---------------|
| 1 | rag_intel_lookup | http://360-24.com:3128/ | rag_intel_lookup_version_invalid | target_in_scope, not_already_done, tech_stack_available |
| 2 | cve_lookup | http://360-24.com:3128/ | cve_lookup_version_invalid | target_in_scope, not_already_done, tech_stack_available |
| 3 | csp_evaluator | http://360-24.com:8008/ | circuit_open:csp_evaluator:failures=3 | target_in_scope, not_already_done, http_service_confirmed |
| 4 | cookie_security_audit | http://360-24.com:8008/ | circuit_open:cookie_security_audit:failures=3 | target_in_scope, not_already_done, http_service_confirmed |

## Reconnaissance & Information Gathering

### Target Overview

- **Target**: `360-24.com`
- **Scope**: `360-24.com`
- **Service Origins**: 10
  - `http://360-24.com:3128`
  - `http://360-24.com:5800`
  - `http://360-24.com:80`
  - `http://360-24.com:8000`
  - `http://360-24.com:8008`
  - `http://360-24.com:8080`
  - `http://360-24.com:8888`
  - `https://360-24.com`
  - `https://360-24.com:443`
  - `https://360-24.com:8443`

### Subdomain Enumeration

Discovered **1** subdomain(s) via passive enumeration:

- `360-24.com`

### SSL/TLS Certificate

- **Host**: `360-24.com:443`
- **TLS Version**: `TLSv1.3`
- **Days Until Expiry**: `6`
- **Expires At**: `2026-03-12T23:59:59+00:00`
- **SAN**: `DNS=*.360-24.com`, `DNS=360-24.com`

### HTTP Security Headers

| Header | Value |
|--------|-------|
| `server` | `nginx/1.14.1` |
| `date` | `Fri, 06 Mar 2026 03:53:35 GMT` |
| `content-type` | `text/html` |
| `content-length` | `61877` |
| `last-modified` | `Sat, 02 Aug 2025 09:42:59 GMT` |
| `connection` | `close` |
| `etag` | `"688ddda3-f1b5"` |
| `access-control-allow-origin` | `*` |
| `access-control-allow-methods` | `GET, POST, PUT, DELETE, OPTIONS` |
| `access-control-allow-headers` | `Origin, X-Requested-With, Content-Type, Accept, Authorization` |
| `access-control-allow-credentials` | `true` |
| `accept-ranges` | `bytes` |

### Technology Stack

- `nginx`

### security.txt

- **Present**: `True`
- **Has Contact**: `False`
- **Has Expires**: `False`

```text
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>北京数据织梦智御科技有限公司 - 专业AI、网络安全、云计算解决方案</title>
<!-- Bootstrap 5.3 CSS -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<!-- Font Awesome -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<!-- AOS Animation Library -->
<link href="https://unpkg
```

### Content Security Policy (CSP)

- **Present**: `False`

### API Schema Discovery

- `https://360-24.com:443/graphql` (graphql) — HTTP 200

### Source Map Detection

- `https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js.map`
- `https://unpkg.com/aos@2.3.1/dist/aos.js.map`

### API Endpoints

Total API endpoints: **1**

| URL | Method | Source |
|-----|--------|--------|
| `https://360-24.com:443/graphql` | GET | api_schema_discovery |

## Findings Catalog

| # | Name | Type | Severity | CVE |
|---|------|------|----------|-----|
| 1 | Passive Subdomain Enumeration Results | info | Info | - |
| 2 | Passive Technology Fingerprint | vuln | Info | None |
| 3 | Exposed JavaScript Source Map | vuln | Medium | None |
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
| 15 | API Schema Endpoint Discovered | vuln | Info | None |
| 16 | Content-Security-Policy Missing | vuln | Medium | None |
| 17 | CORS Allows Any Origin With Credentials | vuln | High | - |
| 18 | CORS Allows Any Origin With Credentials | vuln | High | - |
| 19 | CORS Allows Any Origin With Credentials | vuln | High | - |
| 20 | Content-Security-Policy Missing | vuln | Medium | None |

## Detailed Evidence

### 1. Passive Subdomain Enumeration Results (Severity: Info)

- Type: `info`
- Category: `-`
- CVE Verified: `False`

**Evidence**

```text
{"domain": "360-24.com", "count": 1, "subdomains": ["360-24.com"]}
```

**Reproduction Steps**

1. Query crt.sh for %.360-24.com and review returned SAN/CN values.

**Remediation**

Review evidence, confirm impact, and apply least-privilege plus secure configuration controls.

### 2. Passive Technology Fingerprint (Severity: Info)

- Type: `vuln`
- Category: `info_leak`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"server": "nginx/1.14.1", "status_code": 200, "tech_stack": ["nginx"], "url": "https://360-24.com:443"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Review exposed technology markers and minimize unnecessary fingerprinting signals where practical.

### 3. Exposed JavaScript Source Map (Severity: Medium)

- Type: `vuln`
- Category: `info_leak`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"script_url": "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js", "url": "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js.map"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Disable public source map exposure in production or gate access to build artifacts.

### 4. Exposed JavaScript Source Map (Severity: Medium)

- Type: `vuln`
- Category: `info_leak`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"script_url": "https://unpkg.com/aos@2.3.1/dist/aos.js", "url": "https://unpkg.com/aos@2.3.1/dist/aos.js.map"}
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
{"has_contact": false, "has_expires": false, "status_code": 200, "url": "https://360-24.com:443/.well-known/security.txt"}
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
{"forms": [], "status_code": 200, "url": "https://360-24.com:443"}
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
{"forms": [], "status_code": 503, "url": "http://360-24.com:80"}
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
{"missing_header": "strict-transport-security", "status_code": 200, "url": "https://360-24.com:443"}
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
{"missing_header": "content-security-policy", "status_code": 200, "url": "https://360-24.com:443"}
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
{"missing_header": "x-frame-options", "status_code": 200, "url": "https://360-24.com:443"}
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
{"missing_header": "x-content-type-options", "status_code": 200, "url": "https://360-24.com:443"}
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
{"missing_header": "referrer-policy", "status_code": 200, "url": "https://360-24.com:443"}
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
{"host": "360-24.com", "port": 443, "days_left": 6, "expires_at": "2026-03-12T23:59:59+00:00", "tls_version": "TLSv1.3", "subject_alt_name": [["DNS", "*.360-24.com"], ["DNS", "360-24.com"]]}
```

**Reproduction Steps**

1. Open TLS connection to 360-24.com:443.
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
{"count": 0, "scripts": ["https://360-24.com:443/js/script.js"], "url": "https://360-24.com:443"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Review exposed client-side endpoints and ensure undocumented APIs are properly scoped and protected.

### 15. API Schema Endpoint Discovered (Severity: Info)

- Type: `vuln`
- Category: `info_leak`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"content_type": "text/html", "status_code": 200, "url": "https://360-24.com:443/graphql"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Restrict schema exposure in production or ensure it contains no sensitive metadata.

### 16. Content-Security-Policy Missing (Severity: Medium)

- Type: `vuln`
- Category: `misconfig`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"status_code": 200, "url": "https://360-24.com:443"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

**Remediation**

Deploy a restrictive Content-Security-Policy tailored to the application.

### 17. CORS Allows Any Origin With Credentials (Severity: High)

- Type: `vuln`
- Category: `-`
- CVE Verified: `False`

**Evidence**

```text
{"origin": "https://evil.example.com", "status_code": 204, "probe_method": "OPTIONS", "allow_origin": "*", "allow_credentials": "true"}
```

**Reproduction Steps**

1. Send OPTIONS/GET request to https://360-24.com:443 with Origin: https://evil.example.com.
2. Observe wildcard ACAO plus credentials.

**Remediation**

Review evidence, confirm impact, and apply least-privilege plus secure configuration controls.

### 18. CORS Allows Any Origin With Credentials (Severity: High)

- Type: `vuln`
- Category: `-`
- CVE Verified: `False`

**Evidence**

```text
{"origin": "null", "status_code": 204, "probe_method": "OPTIONS", "allow_origin": "*", "allow_credentials": "true"}
```

**Reproduction Steps**

1. Send OPTIONS/GET request to https://360-24.com:443 with Origin: null.
2. Observe wildcard ACAO plus credentials.

**Remediation**

Review evidence, confirm impact, and apply least-privilege plus secure configuration controls.

### 19. CORS Allows Any Origin With Credentials (Severity: High)

- Type: `vuln`
- Category: `-`
- CVE Verified: `False`

**Evidence**

```text
{"origin": "https://360-24.com.evil.invalid", "status_code": 204, "probe_method": "OPTIONS", "allow_origin": "*", "allow_credentials": "true"}
```

**Reproduction Steps**

1. Send OPTIONS/GET request to https://360-24.com:443 with Origin: https://360-24.com.evil.invalid.
2. Observe wildcard ACAO plus credentials.

**Remediation**

Review evidence, confirm impact, and apply least-privilege plus secure configuration controls.

### 20. Content-Security-Policy Missing (Severity: Medium)

- Type: `vuln`
- Category: `misconfig`
- CVE: `None`
- CVE Verified: `False`

**Evidence**

```text
{"status_code": 503, "url": "http://360-24.com:80"}
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
