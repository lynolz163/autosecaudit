# Security Audit Report

- Generated (UTC): `2026-03-05T01:54:11.945502+00:00`
- Total Findings: `15`
- Vulnerabilities: `13`

## Summary

- Critical: `0`
- High: `1`
- Medium: `4`
- Low: `4`
- Info: `4`
- Unique Vulnerability Types: `13`

Top Vulnerability Names:
- TLS Certificate Expiring Within 7 Days
- Unnamed Finding 10
- Unnamed Finding 12
- Unnamed Finding 13
- Unnamed Finding 14
- Unnamed Finding 2
- Unnamed Finding 3
- Unnamed Finding 4
- Unnamed Finding 5
- Unnamed Finding 6
- Unnamed Finding 7
- Unnamed Finding 8
- Unnamed Finding 9

## Reconnaissance & Information Gathering

### Target Overview

- **Target**: `edu.360-24.com`
- **Scope**: `edu.360-24.com`
- **Service Origins**: 1
  - `https://edu.360-24.com:443`

### SSL/TLS Certificate

- **Host**: `edu.360-24.com:443`
- **TLS Version**: `TLSv1.3`
- **Days Until Expiry**: `7`
- **Expires At**: `2026-03-12T23:59:59+00:00`
- **SAN**: `DNS=*.360-24.com`, `DNS=360-24.com`

### HTTP Security Headers

| Header | Value |
|--------|-------|
| `server` | `nginx` |
| `date` | `Thu, 05 Mar 2026 01:52:57 GMT` |
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

## Vulnerability List

| # | Name | Type | Severity |
|---|------|------|----------|
| 2 | Unnamed Finding 2 | vuln | Info |
| 3 | Unnamed Finding 3 | vuln | Medium |
| 4 | Unnamed Finding 4 | vuln | Low |
| 5 | Unnamed Finding 5 | vuln | Info |
| 6 | Unnamed Finding 6 | vuln | Medium |
| 7 | Unnamed Finding 7 | vuln | Medium |
| 8 | Unnamed Finding 8 | vuln | Low |
| 9 | Unnamed Finding 9 | vuln | Low |
| 10 | Unnamed Finding 10 | vuln | Low |
| 11 | TLS Certificate Expiring Within 7 Days | vuln | High |
| 12 | Unnamed Finding 12 | vuln | Info |
| 13 | Unnamed Finding 13 | vuln | Info |
| 14 | Unnamed Finding 14 | vuln | Medium |

## Evidence

### 2. Unnamed Finding 2 (Severity: Info)

**Detailed Evidence**

```text
{'url': 'https://edu.360-24.com:443', 'status_code': 200, 'tech_stack': ['nginx'], 'server': 'nginx'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 3. Unnamed Finding 3 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://edu.360-24.com:443/bootstrap-5.3.2-dist/js/bootstrap.bundle.min.js.map', 'script_url': 'https://edu.360-24.com:443/bootstrap-5.3.2-dist/js/bootstrap.bundle.min.js'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 4. Unnamed Finding 4 (Severity: Low)

**Detailed Evidence**

```text
{'url': 'https://edu.360-24.com:443/.well-known/security.txt', 'status_code': 200, 'has_contact': False, 'has_expires': False}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 5. Unnamed Finding 5 (Severity: Info)

**Detailed Evidence**

```text
{'status_code': 200, 'forms': [{'action': 'https://edu.360-24.com:443/', 'method': 'GET', 'params': {'account': '', 'password': '', 'captcha': ''}}], 'url': 'https://edu.360-24.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 6. Unnamed Finding 6 (Severity: Medium)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'strict-transport-security', 'url': 'https://edu.360-24.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 7. Unnamed Finding 7 (Severity: Medium)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'content-security-policy', 'url': 'https://edu.360-24.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 8. Unnamed Finding 8 (Severity: Low)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'x-frame-options', 'url': 'https://edu.360-24.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 9. Unnamed Finding 9 (Severity: Low)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'x-content-type-options', 'url': 'https://edu.360-24.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 10. Unnamed Finding 10 (Severity: Low)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'referrer-policy', 'url': 'https://edu.360-24.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 11. TLS Certificate Expiring Within 7 Days (Severity: High)

**Detailed Evidence**

```text
{"host": "edu.360-24.com", "port": 443, "days_left": 7, "expires_at": "2026-03-12T23:59:59+00:00", "tls_version": "TLSv1.3", "subject_alt_name": [["DNS", "*.360-24.com"], ["DNS", "360-24.com"]]}
```

**Reproduction Steps**

1. Open TLS connection to edu.360-24.com:443.
2. Observe imminent certificate expiry.

### 12. Unnamed Finding 12 (Severity: Info)

**Detailed Evidence**

```text
{'url': 'https://edu.360-24.com:443', 'count': 6, 'scripts': ['https://edu.360-24.com:443/bootstrap-5.3.2-dist/js/bootstrap.bundle.min.js', 'https://edu.360-24.com:443/js/security-utils.js', 'https://edu.360-24.com:443/js/api.js', 'https://edu.360-24.com:443/js/login-dark.js']}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 13. Unnamed Finding 13 (Severity: Info)

**Detailed Evidence**

```text
{'url': 'https://edu.360-24.com:443', 'status_code': 200, 'vendor': 'akamai'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 14. Unnamed Finding 14 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://edu.360-24.com:443', 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `999`
