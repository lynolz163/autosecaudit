# Security Audit Report

- Generated (UTC): `2026-03-04T12:57:56.344775+00:00`
- Total Findings: `19`
- Vulnerabilities: `16`

## Summary

- Critical: `0`
- High: `0`
- Medium: `6`
- Low: `4`
- Info: `6`
- Unique Vulnerability Types: `16`

Top Vulnerability Names:
- TLS Certificate Expiring Soon
- Unnamed Finding 10
- Unnamed Finding 11
- Unnamed Finding 12
- Unnamed Finding 14
- Unnamed Finding 15
- Unnamed Finding 16
- Unnamed Finding 19
- Unnamed Finding 2
- Unnamed Finding 3
- Unnamed Finding 4
- Unnamed Finding 5
- Unnamed Finding 6
- Unnamed Finding 7
- Unnamed Finding 8
- Unnamed Finding 9

## Vulnerability List

| # | Name | Type | Severity |
|---|------|------|----------|
| 2 | Unnamed Finding 2 | vuln | Info |
| 3 | Unnamed Finding 3 | vuln | Info |
| 4 | Unnamed Finding 4 | vuln | Medium |
| 5 | Unnamed Finding 5 | vuln | Low |
| 6 | Unnamed Finding 6 | vuln | Info |
| 7 | Unnamed Finding 7 | vuln | Info |
| 8 | Unnamed Finding 8 | vuln | Medium |
| 9 | Unnamed Finding 9 | vuln | Medium |
| 10 | Unnamed Finding 10 | vuln | Low |
| 11 | Unnamed Finding 11 | vuln | Low |
| 12 | Unnamed Finding 12 | vuln | Low |
| 13 | TLS Certificate Expiring Soon | vuln | Medium |
| 14 | Unnamed Finding 14 | vuln | Info |
| 15 | Unnamed Finding 15 | vuln | Info |
| 16 | Unnamed Finding 16 | vuln | Medium |
| 19 | Unnamed Finding 19 | vuln | Medium |

## Evidence

### 2. Unnamed Finding 2 (Severity: Info)

**Detailed Evidence**

```text
{'url': 'https://edu.360-24.com:443', 'status_code': 200, 'tech_stack': ['nginx'], 'server': 'nginx'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 3. Unnamed Finding 3 (Severity: Info)

**Detailed Evidence**

```text
{'url': 'http://edu.360-24.com:80', 'status_code': 503, 'tech_stack': [], 'server': ''}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 4. Unnamed Finding 4 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://edu.360-24.com:443/bootstrap-5.3.2-dist/js/bootstrap.bundle.min.js.map', 'script_url': 'https://edu.360-24.com:443/bootstrap-5.3.2-dist/js/bootstrap.bundle.min.js'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 5. Unnamed Finding 5 (Severity: Low)

**Detailed Evidence**

```text
{'url': 'https://edu.360-24.com:443/.well-known/security.txt', 'status_code': 200, 'has_contact': False, 'has_expires': False}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 6. Unnamed Finding 6 (Severity: Info)

**Detailed Evidence**

```text
{'status_code': 200, 'forms': [{'action': 'https://edu.360-24.com:443/', 'method': 'GET', 'params': {'account': '', 'password': '', 'captcha': ''}}], 'url': 'https://edu.360-24.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 7. Unnamed Finding 7 (Severity: Info)

**Detailed Evidence**

```text
{'status_code': 503, 'forms': [], 'url': 'http://edu.360-24.com:80'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 8. Unnamed Finding 8 (Severity: Medium)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'strict-transport-security', 'url': 'https://edu.360-24.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 9. Unnamed Finding 9 (Severity: Medium)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'content-security-policy', 'url': 'https://edu.360-24.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 10. Unnamed Finding 10 (Severity: Low)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'x-frame-options', 'url': 'https://edu.360-24.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 11. Unnamed Finding 11 (Severity: Low)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'x-content-type-options', 'url': 'https://edu.360-24.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 12. Unnamed Finding 12 (Severity: Low)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'referrer-policy', 'url': 'https://edu.360-24.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 13. TLS Certificate Expiring Soon (Severity: Medium)

**Detailed Evidence**

```text
{"host": "edu.360-24.com", "port": 443, "days_left": 8, "expires_at": "2026-03-12T23:59:59+00:00", "tls_version": "TLSv1.3", "subject_alt_name": [["DNS", "*.360-24.com"], ["DNS", "360-24.com"]]}
```

**Reproduction Steps**

1. Open TLS connection to edu.360-24.com:443.
2. Observe expiry window below 30 days.

### 14. Unnamed Finding 14 (Severity: Info)

**Detailed Evidence**

```text
{'url': 'https://edu.360-24.com:443', 'count': 6, 'scripts': ['https://edu.360-24.com:443/bootstrap-5.3.2-dist/js/bootstrap.bundle.min.js', 'https://edu.360-24.com:443/js/security-utils.js', 'https://edu.360-24.com:443/js/api.js', 'https://edu.360-24.com:443/js/login-dark.js']}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 15. Unnamed Finding 15 (Severity: Info)

**Detailed Evidence**

```text
{'url': 'https://edu.360-24.com:443', 'status_code': 200, 'vendor': 'akamai'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 16. Unnamed Finding 16 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://edu.360-24.com:443', 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 19. Unnamed Finding 19 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'http://edu.360-24.com:80', 'status_code': 503}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `999`
