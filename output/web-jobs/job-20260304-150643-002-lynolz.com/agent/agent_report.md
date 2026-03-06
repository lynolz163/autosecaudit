# Security Audit Report

- Generated (UTC): `2026-03-04T07:14:04.648085+00:00`
- Total Findings: `26`
- Vulnerabilities: `22`

## Summary

- Critical: `0`
- High: `5`
- Medium: `11`
- Low: `4`
- Info: `2`
- Unique Vulnerability Types: `18`

Top Vulnerability Names:
- Potential XSS Reflection / Encoding Weakness
- Unnamed Finding 1
- Unnamed Finding 10
- Unnamed Finding 11
- Unnamed Finding 12
- Unnamed Finding 16
- Unnamed Finding 17
- Unnamed Finding 2
- Unnamed Finding 20
- Unnamed Finding 21
- Unnamed Finding 22
- Unnamed Finding 24
- Unnamed Finding 3
- Unnamed Finding 4
- Unnamed Finding 5
- Unnamed Finding 6
- Unnamed Finding 7
- Unnamed Finding 8

## Vulnerability List

| # | Name | Type | Severity |
|---|------|------|----------|
| 1 | Unnamed Finding 1 | vuln | Info |
| 2 | Unnamed Finding 2 | vuln | Low |
| 3 | Unnamed Finding 3 | vuln | Info |
| 4 | Unnamed Finding 4 | vuln | Medium |
| 5 | Unnamed Finding 5 | vuln | Medium |
| 6 | Unnamed Finding 6 | vuln | Low |
| 7 | Unnamed Finding 7 | vuln | Low |
| 8 | Unnamed Finding 8 | vuln | Low |
| 10 | Unnamed Finding 10 | vuln | Medium |
| 11 | Unnamed Finding 11 | vuln | Medium |
| 12 | Unnamed Finding 12 | vuln | Medium |
| 16 | Unnamed Finding 16 | vuln | Medium |
| 17 | Unnamed Finding 17 | vuln | Medium |
| 18 | Potential XSS Reflection / Encoding Weakness | vuln | High |
| 19 | Potential XSS Reflection / Encoding Weakness | vuln | High |
| 20 | Unnamed Finding 20 | vuln | Medium |
| 21 | Unnamed Finding 21 | vuln | Medium |
| 22 | Unnamed Finding 22 | vuln | Medium |
| 23 | Potential XSS Reflection / Encoding Weakness | vuln | High |
| 24 | Unnamed Finding 24 | vuln | Medium |
| 25 | Potential XSS Reflection / Encoding Weakness | vuln | High |
| 26 | Potential XSS Reflection / Encoding Weakness | vuln | High |

## Evidence

### 1. Unnamed Finding 1 (Severity: Info)

**Detailed Evidence**

```text
{'url': 'https://lynolz.com:443', 'status_code': 200, 'tech_stack': [], 'server': 'cloudflare'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 2. Unnamed Finding 2 (Severity: Low)

**Detailed Evidence**

```text
{'url': 'https://lynolz.com:443/.well-known/security.txt', 'status_code': 404}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 3. Unnamed Finding 3 (Severity: Info)

**Detailed Evidence**

```text
{'status_code': 200, 'forms': [], 'url': 'https://lynolz.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 4. Unnamed Finding 4 (Severity: Medium)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'strict-transport-security', 'url': 'https://lynolz.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 5. Unnamed Finding 5 (Severity: Medium)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'content-security-policy', 'url': 'https://lynolz.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 6. Unnamed Finding 6 (Severity: Low)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'x-frame-options', 'url': 'https://lynolz.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 7. Unnamed Finding 7 (Severity: Low)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'x-content-type-options', 'url': 'https://lynolz.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 8. Unnamed Finding 8 (Severity: Low)

**Detailed Evidence**

```text
{'status_code': 200, 'missing_header': 'referrer-policy', 'url': 'https://lynolz.com:443'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 10. Unnamed Finding 10 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://unpkg.com/typed.js@2.1.0/dist/typed.umd.js.map', 'script_url': 'https://unpkg.com/typed.js@2.1.0/dist/typed.umd.js'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 11. Unnamed Finding 11 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://dogs.lynolz.com:443', 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 12. Unnamed Finding 12 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://lynolz.com:443', 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 16. Unnamed Finding 16 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://tools.lynolz.com:443', 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 17. Unnamed Finding 17 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://lynolz.com/', 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 18. Potential XSS Reflection / Encoding Weakness (Severity: High)

**Detailed Evidence**

```text
context=javascript; snippet=\":\"YZdbAzr_rZ1dYCDF1txS9\",\"assetPrefix\":\"\",\"urlParts\":[\"\",\"100?_rsc=XSSA_CANARY_5051bc3391414ea1\"],\"initialTree\":[\"\",{\"children\":[[\"code\",\"100\",\"d\"],{\"children\":
```

**Reproduction Steps**

1. Request endpoint with canary input: https://dogs.lynolz.com:443/100
2. Observe raw reflection at position 5262 in javascript context.
3. Verify output encoding for this context.

### 19. Potential XSS Reflection / Encoding Weakness (Severity: High)

**Detailed Evidence**

```text
context=javascript; snippet=\":\"YZdbAzr_rZ1dYCDF1txS9\",\"assetPrefix\":\"\",\"urlParts\":[\"\",\"101?_rsc=XSSA_CANARY_eded2b5282043c45\"],\"initialTree\":[\"\",{\"children\":[[\"code\",\"101\",\"d\"],{\"children\":
```

**Reproduction Steps**

1. Request endpoint with canary input: https://dogs.lynolz.com:443/101
2. Observe raw reflection at position 5298 in javascript context.
3. Verify output encoding for this context.

### 20. Unnamed Finding 20 (Severity: Medium)

**Detailed Evidence**

```text
{'cookie': {'name': 'lynolz_blog_session', 'secure': False, 'httponly': True, 'samesite': True}, 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 21. Unnamed Finding 21 (Severity: Medium)

**Detailed Evidence**

```text
{'cookie': {'name': '_gorilla_csrf', 'secure': False, 'httponly': True, 'samesite': True}, 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 22. Unnamed Finding 22 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://lynolz.com:8443', 'status_code': 521}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 23. Potential XSS Reflection / Encoding Weakness (Severity: High)

**Detailed Evidence**

```text
context=javascript; snippet=\":\"YZdbAzr_rZ1dYCDF1txS9\",\"assetPrefix\":\"\",\"urlParts\":[\"\",\"102?_rsc=XSSA_CANARY_9537690215297149\"],\"initialTree\":[\"\",{\"children\":[[\"code\",\"102\",\"d\"],{\"children\":
```

**Reproduction Steps**

1. Request endpoint with canary input: https://dogs.lynolz.com:443/102
2. Observe raw reflection at position 5248 in javascript context.
3. Verify output encoding for this context.

### 24. Unnamed Finding 24 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'http://lynolz.com:8080', 'status_code': 401}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 25. Potential XSS Reflection / Encoding Weakness (Severity: High)

**Detailed Evidence**

```text
context=javascript; snippet=\":\"YZdbAzr_rZ1dYCDF1txS9\",\"assetPrefix\":\"\",\"urlParts\":[\"\",\"103?_rsc=XSSA_CANARY_18c1a850e3f9d6fe\"],\"initialTree\":[\"\",{\"children\":[[\"code\",\"103\",\"d\"],{\"children\":
```

**Reproduction Steps**

1. Request endpoint with canary input: https://dogs.lynolz.com:443/103
2. Observe raw reflection at position 5292 in javascript context.
3. Verify output encoding for this context.

### 26. Potential XSS Reflection / Encoding Weakness (Severity: High)

**Detailed Evidence**

```text
context=javascript; snippet=\":\"YZdbAzr_rZ1dYCDF1txS9\",\"assetPrefix\":\"\",\"urlParts\":[\"\",\"200?_rsc=XSSA_CANARY_9acdc35c9a3cc8a9\"],\"initialTree\":[\"\",{\"children\":[[\"code\",\"200\",\"d\"],{\"children\":
```

**Reproduction Steps**

1. Request endpoint with canary input: https://dogs.lynolz.com:443/200
2. Observe raw reflection at position 5223 in javascript context.
3. Verify output encoding for this context.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `1000`
