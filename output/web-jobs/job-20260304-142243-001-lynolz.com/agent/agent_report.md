# Security Audit Report

- Generated (UTC): `2026-03-04T06:36:33.179508+00:00`
- Total Findings: `16`
- Vulnerabilities: `12`

## Summary

- Critical: `0`
- High: `5`
- Medium: `7`
- Low: `0`
- Info: `0`
- Unique Vulnerability Types: `8`

Top Vulnerability Names:
- Potential XSS Reflection / Encoding Weakness
- Unnamed Finding 11
- Unnamed Finding 12
- Unnamed Finding 13
- Unnamed Finding 2
- Unnamed Finding 3
- Unnamed Finding 7
- Unnamed Finding 8

## Vulnerability List

| # | Name | Type | Severity |
|---|------|------|----------|
| 2 | Unnamed Finding 2 | vuln | Medium |
| 3 | Unnamed Finding 3 | vuln | Medium |
| 7 | Unnamed Finding 7 | vuln | Medium |
| 8 | Unnamed Finding 8 | vuln | Medium |
| 9 | Potential XSS Reflection / Encoding Weakness | vuln | High |
| 10 | Potential XSS Reflection / Encoding Weakness | vuln | High |
| 11 | Unnamed Finding 11 | vuln | Medium |
| 12 | Unnamed Finding 12 | vuln | Medium |
| 13 | Unnamed Finding 13 | vuln | Medium |
| 14 | Potential XSS Reflection / Encoding Weakness | vuln | High |
| 15 | Potential XSS Reflection / Encoding Weakness | vuln | High |
| 16 | Potential XSS Reflection / Encoding Weakness | vuln | High |

## Evidence

### 2. Unnamed Finding 2 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://dogs.lynolz.com:443', 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 3. Unnamed Finding 3 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://lynolz.com:443', 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 7. Unnamed Finding 7 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://lynolz.com/', 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 8. Unnamed Finding 8 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://lynolz.com:8443', 'status_code': 521}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 9. Potential XSS Reflection / Encoding Weakness (Severity: High)

**Detailed Evidence**

```text
context=javascript; snippet=\":\"YZdbAzr_rZ1dYCDF1txS9\",\"assetPrefix\":\"\",\"urlParts\":[\"\",\"100?_rsc=XSSA_CANARY_12458ff5a392c398\"],\"initialTree\":[\"\",{\"children\":[[\"code\",\"100\",\"d\"],{\"children\":
```

**Reproduction Steps**

1. Request endpoint with canary input: https://dogs.lynolz.com:443/100
2. Observe raw reflection at position 5262 in javascript context.
3. Verify output encoding for this context.

### 10. Potential XSS Reflection / Encoding Weakness (Severity: High)

**Detailed Evidence**

```text
context=javascript; snippet=\":\"YZdbAzr_rZ1dYCDF1txS9\",\"assetPrefix\":\"\",\"urlParts\":[\"\",\"101?_rsc=XSSA_CANARY_745a602a8cc4d4a7\"],\"initialTree\":[\"\",{\"children\":[[\"code\",\"101\",\"d\"],{\"children\":
```

**Reproduction Steps**

1. Request endpoint with canary input: https://dogs.lynolz.com:443/101
2. Observe raw reflection at position 5298 in javascript context.
3. Verify output encoding for this context.

### 11. Unnamed Finding 11 (Severity: Medium)

**Detailed Evidence**

```text
{'cookie': {'name': 'lynolz_blog_session', 'secure': False, 'httponly': True, 'samesite': True}, 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 12. Unnamed Finding 12 (Severity: Medium)

**Detailed Evidence**

```text
{'cookie': {'name': '_gorilla_csrf', 'secure': False, 'httponly': True, 'samesite': True}, 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 13. Unnamed Finding 13 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'http://lynolz.com:8080', 'status_code': 401}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 14. Potential XSS Reflection / Encoding Weakness (Severity: High)

**Detailed Evidence**

```text
context=javascript; snippet=\":\"YZdbAzr_rZ1dYCDF1txS9\",\"assetPrefix\":\"\",\"urlParts\":[\"\",\"102?_rsc=XSSA_CANARY_c379590dadeed7ad\"],\"initialTree\":[\"\",{\"children\":[[\"code\",\"102\",\"d\"],{\"children\":
```

**Reproduction Steps**

1. Request endpoint with canary input: https://dogs.lynolz.com:443/102
2. Observe raw reflection at position 5248 in javascript context.
3. Verify output encoding for this context.

### 15. Potential XSS Reflection / Encoding Weakness (Severity: High)

**Detailed Evidence**

```text
context=javascript; snippet=\":\"YZdbAzr_rZ1dYCDF1txS9\",\"assetPrefix\":\"\",\"urlParts\":[\"\",\"103?_rsc=XSSA_CANARY_885c8fadfa95710e\"],\"initialTree\":[\"\",{\"children\":[[\"code\",\"103\",\"d\"],{\"children\":
```

**Reproduction Steps**

1. Request endpoint with canary input: https://dogs.lynolz.com:443/103
2. Observe raw reflection at position 5292 in javascript context.
3. Verify output encoding for this context.

### 16. Potential XSS Reflection / Encoding Weakness (Severity: High)

**Detailed Evidence**

```text
context=javascript; snippet=\":\"YZdbAzr_rZ1dYCDF1txS9\",\"assetPrefix\":\"\",\"urlParts\":[\"\",\"200?_rsc=XSSA_CANARY_75fe89649f68d979\"],\"initialTree\":[\"\",{\"children\":[[\"code\",\"200\",\"d\"],{\"children\":
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
