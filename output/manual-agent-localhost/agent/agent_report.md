# Security Audit Report

- Generated (UTC): `2026-03-03T12:06:15.777760+00:00`
- Total Findings: `9`
- Vulnerabilities: `5`

## Summary

- Critical: `0`
- High: `0`
- Medium: `2`
- Low: `3`
- Info: `0`
- Unique Vulnerability Types: `5`

Top Vulnerability Names:
- CSP Missing
- HSTS Missing
- Referrer-Policy Missing
- X-Content-Type-Options Missing
- X-Frame-Options Missing

## Vulnerability List

| # | Name | Type | Severity |
|---|------|------|----------|
| 3 | HSTS Missing | vuln | Medium |
| 4 | CSP Missing | vuln | Medium |
| 5 | X-Frame-Options Missing | vuln | Low |
| 6 | X-Content-Type-Options Missing | vuln | Low |
| 7 | Referrer-Policy Missing | vuln | Low |

## Evidence

### 3. HSTS Missing (Severity: Medium)

**Detailed Evidence**

```text
status=200; missing_header=strict-transport-security
```

**Reproduction Steps**

1. Send GET request to http://localhost:8080.
2. Verify response is missing `strict-transport-security`.

### 4. CSP Missing (Severity: Medium)

**Detailed Evidence**

```text
status=200; missing_header=content-security-policy
```

**Reproduction Steps**

1. Send GET request to http://localhost:8080.
2. Verify response is missing `content-security-policy`.

### 5. X-Frame-Options Missing (Severity: Low)

**Detailed Evidence**

```text
status=200; missing_header=x-frame-options
```

**Reproduction Steps**

1. Send GET request to http://localhost:8080.
2. Verify response is missing `x-frame-options`.

### 6. X-Content-Type-Options Missing (Severity: Low)

**Detailed Evidence**

```text
status=200; missing_header=x-content-type-options
```

**Reproduction Steps**

1. Send GET request to http://localhost:8080.
2. Verify response is missing `x-content-type-options`.

### 7. Referrer-Policy Missing (Severity: Low)

**Detailed Evidence**

```text
status=200; missing_header=referrer-policy
```

**Reproduction Steps**

1. Send GET request to http://localhost:8080.
2. Verify response is missing `referrer-policy`.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `100`
