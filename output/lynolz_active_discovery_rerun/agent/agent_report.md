# Security Audit Report

- Generated (UTC): `2026-03-04T05:54:29.121087+00:00`
- Total Findings: `13`
- Vulnerabilities: `10`

## Summary

- Critical: `0`
- High: `0`
- Medium: `4`
- Low: `4`
- Info: `2`
- Unique Vulnerability Types: `10`

Top Vulnerability Names:
- Unnamed Finding 1
- Unnamed Finding 10
- Unnamed Finding 11
- Unnamed Finding 2
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

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `120`
