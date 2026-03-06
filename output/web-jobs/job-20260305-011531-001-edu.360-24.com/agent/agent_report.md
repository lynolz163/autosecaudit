# Security Audit Report

- Generated (UTC): `2026-03-04T17:26:13.916175+00:00`
- Total Findings: `3`
- Vulnerabilities: `2`

## Summary

- Critical: `0`
- High: `0`
- Medium: `0`
- Low: `0`
- Info: `2`
- Unique Vulnerability Types: `2`

Top Vulnerability Names:
- Unnamed Finding 2
- Unnamed Finding 3

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

### Crawled URLs

Total discovered URLs: **10**

- `http://edu.360-24.com/`
- `http://edu.360-24.com:3128/`
- `http://edu.360-24.com:80/`
- `http://edu.360-24.com:8000/`
- `http://edu.360-24.com:8008/`
- `http://edu.360-24.com:8080/`
- `http://edu.360-24.com:8888/`
- `https://edu.360-24.com/`
- `https://edu.360-24.com:443/`
- `https://edu.360-24.com:8443/`

## Vulnerability List

| # | Name | Type | Severity |
|---|------|------|----------|
| 2 | Unnamed Finding 2 | vuln | Info |
| 3 | Unnamed Finding 3 | vuln | Info |

## Evidence

### 2. Unnamed Finding 2 (Severity: Info)

**Detailed Evidence**

```text
{'url': 'http://edu.360-24.com:80', 'status_code': 503, 'tech_stack': [], 'server': ''}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 3. Unnamed Finding 3 (Severity: Info)

**Detailed Evidence**

```text
{'status_code': 503, 'forms': [], 'url': 'http://edu.360-24.com:80'}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `999`
