# Security Audit Report

- Generated (UTC): `2026-03-06T02:28:33.999525+00:00`
- Total Findings: `3`
- Vulnerabilities: `3`

## Summary

- Critical: `0`
- High: `0`
- Medium: `0`
- Low: `0`
- Info: `3`
- Unique Vulnerability Types: `3`

Top Vulnerability Names:
- JavaScript Endpoint Extraction
- Login Form Detection
- Passive Technology Fingerprint

## Reconnaissance & Information Gathering

### Target Overview

- **Target**: `172.20.0.42`
- **Scope**: `172.20.0.42`
- **Service Origins**: 4
  - `http://172.20.0.42:80`
  - `http://172.20.0.42:8000`
  - `http://172.20.0.42:8080`
  - `https://172.20.0.42:443`

### Technology Stack

- `nginx`

## Vulnerability List

| # | Name | Type | Severity |
|---|------|------|----------|
| 1 | Passive Technology Fingerprint | vuln | Info |
| 2 | Login Form Detection | vuln | Info |
| 3 | JavaScript Endpoint Extraction | vuln | Info |

## Evidence

### 1. Passive Technology Fingerprint (Severity: Info)

**Detailed Evidence**

```text
{"server": "nginx/1.14.1", "status_code": 200, "tech_stack": ["nginx"], "url": "http://172.20.0.42:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 2. Login Form Detection (Severity: Info)

**Detailed Evidence**

```text
{"forms": [], "status_code": 200, "url": "http://172.20.0.42:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 3. JavaScript Endpoint Extraction (Severity: Info)

**Detailed Evidence**

```text
{"count": 0, "scripts": [], "url": "http://172.20.0.42:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `999`
