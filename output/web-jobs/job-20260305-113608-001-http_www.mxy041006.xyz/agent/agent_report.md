# Security Audit Report

- Generated (UTC): `2026-03-05T03:37:33.797039+00:00`
- Total Findings: `8`
- Vulnerabilities: `8`

## Summary

- Critical: `0`
- High: `0`
- Medium: `1`
- Low: `4`
- Info: `3`
- Unique Vulnerability Types: `8`

Top Vulnerability Names:
- CSP Missing
- JavaScript Endpoint Extraction
- Login Form Detection
- Passive Technology Fingerprint
- Referrer-Policy Missing
- X-Content-Type-Options Missing
- X-Frame-Options Missing
- security.txt Missing

## Reconnaissance & Information Gathering

### Target Overview

- **Target**: `http://www.mxy041006.xyz/`
- **Scope**: `http://www.mxy041006.xyz/`
- **Service Origins**: 1
  - `http://www.mxy041006.xyz`

### HTTP Security Headers

| Header | Value |
|--------|-------|
| `content-length` | `429` |
| `accept-ranges` | `bytes` |
| `alt-svc` | `quic=":443"; h3=":443"; h3-29=":443"; h3-27=":443";h3-25=":443"; h3-T050=":443"; h3-Q050=":443";h3-Q049=":443";h3-Q048="...` |
| `connection` | `keep-alive` |
| `content-type` | `text/html` |
| `date` | `Thu, 05 Mar 2026 03:36:32 GMT` |
| `etag` | `"69a6977c-1ad"` |
| `keep-alive` | `timeout=60` |
| `last-modified` | `Tue, 03 Mar 2026 08:10:36 GMT` |
| `proxy-connection` | `keep-alive` |
| `server` | `nginx` |
| `strict-transport-security` | `max-age=31536000` |

### Technology Stack

- `nginx`

### security.txt

- **Present**: `False`

### Crawled URLs

Total discovered URLs: **4**

- `http://www.mxy041006.xyz/`
- `http://www.mxy041006.xyz/assets/index-CNfVobV3.js`
- `http://www.mxy041006.xyz/assets/index-D9QJqW-W.css`
- `http://www.mxy041006.xyz:80/`

## Vulnerability List

| # | Name | Type | Severity |
|---|------|------|----------|
| 1 | Passive Technology Fingerprint | vuln | Info |
| 2 | security.txt Missing | vuln | Low |
| 3 | Login Form Detection | vuln | Info |
| 4 | CSP Missing | vuln | Medium |
| 5 | X-Frame-Options Missing | vuln | Low |
| 6 | X-Content-Type-Options Missing | vuln | Low |
| 7 | Referrer-Policy Missing | vuln | Low |
| 8 | JavaScript Endpoint Extraction | vuln | Info |

## Evidence

### 1. Passive Technology Fingerprint (Severity: Info)

**Detailed Evidence**

```text
{"server": "nginx", "status_code": 200, "tech_stack": ["nginx"], "url": "http://www.mxy041006.xyz:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 2. security.txt Missing (Severity: Low)

**Detailed Evidence**

```text
{"status_code": 404, "url": "http://www.mxy041006.xyz:80/.well-known/security.txt"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 3. Login Form Detection (Severity: Info)

**Detailed Evidence**

```text
{"forms": [], "status_code": 200, "url": "http://www.mxy041006.xyz:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 4. CSP Missing (Severity: Medium)

**Detailed Evidence**

```text
{"missing_header": "content-security-policy", "status_code": 200, "url": "http://www.mxy041006.xyz:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 5. X-Frame-Options Missing (Severity: Low)

**Detailed Evidence**

```text
{"missing_header": "x-frame-options", "status_code": 200, "url": "http://www.mxy041006.xyz:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 6. X-Content-Type-Options Missing (Severity: Low)

**Detailed Evidence**

```text
{"missing_header": "x-content-type-options", "status_code": 200, "url": "http://www.mxy041006.xyz:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 7. Referrer-Policy Missing (Severity: Low)

**Detailed Evidence**

```text
{"missing_header": "referrer-policy", "status_code": 200, "url": "http://www.mxy041006.xyz:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 8. JavaScript Endpoint Extraction (Severity: Info)

**Detailed Evidence**

```text
{"count": 0, "scripts": ["http://www.mxy041006.xyz:80/assets/index-CNfVobV3.js"], "url": "http://www.mxy041006.xyz:80"}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `100`
