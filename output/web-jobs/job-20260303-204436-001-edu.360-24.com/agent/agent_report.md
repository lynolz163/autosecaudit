# Security Audit Report

- Generated (UTC): `2026-03-03T12:54:38.148434+00:00`
- Total Findings: `7`
- Vulnerabilities: `2`

## Summary

- Critical: `0`
- High: `0`
- Medium: `2`
- Low: `0`
- Info: `0`
- Unique Vulnerability Types: `2`

Top Vulnerability Names:
- Sensitive File Exposure: actuator/health
- Sensitive File Exposure: config.php.bak

## Vulnerability List

| # | Name | Type | Severity |
|---|------|------|----------|
| 2 | Sensitive File Exposure: actuator/health | vuln | Medium |
| 3 | Sensitive File Exposure: config.php.bak | vuln | Medium |

## Evidence

### 2. Sensitive File Exposure: actuator/health (Severity: Medium)

**Detailed Evidence**

```text
keywords=['"status"']; snippet=t-50 translate-middle-x p-3 dd-toast-container"> <div id="ddToast" class="toast dd-toast" role="status" aria-live="polite" aria-atomic="true"> <div class="toast-body d-flex align-items-start gap-2
```

**Reproduction Steps**

1. Send GET request to https://edu.360-24.com:443/actuator/health.
2. Confirm HTTP 200 and sensitive marker(s): "status".

### 3. Sensitive File Exposure: config.php.bak (Severity: Medium)

**Detailed Evidence**

```text
keywords=['password']; snippet=</div> <div class="mb-3"> <label class="form-label dd-label" for="password"> 密码 </label> <div class="input-group dd-input
```

**Reproduction Steps**

1. Send GET request to https://edu.360-24.com:443/config.php.bak.
2. Confirm HTTP 200 and sensitive marker(s): password.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `100`
