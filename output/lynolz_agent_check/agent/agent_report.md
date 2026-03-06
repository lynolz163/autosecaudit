# Security Audit Report

- Generated (UTC): `2026-03-04T05:37:46.063443+00:00`
- Total Findings: `5`
- Vulnerabilities: `3`

## Summary

- Critical: `0`
- High: `1`
- Medium: `2`
- Low: `0`
- Info: `0`
- Unique Vulnerability Types: `3`

Top Vulnerability Names:
- Potential XSS Reflection / Encoding Weakness
- Unnamed Finding 1
- Unnamed Finding 4

## Vulnerability List

| # | Name | Type | Severity |
|---|------|------|----------|
| 1 | Unnamed Finding 1 | vuln | Medium |
| 4 | Unnamed Finding 4 | vuln | Medium |
| 5 | Potential XSS Reflection / Encoding Weakness | vuln | High |

## Evidence

### 1. Unnamed Finding 1 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://dogs.lynolz.com:443', 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 4. Unnamed Finding 4 (Severity: Medium)

**Detailed Evidence**

```text
{'url': 'https://lynolz.com:443', 'status_code': 200}
```

**Reproduction Steps**

1. Reproduction steps were not provided.

### 5. Potential XSS Reflection / Encoding Weakness (Severity: High)

**Detailed Evidence**

```text
context=javascript; snippet=\":\"YZdbAzr_rZ1dYCDF1txS9\",\"assetPrefix\":\"\",\"urlParts\":[\"\",\"100?_rsc=XSSA_CANARY_7ac6e4b6d2c4257f\"],\"initialTree\":[\"\",{\"children\":[[\"code\",\"100\",\"d\"],{\"children\":
```

**Reproduction Steps**

1. Request endpoint with canary input: https://dogs.lynolz.com:443/100
2. Observe raw reflection at position 5262 in javascript context.
3. Verify output encoding for this context.

## Run Metadata

- resumed: `true`
- resumed_from: `/workspace/output/lynolz_agent_check/agent/agent_state.json`
- resume_start_iteration: `3`
- resume_start_budget: `63`
