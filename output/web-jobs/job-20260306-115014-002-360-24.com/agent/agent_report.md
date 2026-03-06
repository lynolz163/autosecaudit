# Security Audit Report

- Generated (UTC): `2026-03-06T03:50:56.833470+00:00`
- Report Language: `en`
- Total Findings: `0`
- Vulnerabilities: `0`

## Decision Summary

[phase:passive_recon] Proposed 2 safe action(s), total estimated cost 20, remaining budget after plan 179. Blocked actions: 2. Executable actions after environment checks: 0.

## Summary

No vulnerability findings were provided.

## Runtime Profile

- Target: `360-24.com`
- Safety Grade: `aggressive`
- Iteration Count: `1`
- Budget Remaining: `999`
- Resumed: `False`
- Resumed From: `None`

## Execution Coverage

- Unique Tools Executed: `0`
- Completed/Failed/Error Actions: `0/0/0`
- Observed Service Origins: `0`
- API Endpoints / URL Params: `0 / 0`

Coverage Highlights:
- Coverage remained shallow; few concrete HTTP artifacts were discovered.

### Tool Execution Matrix

| Tool | Total | Completed | Failed | Error |
|------|------:|----------:|-------:|------:|
| - | 0 | 0 | 0 | 0 |

## Scope Snapshot

- Scope Entries: `1`
- Breadcrumb Records: `1`
- Surface Keys: `6`
- Scope Samples: `*.360-24.com`

## Blocked Actions

| # | Tool | Target | Reason | Preconditions |
|---|------|--------|--------|---------------|
| 1 | subdomain_enum_passive | *.360-24.com | scope_fail_closed_resolution_failed | target_in_scope, not_already_done, domain_scope_declared |
| 2 | nmap_scan | *.360-24.com | scope_fail_closed_resolution_failed | target_in_scope, not_already_done |

## Reconnaissance & Information Gathering

### Target Overview

- **Target**: `360-24.com`
- **Scope**: `*.360-24.com`

## Findings Catalog

| # | Name | Type | Severity | CVE |
|---|------|------|----------|-----|
| - | None | - | - | - |

## Detailed Evidence

No findings evidence to display.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `999`
