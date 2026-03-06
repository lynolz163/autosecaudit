# 安全审计报告

- 生成时间（UTC）: `2026-03-06T11:47:02.860310+00:00`
- 报告语言: `zh-CN`
- 发现总数: `2`
- 漏洞类发现: `1`

## 决策摘要

[phase:passive_recon] Proposed 1 safe action(s), total estimated cost 3, remaining budget after plan 3. Blocked actions: 1. Executable actions after environment checks: 0.

## 风险摘要

- Critical: `0`
- High: `0`
- Medium: `0`
- Low: `0`
- Info: `1`
- 漏洞类型去重数: `1`

主要漏洞名称：
- Observed DNS authority metadata for example.com

## 运行画像

- 目标: `example.com`
- 安全等级: `balanced`
- 迭代次数: `2`
- 剩余预算: `41`
- 是否续跑: `False`
- 续跑来源: `None`

## 执行覆盖

- 执行工具去重数: `2`
- 完成/失败/错误动作: `2/0/0`
- 观察到服务 Origin 数: `6`
- API 端点 / URL 参数: `0 / 0`

覆盖亮点：
- Observed 6 HTTP(S) service origin(s).

### 工具执行矩阵

| Tool | Total | Completed | Failed | Error |
|------|------:|----------:|-------:|------:|
| dns_zone_audit | 1 | 1 | 0 | 0 |
| subdomain_enum_passive | 1 | 1 | 0 | 0 |

## 范围快照

- 范围条目数: `1`
- 面包屑记录数: `7`
- 资产面键数: `18`
- 范围样本: `example.com`

## 执行时间线

| # | Tool | Target | Status | Cost | Budget Before | Budget After | Error |
|---|------|--------|--------|-----:|--------------:|-------------:|-------|
| 1 | subdomain_enum_passive | example.com | completed | 5 | 50 | 41 | None |
| 2 | dns_zone_audit | example.com | completed | 4 | 41 | 41 | None |

### 这些动作为何被选中

#### 1. `subdomain_enum_passive` -> `example.com`

- 选中候选: `None`
- 选择原因:
  - Enumerate likely subdomains through passive certificate transparency sources.
  - Scheduled in phase: passive_recon
  - Preconditions satisfied: target_in_scope, not_already_done, domain_scope_declared

#### 2. `dns_zone_audit` -> `example.com`

- 选中候选: `None`
- 选择原因:
  - Resolve NS/MX/TXT/SOA records and test whether AXFR is exposed.
  - Scheduled in phase: passive_recon
  - Preconditions satisfied: target_in_scope, not_already_done, domain_scope_declared

## 被阻断动作

| # | Tool | Target | Reason | Preconditions |
|---|------|--------|--------|---------------|
| 1 | reverse_dns_probe | example.com | dependency_unsatisfied:nmap_scan | target_in_scope, not_already_done |
| 2 | passive_config_audit | https://dev.example.com:443 | scope_fail_closed_resolution_failed | target_in_scope, not_already_done, http_service_confirmed |

## 侦察与信息收集

### 目标概览

- **目标**: `example.com`
- **范围**: `example.com`
- **服务 Origin**: 6
  - `https://dev.example.com`
  - `https://example.com`
  - `https://m.example.com`
  - `https://products.example.com`
  - `https://support.example.com`
  - `https://www.example.com`

### 子域名枚举

通过被动枚举发现 **6** 个子域名：

- `dev.example.com`
- `example.com`
- `m.example.com`
- `products.example.com`
- `support.example.com`
- `www.example.com`

### DNS Records


### 资产清单

| Kind | Identifier | Source Tool |
|------|------------|-------------|
| domain | domain:example.com | dns_zone_audit |

## 发现目录

| # | Name | Type | Severity | CVE |
|---|------|------|----------|-----|
| 1 | Passive Subdomain Enumeration Results | info | Info | - |
| 2 | Observed DNS authority metadata for example.com | vuln | Info | None |

## 详细证据

### 1. Passive Subdomain Enumeration Results (严重性: Info)

- 类型: `info`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
{"domain": "example.com", "count": 6, "subdomains": ["dev.example.com", "example.com", "m.example.com", "products.example.com", "support.example.com", "www.example.com"]}
```

**复现步骤**

1. Query crt.sh for %.example.com and review returned SAN/CN values.

**修复建议**

Review evidence, confirm impact, and apply least-privilege plus secure configuration controls.

### 2. Observed DNS authority metadata for example.com (严重性: Info)

- 类型: `vuln`
- 类别: `inventory`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"domain": "example.com", "records": {"A": ["104.18.26.120", "104.18.27.120"]}, "zone_transfer": {"attempted": false, "server": null, "subdomains": [], "success": false}}
```

**复现步骤**

1. Query NS/MX/TXT/SOA records for example.com.
2. Attempt a bounded AXFR request against a limited set of authoritative nameservers.

**修复建议**

Restrict AXFR to trusted DNS management hosts and review externally visible DNS metadata.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `50`
