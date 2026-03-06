# 安全审计报告

- 生成时间（UTC）: `2026-03-06T12:39:06.238002+00:00`
- 报告语言: `zh-CN`
- 发现总数: `2`
- 漏洞类发现: `1`

## 决策摘要

[phase:passive_recon] No safe in-scope actions selected. Possible reasons: budget exhausted, all actions already executed, or scope constraints.

## 风险摘要

- Critical: `0`
- High: `0`
- Medium: `0`
- Low: `0`
- Info: `1`
- 漏洞类型去重数: `1`

主要漏洞名称：
- Observed DNS authority metadata for 0x6288.com

## 运行画像

- 目标: `0x6288.com`
- 安全等级: `balanced`
- 迭代次数: `3`
- 剩余预算: `38`
- 是否续跑: `False`
- 续跑来源: `None`

## 执行覆盖

- 执行工具去重数: `3`
- 完成/失败/错误动作: `3/0/0`
- 观察到服务 Origin 数: `1`
- API 端点 / URL 参数: `0 / 0`

覆盖亮点：
- Observed 1 HTTP(S) service origin(s).

### 工具执行矩阵

| Tool | Total | Completed | Failed | Error |
|------|------:|----------:|-------:|------:|
| dns_zone_audit | 1 | 1 | 0 | 0 |
| passive_config_audit | 1 | 1 | 0 | 0 |
| subdomain_enum_passive | 1 | 1 | 0 | 0 |

## 范围快照

- 范围条目数: `1`
- 面包屑记录数: `2`
- 资产面键数: `21`
- 范围样本: `0x6288.com`

## 执行时间线

| # | Tool | Target | Status | Cost | Budget Before | Budget After | Error |
|---|------|--------|--------|-----:|--------------:|-------------:|-------|
| 1 | subdomain_enum_passive | 0x6288.com | completed | 5 | 50 | 41 | None |
| 2 | dns_zone_audit | 0x6288.com | completed | 4 | 41 | 41 | None |
| 3 | passive_config_audit | https://0x6288.com:443 | completed | 3 | 41 | 38 | None |

### 这些动作为何被选中

#### 1. `subdomain_enum_passive` -> `0x6288.com`

- 选中候选: `None`
- 选择原因:
  - Enumerate likely subdomains through passive certificate transparency sources.
  - Scheduled in phase: passive_recon
  - Preconditions satisfied: target_in_scope, not_already_done, domain_scope_declared

#### 2. `dns_zone_audit` -> `0x6288.com`

- 选中候选: `None`
- 选择原因:
  - Resolve NS/MX/TXT/SOA records and test whether AXFR is exposed.
  - Scheduled in phase: passive_recon
  - Preconditions satisfied: target_in_scope, not_already_done, domain_scope_declared

#### 3. `passive_config_audit` -> `https://0x6288.com:443`

- 选中候选: `None`
- 选择原因:
  - Check common sensitive config paths using read-only requests.
  - Scheduled in phase: passive_recon
  - Preconditions satisfied: target_in_scope, not_already_done, http_service_confirmed

## 被阻断动作

| # | Tool | Target | Reason | Preconditions |
|---|------|--------|--------|---------------|
| 1 | reverse_dns_probe | 0x6288.com | dependency_unsatisfied:nmap_scan | target_in_scope, not_already_done |

## 侦察与信息收集

### 目标概览

- **目标**: `0x6288.com`
- **范围**: `0x6288.com`
- **服务 Origin**: 1
  - `https://0x6288.com`

### 子域名枚举

通过被动枚举发现 **1** 个子域名：

- `0x6288.com`

### DNS Records


### 资产清单

| Kind | Identifier | Source Tool |
|------|------------|-------------|
| domain | domain:0x6288.com | dns_zone_audit |

## 发现目录

| # | Name | Type | Severity | CVE |
|---|------|------|----------|-----|
| 1 | Passive Subdomain Enumeration Results | info | Info | - |
| 2 | Observed DNS authority metadata for 0x6288.com | vuln | Info | None |

## 详细证据

### 1. Passive Subdomain Enumeration Results (严重性: Info)

- 类型: `info`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
{"domain": "0x6288.com", "count": 1, "subdomains": ["0x6288.com"]}
```

**复现步骤**

1. Query crt.sh for %.0x6288.com and review returned SAN/CN values.

**修复建议**

Review evidence, confirm impact, and apply least-privilege plus secure configuration controls.

### 2. Observed DNS authority metadata for 0x6288.com (严重性: Info)

- 类型: `vuln`
- 类别: `inventory`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"domain": "0x6288.com", "records": {"A": ["104.21.76.210", "172.67.201.15"]}, "zone_transfer": {"attempted": false, "server": null, "subdomains": [], "success": false}}
```

**复现步骤**

1. Query NS/MX/TXT/SOA records for 0x6288.com.
2. Attempt a bounded AXFR request against a limited set of authoritative nameservers.

**修复建议**

Restrict AXFR to trusted DNS management hosts and review externally visible DNS metadata.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `50`
