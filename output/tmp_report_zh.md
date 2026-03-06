# 安全审计报告

- 生成时间（UTC）: `2026-03-06T02:41:59.161398+00:00`
- 报告语言: `zh-CN`
- 发现总数: `1`
- 漏洞类发现: `1`

## 风险摘要

- Critical: `0`
- High: `1`
- Medium: `0`
- Low: `0`
- Info: `0`
- 漏洞类型去重数: `1`

主要漏洞名称：
- SQL Injection

## 运行画像

- 目标: `https://example.com`
- 安全等级: `aggressive`
- 迭代次数: `2`
- 剩余预算: `80`
- 是否续跑: `False`

## 范围快照

- 范围条目数: `1`
- 面包屑记录数: `0`
- 资产面键数: `0`
- 范围样本: `example.com`

## 发现目录

| # | Name | Type | Severity | CVE |
|---|------|------|----------|-----|
| 1 | SQL Injection | vuln | High | - |

## 详细证据

### 1. SQL Injection (严重性: High)

- 类型: `vuln`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
error-based
```

**复现步骤**

1. GET /?id=1'

**修复建议**

Use prepared statements.
