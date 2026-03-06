# 安全审计报告

- 生成时间（UTC）: `2026-03-06T09:47:54.317089+00:00`
- 报告语言: `zh-CN`
- 发现总数: `27`
- 漏洞类发现: `16`

## 决策摘要

[phase:deep_testing] Proposed 14 safe action(s), total estimated cost 54, remaining budget after plan 188. Blocked actions: 1. Executable actions after environment checks: 13.

## 风险摘要

- Critical: `0`
- High: `0`
- Medium: `6`
- Low: `4`
- Info: `6`
- 漏洞类型去重数: `13`

主要漏洞名称：
- CSP Missing
- Content-Security-Policy Missing
- HSTS Missing
- JavaScript Endpoint Extraction
- Login Form Detection
- Observed DNS authority metadata for 0x6288.com
- Observed TLS service metadata on 0x6288.com:443
- Passive Technology Fingerprint
- Potential WAF/CDN Identified
- Referrer-Policy Missing
- X-Content-Type-Options Missing
- X-Frame-Options Missing
- security.txt Missing

## 运行画像

- 目标: `0x6288.com`
- 安全等级: `aggressive`
- 迭代次数: `9`
- 剩余预算: `529`
- 是否续跑: `False`
- 续跑来源: `None`

## 执行覆盖

- 执行工具去重数: `25`
- 完成/失败/错误动作: `53/0/33`
- 观察到服务 Origin 数: `10`
- API 端点 / URL 参数: `0 / 0`

覆盖亮点：
- Observed 10 HTTP(S) service origin(s).

### 工具执行矩阵

| Tool | Total | Completed | Failed | Error |
|------|------:|----------:|-------:|------:|
| service_banner_probe | 11 | 11 | 0 | 0 |
| api_schema_discovery | 9 | 9 | 0 | 0 |
| cors_misconfiguration | 9 | 9 | 0 | 0 |
| cookie_security_audit | 9 | 4 | 0 | 5 |
| csp_evaluator | 9 | 4 | 0 | 5 |
| dns_zone_audit | 1 | 1 | 0 | 0 |
| error_page_analyzer | 1 | 1 | 0 | 0 |
| git_exposure_check | 1 | 1 | 0 | 0 |
| http_security_headers | 1 | 1 | 0 | 0 |
| js_endpoint_extractor | 1 | 1 | 0 | 0 |
| login_form_detector | 1 | 1 | 0 | 0 |
| nmap_scan | 1 | 1 | 0 | 0 |
| passive_config_audit | 1 | 1 | 0 | 0 |
| reverse_dns_probe | 1 | 1 | 0 | 0 |
| security_txt_check | 1 | 1 | 0 | 0 |
| source_map_detector | 1 | 1 | 0 | 0 |
| ssl_expiry_check | 1 | 1 | 0 | 0 |
| subdomain_enum_passive | 1 | 1 | 0 | 0 |
| tech_stack_fingerprint | 1 | 1 | 0 | 0 |
| tls_service_probe | 1 | 1 | 0 | 0 |
| waf_detector | 1 | 1 | 0 | 0 |
| page_vision_analyzer | 9 | 0 | 0 | 9 |
| active_web_crawler | 5 | 0 | 0 | 5 |
| dynamic_crawl | 5 | 0 | 0 | 5 |
| dirsearch_scan | 4 | 0 | 0 | 4 |

## 范围快照

- 范围条目数: `1`
- 面包屑记录数: `11`
- 资产面键数: `39`
- 范围样本: `0x6288.com`

## 执行时间线

| # | Tool | Target | Status | Cost | Budget Before | Budget After | Error |
|---|------|--------|--------|-----:|--------------:|-------------:|-------|
| 1 | subdomain_enum_passive | 0x6288.com | completed | 5 | 999 | 975 | None |
| 2 | nmap_scan | 0x6288.com | completed | 15 | 975 | 975 | None |
| 3 | dns_zone_audit | 0x6288.com | completed | 4 | 975 | 975 | None |
| 4 | passive_config_audit | https://0x6288.com:443 | completed | 3 | 975 | 936 | None |
| 5 | tech_stack_fingerprint | https://0x6288.com:443/ | completed | 2 | 936 | 936 | None |
| 6 | git_exposure_check | https://0x6288.com:443/ | completed | 2 | 936 | 936 | None |
| 7 | source_map_detector | https://0x6288.com:443/ | completed | 2 | 936 | 936 | None |
| 8 | security_txt_check | https://0x6288.com:443/ | completed | 1 | 936 | 936 | None |
| 9 | login_form_detector | https://0x6288.com:443/ | completed | 3 | 936 | 936 | None |
| 10 | http_security_headers | https://0x6288.com:443/ | completed | 3 | 936 | 936 | None |
| 11 | ssl_expiry_check | https://0x6288.com:443/ | completed | 3 | 936 | 936 | None |
| 12 | js_endpoint_extractor | https://0x6288.com:443/ | completed | 4 | 936 | 936 | None |
| 13 | reverse_dns_probe | 0x6288.com | completed | 2 | 936 | 936 | None |
| 14 | error_page_analyzer | https://0x6288.com:443/ | completed | 3 | 936 | 936 | None |
| 15 | tls_service_probe | https://0x6288.com:443/ | completed | 4 | 936 | 936 | None |
| 16 | waf_detector | https://0x6288.com:443/ | completed | 3 | 936 | 936 | None |
| 17 | service_banner_probe | 0x6288.com | completed | 4 | 936 | 936 | None |
| 18 | api_schema_discovery | https://0x6288.com:443/ | completed | 4 | 936 | 823 | None |
| 19 | api_schema_discovery | http://0x6288.com:80/ | completed | 4 | 823 | 823 | None |
| 20 | api_schema_discovery | https://0x6288.com:8443/ | completed | 4 | 823 | 823 | None |
| 21 | service_banner_probe | 0x6288.com | completed | 4 | 823 | 823 | None |
| 22 | service_banner_probe | 0x6288.com | completed | 4 | 823 | 823 | None |
| 23 | service_banner_probe | 0x6288.com | completed | 4 | 823 | 823 | None |
| 24 | page_vision_analyzer | https://0x6288.com:443/ | error | 7 | 823 | 823 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 25 | page_vision_analyzer | http://0x6288.com:80/ | error | 7 | 823 | 823 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 26 | page_vision_analyzer | https://0x6288.com:8443/ | error | 7 | 823 | 823 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 27 | dynamic_crawl | https://0x6288.com:443/ | error | 12 | 823 | 823 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 28 | dynamic_crawl | http://0x6288.com:80/ | error | 12 | 823 | 823 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 29 | active_web_crawler | https://0x6288.com:443/ | error | 12 | 823 | 823 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 30 | active_web_crawler | http://0x6288.com:80/ | error | 12 | 823 | 823 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 31 | dirsearch_scan | https://0x6288.com:443 | error | 10 | 823 | 823 | dirsearch scan timed out after 90.0s |
| 32 | dirsearch_scan | http://0x6288.com:80 | error | 10 | 823 | 823 | dirsearch scan timed out after 90.0s |
| 33 | api_schema_discovery | http://0x6288.com:8080/ | completed | 4 | 823 | 710 | None |
| 34 | api_schema_discovery | http://0x6288.com:8000/ | completed | 4 | 710 | 710 | None |
| 35 | api_schema_discovery | http://0x6288.com:8008/ | completed | 4 | 710 | 710 | None |
| 36 | service_banner_probe | 0x6288.com | completed | 4 | 710 | 710 | None |
| 37 | service_banner_probe | 0x6288.com | completed | 4 | 710 | 710 | None |
| 38 | service_banner_probe | 0x6288.com | completed | 4 | 710 | 710 | None |
| 39 | page_vision_analyzer | http://0x6288.com:8080/ | error | 7 | 710 | 710 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 40 | page_vision_analyzer | http://0x6288.com:8000/ | error | 7 | 710 | 710 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 41 | page_vision_analyzer | http://0x6288.com:8008/ | error | 7 | 710 | 710 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 42 | dynamic_crawl | https://0x6288.com:8443/ | error | 12 | 710 | 710 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 43 | dynamic_crawl | http://0x6288.com:8080/ | error | 12 | 710 | 710 | circuit_open:dynamic_crawl:failures=3 |
| 44 | active_web_crawler | https://0x6288.com:8443/ | error | 12 | 710 | 710 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 45 | active_web_crawler | http://0x6288.com:8080/ | error | 12 | 710 | 710 | circuit_open:active_web_crawler:failures=3 |
| 46 | dirsearch_scan | https://0x6288.com:8443 | error | 10 | 710 | 710 | dirsearch scan timed out after 90.0s |
| 47 | dirsearch_scan | http://0x6288.com:8080 | error | 10 | 710 | 710 | circuit_open:dirsearch_scan:failures=3 |
| 48 | api_schema_discovery | http://0x6288.com:8888/ | completed | 4 | 710 | 648 | None |
| 49 | api_schema_discovery | http://0x6288.com:3128/ | completed | 4 | 648 | 648 | None |
| 50 | api_schema_discovery | http://0x6288.com:5800/ | completed | 4 | 648 | 648 | None |
| 51 | service_banner_probe | 0x6288.com | completed | 4 | 648 | 648 | None |
| 52 | service_banner_probe | 0x6288.com | completed | 4 | 648 | 648 | None |
| 53 | service_banner_probe | 0x6288.com | completed | 4 | 648 | 648 | None |
| 54 | page_vision_analyzer | http://0x6288.com:8888/ | error | 7 | 648 | 648 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 55 | page_vision_analyzer | http://0x6288.com:3128/ | error | 7 | 648 | 648 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 56 | dynamic_crawl | http://0x6288.com:8000/ | error | 12 | 648 | 648 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 57 | active_web_crawler | http://0x6288.com:8000/ | error | 12 | 648 | 648 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 58 | service_banner_probe | 0x6288.com | completed | 4 | 648 | 637 | None |
| 59 | page_vision_analyzer | http://0x6288.com:5800/ | error | 7 | 637 | 637 | BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell
╔════════════════════════════════════════════════════════════╗
║ Looks like Playwright was just installed or updated.       ║
║ Please run the following command to download new browsers: ║
║                                                            ║
║     playwright install                                     ║
║                                                            ║
║ <3 Playwright Team                                         ║
╚════════════════════════════════════════════════════════════╝ |
| 60 | csp_evaluator | https://0x6288.com:443/ | completed | 4 | 637 | 580 | None |
| 61 | csp_evaluator | http://0x6288.com:80/ | completed | 4 | 580 | 580 | None |
| 62 | csp_evaluator | https://0x6288.com:8443/ | completed | 4 | 580 | 580 | None |
| 63 | csp_evaluator | http://0x6288.com:8080/ | completed | 4 | 580 | 580 | None |
| 64 | csp_evaluator | http://0x6288.com:8000/ | error | 4 | 580 | 580 | timed out |
| 65 | cors_misconfiguration | https://0x6288.com:443/ | completed | 5 | 580 | 580 | None |
| 66 | cors_misconfiguration | http://0x6288.com:80/ | completed | 5 | 580 | 580 | None |
| 67 | cors_misconfiguration | https://0x6288.com:8443/ | completed | 5 | 580 | 580 | None |
| 68 | cors_misconfiguration | http://0x6288.com:8080/ | completed | 5 | 580 | 580 | None |
| 69 | cors_misconfiguration | http://0x6288.com:8000/ | completed | 5 | 580 | 580 | None |
| 70 | cookie_security_audit | https://0x6288.com:443/ | completed | 3 | 580 | 580 | None |
| 71 | cookie_security_audit | http://0x6288.com:80/ | completed | 3 | 580 | 580 | None |
| 72 | cookie_security_audit | https://0x6288.com:8443/ | completed | 3 | 580 | 580 | None |
| 73 | cookie_security_audit | http://0x6288.com:8080/ | completed | 3 | 580 | 580 | None |
| 74 | csp_evaluator | http://0x6288.com:8008/ | error | 4 | 580 | 529 | timed out |
| 75 | csp_evaluator | http://0x6288.com:8888/ | error | 4 | 529 | 529 | timed out |
| 76 | csp_evaluator | http://0x6288.com:3128/ | error | 4 | 529 | 529 | circuit_open:csp_evaluator:failures=3 |
| 77 | csp_evaluator | http://0x6288.com:5800/ | error | 4 | 529 | 529 | circuit_open:csp_evaluator:failures=4 |
| 78 | cors_misconfiguration | http://0x6288.com:8008/ | completed | 5 | 529 | 529 | None |
| 79 | cors_misconfiguration | http://0x6288.com:8888/ | completed | 5 | 529 | 529 | None |
| 80 | cors_misconfiguration | http://0x6288.com:3128/ | completed | 5 | 529 | 529 | None |
| 81 | cors_misconfiguration | http://0x6288.com:5800/ | completed | 5 | 529 | 529 | None |
| 82 | cookie_security_audit | http://0x6288.com:8000/ | error | 3 | 529 | 529 | timed out |
| 83 | cookie_security_audit | http://0x6288.com:8008/ | error | 3 | 529 | 529 | timed out |
| 84 | cookie_security_audit | http://0x6288.com:8888/ | error | 3 | 529 | 529 | timed out |
| 85 | cookie_security_audit | http://0x6288.com:3128/ | error | 3 | 529 | 529 | circuit_open:cookie_security_audit:failures=3 |
| 86 | cookie_security_audit | http://0x6288.com:5800/ | error | 3 | 529 | 529 | circuit_open:cookie_security_audit:failures=4 |

### 这些动作为何被选中

#### 1. `service_banner_probe` -> `0x6288.com`

- 选中候选: `None`
- 服务: `echo`
- 选择原因:
  - Service match: echo

#### 2. `service_banner_probe` -> `0x6288.com`

- 选中候选: `None`
- 服务: `discard`
- 选择原因:
  - Service match: discard

#### 3. `service_banner_probe` -> `0x6288.com`

- 选中候选: `None`
- 服务: `daytime`
- 选择原因:
  - Service match: daytime

#### 4. `service_banner_probe` -> `0x6288.com`

- 选中候选: `None`
- 服务: `ftp`
- 选择原因:
  - Service match: ftp

#### 5. `service_banner_probe` -> `0x6288.com`

- 选中候选: `None`
- 服务: `ssh`
- 选择原因:
  - Service match: ssh

#### 6. `service_banner_probe` -> `0x6288.com`

- 选中候选: `None`
- 服务: `telnet`
- 选择原因:
  - Service match: telnet

#### 7. `service_banner_probe` -> `0x6288.com`

- 选中候选: `None`
- 服务: `smtp`
- 选择原因:
  - Service match: smtp

#### 8. `service_banner_probe` -> `0x6288.com`

- 选中候选: `None`
- 服务: `rsftp`
- 选择原因:
  - Service match: rsftp

#### 9. `service_banner_probe` -> `0x6288.com`

- 选中候选: `None`
- 服务: `time`
- 选择原因:
  - Service match: time

#### 10. `service_banner_probe` -> `0x6288.com`

- 选中候选: `None`
- 服务: `domain`
- 选择原因:
  - Service match: domain

#### 11. `service_banner_probe` -> `0x6288.com`

- 选中候选: `None`
- 服务: `finger`
- 选择原因:
  - Service match: finger

## 被阻断动作

| # | Tool | Target | Reason | Preconditions |
|---|------|--------|--------|---------------|
| 1 | reverse_dns_probe | 0x6288.com | dependency_unsatisfied:nmap_scan | target_in_scope, not_already_done |
| 2 | ssh_auth_audit | 0x6288.com | dependency_unsatisfied:service_banner_probe | target_in_scope, not_already_done |
| 3 | dirsearch_scan | http://0x6288.com:8000 | circuit_open:dirsearch_scan:failures=4 | target_in_scope, not_already_done, http_service_confirmed |
| 4 | rag_intel_lookup | https://0x6288.com:443/ | precondition_failed:tech_stack_available | target_in_scope, not_already_done, tech_stack_available |

## 侦察与信息收集

### 目标概览

- **目标**: `0x6288.com`
- **范围**: `0x6288.com`
- **服务 Origin**: 10
  - `http://0x6288.com:3128`
  - `http://0x6288.com:5800`
  - `http://0x6288.com:80`
  - `http://0x6288.com:8000`
  - `http://0x6288.com:8008`
  - `http://0x6288.com:8080`
  - `http://0x6288.com:8888`
  - `https://0x6288.com`
  - `https://0x6288.com:443`
  - `https://0x6288.com:8443`

### 子域名枚举

通过被动枚举发现 **1** 个子域名：

- `0x6288.com`

### DNS Records


### 端口与服务

| Port | Protocol | State | Service |
|------|----------|-------|---------|
| 7 | tcp | open | echo |
| 9 | tcp | open | discard |
| 13 | tcp | open | daytime |
| 21 | tcp | open | ftp |
| 22 | tcp | open | ssh |
| 23 | tcp | open | telnet |
| 25 | tcp | open | smtp |
| 26 | tcp | open | rsftp |
| 37 | tcp | open | time |
| 53 | tcp | open | domain |
| 79 | tcp | open | finger |
| 80 | tcp | open | http |
| 81 | tcp | open | hosts2-ns |
| 88 | tcp | open | kerberos-sec |
| 106 | tcp | open | pop3pw |
| 110 | tcp | open | pop3 |
| 111 | tcp | open | rpcbind |
| 113 | tcp | open | ident |
| 119 | tcp | open | nntp |
| 135 | tcp | open | msrpc |
| 139 | tcp | open | netbios-ssn |
| 143 | tcp | open | imap |
| 144 | tcp | open | news |
| 179 | tcp | open | bgp |
| 199 | tcp | open | smux |
| 389 | tcp | open | ldap |
| 427 | tcp | open | svrloc |
| 443 | tcp | open | https |
| 444 | tcp | open | snpp |
| 445 | tcp | open | microsoft-ds |
| ... | 71 more | | |

### 资产清单

| Kind | Identifier | Source Tool |
|------|------------|-------------|
| service | 0x6288.com:7 | nmap_scan |
| service | 0x6288.com:9 | nmap_scan |
| service | 0x6288.com:13 | nmap_scan |
| service | 0x6288.com:21 | nmap_scan |
| service | 0x6288.com:22 | nmap_scan |
| service | 0x6288.com:23 | nmap_scan |
| service | 0x6288.com:25 | nmap_scan |
| service | 0x6288.com:26 | nmap_scan |
| service | 0x6288.com:37 | nmap_scan |
| service | 0x6288.com:53 | nmap_scan |
| service | 0x6288.com:79 | nmap_scan |
| service | 0x6288.com:80 | nmap_scan |
| service | 0x6288.com:81 | nmap_scan |
| service | 0x6288.com:88 | nmap_scan |
| service | 0x6288.com:106 | nmap_scan |
| service | 0x6288.com:110 | nmap_scan |
| service | 0x6288.com:111 | nmap_scan |
| service | 0x6288.com:113 | nmap_scan |
| service | 0x6288.com:119 | nmap_scan |
| service | 0x6288.com:135 | nmap_scan |
| service | 0x6288.com:139 | nmap_scan |
| service | 0x6288.com:143 | nmap_scan |
| service | 0x6288.com:144 | nmap_scan |
| service | 0x6288.com:179 | nmap_scan |
| service | 0x6288.com:199 | nmap_scan |
| service | 0x6288.com:389 | nmap_scan |
| service | 0x6288.com:427 | nmap_scan |
| service | 0x6288.com:443 | nmap_scan |
| service | 0x6288.com:444 | nmap_scan |
| service | 0x6288.com:445 | nmap_scan |
| ... | 74 more | |

### SSL/TLS Certificate

- **Host**: `0x6288.com:443`
- **TLS Version**: `TLSv1.3`
- **Days Until Expiry**: `51`
- **Expires At**: `2026-04-26T11:51:55+00:00`
- **SAN**: `DNS=0x6288.com`, `DNS=*.0x6288.com`

### HTTP Security Headers

| Header | Value |
|--------|-------|
| `date` | `Fri, 06 Mar 2026 09:33:35 GMT` |
| `content-type` | `text/html; charset=utf-8` |
| `transfer-encoding` | `chunked` |
| `connection` | `close` |
| `server` | `cloudflare` |
| `cf-cache-status` | `DYNAMIC` |
| `nel` | `{"report_to":"cf-nel","success_fraction":0.0,"max_age":604800}` |
| `server-timing` | `cfEdge;dur=5,cfOrigin;dur=25` |
| `report-to` | `{"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s=DAFYxtFvblNdaOSYE%2FcS0...` |
| `cf-ray` | `9d805c196b572590-LAX` |
| `alt-svc` | `h3=":443"; ma=86400` |

### WAF / CDN Detection

- `cloudflare`

### security.txt

- **Present**: `False`

### Content Security Policy (CSP)

- **Present**: `False`

## 发现目录

| # | Name | Type | Severity | CVE |
|---|------|------|----------|-----|
| 1 | Passive Subdomain Enumeration Results | info | Info | - |
| 2 | Observed DNS authority metadata for 0x6288.com | vuln | Info | None |
| 3 | Passive Technology Fingerprint | vuln | Info | None |
| 4 | security.txt Missing | vuln | Low | None |
| 5 | Login Form Detection | vuln | Info | None |
| 6 | HSTS Missing | vuln | Medium | None |
| 7 | CSP Missing | vuln | Medium | None |
| 8 | X-Frame-Options Missing | vuln | Low | None |
| 9 | X-Content-Type-Options Missing | vuln | Low | None |
| 10 | Referrer-Policy Missing | vuln | Low | None |
| 11 | TLS Certificate Expiry Healthy | info | Info | - |
| 12 | JavaScript Endpoint Extraction | vuln | Info | None |
| 13 | Observed TLS service metadata on 0x6288.com:443 | vuln | Info | None |
| 14 | Potential WAF/CDN Identified | vuln | Info | None |
| 15 | Content-Security-Policy Missing | vuln | Medium | None |
| 16 | Content-Security-Policy Missing | vuln | Medium | None |
| 17 | Content-Security-Policy Missing | vuln | Medium | None |
| 18 | Content-Security-Policy Missing | vuln | Medium | None |
| 19 | No Obvious CORS Misconfiguration | info | Info | - |
| 20 | No Obvious CORS Misconfiguration | info | Info | - |
| 21 | No Obvious CORS Misconfiguration | info | Info | - |
| 22 | No Obvious CORS Misconfiguration | info | Info | - |
| 23 | No Obvious CORS Misconfiguration | info | Info | - |
| 24 | No Obvious CORS Misconfiguration | info | Info | - |
| 25 | No Obvious CORS Misconfiguration | info | Info | - |
| 26 | No Obvious CORS Misconfiguration | info | Info | - |
| 27 | No Obvious CORS Misconfiguration | info | Info | - |

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

### 3. Passive Technology Fingerprint (严重性: Info)

- 类型: `vuln`
- 类别: `info_leak`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"server": "cloudflare", "status_code": 402, "tech_stack": [], "url": "https://0x6288.com:443"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Review exposed technology markers and minimize unnecessary fingerprinting signals where practical.

### 4. security.txt Missing (严重性: Low)

- 类型: `vuln`
- 类别: `compliance`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"status_code": 403, "url": "https://0x6288.com:443/.well-known/security.txt"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Publish a valid security.txt file with contact and expiry metadata.

### 5. Login Form Detection (严重性: Info)

- 类型: `vuln`
- 类别: `info_leak`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"forms": [], "status_code": 402, "url": "https://0x6288.com:443"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Use the discovered auth surface to drive low-risk validation of cookie and session controls.

### 6. HSTS Missing (严重性: Medium)

- 类型: `vuln`
- 类别: `misconfig`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"missing_header": "strict-transport-security", "status_code": 402, "url": "https://0x6288.com:443"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Add Strict-Transport-Security on HTTPS responses.

### 7. CSP Missing (严重性: Medium)

- 类型: `vuln`
- 类别: `misconfig`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"missing_header": "content-security-policy", "status_code": 402, "url": "https://0x6288.com:443"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Add a Content-Security-Policy to reduce XSS impact.

### 8. X-Frame-Options Missing (严重性: Low)

- 类型: `vuln`
- 类别: `misconfig`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"missing_header": "x-frame-options", "status_code": 402, "url": "https://0x6288.com:443"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Set X-Frame-Options or CSP frame-ancestors.

### 9. X-Content-Type-Options Missing (严重性: Low)

- 类型: `vuln`
- 类别: `misconfig`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"missing_header": "x-content-type-options", "status_code": 402, "url": "https://0x6288.com:443"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Set X-Content-Type-Options: nosniff.

### 10. Referrer-Policy Missing (严重性: Low)

- 类型: `vuln`
- 类别: `misconfig`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"missing_header": "referrer-policy", "status_code": 402, "url": "https://0x6288.com:443"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Set Referrer-Policy to reduce cross-origin leakage.

### 11. TLS Certificate Expiry Healthy (严重性: Info)

- 类型: `info`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
{"host": "0x6288.com", "port": 443, "days_left": 51, "expires_at": "2026-04-26T11:51:55+00:00", "tls_version": "TLSv1.3", "subject_alt_name": [["DNS", "0x6288.com"], ["DNS", "*.0x6288.com"]]}
```

**复现步骤**

1. Open TLS connection to 0x6288.com:443.
2. Observe certificate validity and remaining lifetime.

**修复建议**

Review evidence, confirm impact, and apply least-privilege plus secure configuration controls.

### 12. JavaScript Endpoint Extraction (严重性: Info)

- 类型: `vuln`
- 类别: `info_leak`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"count": 0, "scripts": [], "url": "https://0x6288.com:443"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Review exposed client-side endpoints and ensure undocumented APIs are properly scoped and protected.

### 13. Observed TLS service metadata on 0x6288.com:443 (严重性: Info)

- 类型: `vuln`
- 类别: `transport_security`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"cipher": "TLS_AES_256_GCM_SHA384", "cipher_bits": 256, "days_remaining": 51, "fingerprint_sha256": "b0c02a32c6b7fef9c1d81438c27764b88375c7d6919164ef8ac68567bfa55836", "host": "0x6288.com", "issuer": [[["countryName", "US"]], [["organizationName", "Google Trust Services"]], [["commonName", "WE1"]]], "not_after": "2026-04-26T11:51:55+00:00", "port": 443, "server_name": "0x6288.com", "subject": [[["commonName", "0x6288.com"]]], "subject_alt_names": ["0x6288.com", "*.0x6288.com"], "tls_version": "TLSv1.3"}
```

**复现步骤**

1. Open a TLS connection to 0x6288.com:443.
2. Record the negotiated protocol version, cipher, and presented certificate metadata.

**修复建议**

Review TLS version and certificate lifecycle to keep transport security current.

### 14. Potential WAF/CDN Identified (严重性: Info)

- 类型: `vuln`
- 类别: `misconfig`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"status_code": 402, "url": "https://0x6288.com:443", "vendor": "cloudflare"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Account for upstream WAF/CDN behavior when validating false positives or tuning scans.

### 15. Content-Security-Policy Missing (严重性: Medium)

- 类型: `vuln`
- 类别: `misconfig`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"status_code": 402, "url": "https://0x6288.com:443"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Deploy a restrictive Content-Security-Policy tailored to the application.

### 16. Content-Security-Policy Missing (严重性: Medium)

- 类型: `vuln`
- 类别: `misconfig`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"status_code": 402, "url": "https://0x6288.com/"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Deploy a restrictive Content-Security-Policy tailored to the application.

### 17. Content-Security-Policy Missing (严重性: Medium)

- 类型: `vuln`
- 类别: `misconfig`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"status_code": 500, "url": "https://0x6288.com:8443"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Deploy a restrictive Content-Security-Policy tailored to the application.

### 18. Content-Security-Policy Missing (严重性: Medium)

- 类型: `vuln`
- 类别: `misconfig`
- CVE: `None`
- CVE 是否已验证: `False`

**证据**

```text
{"status_code": 500, "url": "http://0x6288.com:8080"}
```

**复现步骤**

1. 未提供可执行复现步骤。

**修复建议**

Deploy a restrictive Content-Security-Policy tailored to the application.

### 19. No Obvious CORS Misconfiguration (严重性: Info)

- 类型: `info`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
[{"origin": "https://evil.example.com", "status_code": 200, "probe_method": "OPTIONS", "allow_origin": null, "allow_credentials": null}, {"origin": "null", "status_code": 200, "probe_method": "OPTIONS", "allow_origin": null, "allow_credentials": null}, {"origin": "https://0x6288.com.evil.invalid", "status_code": 200, "probe_method": "OPTIONS", "allow_origin": null, "allow_credentials": null}]
```

**复现步骤**

1. Probe https://0x6288.com:443 with untrusted Origin headers and inspect response.

**修复建议**

Remove public exposure, rotate leaked secrets, and enforce deny-by-default on sensitive files.

### 20. No Obvious CORS Misconfiguration (严重性: Info)

- 类型: `info`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
[{"origin": "https://evil.example.com", "error": "HTTP Error 301: Moved Permanently"}, {"origin": "null", "error": "HTTP Error 301: Moved Permanently"}, {"origin": "https://0x6288.com.evil.invalid", "error": "HTTP Error 301: Moved Permanently"}]
```

**复现步骤**

1. Probe http://0x6288.com:80 with untrusted Origin headers and inspect response.

**修复建议**

Remove public exposure, rotate leaked secrets, and enforce deny-by-default on sensitive files.

### 21. No Obvious CORS Misconfiguration (严重性: Info)

- 类型: `info`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
[{"origin": "https://evil.example.com", "error": "HTTP Error 500: Internal Server Error"}, {"origin": "null", "error": "HTTP Error 500: Internal Server Error"}, {"origin": "https://0x6288.com.evil.invalid", "error": "HTTP Error 500: Internal Server Error"}]
```

**复现步骤**

1. Probe https://0x6288.com:8443 with untrusted Origin headers and inspect response.

**修复建议**

Remove public exposure, rotate leaked secrets, and enforce deny-by-default on sensitive files.

### 22. No Obvious CORS Misconfiguration (严重性: Info)

- 类型: `info`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
[{"origin": "https://evil.example.com", "error": "HTTP Error 500: Internal Server Error"}, {"origin": "null", "error": "HTTP Error 500: Internal Server Error"}, {"origin": "https://0x6288.com.evil.invalid", "error": "HTTP Error 523: <none>"}]
```

**复现步骤**

1. Probe http://0x6288.com:8080 with untrusted Origin headers and inspect response.

**修复建议**

Remove public exposure, rotate leaked secrets, and enforce deny-by-default on sensitive files.

### 23. No Obvious CORS Misconfiguration (严重性: Info)

- 类型: `info`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
[{"origin": "https://evil.example.com", "error": "timed out"}, {"origin": "null", "error": "timed out"}, {"origin": "https://0x6288.com.evil.invalid", "error": "timed out"}]
```

**复现步骤**

1. Probe http://0x6288.com:8000 with untrusted Origin headers and inspect response.

**修复建议**

Remove public exposure, rotate leaked secrets, and enforce deny-by-default on sensitive files.

### 24. No Obvious CORS Misconfiguration (严重性: Info)

- 类型: `info`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
[{"origin": "https://evil.example.com", "error": "timed out"}, {"origin": "null", "error": "timed out"}, {"origin": "https://0x6288.com.evil.invalid", "error": "timed out"}]
```

**复现步骤**

1. Probe http://0x6288.com:8008 with untrusted Origin headers and inspect response.

**修复建议**

Remove public exposure, rotate leaked secrets, and enforce deny-by-default on sensitive files.

### 25. No Obvious CORS Misconfiguration (严重性: Info)

- 类型: `info`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
[{"origin": "https://evil.example.com", "error": "timed out"}, {"origin": "null", "error": "timed out"}, {"origin": "https://0x6288.com.evil.invalid", "error": "timed out"}]
```

**复现步骤**

1. Probe http://0x6288.com:8888 with untrusted Origin headers and inspect response.

**修复建议**

Remove public exposure, rotate leaked secrets, and enforce deny-by-default on sensitive files.

### 26. No Obvious CORS Misconfiguration (严重性: Info)

- 类型: `info`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
[{"origin": "https://evil.example.com", "error": "timed out"}, {"origin": "null", "error": "timed out"}, {"origin": "https://0x6288.com.evil.invalid", "error": "timed out"}]
```

**复现步骤**

1. Probe http://0x6288.com:3128 with untrusted Origin headers and inspect response.

**修复建议**

Remove public exposure, rotate leaked secrets, and enforce deny-by-default on sensitive files.

### 27. No Obvious CORS Misconfiguration (严重性: Info)

- 类型: `info`
- 类别: `-`
- CVE 是否已验证: `False`

**证据**

```text
[{"origin": "https://evil.example.com", "error": "timed out"}, {"origin": "null", "error": "timed out"}, {"origin": "https://0x6288.com.evil.invalid", "error": "timed out"}]
```

**复现步骤**

1. Probe http://0x6288.com:5800 with untrusted Origin headers and inspect response.

**修复建议**

Remove public exposure, rotate leaked secrets, and enforce deny-by-default on sensitive files.

## Run Metadata

- resumed: `false`
- resumed_from: ``
- resume_start_iteration: `1`
- resume_start_budget: `999`
