# lynolz.com ??????????

- ????(UTC): 2026-03-04T07:48:57.109608+00:00
- ????: lynolz.com
- ????: controlled_tool_smoke_test
- ????: 24
- ??????: 24/24
- ?? smoke ??: 24/24
- ????????: 5

## ????

- ?????? smoke test??????????????
- ???????????????? dirsearch ?? VCS ????nuclei ?? info ?????crawler ??????/?????
- ??????????????????????/???????? dogs.lynolz.com?

## ????

| Tool | Category | Availability | Execution | Duration(ms) | Findings | Notes |
| --- | --- | --- | --- | ---: | ---: | --- |
| active_web_crawler | discovery | OK | OK | 35577 | 0 | - |
| api_schema_discovery | discovery | OK | OK | 6981 | 0 | - |
| cookie_security_audit | testing | OK | OK | 766 | 0 | - |
| cors_misconfiguration | testing | OK | OK | 5231 | 1 | No Obvious CORS Misconfiguration |
| csp_evaluator | testing | OK | OK | 978 | 0 | - |
| dirsearch_scan | discovery | OK | OK | 16102 | 0 | - |
| dynamic_crawl | discovery | OK | OK | 41222 | 0 | - |
| error_page_analyzer | recon | OK | OK | 786 | 0 | - |
| git_exposure_check | recon | OK | OK | 4050 | 0 | - |
| http_security_headers | recon | OK | OK | 1395 | 0 | - |
| js_endpoint_extractor | recon | OK | OK | 1729 | 0 | - |
| login_form_detector | recon | OK | OK | 731 | 0 | - |
| nmap_scan | recon | OK | OK | 12189 | 0 | - |
| nuclei_exploit_check | validation | OK | OK | 210056 | 42 | DNS WAF Detection, Cookies without Secure attribute - Detect |
| param_fuzzer | testing | OK | OK | 2315 | 1 | Parameter Fuzzing Observed Notable Response Change |
| passive_config_audit | recon | OK | OK | 10900 | 0 | - |
| security_txt_check | recon | OK | OK | 743 | 0 | - |
| source_map_detector | recon | OK | OK | 12414 | 0 | - |
| sql_sanitization_audit | testing | OK | OK | 7371 | 0 | - |
| ssl_expiry_check | recon | OK | OK | 892 | 1 | TLS Certificate Expiry Healthy |
| subdomain_enum_passive | recon | OK | OK | 1948 | 1 | Passive Subdomain Enumeration Results |
| tech_stack_fingerprint | recon | OK | OK | 922 | 0 | - |
| waf_detector | recon | OK | OK | 765 | 0 | - |
| xss_protection_audit | testing | OK | OK | 1078 | 0 | - |

## ????

- **active_web_crawler**: api_endpoints=13; urls=153
- **cors_misconfiguration**: findings=1
- **dirsearch_scan**: entries=0
- **dynamic_crawl**: api_endpoints=13; urls=153
- **nuclei_exploit_check**: findings=42
- **param_fuzzer**: findings=1
- **ssl_expiry_check**: findings=1
- **subdomain_enum_passive**: findings=1; subdomains=1 sample

## ??????

- JSON: `/workspace/output/lynolz_tool_availability/results.json`
- Doctor: `/workspace/output/lynolz_tool_availability/doctor.json`
