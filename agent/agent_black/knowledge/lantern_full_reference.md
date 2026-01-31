# LANTERN Full Reference

This document is auto-generated from the live LANTERN codebase.
Run `python build_from_lantern.py` from the LANTERN root to regenerate.

## IMPORTANT: Complete Documentation

For FULL mastery of LANTERN, I also have access to the complete official
documentation in my knowledge folder:

```
lantern_docs/
├── INDEX.md              ← Documentation index
├── features/             ← Feature-specific guides
│   ├── auth-testing.md   ← Authentication testing
│   ├── cve-scanning.md   ← CVE detection
│   ├── js-analysis.md    ← JavaScript analysis
│   ├── oob-server.md     ← Out-of-band callbacks
│   ├── waf-bypass.md     ← WAF bypass techniques (8KB!)
│   └── workflows.md      ← Workflow system guide
├── guides/
│   ├── advanced.md       ← Advanced usage
│   └── reference.md      ← Complete CLI reference (10KB!)
├── modules/
│   ├── injection.md      ← SQLi, XSS, CMDI, SSTI, XXE, LFI
│   ├── auth.md           ← JWT, OAuth, MFA, Session
│   ├── rce.md            ← Remote code execution
│   ├── recon.md          ← Reconnaissance modules
│   ├── api.md            ← API testing
│   ├── business.md       ← Business logic
│   ├── client.md         ← Client-side attacks
│   ├── config.md         ← Configuration issues
│   └── data.md           ← Data exposure
└── *.yml                 ← Attack workflow definitions
    ├── auth_bypass.yml
    ├── payment_bypass.yml
    ├── password_reset.yml
    ├── sqli_escalate.yml
    ├── ssrf_chain.yml
    └── ...
```

I should read these files when I need detailed information about:
- Specific module capabilities
- WAF bypass techniques
- Workflow attack sequences
- Complete CLI flag usage

## Modules
Total modules: 63

### Module Lists
**ALL_MODULES**
- sqli
- xss
- ssrf
- lfi
- ssti
- cmdi
- xxe
- crlf
- hpp
- auth
- jwt
- oauth
- mfa
- session
- cookie
- csrf
- ldap
- idor
- massassign
- cors
- accessctl
- api
- graphql
- websocket
- apiver
- dom
- prototype
- clickjack
- payment
- race
- captcha
- account
- logic
- headers
- ssl
- cache
- upload
- download
- fingerprint
- disclosure
- secrets
- subdomain
- dork
- cve
- dirbust
- smuggle
- deserial
- fuzz
- redirect
- techdetect
- waf
- takeover
- cloud
- paramfind
- csp
- h2smuggle
- cachepois
- cdn
- brokenlinks
- embed
- hostinject
- emailinject

**FAST_MODULES** (used with --fast)
- waf
- headers
- cors
- disclosure
- fingerprint
- secrets
- clickjack
- cve
- ssl
- cookie
- dork
- techdetect

**DEEP_MODULES** (used with --deep)
- sqli
- xss
- ssrf
- lfi
- ssti
- cmdi
- xxe
- ldap
- oauth
- mfa
- jwt
- massassign
- prototype
- fuzz
- smuggle
- crlf
- upload
- hpp
- cache
- race
- dom
- session
- deserial
- payment
- account
- download
- dirbust

### Module Details
| Module | Description | Category | Exploitable |
|--------|-------------|----------|-------------|
| accessctl | Access Control / Privilege Escalation Scanner | Access | Yes |
| account | Account & Registration Security Scanner | Business | No |
| api | REST API Security Scanner | API | No |
| apiver | API Version Discovery Scanner | API | No |
| auth | Authentication Security Scanner | Auth | No |
| base | Base module | None | No |
| brokenlinks | Broken Links Checker | Recon | No |
| cache | Web Cache Poisoning and Deception Scanner | Config | No |
| cachepois | Web Cache Poisoning Scanner | Advanced | Yes |
| captcha | CAPTCHA & Rate Limit Bypass Scanner | Business | No |
| cdn | CDN Detection | Config | No |
| clickjack | Clickjacking Vulnerability Scanner | Client | No |
| cloud | Cloud Misconfiguration Scanner | Recon | Yes |
| cmdi | OS Command Injection Scanner | Injection | Yes |
| cookie | Cookie Security Scanner | Auth | No |
| cors | CORS Misconfiguration Scanner | Access | No |
| crlf | CRLF Injection / HTTP Response Splitting Scanner | Injection | Yes |
| csp | Content Security Policy Analyzer | Config | No |
| csrf | Cross-Site Request Forgery Scanner | Auth | No |
| cve | Known CVE and CMS Vulnerability Scanner | Recon | No |
| deserial | Insecure Deserialization Scanner with Gadget Chains | Advanced | Yes |
| dirbust | Directory & File Brute Force Scanner | None | No |
| disclosure | Information Disclosure Scanner | Recon | No |
| dom | DOM-based Vulnerability Scanner | Client | Yes |
| dork | Google Dork Generator for Target Recon | Recon | No |
| download | File Download & Export Security Scanner | Config | No |
| emailinject | Email Header Injection (CRLF in email-sending forms) Scanner | Injection | No |
| embed | Embedded Objects Scanner | Client | No |
| fingerprint | Technology Fingerprinting | Recon | No |
| fuzz | Smart Parameter Fuzzer | Advanced | No |
| graphql | GraphQL Security Scanner | API | Yes |
| h2smuggle | HTTP/2 Request Smuggling Scanner | Advanced | Yes |
| headers | Security Headers Analyzer | Config | No |
| hostinject | Host Header / Password Reset Poisoning Scanner | Auth | No |
| hpp | HTTP Parameter Pollution Scanner | Injection | No |
| idor | Insecure Direct Object Reference Scanner | Access | Yes |
| jwt | JWT Token Full Attack Suite | Auth | Yes |
| ldap | LDAP Injection & Active Directory Scanner | Injection | Yes |
| lfi | Local File Inclusion / Path Traversal Scanner | Server-Side | Yes |
| logic | Business Logic / Parameter Tampering Scanner | Business | Yes |
| massassign | Mass Assignment / Hidden Parameter Injection Scanner | Access | No |
| mfa | Multi-Factor Authentication Bypass Scanner | Auth | Yes |
| oauth | OAuth 2.0 Misconfiguration Scanner | Auth | Yes |
| paramfind | Hidden Parameter Discovery | Recon | No |
| payment | E-commerce & Payment Security Scanner | Business | No |
| prototype | JavaScript Prototype Pollution Scanner | Client | No |
| race | Race Condition Scanner | Business | Yes |
| redirect | Open Redirect Scanner | Advanced | Yes |
| secrets | Secrets and Credentials Scanner | Recon | No |
| session | Session Management Security Scanner | Auth | No |
| smuggle | HTTP Request Smuggling Scanner | Advanced | No |
| sqli | SQL Injection Scanner with Auto Exploitation | Injection | Yes |
| ssl | SSL/TLS Configuration Scanner | Config | No |
| ssrf | Server-Side Request Forgery Scanner | Server-Side | Yes |
| ssti | Server-Side Template Injection Scanner with Auto RCE | Server-Side | Yes |
| subdomain | High-Speed Subdomain Enumeration and Takeover Detection | Recon | No |
| takeover | Subdomain Takeover Scanner | Recon | Yes |
| techdetect | Technology Stack Detection and Module Recommendation | Recon | No |
| upload | File Upload Vulnerability Scanner | Config | Yes |
| waf | WAF Detection & Fingerprinting | Recon | No |
| websocket | WebSocket Security Scanner | API | Yes |
| xss | Cross-Site Scripting Scanner | Injection | Yes |
| xxe | XML External Entity Injection Scanner | Injection | Yes |

## Attack Chains
Pre-configured module combinations for specific attack goals.

**auth_bypass**: waf, sqli, ldap, auth, jwt, oauth, mfa, session
**data_theft**: waf, sqli, ssrf, lfi, xxe, idor, disclosure, dirbust, cloud
**rce**: waf, cmdi, ssti, deserial, upload, ssrf
**xss_chain**: waf, csp, xss, dom, prototype, cors, csrf
**api_attack**: waf, api, graphql, massassign, jwt, idor
**enum**: waf, dirbust, subdomain, takeover, disclosure, fingerprint, techdetect, dork, cloud
**cloud**: cloud, ssrf, disclosure, dirbust
**takeover**: takeover, subdomain
**full_recon**: waf, techdetect, fingerprint, subdomain, takeover, cloud, dirbust, disclosure, dork, paramfind, csp
**injection**: waf, paramfind, sqli, xss, ssti, cmdi, lfi, xxe, crlf
**smuggle**: waf, h2smuggle, smuggle, cachepois
**cache**: cachepois, headers, cors
**poisoning**: hostinject, emailinject, crlf, cachepois, redirect, cache
**business_logic**: logic, payment, race, account, massassign

## Presets
### api
API-focused security testing
- Modules: api, graphql, jwt, oauth, massassign, idor, auth, cors, apiver, sqli, xss, ssrf, headers, secrets, disclosure

### exploit
Full exploitation mode with attack chains
- Modules: waf, sqli, xss, ssrf, lfi, ssti, cmdi, xxe, ldap, jwt, deserial, auth, oauth, massassign, upload, cloud, takeover, graphql, websocket, race, h2smuggle, cachepois

### fast
Quick scan with passive checks only
- Modules: headers, cors, disclosure, fingerprint, secrets, clickjack, cve, ssl, cookie, dork

### stealth
Low-profile scan with randomized timing
- Modules: headers, cors, disclosure, fingerprint, secrets, ssl, cookie, cve, subdomain

### thorough
Comprehensive scan with all injection tests
- Modules: waf, sqli, xss, ssrf, lfi, ssti, cmdi, xxe, crlf, hpp, ldap, auth, jwt, oauth, mfa, session, cookie, csrf, idor, massassign, cors, api, graphql, websocket, apiver, dom, prototype, clickjack, payment, race, captcha, account, headers, ssl, cache, cachepois, csp, upload, download, fingerprint, disclosure, secrets, subdomain, takeover, cloud, paramfind, dirbust, dork, cve, smuggle, h2smuggle, deserial, fuzz, redirect, techdetect, cdn, brokenlinks, embed, hostinject, emailinject, logic

## CLI Flags
| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target URL or file containing URLs |  |
| `-m, --modules` | Comma-separated modules (default: all) |  |
| `-o, --output` | Output report filename (without extension) |  |
| `--format` | Report format | html |
| `-H, --header` | Custom header (can be used multiple times) |  |
| `-c, --cookies` | Cookies string |  |
| `--threads` | Concurrent requests (default: 50) | 50 |
| `--timeout` | Request timeout (default: 10) | 10 |
| `--crawl` | Crawl target to discover URLs |  |
| `--crawl-depth` | Crawl depth (default: 3) | 3 |
| `--aggressive` | Aggressive mode (more payloads, WAF bypass) |  |
| `--stealth` | Stealth mode (slower, randomized) |  |
| `--fast` | Fast mode (quick checks only) |  |
| `--deep` | Deep mode (thorough injection testing) |  |
| `--preset` | Use preset profile (fast, thorough, api, stealth, exploit) |  |
| `--list-presets` | List available presets |  |
| `--chain` | Attack chain mode |  |
| `--exploit` | Enable auto-exploitation (extract data, dump creds) |  |
| `--proxy` | Proxy URL (e.g., http://127.0.0.1:8080) |  |
| `--callback-host` | Callback server host for OOB detection |  |
| `--list` | List available modules |  |
| `--list-chains` | List attack chain presets |  |
| `--resume` | Resume from last checkpoint |  |
| `--collab-server` | Start collab server (e.g., 0.0.0.0:8080) |  |
| `--collab-client` | Connect to collab server (e.g., ws://team.local:8080) |  |
| `--no-banner` | Hide banner |  |
| `--smart` | Smart module selection based on tech detection |  |
| `--tech-detect` | Run technology detection only |  |
| `--dns-brute` | High-speed DNS subdomain brute force |  |
| `--dns-wordlist` | Custom wordlist for DNS brute force |  |
| `--dns-concurrency` | DNS brute force concurrency (default: 500) | 500 |
| `-v, --verbose` | Verbose output |  |
| `--ci` | CI/CD mode with exit codes |  |
| `--fail-on` | Fail on severity (default: HIGH) | HIGH |
| `--sarif` | Output SARIF report for GitHub/GitLab |  |
| `--junit` | Output JUnit XML for CI pipelines |  |
| `--scope-file` | Scope configuration file |  |
| `--include-domain` | Include domain in scope |  |
| `--exclude-domain` | Exclude domain from scope |  |
| `--exclude-pattern` | Exclude URL pattern (regex) |  |
| `--cache` | Enable response caching |  |
| `--cache-ttl` | Cache TTL in seconds (default: 300) | 300 |
| `--auth-config` | Authentication configuration YAML file |  |
| `--workflow` | Run business logic workflow YAML file |  |
| `--workflow-attack` | Run specific attack from workflow |  |
| `--oob-server` | Start built-in OOB callback server |  |
| `--oob-port` | OOB HTTP server port (default: 8888) | 8888 |
| `--oob-dns-port` | OOB DNS server port (default: 5353) | 5353 |
| `--analyze-js` | Deep JavaScript analysis (endpoints, secrets, DOM sinks) |  |
| `--cve-scan` | Scan for known CVEs based on detected technologies |  |
| `--generate-pocs` | Generate PoC files for each finding |  |
| `--fuzz-params` | Intelligent parameter fuzzing with boundary values |  |
| `--diff-baseline` | Establish response baselines for anomaly detection |  |
| `--list-workflows` | List available attack workflows |  |

## Payloads
Total payload files: 28

- payloads\__init__.py (0 bytes)
- payloads\cmdi.txt (924 bytes)
- payloads\crlf.txt (1315 bytes)
- payloads\dorks\admin_login.txt (2629 bytes)
- payloads\dorks\backups.txt (2208 bytes)
- payloads\dorks\cms_vulns.txt (2968 bytes)
- payloads\dorks\database_files.txt (3386 bytes)
- payloads\dorks\error_pages.txt (2714 bytes)
- payloads\dorks\sensitive_files.txt (3032 bytes)
- payloads\headers_bypass.txt (1131 bytes)
- payloads\learned\index.json (6577 bytes)
- payloads\learned\lfi.txt (35 bytes)
- payloads\learned\redirect.txt (12 bytes)
- payloads\learned\sqli.txt (83 bytes)
- payloads\learned\websocket.txt (372 bytes)
- payloads\learned\xss.txt (101 bytes)
- payloads\lfi.txt (2940 bytes)
- payloads\paths.txt (1557 bytes)
- payloads\redirect.txt (1404 bytes)
- payloads\smuggle.txt (864 bytes)
- payloads\sqli.txt (2351 bytes)
- payloads\sqli_advanced.txt (2732 bytes)
- payloads\ssrf.txt (2794 bytes)
- payloads\ssti.txt (3051 bytes)
- payloads\xss.txt (4149 bytes)
- payloads\xss_advanced.txt (3093 bytes)
- payloads\xss_master.txt (4756 bytes)
- payloads\xxe.txt (2567 bytes)

## Smart Module Mapping
Technology to module mapping for --smart mode:

- **sqli**: s, q, l, i
- **xss**: x, s, s
- **lfi**: l, f, i
- **ssrf**: s, s, r, f
- **ssti**: s, s, t, i
- **cmdi**: c, m, d, i
- **xxe**: x, x, e
- **upload**: u, p, l, o, a, d
- **deserial**: d, e, s, e, r, i, a, l
- **prototype**: p, r, o, t, o, t, y, p, e
- **graphql**: g, r, a, p, h, q, l
- **api**: a, p, i, v, e, r
- **idor**: i, d, o, r
- **auth**: a, u, t, h
