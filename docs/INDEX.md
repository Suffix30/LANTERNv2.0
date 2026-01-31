# LANTERN Documentation

**LANTERN** is not just a vulnerability scanner - it's an intelligent exploitation framework that finds vulnerabilities, confirms they're real, extracts data, and generates ready-to-use proof-of-concept code.

---

## What Makes LANTERN Different

| Feature | What It Does |
|---------|--------------|
| **Auto-Exploitation** | Doesn't just find SQLi - extracts database version, tables, and credentials |
| **Smart Mutations** | 200+ payload transformations that adapt to WAFs in real-time |
| **Learned Payloads** | Successful bypasses are saved and reused - your arsenal grows with each scan |
| **Context-Aware Testing** | Detects WHERE your input is reflected (HTML, attribute, script, etc.) and uses targeted payloads |
| **PoC Generation** | Every finding includes working curl commands, Python scripts, and JS code |
| **Business Logic Testing** | YAML workflows for multi-step attacks (checkout bypass, auth escalation, etc.) |

---

## Quick Start

```bash
lantern -t https://target.com --fast                    # Quick reconnaissance
lantern -t https://target.com -m sqli,xss --exploit     # Find + exploit injections
lantern -t https://target.com --deep --aggressive       # Full mutation engine
lantern -t https://target.com -o report --generate-pocs # Generate PoC files
```

---

## Documentation

### Core Guides

| Guide | Description |
|-------|-------------|
| [Complete CLI Reference](guides/reference.md) | Every flag, every option, every mode |
| [Advanced Techniques](guides/advanced.md) | Stealth mode, proxies, CI/CD, multi-stage attacks |

### Module Guides

Deep-dive into each vulnerability category with real attack scenarios.

| Category | What It Finds | Guide |
|----------|---------------|-------|
| **Injection** | SQLi (with auto-extraction), XSS (context-aware), Command Injection, SSTI, XXE, LDAP, CRLF | [View](modules/injection.md) |
| **Authentication** | JWT attacks, OAuth flaws, MFA bypass, session fixation, IDOR, privilege escalation | [View](modules/auth.md) |
| **API Security** | REST/GraphQL introspection, WebSocket hijacking, mass assignment, BOLA | [View](modules/api.md) |
| **Client-Side** | DOM XSS, prototype pollution, CSP bypass, clickjacking | [View](modules/client.md) |
| **Reconnaissance** | Tech fingerprinting, subdomain takeover, cloud misconfig, secret scanning | [View](modules/recon.md) |
| **RCE** | Command injection chains, SSTI to shell, deserialization, file upload bypass | [View](modules/rce.md) |
| **Data Extraction** | LFI chains, XXE OOB exfil, SSRF to cloud metadata, credential harvesting | [View](modules/data.md) |
| **Configuration** | Security headers, SSL/TLS issues, cache poisoning | [View](modules/config.md) |
| **Business Logic** | Race conditions, payment bypass, coupon stacking, account enumeration | [View](modules/business.md) |
| **Advanced Attacks** | HTTP/2 smuggling, request smuggling, cache poisoning chains | [View](modules/advanced.md) |

### Feature Guides

LANTERN's advanced capabilities explained in depth.

| Feature | What It Does | Guide |
|---------|--------------|-------|
| **Mutation Engine** | How the 200+ payload transformations and 34 obfuscation techniques work | [View](features/waf-bypass.md) |
| **Workflows** | Create multi-step attack chains (YAML-based business logic testing) | [View](features/workflows.md) |
| **JavaScript Analysis** | Extract hidden endpoints, hardcoded secrets, and DOM sinks from JS | [View](features/js-analysis.md) |
| **CVE Scanning** | Auto-detect Log4Shell, Spring4Shell, and 50+ other CVEs | [View](features/cve-scanning.md) |
| **Auth Testing** | Multi-role testing - find what admin can see that user can't | [View](features/auth-testing.md) |
| **OOB Server** | Built-in callback server for blind SSRF, XXE, and SQLi | [View](features/oob-server.md) |

---

## Module Reference (62 Total)

| Category | Modules |
|----------|---------|
| **Injection** | `sqli`, `xss`, `cmdi`, `ssti`, `lfi`, `xxe`, `crlf`, `hpp`, `ldap`, `fuzz`, `deserial`, `smuggle`, `h2smuggle`, `emailinject`, `hostinject` |
| **Auth** | `auth`, `jwt`, `oauth`, `mfa`, `session`, `cookie`, `csrf`, `idor`, `massassign`, `cors`, `redirect`, `clickjack`, `upload`, `accessctl` |
| **API** | `api`, `graphql`, `websocket`, `apiver` |
| **Recon** | `fingerprint`, `disclosure`, `secrets`, `subdomain`, `techdetect`, `dirbust`, `paramfind`, `takeover`, `cloud`, `waf`, `dork`, `cve`, `brokenlinks` |
| **Client** | `dom`, `prototype`, `csp`, `embed` |
| **Config** | `headers`, `ssl`, `cache`, `cachepois`, `download`, `ssrf`, `cdn` |
| **Business** | `payment`, `race`, `captcha`, `account`, `logic` |

---

## Attack Chains

Pre-configured module combinations for specific attack goals.

```bash
lantern -t https://target.com --chain rce --exploit        # Shell access
lantern -t https://target.com --chain auth_bypass --exploit # Break authentication
lantern -t https://target.com --chain data_theft --exploit  # Extract everything
```

| Chain | Goal | Modules |
|-------|------|---------|
| `rce` | Remote code execution | cmdi, ssti, deserial, upload, ssrf |
| `auth_bypass` | Break authentication | sqli, ldap, auth, jwt, oauth, mfa, session |
| `data_theft` | Extract sensitive data | sqli, ssrf, lfi, xxe, idor, disclosure, cloud |
| `xss_chain` | Client-side attacks | csp, xss, dom, prototype, cors, csrf |
| `api_attack` | API exploitation | api, graphql, massassign, jwt, idor |
| `injection` | All injection types | sqli, xss, ssti, cmdi, lfi, xxe, crlf |
| `full_recon` | Complete enumeration | techdetect, fingerprint, subdomain, takeover, cloud, dirbust, disclosure |

---

## Reporting

LANTERN generates professional reports with everything you need:

- **Executive Summary** - Risk level, recommendations, affected areas
- **Detailed Findings** - CVSS scores, evidence, request/response data
- **Proof of Concept** - Working curl commands, Python scripts, JS code
- **Remediation** - Specific fix guidance with code examples

```bash
lantern -t https://target.com -o report --format html         # HTML report
lantern -t https://target.com -o report --format all          # All formats
lantern -t https://target.com -o report --generate-pocs       # With PoC files
lantern -t https://target.com --sarif results.sarif           # GitHub/GitLab integration
```

---

## Agent BLACK - AI Security Companion

LANTERN includes an AI-powered security assistant that understands your workflow.

> **Note:** Obsidian integration is in beta - core features work but may evolve.

| Feature | Description |
|---------|-------------|
| **Chat Mode** | Natural language commands → LANTERN actions |
| **Overwatch Mode** | Monitors terminals, browser, files for situational awareness |
| **Watch Mode** | Continuous monitoring with proactive alerts |
| **Obsidian Integration** | Full vault for writeups, targets, methodology |

```bash
black chat                    # Interactive chat
black overwatch --snapshot    # Analyze current situation
black overwatch --watch       # Continuous monitoring
black obsidian init ~/vault   # Create security vault
```

**[→ Full Agent BLACK Documentation](../agent/docs/SETUP.md)**

---

*For authorized testing only.*
