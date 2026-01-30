[← Back to Index](../INDEX.md)

# Complete CLI Reference

Every flag LANTERN supports, organized by function.

---

## Target & Basic

| Flag | Description | Example |
|------|-------------|---------|
| `-t, --target` | Target URL or file of URLs | `-t https://target.com` or `-t urls.txt` |
| `-m, --modules` | Comma-separated modules | `-m sqli,xss,cmdi` |
| `-H, --header` | Custom header (repeatable) | `-H "Authorization: Bearer TOKEN"` |
| `-c, --cookies` | Cookies string | `-c "session=abc123; auth=xyz"` |
| `--proxy` | Proxy URL | `--proxy http://127.0.0.1:8080` |
| `--threads` | Concurrent requests (default: 50) | `--threads 100` |
| `--timeout` | Request timeout seconds (default: 10) | `--timeout 30` |
| `-v, --verbose` | Verbose output | `-v` |
| `--no-banner` | Hide banner | `--no-banner` |

---

## Scan Modes

| Flag | What It Does | When to Use |
|------|--------------|-------------|
| `--fast` | Quick checks only (headers, cors, fingerprint) | Initial reconnaissance |
| `--deep` | Thorough injection testing | Full vulnerability assessment |
| `--aggressive` | 200+ payload mutations, WAF bypass | WAF-protected targets |
| `--stealth` | Slower, randomized timing | Rate-limited or monitored targets |
| `--smart` | Auto-select modules based on detected tech | Unknown targets |
| `--exploit` | Extract data, dump creds, prove impact | Confirmed vulnerabilities |

**Combinations:**
```bash
--deep --aggressive --exploit    # Maximum coverage + exploitation
--stealth --deep --threads 10    # Thorough but quiet
--smart --exploit --crawl        # Auto-adapt and exploit
```

---

## Reporting

| Flag | Description | Example |
|------|-------------|---------|
| `-o, --output` | Report filename (no extension) | `-o scan_report` |
| `--format` | Report format | `--format html` / `json` / `md` / `jira` / `all` |
| `--generate-pocs` | Create PoC files (curl, Python, JS) | `--generate-pocs` |
| `--sarif` | SARIF output for GitHub/GitLab | `--sarif results.sarif` |
| `--junit` | JUnit XML for CI pipelines | `--junit results.xml` |

**Report contents:**
- **Executive Summary** - Risk level, affected areas, recommendations
- **Detailed Findings** - CVSS score, evidence, request/response
- **Proof of Concept** - Working curl command, Python script, JS code
- **Remediation** - Specific fix with code examples

**Examples:**
```bash
lantern -t https://target.com -o report --format html
lantern -t https://target.com -o report --format all --generate-pocs
lantern -t https://target.com --sarif results.sarif --junit results.xml
```

---

## Mutation & WAF Bypass

The `--aggressive` flag enables:

| Feature | What It Does |
|---------|--------------|
| **200+ Regex Mutations** | Pattern-based payload transformations |
| **34 Obfuscation Techniques** | Encoding, case mixing, comments, concatenation |
| **WAF Detection** | Identifies Cloudflare, AWS WAF, Akamai, etc. |
| **Adaptive Bypass** | Uses WAF-specific bypass techniques |
| **Learned Payloads** | Saves successful bypasses for future scans |

**Mutation categories:**
- **Encoding**: URL, double URL, unicode, hex, HTML entities, UTF-7/16
- **Case**: Random, alternating, inverse
- **Whitespace**: Tab, newline, null byte, zero-width chars
- **Comments**: SQL inline, version comments, HTML/JS comment injection
- **Concatenation**: String concat, CHAR(), fromCharCode()
- **Splitting**: Keyword split, reverse, chunking

```bash
lantern -t https://target.com -m sqli,xss --aggressive
lantern -t https://target.com -m waf,sqli,xss --aggressive --deep
```

---

## Presets & Chains

| Flag | Description |
|------|-------------|
| `--preset` | Use preset profile | `--preset fast/thorough/api/stealth/exploit` |
| `--chain` | Attack chain mode | `--chain rce/auth_bypass/data_theft/injection` |
| `--list` | List available modules | |
| `--list-presets` | List available presets | |
| `--list-chains` | List attack chains | |

**Attack Chains:**

| Chain | Goal | Modules |
|-------|------|---------|
| `rce` | Remote code execution | cmdi, ssti, deserial, upload, ssrf |
| `auth_bypass` | Break authentication | sqli, ldap, auth, jwt, oauth, mfa, session |
| `data_theft` | Extract sensitive data | sqli, ssrf, lfi, xxe, idor, disclosure, cloud |
| `xss_chain` | Client-side attacks | csp, xss, dom, prototype, cors, csrf |
| `api_attack` | API exploitation | api, graphql, massassign, jwt, idor |
| `injection` | All injections | sqli, xss, ssti, cmdi, lfi, xxe, crlf |
| `full_recon` | Complete enumeration | techdetect, fingerprint, subdomain, takeover, cloud, dirbust |
| `smuggle` | HTTP smuggling | h2smuggle, smuggle, cachepois |
| `poisoning` | Poisoning attacks | hostinject, emailinject, crlf, cachepois, redirect |
| `business_logic` | Business logic | logic, payment, race, account, massassign |

---

## Crawling

| Flag | Description |
|------|-------------|
| `--crawl` | Crawl target to discover URLs |
| `--crawl-depth` | Crawl depth (default: 3) |

```bash
lantern -t https://target.com --crawl --crawl-depth 5 -m sqli,xss --exploit
```

---

## DNS & Subdomain

| Flag | Description |
|------|-------------|
| `--dns-brute` | High-speed DNS subdomain brute force |
| `--dns-wordlist` | Custom wordlist path |
| `--dns-concurrency` | DNS concurrency (default: 500) |

```bash
lantern -t https://target.com --dns-brute --dns-concurrency 1000 -m subdomain,takeover
```

---

## Scope Management

| Flag | Description |
|------|-------------|
| `--scope-file` | Scope configuration YAML |
| `--include-domain` | Include domain (repeatable) |
| `--exclude-domain` | Exclude domain (repeatable) |
| `--exclude-pattern` | Exclude URL regex (repeatable) |

```bash
lantern -t urls.txt --include-domain api.target.com --exclude-pattern "/static/"
```

---

## Caching

| Flag | Description |
|------|-------------|
| `--cache` | Enable response caching |
| `--cache-ttl` | Cache TTL in seconds (default: 300) |

```bash
lantern -t https://target.com --cache --cache-ttl 600 -m dirbust,disclosure
```

---

## Authentication

| Flag | Description |
|------|-------------|
| `--auth-config` | Auth configuration YAML file |

```yaml
# configs/auth.yml
authentication:
  type: form          # form, basic, bearer, api_key
  login_url: /login
  form:
    username_field: email
    password_field: password
  roles:
    admin:
      username: admin@target.com
      password: "${ADMIN_PASSWORD}"
    user:
      username: user@target.com
      password: "${USER_PASSWORD}"
```

```bash
lantern -t https://target.com --auth-config configs/auth.yml -m idor,auth --exploit
```

---

## Workflows

| Flag | Description |
|------|-------------|
| `--workflow` | Run workflow YAML file |
| `--workflow-attack` | Run specific attack from workflow |
| `--list-workflows` | List available workflows |

```bash
lantern --list-workflows
lantern -t https://target.com --workflow workflows/payment_bypass.yml
lantern -t https://target.com --workflow workflows/auth_bypass.yml --workflow-attack jwt_none_algorithm
```

---

## OOB Callback Server

| Flag | Description |
|------|-------------|
| `--callback-host` | External callback host |
| `--oob-server` | Start built-in OOB server |
| `--oob-port` | HTTP port (default: 8888) |
| `--oob-dns-port` | DNS port (default: 5353) |

**Use cases:**
- Blind SSRF - HTTP callback confirms connectivity
- Blind XXE - OOB entity exfiltration
- Blind SQLi - DNS/HTTP exfil
- Log4Shell - JNDI callback
- Blind XSS - Delayed callback

```bash
lantern -t https://target.com --oob-server -m ssrf,xxe,sqli --exploit
lantern -t https://target.com --callback-host your-server.com -m xss,ssrf
```

---

## New v2.0 Features

| Flag | What It Does |
|------|--------------|
| `--tech-detect` | Technology fingerprinting only |
| `--analyze-js` | Extract endpoints, secrets, DOM sinks from JS |
| `--cve-scan` | Scan for Log4Shell, Spring4Shell, 50+ CVEs |
| `--fuzz-params` | Intelligent parameter fuzzing |
| `--diff-baseline` | Anomaly detection with response baselines |
| `--resume` | Resume from checkpoint |

```bash
lantern -t https://target.com --tech-detect
lantern -t https://target.com --analyze-js -m xss,dom --exploit
lantern -t https://target.com --cve-scan --oob-server
lantern -t https://target.com --fuzz-params -m sqli,xss
```

---

## CI/CD Integration

| Flag | Description |
|------|-------------|
| `--ci` | CI/CD mode with exit codes |
| `--fail-on` | Fail threshold: `CRITICAL/HIGH/MEDIUM/LOW` |

**Exit Codes:**
| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities above threshold |
| 1 | Vulnerabilities at/above fail-on severity |
| 2 | Count threshold exceeded |
| 3 | Scan error |
| 4 | Configuration error |

```bash
lantern -t https://staging.target.com --ci --fail-on HIGH --sarif results.sarif --no-banner
```

**GitHub Actions:**
```yaml
- name: Security Scan
  run: lantern -t ${{ env.TARGET }} --ci --sarif results.sarif --fail-on HIGH
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Collaboration

| Flag | Description |
|------|-------------|
| `--collab-server` | Start collaboration server |
| `--collab-client` | Connect to collaboration server |

```bash
# Start server
lantern --collab-server 0.0.0.0:8080

# Team member connects
lantern -t https://target.com --collab-client ws://team.local:8080 -m sqli,xss
```

Findings are shared in real-time across the team.

---

## Module Quick Reference

**Injection (15):** `sqli`, `xss`, `cmdi`, `ssti`, `lfi`, `xxe`, `crlf`, `hpp`, `ldap`, `fuzz`, `deserial`, `smuggle`, `h2smuggle`, `emailinject`, `hostinject`

**Auth (14):** `auth`, `jwt`, `oauth`, `mfa`, `session`, `cookie`, `csrf`, `idor`, `massassign`, `cors`, `redirect`, `clickjack`, `upload`, `accessctl`

**API (4):** `api`, `graphql`, `websocket`, `apiver`

**Recon (13):** `fingerprint`, `disclosure`, `secrets`, `subdomain`, `techdetect`, `dirbust`, `paramfind`, `takeover`, `cloud`, `waf`, `dork`, `cve`, `brokenlinks`

**Client (4):** `dom`, `prototype`, `csp`, `embed`

**Config (7):** `headers`, `ssl`, `cache`, `cachepois`, `download`, `ssrf`, `cdn`

**Business (5):** `payment`, `race`, `captcha`, `account`, `logic`

**Total: 62 modules**

---

[← Back to Index](../INDEX.md)
