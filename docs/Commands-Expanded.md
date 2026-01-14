# Lantern Command Reference

Comprehensive command examples and module combinations for security testing scenarios.

---

## Table of Contents

- [Module Combinations](#module-combinations)
- [Obfuscation & WAF Bypass](#obfuscation--waf-bypass)
- [Advanced Techniques](#advanced-techniques)
- [Module Reference](#module-reference)
- [Quick Reference](#quick-reference)

---

## Module Combinations

### Injection Testing

**Complete Injection Suite**
```bash
lantern -t https://target.com -m sqli,xss,cmdi,ssti,lfi,xxe,crlf,hpp,ldap --exploit --aggressive
```

**Web Application Injections**
```bash
lantern -t https://target.com -m sqli,xss,lfi,ssti --exploit --deep --crawl
```

**API Injection Testing**
```bash
lantern -t https://target.com -m sqli,xss,xxe,ldap --aggressive --crawl
```

**Advanced Injection Chain**
```bash
lantern -t https://target.com -m sqli,xss,cmdi,ssti,xxe,deserial,smuggle,h2smuggle --exploit --deep
```

**WAF Bypass + Injections**
```bash
lantern -t https://target.com -m waf,sqli,xss,cmdi --aggressive --exploit
```

### Authentication & Authorization

**Complete Auth Testing**
```bash
lantern -t https://target.com -m auth,jwt,oauth,mfa,session,cookie,csrf,idor --exploit --aggressive
```

**JWT & Session Security**
```bash
lantern -t https://target.com -m jwt,session,cookie,csrf --exploit --deep
```

**OAuth & MFA Bypass**
```bash
lantern -t https://target.com -m oauth,mfa,auth --exploit --aggressive
```

**Access Control Testing**
```bash
lantern -t https://target.com -m idor,massassign,auth --exploit --crawl
```

**Session & Cookie Security**
```bash
lantern -t https://target.com -m session,cookie,csrf,clickjack --aggressive --crawl
```

### API Security

**Complete API Assessment**
```bash
lantern -t https://api.target.com -m api,graphql,websocket,jwt,idor,apiver --exploit --aggressive
```

**REST API Testing**
```bash
lantern -t https://api.target.com -m api,idor,massassign,jwt --exploit --crawl
```

**GraphQL Security**
```bash
lantern -t https://api.target.com -m graphql,api,idor --exploit --deep
```

**WebSocket & Real-time APIs**
```bash
lantern -t https://target.com -m websocket,api,jwt --exploit --aggressive
```

**API Version Discovery**
```bash
lantern -t https://api.target.com -m apiver,api,graphql --crawl
```

### Client-Side Security

**XSS & DOM Testing**
```bash
lantern -t https://target.com -m xss,dom,prototype,csp,clickjack --exploit --callback-host your-server.com
```

**CORS & Clickjacking**
```bash
lantern -t https://target.com -m cors,clickjack,csrf --aggressive --crawl
```

**Prototype Pollution Chain**
```bash
lantern -t https://target.com -m prototype,dom,xss --exploit --aggressive
```

**CSP Bypass Testing**
```bash
lantern -t https://target.com -m csp,xss,dom,prototype --exploit --crawl
```

**Complete Client-Side**
```bash
lantern -t https://target.com -m xss,dom,prototype,cors,clickjack,csp,csrf --exploit --aggressive
```

### Reconnaissance

**Information Gathering**
```bash
lantern -t https://target.com -m fingerprint,disclosure,secrets,techdetect,dork --crawl
```

**Directory & File Discovery**
```bash
lantern -t https://target.com -m dirbust,disclosure,secrets,download --aggressive --crawl
```

**Subdomain & Infrastructure**
```bash
lantern -t https://target.com -m subdomain,takeover,cloud --dns-brute --dns-concurrency 1000
```

**Technology Detection & Smart Scan**
```bash
lantern -t https://target.com -m techdetect,fingerprint --smart --crawl
```

**Complete Reconnaissance**
```bash
lantern -t https://target.com -m techdetect,fingerprint,subdomain,takeover,cloud,dirbust,disclosure,secrets,dork,paramfind --dns-brute
```

### RCE & Code Execution

**Complete RCE Chain**
```bash
lantern -t https://target.com -m cmdi,ssti,deserial,upload,ssrf --exploit --deep --aggressive
```

**File Upload & Command Injection**
```bash
lantern -t https://target.com -m upload,cmdi --exploit --aggressive --deep
```

**Template Injection & Deserialization**
```bash
lantern -t https://target.com -m ssti,deserial --exploit --deep
```

**SSRF to RCE**
```bash
lantern -t https://target.com -m ssrf,cloud,cmdi --exploit --callback-host your-server.com
```

**Upload with Multiple Shell Types**
```bash
lantern -t https://target.com -m upload,cmdi,ssti --exploit --aggressive
```

### Data Extraction

**Sensitive Data Discovery**
```bash
lantern -t https://target.com -m secrets,disclosure,dirbust,lfi,xxe --exploit --crawl
```

**Cloud & Secrets Extraction**
```bash
lantern -t https://target.com -m cloud,secrets,ssrf,disclosure --exploit --aggressive
```

**File Reading Chain**
```bash
lantern -t https://target.com -m lfi,xxe,download,dirbust --exploit --deep
```

**Complete Data Theft**
```bash
lantern -t https://target.com -m ssrf,lfi,xxe,idor,disclosure,dirbust,secrets,cloud --exploit --aggressive
```

### Advanced Attacks

**HTTP Smuggling & Cache Poisoning**
```bash
lantern -t https://target.com -m smuggle,h2smuggle,cache,cachepois --exploit --aggressive
```

**Parameter Manipulation**
```bash
lantern -t https://target.com -m hpp,crlf,paramfind,fuzz --aggressive --crawl
```

**Race Conditions & Business Logic**
```bash
lantern -t https://target.com -m race,payment,captcha,account --exploit --threads 200
```

**Cache & Redirect Testing**
```bash
lantern -t https://target.com -m cache,cachepois,redirect --aggressive
```

### Configuration & Headers

**Security Headers & SSL**
```bash
lantern -t https://target.com -m headers,ssl,csp,clickjack --fast
```

**WAF Detection & Bypass**
```bash
lantern -t https://target.com -m waf,sqli,xss --aggressive
```

**Complete Config Testing**
```bash
lantern -t https://target.com -m headers,ssl,cache,cachepois,csp,redirect --fast
```

### Business Logic

**E-commerce Security**
```bash
lantern -t https://shop.target.com -m payment,race,captcha,account --exploit --aggressive
```

**Account Security**
```bash
lantern -t https://target.com -m account,race,captcha,payment --exploit --crawl
```

**Payment & Race Conditions**
```bash
lantern -t https://target.com -m payment,race,account --exploit --threads 200
```

---

## Obfuscation & WAF Bypass

### Aggressive Mode

The `--aggressive` flag automatically enables:
- **200+ regex-based payload mutations** (pattern transformations)
- **34 obfuscation techniques** across 6 categories
- **WAF detection and adaptive bypass**
- **Increased payload variants** per test

**Basic Usage**
```bash
lantern -t https://target.com -m sqli,xss --aggressive --exploit
```

**Maximum Bypass Attempts**
```bash
lantern -t https://target.com -m sqli,xss,cmdi --aggressive --deep --exploit
```

### WAF Detection + Bypass

**Detect Then Bypass**
```bash
lantern -t https://target.com -m waf,sqli,xss --aggressive --exploit
```

**WAF + Multiple Injection Types**
```bash
lantern -t https://target.com -m waf,sqli,xss,cmdi,ssti,xxe --aggressive --exploit
```

**WAF + Auth Bypass**
```bash
lantern -t https://target.com -m waf,auth,jwt,oauth --aggressive --exploit
```

### Mutation Strategies by Vulnerability Type

**SQL Injection Mutations**
- Case variations: `SELECT` → `SeLeCt`, `select`
- Inline comments: `SELECT/**/FROM`, `/*!SELECT*/`
- Whitespace encoding: `SELECT%09FROM`, `SELECT%0aFROM`
- Quote bypass: `'`, `"`, `` ` ``, hex, unicode
- Logical operator bypass: `OR`, `||`, `&&`

```bash
lantern -t https://target.com -m sqli --aggressive --exploit --deep
```

**XSS Mutations**
- Tag encoding: `<script>` → `%3Cscript>`, `&#60;script>`
- Case mixing: `<ScRiPt>`, `<SCRIPT>`
- Event handler bypass: `onerror`, `onload`, `onclick` variants
- Protocol bypass: `javascript:`, `data:`, `vbscript:`
- Unicode escapes: `\u003c`, `\x3c`

```bash
lantern -t https://target.com -m xss --aggressive --exploit --crawl
```

**Command Injection Mutations**
- Separator variants: `;`, `|`, `&`, `&&`, `||`, `%0a`, `%0d`
- IFS bypass: `${IFS}`, `$'IFS'`, space encoding
- Backtick bypass: `` `command` ``, `$(command)`
- Quote bypass for commands

```bash
lantern -t https://target.com -m cmdi --aggressive --exploit --deep
```

**LFI Mutations**
- Path traversal encoding: `../` → `..%2f`, `..%252f`, `..%c0%af`
- Null byte variants: `%00`, `%2500`, `\x00`
- Path encoding: `/etc/passwd` → `%2fetc%2fpasswd`

```bash
lantern -t https://target.com -m lfi --aggressive --exploit
```

**SSTI Mutations**
- Template syntax variations: `{{ }}`, `${ }`, `<%= %>`
- Dunder method bypass: `__class__`, `__init__`, etc.
- Expression variations

```bash
lantern -t https://target.com -m ssti --aggressive --exploit --deep
```

**SSRF Mutations**
- IP encoding: `127.0.0.1` → `127.1`, `0x7f000001`, `2130706433`
- Host bypass: `localhost` → `0.0.0.0`, `127.0.0.1.nip.io`
- Protocol wrapping: `http://`, `file://`, `gopher://`, `dict://`

```bash
lantern -t https://target.com -m ssrf --aggressive --exploit --callback-host your-server.com
```

### Obfuscation Categories

When using `--aggressive`, all 6 obfuscation categories are applied:

1. **Encoding** - URL, double/triple URL, unicode, hex, octal, HTML entities
2. **Case** - Random, alternating, inverse case mixing
3. **Whitespace** - Tab, newline, null byte, zero-width characters
4. **Comments** - SQL inline, multiline, version-specific comments
5. **Concatenation** - String concat, CHAR(), fromCharCode
6. **Splitting** - Keyword split, reverse, chunked

**Example Transformation:**
`<script>` becomes:
- `%3Cscript>` (URL encoding)
- `<ScRiPt>` (case mixing)
- `<script%09>` (whitespace)
- `<scr/**/ipt>` (comment injection)
- `'<'+'script>'+'</script>'` (concatenation)

### Advanced Bypass Strategies

**Multi-Layer Bypass**
```bash
lantern -t https://target.com -m waf,sqli,xss,cmdi --aggressive --deep --exploit
```

**Bypass + Exploitation**
```bash
lantern -t https://target.com -m waf,sqli --aggressive --exploit --deep
```

**Bypass + Multiple Injection Types**
```bash
lantern -t https://target.com -m waf,sqli,xss,cmdi,ssti,xxe,lfi --aggressive --exploit
```

**Bypass + Auth Testing**
```bash
lantern -t https://target.com -m waf,auth,jwt,oauth,mfa --aggressive --exploit
```

### Learned Payloads

Successful mutations are automatically saved and reused. On future scans, learned payloads are tested first, then new mutations are attempted. Your bypass arsenal grows with each scan.

**Using Learned Payloads**
```bash
# Learned payloads are automatically used
lantern -t https://target.com -m sqli,xss --aggressive --exploit --deep
```

---

## Advanced Techniques

### Stealth + Exploitation

**Avoid Detection While Exploiting**
```bash
lantern -t https://target.com -m sqli,xss,ssrf --stealth --exploit --deep --threads 10
```

**Stealth RCE Chain**
```bash
lantern -t https://target.com --chain rce --stealth --exploit --threads 15 --timeout 20
```

**Stealth Auth Bypass**
```bash
lantern -t https://target.com -m jwt,oauth,mfa --stealth --exploit --aggressive --threads 5
```

### Smart Detection + Custom Modules

**Tech-Based + Manual Selection**
```bash
lantern -t https://target.com --smart -m deserial,upload --exploit --crawl
```

**Smart Detection + Additional Modules**
```bash
lantern -t https://target.com --smart -m xxe,ldap,crlf --exploit --aggressive
```

**Tech Detect + Chain + Custom Modules**
```bash
lantern -t https://target.com --tech-detect --chain injection -m h2smuggle,cachepois --exploit
```

### Preset + Chain + Modules

**Layering Multiple Approaches**
```bash
lantern -t https://target.com --preset api --chain api_attack -m websocket,apiver --exploit
```

**Fast Preset + Injection Chain + Additional Modules**
```bash
lantern -t https://target.com --preset fast --chain injection -m deserial --exploit
```

**Thorough Preset + RCE Chain + Upload**
```bash
lantern -t https://target.com --preset thorough --chain rce -m upload --exploit --deep
```

### DNS Brute Force + Targeted Testing

**Subdomain Discovery + Immediate Testing**
```bash
lantern -t https://target.com --dns-brute --dns-concurrency 1000 \
  -m takeover,cloud,ssrf --exploit --crawl
```

**High-Speed DNS + Auth Testing**
```bash
lantern -t https://target.com --dns-brute --dns-concurrency 2000 \
  -m subdomain,auth,jwt,oauth --exploit
```

**DNS + API Testing**
```bash
lantern -t https://target.com --dns-brute -m subdomain,api,graphql,websocket --exploit
```

### Callback Host + Multiple Modules

**OOB Testing Across Vulnerability Types**
```bash
lantern -t https://target.com -m xss,ssrf,xxe --exploit \
  --callback-host your-server.com --aggressive --crawl
```

**Blind Injection Testing**
```bash
lantern -t https://target.com -m sqli,xss,ssrf,xxe --exploit \
  --callback-host your-server.com --deep
```

**XSS + SSRF + Cloud Extraction**
```bash
lantern -t https://target.com -m xss,ssrf,cloud --exploit \
  --callback-host your-server.com --aggressive
```

### Crawling + Specific Module Sets

**Deep Crawl + Injection Testing**
```bash
lantern -t https://target.com --crawl --crawl-depth 5 \
  -m sqli,xss,cmdi,ssti --exploit --aggressive
```

**Crawl + Auth Testing**
```bash
lantern -t https://target.com --crawl --crawl-depth 4 \
  -m auth,jwt,oauth,idor --exploit --aggressive
```

**Crawl + Parameter Discovery + Fuzzing**
```bash
lantern -t https://target.com --crawl --crawl-depth 3 \
  -m paramfind,fuzz,sqli,xss --aggressive
```

### Performance Tuning

**High-Performance Injection Testing**
```bash
lantern -t https://target.com -m sqli,xss,cmdi,ssti --exploit \
  --threads 200 --timeout 5 --cache --cache-ttl 300
```

**Slow Target + Race Condition Testing**
```bash
lantern -t https://target.com -m race,payment,account --exploit \
  --threads 300 --timeout 30 --stealth
```

**Cached Reconnaissance**
```bash
lantern -t https://target.com -m dirbust,disclosure,secrets \
  --cache --cache-ttl 600 --threads 150
```

### Scope Management

**Scoped Injection Testing**
```bash
lantern -t urls.txt --include-domain api.target.com \
  -m sqli,xss,ssrf --exploit --aggressive
```

**Exclude Static + Test Dynamic**
```bash
lantern -t https://target.com --exclude-pattern "/static/" \
  --exclude-pattern "/assets/" -m sqli,xss,cmdi,ssti --exploit
```

**Multi-Domain Auth Testing**
```bash
lantern -t urls.txt --include-domain target.com \
  --include-domain api.target.com -m auth,jwt,oauth,mfa --exploit
```

### Proxy + Testing Scenarios

**Proxy + Injection Testing**
```bash
lantern -t https://target.com --proxy http://127.0.0.1:8080 \
  -m sqli,xss,cmdi --exploit --verbose --aggressive
```

**Proxy + Auth Testing**
```bash
lantern -t https://target.com --proxy http://127.0.0.1:8080 \
  -m jwt,oauth,mfa --exploit --verbose
```

**Proxy + API Testing**
```bash
lantern -t https://api.target.com --proxy http://127.0.0.1:8080 \
  -m api,graphql,websocket --exploit -v
```

### Authenticated Testing

**Authenticated Deep Injection Testing**
```bash
lantern -t https://target.com -H "Authorization: Bearer TOKEN" \
  -c "session=abc123" -m sqli,xss,cmdi,ssti --exploit --deep --aggressive
```

**Authenticated API Testing**
```bash
lantern -t https://api.target.com -H "Authorization: Bearer TOKEN" \
  -m api,graphql,idor,massassign --exploit --aggressive
```

**Authenticated Auth Testing**
```bash
lantern -t https://target.com -H "Authorization: Bearer TOKEN" \
  -m jwt,oauth,session,cookie --exploit --deep
```

### CI/CD Integration

**CI/CD with Specific Modules**
```bash
lantern -t https://staging.target.com --ci --fail-on HIGH \
  -m sqli,xss,ssrf,cmdi --exploit --preset fast --no-banner
```

**CI/CD API Security**
```bash
lantern -t https://api.target.com --ci --fail-on MEDIUM \
  -m api,graphql,idor,jwt --sarif api_scan.sarif --no-banner
```

**Complete CI/CD Setup**
```bash
lantern -t https://staging.target.com --ci --fail-on HIGH \
  --sarif results.sarif --junit results.xml -o ci_scan \
  --preset fast --no-banner --cache --cache-ttl 600
```

### Multi-Stage Approaches

**Stage 1: Recon → Stage 2: Targeted Testing**
```bash
# Stage 1: Discover everything
lantern -t https://target.com -m techdetect,fingerprint,dirbust,paramfind \
  --crawl --crawl-depth 5 -o stage1_recon

# Stage 2: Test based on findings
lantern -t https://target.com -m sqli,xss,cmdi --exploit --aggressive \
  --cache -o stage2_injection
```

**Smart Detection → Custom Modules → Exploitation**
```bash
lantern -t https://target.com --smart -m deserial,upload,h2smuggle \
  --exploit --deep --aggressive
```

**DNS Discovery → Subdomain Testing → Main Domain**
```bash
# Discover subdomains
lantern -t https://target.com --dns-brute --dns-concurrency 1000 \
  -m subdomain,takeover -o subdomains

# Test discovered subdomains
lantern -t discovered_subdomains.txt -m sqli,xss,ssrf --exploit

# Test main domain
lantern -t https://target.com -m sqli,xss,ssrf --exploit --deep
```

### Unusual but Effective Combinations

**WAF Detection + Bypass + Exploitation**
```bash
lantern -t https://target.com -m waf,sqli,xss,cmdi \
  --aggressive --exploit --deep
```

**Parameter Discovery + Immediate Fuzzing**
```bash
lantern -t https://target.com -m paramfind,fuzz,sqli,xss,cmdi \
  --aggressive --crawl
```

**Secrets + Disclosure + Cloud**
```bash
lantern -t https://target.com -m secrets,disclosure,cloud,ssrf \
  --exploit --aggressive --crawl
```

**Race Conditions + Payment + Account**
```bash
lantern -t https://target.com -m race,payment,account,captcha \
  --exploit --threads 300 --aggressive
```

**Cache Poisoning + Smuggling + Headers**
```bash
lantern -t https://target.com -m cachepois,smuggle,h2smuggle,headers \
  --exploit --aggressive
```

---

## Module Reference

Quick reference for module combinations:

### Injection Modules

| Module | Common Combinations |
|--------|---------------------|
| `sqli` | `sqli,xss,cmdi` or `waf,sqli` |
| `xss` | `xss,dom,prototype,csp` |
| `cmdi` | `cmdi,upload,ssti` |
| `ssti` | `ssti,deserial` |
| `xxe` | `xxe,ssrf,lfi` |
| `lfi` | `lfi,xxe,download` |
| `crlf` | `crlf,hpp` |
| `hpp` | `hpp,crlf,paramfind` |
| `ldap` | `ldap,sqli,auth` |
| `fuzz` | `fuzz,paramfind` |
| `deserial` | `deserial,ssti,cmdi` |
| `smuggle` | `smuggle,h2smuggle` |
| `h2smuggle` | `h2smuggle,smuggle` |

### Authentication & Authorization

| Module | Common Combinations |
|--------|---------------------|
| `auth` | `auth,jwt,oauth,mfa` |
| `jwt` | `jwt,session,cookie` |
| `oauth` | `oauth,mfa,auth` |
| `mfa` | `mfa,oauth,auth` |
| `session` | `session,cookie,csrf` |
| `cookie` | `cookie,session,csrf` |
| `csrf` | `csrf,clickjack,cors` |
| `idor` | `idor,massassign,auth` |
| `massassign` | `massassign,idor,api` |
| `cors` | `cors,clickjack,csrf` |
| `redirect` | `redirect,ssrf` |
| `clickjack` | `clickjack,cors,csrf` |
| `upload` | `upload,cmdi` |

### API Modules

| Module | Common Combinations |
|--------|---------------------|
| `api` | `api,graphql,websocket,jwt` |
| `graphql` | `graphql,api,idor` |
| `websocket` | `websocket,api,jwt` |
| `apiver` | `apiver,api` |

### Reconnaissance

| Module | Common Combinations |
|--------|---------------------|
| `fingerprint` | `fingerprint,techdetect` |
| `disclosure` | `disclosure,secrets,dirbust` |
| `secrets` | `secrets,disclosure,dirbust` |
| `subdomain` | `subdomain,takeover,cloud` |
| `techdetect` | `techdetect,fingerprint` |
| `dork` | `dork,disclosure,secrets` |
| `cve` | `cve,disclosure` |
| `dirbust` | `dirbust,disclosure,secrets` |
| `paramfind` | `paramfind,fuzz` |
| `takeover` | `takeover,subdomain` |
| `cloud` | `cloud,ssrf,secrets` |
| `waf` | `waf,sqli,xss` |

### Configuration & Headers

| Module | Common Combinations |
|--------|---------------------|
| `headers` | `headers,ssl,csp` |
| `ssl` | `ssl,headers` |
| `cache` | `cache,cachepois` |
| `cachepois` | `cachepois,cache` |
| `download` | `download,lfi,xxe` |
| `ssrf` | `ssrf,cloud,xxe` |
| `csp` | `csp,xss,dom` |

### Client-Side & DOM

| Module | Common Combinations |
|--------|---------------------|
| `dom` | `dom,xss,prototype` |
| `prototype` | `prototype,dom,xss` |

### Business Logic

| Module | Common Combinations |
|--------|---------------------|
| `payment` | `payment,race,captcha` |
| `race` | `race,account,payment` |
| `captcha` | `captcha,account,payment` |
| `account` | `account,race,captcha` |

---

## Quick Reference

### Essential Command Patterns

**Quick Scan**
```bash
lantern -t https://target.com --fast
```

**Comprehensive Scan**
```bash
lantern -t https://target.com --preset thorough --exploit
```

**API Testing**
```bash
lantern -t https://api.target.com --preset api --exploit
```

**Stealth Reconnaissance**
```bash
lantern -t https://target.com --preset stealth --chain enum
```

**Injection Testing**
```bash
lantern -t https://target.com -m sqli,xss,cmdi,ssti --exploit --aggressive
```

**Authentication Testing**
```bash
lantern -t https://target.com -m auth,jwt,oauth,mfa --exploit --aggressive
```

**RCE Testing**
```bash
lantern -t https://target.com -m cmdi,ssti,deserial,upload --exploit --deep
```

**Data Extraction**
```bash
lantern -t https://target.com -m ssrf,lfi,xxe,secrets --exploit --aggressive
```

### Module Quick Lists

**Injection**: `sqli`, `xss`, `cmdi`, `ssti`, `lfi`, `xxe`, `crlf`, `hpp`, `ldap`, `deserial`, `smuggle`, `h2smuggle`

**Auth**: `auth`, `jwt`, `oauth`, `mfa`, `session`, `cookie`, `csrf`, `idor`, `massassign`

**API**: `api`, `graphql`, `websocket`, `apiver`

**Recon**: `fingerprint`, `disclosure`, `secrets`, `subdomain`, `techdetect`, `dirbust`, `paramfind`, `takeover`, `cloud`, `waf`, `dork`, `cve`

**Client**: `dom`, `prototype`, `cors`, `clickjack`, `csp`

**Config**: `headers`, `ssl`, `cache`, `cachepois`, `download`, `ssrf`

**Business**: `payment`, `race`, `captcha`, `account`

### Common Flag Combinations

**Deep + Aggressive + Exploit**
```bash
--deep --aggressive --exploit
```

**Stealth + Deep**
```bash
--stealth --deep --threads 10
```

**Crawl + Deep + Exploit**
```bash
--crawl --crawl-depth 5 --deep --exploit
```

**Smart + Exploit + Crawl**
```bash
--smart --exploit --crawl
```

**Preset + Custom Modules**
```bash
--preset fast -m sqli,xss --aggressive
```

**Chain + Additional Modules**
```bash
--chain injection -m deserial,upload --exploit
```

### Best Practices

1. **Start with reconnaissance**: Use `techdetect`, `fingerprint`, and `disclosure` to understand the target
2. **Match modules to technology**: Use `--smart` for automatic selection based on detected tech
3. **Combine related modules**: Group similar vulnerabilities together
4. **Use presets as starting points**: Modify presets with additional modules
5. **Always use `--aggressive` for WAF-protected targets**: Enables mutations and obfuscation
6. **Combine `--aggressive` + `--deep` for maximum coverage**: Maximum mutation attempts
7. **Use `--callback-host` for blind vulnerabilities**: XSS, SSRF, XXE benefit from OOB testing
8. **Cache for repeated scans**: Use `--cache` to speed up multiple scan rounds
9. **Adjust threads based on target**: High threads for fast targets, low for rate-limited
10. **Use `--stealth` for rate-limited targets**: Slower but avoids detection

---

*For authorized testing only. You are responsible for ensuring you have proper authorization before testing any target.*
