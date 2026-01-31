# LANTERN Core Systems Reference

Complete technical reference for all 25 LANTERN core systems.

## Engine Systems

### engine.py - Scan Orchestration
Coordinates all modules, manages concurrency, handles results.
```
- Loads modules dynamically
- Manages thread pools (default 50)
- Aggregates findings
- Handles graceful shutdown
```

### cli.py - Command Line Interface
Parses arguments, loads presets, starts scans.
```
--fast, --deep, --aggressive, --stealth, --smart
--preset fast/thorough/api/stealth/exploit
--chain rce/auth_bypass/data_theft/xss_chain
```

## HTTP Systems

### http.py - HTTP Client
Async HTTP client with advanced features.
```python
await http.get(url, headers={}, params={})
await http.post(url, json={}, data={}, headers={})
await http.timed_get(url)  # Returns elapsed time
inject_param(url, param, payload)  # URL injection helper
```

### bypass.py - WAF/Protection Bypass
Techniques to evade security controls.
```
- User-Agent rotation
- IP spoofing headers (X-Forwarded-For, X-Real-IP)
- Request rate throttling
- Payload encoding/obfuscation
```

## Intelligence Systems

### fuzzer.py - Smart Fuzzing Engine (537 lines)
**MutationEngine:**
- String mutations: case, truncation, duplication, encoding
- Number mutations: boundaries, negatives, overflow
- JSON mutations: key deletion, prototype pollution, type confusion

**Boundary Values:**
```python
"integer": [0, 1, -1, 127, 128, 255, 256, 32767, 65535, 2147483647, ...]
"string": ["", "null", "NULL", "undefined", "NaN", "[]", "{}", "\x00", ...]
"format_string": ["%s", "%n", "%x", "{}", "${}", "#{}"]
"path_traversal": ["../", "..%2f", "..%252f", "..%c0%af"]
"sql": ["'", "' OR '1'='1", "' UNION SELECT NULL--"]
"xss": ["<script>", "<img onerror=1>", "javascript:"]
"command": [";", "|", "&&", "$()", "`"]
"unicode": ["\u0000", "\ufeff", "\u202e"]
```

**IntelligentFuzzer:**
- Baseline establishment (5 samples)
- Anomaly detection (status, length, timing)
- Parameter-aware payload selection
- ReDoS pattern testing
- Differential testing (GET vs POST)

---

### differ.py - Response Comparison (623 lines)
**ReflectionContext Detection:**
- HTML_BODY, HTML_ATTRIBUTE, HTML_ATTRIBUTE_UNQUOTED
- JAVASCRIPT_STRING, JAVASCRIPT_CODE
- JSON_VALUE, JSON_KEY
- CSS_VALUE, HTML_COMMENT, SCRIPT_BLOCK

**DynamicContentStripper:**
Removes noise from responses for accurate comparison:
- CSRF tokens (13 patterns)
- Timestamps (5 patterns)
- Session tokens, nonces (7 patterns)
- Cache busters (5 patterns)
- Dynamic headers (date, etag, x-request-id, etc.)

**AdvancedResponseDiffer:**
```python
differ = create_differ(threshold=0.95)
differ.set_baseline("key", response)
result = differ.compare("key", new_response)
# Returns: similarity, length_diff, status_changed, body_changes

reflections = differ.find_reflection(response, payload, check_encodings=True)
# Returns: location, context, encoding, breakout_chars, exploitable

behavior = differ.detect_boolean_behavior(true_responses, false_responses)
# Returns: confidence, indicators, len_diff

anomaly = differ.detect_time_anomaly(responses, baseline_time, threshold=2.0)
# Returns: confidence, baseline, anomaly_times
```

---

### learned.py - Payload Learning System
Records successful payloads and prioritizes them.
```python
learned.record_success(payload, target, module, context)
learned.get_prioritized_payloads(module, tech_stack)
learned.save_to_file(path)
learned.load_from_file(path)
```

---

### confidence.py - Confidence Scoring
Evidence-based vulnerability confidence.
```
CONFIRMED (100%): Data extracted, code executed, file read
HIGH (80%): Error message with DB type, time delay matched
MEDIUM (60%): Response differences, suspicious patterns
LOW (40%): Possible indicators, needs verification
INFO (20%): Informational, no direct exploit
```

## Detection Systems

### tech_detect.py - Technology Fingerprinting
Identifies server technologies.
```
Frameworks: React, Angular, Vue, Django, Laravel, Rails, Express, Spring
CMS: WordPress, Drupal, Joomla, Magento, Shopify
Servers: Apache, Nginx, IIS, Tomcat, Node.js
Languages: PHP, Python, Java, .NET, Ruby
WAFs: Cloudflare, AWS WAF, Akamai, ModSecurity
```

### js_analyzer.py - JavaScript Analysis
Extracts security-relevant info from JS.
```
- API endpoints
- Secrets/hardcoded credentials
- DOM sinks (innerHTML, eval, document.write)
- Event handlers
- WebSocket URLs
- GraphQL queries
```

### cve_db.py - CVE Database
Known vulnerability signatures.
```
- Log4Shell (CVE-2021-44228)
- Spring4Shell (CVE-2022-22965)
- Text4Shell (CVE-2022-42889)
- Apache Struts (CVE-2017-5638)
- 50+ additional CVEs
```

## Scanning Systems

### crawler.py - Web Crawler
Discovers URLs and attack surface.
```python
crawler = Crawler(http, depth=3, scope=scope)
urls = await crawler.crawl(start_url)
# Extracts: links, forms, parameters, comments
```

### dns_brute.py - DNS Brute Force
High-speed subdomain enumeration.
```
- Concurrent DNS queries (default 500)
- Custom wordlists
- Wildcard detection
- Result deduplication
```

### scope.py - Scope Management
Controls what gets scanned.
```yaml
scope:
  include:
    - "*.target.com"
    - "api.target.com"
  exclude:
    - "logout"
    - "/static/"
    - "*.pdf"
```

## Authentication Systems

### auth.py - Basic Auth Handling
Session management and authentication.

### auth_manager.py - Multi-Role Auth
Manages multiple user sessions for IDOR/access control testing.
```python
auth_manager = await create_auth_manager(config, http)
session = await auth_manager.login("admin")
response = await auth_manager.request_as("user", "GET", url)
```

## Callback Systems

### oob.py - Out-of-Band Server
Built-in HTTP/DNS callback server.
```python
server = OOBServer(port=8888, dns_port=5353)
token = server.generate_token()
# Payloads use: http://callback.server/{token}
# DNS payloads: {token}.callback.server
interactions = server.check_interactions(token)
```

### callback.py - External Callbacks
Integration with external callback services.

## Reporting Systems

### reporter.py - Report Generation
Multiple output formats.
```
JSON:  Machine-readable, full details
HTML:  Human-readable with charts
Markdown: Documentation-friendly
SARIF: GitHub/GitLab security integration
JIRA CSV: Issue tracker import
JUnit XML: CI/CD pipeline integration
```

### poc.py - PoC Generator
Creates proof-of-concept scripts.
```
curl:   Command-line reproduction
Python: requests-based script
JavaScript: fetch-based script
```

## Workflow Systems

### workflow.py - Business Logic Engine
Executes multi-step attack workflows.
```yaml
name: payment_bypass
steps:
  - name: add_item
    request:
      method: POST
      url: /cart/add
      json: {item_id: 1}
    extract:
      cart_id: $.cart_id
  - name: checkout
    request:
      method: POST
      url: /checkout
      json: {cart_id: "${cart_id}", total: 0}
    expect:
      status: 200
```

## Integration Systems

### cicd.py - CI/CD Integration
Pipeline integration features.
```
Exit Codes:
  0 = No vulnerabilities above threshold
  1 = Vulnerabilities found at threshold
  2 = Count threshold exceeded
  3 = Scan error
  4 = Configuration error
```

### collab.py - Team Collaboration
Real-time finding sharing.
```
lantern --collab-server 0.0.0.0:8080
lantern --collab-client ws://team.local:8080
```

## Utility Systems

### utils.py - Common Utilities
Helper functions used throughout.
```python
extract_params(url)        # Parse URL parameters
random_string(length)      # Generate random strings
is_binary(content)         # Detect binary content
safe_json_loads(text)      # Safe JSON parsing
```

### cache.py - Response Caching
Reduces redundant requests.
```
--cache           # Enable caching
--cache-ttl 300   # TTL in seconds
```

## How Systems Work Together

**Scan Flow:**
1. `cli.py` parses args, loads preset
2. `tech_detect.py` fingerprints target
3. `engine.py` selects modules based on tech
4. `crawler.py` discovers attack surface
5. `http.py` sends requests through `bypass.py`
6. Modules use `fuzzer.py` for payloads
7. `differ.py` analyzes responses
8. `confidence.py` scores findings
9. `learned.py` records successes
10. `reporter.py` generates output

**Detection Flow:**
1. Module sends payload via `http.py`
2. `differ.py` compares to baseline
3. `fuzzer.py` mutates for bypass
4. `confidence.py` calculates score
5. If OOB needed, `oob.py` checks callbacks
6. `learned.py` updates successful payloads
