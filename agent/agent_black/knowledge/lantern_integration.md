# LANTERN Integration Guide

How I interact with LANTERN to perform scans and analyze results.

---

## Running LANTERN Scans

### Basic Scan Execution

```python
def run_lantern_scan(target, modules=None, preset=None):
    lantern_path = Path("external/core/cli.py")
    
    if preset:
        cmd = f"python -m core.cli -t {target} --preset {preset}"
    elif modules:
        cmd = f"python -m core.cli -t {target} -m {','.join(modules)}"
    else:
        cmd = f"python -m core.cli -t {target} -m fingerprint,headers,ssl"
    
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return parse_result(result)
```

### Command Construction

| Request Type | Command |
|--------------|---------|
| Quick scan | `lantern -t URL -m fingerprint,headers` |
| Full scan | `lantern -t URL --preset thorough` |
| Specific vuln | `lantern -t URL -m sqli,xss` |
| With crawling | `lantern -t URL --crawl --crawl-depth 3` |
| Aggressive | `lantern -t URL --aggressive --deep` |
| Exploit mode | `lantern -t URL --preset exploit --chain` |

---

## LANTERN Modules I Can Use

### Reconnaissance Modules

| Module | Purpose |
|--------|---------|
| `fingerprint` | Technology detection |
| `techdetect` | Framework identification |
| `dirbust` | Directory enumeration |
| `subdomain` | Subdomain discovery |
| `paramfind` | Hidden parameter discovery |
| `dns_brute` | DNS brute forcing |
| `dork` | Google dork queries |

### Vulnerability Modules

| Module | Vulnerability Type |
|--------|-------------------|
| `sqli` | SQL Injection |
| `xss` | Cross-Site Scripting |
| `dom` | DOM-based XSS |
| `lfi` | Local File Inclusion |
| `ssrf` | Server-Side Request Forgery |
| `ssti` | Template Injection |
| `cmdi` | Command Injection |
| `xxe` | XML External Entity |
| `deserial` | Insecure Deserialization |
| `upload` | File Upload |
| `idor` | Insecure Direct Object Reference |

### Authentication Modules

| Module | Target |
|--------|--------|
| `auth` | Authentication bypass |
| `jwt` | JWT vulnerabilities |
| `oauth` | OAuth/OIDC issues |
| `mfa` | MFA bypass |
| `session` | Session management |
| `cookie` | Cookie security |

### Infrastructure Modules

| Module | Function |
|--------|----------|
| `headers` | Security header analysis |
| `ssl` | TLS/SSL configuration |
| `cors` | CORS misconfiguration |
| `csp` | Content Security Policy |
| `waf` | WAF detection |
| `cloud` | Cloud misconfiguration |
| `takeover` | Subdomain takeover |

### Advanced Modules

| Module | Attack Type |
|--------|-------------|
| `graphql` | GraphQL introspection/injection |
| `smuggle` | HTTP request smuggling |
| `h2smuggle` | HTTP/2 smuggling |
| `cachepois` | Cache poisoning |
| `race` | Race conditions |
| `prototype` | Prototype pollution |
| `websocket` | WebSocket security |

---

## LANTERN Presets

Presets are predefined module combinations.

### fast.yml
```yaml
modules: [fingerprint, headers, ssl, cors, secrets]
options:
  timeout: 5
  threads: 20
```

### thorough.yml
```yaml
modules: [ALL reconnaissance + ALL vulnerability modules]
options:
  crawl: true
  crawl_depth: 3
  aggressive: true
```

### stealth.yml
```yaml
modules: [fingerprint, headers, ssl]
options:
  delay: 2
  threads: 3
  random_ua: true
```

### exploit.yml
```yaml
modules: [sqli, xss, ssti, cmdi, lfi, ssrf, xxe]
options:
  aggressive: true
  chain: true
  exploit: true
```

### api.yml
```yaml
modules: [api, graphql, jwt, idor, massassign, auth]
options:
  api_mode: true
```

---

## LANTERN Flags I Use

### Scan Control

| Flag | Purpose |
|------|---------|
| `-t, --target` | Target URL |
| `-m, --modules` | Comma-separated module list |
| `--preset` | Use predefined preset |
| `--chain` | Execute attack chains |

### Behavior Flags

| Flag | Effect |
|------|--------|
| `--crawl` | Enable URL crawling |
| `--crawl-depth N` | Crawl depth (default 2) |
| `--aggressive` | More payloads, faster |
| `--deep` | Thorough scanning |
| `--exploit` | Enable exploitation |

### Performance Flags

| Flag | Effect |
|------|--------|
| `--threads N` | Concurrent threads |
| `--timeout N` | Request timeout |
| `--delay N` | Delay between requests |
| `--rate N` | Requests per second |

### Output Flags

| Flag | Effect |
|------|--------|
| `-o, --output` | Output file path |
| `--format` | json/html/md/sarif |
| `-v, --verbose` | Verbose output |
| `--no-color` | Disable colors |

---

## Parsing LANTERN Output

### JSON Report Structure

```json
{
  "scan_info": {
    "timestamp": "2026-01-29 10:00:00",
    "targets": ["https://target.com"],
    "modules": ["sqli", "xss"],
    "total_findings": 5
  },
  "executive_summary": {
    "risk_level": "HIGH",
    "summary": "...",
    "critical": 1,
    "high": 2
  },
  "findings": [
    {
      "module": "sqli",
      "severity": "CRITICAL",
      "confidence": "CONFIRMED",
      "url": "https://target.com/search?q=test",
      "parameter": "q",
      "description": "SQL Injection detected",
      "evidence": "mysql error in response",
      "cvss": {"score": 9.8, "vector": "..."},
      "remediation": {...},
      "poc_data": {...}
    }
  ]
}
```

### Extracting Key Data

```python
def analyze_lantern_results(json_report):
    findings = json_report.get("findings", [])
    
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    
    vuln_modules = list(set(f["module"] for f in findings))
    
    risk_score = critical_count * 10 + high_count * 5
    
    return {
        "total": len(findings),
        "critical": critical_count,
        "high": high_count,
        "risk_score": risk_score,
        "vulnerable_modules": vuln_modules
    }
```

---

## Smart Probe vs LANTERN

When LANTERN doesn't find something, I do my own probing.

### Smart Probe Pipeline

```
1. LANTERN scan completes → findings collected
2. I analyze what was tested vs what could be tested
3. Smart Probe tests endpoints LANTERN missed
4. If I find something LANTERN missed:
   → Log the finding
   → Record the payload that worked
   → Generate improvement suggestion for LANTERN
   → Save patch to lantern_patches/
```

### Improvement Generation

```python
def generate_improvement(finding):
    if finding.type == "sqli":
        return f"""
# Add to modules/sqli.py:
AGENT_BLACK_PAYLOADS = [
    "{finding.payload}",
]

AGENT_BLACK_PATTERNS = [
    r"{finding.indicator}",
]
"""
```

---

## LANTERN Attack Chains

Pre-built sequences of modules for specific goals.

### auth_bypass Chain
```
waf → sqli → ldap → auth → jwt → oauth → mfa → session
```
Purpose: Find any way to bypass authentication

### data_theft Chain
```
waf → sqli → ssrf → lfi → xxe → idor → disclosure → dirbust → cloud
```
Purpose: Extract sensitive data from target

### rce Chain
```
waf → cmdi → ssti → deserial → upload → ssrf
```
Purpose: Achieve remote code execution

### injection Chain
```
waf → paramfind → sqli → xss → ssti → cmdi → lfi → xxe → crlf
```
Purpose: Test all injection types on all parameters

---

## Calling LANTERN Programmatically

### From Agent Black

```python
class AgentBlack:
    def run_lantern_scan(self, target, modules=None, preset=None):
        lantern_path = Path(__file__).parent.parent / "external"
        cli_script = lantern_path / "core" / "cli.py"
        
        if preset:
            cmd = f"cd /d \"{lantern_path}\" && python -m core.cli -t {target} --preset {preset}"
        elif modules:
            cmd = f"cd /d \"{lantern_path}\" && python -m core.cli -t {target} -m {','.join(modules)}"
        else:
            cmd = f"cd /d \"{lantern_path}\" && python -m core.cli -t {target} -m fingerprint,headers,ssl"
        
        result = self.execute_command(cmd, timeout=300)
        return result
```

### Direct Python Import

```python
from core.engine import Scanner
from core.scope import ScopeManager

scope = ScopeManager()
scope.add_target("https://target.com")

scanner = Scanner(
    targets=["https://target.com"],
    modules=["sqli", "xss"],
    config={"aggressive": True}
)

results = await scanner.run()
```

---

## LANTERN Output Processing

### Result Recording for Learning

```python
def record_scan_result(target, modules_used, findings, flags_found, successful_exploits, tech_detected):
    profile = get_or_create_profile(target)
    
    profile["scan_count"] += 1
    profile["tech_stack"].extend(tech_detected)
    
    for sev, count in findings.items():
        if count > profile["total_findings"].get(sev, 0):
            profile["total_findings"][sev] = count
    
    for flag in flags_found:
        if flag not in profile["flags_captured"]:
            profile["flags_captured"].append(flag)
    
    for exploit in successful_exploits:
        if exploit["module"] not in profile["vulnerable_modules"]:
            profile["vulnerable_modules"].append(exploit["module"])
        if exploit["payload"] not in profile["working_payloads"]:
            profile["working_payloads"].append(exploit["payload"])
    
    save_profile(profile)
```

### Module Effectiveness Tracking

```python
def record_module_effectiveness(modules_used, findings, successful_exploits):
    total_score = (
        findings.get("CRITICAL", 0) * 100 +
        findings.get("HIGH", 0) * 50 +
        findings.get("MEDIUM", 0) * 20 +
        findings.get("LOW", 0) * 5
    )
    
    for module in modules_used:
        effectiveness[module]["times_used"] += 1
        effectiveness[module]["total_score"] += total_score / len(modules_used)
        
        if module in exploit_modules:
            effectiveness[module]["exploit_success"] += 1
```

This data directly influences future module selection decisions.

---

## Post-Scan Validation

After every LANTERN scan, I validate findings before reporting.

### Automatic Validation Flow

```
LANTERN Scan
    ↓
Parse JSON Report
    ↓
validate_findings()
    ↓
├── Confirmed findings → Report immediately
├── False positives → Filter out
└── Needs review → Flag for manual check
    ↓
Final Report with Validation Stats
```

### My run_lantern_scan() Method

```python
def run_lantern_scan(target, modules=None, preset=None, extra_args=None, timeout=300):
    cmd = ["lantern", "-t", target]
    
    if modules:
        cmd.extend(["-m", ",".join(modules)])
    if preset:
        cmd.extend(["--preset", preset])
    if extra_args:
        cmd.extend(extra_args)
    
    cmd.append("--analyze-js")
    cmd.append("--quiet")
    cmd.extend(["-o", f"scan_{sanitize(target)}"])
    
    result = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='replace')
    
    return {
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": " ".join(cmd)
    }
```

### Chat Mode Integration

When user types "scan http://target.com with sqli, xss", I:

1. Parse URL and modules from natural language
2. Calculate appropriate timeout (base + crawl + modules)
3. Execute LANTERN with `--quiet` mode
4. Load JSON report
5. Call `validate_findings()` on all findings
6. Show validation summary
7. Report only confirmed/high-confidence findings

### Timeout Calculation

```python
timeout = 300  # base 5 minutes

if "crawl" in request:
    timeout += 600  # +10 min for crawling
if "deep" or "thorough" in request:
    timeout += 300  # +5 min for deep mode
if len(modules) > 5:
    timeout += len(modules) * 60  # +1 min per extra module
```

### The --quiet Flag

When running as subprocess, LANTERN uses `--quiet` mode:
- Disables Rich Live display (no terminal refresh spam)
- Shows progress at 10% intervals
- Prints findings as discovered
- Compatible with non-TTY environments

---

## Chat Commands for LANTERN

| User Says | I Execute |
|-----------|-----------|
| "scan target.com" | `lantern -t target.com -m sqli,xss,secrets,headers` |
| "scan with all modules" | `lantern -t URL -m sqli,xss,ssrf,lfi,secrets,headers,cors,auth` |
| "scan and crawl" | `lantern -t URL --crawl -m ...` |
| "deep scan" | `lantern -t URL --deep -m ...` |
| "aggressive scan" | `lantern -t URL --aggressive --exploit -m ...` |

I always add `--analyze-js` automatically for JavaScript analysis.
