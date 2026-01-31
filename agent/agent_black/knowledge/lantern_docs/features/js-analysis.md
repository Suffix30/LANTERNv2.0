[← Back to Index](../INDEX.md)

# JavaScript Analysis

Deep analysis of JavaScript files for security issues.

---

## Basic Analysis

**Analyze JavaScript files:**
```bash
lantern -t https://target.com --analyze-js
```

**JS analysis + XSS testing:**
```bash
lantern -t https://target.com --analyze-js -m xss,dom,prototype --exploit
```

**JS analysis + API testing:**
```bash
lantern -t https://target.com --analyze-js -m api,graphql,idor --crawl
```

---

## What JS Analysis Detects

| Category | Detection |
|----------|-----------|
| **Endpoints** | fetch(), axios, XHR, WebSocket, GraphQL URLs |
| **Secrets** | API keys, tokens, passwords, AWS keys, JWTs |
| **BaaS Credentials** | Supabase, Firebase, Appwrite, PocketBase, AWS Amplify keys |
| **DOM Sinks** | innerHTML, eval, document.write, location assignment |
| **Frameworks** | React, Angular, Vue, jQuery, etc. |
| **Source Maps** | Exposed .map files |

---

## Backend-as-a-Service (BaaS) Detection

LANTERN automatically detects and validates exposed backend credentials:

| Provider | Detection | Validation |
|----------|-----------|------------|
| **Supabase** | Project URL + JWT keys | Tests REST API access, enumerates tables |
| **Firebase** | API keys + auth domain | Detects misconfigured rules |
| **Appwrite** | Project URL + endpoints | Checks API accessibility |
| **PocketBase** | Client initialization | Tests admin access |
| **AWS Amplify** | AppSync + Cognito configs | Checks GraphQL access |

**Exploitation Process:**
1. Detect credentials in JS (Supabase URL + JWT patterns)
2. Validate API access
3. Enumerate tables (probes 40+ common names)
4. Dump accessible data (first 10 rows per table)
5. Analyze for sensitive fields (password, email, ssn, credit_card, etc.)
6. Detect sensitive values (JWTs, hashes, credit cards, phone numbers)
7. Log all exploitation attempts for report

**Example finding:**
```
CRITICAL: Exposed SUPABASE credentials - 5 TABLES ACCESSIBLE [12 sensitive fields]
(847 rows dumped) [!!! 23 SENSITIVE VALUES EXTRACTED]
URL: https://abc123.supabase.co
Tables: users, accounts, payments, sessions, logs
Sensitive: users.password, users.email, payments.card_number

Exploitation Log:
[*] Testing Supabase REST API access...
[+] REST API accessible!
[*] Enumerating tables via common names...
[+] TABLE FOUND: users (156 rows, 12 columns)
    Columns: id, email, password_hash, created_at...
    [!] SENSITIVE COLUMN: password_hash
    [!] SENSITIVE COLUMN: email
    [!!!] BCRYPT_HASH FOUND in password_hash
    [!!!] EMAIL FOUND in email
[+] TABLE FOUND: payments (691 rows, 8 columns)
    [!!!] CREDIT_CARD FOUND in card_number
```

**Agent Black Integration:**
When I find BaaS credentials during scanning:
1. I automatically attempt full exploitation
2. I analyze what data is accessible
3. I categorize sensitive information by severity
4. I suggest remediation (enable RLS, rotate keys)
5. I can recommend module improvements based on what bypass techniques worked

---

## Combined Analysis Patterns

**Full client-side analysis:**
```bash
lantern -t https://target.com --analyze-js -m xss,dom,prototype,csp --exploit --crawl
```

**JS secrets + cloud testing:**
```bash
lantern -t https://target.com --analyze-js -m secrets,cloud,ssrf --exploit
```

**JavaScript security audit:**
```bash
lantern -t https://target.com --analyze-js -m xss,dom,prototype,secrets --exploit --crawl
```

---

[← Back to Index](../INDEX.md)
