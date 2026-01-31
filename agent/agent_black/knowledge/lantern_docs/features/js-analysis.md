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
| **DOM Sinks** | innerHTML, eval, document.write, location assignment |
| **Frameworks** | React, Angular, Vue, jQuery, etc. |
| **Source Maps** | Exposed .map files |

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
