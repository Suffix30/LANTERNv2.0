[← Back to Index](../INDEX.md)

# Configuration & Headers Modules

Command examples for testing security headers, SSL/TLS, and caching.

---

## Security Headers & SSL

```bash
lantern -t https://target.com -m headers,ssl,csp,clickjack --fast
```

## WAF Detection & Bypass

```bash
lantern -t https://target.com -m waf,sqli,xss --aggressive
```

## Complete Config Testing

```bash
lantern -t https://target.com -m headers,ssl,cache,cachepois,csp,redirect,cdn --fast
```

## CDN, Broken Links, Embeds

```bash
lantern -t https://target.com -m cdn,brokenlinks,embed --crawl
```

---

## Module Reference

| Module | Common Combinations |
|--------|---------------------|
| `headers` | `headers,ssl,csp` |
| `ssl` | `ssl,headers` |
| `cache` | `cache,cachepois` |
| `cachepois` | `cachepois,cache` |
| `download` | `download,lfi,xxe` |
| `ssrf` | `ssrf,cloud,xxe` |
| `csp` | `csp,xss,dom` |
| `cdn` | `cdn,headers,waf` |

---

[← Back to Index](../INDEX.md) | [Next: Business Logic →](business.md)
