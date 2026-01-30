[← Back to Index](../INDEX.md)

# Advanced Techniques

Stealth mode, proxy usage, CI/CD integration, and multi-stage approaches.

---

## Stealth + Exploitation

**Avoid Detection While Exploiting**
```bash
lantern -t https://target.com -m sqli,xss,ssrf --stealth --exploit --deep --threads 10
```

**Stealth RCE Chain**
```bash
lantern -t https://target.com --chain rce --stealth --exploit --threads 15 --timeout 20
```

**Stealth Auth Bypass**
```bash
lantern -t https://target.com -m jwt,oauth,mfa --stealth --exploit --aggressive --threads 5
```

---

## Smart Detection + Custom Modules

**Tech-Based + Manual Selection**
```bash
lantern -t https://target.com --smart -m deserial,upload --exploit --crawl
```

**Smart Detection + Additional Modules**
```bash
lantern -t https://target.com --smart -m xxe,ldap,crlf --exploit --aggressive
```

**Tech Detect + Chain + Custom Modules**
```bash
lantern -t https://target.com --tech-detect --chain injection -m h2smuggle,cachepois --exploit
```

---

## Preset + Chain + Modules

**Layering Multiple Approaches**
```bash
lantern -t https://target.com --preset api --chain api_attack -m websocket,apiver --exploit
```

**Fast Preset + Injection Chain + Additional Modules**
```bash
lantern -t https://target.com --preset fast --chain injection -m deserial --exploit
```

**Thorough Preset + RCE Chain + Upload**
```bash
lantern -t https://target.com --preset thorough --chain rce -m upload --exploit --deep
```

---

## DNS Brute Force + Targeted Testing

**Subdomain Discovery + Immediate Testing**
```bash
lantern -t https://target.com --dns-brute --dns-concurrency 1000 \
  -m takeover,cloud,ssrf --exploit --crawl
```

**High-Speed DNS + Auth Testing**
```bash
lantern -t https://target.com --dns-brute --dns-concurrency 2000 \
  -m subdomain,auth,jwt,oauth --exploit
```

---

## Proxy + Testing Scenarios

**Proxy + Injection Testing**
```bash
lantern -t https://target.com --proxy http://127.0.0.1:8080 \
  -m sqli,xss,cmdi --exploit --verbose --aggressive
```

**Proxy + Auth Testing**
```bash
lantern -t https://target.com --proxy http://127.0.0.1:8080 \
  -m jwt,oauth,mfa --exploit --verbose
```

**Proxy + API Testing**
```bash
lantern -t https://api.target.com --proxy http://127.0.0.1:8080 \
  -m api,graphql,websocket --exploit -v
```

---

## Authenticated Testing

**Authenticated Deep Injection Testing**
```bash
lantern -t https://target.com -H "Authorization: Bearer TOKEN" \
  -c "session=abc123" -m sqli,xss,cmdi,ssti --exploit --deep --aggressive
```

**Authenticated API Testing**
```bash
lantern -t https://api.target.com -H "Authorization: Bearer TOKEN" \
  -m api,graphql,idor,massassign --exploit --aggressive
```

---

## CI/CD Integration

**CI/CD with Specific Modules**
```bash
lantern -t https://staging.target.com --ci --fail-on HIGH \
  -m sqli,xss,ssrf,cmdi --exploit --preset fast --no-banner
```

**CI/CD API Security**
```bash
lantern -t https://api.target.com --ci --fail-on MEDIUM \
  -m api,graphql,idor,jwt --sarif api_scan.sarif --no-banner
```

**Complete CI/CD Setup**
```bash
lantern -t https://staging.target.com --ci --fail-on HIGH \
  --sarif results.sarif --junit results.xml -o ci_scan \
  --preset fast --no-banner --cache --cache-ttl 600
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities above threshold |
| `1` | Vulnerabilities found at or above fail-on severity |
| `2` | Vulnerability count threshold exceeded |
| `3` | Scan error |
| `4` | Configuration error |

### GitHub Actions Example

```yaml
- name: Security Scan
  run: |
    lantern -t ${{ env.TARGET }} --ci --sarif results.sarif --fail-on HIGH
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Scope Management

**Scoped Injection Testing**
```bash
lantern -t urls.txt --include-domain api.target.com \
  -m sqli,xss,ssrf --exploit --aggressive
```

**Exclude Static + Test Dynamic**
```bash
lantern -t https://target.com --exclude-pattern "/static/" \
  --exclude-pattern "/assets/" -m sqli,xss,cmdi,ssti --exploit
```

**Multi-Domain Auth Testing**
```bash
lantern -t urls.txt --include-domain target.com \
  --include-domain api.target.com -m auth,jwt,oauth,mfa --exploit
```

---

## Multi-Stage Approaches

**Stage 1: Recon → Stage 2: Targeted Testing**
```bash
lantern -t https://target.com -m techdetect,fingerprint,dirbust,paramfind \
  --crawl --crawl-depth 5 -o stage1_recon

lantern -t https://target.com -m sqli,xss,cmdi --exploit --aggressive \
  --cache -o stage2_injection
```

**DNS Discovery → Subdomain Testing → Main Domain**
```bash
lantern -t https://target.com --dns-brute --dns-concurrency 1000 \
  -m subdomain,takeover -o subdomains

lantern -t discovered_subdomains.txt -m sqli,xss,ssrf --exploit

lantern -t https://target.com -m sqli,xss,ssrf --exploit --deep
```

---

## Performance Tuning

**High-Performance Injection Testing**
```bash
lantern -t https://target.com -m sqli,xss,cmdi,ssti --exploit \
  --threads 200 --timeout 5 --cache --cache-ttl 300
```

**Slow Target + Race Condition Testing**
```bash
lantern -t https://target.com -m race,payment,account --exploit \
  --threads 300 --timeout 30 --stealth
```

---

[← Back to Index](../INDEX.md)
