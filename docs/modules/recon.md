[← Back to Index](../INDEX.md)

# Reconnaissance

LANTERN's recon modules don't just find information - they identify attack vectors and prioritize targets.

---

## Technology Fingerprinting

### What Gets Detected

| Category | Technologies |
|----------|--------------|
| **Web Servers** | Apache, Nginx, IIS, Tomcat, Jetty |
| **Languages** | PHP, ASP.NET, Java, Python, Ruby, Node.js |
| **Frameworks** | Laravel, Django, Rails, Spring, Express, React, Angular, Vue |
| **CMS** | WordPress, Drupal, Joomla, Magento, Shopify |
| **Databases** | MySQL, PostgreSQL, MongoDB, Redis |
| **CDN/WAF** | Cloudflare, Akamai, AWS, Sucuri |

### How It Works

1. **Response Headers** - `X-Powered-By`, `Server`, custom headers
2. **Cookies** - Framework-specific cookie names
3. **HTML Patterns** - Meta tags, comments, class names
4. **JavaScript** - Library signatures, global variables
5. **Error Messages** - Stack traces, version strings

### Smart Module Selection

With `--smart`, LANTERN uses fingerprints to select modules:

| Detected Tech | Modules Selected |
|---------------|------------------|
| PHP | lfi, ssti, deserial, upload |
| Java/Spring | ssti, deserial, xxe, log4shell |
| .NET | deserial, sqli (MSSQL payloads) |
| WordPress | cve (WP-specific), upload, sqli |
| GraphQL | graphql, idor |
| React/Angular | dom, prototype, xss |

```bash
lantern -t https://target.com --tech-detect
lantern -t https://target.com --smart --exploit
```

---

## Subdomain Discovery

### High-Speed DNS Brute Force

LANTERN's DNS module achieves 1000+ queries/second:

```bash
lantern -t https://target.com --dns-brute --dns-concurrency 1000
```

**Output:**
```
[DNS] Brute forcing target.com
  + api.target.com -> 10.0.0.1
  + staging.target.com -> 10.0.0.2
  + dev.target.com -> 10.0.0.3
  + admin.target.com -> 10.0.0.4

Results: 127 subdomains @ 1,234 req/s
```

### Subdomain Takeover Detection

LANTERN checks for dangling DNS:

| Service | Fingerprint | Risk |
|---------|-------------|------|
| **GitHub Pages** | `There isn't a GitHub Pages site here` | Takeover possible |
| **Heroku** | `No such app` | Takeover possible |
| **AWS S3** | `NoSuchBucket` | Takeover possible |
| **Azure** | `404 Web Site not found` | Takeover possible |
| **Shopify** | `Sorry, this shop is currently unavailable` | Takeover possible |

```bash
lantern -t https://target.com -m subdomain,takeover --dns-brute
```

---

## Directory & File Discovery

### What Gets Found

| Type | Examples |
|------|----------|
| **Backup Files** | `.bak`, `.old`, `.backup`, `~`, `.swp` |
| **Config Files** | `.env`, `config.php`, `web.config`, `settings.py` |
| **Git Repos** | `.git/`, `.gitignore`, `.git/config` |
| **Admin Panels** | `/admin`, `/administrator`, `/manage`, `/wp-admin` |
| **API Endpoints** | `/api/`, `/v1/`, `/graphql`, `/swagger` |
| **Debug Pages** | `/debug`, `/phpinfo.php`, `/server-status` |

### False Positive Reduction

LANTERN uses multiple techniques to reduce false positives:

1. **Baseline Comparison** - Requests fake paths, compares responses
2. **Content Hashing** - Detects soft 404s returning same content
3. **Length Analysis** - Filters generic error pages
4. **WAF Detection** - Identifies Cloudflare challenge pages
5. **Content Validation** - `.git/config` must contain `[core]`

```bash
lantern -t https://target.com -m dirbust,disclosure --crawl
```

---

## Secret Scanning

### What Gets Extracted

| Secret Type | Pattern |
|-------------|---------|
| **API Keys** | `api[_-]?key.*[a-zA-Z0-9]{20,}` |
| **AWS Keys** | `AKIA[A-Z0-9]{16}` |
| **JWTs** | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` |
| **Passwords** | `password.*[:=].*[^\s]+` |
| **Private Keys** | `-----BEGIN .* PRIVATE KEY-----` |
| **Credit Cards** | Visa, Mastercard, Amex patterns |
| **Internal IPs** | `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x` |

### Where It Looks

- HTML source code
- JavaScript files
- JSON responses
- Comments
- Error messages
- Environment files

```bash
lantern -t https://target.com -m secrets,disclosure --crawl
lantern -t https://target.com --analyze-js -m secrets
```

---

## Cloud Misconfiguration

### AWS

| Check | Issue |
|-------|-------|
| **Public S3 Buckets** | `ListBucket` or `GetObject` without auth |
| **Metadata Service** | SSRF to `169.254.169.254` |
| **EC2 Instance Role** | Leaked credentials via metadata |

### Azure

| Check | Issue |
|-------|-------|
| **Public Blob Storage** | Anonymous access enabled |
| **IMDS** | Instance metadata at `169.254.169.254` |

### GCP

| Check | Issue |
|-------|-------|
| **Public GCS Buckets** | `allUsers` or `allAuthenticatedUsers` |
| **Metadata Server** | `metadata.google.internal` |

```bash
lantern -t https://target.com -m cloud,ssrf --exploit
```

---

## WAF Detection

### Detected WAFs

| WAF | Detection Method |
|-----|------------------|
| **Cloudflare** | `cf-ray` header, challenge page |
| **AWS WAF** | `x-amzn-requestid` header |
| **Akamai** | `akamai-` headers |
| **Sucuri** | Challenge page pattern |
| **Incapsula** | `visid_incap` cookie |
| **ModSecurity** | Error message patterns |
| **F5 BIG-IP** | Cookie patterns |

**Purpose:** Knowing which WAF is present helps LANTERN select the right bypass techniques.

```bash
lantern -t https://target.com -m waf
lantern -t https://target.com -m waf,sqli,xss --aggressive
```

---

## Parameter Discovery

### Where Parameters Are Found

1. **URL Query Strings** - Obvious `?param=value`
2. **HTML Forms** - `<input name="param">`
3. **JavaScript** - `fetch('/api?param=')`, AJAX calls
4. **Comments** - `<!-- debug: ?admin=1 -->`
5. **Wordlist Fuzzing** - Common param names like `id`, `page`, `user`

### Hidden Parameter Detection

LANTERN tries common parameter names and detects changes in:
- Response length
- Status code
- Response time
- Error messages

```bash
lantern -t https://target.com -m paramfind,fuzz --crawl
```

---

## Complete Reconnaissance

```bash
# Full recon chain
lantern -t https://target.com --chain full_recon

# Manual recon
lantern -t https://target.com -m techdetect,fingerprint,subdomain,takeover,cloud,dirbust,disclosure,secrets,dork,paramfind --dns-brute

# Quick recon
lantern -t https://target.com --fast
```

---

## What Gets Reported

For each finding:
- **Type** - What kind of information/exposure
- **Location** - Exact URL/path
- **Evidence** - Sample of discovered content
- **Risk** - Potential impact
- **Recommendations** - How to fix

---

[← Back to Index](../INDEX.md)
