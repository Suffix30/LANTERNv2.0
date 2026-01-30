[← Back to Index](../INDEX.md)

# OOB Callback Server

Built-in HTTP/DNS callback server for blind vulnerability detection.

---

## Starting OOB Server

**Start OOB server with default ports:**
```bash
lantern -t https://target.com --oob-server -m ssrf,xxe,sqli --exploit
```

**Custom OOB ports:**
```bash
lantern -t https://target.com --oob-server --oob-port 9999 --oob-dns-port 5354 -m ssrf --exploit
```

**OOB + CVE scanning (Log4Shell, etc.):**
```bash
lantern -t https://target.com --oob-server --cve-scan --exploit
```

---

## OOB Use Cases

| Vulnerability | OOB Usage |
|---------------|-----------|
| **Blind SSRF** | HTTP callback to OOB server |
| **Blind XXE** | OOB XML entity exfiltration |
| **Blind SQLi** | DNS/HTTP exfiltration |
| **Log4Shell** | JNDI callback detection |
| **Blind XSS** | Delayed callback capture |

---

## Combined OOB Patterns

**OOB + Injection testing:**
```bash
lantern -t https://target.com --oob-server -m sqli,ssrf,xxe,cmdi --exploit --aggressive
```

**OOB + Full exploitation:**
```bash
lantern -t https://target.com --oob-server --chain data_theft --exploit --deep
```

**Blind vulnerability hunting:**
```bash
lantern -t https://target.com --oob-server -m ssrf,xxe,sqli,cmdi --exploit --aggressive
```

---

## OOB Server Options

| Option | Default | Description |
|--------|---------|-------------|
| `--oob-server` | - | Start the OOB callback server |
| `--oob-port` | 8888 | HTTP callback port |
| `--oob-dns-port` | 5353 | DNS callback port |

---

[← Back to Index](../INDEX.md)
