[← Back to Index](../INDEX.md)

# Authentication & Authorization

LANTERN tests every aspect of authentication - from JWT attacks to OAuth misconfigurations to privilege escalation.

---

## JWT Attacks

### Attack Types

| Attack | What It Does |
|--------|--------------|
| **None Algorithm** | Changes `alg` to `none` - signature not verified |
| **Algorithm Confusion** | Switches RS256 → HS256, signs with public key |
| **Weak Secret** | Brute-forces common secrets (`secret`, `password123`, etc.) |
| **JWK Injection** | Injects attacker's public key into `jwk` header |
| **JKU Injection** | Points `jku` to attacker's key server |
| **KID Injection** | SQLi/Path traversal in `kid` parameter |
| **Expired Token** | Tests if expiration is enforced |
| **Claim Tampering** | Changes `role: user` → `role: admin` |

### Example: None Algorithm Attack

```json
// Original header
{"alg": "HS256", "typ": "JWT"}

// Attacked header
{"alg": "none", "typ": "JWT"}

// Payload (unchanged)
{"sub": "user123", "role": "admin", "exp": 9999999999}

// Signature removed
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIn0.
```

### Commands

```bash
# JWT security scan
lantern -t https://target.com -m jwt --exploit

# JWT + session testing
lantern -t https://target.com -m jwt,session,cookie --exploit
```

---

## OAuth/OIDC Vulnerabilities

### Attack Types

| Attack | What It Does |
|--------|--------------|
| **Open Redirect** | `redirect_uri=https://evil.com` steals auth codes |
| **State Parameter Missing** | CSRF to link attacker's account |
| **Token Leakage** | Access tokens in URL fragments, referrer headers |
| **Scope Escalation** | Request `scope=admin` when granted `user` |
| **Code Injection** | Inject malicious code in auth flow |
| **Token Exchange** | Exchange leaked refresh token for access token |

### Commands

```bash
# OAuth misconfiguration scan
lantern -t https://target.com -m oauth --exploit

# OAuth + MFA bypass
lantern -t https://target.com -m oauth,mfa --exploit --aggressive
```

---

## MFA/2FA Bypass

### Attack Types

| Attack | What It Does |
|--------|--------------|
| **Rate Limiting** | Brute-force 4-6 digit codes |
| **Response Manipulation** | Change `success: false` → `success: true` |
| **Backup Codes** | Test if backup codes are predictable |
| **Race Condition** | Parallel requests with same code |
| **Skip Step** | Access authenticated pages without completing MFA |
| **Time-Based Bypass** | TOTP codes valid for extended windows |

### Commands

```bash
# MFA bypass testing
lantern -t https://target.com -m mfa --exploit --aggressive

# With race condition testing
lantern -t https://target.com -m mfa,race --threads 200 --exploit
```

---

## Session Management

### What Gets Tested

| Test | What It Checks |
|------|----------------|
| **Session Fixation** | Can attacker set victim's session ID? |
| **Session Prediction** | Are session IDs random enough? |
| **Concurrent Sessions** | Does new login invalidate old sessions? |
| **Session Timeout** | Do sessions expire properly? |
| **Logout Invalidation** | Does logout actually destroy the session? |
| **Cookie Flags** | HttpOnly, Secure, SameSite attributes |

### Commands

```bash
# Session security scan
lantern -t https://target.com -m session,cookie --exploit

# With CSRF testing
lantern -t https://target.com -m session,cookie,csrf --exploit
```

---

## IDOR (Insecure Direct Object Reference)

### What Gets Tested

LANTERN automatically tests:
- `/api/users/1` → `/api/users/2` (can user 1 see user 2's data?)
- `/orders/ORDER-001` → `/orders/ORDER-002`
- Sequential IDs, UUIDs, encoded IDs
- POST body parameters (`user_id`, `account_id`, etc.)

### With Auth Config

```yaml
# configs/auth.yml
authentication:
  type: form
  login_url: /login
  roles:
    admin:
      username: admin@target.com
      password: "${ADMIN_PASSWORD}"
    user:
      username: user@target.com  
      password: "${USER_PASSWORD}"
```

```bash
# Test what user can access that admin can
lantern -t https://target.com --auth-config configs/auth.yml -m idor,auth --exploit
```

---

## Mass Assignment

### What Gets Tested

```json
// Normal request
{"name": "John", "email": "john@example.com"}

// Attack request
{"name": "John", "email": "john@example.com", "role": "admin", "is_admin": true}
```

LANTERN injects common privilege parameters:
- `role`, `is_admin`, `admin`, `isAdmin`
- `permission`, `permissions`, `access_level`
- `user_type`, `account_type`, `membership`

### Commands

```bash
# Mass assignment scan
lantern -t https://target.com -m massassign --exploit

# Combined with IDOR
lantern -t https://target.com -m idor,massassign,auth --exploit
```

---

## Access Control Testing

### Horizontal Privilege Escalation
- User A accessing User B's resources
- Same role, different user

### Vertical Privilege Escalation  
- User accessing admin functions
- Lower role accessing higher role

### Commands

```bash
# Access control scan
lantern -t https://target.com -m accessctl,idor,auth --exploit

# With multi-role auth config
lantern -t https://target.com --auth-config configs/auth.yml -m accessctl --exploit
```

---

## CORS Misconfiguration

### What Gets Tested

| Misconfiguration | Risk |
|------------------|------|
| `Access-Control-Allow-Origin: *` with credentials | Any site can steal data |
| Origin reflection | Attacker's origin is trusted |
| `null` origin allowed | Sandboxed pages can attack |
| Subdomain wildcards | Subdomain takeover → full access |

### Commands

```bash
# CORS scan
lantern -t https://target.com -m cors --exploit

# Combined with CSRF
lantern -t https://target.com -m cors,csrf,clickjack --exploit
```

---

## CSRF (Cross-Site Request Forgery)

### What Gets Tested

| Test | What It Checks |
|------|----------------|
| **Missing Token** | No CSRF token at all |
| **Weak Token** | Predictable or static tokens |
| **Token Not Validated** | Token present but not checked |
| **Token in URL** | Token leaked in Referer header |
| **Method Override** | Change POST to GET to bypass |
| **Content-Type Bypass** | Change to `text/plain` to bypass |

### Commands

```bash
# CSRF scan
lantern -t https://target.com -m csrf --exploit

# Full client-side testing
lantern -t https://target.com -m csrf,cors,clickjack --exploit
```

---

## File Upload Bypass

### Bypass Techniques

| Technique | Example |
|-----------|---------|
| **Double Extension** | `shell.php.jpg` |
| **Null Byte** | `shell.php%00.jpg` |
| **Case Variation** | `shell.pHp` |
| **Content-Type Spoof** | Upload PHP, claim `image/jpeg` |
| **Magic Bytes** | Add `GIF89a` to start of PHP file |
| **Polyglot** | Valid image that's also valid PHP |
| **SVG XSS** | `<svg onload=alert(1)>` |
| **SVG XXE** | External entity in SVG |
| **.htaccess** | Upload `.htaccess` to enable PHP |

### Commands

```bash
# File upload bypass scan
lantern -t https://target.com -m upload --exploit

# Combined with command injection
lantern -t https://target.com -m upload,cmdi --exploit --aggressive
```

---

## Complete Auth Testing

```bash
# Full authentication audit
lantern -t https://target.com -m auth,jwt,oauth,mfa,session,cookie,csrf,idor,massassign,cors,accessctl --exploit --aggressive

# Auth bypass chain
lantern -t https://target.com --chain auth_bypass --exploit

# With multi-role testing
lantern -t https://target.com --auth-config configs/auth.yml --chain auth_bypass --exploit
```

---

[← Back to Index](../INDEX.md)
