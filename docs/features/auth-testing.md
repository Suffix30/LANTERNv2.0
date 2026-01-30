[← Back to Index](../INDEX.md)

# Multi-Role Authentication Testing

Test access controls across different user roles.

---

## Setup Authentication

**Create auth config file (`configs/auth.yml`):**
```yaml
authentication:
  type: form          # form, basic, bearer, api_key
  login_url: /login
  logout_url: /logout
  form:
    username_field: email
    password_field: password
    csrf_field: _token
  roles:
    admin:
      username: admin@target.com
      password: "${ADMIN_PASSWORD}"
    user:
      username: user@target.com  
      password: "${USER_PASSWORD}"
    guest:
      authenticated: false
```

---

## Role-Based Testing

**Test with auth config:**
```bash
lantern -t https://target.com --auth-config configs/auth.yml -m idor,auth,session
```

**Auth bypass chain:**
```bash
lantern -t https://target.com --auth-config configs/auth.yml --chain auth_bypass --exploit
```

**Privilege escalation testing:**
```bash
lantern -t https://target.com --auth-config configs/auth.yml -m idor,massassign,auth --exploit --aggressive
```

---

## Workflow + Auth

**Business logic with roles:**
```bash
lantern -t https://target.com --workflow workflows/checkout_bypass.yml --auth-config configs/auth.yml
```

---

## Auth Types Supported

| Type | Description |
|------|-------------|
| `form` | Form-based login (POST username/password) |
| `basic` | HTTP Basic Authentication |
| `bearer` | Bearer token in Authorization header |
| `api_key` | API key in header or query param |

---

[← Back to Index](../INDEX.md)
