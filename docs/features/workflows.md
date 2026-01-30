[← Back to Index](../INDEX.md)

# Business Logic Workflows

LANTERN's workflow engine lets you define multi-step attack flows in YAML. This is how you test business logic vulnerabilities that require multiple HTTP requests in sequence.

---

## Why Workflows?

Traditional scanners test one request at a time. But real vulnerabilities often require:

1. Add item to cart (request 1)
2. Apply coupon (request 2)
3. Modify price to 0 (request 3)
4. Complete checkout (request 4)

LANTERN workflows let you define this entire flow and automatically test for logic flaws at each step.

---

## Workflow Structure

```yaml
name: checkout_bypass
description: E-commerce checkout flow attacks

authentication:
  inherit: true  # Use --auth-config if provided

variables:
  base_url: "{{target}}"
  product_id: "PROD-001"

steps:
  - name: add_to_cart
    request:
      method: POST
      url: "{{base_url}}/api/cart/add"
      json:
        product_id: "{{product_id}}"
        quantity: 1
    extract:
      cart_id: "$.cart_id"
      item_id: "$.items[0].id"

  - name: apply_coupon
    request:
      method: POST
      url: "{{base_url}}/api/cart/{{cart_id}}/coupon"
      json:
        code: "SAVE10"
    
  - name: checkout
    request:
      method: POST
      url: "{{base_url}}/api/checkout"
      json:
        cart_id: "{{cart_id}}"
        payment_method: "credit_card"

attacks:
  - name: zero_price_attack
    type: modify_step
    target_step: add_to_cart
    modifications:
      - path: "$.json.price"
        value: 0
      - path: "$.json.quantity"
        value: -1
    success_indicators:
      - "order_id"
      - "success"

  - name: skip_payment
    type: skip_steps
    skip: ["apply_coupon"]
    success_indicators:
      - "order_confirmed"

  - name: coupon_stacking
    type: replay
    target_step: apply_coupon
    replay_count: 10
    success_indicators:
      - "discount.*100%"
```

---

## Attack Types

### `skip_steps`
Skip one or more steps in the flow. Tests if server validates step completion.

```yaml
attacks:
  - name: skip_payment
    type: skip_steps
    skip: ["payment_step", "verification_step"]
```

### `modify_step`
Tamper with request data at a specific step.

```yaml
attacks:
  - name: negative_quantity
    type: modify_step
    target_step: add_to_cart
    modifications:
      - path: "$.json.quantity"
        value: -5
      - path: "$.json.unit_price"
        value: 0
```

### `replay`
Replay a step multiple times. Tests for race conditions and replay attacks.

```yaml
attacks:
  - name: coupon_replay
    type: replay
    target_step: apply_coupon
    replay_count: 50
    parallel: true
```

### `race`
Send parallel requests to exploit race conditions.

```yaml
attacks:
  - name: double_spend
    type: race
    target_step: transfer_funds
    parallel_count: 20
    success_indicators:
      - "balance.*negative"
```

---

## Pre-Built Workflows

LANTERN includes workflows for common attack scenarios:

### Payment/E-commerce (`payment_bypass.yml`)

| Attack | What It Does |
|--------|--------------|
| `zero_price_attack` | Set item price to 0 |
| `negative_quantity` | Use negative quantities for credit |
| `coupon_stacking` | Apply same coupon multiple times |
| `skip_payment` | Complete order without payment step |
| `currency_manipulation` | Change currency to get better rate |

```bash
lantern -t https://shop.target.com --workflow workflows/payment_bypass.yml
lantern -t https://shop.target.com --workflow workflows/payment_bypass.yml --workflow-attack zero_price_attack
```

### Authentication (`auth_bypass.yml`)

| Attack | What It Does |
|--------|--------------|
| `jwt_none_algorithm` | Set JWT alg to none |
| `password_reset_takeover` | Reset another user's password |
| `session_fixation` | Force victim into attacker's session |
| `role_escalation` | Modify role claim in token |
| `idor_enumeration` | Access other users' resources |

```bash
lantern -t https://target.com --workflow workflows/auth_bypass.yml
lantern -t https://target.com --workflow workflows/auth_bypass.yml --workflow-attack jwt_none_algorithm
```

### API Exploitation (`api_abuse.yml`)

| Attack | What It Does |
|--------|--------------|
| `mass_assignment` | Inject admin fields in registration |
| `graphql_introspection` | Dump GraphQL schema |
| `bola_enumeration` | Access other objects via API |
| `rate_limit_bypass` | Circumvent rate limiting |

```bash
lantern -t https://api.target.com --workflow workflows/api_abuse.yml
```

### File Upload RCE (`file_upload.yml`)

| Attack | What It Does |
|--------|--------------|
| `php_webshell` | Upload PHP shell with bypass |
| `double_extension` | `shell.php.jpg` |
| `null_byte` | `shell.php%00.jpg` |
| `svg_xss` | XSS via SVG upload |
| `svg_xxe` | XXE via SVG upload |
| `polyglot` | Valid image + valid PHP |
| `htaccess` | Upload .htaccess to enable PHP |

```bash
lantern -t https://target.com --workflow workflows/file_upload.yml
```

### SSRF to Cloud (`ssrf_chain.yml`)

| Attack | What It Does |
|--------|--------------|
| `aws_metadata` | Read `169.254.169.254` for AWS creds |
| `gcp_metadata` | Read GCP metadata server |
| `azure_metadata` | Read Azure IMDS |
| `gopher_redis` | SSRF → Redis RCE |
| `dns_rebinding` | Bypass same-origin with DNS rebind |

```bash
lantern -t https://target.com --workflow workflows/ssrf_chain.yml --oob-server
```

### SQL Injection Escalation (`sqli_escalate.yml`)

| Attack | What It Does |
|--------|--------------|
| `mysql_file_write` | Write webshell via INTO OUTFILE |
| `mysql_file_read` | Read /etc/passwd via LOAD_FILE |
| `mssql_xp_cmdshell` | Enable and use xp_cmdshell |
| `postgres_copy_rce` | COPY ... TO PROGRAM for RCE |

```bash
lantern -t https://target.com --workflow workflows/sqli_escalate.yml
```

---

## Workflow + Auth Config

Combine workflows with multi-role authentication testing:

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
# Test workflow as different users
lantern -t https://target.com --workflow workflows/checkout_bypass.yml --auth-config configs/auth.yml
```

LANTERN will:
1. Log in as admin, run workflow, log findings
2. Log in as user, run workflow, compare results
3. Report access control issues (user can do what only admin should)

---

## Commands

```bash
# List available workflows
lantern --list-workflows

# Run all attacks in workflow
lantern -t https://target.com --workflow workflows/payment_bypass.yml

# Run specific attack
lantern -t https://target.com --workflow workflows/payment_bypass.yml --workflow-attack zero_price_attack

# Workflow with authentication
lantern -t https://target.com --workflow workflows/auth_bypass.yml --auth-config configs/auth.yml

# Workflow with exploitation
lantern -t https://target.com --workflow workflows/sqli_escalate.yml --exploit
```

---

## Creating Custom Workflows

1. Create YAML file in `workflows/` directory
2. Define steps (the normal flow)
3. Define attacks (how to break the flow)
4. Define success indicators (how to know attack worked)

See existing workflows in `workflows/` for examples.

---

[← Back to Index](../INDEX.md)
