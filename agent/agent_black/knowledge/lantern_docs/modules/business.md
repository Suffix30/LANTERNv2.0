[← Back to Index](../INDEX.md)

# Business Logic Modules

Command examples for testing payment flows, race conditions, and account security.

---

## E-commerce Security

```bash
lantern -t https://shop.target.com -m payment,race,captcha,account --exploit --aggressive
```

## Account Security

```bash
lantern -t https://target.com -m account,race,captcha,payment --exploit --crawl
```

## Payment & Race Conditions

```bash
lantern -t https://target.com -m payment,race,account --exploit --threads 200
```

---

## Module Reference

| Module | Common Combinations |
|--------|---------------------|
| `payment` | `payment,race,captcha` |
| `race` | `race,account,payment` |
| `captcha` | `captcha,account,payment` |
| `account` | `account,race,captcha` |
| `logic` | `logic,payment,race` |

---

## See Also

For multi-step business logic testing, see [Workflows](../features/workflows.md).

---

[← Back to Index](../INDEX.md) | [Next: Advanced Attacks →](advanced.md)
