[← Back to Index](../INDEX.md)

# Client-Side Security Modules

Command examples for XSS, DOM vulnerabilities, and client-side attacks.

---

## XSS & DOM Testing

```bash
lantern -t https://target.com -m xss,dom,prototype,csp,clickjack --exploit --callback-host your-server.com
```

## CORS & Clickjacking

```bash
lantern -t https://target.com -m cors,clickjack,csrf --aggressive --crawl
```

## Prototype Pollution Chain

```bash
lantern -t https://target.com -m prototype,dom,xss --exploit --aggressive
```

## CSP Bypass Testing

```bash
lantern -t https://target.com -m csp,xss,dom,prototype --exploit --crawl
```

## Complete Client-Side

```bash
lantern -t https://target.com -m xss,dom,prototype,cors,clickjack,csp,csrf --exploit --aggressive
```

---

## Module Reference

| Module | Common Combinations |
|--------|---------------------|
| `xss` | `xss,dom,prototype,csp` |
| `dom` | `dom,xss,prototype` |
| `prototype` | `prototype,dom,xss` |
| `csp` | `csp,xss,dom` |
| `cors` | `cors,clickjack,csrf` |
| `clickjack` | `clickjack,cors,csrf` |
| `embed` | `embed,dom,clickjack` |

---

[← Back to Index](../INDEX.md) | [Next: Reconnaissance →](recon.md)
