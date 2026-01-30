[← Back to Index](../INDEX.md)

# Advanced Attack Modules

Command examples for HTTP smuggling, cache poisoning, and parameter manipulation.

---

## HTTP Smuggling & Cache Poisoning

```bash
lantern -t https://target.com -m smuggle,h2smuggle,cache,cachepois --exploit --aggressive
```

## Parameter Manipulation

```bash
lantern -t https://target.com -m hpp,crlf,paramfind,fuzz --aggressive --crawl
```

## Race Conditions & Business Logic

```bash
lantern -t https://target.com -m race,payment,captcha,account --exploit --threads 200
```

## Cache & Redirect Testing

```bash
lantern -t https://target.com -m cache,cachepois,redirect --aggressive
```

---

## Module Reference

| Module | Description |
|--------|-------------|
| `smuggle` | HTTP/1.1 request smuggling (CL.TE, TE.CL) |
| `h2smuggle` | HTTP/2 smuggling (H2.CL, H2.TE, tunneling) |
| `cachepois` | Cache poisoning via unkeyed headers/params |
| `hpp` | HTTP parameter pollution |
| `crlf` | CRLF injection / header injection |
| `race` | Race condition testing |

---

[← Back to Index](../INDEX.md)
