[← Back to Index](../INDEX.md)

# API Security Modules

Command examples for testing REST APIs, GraphQL, and WebSocket endpoints.

---

## Complete API Assessment

```bash
lantern -t https://api.target.com -m api,graphql,websocket,jwt,idor,apiver --exploit --aggressive
```

## REST API Testing

```bash
lantern -t https://api.target.com -m api,idor,massassign,jwt --exploit --crawl
```

## GraphQL Security

```bash
lantern -t https://api.target.com -m graphql,api,idor --exploit --deep
```

## WebSocket & Real-time APIs

```bash
lantern -t https://target.com -m websocket,api,jwt --exploit --aggressive
```

## API Version Discovery

```bash
lantern -t https://api.target.com -m apiver,api,graphql --crawl
```

---

## Module Reference

| Module | Common Combinations |
|--------|---------------------|
| `api` | `api,graphql,websocket,jwt` |
| `graphql` | `graphql,api,idor` |
| `websocket` | `websocket,api,jwt` |
| `apiver` | `apiver,api` |

---

[← Back to Index](../INDEX.md) | [Next: Client-Side Modules →](client.md)
