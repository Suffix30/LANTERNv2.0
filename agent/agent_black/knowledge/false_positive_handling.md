# False Positive Handling

This is one of the most critical aspects of my operation. A scanner that 
reports false positives is worse than useless - it wastes operator time
and erodes trust.

---

## Confidence Scoring System

Every finding has a confidence level, not just a severity.

### Confidence Levels

| Level | Numeric | Meaning |
|-------|---------|---------|
| **CONFIRMED** | 1.0 | Vulnerability exploited, data extracted |
| **HIGH** | 0.8 | Strong indicators, very likely real |
| **MEDIUM** | 0.6 | Behavioral indicators, needs verification |
| **LOW** | 0.4 | Weak indicators, high false positive risk |
| **INFO** | 0.2 | Informational only, not a vulnerability |

### How Confidence Affects Severity

```python
def adjust_severity(original_severity, confidence):
    if confidence == LOW:
        return downgrade_one_level(original_severity)
    if confidence == INFO:
        return "INFO"
    return original_severity
```

Example: A "HIGH" severity finding with "LOW" confidence becomes "MEDIUM".

---

## Evidence-Based Scoring

Confidence is calculated from evidence items, not guesswork.

### SQL Injection Evidence

**CONFIRMED (score >= 0.9):**
- `data_extracted` - Actual database data was extracted
- `union_columns_found` - UNION query returned enumerated columns  
- `time_delay_verified` - Consistent time delays across multiple tests
- `oob_callback_received` - Out-of-band callback confirmed
- `stacked_query_executed` - Stacked query was executed

**HIGH (score >= 0.7):**
- `db_error_detailed` - Database-specific error message returned
- `boolean_diff_verified` - True/false responses consistently differ
- `syntax_error_triggered` - SQL syntax error on malformed input
- `version_extracted` - Database version string extracted

**MEDIUM (score >= 0.5):**
- `error_message_generic` - Generic database error returned
- `response_anomaly` - Response changed with SQL characters
- `single_quote_diff` - Single quote causes different behavior

**LOW (score < 0.5):**
- `payload_not_rejected` - SQL payload was not filtered
- `no_error_on_injection` - No error returned on injection

### XSS Evidence

**CONFIRMED:**
- `payload_executed` - JavaScript execution confirmed via callback
- `dom_manipulation_verified` - DOM was modified by injected script
- `alert_triggered` - Alert/prompt/confirm triggered in browser
- `oob_callback_received` - XSS triggered OOB callback

**HIGH:**
- `unencoded_in_html` - Payload reflected without HTML encoding
- `context_breakout` - Can break out of current context
- `event_handler_injectable` - Event handler attribute injectable
- `script_tag_injectable` - Script tag can be injected

**MEDIUM:**
- `partial_reflection` - Payload partially reflected
- `attribute_injection` - Can inject into HTML attribute
- `csp_weak` - CSP is weak or bypassable

**LOW:**
- `reflected_encoded` - Payload reflected but encoded
- `filter_bypass_needed` - Filter present but may be bypassable

### SSRF Evidence

**CONFIRMED:**
- `oob_callback_received` - HTTP/DNS callback received
- `internal_data_returned` - Internal service data in response
- `metadata_accessed` - Cloud metadata endpoint accessed
- `file_content_returned` - Local file content returned via file://

**HIGH:**
- `different_response_internal` - Different response for internal URL
- `timing_indicates_request` - Timing suggests request was made
- `error_reveals_request` - Error message reveals request attempt
- `dns_resolution_confirmed` - DNS resolution of payload confirmed

**MEDIUM:**
- `url_parameter_accepted` - URL parameter accepted without error
- `redirect_followed` - Server followed redirect to payload

**LOW:**
- `no_validation_error` - No URL validation error returned

---

## Score Calculation Formula

```python
max_weight = max(evidence_weights)
avg_weight = sum(evidence_weights) / count
evidence_count_factor = min(count / 3, 1.0)

score = (max_weight * 0.6) + (avg_weight * 0.3) + (evidence_count_factor * 0.1)
```

**Interpretation:**
- Strong single evidence (like OOB callback) matters most (60%)
- Average evidence quality matters (30%)
- Multiple pieces of evidence add confidence (10%)

---

## Verification Steps

When I find a LOW or MEDIUM confidence finding, I know what to do next.

### Upgrading LOW → MEDIUM (SQL Injection)

```
To upgrade:
1. db_error_detailed: Get database-specific error message
2. boolean_diff_verified: Test true/false condition differences
3. syntax_error_triggered: Trigger SQL syntax error
```

### Upgrading MEDIUM → HIGH (XSS)

```
To upgrade:
1. unencoded_in_html: Confirm payload reflected without encoding
2. context_breakout: Verify can break out of current context
3. event_handler_injectable: Test event handler injection
```

### Upgrading HIGH → CONFIRMED (Any)

```
To upgrade:
1. Actually extract data (SQLi)
2. Trigger JavaScript execution (XSS)
3. Receive OOB callback (SSRF, XXE, CMDI)
```

---

## My False Positive Reduction Process

### Step 1: Initial Detection

```
LANTERN reports: SQLi MEDIUM confidence
Evidence: single_quote_diff
```

### Step 2: I Verify Before Reporting

```
Before telling operator:
1. Can I get a database error? (upgrade to HIGH)
2. Can I extract data? (upgrade to CONFIRMED)
3. Is this just a filter/WAF? (downgrade or discard)
```

### Step 3: Smart Probe Verification

```python
def verify_sqli(finding):
    target_url = finding["url"]
    param = finding["parameter"]
    
    for payload in VERIFICATION_PAYLOADS:
        response = request(target_url, {param: payload})
        
        for pattern, db_type in ERROR_PATTERNS:
            if re.search(pattern, response.text):
                return upgrade_to_high(finding, "db_error_detailed")
    
    if can_extract_version(target_url, param):
        return upgrade_to_confirmed(finding, "version_extracted")
    
    return finding  # Keep original confidence if can't verify
```

### Step 4: Report with Context

```
If CONFIRMED: Report immediately, include extracted data
If HIGH: Report with strong evidence noted
If MEDIUM: Report but note "needs manual verification"
If LOW: Don't report unless --verbose, or aggregate with others
```

---

## Per-Module False Positive Patterns

### SQL Injection False Positives

**Common FPs:**
- Single quote in error message (not SQL error)
- "Syntax error" in application error (not database)
- WAF blocking (different from SQL error)

**How I detect FP:**
```python
def is_sqli_false_positive(response):
    if "syntax error" in response.text:
        if not any(re.search(pattern, response.text) for pattern, _ in SQL_ERROR_PATTERNS):
            return True  # Generic syntax error, not SQL
    return False
```

### XSS False Positives

**Common FPs:**
- Payload reflected but HTML encoded
- Payload in HTTP response headers (not rendered)
- Payload in JSON response (not in HTML)

**How I detect FP:**
```python
def is_xss_false_positive(response, payload):
    if payload in response.text:
        if html.escape(payload) in response.text:
            return True  # Encoded = not exploitable
        if "application/json" in response.headers.get("content-type", ""):
            return True  # JSON response, not HTML
    return False
```

### SSRF False Positives

**Common FPs:**
- URL parameter exists but server doesn't fetch
- Internal URL in error message (not fetched)
- Redirect but no actual request

**How I detect FP:**
```python
def is_ssrf_false_positive(response, payload_url):
    if payload_url in response.text:
        if "invalid url" in response.text.lower():
            return True  # Just echoed in error
    return False
```

---

## When to Suppress Findings

I suppress findings when:

1. **Confidence is INFO** - Not a vulnerability
2. **Duplicate of higher-confidence finding** - Same vuln, better evidence exists
3. **Known false positive pattern** - Matches FP signature
4. **WAF blocking everything** - All payloads blocked, not testing real app

```python
def should_report(finding):
    if finding["confidence"] == "INFO":
        return False
    
    if is_duplicate_with_higher_confidence(finding):
        return False
    
    if matches_fp_signature(finding):
        return False
    
    if waf_blocking_all():
        return False
    
    return True
```

---

## Confidence in Reports

Every finding I report includes:

```json
{
  "module": "sqli",
  "severity": "CRITICAL",
  "confidence": "CONFIRMED",
  "confidence_score": 0.95,
  "evidence": [
    {"name": "data_extracted", "description": "Extracted user table data"},
    {"name": "version_extracted", "description": "MySQL 8.0.23"}
  ],
  "explanation": "Confirmed with high-confidence evidence: data_extracted, version_extracted",
  "missing_for_upgrade": []
}
```

---

## Operator Guidance

When reporting to operator:

**CONFIRMED findings:**
```
🔴 CONFIRMED: SQL Injection at /api/users?id=
   → Data extracted: users table (15 rows)
   → Database: MySQL 8.0.23
   → Immediate action required
```

**HIGH findings:**
```
🟠 HIGH CONFIDENCE: XSS at /search?q=
   → Payload reflected without encoding
   → Can inject event handlers
   → Recommend manual verification
```

**MEDIUM findings:**
```
🟡 MEDIUM CONFIDENCE: Possible SSRF at /fetch?url=
   → URL parameter accepted
   → Could not confirm external request
   → Verify manually with OOB server
```

**LOW findings (only with --verbose):**
```
⚪ LOW CONFIDENCE: Possible SQLi at /login
   → Single quote causes different response
   → No SQL errors detected
   → Likely false positive, investigate if time permits
```

---

## Summary: My False Positive Philosophy

1. **Never report LOW confidence as high severity**
2. **Always try to upgrade confidence before reporting**
3. **Include evidence and explanation in every finding**
4. **Tell operator what's needed for confirmation**
5. **Use OOB callbacks when possible - they're definitive**
6. **Track false positives to improve over time**

The goal is: every finding I report should be real. Operator should trust
that if I say CONFIRMED, it's exploitable.
