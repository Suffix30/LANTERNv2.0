import json
import os
import aiofiles
from datetime import datetime
from pathlib import Path


class Reporter:
    def __init__(self, results, targets, modules):
        self.results = results
        self.targets = targets
        self.modules = modules
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.reports_dir = Path.cwd() / "reports"
        self.reports_dir.mkdir(exist_ok=True)
    
    cvss_scores = {
        "sqli": {"base": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "xss": {"base": 6.1, "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
        "ssrf": {"base": 9.1, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "lfi": {"base": 7.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "ssti": {"base": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "cmdi": {"base": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "xxe": {"base": 7.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "deserial": {"base": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "jwt": {"base": 7.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "idor": {"base": 6.5, "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
        "csrf": {"base": 4.3, "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
        "cors": {"base": 5.3, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
        "redirect": {"base": 4.7, "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N"},
        "upload": {"base": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "ldap": {"base": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "dirbust": {"base": 5.3, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
        "waf": {"base": 0.0, "vector": "N/A"},
        "takeover": {"base": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "cloud": {"base": 9.1, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "paramfind": {"base": 3.1, "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
        "csp": {"base": 6.1, "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
        "h2smuggle": {"base": 9.1, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "cachepois": {"base": 7.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"},
        "default": {"base": 5.0, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"},
    }
    
    remediation = {
        "sqli": {
            "title": "SQL Injection",
            "fix": "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
            "code": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        },
        "xss": {
            "title": "Cross-Site Scripting",
            "fix": "Encode all user output. Use Content-Security-Policy headers. Validate input.",
            "code": "html.escape(user_input)  # Python\nDOMPurify.sanitize(input)  // JavaScript",
        },
        "ssrf": {
            "title": "Server-Side Request Forgery",
            "fix": "Whitelist allowed domains. Block internal IP ranges. Validate URL schemes.",
            "code": "if not url.startswith(('https://allowed.com',)): abort(403)",
        },
        "lfi": {
            "title": "Local File Inclusion",
            "fix": "Never use user input in file paths. Use a whitelist of allowed files.",
            "code": "if filename not in ALLOWED_FILES: abort(403)",
        },
        "ssti": {
            "title": "Server-Side Template Injection",
            "fix": "Never render user input as template code. Use sandboxed templates.",
            "code": "render_template('page.html', name=user_input)  # Not f-strings",
        },
        "cmdi": {
            "title": "Command Injection",
            "fix": "Avoid shell=True. Use arrays for subprocess. Validate/sanitize all input.",
            "code": "subprocess.run(['ping', '-c', '1', validated_host], shell=False)",
        },
        "xxe": {
            "title": "XML External Entity Injection",
            "fix": "Disable external entities in XML parser. Use defusedxml library.",
            "code": "from defusedxml import ElementTree as ET",
        },
        "deserial": {
            "title": "Insecure Deserialization",
            "fix": "Never deserialize untrusted data. Use safe formats like JSON.",
            "code": "data = json.loads(input)  # Not pickle.loads()",
        },
        "jwt": {
            "title": "JWT Vulnerabilities",
            "fix": "Use strong secrets. Validate algorithm. Check expiration. Use asymmetric keys.",
            "code": "jwt.decode(token, key, algorithms=['RS256'])  # Specify algorithm",
        },
        "idor": {
            "title": "Insecure Direct Object Reference",
            "fix": "Check authorization for every resource access. Use indirect references.",
            "code": "if resource.owner_id != current_user.id: abort(403)",
        },
        "csrf": {
            "title": "Cross-Site Request Forgery",
            "fix": "Use CSRF tokens. Check Referer/Origin headers. Use SameSite cookies.",
            "code": "@csrf.protect  # Flask-WTF",
        },
        "cors": {
            "title": "CORS Misconfiguration",
            "fix": "Whitelist specific origins. Never use wildcard with credentials.",
            "code": "Access-Control-Allow-Origin: https://trusted.com",
        },
        "upload": {
            "title": "File Upload Vulnerability",
            "fix": "Validate file type by content. Use random filenames. Store outside webroot.",
            "code": "filename = secure_filename(secrets.token_hex(16) + '.pdf')",
        },
        "ldap": {
            "title": "LDAP Injection",
            "fix": "Escape special LDAP characters. Use parameterized LDAP queries. Validate input.",
            "code": "ldap.filter.escape_filter_chars(user_input)  # python-ldap",
        },
        "dirbust": {
            "title": "Sensitive File/Directory Exposure",
            "fix": "Remove sensitive files from webroot. Configure proper access controls. Use .htaccess deny rules.",
            "code": "<Files ~ \"\\.(env|git|bak|sql)$\">\\n  Require all denied\\n</Files>",
        },
        "waf": {
            "title": "WAF Detection",
            "fix": "N/A - Informational finding. WAF presence is defensive, not a vulnerability.",
            "code": "N/A",
        },
        "takeover": {
            "title": "Subdomain Takeover",
            "fix": "Remove dangling DNS records. Delete CNAME entries pointing to deprovisioned services. Audit DNS regularly.",
            "code": "# Remove CNAME record or claim the external resource before attackers do",
        },
        "cloud": {
            "title": "Cloud Misconfiguration",
            "fix": "Restrict bucket/container ACLs. Enable access logging. Use IAM policies. Block public access.",
            "code": "aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        },
        "paramfind": {
            "title": "Hidden Parameter Discovery",
            "fix": "N/A - Informational. Review discovered parameters for potential injection points.",
            "code": "N/A",
        },
        "csp": {
            "title": "Content Security Policy Issues",
            "fix": "Remove unsafe-inline, unsafe-eval. Use nonces or hashes. Whitelist specific domains, not CDNs. Add base-uri 'self'.",
            "code": "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random123'; base-uri 'self'; object-src 'none'",
        },
        "h2smuggle": {
            "title": "HTTP/2 Request Smuggling",
            "fix": "Normalize HTTP/2 to HTTP/1.1 translation. Reject requests with conflicting Content-Length and Transfer-Encoding. Use HTTP/2 end-to-end.",
            "code": "# Configure reverse proxy to reject ambiguous requests",
        },
        "cachepois": {
            "title": "Web Cache Poisoning",
            "fix": "Include all user-controlled inputs in cache key. Use Vary header properly. Disable caching for dynamic content. Validate Host header.",
            "code": "Vary: Origin, Accept-Encoding, Accept-Language",
        },
    }
    
    def _get_cvss(self, finding):
        module = finding.get("module", "").lower()
        cvss = self.cvss_scores.get(module, self.cvss_scores["default"])
        
        severity = finding.get("severity", "MEDIUM")
        multiplier = {"CRITICAL": 1.0, "HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5, "INFO": 0.3}.get(severity, 0.7)
        
        adjusted = min(cvss["base"] * multiplier, 10.0)
        return {"score": round(adjusted, 1), "vector": cvss["vector"]}
    
    def _get_remediation(self, finding):
        module = finding.get("module", "").lower()
        return self.remediation.get(module, {
            "title": finding.get("module", "Unknown"),
            "fix": "Review the vulnerability and implement appropriate security controls.",
            "code": "# Consult security documentation",
        })
    
    def _format_exploit_data_html(self, exploit_data):
        if not exploit_data:
            return ""
        
        html = '<div class="exploit-data" style="background: #1a0a0a; border: 1px solid #dc3545; border-radius: 8px; padding: 15px; margin-top: 15px;">'
        html += '<h4 style="color: #dc3545; margin-bottom: 10px;">⚠️ EXPLOITATION DATA EXTRACTED</h4>'
        
        if exploit_data.get("credentials"):
            creds = exploit_data["credentials"]
            html += '<div style="margin-bottom: 10px;"><strong>Credentials:</strong><pre style="background: #0a0a0f; padding: 10px; border-radius: 4px; overflow-x: auto;">'
            for k, v in creds.items():
                if v:
                    html += f'{k}: {str(v)[:100]}\n'
            html += '</pre></div>'
        
        if exploit_data.get("files"):
            html += '<div style="margin-bottom: 10px;"><strong>Files Extracted:</strong><ul>'
            for filepath, content in list(exploit_data["files"].items())[:5]:
                html += f'<li><code>{filepath}</code>: {len(content)} bytes</li>'
            html += '</ul></div>'
        
        if exploit_data.get("secrets"):
            html += '<div style="margin-bottom: 10px;"><strong>Secrets Found:</strong><ul>'
            for secret in exploit_data["secrets"][:10]:
                html += f'<li>{secret.get("type")}: <code>{str(secret.get("value", ""))[:50]}...</code></li>'
            html += '</ul></div>'
        
        if exploit_data.get("users"):
            html += '<div style="margin-bottom: 10px;"><strong>Users Discovered:</strong> '
            html += ', '.join([u.get("name", "") for u in exploit_data["users"][:10]])
            html += '</div>'
        
        if exploit_data.get("internal_services"):
            html += '<div style="margin-bottom: 10px;"><strong>Internal Services:</strong><ul>'
            for svc in exploit_data["internal_services"][:10]:
                html += f'<li>Port {svc.get("port")}: {svc.get("service")} (status: {svc.get("status")})</li>'
            html += '</ul></div>'
        
        if exploit_data.get("cloud") or exploit_data.get("metadata"):
            html += f'<div style="margin-bottom: 10px;"><strong>Cloud Provider:</strong> {exploit_data.get("cloud", "Unknown")}</div>'
        
        if exploit_data.get("rce_output"):
            html += '<div style="margin-bottom: 10px;"><strong>RCE Output:</strong><pre style="background: #0a0a0f; padding: 10px; border-radius: 4px; overflow-x: auto;">'
            for cmd, output in list(exploit_data["rce_output"].items())[:5]:
                html += f'[{cmd}]: {str(output)[:200]}\n'
            html += '</pre></div>'
        
        if exploit_data.get("env_vars"):
            html += '<div style="margin-bottom: 10px;"><strong>Environment Variables:</strong><pre style="background: #0a0a0f; padding: 10px; border-radius: 4px; overflow-x: auto;">'
            for k, v in list(exploit_data["env_vars"].items())[:10]:
                html += f'{k}={str(v)[:80]}\n'
            html += '</pre></div>'
        
        html += '</div>'
        return html
    
    def _generate_executive_summary(self):
        total = len(self.results)
        critical = sum(1 for r in self.results if r["severity"] == "CRITICAL")
        high = sum(1 for r in self.results if r["severity"] == "HIGH")
        medium = sum(1 for r in self.results if r["severity"] == "MEDIUM")
        
        if critical > 0:
            risk_level = "CRITICAL"
            risk_color = "#dc3545"
            summary = f"The scan identified {critical} critical vulnerabilities requiring immediate attention. These issues could lead to complete system compromise, data breach, or remote code execution."
        elif high > 0:
            risk_level = "HIGH"
            risk_color = "#fd7e14"
            summary = f"The scan identified {high} high-severity vulnerabilities. These issues pose significant risk and should be addressed within 30 days."
        elif medium > 0:
            risk_level = "MEDIUM"
            risk_color = "#ffc107"
            summary = f"The scan identified {medium} medium-severity vulnerabilities. These should be addressed as part of regular security maintenance."
        else:
            risk_level = "LOW"
            risk_color = "#28a745"
            summary = "No significant vulnerabilities were identified. Continue regular security monitoring."
        
        modules_affected = list(set(r["module"] for r in self.results))
        
        return {
            "risk_level": risk_level,
            "risk_color": risk_color,
            "summary": summary,
            "total_findings": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "modules_affected": modules_affected[:10],
            "recommendation": f"Address {critical + high} critical/high findings immediately. Schedule fixes for {medium} medium issues.",
        }
    
    async def save_json(self, filename):
        filepath = self.reports_dir / filename if not os.path.dirname(filename) else Path(filename)
        
        enriched_results = []
        for r in self.results:
            enriched = r.copy()
            enriched["cvss"] = self._get_cvss(r)
            enriched["remediation"] = self._get_remediation(r)
            enriched_results.append(enriched)
        
        data = {
            "scan_info": {
                "timestamp": self.timestamp,
                "targets": self.targets,
                "modules": self.modules,
                "total_findings": len(self.results),
            },
            "executive_summary": self._generate_executive_summary(),
            "findings": enriched_results,
        }
        
        async with aiofiles.open(filepath, "w") as f:
            await f.write(json.dumps(data, indent=2))
        return str(filepath)
    
    async def save_html(self, filename):
        severity_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#17a2b8",
            "INFO": "#6c757d"
        }
        
        exec_summary = self._generate_executive_summary()
        
        severity_counts = {}
        for r in self.results:
            sev = r["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        findings_html = ""
        for r in self.results:
            color = severity_colors.get(r["severity"], "#6c757d")
            cvss = self._get_cvss(r)
            remediation = self._get_remediation(r)
            
            finding_id = f"finding-{hash(r.get('url', '') + r.get('description', '')) % 10000}"
            findings_html += f"""
            <div class="finding" id="{finding_id}">
                <div class="finding-header">
                    <span class="severity" style="background-color: {color}">{r['severity']}</span>
                    <span class="module">{r['module']}</span>
                    <span class="cvss">CVSS: {cvss['score']}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Target:</strong> {r.get('target', 'N/A')}</p>
                    <p><strong>URL:</strong> <code>{r.get('url', 'N/A')}</code></p>
                    <p><strong>Description:</strong> {r['description']}</p>
                    {f"<p><strong>Parameter:</strong> <code>{r.get('parameter')}</code></p>" if r.get('parameter') else ""}
                    {f"<p><strong>Evidence:</strong> <code>{str(r.get('evidence', ''))[:200]}</code></p>" if r.get('evidence') else ""}
                    {self._format_exploit_data_html(r.get('exploit_data')) if r.get('exploit_data') else ""}
                    <div class="screenshot-placeholder">
                        <div class="screenshot-box">
                            <span>📷 Screenshot Placeholder</span>
                            <p>Add screenshot: screenshots/{finding_id}.png</p>
                        </div>
                    </div>
                    <div class="remediation">
                        <h4>🔧 Remediation: {remediation['title']}</h4>
                        <p>{remediation['fix']}</p>
                        <pre><code>{remediation['code']}</code></pre>
                    </div>
                    <p class="cvss-vector"><strong>CVSS Vector:</strong> {cvss['vector']}</p>
                </div>
            </div>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lantern Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0f; color: #e0e0e0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 40px; border-radius: 12px; margin-bottom: 30px; border: 1px solid #0f3460; }}
        h1 {{ color: #00d4ff; font-size: 2.5em; margin-bottom: 10px; }}
        .subtitle {{ color: #888; font-size: 1.1em; }}
        .executive-summary {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 30px; border-radius: 12px; margin-bottom: 30px; border-left: 4px solid {exec_summary['risk_color']}; }}
        .executive-summary h2 {{ color: #00d4ff; margin-bottom: 15px; }}
        .risk-badge {{ display: inline-block; background: {exec_summary['risk_color']}; color: white; padding: 8px 20px; border-radius: 20px; font-weight: bold; margin-bottom: 15px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat-card {{ background: #1a1a2e; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #2a2a4e; }}
        .stat-card .number {{ font-size: 2em; font-weight: bold; }}
        .stat-card .label {{ color: #888; font-size: 0.9em; text-transform: uppercase; }}
        .findings {{ margin-top: 30px; }}
        .finding {{ background: #1a1a2e; border-radius: 8px; margin-bottom: 20px; overflow: hidden; border: 1px solid #2a2a4e; }}
        .finding-header {{ padding: 15px 20px; display: flex; align-items: center; gap: 15px; border-bottom: 1px solid #2a2a4e; background: #12121a; }}
        .severity {{ padding: 5px 12px; border-radius: 4px; font-weight: bold; font-size: 0.8em; color: white; }}
        .module {{ color: #00d4ff; font-weight: 500; }}
        .cvss {{ margin-left: auto; background: #2a2a4e; padding: 5px 12px; border-radius: 4px; font-size: 0.85em; }}
        .finding-body {{ padding: 20px; }}
        .finding-body p {{ margin-bottom: 10px; }}
        .finding-body code {{ background: #0a0a0f; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; word-break: break-all; }}
        .remediation {{ background: #0d1f0d; border: 1px solid #1a3a1a; border-radius: 8px; padding: 15px; margin-top: 15px; }}
        .remediation h4 {{ color: #4ade80; margin-bottom: 10px; }}
        .remediation pre {{ background: #0a0a0f; padding: 10px; border-radius: 4px; overflow-x: auto; margin-top: 10px; }}
        .cvss-vector {{ font-size: 0.85em; color: #666; margin-top: 10px; }}
        .screenshot-placeholder {{ margin: 15px 0; }}
        .screenshot-box {{ border: 2px dashed #3a3a5e; border-radius: 8px; padding: 30px; text-align: center; background: #12121a; }}
        .screenshot-box span {{ font-size: 1.5em; display: block; margin-bottom: 10px; }}
        .screenshot-box p {{ color: #666; font-size: 0.85em; margin: 0; }}
        .meta {{ color: #666; font-size: 0.9em; margin-top: 30px; text-align: center; padding: 20px; }}
        @media print {{ body {{ background: white; color: black; }} .finding {{ break-inside: avoid; }} }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔦 Lantern Security Report</h1>
            <p class="subtitle">Automated Web Vulnerability Assessment</p>
            <p class="subtitle" style="margin-top: 10px;">Generated: {self.timestamp}</p>
        </header>
        
        <div class="executive-summary">
            <h2>📋 Executive Summary</h2>
            <span class="risk-badge">Overall Risk: {exec_summary['risk_level']}</span>
            <p style="margin-bottom: 15px;">{exec_summary['summary']}</p>
            <p><strong>Recommendation:</strong> {exec_summary['recommendation']}</p>
            <p style="margin-top: 10px; color: #888;">Affected areas: {', '.join(exec_summary['modules_affected'][:5])}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="number">{len(self.targets)}</div>
                <div class="label">Targets Scanned</div>
            </div>
            <div class="stat-card">
                <div class="number">{len(self.results)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #dc3545">{severity_counts.get('CRITICAL', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #fd7e14">{severity_counts.get('HIGH', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #ffc107">{severity_counts.get('MEDIUM', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #17a2b8">{severity_counts.get('LOW', 0)}</div>
                <div class="label">Low</div>
            </div>
        </div>
        
        <div class="findings">
            <h2 style="color: #00d4ff; margin-bottom: 20px;">🔍 Detailed Findings</h2>
            {findings_html if findings_html else '<p style="color: #888;">No vulnerabilities found.</p>'}
        </div>
        
        <p class="meta">Generated by Lantern Web Vulnerability Scanner<br>Report ID: {hash(self.timestamp)}</p>
    </div>
</body>
</html>"""
        
        filepath = self.reports_dir / filename if not os.path.dirname(filename) else Path(filename)
        async with aiofiles.open(filepath, "w") as f:
            await f.write(html)
        return str(filepath)
    
    async def save_markdown(self, filename):
        exec_summary = self._generate_executive_summary()
        
        md = f"""# 🔦 Lantern Security Report

**Generated:** {self.timestamp}  
**Targets:** {len(self.targets)}  
**Total Findings:** {len(self.results)}

---

## 📋 Executive Summary

**Overall Risk Level:** {exec_summary['risk_level']}

{exec_summary['summary']}

**Recommendation:** {exec_summary['recommendation']}

---

## 📊 Statistics

| Severity | Count |
|----------|-------|
| Critical | {exec_summary['critical']} |
| High | {exec_summary['high']} |
| Medium | {exec_summary['medium']} |

---

## 🔍 Detailed Findings

"""
        
        for i, r in enumerate(self.results, 1):
            cvss = self._get_cvss(r)
            remediation = self._get_remediation(r)
            
            md += f"""### {i}. [{r['severity']}] {r['description']}

- **Module:** {r['module']}
- **CVSS Score:** {cvss['score']}
- **Target:** {r.get('target', 'N/A')}
- **URL:** `{r.get('url', 'N/A')}`
"""
            if r.get('parameter'):
                md += f"- **Parameter:** `{r.get('parameter')}`\n"
            if r.get('evidence'):
                md += f"- **Evidence:** `{str(r.get('evidence', ''))[:150]}`\n"
            
            md += f"""
**Screenshot:** `screenshots/finding-{i}.png`

#### Remediation: {remediation['title']}

{remediation['fix']}

```
{remediation['code']}
```

---

"""
        
        md += f"""
## 📝 Notes

- Report generated by Lantern Web Vulnerability Scanner
- CVSS scores are estimates based on vulnerability type
- Manual verification recommended for all findings

---

*Report ID: {hash(self.timestamp)}*
"""
        
        filepath = self.reports_dir / filename if not os.path.dirname(filename) else Path(filename)
        async with aiofiles.open(filepath, "w") as f:
            await f.write(md)
        return str(filepath)
    
    async def save_jira_csv(self, filename):
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            "Summary", "Description", "Priority", "Labels", 
            "Component", "Affected URL", "CVSS Score"
        ])
        
        priority_map = {
            "CRITICAL": "Highest",
            "HIGH": "High", 
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Lowest"
        }
        
        for r in self.results:
            cvss = self._get_cvss(r)
            remediation = self._get_remediation(r)
            
            summary = f"[{r['severity']}] {r['description'][:100]}"
            
            description = f"""*Vulnerability:* {r['description']}

*Target:* {r.get('target', 'N/A')}
*URL:* {r.get('url', 'N/A')}
*Parameter:* {r.get('parameter', 'N/A')}
*Evidence:* {str(r.get('evidence', ''))[:300]}

*CVSS Score:* {cvss['score']}
*CVSS Vector:* {cvss['vector']}

h3. Remediation
{remediation['fix']}

{{code}}
{remediation['code']}
{{code}}
"""
            
            writer.writerow([
                summary,
                description,
                priority_map.get(r['severity'], "Medium"),
                f"security,{r['module']}",
                "Security",
                r.get('url', ''),
                cvss['score']
            ])
        
        filepath = self.reports_dir / filename if not os.path.dirname(filename) else Path(filename)
        async with aiofiles.open(filepath, "w") as f:
            await f.write(output.getvalue())
        return str(filepath)