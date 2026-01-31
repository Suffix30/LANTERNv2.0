import json
import os
import uuid
import aiofiles
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from core.poc import PoCGenerator, create_poc_generator


class Reporter:
    def __init__(self, results, targets, modules):
        self.results = results
        self.targets = targets
        self.modules = modules
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.reports_dir = Path.cwd() / "reports"
        self.reports_dir.mkdir(exist_ok=True)
        self.poc_generator = create_poc_generator()
        self.scan_id = str(uuid.uuid4())[:8]
    
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
        "baas_exposure": {"base": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "js_analysis": {"base": 7.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
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
        "dom": {
            "title": "DOM-based XSS",
            "fix": "Sanitize user input before DOM manipulation. Use textContent instead of innerHTML. Implement CSP. Avoid dangerous sinks like eval(), document.write(), innerHTML with user data.",
            "code": "element.textContent = userInput;  // Safe\n// element.innerHTML = userInput;  // Dangerous\nDOMPurify.sanitize(userInput);  // If HTML needed",
        },
        "prototype": {
            "title": "Prototype Pollution",
            "fix": "Freeze Object.prototype. Use Object.create(null) for dictionaries. Validate JSON keys. Avoid recursive merging of user-controlled objects.",
            "code": "Object.freeze(Object.prototype);\nconst safeObj = Object.create(null);\n// Reject __proto__, constructor, prototype keys",
        },
        "auth": {
            "title": "Authentication Bypass",
            "fix": "Use strong authentication mechanisms. Implement proper session management. Enforce password complexity. Use MFA where possible.",
            "code": "if not user.is_authenticated: abort(401)",
        },
        "session": {
            "title": "Session Management",
            "fix": "Use secure, HttpOnly, SameSite cookies. Regenerate session ID on login. Implement proper timeout. Invalidate sessions on logout.",
            "code": "session.regenerate(); // After login\nres.cookie('session', token, {httpOnly: true, secure: true, sameSite: 'strict'})",
        },
        "oauth": {
            "title": "OAuth/OIDC Vulnerabilities",
            "fix": "Validate redirect_uri strictly. Use state parameter for CSRF protection. Validate tokens server-side. Use PKCE for public clients.",
            "code": "if redirect_uri not in ALLOWED_REDIRECTS: abort(400)",
        },
        "mfa": {
            "title": "MFA/2FA Bypass",
            "fix": "Rate limit verification attempts. Implement lockout after failures. Use time-based codes with short validity. Validate MFA on all sensitive operations.",
            "code": "if not verify_totp(code, user.mfa_secret): abort(401)",
        },
        "graphql": {
            "title": "GraphQL Security",
            "fix": "Disable introspection in production. Implement query depth limiting. Add query cost analysis. Use proper authorization on all resolvers.",
            "code": "# Disable introspection\nschema = graphene.Schema(query=Query, auto_camelcase=False)",
        },
        "websocket": {
            "title": "WebSocket Security",
            "fix": "Validate Origin header. Implement authentication. Rate limit connections. Validate all messages server-side.",
            "code": "if request.headers.get('Origin') not in ALLOWED_ORIGINS: abort(403)",
        },
        "race": {
            "title": "Race Condition",
            "fix": "Use database transactions with proper isolation. Implement locking mechanisms. Use atomic operations. Validate state before and after.",
            "code": "with transaction.atomic():\n    obj = Model.objects.select_for_update().get(id=id)",
        },
        "secrets": {
            "title": "Exposed Secrets",
            "fix": "Remove hardcoded secrets. Use environment variables or secret managers. Rotate exposed credentials immediately. Audit commit history.",
            "code": "import os\napi_key = os.environ.get('API_KEY')  # Not hardcoded",
        },
        "baas_exposure": {
            "title": "Backend-as-a-Service Credential Exposure",
            "fix": "Remove API keys from frontend code. Use Row Level Security (RLS). Implement proper authentication. Rotate exposed keys immediately. Review database access policies.",
            "code": "# Supabase: Enable RLS\nALTER TABLE users ENABLE ROW LEVEL SECURITY;\n# Use server-side auth, not anon keys in frontend",
        },
        "js_analysis": {
            "title": "JavaScript Security Issue",
            "fix": "Remove hardcoded credentials from JavaScript. Use server-side proxies for API calls. Implement proper content security policies.",
            "code": "// Use environment variables at build time\nconst apiUrl = process.env.REACT_APP_API_URL;",
        },
        "disclosure": {
            "title": "Information Disclosure",
            "fix": "Disable debug mode in production. Remove sensitive files from webroot. Configure proper error handling. Review response headers.",
            "code": "DEBUG = False  # Production\napp.config['PROPAGATE_EXCEPTIONS'] = False",
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
    
    def _colorize_log_line(self, line: str) -> str:
        import html as html_escape
        escaped = html_escape.escape(line)
        if line.strip().startswith("[+]"):
            return f'<span style="color: #00ff00;">{escaped}</span>'
        elif line.strip().startswith("[!!!]"):
            return f'<span style="color: #ff0000; font-weight: bold;">{escaped}</span>'
        elif line.strip().startswith("[!]"):
            return f'<span style="color: #ffaa00;">{escaped}</span>'
        elif line.strip().startswith("[-]"):
            return f'<span style="color: #ff6666;">{escaped}</span>'
        elif line.strip().startswith("[*]"):
            return f'<span style="color: #00aaff;">{escaped}</span>'
        elif "SENSITIVE" in line.upper() or "CRITICAL" in line.upper():
            return f'<span style="color: #ff4444; font-weight: bold;">{escaped}</span>'
        elif "FOUND" in line.upper() or "SUCCESS" in line.upper():
            return f'<span style="color: #00ff00;">{escaped}</span>'
        return escaped
    
    def _redact_sensitive_value(self, value: str, value_type: str = None) -> str:
        if not value or len(value) < 8:
            return "***"
        if value_type in ["credit_card", "ssn", "phone"]:
            return value[:4] + "*" * (len(value) - 8) + value[-4:]
        elif value_type in ["email"]:
            parts = value.split("@")
            if len(parts) == 2:
                return parts[0][:2] + "***@" + parts[1]
            return value[:3] + "***"
        elif value_type in ["jwt", "api_key", "token", "password", "hash"]:
            return value[:10] + "..." + value[-4:] if len(value) > 20 else value[:5] + "***"
        else:
            return value[:6] + "***" + value[-4:] if len(value) > 12 else value[:3] + "***"
    
    def _format_exploit_data_html(self, exploit_data):
        if not exploit_data:
            return ""
        
        import html as html_escape
        
        html = '<div class="exploit-data" style="background: #1a0a0a; border: 2px solid #dc3545; border-radius: 8px; padding: 20px; margin-top: 15px;">'
        html += '<h4 style="color: #dc3545; margin-bottom: 15px; font-size: 1.2em;">⚠️ EXPLOITATION DATA EXTRACTED</h4>'
        
        if exploit_data.get("credentials"):
            creds = exploit_data["credentials"]
            html += '<div style="margin-bottom: 15px;"><strong style="color: #ff6666;">🔑 Credentials:</strong><pre style="background: #0a0a0f; padding: 10px; border-radius: 4px; overflow-x: auto;">'
            for k, v in creds.items():
                if v:
                    html += f'{k}: {str(v)[:100]}\n'
            html += '</pre></div>'
        
        if exploit_data.get("files"):
            html += '<div style="margin-bottom: 15px;"><strong style="color: #ff6666;">📁 Files Extracted:</strong><ul style="margin-top: 5px;">'
            for filepath, content in list(exploit_data["files"].items())[:5]:
                html += f'<li><code>{html_escape.escape(filepath)}</code>: {len(content)} bytes</li>'
            html += '</ul></div>'
        
        if exploit_data.get("secrets"):
            html += '<div style="margin-bottom: 15px;"><strong style="color: #ff6666;">🔐 Secrets Found:</strong><ul style="margin-top: 5px;">'
            for secret in exploit_data["secrets"][:10]:
                html += f'<li>{secret.get("type")}: <code>{html_escape.escape(str(secret.get("value", ""))[:50])}...</code></li>'
            html += '</ul></div>'
        
        if exploit_data.get("baas_credentials"):
            total_tables = 0
            total_rows = 0
            total_sensitive = 0
            for cred in exploit_data["baas_credentials"]:
                total_tables += len(cred.get("accessible_tables", []))
                for tbl, data in cred.get("extracted_data", {}).items():
                    total_rows += data.get("row_count", 0)
                    total_sensitive += len(data.get("sensitive_values", []))
            
            html += '<div style="margin-bottom: 15px; background: #2a0a0a; padding: 20px; border-radius: 8px; border: 2px solid #ff4444;">'
            html += '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">'
            html += '<strong style="color: #ff4444; font-size: 1.2em;">🔓 BACKEND DATABASE EXPOSURE</strong>'
            html += '<div style="display: flex; gap: 15px;">'
            if total_tables > 0:
                html += f'<span style="background: #1a1a2e; padding: 5px 12px; border-radius: 4px; color: #00ff00;">{total_tables} Tables</span>'
            if total_rows > 0:
                html += f'<span style="background: #1a1a2e; padding: 5px 12px; border-radius: 4px; color: #00aaff;">{total_rows} Rows</span>'
            if total_sensitive > 0:
                html += f'<span style="background: #ff0000; padding: 5px 12px; border-radius: 4px; color: #fff; font-weight: bold;">{total_sensitive} Sensitive Values</span>'
            html += '</div></div>'
            
            for cred in exploit_data["baas_credentials"][:5]:
                status = "✓ EXPLOITED - DATA EXTRACTED" if cred.get("validated") else "⚠ Detected (not exploitable)"
                status_color = "#00ff00" if cred.get("validated") else "#ffaa00"
                
                html += f'<div style="margin-top: 15px; padding: 15px; background: #1a0a0a; border-radius: 8px; border-left: 4px solid {status_color};">'
                
                html += '<div style="margin-bottom: 10px;">'
                html += f'<strong style="color: #00aaff; font-size: 1.1em;">{html_escape.escape(cred.get("provider", "Unknown").upper())}</strong>'
                html += f' <code style="background: #0a0a0f; padding: 2px 8px; border-radius: 4px;">{html_escape.escape(cred.get("project_url", ""))}</code>'
                html += f'<br/><span style="color: {status_color}; font-weight: bold;">{status}</span>'
                html += '</div>'
                
                if cred.get("source_file") or cred.get("line_number"):
                    html += '<div style="background: #0a0a0f; padding: 10px; border-radius: 4px; margin-bottom: 10px;">'
                    html += '<strong style="color: #888;">📍 Discovery Location:</strong><br/>'
                    if cred.get("source_file"):
                        html += f'<code style="color: #00aaff;">{html_escape.escape(cred.get("source_file", ""))}</code>'
                    if cred.get("line_number"):
                        html += f' <span style="color: #888;">Line {cred.get("line_number")}</span>'
                    html += '</div>'
                
                if cred.get("api_key"):
                    key_preview = self._redact_sensitive_value(cred.get("api_key", ""), "api_key")
                    html += f'<div style="margin-bottom: 10px;"><strong style="color: #888;">🔑 API Key:</strong> <code style="color: #ff6666;">{html_escape.escape(key_preview)}</code></div>'
                
                if cred.get("accessible_tables"):
                    html += f'<div style="margin-bottom: 10px;"><strong style="color: #00ff00;">✓ Accessible Tables ({len(cred["accessible_tables"])}):</strong><br/>'
                    html += f'<code style="color: #00ff00; display: block; padding: 8px; background: #0a0a0f; border-radius: 4px; margin-top: 5px;">{html_escape.escape(", ".join(cred["accessible_tables"][:15]))}</code>'
                    html += '</div>'
                
                if cred.get("sensitive_data_types"):
                    html += '<div style="background: #3a0a0a; padding: 10px; border-radius: 4px; margin-bottom: 10px; border: 1px solid #ff0000;">'
                    html += '<strong style="color: #ff0000;">⚠️ SENSITIVE DATA FIELDS FOUND:</strong><br/>'
                    html += f'<code style="color: #ff6666;">{html_escape.escape(", ".join(cred["sensitive_data_types"][:20]))}</code>'
                    html += '</div>'
                
                if cred.get("extracted_data"):
                    html += '<div style="margin-bottom: 10px;"><strong style="color: #fff;">📊 Extracted Data Summary:</strong>'
                    html += '<table style="width: 100%; margin-top: 8px; border-collapse: collapse; background: #0a0a0f;">'
                    html += '<tr style="background: #1a1a2e;"><th style="padding: 8px; border: 1px solid #333; text-align: left; color: #00aaff;">Table</th>'
                    html += '<th style="padding: 8px; border: 1px solid #333; text-align: center; color: #00aaff;">Rows</th>'
                    html += '<th style="padding: 8px; border: 1px solid #333; text-align: left; color: #00aaff;">Columns</th>'
                    html += '<th style="padding: 8px; border: 1px solid #333; text-align: left; color: #00aaff;">Sensitive Fields</th>'
                    html += '<th style="padding: 8px; border: 1px solid #333; text-align: center; color: #00aaff;">Values</th></tr>'
                    for table, data in list(cred["extracted_data"].items())[:10]:
                        sensitive_count = len(data.get("sensitive_values", []))
                        row_style = "background: #2a0a0a;" if sensitive_count > 0 else ""
                        value_style = "color: #ff0000; font-weight: bold;" if sensitive_count > 0 else "color: #888;"
                        columns = data.get("columns", [])
                        col_display = ", ".join(columns[:5]) + ("..." if len(columns) > 5 else "")
                        html += f'<tr style="{row_style}">'
                        html += f'<td style="padding: 8px; border: 1px solid #333;"><code>{html_escape.escape(table)}</code></td>'
                        html += f'<td style="padding: 8px; border: 1px solid #333; text-align: center;">{data.get("row_count", 0)}</td>'
                        html += f'<td style="padding: 8px; border: 1px solid #333; font-size: 0.85em; color: #888;">{html_escape.escape(col_display)}</td>'
                        html += f'<td style="padding: 8px; border: 1px solid #333; color: #ff6666;">{html_escape.escape(", ".join(data.get("sensitive_fields", [])))}</td>'
                        html += f'<td style="padding: 8px; border: 1px solid #333; text-align: center; {value_style}">{sensitive_count}</td>'
                        html += '</tr>'
                    html += '</table></div>'
                    
                    has_sensitive_values = any(len(d.get("sensitive_values", [])) > 0 for d in cred.get("extracted_data", {}).values())
                    if has_sensitive_values:
                        html += '<details style="margin-top: 10px;"><summary style="cursor: pointer; color: #ff4444; font-weight: bold;">🔴 View Sensitive Values Extracted (Redacted)</summary>'
                        html += '<div style="background: #0a0a0f; padding: 15px; margin-top: 5px; border-radius: 4px; border: 1px solid #ff0000;">'
                        for table, data in cred.get("extracted_data", {}).items():
                            if data.get("sensitive_values"):
                                html += f'<div style="margin-bottom: 10px;"><strong style="color: #ff6666;">{html_escape.escape(table)}:</strong><ul style="margin: 5px 0 0 20px;">'
                                for sv in data["sensitive_values"][:10]:
                                    col = sv.get("column", "unknown")
                                    vtype = sv.get("type", "unknown")
                                    val = self._redact_sensitive_value(str(sv.get("value", "")), vtype)
                                    html += f'<li><code>{html_escape.escape(col)}</code> ({vtype}): <span style="color: #ff4444;">{html_escape.escape(val)}</span></li>'
                                if len(data["sensitive_values"]) > 10:
                                    html += f'<li style="color: #888;">... and {len(data["sensitive_values"]) - 10} more</li>'
                                html += '</ul></div>'
                        html += '</div></details>'
                
                if cred.get("exploitation_log"):
                    log_count = len(cred["exploitation_log"])
                    html += f'<details style="margin-top: 10px;"><summary style="cursor: pointer; color: #00aaff;">📜 View Full Exploitation Log ({log_count} entries)</summary>'
                    html += '<pre style="background: #0a0a0f; padding: 15px; margin-top: 5px; border-radius: 4px; font-size: 0.85em; max-height: 400px; overflow-y: auto; line-height: 1.5;">'
                    for log_line in cred["exploitation_log"]:
                        html += self._colorize_log_line(log_line) + '\n'
                    html += '</pre></details>'
                
                api_key = cred.get("api_key", "YOUR_KEY")
                project_url = cred.get("project_url", "")
                if cred.get("validated") and cred.get("accessible_tables"):
                    first_table = cred["accessible_tables"][0]
                    html += '<details style="margin-top: 10px;"><summary style="cursor: pointer; color: #ff6666;">🔴 Proof of Concept (curl)</summary>'
                    html += '<pre style="background: #0a0a0f; padding: 15px; margin-top: 5px; border-radius: 4px; font-size: 0.85em; overflow-x: auto;">'
                    html += f'curl -X GET "{html_escape.escape(project_url)}/rest/v1/{html_escape.escape(first_table)}?select=*&amp;limit=10" \\\n'
                    html += f'  -H "apikey: {html_escape.escape(api_key[:20])}..." \\\n'
                    html += f'  -H "Authorization: Bearer {html_escape.escape(api_key[:20])}..."'
                    html += '</pre></details>'
                
                html += '</div>'
            html += '</div>'
        
        if exploit_data.get("users"):
            html += '<div style="margin-bottom: 15px;"><strong style="color: #ff6666;">👤 Users Discovered:</strong> '
            html += ', '.join([html_escape.escape(u.get("name", "")) for u in exploit_data["users"][:10]])
            html += '</div>'
        
        if exploit_data.get("internal_services"):
            html += '<div style="margin-bottom: 15px;"><strong style="color: #ff6666;">🖥️ Internal Services:</strong><ul style="margin-top: 5px;">'
            for svc in exploit_data["internal_services"][:10]:
                html += f'<li>Port {svc.get("port")}: {html_escape.escape(str(svc.get("service")))} (status: {svc.get("status")})</li>'
            html += '</ul></div>'
        
        if exploit_data.get("cloud") or exploit_data.get("metadata"):
            html += f'<div style="margin-bottom: 15px;"><strong style="color: #ff6666;">☁️ Cloud Provider:</strong> {html_escape.escape(str(exploit_data.get("cloud", "Unknown")))}</div>'
        
        if exploit_data.get("rce_output"):
            html += '<div style="margin-bottom: 15px;"><strong style="color: #ff0000;">💀 RCE Output:</strong><pre style="background: #0a0a0f; padding: 10px; border-radius: 4px; overflow-x: auto;">'
            for cmd, output in list(exploit_data["rce_output"].items())[:5]:
                html += f'<span style="color: #00aaff;">[{html_escape.escape(cmd)}]</span>: {html_escape.escape(str(output)[:200])}\n'
            html += '</pre></div>'
        
        if exploit_data.get("env_vars"):
            html += '<div style="margin-bottom: 15px;"><strong style="color: #ff6666;">🔧 Environment Variables:</strong><pre style="background: #0a0a0f; padding: 10px; border-radius: 4px; overflow-x: auto;">'
            for k, v in list(exploit_data["env_vars"].items())[:10]:
                html += f'{html_escape.escape(k)}={html_escape.escape(str(v)[:80])}\n'
            html += '</pre></div>'
        
        html += '</div>'
        return html
    
    def _format_response_data_html(self, response_data):
        if not response_data:
            return ""
        
        import html as html_escape
        
        status = response_data.get("status", "N/A")
        headers = response_data.get("headers", {})
        text = response_data.get("text", "")[:1500]
        
        headers_html = ""
        if headers:
            headers_html = "<br>".join([f"<code>{k}: {html_escape.escape(str(v)[:100])}</code>" for k, v in list(headers.items())[:10]])
        
        return f"""
        <div class="response-data" style="background: #0a1a0a; border: 1px solid #1a3a1a; border-radius: 8px; padding: 15px; margin-top: 15px;">
            <h4 style="color: #4ade80; margin-bottom: 10px;">📥 Response Details</h4>
            <p><strong>Status Code:</strong> <code>{status}</code></p>
            <details style="margin-top: 10px;">
                <summary style="cursor: pointer; color: #4ade80;">Response Headers (click to expand)</summary>
                <div style="margin-top: 10px; padding: 10px; background: #0a0a0f; border-radius: 4px; font-size: 0.9em;">
                    {headers_html if headers_html else "<p>No headers captured</p>"}
                </div>
            </details>
            <details style="margin-top: 10px;">
                <summary style="cursor: pointer; color: #4ade80;">Response Body (click to expand)</summary>
                <pre style="background: #0a0a0f; padding: 15px; border-radius: 4px; overflow-x: auto; margin-top: 10px; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;"><code>{html_escape.escape(text)}</code></pre>
            </details>
        </div>
        """
    
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
            
            enriched["discovery_metadata"] = {
                "technique": r.get("technique"),
                "payload": r.get("payload"),
                "injection_point": r.get("injection_point"),
                "http_method": r.get("http_method"),
                "status_code": r.get("status_code"),
                "response_time": r.get("response_time"),
                "content_length": r.get("content_length"),
                "detection_method": r.get("detection_method"),
                "matched_pattern": r.get("matched_pattern"),
            }
            
            enriched["validation"] = {
                "validated": r.get("validated", False),
                "confidence": r.get("confidence", "MEDIUM"),
                "verification_method": r.get("verification_method"),
                "false_positive_check": r.get("false_positive_check"),
                "exploitation_success": r.get("exploitation_success", False),
            }
            
            if r.get("exploit_data", {}).get("baas_credentials"):
                baas_summary = []
                for cred in r["exploit_data"]["baas_credentials"]:
                    total_rows = sum(t.get("row_count", 0) for t in cred.get("extracted_data", {}).values())
                    total_sensitive = sum(len(t.get("sensitive_values", [])) for t in cred.get("extracted_data", {}).values())
                    baas_summary.append({
                        "provider": cred.get("provider"),
                        "project_url": cred.get("project_url"),
                        "validated": cred.get("validated"),
                        "tables_accessible": len(cred.get("accessible_tables", [])),
                        "total_rows_extracted": total_rows,
                        "sensitive_values_found": total_sensitive,
                        "sensitive_fields": cred.get("sensitive_data_types", []),
                        "source_file": cred.get("source_file"),
                        "line_number": cred.get("line_number"),
                    })
                enriched["baas_exploitation_summary"] = baas_summary
            
            enriched_results.append(enriched)
        
        data = {
            "scan_info": {
                "scan_id": self.scan_id,
                "timestamp": self.timestamp,
                "targets": self.targets,
                "modules": self.modules,
                "total_findings": len(self.results),
            },
            "executive_summary": self._generate_executive_summary(),
            "findings": enriched_results,
        }
        
        async with aiofiles.open(filepath, "w", encoding="utf-8") as f:
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
            confidence = r.get('confidence', 'N/A')
            confidence_colors = {"CONFIRMED": "#28a745", "HIGH": "#20c997", "MEDIUM": "#ffc107", "LOW": "#6c757d", "INFO": "#17a2b8"}
            confidence_color = confidence_colors.get(confidence, "#6c757d")
            
            request_html = ""
            if r.get('request_data'):
                req = r['request_data']
                request_html = f"""
                    <div class="request-data" style="background: #0a0a0f; border-radius: 8px; padding: 15px; margin-top: 15px;">
                        <h4 style="color: #00d4ff; margin-bottom: 10px;">🔗 Request Details</h4>
                        <p><strong>Method:</strong> {req.get('method', 'GET')}</p>
                        <p><strong>URL:</strong> <code>{req.get('url', 'N/A')}</code></p>
                        {f"<p><strong>Parameter:</strong> <code>{req.get('param')}</code></p>" if req.get('param') else ""}
                        {f"<p><strong>Payload:</strong> <code>{str(req.get('payload', ''))[:100]}</code></p>" if req.get('payload') else ""}
                    </div>
                """
            
            poc_html = ""
            if r.get('poc_data'):
                poc = r['poc_data']
                steps_html = ""
                if poc.get('reproduction_steps'):
                    steps_html = "<ol>" + "".join(f"<li>{step}</li>" for step in poc['reproduction_steps']) + "</ol>"
                
                import html as html_escape
                curl_escaped = html_escape.escape(poc.get('curl_command', ''))
                python_escaped = html_escape.escape(poc.get('python_code', '')[:500])
                
                poc_html = f"""
                    <div class="poc-section" style="background: #0d0d1a; border: 1px solid #1a1a3e; border-radius: 8px; padding: 20px; margin-top: 15px;">
                        <h4 style="color: #ff6b6b; margin-bottom: 15px;">🔴 Proof of Concept</h4>
                        <div style="margin-bottom: 15px;">
                            <h5 style="color: #00d4ff; margin-bottom: 10px;">Reproduction Steps</h5>
                            {steps_html if steps_html else "<p>See curl command below</p>"}
                        </div>
                        <div style="margin-bottom: 15px;">
                            <h5 style="color: #00d4ff; margin-bottom: 10px;">curl Command</h5>
                            <pre style="background: #0a0a0f; padding: 15px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-all;"><code>{curl_escaped}</code></pre>
                        </div>
                        <details style="margin-top: 15px;">
                            <summary style="cursor: pointer; color: #00d4ff;">Python PoC (click to expand)</summary>
                            <pre style="background: #0a0a0f; padding: 15px; border-radius: 4px; overflow-x: auto; margin-top: 10px;"><code>{python_escaped}</code></pre>
                        </details>
                    </div>
                """
            
            import html as html_esc
            
            discovery_html = ""
            if r.get('discovery') or r.get('payload') or r.get('technique') or r.get('exploitation_log'):
                discovery_html = '<div style="background: #0a0a1a; border: 1px solid #1a1a3e; border-radius: 8px; padding: 15px; margin-top: 15px;">'
                discovery_html += '<h4 style="color: #00d4ff; margin-bottom: 10px;">🔍 Discovery Details</h4>'
                discovery_html += '<table style="width: 100%; border-collapse: collapse;">'
                
                if r.get('technique'):
                    discovery_html += f'<tr><td style="padding: 5px; color: #888; width: 150px;">Technique:</td><td style="padding: 5px;"><code>{html_esc.escape(str(r.get("technique")))}</code></td></tr>'
                if r.get('payload'):
                    payload_display = str(r.get('payload', ''))[:200]
                    discovery_html += f'<tr><td style="padding: 5px; color: #888;">Payload Used:</td><td style="padding: 5px;"><code style="color: #ff6666;">{html_esc.escape(payload_display)}</code></td></tr>'
                if r.get('injection_point'):
                    discovery_html += f'<tr><td style="padding: 5px; color: #888;">Injection Point:</td><td style="padding: 5px;"><code>{html_esc.escape(str(r.get("injection_point")))}</code></td></tr>'
                if r.get('http_method'):
                    discovery_html += f'<tr><td style="padding: 5px; color: #888;">HTTP Method:</td><td style="padding: 5px;">{html_esc.escape(str(r.get("http_method")))}</td></tr>'
                if r.get('status_code'):
                    discovery_html += f'<tr><td style="padding: 5px; color: #888;">Response Code:</td><td style="padding: 5px;">{r.get("status_code")}</td></tr>'
                if r.get('response_time'):
                    discovery_html += f'<tr><td style="padding: 5px; color: #888;">Response Time:</td><td style="padding: 5px;">{r.get("response_time")}ms</td></tr>'
                if r.get('content_length'):
                    discovery_html += f'<tr><td style="padding: 5px; color: #888;">Content Length:</td><td style="padding: 5px;">{r.get("content_length")} bytes</td></tr>'
                if r.get('detection_method'):
                    discovery_html += f'<tr><td style="padding: 5px; color: #888;">Detection Method:</td><td style="padding: 5px;">{html_esc.escape(str(r.get("detection_method")))}</td></tr>'
                if r.get('matched_pattern'):
                    discovery_html += f'<tr><td style="padding: 5px; color: #888;">Pattern Matched:</td><td style="padding: 5px;"><code>{html_esc.escape(str(r.get("matched_pattern"))[:100])}</code></td></tr>'
                
                discovery_html += '</table>'
                
                if r.get('exploitation_log') and isinstance(r.get('exploitation_log'), list):
                    log_count = len(r['exploitation_log'])
                    discovery_html += f'<details style="margin-top: 10px;"><summary style="cursor: pointer; color: #00aaff;">📜 Exploitation Log ({log_count} steps)</summary>'
                    discovery_html += '<pre style="background: #0a0a0f; padding: 10px; margin-top: 5px; border-radius: 4px; font-size: 0.85em; max-height: 300px; overflow-y: auto;">'
                    for log_line in r['exploitation_log']:
                        discovery_html += self._colorize_log_line(str(log_line)) + '\n'
                    discovery_html += '</pre></details>'
                
                discovery_html += '</div>'
            
            validation_html = ""
            if r.get('validated') or r.get('verification_method') or r.get('false_positive_check'):
                validation_html = '<div style="background: #0a1a0a; border: 1px solid #1a3a1a; border-radius: 8px; padding: 15px; margin-top: 15px;">'
                validation_html += '<h4 style="color: #4ade80; margin-bottom: 10px;">✅ Validation</h4>'
                if r.get('validated'):
                    validation_html += f'<p><strong>Status:</strong> <span style="color: #00ff00;">CONFIRMED</span></p>'
                if r.get('verification_method'):
                    validation_html += f'<p><strong>Method:</strong> {html_esc.escape(str(r.get("verification_method")))}</p>'
                if r.get('false_positive_check'):
                    validation_html += f'<p><strong>FP Check:</strong> {html_esc.escape(str(r.get("false_positive_check")))}</p>'
                if r.get('exploitation_success'):
                    validation_html += f'<p><strong>Exploitation:</strong> <span style="color: #ff0000;">SUCCESSFUL</span></p>'
                validation_html += '</div>'
            
            findings_html += f"""
            <div class="finding" id="{finding_id}">
                <div class="finding-header">
                    <span class="severity" style="background-color: {color}">{r['severity']}</span>
                    <span class="module">{r['module']}</span>
                    <span class="confidence" style="background-color: {confidence_color}; padding: 5px 12px; border-radius: 4px; font-size: 0.8em; color: white;">Conf: {confidence}</span>
                    <span class="cvss">CVSS: {cvss['score']}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Target:</strong> {r.get('target', 'N/A')}</p>
                    <p><strong>URL:</strong> <code>{r.get('url', 'N/A')}</code></p>
                    <p><strong>Description:</strong> {r['description']}</p>
                    {f"<p><strong>Parameter:</strong> <code>{r.get('parameter')}</code></p>" if r.get('parameter') else ""}
                    {f"<p><strong>Evidence:</strong> <code>{str(r.get('evidence', ''))[:500]}</code></p>" if r.get('evidence') else ""}
                    {discovery_html}
                    {validation_html}
                    {self._format_exploit_data_html(r.get('exploit_data')) if r.get('exploit_data') else ""}
                    {request_html}
                    {self._format_response_data_html(r.get('response_data')) if r.get('response_data') else ""}
                    {poc_html}
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
        async with aiofiles.open(filepath, "w", encoding="utf-8") as f:
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
        async with aiofiles.open(filepath, "w", encoding="utf-8") as f:
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
        async with aiofiles.open(filepath, "w", encoding="utf-8") as f:
            await f.write(output.getvalue())
        return str(filepath)
    
    async def save_sarif(self, filename):
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Lantern",
                        "version": "2.0",
                        "informationUri": "https://github.com/lantern",
                        "rules": self._generate_sarif_rules(),
                    }
                },
                "results": self._generate_sarif_results(),
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": self.timestamp,
                }],
            }],
        }
        
        filepath = self.reports_dir / filename if not os.path.dirname(filename) else Path(filename)
        async with aiofiles.open(filepath, "w", encoding="utf-8") as f:
            await f.write(json.dumps(sarif, indent=2))
        return str(filepath)
    
    def _generate_sarif_rules(self) -> List[Dict]:
        rules = {}
        
        for r in self.results:
            module = r.get("module", "unknown")
            if module not in rules:
                cvss = self._get_cvss(r)
                remediation = self._get_remediation(r)
                
                severity_map = {
                    "CRITICAL": "error",
                    "HIGH": "error",
                    "MEDIUM": "warning",
                    "LOW": "note",
                    "INFO": "none",
                }
                
                rules[module] = {
                    "id": f"LANTERN-{module.upper()}",
                    "name": remediation.get("title", module),
                    "shortDescription": {"text": remediation.get("title", module)},
                    "fullDescription": {"text": remediation.get("fix", "Security vulnerability detected")},
                    "defaultConfiguration": {
                        "level": severity_map.get(r.get("severity", "MEDIUM"), "warning")
                    },
                    "properties": {
                        "security-severity": str(cvss["score"]),
                        "tags": ["security", module],
                    },
                }
        
        return list(rules.values())
    
    def _generate_sarif_results(self) -> List[Dict]:
        results = []
        
        for r in self.results:
            cvss = self._get_cvss(r)
            
            result = {
                "ruleId": f"LANTERN-{r.get('module', 'unknown').upper()}",
                "message": {"text": r.get("description", "Vulnerability detected")},
                "level": self._severity_to_sarif_level(r.get("severity", "MEDIUM")),
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": r.get("url", "unknown"),
                        },
                    },
                }],
                "properties": {
                    "confidence": r.get("confidence", "MEDIUM"),
                    "cvss": cvss["score"],
                    "parameter": r.get("parameter"),
                },
            }
            
            if r.get("evidence"):
                result["fingerprints"] = {
                    "evidence": r["evidence"][:200]
                }
            
            results.append(result)
        
        return results
    
    def _severity_to_sarif_level(self, severity: str) -> str:
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "none",
        }
        return mapping.get(severity, "warning")
    
    async def save_obsidian(self, vault_path: str = None):
        import re
        
        if vault_path:
            obsidian_dir = Path(vault_path) / "LANTERN Reports"
        else:
            obsidian_dir = self.reports_dir / "obsidian"
        
        obsidian_dir.mkdir(parents=True, exist_ok=True)
        findings_dir = obsidian_dir / "Findings"
        findings_dir.mkdir(exist_ok=True)
        
        target_name = "unknown"
        if self.targets:
            target_name = re.sub(r'https?://', '', str(self.targets[0]))
            target_name = re.sub(r'[^\w\-.]', '_', target_name)[:50]
        
        exec_summary = self._generate_executive_summary()
        date_str = datetime.now().strftime("%Y-%m-%d")
        
        severity_tags = []
        for r in self.results:
            sev = r.get("severity", "").lower()
            if sev and sev not in severity_tags:
                severity_tags.append(sev)
        
        module_tags = list(set([r.get("module", "") for r in self.results if r.get("module")]))[:5]
        
        all_tags = ["lantern", "scan", target_name] + severity_tags[:3] + module_tags[:3]
        tags_str = ", ".join(all_tags)
        
        main_report = f"""---
tags: [{tags_str}]
target: {self.targets[0] if self.targets else "unknown"}
scan_date: {date_str}
scan_id: {self.scan_id}
total_findings: {len(self.results)}
risk_level: {exec_summary['risk_level']}
critical: {exec_summary['critical']}
high: {exec_summary['high']}
medium: {exec_summary['medium']}
---

# LANTERN Scan: {target_name}

## Quick Info
| Property | Value |
|----------|-------|
| Target | `{self.targets[0] if self.targets else "N/A"}` |
| Scan Date | {date_str} |
| Risk Level | **{exec_summary['risk_level']}** |
| Total Findings | {len(self.results)} |

## Executive Summary

{exec_summary['summary']}

**Recommendation:** {exec_summary['recommendation']}

## Severity Breakdown

| Severity | Count |
|----------|-------|
| Critical | {exec_summary['critical']} |
| High | {exec_summary['high']} |
| Medium | {exec_summary['medium']} |

## Findings

"""
        
        finding_files = []
        for i, r in enumerate(self.results, 1):
            cvss = self._get_cvss(r)
            remediation = self._get_remediation(r)
            
            finding_name = f"{r['module']}_{i}_{target_name}"
            finding_name = re.sub(r'[^\w\-]', '_', finding_name)[:60]
            
            main_report += f"- [[{finding_name}|{r['severity']}: {r['description'][:50]}...]]\n"
            
            finding_content = f"""---
tags: [finding, {r['module']}, {r['severity'].lower()}]
target: "[[{target_name}_{date_str}]]"
module: {r['module']}
severity: {r['severity']}
cvss: {cvss['score']}
url: {r.get('url', 'N/A')}
parameter: {r.get('parameter', 'N/A')}
status: open
---

# {r['description']}

## Summary
| Property | Value |
|----------|-------|
| Module | `{r['module']}` |
| Severity | **{r['severity']}** |
| CVSS Score | {cvss['score']} |
| CVSS Vector | `{cvss['vector']}` |

## Affected URL
`{r.get('url', 'N/A')}`

"""
            if r.get('parameter'):
                finding_content += f"**Parameter:** `{r.get('parameter')}`\n\n"
            
            if r.get('evidence'):
                evidence = str(r.get('evidence', ''))[:500]
                finding_content += f"""## Evidence
```
{evidence}
```

"""
            
            if r.get('payload'):
                finding_content += f"""## Payload Used
```
{r.get('payload', '')}
```

"""
            
            finding_content += f"""## Remediation

### {remediation['title']}

{remediation['fix']}

```python
{remediation['code']}
```

## Related
- [[{target_name}_{date_str}|Main Scan Report]]
- [[{r['module']}|{r['module'].upper()} Methodology]]
"""
            
            finding_path = findings_dir / f"{finding_name}.md"
            async with aiofiles.open(finding_path, "w", encoding="utf-8") as f:
                await f.write(finding_content)
            finding_files.append(str(finding_path))
        
        main_report += f"""

## Modules Run
{', '.join([f'`{m}`' for m in self.modules])}

## Notes
- This report was generated by [[LANTERN]]
- CVSS scores are estimates based on vulnerability type
- Manual verification recommended for all findings

## Related
- [[Targets MOC]]
- [[Methodology MOC]]
"""
        
        main_path = obsidian_dir / f"{target_name}_{date_str}.md"
        async with aiofiles.open(main_path, "w", encoding="utf-8") as f:
            await f.write(main_report)
        
        return {
            "main_report": str(main_path),
            "findings": finding_files,
            "directory": str(obsidian_dir),
        }
    
    async def save_with_pocs(self, base_filename: str, include_formats: List[str] = None):
        if include_formats is None:
            include_formats = ["html", "json", "sarif"]
        
        results_dir = self.reports_dir / f"scan_{self.scan_id}"
        results_dir.mkdir(exist_ok=True)
        
        pocs_dir = results_dir / "pocs"
        pocs_dir.mkdir(exist_ok=True)
        
        enriched_results = []
        for i, r in enumerate(self.results):
            poc = self.poc_generator.generate(r)
            
            poc_filename = f"poc_{i+1}_{r.get('module', 'unknown')}.md"
            poc_path = pocs_dir / poc_filename
            async with aiofiles.open(poc_path, "w", encoding="utf-8") as f:
                await f.write(poc.to_markdown())
            
            enriched = r.copy()
            enriched["poc_file"] = str(poc_path)
            enriched["cvss"] = poc.cvss.to_dict()
            enriched["poc_data"] = {
                "curl_command": poc.curl_command,
                "python_code": poc.python_code,
                "reproduction_steps": poc.reproduction_steps,
                "raw_request": poc.raw_request[:1000] if poc.raw_request else "",
                "remediation": poc.remediation,
            }
            enriched_results.append(enriched)
        
        original_results = self.results
        self.results = enriched_results
        
        generated_files = []
        
        if "html" in include_formats:
            html_file = await self.save_html(str(results_dir / f"{base_filename}.html"))
            generated_files.append(html_file)
        
        if "json" in include_formats:
            json_file = await self.save_json(str(results_dir / f"{base_filename}.json"))
            generated_files.append(json_file)
        
        if "sarif" in include_formats:
            sarif_file = await self.save_sarif(str(results_dir / f"{base_filename}.sarif"))
            generated_files.append(sarif_file)
        
        if "markdown" in include_formats:
            md_file = await self.save_markdown(str(results_dir / f"{base_filename}.md"))
            generated_files.append(md_file)
        
        if "jira" in include_formats:
            jira_file = await self.save_jira_csv(str(results_dir / f"{base_filename}_jira.csv"))
            generated_files.append(jira_file)
        
        if "obsidian" in include_formats:
            vault_path = os.environ.get("BLACK_OBSIDIAN_VAULT")
            obsidian_result = await self.save_obsidian(vault_path)
            generated_files.append(obsidian_result["main_report"])
        
        self.results = original_results
        
        return {
            "directory": str(results_dir),
            "files": generated_files,
            "poc_count": len(enriched_results),
        }
    
    def get_summary(self) -> Dict[str, Any]:
        exec_summary = self._generate_executive_summary()
        
        severity_counts = {}
        module_counts = {}
        confidence_counts = {}
        
        for r in self.results:
            sev = r.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            mod = r.get("module", "unknown")
            module_counts[mod] = module_counts.get(mod, 0) + 1
            
            conf = r.get("confidence", "UNKNOWN")
            confidence_counts[conf] = confidence_counts.get(conf, 0) + 1
        
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "targets": len(self.targets),
            "modules_run": len(self.modules),
            "total_findings": len(self.results),
            "severity_breakdown": severity_counts,
            "module_breakdown": module_counts,
            "confidence_breakdown": confidence_counts,
            "executive_summary": exec_summary,
        }