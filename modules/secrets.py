import re
from modules.base import BaseModule
from core.http import get_base_url

class SecretsModule(BaseModule):
    name = "secrets"
    description = "Secrets and Credentials Scanner"
    
    secret_patterns = {
        "AWS Access Key": (r'AKIA[0-9A-Z]{16}', "CRITICAL"),
        "AWS Secret Key": (r'[0-9a-zA-Z/+]{40}', "CRITICAL"),
        "GitHub Token": (r'ghp_[a-zA-Z0-9]{36}', "CRITICAL"),
        "GitHub OAuth": (r'gho_[a-zA-Z0-9]{36}', "CRITICAL"),
        "GitLab Token": (r'glpat-[a-zA-Z0-9\-]{20}', "CRITICAL"),
        "Slack Token": (r'xox[baprs]-[a-zA-Z0-9\-]+', "CRITICAL"),
        "Slack Webhook": (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+', "HIGH"),
        "Discord Webhook": (r'https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_\-]+', "HIGH"),
        "Google API Key": (r'AIza[0-9A-Za-z\-_]{35}', "HIGH"),
        "Google OAuth": (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', "HIGH"),
        "Firebase": (r'[a-z0-9\-]+\.firebaseio\.com', "MEDIUM"),
        "Firebase Config": (r'apiKey[\'"]?\s*[:=]\s*[\'"]AIza[0-9A-Za-z\-_]{35}', "HIGH"),
        "Heroku API Key": (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', "HIGH"),
        "Mailgun API Key": (r'key-[0-9a-zA-Z]{32}', "HIGH"),
        "Mailchimp API Key": (r'[0-9a-f]{32}-us[0-9]{1,2}', "HIGH"),
        "Stripe API Key": (r'sk_live_[0-9a-zA-Z]{24}', "CRITICAL"),
        "Stripe Publishable": (r'pk_live_[0-9a-zA-Z]{24}', "MEDIUM"),
        "Square Access Token": (r'sq0atp-[0-9A-Za-z\-_]{22}', "CRITICAL"),
        "Square OAuth": (r'sq0csp-[0-9A-Za-z\-_]{43}', "CRITICAL"),
        "Twilio API Key": (r'SK[0-9a-fA-F]{32}', "HIGH"),
        "Twilio Account SID": (r'AC[a-zA-Z0-9_\-]{32}', "MEDIUM"),
        "SendGrid API Key": (r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}', "CRITICAL"),
        "OpenAI API Key": (r'sk-[a-zA-Z0-9]{48}', "CRITICAL"),
        "NPM Token": (r'npm_[a-zA-Z0-9]{36}', "HIGH"),
        "PyPI Token": (r'pypi-[a-zA-Z0-9_\-]{50,}', "HIGH"),
        "Private Key": (r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', "CRITICAL"),
        "JWT Token": (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "MEDIUM"),
        "Basic Auth": (r'[Bb]asic [A-Za-z0-9+/=]{10,}', "HIGH"),
        "Bearer Token": (r'[Bb]earer [a-zA-Z0-9_\-\.]+', "HIGH"),
        "Password in URL": (r'(?:https?|ftp|mysql|postgres|mongodb|redis|amqp)://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_!@#$%^&*()-]+@[a-zA-Z0-9.-]+', "HIGH"),
        "Database URL": (r'(?:mysql|postgres|mongodb|redis)://[^\s"\']+', "CRITICAL"),
        "S3 Bucket": (r's3://[a-zA-Z0-9\.\-_]+', "MEDIUM"),
        "S3 URL": (r'[a-zA-Z0-9\-]+\.s3\.amazonaws\.com', "MEDIUM"),
        "Supabase URL": (r'https://[a-zA-Z0-9_-]+\.supabase\.co', "CRITICAL"),
        "Supabase Key": (r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}', "CRITICAL"),
        "Supabase Config": (r'supabaseUrl[\'"]?\s*[:=]\s*[\'"]https://[^"\']+\.supabase\.co', "CRITICAL"),
        "Appwrite URL": (r'https://[a-zA-Z0-9_.-]+\.appwrite\.io', "HIGH"),
        "PocketBase URL": (r'new PocketBase\s*\([\'"][^\'"]+[\'"]', "HIGH"),
        "Amplify Config": (r'aws_appsync_graphqlEndpoint[\'"]?\s*[:=]', "HIGH"),
        "Cognito Pool": (r'aws_user_pools_id[\'"]?\s*[:=]\s*[\'"][^\'"]+', "HIGH"),
        "IPv4 Private": (r'\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b', "LOW"),
        "Email": (r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', "INFO"),
        "Phone Number": (r'(?<![.\d/])(?:\+1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}(?![.\d])', "INFO"),
        "SSN": (r'\b\d{3}-\d{2}-\d{4}\b', "CRITICAL"),
        "Credit Card": (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', "CRITICAL"),
    }
    
    sensitive_files = [
        "/.env",
        "/.env.local",
        "/.env.development",
        "/.env.production",
        "/.env.backup",
        "/config.json",
        "/config.yml",
        "/config.yaml",
        "/secrets.json",
        "/secrets.yml",
        "/credentials.json",
        "/credentials.xml",
        "/.aws/credentials",
        "/.docker/config.json",
        "/.npmrc",
        "/.netrc",
        "/.htpasswd",
        "/id_rsa",
        "/id_dsa",
        "/id_ecdsa",
        "/.ssh/authorized_keys",
        "/wp-config.php.bak",
        "/config.php.bak",
        "/database.yml",
        "/application.yml",
        "/application.properties",
        "/appsettings.json",
        "/web.config.bak",
        "/.bash_history",
        "/.zsh_history",
        "/.mysql_history",
    ]
    
    async def scan(self, target):
        self.findings = []
        base_url = get_base_url(target)
        
        resp = await self.http.get(target)
        if resp.get("status"):
            await self._scan_content(target, resp["text"])
        
        await self._scan_sensitive_files(base_url)
        
        return self.findings
    
    async def _scan_content(self, url, content):
        found_secrets = {}
        
        for secret_name, (pattern, severity) in self.secret_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                unique_matches = list(set(matches))[:3]
                if secret_name not in found_secrets:
                    found_secrets[secret_name] = {
                        "severity": severity,
                        "matches": unique_matches,
                    }
        
        for secret_name, data in found_secrets.items():
            full_matches = data["matches"][:3]
            masked = []
            for m in full_matches:
                if len(m) > 40:
                    masked.append(m[:20] + "..." + m[-10:])
                elif len(m) > 20:
                    masked.append(m[:12] + "..." + m[-6:])
                else:
                    masked.append(m)
            pattern_used = self.secret_patterns.get(secret_name, (None, None))[0]
            grep_cmd = f"grep -oE '{pattern_used}' response.html" if pattern_used else "N/A"
            self.add_finding(
                data["severity"],
                f"Secret found: {secret_name}",
                url=url,
                evidence=f"Found {len(data['matches'])} match(es): {', '.join(masked)}",
                technique="Pattern-based secret detection",
                payload=None,
                injection_point="Response body content",
                http_method="GET",
                detection_method=f"Regex pattern matching for {secret_name}",
                matched_pattern=pattern_used if pattern_used else "N/A",
                secret_type=secret_name,
                match_count=len(data["matches"]),
                grep_command=grep_cmd,
            )
    
    spa_indicators = [
        "<!doctype html",
        "<html",
        "<head>",
        "<script",
        "ng-app",
        "ng-controller",
        "__next",
        "__nuxt",
        "data-reactroot",
        "data-react",
        "__vue__",
        "app-root",
        "<app-root>",
        "<router-outlet>",
        "window.__INITIAL_STATE__",
        "window.__NUXT__",
        "window.__NEXT_DATA__",
    ]
    
    file_content_patterns = {
        ".env": [r'^[A-Z_]+=', r'^\s*#', r'DATABASE_URL=', r'API_KEY=', r'SECRET='],
        ".yml": [r'^\s*[a-z_]+:', r'---', r'^\s*-\s+'],
        ".yaml": [r'^\s*[a-z_]+:', r'---', r'^\s*-\s+'],
        ".json": [r'^\s*\{', r'^\s*\[', r'"[^"]+"\s*:'],
        ".xml": [r'<\?xml', r'<[a-zA-Z]+>', r'</[a-zA-Z]+>'],
        ".properties": [r'^[a-z._]+=', r'^\s*#'],
        ".php": [r'<\?php', r'\$[a-zA-Z_]+\s*='],
        ".htpasswd": [r'^[a-zA-Z0-9_]+:\$', r'^[a-zA-Z0-9_]+:\{'],
        "id_rsa": [r'-----BEGIN', r'PRIVATE KEY'],
        "id_dsa": [r'-----BEGIN', r'PRIVATE KEY'],
        "id_ecdsa": [r'-----BEGIN', r'PRIVATE KEY'],
        "authorized_keys": [r'^ssh-rsa ', r'^ssh-ed25519 ', r'^ecdsa-sha'],
        ".history": [r'^[a-z]+\s', r'^cd\s', r'^ls\s', r'^cat\s', r'^sudo\s'],
        "credentials": [r'\[default\]', r'aws_access_key_id', r'aws_secret_access_key'],
        ".npmrc": [r'^//registry', r'_authToken=', r'^registry='],
        ".netrc": [r'^machine\s', r'login\s', r'password\s'],
        ".docker/config.json": [r'"auths"', r'"auth":', r'"https://'],
    }
    
    def _is_spa_response(self, content):
        lower_content = content.lower()[:2000]
        spa_score = sum(1 for indicator in self.spa_indicators if indicator.lower() in lower_content)
        return spa_score >= 2
    
    def _validate_file_content(self, path, content):
        if self._is_spa_response(content):
            return False, "SPA fallback detected"
        
        for ext, patterns in self.file_content_patterns.items():
            if ext in path.lower():
                matches = sum(1 for p in patterns if re.search(p, content[:1000], re.MULTILINE | re.IGNORECASE))
                if matches >= 1:
                    return True, f"Content matches {ext} pattern ({matches} indicators)"
                return False, f"Content doesn't match expected {ext} format"
        
        if any(c in content[:500] for c in ['=', ':', '{', 'password', 'secret', 'key', 'token']):
            return True, "Contains config-like content"
        
        return False, "Unknown format, no validation"
    
    async def _scan_sensitive_files(self, base_url):
        baseline_resp = await self.http.get(f"{base_url}/this-path-should-not-exist-abc123xyz")
        baseline_size = len(baseline_resp.get("text", "")) if baseline_resp.get("status") == 200 else 0
        baseline_is_spa = self._is_spa_response(baseline_resp.get("text", "")) if baseline_resp.get("status") == 200 else False
        
        for path in self.sensitive_files:
            url = f"{base_url}{path}"
            resp = await self.http.get(url)
            
            if resp.get("status") != 200:
                continue
            
            content = resp.get("text", "")
            content_len = len(content)
            
            if content_len < 10:
                continue
            
            if baseline_is_spa and abs(content_len - baseline_size) < 100:
                continue
            
            is_valid, validation_msg = self._validate_file_content(path, content)
            
            if is_valid:
                content_type = resp.get("headers", {}).get("content-type", "unknown")
                content_preview = content[:200].replace('\n', ' ').replace('\r', '') if content else ""
                self.add_finding(
                    "CRITICAL",
                    f"Sensitive file exposed: {path}",
                    url=url,
                    evidence=f"Size: {content_len} bytes | Validation: {validation_msg} | Type: {content_type}",
                    confidence="HIGH",
                    request_data={"method": "GET", "url": url},
                    response_data={"status": resp.get("status"), "headers": resp.get("headers", {}), "text": content[:1000]},
                    technique="Sensitive file enumeration",
                    injection_point=f"Path: {path}",
                    http_method="GET",
                    status_code=resp.get("status"),
                    content_length=content_len,
                    detection_method="File path enumeration with content validation",
                    matched_pattern=f"File exists, content validated: {validation_msg}",
                )
                await self._scan_content(url, content)
