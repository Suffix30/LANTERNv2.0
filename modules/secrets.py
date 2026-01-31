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
        "Password in URL": (r'[a-zA-Z]+://[^:]+:[^@]+@', "HIGH"),
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
        "Phone Number": (r'\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', "INFO"),
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
            masked = [m[:8] + "..." + m[-4:] if len(m) > 16 else m[:4] + "..." for m in data["matches"]]
            self.add_finding(
                data["severity"],
                f"Secret found: {secret_name}",
                url=url,
                evidence=f"Values: {', '.join(masked)}"
            )
    
    async def _scan_sensitive_files(self, base_url):
        for path in self.sensitive_files:
            url = f"{base_url}{path}"
            resp = await self.http.get(url)
            
            if resp.get("status") == 200 and len(resp.get("text", "")) > 10:
                if "<!doctype html" not in resp["text"].lower()[:100]:
                    self.add_finding(
                        "CRITICAL",
                        f"Sensitive file exposed: {path}",
                        url=url,
                        evidence=f"Size: {len(resp['text'])} bytes"
                    )
                    
                    await self._scan_content(url, resp["text"])
