import re
from modules.base import BaseModule
from core.http import get_base_url

class DisclosureModule(BaseModule):
    name = "disclosure"
    description = "Information Disclosure Scanner"
    
    sensitive_patterns = {
        "password": (r"password\s*[:=]\s*['\"]?[\w@#$%^&*]+", "HIGH"),
        "api_key": (r"api[_-]?key\s*[:=]\s*['\"]?[\w-]{20,}", "HIGH"),
        "aws_key": (r"AKIA[0-9A-Z]{16}", "CRITICAL"),
        "aws_secret": (r"['\"][0-9a-zA-Z/+]{40}['\"]", "HIGH"),
        "private_key": (r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----", "CRITICAL"),
        "jwt": (r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", "MEDIUM"),
        "email": (r"[\w.-]+@[\w.-]+\.\w{2,}", "INFO"),
        "ip_address": (r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b", "LOW"),
        "credit_card": (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "CRITICAL"),
        "ssn": (r"\b\d{3}-\d{2}-\d{4}\b", "CRITICAL"),
        "database_conn": (r"(?:mysql|postgres|mongodb|redis)://[\w:@]+", "CRITICAL"),
    }
    
    sensitive_files = [
        (".git/config", "Git configuration exposed"),
        (".git/HEAD", "Git repository exposed"),
        (".env", "Environment file exposed"),
        (".env.local", "Local environment file exposed"),
        (".env.production", "Production environment file exposed"),
        ("wp-config.php", "WordPress config exposed"),
        ("config.php", "PHP config exposed"),
        ("web.config", "IIS config exposed"),
        (".htaccess", "Apache config exposed"),
        (".htpasswd", "Apache password file exposed"),
        ("phpinfo.php", "PHP info exposed"),
        ("info.php", "PHP info exposed"),
        ("server-status", "Apache server status exposed"),
        ("elmah.axd", "ELMAH error log exposed"),
        (".svn/entries", "SVN repository exposed"),
        (".DS_Store", "macOS metadata exposed"),
        ("backup.sql", "Database backup exposed"),
        ("dump.sql", "Database dump exposed"),
        ("database.sql", "Database file exposed"),
        ("robots.txt", "Robots.txt found"),
        ("sitemap.xml", "Sitemap found"),
        ("crossdomain.xml", "Flash crossdomain policy found"),
        ("clientaccesspolicy.xml", "Silverlight policy found"),
        ("/.well-known/security.txt", "Security.txt found"),
        ("/api/", "API endpoint found"),
        ("/swagger/", "Swagger documentation found"),
        ("/api/swagger", "API Swagger found"),
        ("/graphql", "GraphQL endpoint found"),
        ("/admin", "Admin panel found"),
        ("/admin/", "Admin panel found"),
        ("/administrator", "Administrator panel found"),
        ("/phpmyadmin", "phpMyAdmin found"),
        ("/pma", "phpMyAdmin found"),
    ]
    
    async def scan(self, target):
        self.findings = []
        base_url = get_base_url(target)
        
        await self._scan_sensitive_files(base_url)
        await self._scan_response_content(target)
        await self._scan_error_disclosure(target)
        
        return self.findings
    
    async def _scan_sensitive_files(self, base_url):
        for path, description in self.sensitive_files:
            url = f"{base_url}/{path.lstrip('/')}"
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                if len(resp["text"]) > 0:
                    severity = self._determine_severity(path, resp["text"])
                    
                    if self._is_valid_response(path, resp["text"]):
                        self.add_finding(
                            severity,
                            description,
                            url=url,
                            evidence=f"Status: 200, Size: {len(resp['text'])} bytes"
                        )
    
    async def _scan_response_content(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        for name, (pattern, severity) in self.sensitive_patterns.items():
            matches = re.findall(pattern, resp["text"], re.IGNORECASE)
            if matches:
                self.add_finding(
                    severity,
                    f"Sensitive data exposure: {name}",
                    url=target,
                    evidence=f"Found {len(matches)} instance(s)"
                )
    
    async def _scan_error_disclosure(self, target):
        error_triggers = [
            f"{target}/'",
            f"{target}/\"",
            f"{target}/%00",
            f"{target}/../../../",
            f"{target}/?id=1'",
        ]
        
        error_patterns = [
            (r"stack trace:", "HIGH"),
            (r"exception.*at\s+\w+\.", "MEDIUM"),
            (r"<b>Warning</b>:.*on line", "MEDIUM"),
            (r"<b>Fatal error</b>:", "HIGH"),
            (r"Traceback \(most recent call last\)", "MEDIUM"),
            (r"Microsoft OLE DB Provider", "MEDIUM"),
            (r"ODBC.*Driver", "MEDIUM"),
            (r"syntax error", "LOW"),
            (r"\.php on line \d+", "MEDIUM"),
            (r"\.asp on line \d+", "MEDIUM"),
        ]
        
        for trigger in error_triggers:
            resp = await self.http.get(trigger)
            if resp.get("status"):
                for pattern, severity in error_patterns:
                    if re.search(pattern, resp["text"], re.IGNORECASE):
                        self.add_finding(
                            severity,
                            "Verbose error message disclosure",
                            url=trigger,
                            evidence=f"Error pattern detected"
                        )
                        return
    
    def _determine_severity(self, path, content):
        critical_files = [".env", "config.php", "wp-config.php", ".htpasswd", 
                         "backup.sql", "dump.sql", ".git/config"]
        high_files = [".git/HEAD", "web.config", "phpinfo.php"]
        
        for f in critical_files:
            if f in path:
                return "CRITICAL"
        for f in high_files:
            if f in path:
                return "HIGH"
        return "MEDIUM"
    
    def _is_valid_response(self, path, content):
        if len(content) < 10:
            return False
        
        if "404" in content.lower() and "not found" in content.lower():
            return False
        
        if path.endswith(".git/config") and "[core]" in content:
            return True
        if path.endswith(".git/HEAD") and "ref:" in content:
            return True
        if ".env" in path and "=" in content:
            return True
        if "phpinfo" in path and "PHP Version" in content:
            return True
        if path.endswith("robots.txt") and ("User-agent" in content or "Disallow" in content):
            return True
        
        return True
