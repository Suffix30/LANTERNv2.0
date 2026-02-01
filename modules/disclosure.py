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
        (".gitignore", "Git ignore exposed"),
        (".env", "Environment file exposed"),
        (".env.local", "Local environment file exposed"),
        (".env.production", "Production environment file exposed"),
        (".env.php", "PHP env file exposed"),
        ("environment", "Environment file exposed"),
        ("wp-config.php", "WordPress config exposed"),
        ("config.php", "PHP config exposed"),
        ("config.yaml", "Config YAML exposed"),
        ("config.yml", "Config YAML exposed"),
        ("config.json", "Config JSON exposed"),
        ("config.ini", "Config INI exposed"),
        ("web.config", "IIS config exposed"),
        (".htaccess", "Apache config exposed"),
        (".htpasswd", "Apache password file exposed"),
        ("phpinfo.php", "PHP info exposed"),
        ("info.php", "PHP info exposed"),
        ("php.ini", "PHP ini exposed"),
        ("server-status", "Apache server status exposed"),
        ("elmah.axd", "ELMAH error log exposed"),
        (".svn/entries", "SVN repository exposed"),
        (".hg/.hgignore", "Mercurial repo exposed"),
        (".DS_Store", "macOS metadata exposed"),
        ("backup.sql", "Database backup exposed"),
        ("dump.sql", "Database dump exposed"),
        ("database.sql", "Database file exposed"),
        ("localsettings.php", "Local settings exposed"),
        ("settings.php", "Settings exposed"),
        ("db.php", "DB config exposed"),
        ("database.php", "Database config exposed"),
        ("appsettings.json", "App settings exposed"),
        ("composer.lock", "Composer lock exposed"),
        ("package-lock.json", "NPM lock exposed"),
        ("yarn.lock", "Yarn lock exposed"),
        ("Dockerfile", "Dockerfile exposed"),
        ("docker-compose.yml", "Docker Compose exposed"),
        ("Makefile", "Makefile exposed"),
        ("requirements.txt", "Requirements exposed"),
        ("Gemfile", "Gemfile exposed"),
        ("Pipfile", "Pipfile exposed"),
        ("Pipfile.lock", "Pipfile lock exposed"),
        ("setup.py", "Setup script exposed"),
        ("robots.txt", "Robots.txt found"),
        ("sitemap.xml", "Sitemap found"),
        ("sitemap_index.xml", "Sitemap index found"),
        ("sitemap/sitemap.xml", "Sitemap found"),
        ("sitemap/sitemap-index.xml", "Sitemap index found"),
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
        
        self.baseline_response = await self._get_baseline_response(base_url)
        
        await self._scan_sensitive_files(base_url)
        await self._scan_response_content(target)
        await self._scan_error_disclosure(target)
        await self._check_security_txt(base_url)
        await self._scan_html_comments(target)
        return self.findings
    
    async def _get_baseline_response(self, base_url):
        from core.utils import random_string
        fake_paths = [
            f"/{random_string(12)}.{random_string(3)}",
            f"/{random_string(8)}/{random_string(6)}",
        ]
        
        baselines = []
        for fake_path in fake_paths:
            resp = await self.http.get(f"{base_url}{fake_path}")
            if resp.get("status"):
                baselines.append({
                    "status": resp.get("status", 404),
                    "length": len(resp.get("text", "")),
                    "text_hash": hash(resp.get("text", "")[:500]),
                })
        
        if not baselines:
            return {"status": 404, "length": 0, "text_hash": 0}
        
        return {
            "status": baselines[0].get("status", 404),
            "length": baselines[0].get("length", 0),
            "text_hash": baselines[0].get("text_hash", 0),
        }
    
    def _is_baseline_response(self, resp):
        if not self.baseline_response or not resp.get("text"):
            return False
        
        resp_hash = hash(resp.get("text", "")[:500])
        resp_len = len(resp.get("text", ""))
        
        if resp_hash == self.baseline_response.get("text_hash"):
            return True
        
        baseline_len = self.baseline_response.get("length", 0)
        if baseline_len > 0 and abs(resp_len - baseline_len) / baseline_len < 0.05:
            return True
        
        return False
    
    async def _scan_sensitive_files(self, base_url):
        redirects = []
        for path, description in self.sensitive_files:
            url = f"{base_url}/{path.lstrip('/')}"
            resp = await self.http.get(url)
            status = resp.get("status")
            if status in (301, 302):
                loc = resp.get("headers", {}).get("Location", "")
                if loc:
                    redirects.append((url, loc))
            if status == 200:
                if len(resp.get("text", "")) > 0:
                    if self._is_baseline_response(resp):
                        continue
                    
                    severity = self._determine_severity(path, resp["text"])
                    if self._is_valid_response(path, resp["text"]):
                        parsed_data = self._parse_sensitive_file(path, resp["text"])
                        
                        evidence = f"Status: 200, Size: {len(resp['text'])} bytes"
                        confidence_evidence = ["file_accessible"]
                        
                        if parsed_data:
                            evidence += f" | Extracted: {len(parsed_data)} items"
                            confidence_evidence.append("secrets_extracted")
                            
                            if parsed_data.get("repo_url"):
                                evidence = f"Git repo: {parsed_data['repo_url']}"
                            if parsed_data.get("secrets"):
                                evidence = f"Secrets found: {list(parsed_data['secrets'].keys())[:3]}"
                        
                        self.add_finding(
                            severity,
                            description,
                            url=url,
                            evidence=evidence,
                            confidence_evidence=confidence_evidence,
                            request_data={"method": "GET", "url": url},
                            response_data={"status": status, "text": resp.get("text", "")[:1500], "headers": resp.get("headers", {})},
                            technique="Sensitive path enumeration",
                            injection_point=f"Path: {path}",
                            http_method="GET",
                            status_code=status,
                            content_length=len(resp.get("text", "")),
                            detection_method="Path enumeration with content analysis",
                            matched_pattern=f"Response code {status}, file detected",
                        )
                        
                        if parsed_data:
                            self._store_parsed_data(path, parsed_data)
        
        if redirects:
            self.add_finding(
                "INFO",
                "Sensitive path redirects",
                url=redirects[0][0],
                evidence=f"{len(redirects)} path(s) return 301/302: {redirects[0][1][:60]}"
            )
    
    def _parse_sensitive_file(self, path, content):
        if ".git/config" in path:
            return self._parse_git_config(content)
        elif ".env" in path or path.endswith("environment"):
            return self._parse_env_file(content)
        elif "config.json" in path or "appsettings.json" in path:
            return self._parse_json_config(content)
        elif "wp-config.php" in path or "config.php" in path:
            return self._parse_php_config(content)
        return None
    
    def _parse_git_config(self, content):
        result = {"repo_url": None, "remotes": [], "branches": []}
        
        url_match = re.search(r'url\s*=\s*(.+)', content)
        if url_match:
            result["repo_url"] = url_match.group(1).strip()
        
        for match in re.finditer(r'\[remote\s+"([^"]+)"\]', content):
            result["remotes"].append(match.group(1))
        
        for match in re.finditer(r'\[branch\s+"([^"]+)"\]', content):
            result["branches"].append(match.group(1))
        
        return result if result["repo_url"] or result["remotes"] else None
    
    def _parse_env_file(self, content):
        result = {"secrets": {}, "database": {}, "api_keys": []}
        
        secret_patterns = [
            (r'^(?:PASSWORD|PASS|PWD|SECRET)[_\s]*[=:]\s*(.+)$', "password"),
            (r'^(?:API_KEY|APIKEY|API_SECRET)[_\s]*[=:]\s*(.+)$', "api_key"),
            (r'^(?:AWS_SECRET|AWS_ACCESS)[_\s]*[=:]\s*(.+)$', "aws_credential"),
            (r'^(?:PRIVATE_KEY|SIGNING_KEY)[_\s]*[=:]\s*(.+)$', "private_key"),
            (r'^(?:JWT_SECRET|TOKEN_SECRET)[_\s]*[=:]\s*(.+)$', "jwt_secret"),
        ]
        
        db_patterns = [
            (r'^DB_(?:HOST|SERVER)[_\s]*[=:]\s*(.+)$', "host"),
            (r'^DB_(?:USER|USERNAME)[_\s]*[=:]\s*(.+)$', "user"),
            (r'^DB_(?:PASS|PASSWORD)[_\s]*[=:]\s*(.+)$', "password"),
            (r'^DB_(?:NAME|DATABASE)[_\s]*[=:]\s*(.+)$', "database"),
            (r'^DATABASE_URL[_\s]*[=:]\s*(.+)$', "connection_string"),
        ]
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            for pattern, key in secret_patterns:
                match = re.match(pattern, line, re.IGNORECASE)
                if match:
                    value = match.group(1).strip().strip('"\'')
                    if len(value) > 3:
                        result["secrets"][key] = value[:50] + "..." if len(value) > 50 else value
            
            for pattern, key in db_patterns:
                match = re.match(pattern, line, re.IGNORECASE)
                if match:
                    value = match.group(1).strip().strip('"\'')
                    result["database"][key] = value
        
        return result if result["secrets"] or result["database"] else None
    
    def _parse_json_config(self, content):
        import json
        try:
            data = json.loads(content)
            result = {"secrets": {}}
            
            def find_secrets(obj, path=""):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        key_lower = k.lower()
                        if any(s in key_lower for s in ["password", "secret", "key", "token", "credential"]):
                            if isinstance(v, str) and len(v) > 3:
                                result["secrets"][f"{path}{k}"] = v[:50]
                        elif isinstance(v, (dict, list)):
                            find_secrets(v, f"{path}{k}.")
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        find_secrets(item, f"{path}[{i}].")
            
            find_secrets(data)
            return result if result["secrets"] else None
        except json.JSONDecodeError:
            return None
    
    def _parse_php_config(self, content):
        result = {"secrets": {}, "database": {}}
        
        patterns = [
            (r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]", "db_password"),
            (r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]", "db_user"),
            (r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]", "db_name"),
            (r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]", "db_host"),
            (r"define\s*\(\s*['\"]AUTH_KEY['\"]\s*,\s*['\"]([^'\"]+)['\"]", "auth_key"),
            (r"define\s*\(\s*['\"]SECURE_AUTH_KEY['\"]\s*,\s*['\"]([^'\"]+)['\"]", "secure_auth_key"),
            (r"\$password\s*=\s*['\"]([^'\"]+)['\"]", "password"),
            (r"\$secret\s*=\s*['\"]([^'\"]+)['\"]", "secret"),
        ]
        
        for pattern, key in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                value = match.group(1)
                if "db_" in key or "database" in key:
                    result["database"][key] = value
                else:
                    result["secrets"][key] = value[:50]
        
        return result if result["secrets"] or result["database"] else None
    
    def _store_parsed_data(self, path, data):
        if not hasattr(self, "extracted_secrets"):
            self.extracted_secrets = {}
        self.extracted_secrets[path] = data
    
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
                    match = re.search(pattern, resp["text"], re.IGNORECASE)
                    if match:
                        error_snippet = resp["text"][max(0, match.start()-50):match.end()+100][:200]
                        self.add_finding(
                            severity,
                            "Verbose error message disclosure",
                            url=trigger,
                            evidence=f"Error pattern detected: {error_snippet[:80]}...",
                            request_data={"method": "GET", "url": trigger},
                            response_data={"status": resp.get("status"), "text": resp.get("text", "")[:1500]},
                            technique="Error message probing",
                            injection_point="URL path/query",
                            http_method="GET",
                            status_code=resp.get("status"),
                            detection_method="Error pattern matching",
                            matched_pattern=pattern[:50],
                        )
                        return
    
    def _determine_severity(self, path, content):
        critical_files = [".env", "config.php", "wp-config.php", ".htpasswd",
                          "backup.sql", "dump.sql", ".git/config", "appsettings.json",
                          "database.php", "db.php", ".env.php"]
        high_files = [".git/HEAD", "web.config", "phpinfo.php", "config.json", "config.yaml", "config.yml"]
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
        
        content_lower = content.lower()
        
        false_positive_indicators = [
            "404 not found", "page not found", "file not found",
            "does not exist", "cannot be found", "not found",
            "resource not found", "the page you requested",
            "error 404", "nothing here", "invalid url",
        ]
        
        waf_cloudflare_indicators = [
            "attention required", "cloudflare", "checking your browser",
            "ray id", "please wait", "ddos protection", "access denied",
            "forbidden", "you have been blocked", "security check",
            "one more step", "just a moment", "enable javascript",
            "browser verification", "captcha", "challenge-platform",
            "cf-browser-verification", "__cf_chl", "turnstile",
        ]
        
        for indicator in false_positive_indicators:
            if indicator in content_lower:
                return False
        
        for waf in waf_cloudflare_indicators:
            if waf in content_lower:
                return False
        
        if path.endswith(".git/config"):
            return "[core]" in content or "[remote" in content
        if path.endswith(".git/HEAD"):
            return "ref:" in content or content.strip().startswith("ref:")
        if ".env" in path:
            return "=" in content and not "<html" in content_lower
        if "phpinfo" in path:
            return "PHP Version" in content or "phpinfo()" in content
        if path.endswith("robots.txt"):
            return "user-agent" in content_lower or "disallow" in content_lower
        if path.endswith("sitemap.xml"):
            return "<urlset" in content_lower or "<sitemapindex" in content_lower
        if "config.json" in path or "package.json" in path:
            return content.strip().startswith("{") and "}" in content
        if "config.yaml" in path or "config.yml" in path or "docker-compose" in path:
            return ":" in content and not "<html" in content_lower
        if ".htaccess" in path:
            return "rewrite" in content_lower or "deny" in content_lower or "allow" in content_lower
        if ".htpasswd" in path:
            return ":" in content and len(content) < 1000
        if "web.config" in path:
            return "<configuration" in content_lower
        if ".sql" in path or "dump.sql" in path or "backup.sql" in path:
            return "create table" in content_lower or "insert into" in content_lower or "-- " in content
        if ".svn" in path:
            return "svn" in content_lower or "dir" in content_lower
        if "swagger" in path:
            return '"swagger"' in content_lower or '"openapi"' in content_lower or "paths" in content_lower
        
        if "<html" in content_lower and "</html>" in content_lower:
            if len(content) > 500 and not any(x in path.lower() for x in [".html", ".htm", ".php", ".asp"]):
                return False
        
        return True

    async def _check_security_txt(self, base_url):
        url = f"{base_url.rstrip('/')}/.well-known/security.txt"
        resp = await self.http.get(url)
        if resp.get("status") != 200 or not resp.get("text"):
            return
        content = resp.get("text", "")
        entries = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                entries[k.strip()] = v.strip()
        if not entries:
            return
        contact = entries.get("Contact") or entries.get("contact")
        if not contact:
            self.add_finding(
                "LOW",
                "Security.txt missing Contact",
                url=url,
                evidence="Required Contact field not present"
            )
        elif not re.match(r"^(mailto:|https?://)", contact, re.IGNORECASE):
            self.add_finding(
                "LOW",
                "Security.txt Contact invalid format",
                url=url,
                evidence=f"Contact should be mailto: or https:"
            )
        expires = entries.get("Expires") or entries.get("expires")
        if expires:
            if not re.match(r"^\d{4}-\d{2}-\d{2}T?\d{0,2}:?\d{0,2}:?\d{0,2}", expires):
                self.add_finding(
                    "LOW",
                    "Security.txt Expires invalid format",
                    url=url,
                    evidence=f"Expires: {expires[:30]}"
                )
            else:
                try:
                    from datetime import datetime
                    exp_str = expires[:10]
                    exp_date = datetime.strptime(exp_str, "%Y-%m-%d")
                    if exp_date < datetime.now():
                        self.add_finding(
                            "MEDIUM",
                            "Security.txt expired",
                            url=url,
                            evidence=f"Expires was {exp_str}"
                        )
                except Exception:
                    pass
        canonical = entries.get("Canonical") or entries.get("canonical")
        if canonical and not re.match(r"^https?://", canonical, re.IGNORECASE):
            self.add_finding(
                "LOW",
                "Security.txt Canonical invalid format",
                url=url,
                evidence="Canonical should be absolute URL"
            )
        preferred = entries.get("Preferred-Languages") or entries.get("preferred-languages")
        if preferred and not re.match(r"^[a-z]{2}(,[a-z]{2})*$", preferred, re.IGNORECASE):
            self.add_finding(
                "INFO",
                "Security.txt Preferred-Languages non-standard",
                url=url,
                evidence=f"Preferred-Languages: {preferred[:40]}"
            )
        policy = entries.get("Policy") or entries.get("policy")
        if policy and not re.match(r"^https?://", policy, re.IGNORECASE):
            self.add_finding(
                "LOW",
                "Security.txt Policy invalid format",
                url=url,
                evidence="Policy should be absolute URL"
            )
        if "Encryption" not in entries and "encryption" not in entries:
            self.add_finding(
                "INFO",
                "Security.txt missing Encryption (optional)",
                url=url,
                evidence="Encryption field recommended for PGP key"
            )
        if content and content[0] not in "# \t" and not content.splitlines()[0].strip().startswith("Contact"):
            self.add_finding(
                "INFO",
                "Security.txt should start with Contact (RFC 9116)",
                url=url,
                evidence="First directive should be Contact"
            )

    async def _scan_html_comments(self, target):
        resp = await self.http.get(target)
        if resp.get("status") != 200 or not resp.get("text"):
            return
        html = resp.get("text", "")
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        sensitive = ("todo", "fixme", "api", "key", "secret", "pass", "staging", "debug", "test", "internal", "tmp", "token", "password")
        for c in comments:
            c_lower = c.strip().lower()
            if len(c_lower) > 2 and any(kw in c_lower for kw in sensitive):
                self.add_finding(
                    "INFO",
                    "Sensitive keyword in HTML comment",
                    url=target,
                    evidence=f"Comment snippet: {c.strip()[:80]}"
                )
                return
