import asyncio
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse
from typing import Set, List, Dict
from modules.base import BaseModule
from core.utils import random_string


class DirbustModule(BaseModule):
    name = "dirbust"
    description = "Directory & File Brute Force Scanner"
    
    common_dirs = [
        "admin", "administrator", "wp-admin", "login", "dashboard", "panel",
        "cpanel", "webmail", "phpmyadmin", "pma", "mysql", "myadmin",
        "api", "v1", "v2", "v3", "rest", "graphql", "swagger", "docs",
        "backup", "backups", "bak", "old", "temp", "tmp", "test", "dev",
        "staging", "uat", "qa", "demo", "sandbox", "debug",
        "config", "conf", "cfg", "settings", "setup", "install",
        "uploads", "upload", "files", "images", "img", "assets", "static",
        "media", "content", "data", "download", "downloads",
        "includes", "include", "inc", "lib", "libs", "library",
        "scripts", "js", "css", "fonts", "vendor", "node_modules",
        "src", "source", "app", "application", "core", "system",
        "private", "secure", "protected", "internal", "intranet",
        "portal", "member", "members", "user", "users", "account",
        "profile", "profiles", "customer", "customers", "client",
        "cgi-bin", "cgi", "bin", "scripts", "perl", "python",
        "wp-content", "wp-includes", "themes", "plugins", "modules",
        "components", "extensions", "addons", "widgets",
        "logs", "log", "error", "errors", "debug", "trace",
        "sql", "db", "database", "mysql", "postgres", "mongo",
        "git", ".git", ".svn", ".hg", ".bzr", "cvs",
        "env", ".env", "environment", "secrets",
        "console", "terminal", "shell", "cmd", "command",
        "monitor", "status", "health", "metrics", "stats",
        "actuator", "management", "info", "beans", "mappings",
    ]
    
    common_files = [
        "index.php", "index.html", "index.htm", "index.asp", "index.aspx", "index.jsp",
        "default.php", "default.html", "default.asp", "default.aspx",
        "login.php", "login.html", "signin.php", "auth.php", "authenticate.php",
        "admin.php", "administrator.php", "config.php", "configuration.php",
        "settings.php", "setup.php", "install.php", "installer.php",
        "wp-config.php", "wp-login.php", "xmlrpc.php", "wp-cron.php",
        "web.config", ".htaccess", ".htpasswd", "httpd.conf", "nginx.conf",
        ".env", ".env.local", ".env.production", ".env.development", ".env.backup",
        "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
        "security.txt", ".well-known/security.txt", "humans.txt",
        "package.json", "package-lock.json", "composer.json", "composer.lock",
        "Gemfile", "Gemfile.lock", "requirements.txt", "Pipfile", "Pipfile.lock",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        ".git/config", ".git/HEAD", ".gitignore", ".gitattributes",
        ".svn/entries", ".svn/wc.db",
        "backup.sql", "backup.zip", "backup.tar.gz", "backup.tar", "backup.rar",
        "database.sql", "dump.sql", "db.sql", "data.sql",
        "readme.txt", "README.md", "README.html", "CHANGELOG.md", "LICENSE",
        "phpinfo.php", "info.php", "test.php", "debug.php", "error.log", "debug.log",
        "access.log", "error.log", "application.log", "app.log",
        "server-status", "server-info", "status", "health", "healthcheck",
        "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml", "api-docs",
        "elmah.axd", "trace.axd", "WebResource.axd",
        "web.xml", "beans.xml", "faces-config.xml", "struts.xml",
        "application.properties", "application.yml", "application.yaml",
        ".DS_Store", "Thumbs.db", "desktop.ini",
    ]
    
    extensions = [
        "", ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".do", ".action",
        ".json", ".xml", ".txt", ".log", ".sql", ".bak", ".old", ".orig",
        ".zip", ".tar", ".gz", ".rar", ".7z",
        ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml",
        ".swp", ".swo", ".save", ".tmp", ".temp",
        ".php~", ".php.bak", ".php.old", ".php.swp",
    ]
    
    status_codes_valid = {200, 201, 204, 301, 302, 307, 308, 401, 403}
    
    async def scan(self, target):
        self.findings = []
        self.found_paths: Set[str] = set()
        self.base_url = self.get_base(target)
        self.baseline_404 = await self._get_baseline_404()
        
        await self._enumerate_directories()
        await self._enumerate_files()
        await self._enumerate_with_extensions()
        await self._check_backup_patterns()
        await self._recursive_enum()
        
        return self.findings
    
    async def _get_baseline_404(self) -> Dict:
        fake_path = f"/{random_string(16)}/{random_string(12)}.{random_string(4)}"
        resp = await self.http.get(urljoin(self.base_url, fake_path))
        
        return {
            "status": resp.get("status", 404),
            "length": len(resp.get("text", "")),
            "text_sample": resp.get("text", "")[:500].lower()
        }
    
    def _is_valid_response(self, resp: Dict) -> bool:
        if not resp.get("status"):
            return False
        
        status = resp.get("status")
        length = len(resp.get("text", ""))
        text = resp.get("text", "").lower()
        
        if status not in self.status_codes_valid:
            return False
        
        if status == self.baseline_404.get("status") and abs(length - self.baseline_404.get("length", 0)) < 50:
            return False
        
        false_positives = [
            "page not found", "404 not found", "file not found",
            "the page you requested", "does not exist", "cannot be found",
            "error 404", "not found", "page missing",
        ]
        
        for fp in false_positives:
            if fp in text and status != 401 and status != 403:
                return False
        
        if length < 50 and status not in [301, 302, 307, 308, 204]:
            return False
        
        return True
    
    async def _enumerate_directories(self):
        self.log_info(f"Enumerating {len(self.common_dirs)} directories...")
        
        sem = asyncio.Semaphore(50)
        
        async def check_dir(directory):
            async with sem:
                url = urljoin(self.base_url, f"/{directory}/")
                resp = await self.http.get(url)
                
                if self._is_valid_response(resp):
                    self.found_paths.add(f"/{directory}/")
                    severity = self._determine_severity(directory, resp)
                    
                    self.add_finding(
                        severity,
                        f"Directory Found: /{directory}/",
                        url=url,
                        evidence=f"Status: {resp.get('status')}, Size: {len(resp.get('text', ''))} bytes"
                    )
        
        tasks = [check_dir(d) for d in self.common_dirs]
        await asyncio.gather(*tasks)
    
    async def _enumerate_files(self):
        self.log_info(f"Enumerating {len(self.common_files)} files...")
        
        sem = asyncio.Semaphore(50)
        
        async def check_file(filename):
            async with sem:
                url = urljoin(self.base_url, f"/{filename}")
                resp = await self.http.get(url)
                
                if self._is_valid_response(resp):
                    self.found_paths.add(f"/{filename}")
                    severity = self._determine_severity(filename, resp)
                    
                    self.add_finding(
                        severity,
                        f"File Found: /{filename}",
                        url=url,
                        evidence=f"Status: {resp.get('status')}, Size: {len(resp.get('text', ''))} bytes"
                    )
                    
                    await self._analyze_content(url, filename, resp.get("text", ""))
        
        tasks = [check_file(f) for f in self.common_files]
        await asyncio.gather(*tasks)
    
    async def _enumerate_with_extensions(self):
        if not self.aggressive:
            return
        
        base_words = ["admin", "config", "backup", "test", "debug", "login", "user", "data", "api"]
        
        sem = asyncio.Semaphore(30)
        
        async def check_combo(word, ext):
            async with sem:
                filename = f"{word}{ext}"
                url = urljoin(self.base_url, f"/{filename}")
                resp = await self.http.get(url)
                
                if self._is_valid_response(resp):
                    self.found_paths.add(f"/{filename}")
                    
                    self.add_finding(
                        self._determine_severity(filename, resp),
                        f"File Found: /{filename}",
                        url=url,
                        evidence=f"Status: {resp.get('status')}"
                    )
        
        tasks = []
        for word in base_words:
            for ext in self.extensions[:15]:
                tasks.append(check_combo(word, ext))
        
        await asyncio.gather(*tasks)
    
    async def _check_backup_patterns(self):
        parsed = urlparse(self.base_url)
        domain = parsed.netloc.replace(".", "_").replace(":", "_")
        
        backup_patterns = [
            f"{domain}.zip", f"{domain}.tar.gz", f"{domain}.sql", f"{domain}.bak",
            f"www.zip", f"www.tar.gz", f"site.zip", f"site.tar.gz",
            f"web.zip", f"html.zip", f"public_html.zip",
            f"backup_{domain}.zip", f"{domain}_backup.zip",
            f"db.sql", f"database.sql", f"mysql.sql", f"dump.sql",
            f"backup.sql", f"backup.zip", f"backup.tar.gz",
            f"1.sql", f"2.sql", f"data.sql", f"export.sql",
        ]
        
        sem = asyncio.Semaphore(20)
        
        async def check_backup(filename):
            async with sem:
                url = urljoin(self.base_url, f"/{filename}")
                resp = await self.http.get(url)
                
                if self._is_valid_response(resp):
                    length = len(resp.get("text", ""))
                    
                    if length > 1000:
                        self.add_finding(
                            "CRITICAL",
                            f"Backup File Exposed: {filename}",
                            url=url,
                            evidence=f"Size: {length} bytes"
                        )
        
        tasks = [check_backup(p) for p in backup_patterns]
        await asyncio.gather(*tasks)
    
    async def _recursive_enum(self):
        if not self.aggressive:
            return
        
        found_dirs = [p for p in self.found_paths if p.endswith("/")]
        
        subdirs = ["admin", "api", "config", "backup", "test", "old", "new", "v1", "v2"]
        
        sem = asyncio.Semaphore(30)
        
        async def check_subdir(parent, subdir):
            async with sem:
                path = f"{parent}{subdir}/"
                url = urljoin(self.base_url, path)
                resp = await self.http.get(url)
                
                if self._is_valid_response(resp):
                    self.add_finding(
                        "MEDIUM",
                        f"Subdirectory Found: {path}",
                        url=url,
                        evidence=f"Status: {resp.get('status')}"
                    )
        
        tasks = []
        for parent in list(found_dirs)[:10]:
            for subdir in subdirs:
                tasks.append(check_subdir(parent, subdir))
        
        if tasks:
            await asyncio.gather(*tasks)
    
    async def _analyze_content(self, url, filename, content):
        if not content:
            return
        
        secrets = self.extract_secrets(content)
        if secrets:
            self.add_finding(
                "CRITICAL",
                f"Secrets Found in {filename}",
                url=url,
                evidence=f"Types: {', '.join(secrets.keys())}"
            )
            self.add_exploit_data(f"secrets_{filename}", secrets)
        
        if filename.endswith((".php", ".asp", ".aspx", ".jsp")):
            source_indicators = [
                r"<\?php", r"<%@", r"<%=", r"<jsp:",
                r"function\s+\w+\s*\(", r"class\s+\w+",
                r"import\s+", r"require\s*\(",
            ]
            
            for pattern in source_indicators:
                if re.search(pattern, content, re.IGNORECASE):
                    self.add_finding(
                        "CRITICAL",
                        f"Source Code Exposure: {filename}",
                        url=url,
                        evidence="Server-side code visible"
                    )
                    break
        
        if ".git" in filename:
            git_patterns = [
                r'\[remote\s+"origin"\]',
                r"url\s*=\s*git@",
                r"url\s*=\s*https://github",
            ]
            
            for pattern in git_patterns:
                match = re.search(pattern, content)
                if match:
                    self.add_finding(
                        "HIGH",
                        "Git Repository Exposed",
                        url=url,
                        evidence=match.group(0)[:50]
                    )
                    break
    
    def _determine_severity(self, path, resp) -> str:
        path_lower = path.lower()
        status = resp.get("status")
        
        if status == 403:
            return "LOW"
        
        critical_patterns = [
            ".env", "config.php", "wp-config", ".git/config", ".htpasswd",
            "backup", ".sql", ".zip", ".tar", "phpinfo", "web.config",
            "application.properties", "application.yml", "secrets",
        ]
        
        for pattern in critical_patterns:
            if pattern in path_lower:
                return "CRITICAL"
        
        high_patterns = [
            "admin", "login", ".git", ".svn", "phpmyadmin", "debug",
            "console", "shell", "upload", "api-docs", "swagger",
            "actuator", "management", "elmah", "trace",
        ]
        
        for pattern in high_patterns:
            if pattern in path_lower:
                return "HIGH"
        
        return "MEDIUM"
