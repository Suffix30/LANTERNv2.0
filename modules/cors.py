from modules.base import BaseModule
from urllib.parse import urlparse

class CorsModule(BaseModule):
    name = "cors"
    description = "CORS Misconfiguration Scanner"
    
    async def scan(self, target):
        self.findings = []
        
        await self._test_wildcard_origin(target)
        await self._test_null_origin(target)
        await self._test_reflected_origin(target)
        await self._test_subdomain_trust(target)
        
        return self.findings
    
    async def _test_wildcard_origin(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        
        if acao == "*":
            if acac.lower() == "true":
                self.add_finding(
                    "CRITICAL",
                    "CORS: Wildcard origin with credentials",
                    url=target,
                    evidence="Access-Control-Allow-Origin: * with credentials"
                )
            else:
                self.add_finding(
                    "MEDIUM",
                    "CORS: Wildcard origin",
                    url=target,
                    evidence="Access-Control-Allow-Origin: *"
                )
    
    async def _test_null_origin(self, target):
        resp = await self.http.get(target, headers={"Origin": "null"})
        if not resp.get("status"):
            return
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        
        if acao == "null":
            severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
            self.add_finding(
                severity,
                "CORS: Null origin accepted",
                url=target,
                evidence=f"Reflects null origin (credentials: {acac})"
            )
    
    async def _test_reflected_origin(self, target):
        evil_origins = [
            "https://evil.com",
            "https://attacker.com",
            "http://malicious.com",
        ]
        
        for evil in evil_origins:
            resp = await self.http.get(target, headers={"Origin": evil})
            if not resp.get("status"):
                continue
            
            headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "")
            
            if acao == evil:
                severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
                self.add_finding(
                    severity,
                    "CORS: Arbitrary origin reflected",
                    url=target,
                    evidence=f"Reflects {evil} (credentials: {acac})"
                )
                return
    
    async def _test_subdomain_trust(self, target):
        parsed = urlparse(target)
        domain = parsed.netloc.split(":")[0]
        
        evil_subdomains = [
            f"https://evil.{domain}",
            f"https://{domain}.evil.com",
            f"https://attacker-{domain}",
        ]
        
        for evil in evil_subdomains:
            resp = await self.http.get(target, headers={"Origin": evil})
            if not resp.get("status"):
                continue
            
            headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
            acao = headers.get("access-control-allow-origin", "")
            
            if acao == evil:
                self.add_finding(
                    "HIGH",
                    "CORS: Subdomain/prefix trust issue",
                    url=target,
                    evidence=f"Trusts origin: {evil}"
                )
                return
    
    async def _test_preflight(self, target):
        resp = await self.http.request(
            "OPTIONS",
            target,
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "X-Custom-Header",
            }
        )
        
        if resp.get("status"):
            headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
            methods = headers.get("access-control-allow-methods", "")
            
            dangerous_methods = ["PUT", "DELETE", "PATCH"]
            allowed = [m for m in dangerous_methods if m in methods.upper()]
            
            if allowed:
                self.add_finding(
                    "MEDIUM",
                    "CORS: Dangerous methods allowed",
                    url=target,
                    evidence=f"Allowed methods: {', '.join(allowed)}"
                )
