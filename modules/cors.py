import random
import string
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
        await self._test_target_and_same_domain_origins(target)
        await self._test_random_subdomain_origin(target)
        await self._test_preflight(target)
        
        return self.findings
    
    def _classify(self, origin, acao, acac, target_origin):
        if not acao:
            return "None"
        acac_flag = (acac or "").lower() == "true"
        if acao == "*":
            return "Wildcard+Creds" if acac_flag else "Wildcard"
        if acao.lower() == (origin or "").lower():
            if origin == target_origin:
                return "Reflect-Target+Creds" if acac_flag else "Reflect-Target"
            return "Reflect-Other+Creds" if acac_flag else "Reflect-Other"
        try:
            if target_origin and acao.endswith(target_origin.replace("https://", "").replace("http://", "")):
                return "Subdomain-Pattern+Creds" if acac_flag else "Subdomain-Pattern"
        except Exception:
            pass
        return "Other"
    
    async def _test_wildcard_origin(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        vary = headers.get("vary", "")
        
        if acao == "*":
            cls = self._classify(None, acao, acac, None)
            ev = f"Access-Control-Allow-Origin: * with credentials" if acac.lower() == "true" else "Access-Control-Allow-Origin: *"
            if vary:
                ev += f"; Vary: {vary}"
            if acac.lower() == "true":
                self.add_finding(
                    "CRITICAL",
                    "CORS: Wildcard origin with credentials",
                    url=target,
                    evidence=f"{ev} [class: {cls}]"
                )
            else:
                self.add_finding(
                    "MEDIUM",
                    "CORS: Wildcard origin",
                    url=target,
                    evidence=f"{ev} [class: {cls}]"
                )
    
    async def _test_null_origin(self, target):
        resp = await self.http.get(target, headers={"Origin": "null"})
        if not resp.get("status"):
            return
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        
        if acao == "null":
            cls = self._classify("null", acao, acac, None)
            severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
            self.add_finding(
                severity,
                "CORS: Null origin accepted",
                url=target,
                evidence=f"Reflects null origin (credentials: {acac}) [class: {cls}]"
            )
    
    async def _test_reflected_origin(self, target):
        evil_origins = [
            "https://evil.com",
            "https://attacker.com",
            "http://malicious.com",
            "https://evil.example",
            "http://evil.example",
        ]
        
        parsed = urlparse(target)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"
        
        for evil in evil_origins:
            resp = await self.http.get(target, headers={"Origin": evil})
            if not resp.get("status"):
                continue
            
            headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "")
            
            if acao == evil:
                cls = self._classify(evil, acao, acac, target_origin)
                severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
                self.add_finding(
                    severity,
                    "CORS: Arbitrary origin reflected",
                    url=target,
                    evidence=f"Reflects {evil} (credentials: {acac}) [class: {cls}]"
                )
                return
    
    async def _test_subdomain_trust(self, target):
        parsed = urlparse(target)
        domain = parsed.netloc.split(":")[0]
        target_origin = f"{parsed.scheme}://{parsed.netloc}"
        
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
            acac = headers.get("access-control-allow-credentials", "")
            
            if acao == evil:
                cls = self._classify(evil, acao, acac, target_origin)
                self.add_finding(
                    "HIGH",
                    "CORS: Subdomain/prefix trust issue",
                    url=target,
                    evidence=f"Trusts origin: {evil} [class: {cls}]"
                )
                return
    
    async def _test_target_and_same_domain_origins(self, target):
        parsed = urlparse(target)
        domain = parsed.netloc.split(":")[0]
        target_origin = f"{parsed.scheme}://{parsed.netloc}"
        same_domain_origins = [
            target_origin,
            f"http://{domain}",
            f"https://{domain}",
        ]
        for origin in same_domain_origins:
            resp = await self.http.get(target, headers={"Origin": origin})
            if not resp.get("status"):
                continue
            headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "")
            if not acao or acao != origin:
                continue
            if origin != target_origin and acac.lower() == "true":
                cls = self._classify(origin, acao, acac, target_origin)
                self.add_finding(
                    "HIGH",
                    "CORS: Same-domain alternate origin reflected with credentials",
                    url=target,
                    evidence=f"Reflects {origin} with credentials [class: {cls}]"
                )
                return
    
    async def _test_random_subdomain_origin(self, target):
        parsed = urlparse(target)
        domain = parsed.netloc.split(":")[0]
        target_origin = f"{parsed.scheme}://{parsed.netloc}"
        tok = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        origin = f"https://{tok}.{domain}"
        resp = await self.http.get(target, headers={"Origin": origin})
        if not resp.get("status"):
            return
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao == origin:
            cls = self._classify(origin, acao, acac, target_origin)
            severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
            self.add_finding(
                severity,
                "CORS: Random subdomain origin reflected",
                url=target,
                evidence=f"Reflects arbitrary subdomain {origin} (credentials: {acac}) [class: {cls}]"
            )
    
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
