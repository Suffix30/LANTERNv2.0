from modules.base import BaseModule

class HeadersModule(BaseModule):
    name = "headers"
    description = "Security Headers Analyzer"
    
    required_headers = {
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "description": "Missing HSTS header - susceptible to downgrade attacks",
        },
        "Content-Security-Policy": {
            "severity": "MEDIUM", 
            "description": "Missing CSP header - susceptible to XSS attacks",
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "description": "Missing X-Content-Type-Options - susceptible to MIME sniffing",
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "description": "Missing X-Frame-Options - susceptible to clickjacking",
        },
        "X-XSS-Protection": {
            "severity": "LOW",
            "description": "Missing X-XSS-Protection header",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": "Missing Referrer-Policy - potential information leakage",
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "description": "Missing Permissions-Policy header",
        },
    }
    
    dangerous_headers = {
        "Server": {
            "severity": "INFO",
            "description": "Server version disclosed",
        },
        "X-Powered-By": {
            "severity": "INFO",
            "description": "Technology stack disclosed",
        },
        "X-AspNet-Version": {
            "severity": "INFO",
            "description": "ASP.NET version disclosed",
        },
        "X-AspNetMvc-Version": {
            "severity": "INFO",
            "description": "ASP.NET MVC version disclosed",
        },
    }
    
    async def scan(self, target):
        self.findings = []
        
        resp = await self.http.get(target)
        if not resp.get("status"):
            return self.findings
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        
        for header, info in self.required_headers.items():
            if header.lower() not in headers:
                self.add_finding(
                    info["severity"],
                    info["description"],
                    url=target,
                    evidence=f"Missing header: {header}"
                )
        
        for header, info in self.dangerous_headers.items():
            if header.lower() in headers:
                self.add_finding(
                    info["severity"],
                    f"{info['description']}: {headers[header.lower()]}",
                    url=target,
                    evidence=f"{header}: {headers[header.lower()]}"
                )
        
        await self._check_csp(target, headers)
        await self._check_hsts(target, headers)
        await self._check_cookies(resp)
        
        return self.findings
    
    async def _check_csp(self, target, headers):
        csp = headers.get("content-security-policy", "")
        if csp:
            weak_directives = []
            
            if "unsafe-inline" in csp:
                weak_directives.append("unsafe-inline")
            if "unsafe-eval" in csp:
                weak_directives.append("unsafe-eval")
            if "'*'" in csp or "* " in csp:
                weak_directives.append("wildcard source")
            if "data:" in csp:
                weak_directives.append("data: URI")
            
            if weak_directives:
                self.add_finding(
                    "MEDIUM",
                    f"Weak CSP configuration",
                    url=target,
                    evidence=f"Weak directives: {', '.join(weak_directives)}"
                )
    
    async def _check_hsts(self, target, headers):
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            if "max-age=0" in hsts:
                self.add_finding(
                    "MEDIUM",
                    "HSTS max-age is 0 (disabled)",
                    url=target,
                    evidence=f"HSTS: {hsts}"
                )
            elif "max-age" in hsts:
                try:
                    max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                    if max_age < 31536000:
                        self.add_finding(
                            "LOW",
                            "HSTS max-age less than 1 year",
                            url=target,
                            evidence=f"max-age={max_age}"
                        )
                except:
                    pass
    
    async def _check_cookies(self, resp):
        cookies = resp.get("headers", {}).get("Set-Cookie", "")
        if cookies:
            issues = []
            
            if "httponly" not in cookies.lower():
                issues.append("missing HttpOnly")
            if "secure" not in cookies.lower():
                issues.append("missing Secure")
            if "samesite" not in cookies.lower():
                issues.append("missing SameSite")
            
            if issues:
                self.add_finding(
                    "MEDIUM",
                    f"Cookie security issues",
                    url=resp.get("url", ""),
                    evidence=f"Issues: {', '.join(issues)}"
                )
