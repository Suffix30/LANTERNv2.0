from urllib.parse import urljoin
from modules.base import BaseModule

class ClickjackModule(BaseModule):
    name = "clickjack"
    description = "Clickjacking Vulnerability Scanner"
    
    extra_paths = ["/", "/login", "/admin", "/dashboard", "/account", "/settings"]
    
    async def scan(self, target):
        self.findings = []
        base = target.split("?")[0].rstrip("/")
        urls_to_check = [target]
        for path in self.extra_paths:
            if path != "/":
                u = urljoin(base + "/", path.lstrip("/"))
                if u not in urls_to_check:
                    urls_to_check.append(u)
        for url in urls_to_check[:6]:
            await self._check_one(url)
        return self.findings
    
    async def _check_one(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        
        x_frame = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")
        
        has_xfo = bool(x_frame)
        has_csp_frame = "frame-ancestors" in csp.lower()
        
        if not has_xfo and not has_csp_frame:
            self.add_finding(
                "MEDIUM",
                "Clickjacking: No framing protection",
                url=target,
                evidence="Missing X-Frame-Options and CSP frame-ancestors"
            )
        elif not has_xfo:
            self.add_finding(
                "LOW",
                "Missing X-Frame-Options header",
                url=target,
                evidence="Only CSP frame-ancestors is set (may not work in older browsers)"
            )
        else:
            xfo_lower = x_frame.lower()
            
            if xfo_lower not in ["deny", "sameorigin"]:
                if "allow-from" in xfo_lower:
                    self.add_finding(
                        "LOW",
                        "X-Frame-Options uses deprecated ALLOW-FROM",
                        url=target,
                        evidence=f"Value: {x_frame}"
                    )
                else:
                    self.add_finding(
                        "MEDIUM",
                        "X-Frame-Options has invalid value",
                        url=target,
                        evidence=f"Value: {x_frame}"
                    )
        
        if has_csp_frame:
            if "'*'" in csp or "frame-ancestors *" in csp.lower():
                self.add_finding(
                    "MEDIUM",
                    "CSP frame-ancestors allows all origins",
                    url=target,
                    evidence="frame-ancestors * or 'self' *"
                )
        
        await self._check_sensitive_actions(target, resp)
    
    async def _check_sensitive_actions(self, target, resp):
        text = resp.get("text", "").lower()
        
        sensitive_patterns = [
            ("delete", "delete account"),
            ("transfer", "transfer funds"),
            ("password", "change password"),
            ("admin", "admin action"),
            ("settings", "settings change"),
            ("logout", "session action"),
            ("submit", "form submission"),
        ]
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        has_protection = headers.get("x-frame-options") or "frame-ancestors" in headers.get("content-security-policy", "")
        
        if not has_protection:
            for pattern, action_type in sensitive_patterns:
                if pattern in text:
                    if f"<button" in resp.get("text", "") or f"<input" in resp.get("text", ""):
                        self.add_finding(
                            "HIGH",
                            f"Clickjacking risk: {action_type} on unprotected page",
                            url=target,
                            evidence=f"Sensitive action ({action_type}) vulnerable to clickjacking"
                        )
                        return
