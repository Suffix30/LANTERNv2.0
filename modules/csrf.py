import re
from urllib.parse import urlparse
from modules.base import BaseModule

class CsrfModule(BaseModule):
    name = "csrf"
    description = "Cross-Site Request Forgery Scanner"
    
    async def scan(self, target):
        self.findings = []
        
        await self._check_csrf_tokens(target)
        await self._check_referer_validation(target)
        await self._check_samesite_cookies(target)
        await self._test_token_reuse(target)
        
        return self.findings
    
    async def _check_csrf_tokens(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        text = resp["text"]
        
        csrf_patterns = [
            r'name=["\']?csrf[_-]?token["\']?\s+value=["\']?([^"\'>\s]+)',
            r'name=["\']?_token["\']?\s+value=["\']?([^"\'>\s]+)',
            r'name=["\']?authenticity_token["\']?\s+value=["\']?([^"\'>\s]+)',
            r'name=["\']?csrfmiddlewaretoken["\']?\s+value=["\']?([^"\'>\s]+)',
            r'name=["\']?__RequestVerificationToken["\']?\s+value=["\']?([^"\'>\s]+)',
            r'name=["\']?_csrf["\']?\s+value=["\']?([^"\'>\s]+)',
            r'data-csrf=["\']?([^"\'>\s]+)',
            r'csrf[_-]?token["\']?\s*:\s*["\']([^"\']+)',
        ]
        
        has_forms = bool(re.search(r'<form[^>]*method=["\']?post', text, re.IGNORECASE))
        has_csrf_token = False
        
        for pattern in csrf_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                has_csrf_token = True
                break
        
        if has_forms and not has_csrf_token:
            self.add_finding(
                "MEDIUM",
                "Forms without CSRF tokens detected",
                url=target,
                evidence="POST forms found without anti-CSRF tokens"
            )
        
        meta_csrf = re.search(r'<meta[^>]+name=["\']?csrf[_-]?token["\']?[^>]+content=["\']?([^"\']+)', text, re.IGNORECASE)
        if not meta_csrf and has_forms:
            header_csrf = resp.get("headers", {}).get("X-CSRF-Token")
            if not header_csrf:
                self.add_finding(
                    "LOW",
                    "No CSRF token in meta tags or headers",
                    url=target,
                    evidence="Missing meta csrf-token or X-CSRF-Token header"
                )
    
    async def _check_referer_validation(self, target):
        resp_no_referer = await self.http.post(
            target,
            data={"test": "value"},
            headers={"Referer": ""}
        )
        
        resp_evil_referer = await self.http.post(
            target,
            data={"test": "value"},
            headers={"Referer": "https://evil.com"}
        )
        
        resp_normal = await self.http.post(
            target,
            data={"test": "value"}
        )
        
        if all(r.get("status") for r in [resp_no_referer, resp_evil_referer, resp_normal]):
            if resp_no_referer["status"] == resp_normal["status"]:
                self.add_finding(
                    "LOW",
                    "Server accepts requests without Referer header",
                    url=target,
                    evidence="No Referer validation"
                )
            
            if resp_evil_referer["status"] == resp_normal["status"]:
                if resp_evil_referer["status"] not in [401, 403]:
                    self.add_finding(
                        "LOW",
                        "Server accepts requests from external Referer",
                        url=target,
                        evidence="Referer: evil.com accepted"
                    )
    
    async def _check_samesite_cookies(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        set_cookie = resp.get("headers", {}).get("Set-Cookie", "")
        
        if set_cookie:
            cookies = set_cookie.split(",")
            
            for cookie in cookies:
                cookie_lower = cookie.lower()
                
                if "session" in cookie_lower or "auth" in cookie_lower or "token" in cookie_lower:
                    if "samesite" not in cookie_lower:
                        self.add_finding(
                            "MEDIUM",
                            "Session cookie without SameSite attribute",
                            url=target,
                            evidence="Vulnerable to CSRF attacks"
                        )
                        return
                    
                    if "samesite=none" in cookie_lower:
                        if "secure" not in cookie_lower:
                            self.add_finding(
                                "MEDIUM",
                                "SameSite=None cookie without Secure flag",
                                url=target,
                                evidence="Cookie can be sent over HTTP"
                            )
    
    async def _test_token_reuse(self, target):
        resp1 = await self.http.get(target)
        if not resp1.get("status"):
            return
        
        token1 = self._extract_csrf_token(resp1["text"])
        
        if token1:
            resp2 = await self.http.get(target)
            if resp2.get("status"):
                token2 = self._extract_csrf_token(resp2["text"])
                
                if token1 == token2:
                    self.add_finding(
                        "LOW",
                        "CSRF token is static across requests",
                        url=target,
                        evidence="Token reuse may allow replay attacks"
                    )
    
    def _extract_csrf_token(self, html):
        patterns = [
            r'name=["\']?csrf[_-]?token["\']?\s+value=["\']?([^"\'>\s]+)',
            r'name=["\']?_token["\']?\s+value=["\']?([^"\'>\s]+)',
            r'name=["\']?csrfmiddlewaretoken["\']?\s+value=["\']?([^"\'>\s]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _get_origin(self, target):
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _is_same_origin(self, url1, url2):
        p1, p2 = urlparse(url1), urlparse(url2)
        return p1.scheme == p2.scheme and p1.netloc == p2.netloc
