import re
from urllib.parse import urlparse, urljoin
from modules.base import BaseModule
from core.utils import extract_params
from core.http import inject_param

class RedirectModule(BaseModule):
    name = "redirect"
    description = "Open Redirect Scanner"
    
    redirect_params = [
        "url", "redirect", "next", "target", "rurl", "dest", "destination",
        "redir", "redirect_uri", "redirect_url", "return", "return_url",
        "returnTo", "return_to", "checkout_url", "continue", "go", "goto",
        "link", "to", "out", "view", "image_url", "forward", "success",
        "failure", "path", "uri", "u", "r", "n", "ref", "site", "html",
        "callback", "feed", "host", "port", "data", "reference", "file",
        "document", "folder", "root", "pg", "window", "navigate", "open",
    ]
    
    redirect_payloads = [
        "https://evil.com",
        "//evil.com",
        "///evil.com",
        "////evil.com",
        "/\\evil.com",
        "\\/evil.com",
        "//evil.com/",
        "//evil.com/%2f..",
        "///evil.com/%2f..",
        "////evil.com/%2f..",
        "https:evil.com",
        "http:evil.com",
        "//evil%E3%80%82com",
        "//evil。com",
        "//%0d%0aevil.com",
        "//evil%00.com",
        "https://evil.com#",
        "https://evil.com?",
        "https://evil.com\\",
        "https://evil.com@legitimate.com",
        "https://legitimate.com@evil.com",
        "https://evil.com%23.legitimate.com",
        "https://evil.com%2f.legitimate.com",
        "javascript:alert(1)",
        "javascript://evil.com/%0aalert(1)",
        "data:text/html,<script>alert(1)</script>",
        "//google.com%2f@evil.com",
        "/\\.evil.com",
        "/.evil.com",
        "/evil.com",
        "https:///evil.com",
        "https:\\\\evil.com",
    ]
    
    async def scan(self, target):
        self.findings = []
        params = extract_params(target)
        
        redirect_params = self._find_redirect_params(params)
        
        if redirect_params:
            await self._test_open_redirect(target, redirect_params)
        else:
            await self._test_common_redirect_params(target)
        
        await self._test_header_based_redirect(target)
        
        return self.findings
    
    def _find_redirect_params(self, params):
        found = []
        for param in params:
            if any(rp in param.lower() for rp in self.redirect_params):
                found.append(param)
        return found if found else list(params)
    
    async def _test_open_redirect(self, target, params):
        for param in params:
            for payload in self.redirect_payloads[:10]:
                resp = await self.http.get(
                    inject_param(target, param, payload),
                    allow_redirects=False
                )
                
                if resp.get("status") in [301, 302, 303, 307, 308]:
                    location = resp.get("headers", {}).get("Location", "")
                    
                    if self._is_external_redirect(location, target, payload):
                        self.add_finding(
                            "MEDIUM",
                            f"Open Redirect detected",
                            url=target,
                            parameter=param,
                            evidence=f"Redirects to: {location[:100]}"
                        )
                        return
                
                if resp.get("status") == 200:
                    text = resp.get("text", "").lower()
                    if "evil.com" in text or payload.lower() in text:
                        if "<script>" in text or "javascript:" in payload.lower():
                            self.add_finding(
                                "HIGH",
                                f"Open Redirect with XSS potential",
                                url=target,
                                parameter=param,
                                evidence=f"Payload reflected: {payload[:50]}"
                            )
                            return
    
    async def _test_common_redirect_params(self, target):
        base_url = target.split("?")[0]
        
        for param in self.redirect_params[:15]:
            test_url = f"{base_url}?{param}=https://evil.com"
            
            resp = await self.http.get(test_url, allow_redirects=False)
            
            if resp.get("status") in [301, 302, 303, 307, 308]:
                location = resp.get("headers", {}).get("Location", "")
                
                if "evil.com" in location:
                    self.add_finding(
                        "MEDIUM",
                        f"Open Redirect via hidden parameter",
                        url=base_url,
                        parameter=param,
                        evidence=f"Redirects to: {location[:100]}"
                    )
                    return
    
    async def _test_header_based_redirect(self, target):
        header_payloads = [
            ("Host", "evil.com"),
            ("X-Forwarded-Host", "evil.com"),
            ("X-Original-URL", "https://evil.com"),
            ("X-Rewrite-URL", "https://evil.com"),
        ]
        
        for header, value in header_payloads:
            resp = await self.http.get(
                target,
                headers={header: value},
                allow_redirects=False
            )
            
            if resp.get("status") in [301, 302, 303, 307, 308]:
                location = resp.get("headers", {}).get("Location", "")
                
                if "evil.com" in location:
                    self.add_finding(
                        "HIGH",
                        f"Open Redirect via {header} header",
                        url=target,
                        evidence=f"Redirects to: {location[:100]}"
                    )
                    return
    
    def _is_external_redirect(self, location, original_url, payload):
        if not location:
            return False
        
        if "evil.com" in location.lower():
            return True
        
        try:
            original_host = urlparse(original_url).netloc
            redirect_host = urlparse(location).netloc
            
            if redirect_host and redirect_host != original_host:
                if not redirect_host.endswith(f".{original_host}"):
                    return True
        except:
            pass
        
        return False
    
    def _detect_redirect_patterns(self, text):
        patterns = [
            re.compile(r'window\.location\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'location\.href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'location\.replace\s*\(["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'http-equiv=["\']refresh["\'][^>]+url=([^"\'>\s]+)', re.IGNORECASE),
        ]
        redirects = []
        for pattern in patterns:
            matches = pattern.findall(text)
            redirects.extend(matches)
        return redirects
    
    def _build_redirect_url(self, base, param, payload):
        return urljoin(base, f"?{param}={payload}")
