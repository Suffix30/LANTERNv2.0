import re
from urllib.parse import urlparse
from modules.base import BaseModule

class CookieModule(BaseModule):
    name = "cookie"
    description = "Cookie Security Scanner"
    
    sensitive_cookie_names = [
        "session", "sess", "sid", "ssid", "auth", "token", "jwt",
        "access", "refresh", "login", "user", "admin", "credential",
        "remember", "persistent", "identity", "id", "key", "secret",
        "api", "oauth", "bearer", "csrf", "xsrf", "_token",
    ]
    
    async def scan(self, target):
        self.findings = []
        
        resp = await self.http.get(target)
        if not resp.get("status"):
            return self.findings
        
        cookies = self._parse_cookies(resp.get("headers", {}))
        
        if not cookies:
            self.add_finding(
                "INFO",
                "No cookies set",
                url=target,
                evidence="Response does not set any cookies"
            )
            return self.findings
        
        for cookie in cookies:
            await self._analyze_cookie(target, cookie)
        
        await self._test_session_fixation(target, cookies)
        await self._test_cookie_overflow(target)
        
        return self.findings
    
    def _parse_cookies(self, headers):
        cookies = []
        set_cookie = headers.get("Set-Cookie", "")
        
        if not set_cookie:
            for key, value in headers.items():
                if key.lower() == "set-cookie":
                    set_cookie = value
                    break
        
        if not set_cookie:
            return cookies
        
        cookie_strings = set_cookie.split(", ") if ", " in set_cookie and "expires" not in set_cookie.lower() else [set_cookie]
        
        for cookie_str in cookie_strings:
            cookie = self._parse_single_cookie(cookie_str)
            if cookie:
                cookies.append(cookie)
        
        return cookies
    
    def _parse_single_cookie(self, cookie_str):
        parts = cookie_str.split(";")
        if not parts:
            return None
        
        name_value = parts[0].strip()
        if "=" not in name_value:
            return None
        
        name, value = name_value.split("=", 1)
        
        cookie = {
            "name": name.strip(),
            "value": value.strip(),
            "httponly": False,
            "secure": False,
            "samesite": None,
            "path": "/",
            "domain": None,
            "expires": None,
            "max_age": None,
        }
        
        for part in parts[1:]:
            part = part.strip().lower()
            if part == "httponly":
                cookie["httponly"] = True
            elif part == "secure":
                cookie["secure"] = True
            elif part.startswith("samesite="):
                cookie["samesite"] = part.split("=")[1]
            elif part.startswith("path="):
                cookie["path"] = part.split("=")[1]
            elif part.startswith("domain="):
                cookie["domain"] = part.split("=")[1]
            elif part.startswith("expires="):
                cookie["expires"] = part.split("=", 1)[1]
            elif part.startswith("max-age="):
                cookie["max_age"] = part.split("=")[1]
        
        return cookie
    
    async def _analyze_cookie(self, target, cookie):
        name = cookie["name"].lower()
        is_sensitive = any(sens in name for sens in self.sensitive_cookie_names)
        parsed = urlparse(target)
        is_https = parsed.scheme == "https"
        
        if is_sensitive:
            if not cookie["httponly"]:
                self.add_finding(
                    "HIGH",
                    f"Sensitive cookie without HttpOnly: {cookie['name']}",
                    url=target,
                    evidence="Cookie accessible via JavaScript (XSS risk)"
                )
            
            if not cookie["secure"]:
                self.add_finding(
                    "HIGH" if is_https else "MEDIUM",
                    f"Sensitive cookie without Secure flag: {cookie['name']}",
                    url=target,
                    evidence="Cookie may be sent over HTTP"
                )
            
            if not cookie["samesite"]:
                self.add_finding(
                    "MEDIUM",
                    f"Sensitive cookie without SameSite: {cookie['name']}",
                    url=target,
                    evidence="Cookie vulnerable to CSRF attacks"
                )
            elif cookie["samesite"] == "none" and not cookie["secure"]:
                self.add_finding(
                    "HIGH",
                    f"SameSite=None without Secure: {cookie['name']}",
                    url=target,
                    evidence="Invalid cookie configuration"
                )
        
        if cookie["path"] == "/":
            pass
        elif cookie["path"]:
            self.add_finding(
                "INFO",
                f"Cookie with specific path: {cookie['name']}",
                url=target,
                evidence=f"Path: {cookie['path']}"
            )
        
        if cookie["domain"] and cookie["domain"].startswith("."):
            self.add_finding(
                "LOW",
                f"Cookie with wildcard domain: {cookie['name']}",
                url=target,
                evidence=f"Domain: {cookie['domain']} (shared with subdomains)"
            )
        
        if cookie["value"]:
            value = cookie["value"]
            
            if re.match(r'^[a-f0-9]{32}$', value, re.I):
                self.add_finding(
                    "INFO",
                    f"MD5-like session ID: {cookie['name']}",
                    url=target,
                    evidence="32-char hex value (possibly weak entropy)"
                )
            
            if len(value) < 16 and is_sensitive:
                self.add_finding(
                    "MEDIUM",
                    f"Short session token: {cookie['name']}",
                    url=target,
                    evidence=f"Length: {len(value)} chars (may be predictable)"
                )
            
            if value.isdigit() and is_sensitive:
                self.add_finding(
                    "HIGH",
                    f"Numeric session ID: {cookie['name']}",
                    url=target,
                    evidence="Sequential/predictable session ID risk"
                )
    
    async def _test_session_fixation(self, target, cookies):
        session_cookies = [c for c in cookies if any(s in c["name"].lower() for s in ["session", "sess", "sid"])]
        
        if not session_cookies:
            return
        
        resp2 = await self.http.get(target)
        if not resp2.get("status"):
            return
        
        cookies2 = self._parse_cookies(resp2.get("headers", {}))
        
        for orig in session_cookies:
            for new in cookies2:
                if orig["name"] == new["name"] and orig["value"] == new["value"]:
                    self.add_finding(
                        "MEDIUM",
                        f"Potential session fixation: {orig['name']}",
                        url=target,
                        evidence="Same session ID across requests"
                    )
    
    async def _test_cookie_overflow(self, target):
        long_cookie = "A" * 4097
        
        resp = await self.http.get(target, headers={"Cookie": f"test={long_cookie}"})
        
        if resp.get("status") == 400:
            pass
        elif resp.get("status") == 200:
            self.add_finding(
                "LOW",
                "Server accepts oversized cookies",
                url=target,
                evidence="4KB+ cookie accepted"
            )
