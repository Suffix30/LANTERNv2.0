import re
from modules.base import BaseModule
from core.http import get_base_url

class AuthModule(BaseModule):
    name = "auth"
    description = "Authentication Security Scanner"
    
    default_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("administrator", "administrator"),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
        ("user", "user"),
        ("guest", "guest"),
        ("demo", "demo"),
        ("admin", ""),
        ("", ""),
    ]
    
    login_paths = [
        "/login",
        "/login.php",
        "/admin/login",
        "/administrator/login",
        "/user/login",
        "/auth/login",
        "/signin",
        "/sign-in",
        "/admin",
        "/wp-login.php",
        "/wp-admin",
    ]
    
    async def scan(self, target):
        self.findings = []
        base_url = get_base_url(target)
        
        await self._find_login_forms(base_url)
        await self._test_username_enumeration(base_url)
        await self._test_default_credentials(base_url)
        await self._test_password_policy(target)
        
        return self.findings
    
    async def _find_login_forms(self, base_url):
        for path in self.login_paths:
            url = f"{base_url}{path}"
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                if self._has_login_form(resp["text"]):
                    self.add_finding(
                        "INFO",
                        f"Login form found",
                        url=url,
                        evidence=f"Path: {path}"
                    )
                    self.login_url = url
                    return url
        return None
    
    def _has_login_form(self, html):
        patterns = [
            r'<input[^>]+type=["\']password["\']',
            r'<form[^>]+login',
            r'<form[^>]+signin',
            r'name=["\']password["\']',
            r'id=["\']password["\']',
        ]
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        return False
    
    async def _test_username_enumeration(self, base_url):
        login_url = getattr(self, 'login_url', None)
        if not login_url:
            return
        
        valid_user_resp = await self.http.post(login_url, data={
            "username": "admin",
            "password": "wrongpassword123"
        })
        
        invalid_user_resp = await self.http.post(login_url, data={
            "username": "nonexistent_user_12345",
            "password": "wrongpassword123"
        })
        
        if valid_user_resp.get("status") and invalid_user_resp.get("status"):
            if valid_user_resp["text"] != invalid_user_resp["text"]:
                diff = abs(len(valid_user_resp["text"]) - len(invalid_user_resp["text"]))
                if diff > 10:
                    self.add_finding(
                        "MEDIUM",
                        "Username enumeration possible",
                        url=login_url,
                        evidence=f"Response length diff: {diff} bytes"
                    )
            
            valid_time = valid_user_resp.get("elapsed", 0)
            invalid_time = invalid_user_resp.get("elapsed", 0)
            if abs(valid_time - invalid_time) > 0.5:
                self.add_finding(
                    "MEDIUM",
                    "Username enumeration via timing",
                    url=login_url,
                    evidence=f"Time diff: {abs(valid_time - invalid_time):.2f}s"
                )
    
    async def _test_default_credentials(self, base_url):
        login_url = getattr(self, 'login_url', None)
        if not login_url:
            return
        
        for username, password in self.default_creds[:5]:
            resp = await self.http.post(login_url, data={
                "username": username,
                "password": password
            })
            
            if resp.get("status"):
                if self._check_login_success(resp):
                    self.add_finding(
                        "CRITICAL",
                        f"Default credentials work",
                        url=login_url,
                        evidence=f"Username: {username}, Password: {'*' * len(password) if password else '(empty)'}"
                    )
                    return
    
    def _check_login_success(self, resp):
        success_indicators = [
            "dashboard",
            "welcome",
            "logout",
            "sign out",
            "my account",
            "profile",
        ]
        
        failure_indicators = [
            "invalid",
            "incorrect",
            "failed",
            "error",
            "wrong password",
            "try again",
        ]
        
        text_lower = resp["text"].lower()
        
        for indicator in failure_indicators:
            if indicator in text_lower:
                return False
        
        if resp["status"] in [301, 302, 303, 307, 308]:
            location = resp.get("headers", {}).get("Location", "")
            if "dashboard" in location or "admin" in location:
                return True
        
        for indicator in success_indicators:
            if indicator in text_lower:
                return True
        
        return False
    
    async def _test_password_policy(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        weak_indicators = [
            r'minlength=["\']?[1-5]["\']?',
            r'password.*min.*[1-5]',
            r'at least [1-5] character',
        ]
        
        for pattern in weak_indicators:
            if re.search(pattern, resp["text"], re.IGNORECASE):
                self.add_finding(
                    "LOW",
                    "Weak password policy detected",
                    url=target,
                    evidence="Short minimum password length"
                )
                return
