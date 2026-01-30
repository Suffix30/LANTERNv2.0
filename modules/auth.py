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

    forgot_paths = [
        "/forgot-password", "/forgot_password", "/reset-password", "/password/forgot",
        "/recover", "/recovery", "/auth/forgot", "/api/forgot-password",
    ]
    
    async def scan(self, target):
        self.findings = []
        base_url = get_base_url(target)
        self.auth_manager = None
        self.sessions = {}
        
        auth_config = self.config.get("auth_config")
        if auth_config:
            await self._setup_auth_manager(auth_config, base_url)
        
        await self._find_login_forms(base_url)
        await self._test_username_enumeration(base_url)
        await self._test_forgot_password_enumeration(base_url)
        await self._test_login_rate_limiting(base_url)
        await self._test_default_credentials(base_url)
        await self._test_password_policy(target)
        
        if self.auth_manager and self.aggressive:
            await self._test_role_access_control(base_url)
            await self._test_privilege_escalation(base_url)
        
        return self.findings
    
    async def _setup_auth_manager(self, config, base_url):
        try:
            from core.auth_manager import create_auth_manager
            self.auth_manager = await create_auth_manager(config, self.http)
            
            for role, creds in config.get("credentials", {}).items():
                if creds:
                    session = await self.auth_manager.login(role)
                    if session:
                        self.sessions[role] = session
            
            if self.sessions:
                self.add_finding(
                    "INFO",
                    f"Authenticated as {len(self.sessions)} roles",
                    url=base_url,
                    evidence=f"Roles: {list(self.sessions.keys())}"
                )
        except Exception as e:
            pass
    
    async def _test_role_access_control(self, base_url):
        if len(self.sessions) < 2:
            return
        
        admin_endpoints = [
            "/admin", "/admin/users", "/admin/settings", "/admin/config",
            "/api/admin", "/api/users", "/dashboard/admin", "/manage",
        ]
        
        roles = list(self.sessions.keys())
        admin_role = next((r for r in roles if "admin" in r.lower()), roles[0])
        user_role = next((r for r in roles if r != admin_role), None)
        
        if not user_role:
            return
        
        for endpoint in admin_endpoints:
            url = f"{base_url}{endpoint}"
            
            admin_resp = await self.auth_manager.request_as(admin_role, "GET", url)
            user_resp = await self.auth_manager.request_as(user_role, "GET", url)
            
            if admin_resp.get("status") == 200 and user_resp.get("status") == 200:
                admin_len = len(admin_resp.get("text", ""))
                user_len = len(user_resp.get("text", ""))
                
                if abs(admin_len - user_len) < 100:
                    self.add_finding(
                        "HIGH",
                        f"Broken access control: {endpoint}",
                        url=url,
                        evidence=f"Both {admin_role} and {user_role} can access admin endpoint",
                        confidence_evidence=["same_response_content", "role_comparison"],
                        request_data={"method": "GET", "url": url, "roles_tested": [admin_role, user_role]}
                    )
    
    async def _test_privilege_escalation(self, base_url):
        if "admin" not in [r.lower() for r in self.sessions.keys()]:
            return
        
        user_role = next((r for r in self.sessions.keys() if "admin" not in r.lower()), None)
        if not user_role:
            return
        
        escalation_tests = [
            {"endpoint": "/api/users/role", "method": "POST", "data": {"role": "admin"}},
            {"endpoint": "/api/user/update", "method": "PUT", "data": {"is_admin": True}},
            {"endpoint": "/api/settings", "method": "POST", "data": {"admin": True}},
        ]
        
        for test in escalation_tests:
            url = f"{base_url}{test['endpoint']}"
            resp = await self.auth_manager.request_as(
                user_role, test["method"], url, json=test["data"]
            )
            
            if resp.get("status") in [200, 201]:
                text = resp.get("text", "").lower()
                if "error" not in text and "denied" not in text and "unauthorized" not in text:
                    self.add_finding(
                        "CRITICAL",
                        f"Privilege escalation possible: {test['endpoint']}",
                        url=url,
                        evidence=f"User role can modify admin properties",
                        confidence_evidence=["successful_modification", "no_error_response"],
                        request_data={"method": test["method"], "url": url, "payload": test["data"]}
                    )
    
    async def _find_login_forms(self, base_url):
        for path in self.login_paths:
            url = f"{base_url}{path}"
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                html = resp["text"]
                if self._has_login_form(html):
                    self.add_finding(
                        "INFO",
                        f"Login form found",
                        url=url,
                        evidence=f"Path: {path}"
                    )
                    self.login_url = url
                    await self._check_autocomplete(url, html)
                    return url
        return None
    
    async def _check_autocomplete(self, url, html):
        pat_input = re.compile(r'<input([^>]*)>', re.I)
        pat_attr = re.compile(r'([a-zA-Z_:-]+)\s*=\s*["\']([^"\']*)["\']')
        sensitive_types = ("password", "email")
        sensitive_names = ("password", "passwd", "pwd", "user", "email", "token", "secret")
        for m in pat_input.finditer(html):
            attrs = dict(pat_attr.findall(m.group(1)))
            typ = attrs.get("type", "text").lower()
            name = (attrs.get("name") or attrs.get("id") or "").lower()
            ac = attrs.get("autocomplete", "").lower()
            if typ in sensitive_types or any(s in name for s in sensitive_names):
                if ac not in ("off", "new-password", "one-time-code"):
                    self.add_finding(
                        "LOW",
                        "Sensitive input without autocomplete=off",
                        url=url,
                        evidence=f"type={typ}, autocomplete={ac or 'not set'}"
                    )
                    return

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
    
    async def _test_forgot_password_enumeration(self, base_url):
        for path in self.forgot_paths:
            url = f"{base_url}{path}"
            resp = await self.http.get(url)
            if resp.get("status") != 200:
                continue
            if not re.search(r'email|username|forgot|reset', resp.get("text", ""), re.I):
                continue
            form_action = re.search(r'<form[^>]+action=["\']?([^"\'>\s]*)', resp.get("text", ""), re.I)
            post_url = url if not form_action else (url + form_action.group(1) if not form_action.group(1).startswith("http") else form_action.group(1))
            if not post_url.startswith("http"):
                post_url = base_url + post_url if post_url.startswith("/") else f"{base_url}/{post_url}"
            email_param = "email"
            for m in re.finditer(r'name=["\']?(\w+)["\']?', resp.get("text", "")):
                if m.group(1).lower() in ("email", "username", "user"):
                    email_param = m.group(1)
                    break
            valid_resp = await self.http.post(post_url, data={email_param: "admin@example.com"})
            invalid_resp = await self.http.post(post_url, data={email_param: "nonexistent_user_12345@example.com"})
            if not valid_resp.get("status") or not invalid_resp.get("status"):
                continue
            t1, t2 = valid_resp.get("text", ""), invalid_resp.get("text", "")
            if abs(len(t1) - len(t2)) > 20:
                self.add_finding(
                    "MEDIUM",
                    "Forgot-password user enumeration (response diff)",
                    url=post_url,
                    evidence=f"Valid vs invalid email response length diff: {abs(len(t1) - len(t2))}"
                )
                return
            if valid_resp.get("elapsed", 0) - invalid_resp.get("elapsed", 0) > 0.3:
                self.add_finding(
                    "MEDIUM",
                    "Forgot-password user enumeration (timing)",
                    url=post_url,
                    evidence="Valid email takes longer (e.g. email send)"
                )
                return
            msg_diff = ["sent", "check your email", "not found", "invalid", "unknown"]
            for kw in msg_diff:
                if (kw in t1.lower()) != (kw in t2.lower()):
                    self.add_finding(
                        "MEDIUM",
                        "Forgot-password user enumeration (message diff)",
                        url=post_url,
                        evidence=f"Different message for valid vs invalid ({kw})"
                    )
                    return

    async def _test_login_rate_limiting(self, base_url):
        login_url = getattr(self, "login_url", None)
        if not login_url:
            return
        attempts = 0
        for _ in range(15):
            r = await self.http.post(login_url, data={"username": "rate_limit_test", "password": "wrong"})
            attempts += 1
            if r.get("status") == 429:
                return
            h = (r.get("headers") or {}).get("retry-after", "")
            if h and str(h).isdigit():
                return
            text = (r.get("text") or "").lower()
            if "locked" in text or "too many" in text or "blocked" in text or "rate limit" in text:
                return
        self.add_finding(
            "MEDIUM",
            "No login rate limiting detected",
            url=login_url,
            evidence=f"Sent {attempts} failed login attempts without block"
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
