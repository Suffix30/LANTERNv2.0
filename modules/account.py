import re
import asyncio
from urllib.parse import urljoin, urlparse
from modules.base import BaseModule
from core.utils import random_string

class AccountModule(BaseModule):
    name = "account"
    description = "Account & Registration Security Scanner"
    
    registration_paths = [
        "/register", "/signup", "/sign-up", "/create-account",
        "/join", "/new-user", "/api/register", "/api/signup",
        "/user/register", "/auth/register", "/account/create",
        "/membership/register", "/members/register",
    ]
    
    profile_paths = [
        "/profile", "/account", "/settings", "/user/profile",
        "/api/profile", "/api/user", "/api/me", "/my-account",
        "/user/settings", "/account/settings", "/dashboard",
    ]
    
    password_reset_paths = [
        "/forgot-password", "/password-reset", "/reset-password",
        "/api/password/reset", "/api/forgot", "/auth/reset",
        "/user/forgot", "/account/recover", "/recovery",
    ]
    
    weak_passwords = [
        "password", "123456", "admin", "test", "user",
        "letmein", "welcome", "monkey", "dragon",
    ]
    
    async def scan(self, target):
        self.findings = []
        
        await self._test_registration_abuse(target)
        await self._test_username_enumeration(target)
        await self._test_email_enumeration(target)
        await self._test_password_policy(target)
        await self._test_profile_idor(target)
        await self._test_mass_assignment(target)
        await self._test_account_takeover(target)
        await self._test_verification_bypass(target)
        
        return self.findings
    
    async def _test_registration_abuse(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in self.registration_paths:
            resp = await self.http.get(f"{base}{path}")
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                if "<form" in text.lower():
                    self.log_info(f"Registration form found: {path}")
                    
                    reg_url = urljoin(base, path)
                    test_users = [
                        {"username": f"test_{random_string(8)}", "email": f"test_{random_string(8)}@test.com", "password": "TestPass123!"}
                        for _ in range(5)
                    ]
                    
                    async def try_register(user):
                        return await self.http.post(reg_url, data=user)
                    
                    results = await asyncio.gather(*[try_register(u) for u in test_users], return_exceptions=True)
                    
                    success_count = sum(
                        1 for r in results 
                        if isinstance(r, dict) and r.get("status") in [200, 201, 302]
                        and any(x in r.get("text", "").lower() for x in ["success", "created", "welcome", "verify", "confirm"])
                    )
                    
                    if success_count >= 3:
                        self.add_finding(
                            "HIGH",
                            f"Mass registration possible (concurrent)",
                            url=reg_url,
                            evidence=f"Created {success_count}/5 accounts simultaneously"
                        )
                    
                    disposable_email = f"test@mailinator.com"
                    reg_resp = await self.http.post(
                        f"{base}{path}",
                        data={"username": f"test_{random_string(8)}", "email": disposable_email, "password": "Test123!"}
                    )
                    
                    if reg_resp.get("status") in [200, 201, 302]:
                        if "disposable" not in reg_resp.get("text", "").lower():
                            self.add_finding(
                                "LOW",
                                f"Disposable email accepted",
                                url=f"{base}{path}",
                                evidence="No disposable email filtering"
                            )
                    
                    break
    
    async def _test_username_enumeration(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        login_paths = ["/login", "/signin", "/api/login", "/auth/login"]
        
        for path in login_paths:
            existing_resp = await self.http.post(
                f"{base}{path}",
                data={"username": "admin", "password": "wrongpassword123"}
            )
            
            nonexistent_resp = await self.http.post(
                f"{base}{path}",
                data={"username": f"nonexistent_{random_string(16)}", "password": "wrongpassword123"}
            )
            
            if existing_resp.get("status") and nonexistent_resp.get("status"):
                existing_text = existing_resp.get("text", "").lower()
                nonexistent_text = nonexistent_resp.get("text", "").lower()
                
                if existing_text != nonexistent_text:
                    existing_len = len(existing_text)
                    nonexistent_len = len(nonexistent_text)
                    
                    if abs(existing_len - nonexistent_len) > 50:
                        self.add_finding(
                            "MEDIUM",
                            f"Username enumeration via response length",
                            url=f"{base}{path}",
                            evidence=f"Different response sizes: {existing_len} vs {nonexistent_len}"
                        )
                    
                    enum_indicators = [
                        ("invalid password", "user not found"),
                        ("wrong password", "no user"),
                        ("incorrect password", "account not found"),
                        ("password incorrect", "username not found"),
                    ]
                    
                    for valid_msg, invalid_msg in enum_indicators:
                        if valid_msg in existing_text and invalid_msg in nonexistent_text:
                            self.add_finding(
                                "HIGH",
                                f"Username enumeration via error message",
                                url=f"{base}{path}",
                                evidence=f"Different messages for valid/invalid users"
                            )
                            return
    
    async def _test_email_enumeration(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in self.password_reset_paths:
            existing_resp = await self.http.post(
                f"{base}{path}",
                data={"email": "admin@" + parsed.netloc.replace("www.", "")}
            )
            
            nonexistent_resp = await self.http.post(
                f"{base}{path}",
                data={"email": f"nonexistent_{random_string(16)}@test.com"}
            )
            
            if existing_resp.get("status") and nonexistent_resp.get("status"):
                existing_text = existing_resp.get("text", "").lower()
                nonexistent_text = nonexistent_resp.get("text", "").lower()
                
                if existing_text != nonexistent_text:
                    self.add_finding(
                        "MEDIUM",
                        f"Email enumeration on password reset",
                        url=f"{base}{path}",
                        evidence="Different responses for valid/invalid emails"
                    )
                    return
    
    async def _test_password_policy(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in self.registration_paths:
            resp = await self.http.get(f"{base}{path}")
            
            if resp.get("status") == 200 and "<form" in resp.get("text", "").lower():
                for weak_pass in self.weak_passwords[:3]:
                    reg_resp = await self.http.post(
                        f"{base}{path}",
                        data={
                            "username": f"test_{random_string(8)}",
                            "email": f"test_{random_string(8)}@test.com",
                            "password": weak_pass,
                            "password_confirm": weak_pass,
                        }
                    )
                    
                    if reg_resp.get("status") in [200, 201, 302]:
                        resp_text = reg_resp.get("text", "").lower()
                        if "weak" not in resp_text and "strong" not in resp_text and "policy" not in resp_text:
                            if any(x in resp_text for x in ["success", "created", "welcome"]):
                                self.add_finding(
                                    "HIGH",
                                    f"Weak password accepted: {weak_pass}",
                                    url=f"{base}{path}",
                                    evidence="No password complexity requirements"
                                )
                                return
                break
    
    async def _test_profile_idor(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        idor_patterns = [
            "/user/{id}", "/profile/{id}", "/account/{id}",
            "/api/user/{id}", "/api/users/{id}", "/api/profile/{id}",
            "/user?id={id}", "/profile?id={id}", "/account?id={id}",
        ]
        
        for pattern in idor_patterns:
            for test_id in [1, 2, 100, 1000]:
                test_url = f"{base}{pattern.replace('{id}', str(test_id))}"
                resp = await self.http.get(test_url)
                
                if resp.get("status") == 200:
                    text = resp.get("text", "").lower()
                    
                    sensitive_fields = ["email", "phone", "address", "password", "ssn", "credit"]
                    
                    if any(field in text for field in sensitive_fields):
                        self.add_finding(
                            "HIGH",
                            f"Profile IDOR: User {test_id} data exposed",
                            url=test_url,
                            evidence="User profile accessible without auth"
                        )
                        return
    
    async def _test_mass_assignment(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in self.registration_paths + self.profile_paths:
            test_data = {
                "username": f"test_{random_string(8)}",
                "email": f"test_{random_string(8)}@test.com",
                "password": "TestPass123!",
                "role": "admin",
                "is_admin": True,
                "admin": 1,
                "privilege": "administrator",
                "user_type": "admin",
                "account_type": "premium",
                "verified": True,
                "email_verified": True,
                "balance": 99999,
                "credits": 99999,
            }
            
            resp = await self.http.post(f"{base}{path}", data=test_data)
            
            if resp.get("status") in [200, 201, 302]:
                resp_text = resp.get("text", "")
                
                dangerous_accepted = []
                for field in ["role", "is_admin", "admin", "privilege", "verified", "balance"]:
                    if field in resp_text.lower():
                        dangerous_accepted.append(field)
                
                if dangerous_accepted:
                    self.add_finding(
                        "CRITICAL",
                        f"Mass assignment vulnerability",
                        url=f"{base}{path}",
                        evidence=f"Sensitive fields accepted: {', '.join(dangerous_accepted)}"
                    )
                    return
            
            resp = await self.http.post(f"{base}{path}", json=test_data)
            
            if resp.get("status") in [200, 201, 302]:
                self.add_finding(
                    "MEDIUM",
                    f"JSON mass assignment possible",
                    url=f"{base}{path}",
                    evidence="Endpoint accepts JSON with extra fields"
                )
    
    async def _test_account_takeover(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in self.password_reset_paths:
            resp = await self.http.get(f"{base}{path}")
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                if "token" in text.lower():
                    token_patterns = [
                        r'token=([a-f0-9]{32,})',
                        r'reset[_-]?token=([^&"\']+)',
                        r'code=([a-f0-9]{6,})',
                    ]
                    
                    for pattern in token_patterns:
                        matches = re.findall(pattern, text, re.IGNORECASE)
                        if matches:
                            self.add_finding(
                                "HIGH",
                                f"Reset token exposed in page",
                                url=f"{base}{path}",
                                evidence=f"Token visible: {matches[0][:20]}..."
                            )
                
                reset_resp = await self.http.post(
                    f"{base}{path}",
                    data={
                        "email": "victim@test.com",
                        "new_password": "hacked123",
                    }
                )
                
                if reset_resp.get("status") == 200:
                    if "token" not in reset_resp.get("text", "").lower():
                        self.add_finding(
                            "CRITICAL",
                            f"Password reset without token",
                            url=f"{base}{path}",
                            evidence="Password reset may not require token"
                        )
    
    async def _test_verification_bypass(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        verify_paths = [
            "/verify", "/confirm", "/activate", "/verify-email",
            "/api/verify", "/api/confirm", "/email/verify",
        ]
        
        for path in verify_paths:
            for token in ["1", "true", "verified", "bypass", "admin"]:
                test_url = f"{base}{path}?token={token}"
                resp = await self.http.get(test_url)
                
                if resp.get("status") == 200:
                    text = resp.get("text", "").lower()
                    if any(x in text for x in ["verified", "confirmed", "activated", "success"]):
                        self.add_finding(
                            "CRITICAL",
                            f"Email verification bypass",
                            url=test_url,
                            evidence=f"Weak token accepted: {token}"
                        )
                        return
            
            for test_id in [1, 2, 3]:
                resp = await self.http.post(
                    f"{base}{path}",
                    data={"user_id": test_id, "verified": True}
                )
                
                if resp.get("status") == 200:
                    if "success" in resp.get("text", "").lower():
                        self.add_finding(
                            "CRITICAL",
                            f"Verification IDOR",
                            url=f"{base}{path}",
                            evidence="Can verify arbitrary user IDs"
                        )
                        return
