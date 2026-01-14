import re
import hashlib
from modules.base import BaseModule
from core.utils import random_string

class SessionModule(BaseModule):
    name = "session"
    description = "Session Management Security Scanner"
    
    async def scan(self, target):
        self.findings = []
        
        await self._test_session_fixation(target)
        await self._test_session_prediction(target)
        await self._test_concurrent_sessions(target)
        await self._test_session_timeout(target)
        await self._test_logout_invalidation(target)
        
        return self.findings
    
    async def _test_session_fixation(self, target):
        resp1 = await self.http.get(target)
        if not resp1.get("status"):
            return
        
        session1 = self._extract_session_id(resp1)
        
        if session1:
            resp2 = await self.http.get(target, headers={"Cookie": f"{session1['name']}={session1['value']}"})
            
            if resp2.get("status"):
                session2 = self._extract_session_id(resp2)
                
                if not session2 or session2["value"] == session1["value"]:
                    self.add_finding(
                        "HIGH",
                        "Session Fixation vulnerability",
                        url=target,
                        evidence="Server accepts and maintains pre-set session ID"
                    )
    
    async def _test_session_prediction(self, target):
        sessions = []
        
        for _ in range(5):
            resp = await self.http.get(target)
            if resp.get("status"):
                session = self._extract_session_id(resp)
                if session:
                    sessions.append(session["value"])
        
        if len(sessions) >= 3:
            if self._check_sequential(sessions):
                self.add_finding(
                    "CRITICAL",
                    "Predictable session IDs (sequential)",
                    url=target,
                    evidence="Session IDs appear to be sequential"
                )
            elif self._check_low_entropy(sessions):
                self.add_finding(
                    "HIGH",
                    "Low entropy session IDs",
                    url=target,
                    evidence="Session IDs may be predictable"
                )
            
            lengths = set(len(s) for s in sessions)
            if len(lengths) > 1:
                self.add_finding(
                    "LOW",
                    "Inconsistent session ID length",
                    url=target,
                    evidence=f"Lengths: {lengths}"
                )
    
    async def _test_concurrent_sessions(self, target):
        resp1 = await self.http.get(target)
        resp2 = await self.http.get(target)
        
        if resp1.get("status") and resp2.get("status"):
            session1 = self._extract_session_id(resp1)
            session2 = self._extract_session_id(resp2)
            
            if session1 and session2 and session1["value"] != session2["value"]:
                self.add_finding(
                    "INFO",
                    "Multiple concurrent sessions allowed",
                    url=target,
                    evidence="Different session IDs for parallel requests"
                )
    
    async def _test_session_timeout(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        session = self._extract_session_id(resp)
        if not session:
            return
        
        cookie_header = resp.get("headers", {}).get("Set-Cookie", "")
        
        if "expires=" not in cookie_header.lower() and "max-age=" not in cookie_header.lower():
            self.add_finding(
                "MEDIUM",
                "Session cookie without expiration",
                url=target,
                evidence="Session persists until browser closes (or indefinitely)"
            )
        
        if "max-age=" in cookie_header.lower():
            match = re.search(r'max-age=(\d+)', cookie_header, re.IGNORECASE)
            if match:
                max_age = int(match.group(1))
                if max_age > 86400 * 7:
                    self.add_finding(
                        "LOW",
                        "Long session timeout",
                        url=target,
                        evidence=f"Session valid for {max_age // 86400} days"
                    )
    
    async def _test_logout_invalidation(self, target):
        logout_paths = ["/logout", "/signout", "/sign-out", "/log-out", "/api/logout", "/auth/logout"]
        
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        session = self._extract_session_id(resp)
        if not session:
            return
        
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in logout_paths:
            logout_url = urljoin(base_url, path)
            logout_resp = await self.http.get(logout_url, headers={"Cookie": f"{session['name']}={session['value']}"})
            
            if logout_resp.get("status") in [200, 302]:
                reuse_resp = await self.http.get(target, headers={"Cookie": f"{session['name']}={session['value']}"})
                
                if reuse_resp.get("status") == 200:
                    if "login" not in reuse_resp.get("text", "").lower():
                        self.add_finding(
                            "HIGH",
                            "Session not invalidated on logout",
                            url=logout_url,
                            evidence="Session ID still valid after logout"
                        )
                        return
    
    def _extract_session_id(self, resp):
        cookie_header = resp.get("headers", {}).get("Set-Cookie", "")
        
        if not cookie_header:
            return None
        
        session_names = ["session", "sess", "sid", "ssid", "phpsessid", "jsessionid", "aspsessionid", "connect.sid"]
        
        for name in session_names:
            pattern = rf'{name}=([^;]+)'
            match = re.search(pattern, cookie_header, re.IGNORECASE)
            if match:
                return {"name": name, "value": match.group(1)}
        
        match = re.search(r'([^=]+)=([^;]+)', cookie_header)
        if match:
            return {"name": match.group(1), "value": match.group(2)}
        
        return None
    
    def _check_sequential(self, sessions):
        try:
            nums = [int(s) for s in sessions if s.isdigit()]
            if len(nums) >= 3:
                diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
                if len(set(diffs)) == 1:
                    return True
        except:
            pass
        return False
    
    def _check_low_entropy(self, sessions):
        if all(s.isdigit() for s in sessions):
            return True
        
        if all(len(s) < 16 for s in sessions):
            return True
        
        char_sets = []
        for s in sessions:
            chars = set(s.lower())
            char_sets.append(len(chars))
        
        if sum(char_sets) / len(char_sets) < 10:
            return True
        
        hashes = [hashlib.md5(s.encode()).hexdigest()[:8] for s in sessions]
        if len(set(hashes)) < len(sessions):
            return True
        
        return False
    
    def _generate_test_session(self):
        return random_string(32)