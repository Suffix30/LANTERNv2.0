import re
import asyncio
from urllib.parse import urljoin, urlparse
from modules.base import BaseModule


class AccessctlModule(BaseModule):
    name = "accessctl"
    description = "Access Control / Privilege Escalation Scanner"
    exploitable = True
    
    admin_endpoints = [
        "/admin", "/admin/", "/administrator", "/manage", "/management",
        "/dashboard", "/panel", "/control", "/backend", "/cms",
        "/api/admin", "/api/users", "/api/settings", "/api/config",
        "/users", "/users/all", "/accounts", "/settings", "/config",
    ]
    
    sensitive_actions = [
        {"path": "/api/users", "method": "DELETE", "name": "Delete user"},
        {"path": "/api/users/role", "method": "PUT", "name": "Change role"},
        {"path": "/api/settings", "method": "POST", "name": "Modify settings"},
        {"path": "/api/admin/users", "method": "GET", "name": "List all users"},
        {"path": "/admin/config", "method": "POST", "name": "Update config"},
        {"path": "/api/export", "method": "GET", "name": "Export data"},
        {"path": "/api/backup", "method": "POST", "name": "Create backup"},
    ]
    
    async def scan(self, target):
        self.findings = []
        self.auth_manager = None
        self.sessions = {}
        self.access_violations = []
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        auth_config = self.config.get("auth_config")
        if auth_config:
            await self._setup_auth_manager(auth_config)
        
        await self._test_unauth_admin_access(base_url)
        
        if self.auth_manager and len(self.sessions) >= 2:
            await self._test_horizontal_access(base_url)
            await self._test_vertical_escalation(base_url)
            await self._test_function_level_access(base_url)
        
        await self._test_forced_browsing(base_url)
        await self._test_method_override(base_url)
        
        if self.aggressive:
            await self._test_jwt_manipulation(target)
            await self._test_parameter_pollution(base_url)
        
        return self.findings
    
    async def _setup_auth_manager(self, config):
        try:
            from core.auth_manager import create_auth_manager
            self.auth_manager = await create_auth_manager(config, self.http)
            
            for role, creds in config.get("credentials", {}).items():
                if creds:
                    session = await self.auth_manager.login(role)
                    if session:
                        self.sessions[role] = session
        except Exception:
            pass
    
    async def _test_unauth_admin_access(self, base_url):
        for endpoint in self.admin_endpoints:
            url = urljoin(base_url, endpoint)
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                text = (resp.get("text") or "").lower()
                
                if any(kw in text for kw in ["admin", "dashboard", "manage", "users", "settings"]):
                    if "login" not in text and "sign in" not in text:
                        self.add_finding(
                            "CRITICAL",
                            f"Unauthenticated admin access: {endpoint}",
                            url=url,
                            evidence="Admin functionality accessible without authentication",
                            confidence_evidence=["admin_content_exposed", "no_auth_required"],
                            request_data={"method": "GET", "url": url}
                        )
                        self.access_violations.append({"type": "unauth_admin", "endpoint": endpoint})
    
    async def _test_horizontal_access(self, base_url):
        roles = list(self.sessions.keys())
        
        same_level_roles = [r for r in roles if "admin" not in r.lower()]
        if len(same_level_roles) < 2:
            return
        
        user_a = same_level_roles[0]
        user_b = same_level_roles[1]
        
        user_specific_endpoints = [
            "/api/profile", "/api/account", "/api/orders", "/api/data",
            "/user/settings", "/my/data", "/account/info",
        ]
        
        for endpoint in user_specific_endpoints:
            url = urljoin(base_url, endpoint)
            
            resp_a = await self.auth_manager.request_as(user_a, "GET", url)
            
            if resp_a.get("status") != 200:
                continue
            
            user_a_data = self._extract_identifiers(resp_a.get("text", ""))
            
            if not user_a_data:
                continue
            
            resp_b = await self.auth_manager.request_as(user_b, "GET", url)
            
            if resp_b.get("status") == 200:
                user_b_text = resp_b.get("text", "")
                
                for identifier in user_a_data:
                    if identifier in user_b_text:
                        self.add_finding(
                            "CRITICAL",
                            f"Horizontal privilege escalation: {endpoint}",
                            url=url,
                            evidence=f"{user_b} can access {user_a}'s data",
                            confidence_evidence=["cross_user_data_leak", "horizontal_privesc"],
                            request_data={"method": "GET", "url": url, "user_a": user_a, "user_b": user_b}
                        )
                        self.access_violations.append({
                            "type": "horizontal",
                            "endpoint": endpoint,
                            "user_a": user_a,
                            "user_b": user_b
                        })
                        return
    
    async def _test_vertical_escalation(self, base_url):
        admin_role = next((r for r in self.sessions.keys() if "admin" in r.lower()), None)
        user_role = next((r for r in self.sessions.keys() if "admin" not in r.lower()), None)
        
        if not admin_role or not user_role:
            return
        
        for action in self.sensitive_actions:
            url = urljoin(base_url, action["path"])
            
            admin_resp = await self.auth_manager.request_as(
                admin_role, action["method"], url, json={}
            )
            
            if admin_resp.get("status") not in [200, 201, 204]:
                continue
            
            user_resp = await self.auth_manager.request_as(
                user_role, action["method"], url, json={}
            )
            
            if user_resp.get("status") in [200, 201, 204]:
                user_text = (user_resp.get("text") or "").lower()
                if "denied" not in user_text and "forbidden" not in user_text and "unauthorized" not in user_text:
                    self.add_finding(
                        "CRITICAL",
                        f"Vertical privilege escalation: {action['name']}",
                        url=url,
                        evidence=f"User role can perform admin action: {action['method']} {action['path']}",
                        confidence_evidence=["admin_action_as_user", "vertical_privesc"],
                        request_data={"method": action["method"], "url": url, "role": user_role}
                    )
                    self.access_violations.append({
                        "type": "vertical",
                        "action": action["name"],
                        "endpoint": action["path"]
                    })
    
    async def _test_function_level_access(self, base_url):
        functions = [
            {"endpoint": "/api/users/{id}/delete", "method": "DELETE", "ids": ["1", "2", "admin"]},
            {"endpoint": "/api/users/{id}/role", "method": "PUT", "data": {"role": "admin"}},
            {"endpoint": "/api/orders/{id}/refund", "method": "POST", "ids": ["1", "999"]},
            {"endpoint": "/api/documents/{id}/download", "method": "GET", "ids": ["1", "private"]},
        ]
        
        user_role = next((r for r in self.sessions.keys() if "admin" not in r.lower()), None)
        if not user_role:
            return
        
        for func in functions:
            for test_id in func.get("ids", ["1"]):
                endpoint = func["endpoint"].replace("{id}", test_id)
                url = urljoin(base_url, endpoint)
                
                resp = await self.auth_manager.request_as(
                    user_role, func["method"], url, json=func.get("data", {})
                )
                
                if resp.get("status") in [200, 201, 204]:
                    text = (resp.get("text") or "").lower()
                    if "success" in text or "deleted" in text or "updated" in text:
                        self.add_finding(
                            "CRITICAL",
                            f"Function-level access control bypass: {endpoint}",
                            url=url,
                            evidence=f"User can access function on ID: {test_id}",
                            confidence_evidence=["function_access_bypass", "idor_like"],
                            request_data={"method": func["method"], "url": url}
                        )
                        return
    
    async def _test_forced_browsing(self, base_url):
        hidden_paths = [
            "/debug", "/test", "/dev", "/staging", "/internal",
            "/api/internal", "/api/debug", "/api/test",
            "/.git", "/.env", "/backup", "/old", "/temp",
            "/api/v1/internal", "/api/private", "/hidden",
        ]
        
        for path in hidden_paths:
            url = urljoin(base_url, path)
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                if len(text) > 100 and "404" not in text.lower() and "not found" not in text.lower():
                    self.add_finding(
                        "MEDIUM",
                        f"Hidden endpoint accessible: {path}",
                        url=url,
                        evidence=f"Unprotected internal path",
                        confidence_evidence=["forced_browsing"]
                    )
    
    async def _test_method_override(self, base_url):
        override_headers = [
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-Method-Override", "PUT"),
            ("X-HTTP-Method", "DELETE"),
            ("_method", "DELETE"),
        ]
        
        test_url = urljoin(base_url, "/api/users/1")
        
        for header_name, method in override_headers:
            resp = await self.http.post(
                test_url,
                headers={header_name: method},
                json={}
            )
            
            if resp.get("status") in [200, 204]:
                text = (resp.get("text") or "").lower()
                if "deleted" in text or "success" in text:
                    self.add_finding(
                        "HIGH",
                        f"HTTP method override accepted: {header_name}",
                        url=test_url,
                        evidence=f"POST with {header_name}: {method} executed as {method}",
                        confidence_evidence=["method_override_bypass"],
                        request_data={"method": "POST", "url": test_url, "header": header_name}
                    )
                    return
    
    async def _test_jwt_manipulation(self, target):
        resp = await self.http.get(target)
        cookies = resp.get("headers", {}).get("set-cookie", "")
        auth_header = resp.get("headers", {}).get("authorization", "")
        
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        
        jwt_token = None
        for source in [cookies, auth_header, resp.get("text", "")]:
            match = re.search(jwt_pattern, str(source))
            if match:
                jwt_token = match.group(0)
                break
        
        if not jwt_token:
            return
        
        import base64
        parts = jwt_token.split(".")
        if len(parts) != 3:
            return
        
        try:
            header = base64.urlsafe_b64decode(parts[0] + "==").decode()
            if '"alg":"none"' not in header.lower():
                none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
                none_jwt = f"{none_header}.{parts[1]}."
                
                test_resp = await self.http.get(
                    target,
                    headers={"Authorization": f"Bearer {none_jwt}"}
                )
                
                if test_resp.get("status") == 200:
                    if "unauthorized" not in (test_resp.get("text") or "").lower():
                        self.add_finding(
                            "CRITICAL",
                            "JWT algorithm none accepted",
                            url=target,
                            evidence="Server accepts unsigned JWT tokens",
                            confidence_evidence=["jwt_alg_none", "auth_bypass"],
                            request_data={"method": "GET", "url": target, "jwt": none_jwt[:50] + "..."}
                        )
        except Exception:
            pass
    
    async def _test_parameter_pollution(self, base_url):
        test_endpoints = ["/api/users", "/api/data", "/search", "/filter"]
        
        for endpoint in test_endpoints:
            url = urljoin(base_url, endpoint)
            
            polluted_url = f"{url}?role=user&role=admin&admin=true&admin=false"
            
            resp = await self.http.get(polluted_url)
            
            if resp.get("status") == 200:
                text = (resp.get("text") or "").lower()
                if "admin" in text and "user" not in text:
                    self.add_finding(
                        "HIGH",
                        f"Parameter pollution accepted: {endpoint}",
                        url=polluted_url,
                        evidence="Duplicate params with conflicting values processed",
                        confidence_evidence=["param_pollution", "access_control_confusion"]
                    )
                    return
    
    def _extract_identifiers(self, content):
        identifiers = []
        
        patterns = [
            r'"id"\s*:\s*"?([^",}\s]+)"?',
            r'"user_id"\s*:\s*"?([^",}\s]+)"?',
            r'"email"\s*:\s*"([^"]+)"',
            r'"username"\s*:\s*"([^"]+)"',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            identifiers.extend(matches)
        
        return list(set(identifiers))[:10]
    
    async def exploit(self, target, finding):
        return {
            "access_violations": self.access_violations,
            "sessions_tested": list(self.sessions.keys()),
        }
