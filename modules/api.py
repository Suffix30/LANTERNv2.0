import re
import json
from urllib.parse import urlparse, urljoin
from modules.base import BaseModule

class ApiModule(BaseModule):
    name = "api"
    description = "REST API Security Scanner"
    
    api_paths = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/rest/v2",
        "/v1", "/v2", "/v3",
        "/graphql", "/graphiql",
        "/swagger", "/swagger-ui", "/swagger-ui.html",
        "/api-docs", "/openapi", "/openapi.json", "/openapi.yaml",
        "/redoc", "/docs", "/documentation",
    ]
    
    common_api_endpoints = [
        "/users", "/user", "/me", "/profile", "/account",
        "/admin", "/administrators", "/roles", "/permissions",
        "/auth", "/login", "/logout", "/register", "/signup",
        "/token", "/tokens", "/refresh", "/oauth",
        "/config", "/configuration", "/settings",
        "/health", "/status", "/ping", "/info", "/version",
        "/debug", "/trace", "/metrics", "/stats",
        "/files", "/upload", "/download", "/export", "/import",
        "/search", "/query", "/filter",
        "/orders", "/products", "/items", "/cart", "/checkout",
        "/payments", "/transactions", "/invoices",
        "/messages", "/notifications", "/emails",
        "/logs", "/audit", "/events",
        "/internal", "/private", "/secret", "/hidden",
    ]
    
    async def scan(self, target):
        self.findings = []
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        api_base = await self._find_api_base(base_url)
        
        if api_base:
            self.add_finding(
                "INFO",
                f"API endpoint found",
                url=api_base,
                evidence="REST API detected"
            )
            
            await self._test_api_enumeration(api_base)
            await self._test_api_auth(api_base)
            await self._test_api_methods(api_base)
            await self._test_mass_assignment(api_base)
            await self._test_api_versioning(base_url)
        
        await self._check_api_docs(base_url)
        
        return self.findings
    
    async def _find_api_base(self, base_url):
        for path in self.api_paths[:8]:
            url = urljoin(base_url, path)
            resp = await self.http.get(url)
            
            if resp.get("status") in [200, 401, 403]:
                content_type = resp.get("headers", {}).get("Content-Type", "")
                if "json" in content_type or resp.get("text", "").strip().startswith("{"):
                    return url
        
        return None
    
    async def _test_api_enumeration(self, api_base):
        for endpoint in self.common_api_endpoints[:15]:
            url = urljoin(api_base + "/", endpoint.lstrip("/"))
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                try:
                    data = json.loads(text)
                    if isinstance(data, list) and len(data) > 0:
                        self.add_finding(
                            "MEDIUM",
                            f"API endpoint exposes data: {endpoint}",
                            url=url,
                            evidence=f"Returns {len(data)} items"
                        )
                    elif isinstance(data, dict):
                        sensitive_keys = ["password", "secret", "token", "key", "credential", "ssn", "credit"]
                        found_sensitive = [k for k in data.keys() if any(s in k.lower() for s in sensitive_keys)]
                        if found_sensitive:
                            self.add_finding(
                                "HIGH",
                                f"API exposes sensitive fields: {endpoint}",
                                url=url,
                                evidence=f"Fields: {', '.join(found_sensitive[:5])}"
                            )
                except:
                    pass
            elif resp.get("status") == 401:
                self.add_finding(
                    "INFO",
                    f"Protected API endpoint: {endpoint}",
                    url=url,
                    evidence="Requires authentication"
                )
            elif resp.get("status") == 403:
                self.add_finding(
                    "LOW",
                    f"Forbidden API endpoint: {endpoint}",
                    url=url,
                    evidence="Access denied (endpoint exists)"
                )
    
    async def _test_api_auth(self, api_base):
        no_auth_resp = await self.http.get(api_base)
        
        auth_bypasses = [
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"Authorization": "Bearer "},
            {"Authorization": "Basic YWRtaW46YWRtaW4="},
            {"X-API-Key": "null"},
            {"X-API-Key": "undefined"},
            {"X-API-Key": ""},
            {"X-Auth-Token": "null"},
        ]
        
        for bypass_headers in auth_bypasses:
            resp = await self.http.get(api_base, headers=bypass_headers)
            
            if resp.get("status") == 200 and no_auth_resp.get("status") in [401, 403]:
                self.add_finding(
                    "CRITICAL",
                    f"API Authentication Bypass",
                    url=api_base,
                    evidence=f"Bypass via: {list(bypass_headers.keys())[0]}"
                )
                return
    
    async def _test_api_methods(self, api_base):
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]
        
        for method in methods:
            resp = await self.http.request(method, api_base)
            
            if method == "TRACE" and resp.get("status") == 200:
                self.add_finding(
                    "MEDIUM",
                    f"TRACE method enabled",
                    url=api_base,
                    evidence="Cross-Site Tracing (XST) possible"
                )
            elif method == "OPTIONS" and resp.get("status") == 200:
                allow = resp.get("headers", {}).get("Allow", "")
                if allow:
                    self.add_finding(
                        "INFO",
                        f"API methods disclosed",
                        url=api_base,
                        evidence=f"Allow: {allow}"
                    )
            elif method in ["PUT", "DELETE"] and resp.get("status") in [200, 201, 204]:
                self.add_finding(
                    "HIGH",
                    f"Dangerous HTTP method allowed: {method}",
                    url=api_base,
                    evidence=f"{method} returns {resp.get('status')}"
                )
    
    async def _test_mass_assignment(self, api_base):
        test_endpoints = ["/users", "/user", "/profile", "/account", "/me"]
        
        dangerous_fields = {
            "role": "admin",
            "isAdmin": True,
            "admin": True,
            "is_admin": True,
            "permissions": ["admin", "root"],
            "level": 9999,
            "verified": True,
            "active": True,
        }
        
        for endpoint in test_endpoints:
            url = urljoin(api_base + "/", endpoint.lstrip("/"))
            
            for method in ["POST", "PUT", "PATCH"]:
                resp = await self.http.request(
                    method, url,
                    json=dangerous_fields,
                    headers={"Content-Type": "application/json"}
                )
                
                if resp.get("status") in [200, 201]:
                    text = resp.get("text", "")
                    if any(field in text for field in ["admin", "role", "permission"]):
                        self.add_finding(
                            "HIGH",
                            f"Potential Mass Assignment: {endpoint}",
                            url=url,
                            evidence=f"{method} accepts privileged fields"
                        )
                        return
    
    async def _test_api_versioning(self, base_url):
        old_versions = ["/api/v0", "/api/v1", "/api/v0.1", "/api/beta", "/api/test", "/api/dev"]
        
        for version in old_versions:
            url = urljoin(base_url, version)
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                self.add_finding(
                    "MEDIUM",
                    f"Old/deprecated API version accessible",
                    url=url,
                    evidence="May lack security patches"
                )
    
    async def _check_api_docs(self, base_url):
        doc_paths = [
            "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
            "/api-docs", "/swagger-ui.html", "/swagger/", "/redoc",
            "/api/swagger.json", "/v1/swagger.json", "/v2/swagger.json",
        ]
        
        for path in doc_paths:
            url = urljoin(base_url, path)
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                if "swagger" in text.lower() or "openapi" in text.lower() or "paths" in text:
                    self.add_finding(
                        "LOW",
                        f"API documentation exposed",
                        url=url,
                        evidence="Swagger/OpenAPI spec accessible"
                    )
                    return
    
    def _detect_api_version(self, text):
        version_patterns = [
            re.compile(r'["\']?version["\']?\s*:\s*["\']?([\d\.]+)', re.IGNORECASE),
            re.compile(r'/v(\d+)/', re.IGNORECASE),
            re.compile(r'api[_-]?version["\']?\s*:\s*["\']?([\d\.]+)', re.IGNORECASE),
        ]
        for pattern in version_patterns:
            match = pattern.search(text)
            if match:
                return match.group(1)
        return None
    
    def _extract_api_paths(self, text):
        path_pattern = re.compile(r'["\']?(/(?:api|v\d+)/[a-zA-Z0-9_/\-]+)["\']?', re.IGNORECASE)
        return list(set(path_pattern.findall(text)))
