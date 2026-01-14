import re
from urllib.parse import urlparse, urljoin 
from modules.base import BaseModule


class ApiverModule(BaseModule):
    name = "apiver"
    description = "API Version Discovery Scanner"
    
    version_patterns = [
        "/api/v{n}/",
        "/api/v{n}.",
        "/v{n}/api/",
        "/v{n}/",
        "/api/{n}/",
        "/api-v{n}/",
        "/api_{n}/",
        "/{n}/api/",
    ]
    
    version_headers = [
        "X-API-Version",
        "API-Version",
        "Accept-Version",
        "X-Version",
    ]
    
    version_params = [
        "api_version",
        "apiVersion", 
        "version",
        "v",
        "api-version",
    ]
    
    common_endpoints = [
        "/users",
        "/user",
        "/account",
        "/profile",
        "/settings",
        "/admin",
        "/config",
        "/data",
        "/items",
        "/products",
        "/orders",
        "/auth",
        "/login",
        "/token",
        "/health",
        "/status",
        "/info",
        "/debug",
    ]
    
    async def scan(self, target):
        self.findings = []
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        current_version = self._detect_current_version(target)
        
        await self._scan_path_versions(base_url, current_version)
        await self._scan_header_versions(target)
        await self._scan_param_versions(target)
        await self._scan_deprecated_endpoints(base_url)
        
        return self.findings
    
    def _detect_current_version(self, url):
        match = re.search(r'/v(\d+)(?:\.\d+)?/', url)
        if match:
            return int(match.group(1))
        
        match = re.search(r'/api/(\d+)/', url)
        if match:
            return int(match.group(1))
        
        return None
    
    async def _scan_path_versions(self, base_url, current_version):
        found_versions = {}
        
        max_version = (current_version or 1) + 5
        
        for version in range(0, max_version + 1):
            for pattern in self.version_patterns:
                path = pattern.replace("{n}", str(version))
                
                for endpoint in self.common_endpoints[:5]:
                    url = base_url + path + endpoint.lstrip("/")
                    
                    resp = await self.http.get(url)
                    
                    if resp.get("status") in [200, 201, 401, 403]:
                        if version not in found_versions:
                            found_versions[version] = []
                        found_versions[version].append(url)
                        break
        
        for version, urls in found_versions.items():
            is_older = current_version and version < current_version
            
            if is_older:
                severity = "HIGH"
                desc = f"Deprecated API v{version} Still Accessible"
            elif current_version and version > current_version:
                severity = "MEDIUM"
                desc = f"Unreleased API v{version} Accessible"
            else:
                severity = "INFO"
                desc = f"API v{version} Discovered"
            
            self.add_finding(
                severity,
                desc,
                url=urls[0],
                evidence=f"Version {version} accessible at {len(urls)} endpoints"
            )
        
        if current_version:
            older_versions = [v for v in found_versions.keys() if v < current_version]
            if older_versions:
                await self._compare_versions(base_url, current_version, min(older_versions))
    
    async def _scan_header_versions(self, target):
        for header in self.version_headers:
            for version in ["0", "1", "2", "0.1", "1.0", "2.0", "beta", "legacy", "deprecated"]:
                resp = await self.http.get(target, headers={header: version})
                
                if resp.get("status") == 200:
                    baseline = await self.http.get(target)
                    
                    if len(resp.get("text", "")) != len(baseline.get("text", "")):
                        self.add_finding(
                            "MEDIUM",
                            f"API Version Control via {header} Header",
                            url=target,
                            evidence=f"Header {header}: {version} returns different response"
                        )
                        return
    
    async def _scan_param_versions(self, target):
        for param in self.version_params:
            for version in ["0", "1", "2", "0.1", "1.0", "2.0", "beta", "legacy"]:
                if "?" in target:
                    url = f"{target}&{param}={version}"
                else:
                    url = f"{target}?{param}={version}"
                
                resp = await self.http.get(url)
                
                if resp.get("status") == 200:
                    baseline = await self.http.get(target)
                    
                    if len(resp.get("text", "")) != len(baseline.get("text", "")):
                        self.add_finding(
                            "MEDIUM",
                            f"API Version Control via {param} Parameter",
                            url=url,
                            evidence=f"Parameter {param}={version} returns different response"
                        )
                        return
    
    async def _scan_deprecated_endpoints(self, base_url):
        deprecated_patterns = [
            "/api/old/",
            "/api/legacy/",
            "/api/deprecated/",
            "/old-api/",
            "/legacy/",
            "/api/beta/",
            "/api/alpha/",
            "/api/dev/",
            "/api/test/",
            "/api/staging/",
            "/api/internal/",
            "/api-old/",
            "/api-legacy/",
            "/_api/",
            "/api_internal/",
        ]
        
        for pattern in deprecated_patterns:
            for endpoint in self.common_endpoints[:3]:
                url = base_url + pattern + endpoint.lstrip("/")
                
                resp = await self.http.get(url)
                
                if resp.get("status") in [200, 201, 401, 403]:
                    self.add_finding(
                        "HIGH",
                        f"Deprecated/Internal API Endpoint Accessible",
                        url=url,
                        evidence=f"Pattern: {pattern}"
                    )
                    break
    
    async def _compare_versions(self, base_url, current, older):
        current_path = f"/api/v{current}"
        older_path = f"/api/v{older}"
        
        for endpoint in self.common_endpoints:
            current_url = urljoin(base_url, current_path + endpoint)
            older_url = urljoin(base_url, older_path + endpoint)
            
            current_resp = await self.http.get(current_url)
            older_resp = await self.http.get(older_url)
            
            if current_resp.get("status") == 401 and older_resp.get("status") == 200:
                self.add_finding(
                    "CRITICAL",
                    f"Auth Bypass via Old API Version",
                    url=older_url,
                    evidence=f"v{older} returns 200, v{current} returns 401"
                )
            
            if current_resp.get("status") == 200 and older_resp.get("status") == 200:
                current_text = current_resp.get("text", "")
                older_text = older_resp.get("text", "")
                
                current_fields = set(re.findall(r'"(\w+)":', current_text))
                older_fields = set(re.findall(r'"(\w+)":', older_text))
                
                extra_in_old = older_fields - current_fields
                
                sensitive = ["password", "secret", "token", "key", "hash", "ssn", "credit"]
                exposed_sensitive = [f for f in extra_in_old if any(s in f.lower() for s in sensitive)]
                
                if exposed_sensitive:
                    self.add_finding(
                        "HIGH",
                        f"Sensitive Data Exposed in Old API Version",
                        url=older_url,
                        evidence=f"v{older} exposes: {', '.join(exposed_sensitive)}"
                    )
