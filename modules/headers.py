import re
from urllib.parse import urlparse, urljoin
from modules.base import BaseModule


class HeadersModule(BaseModule):
    name = "headers"
    description = "Security Headers Analyzer"
    
    security_headers = {
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "description": "Missing HSTS - susceptible to downgrade attacks",
            "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        },
        "Content-Security-Policy": {
            "severity": "MEDIUM",
            "description": "Missing CSP - susceptible to XSS attacks",
            "recommendation": "Add a restrictive CSP policy"
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "description": "Missing X-Content-Type-Options - MIME sniffing possible",
            "recommendation": "Add: X-Content-Type-Options: nosniff"
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "description": "Missing X-Frame-Options - clickjacking possible",
            "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": "Missing Referrer-Policy - potential info leakage",
            "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "description": "Missing Permissions-Policy (Feature-Policy)",
            "recommendation": "Restrict browser features like camera, microphone, geolocation"
        },
        "Cross-Origin-Embedder-Policy": {
            "severity": "LOW",
            "description": "Missing COEP - cross-origin isolation not enabled",
            "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp"
        },
        "Cross-Origin-Opener-Policy": {
            "severity": "LOW",
            "description": "Missing COOP - cross-origin window access possible",
            "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin"
        },
        "Cross-Origin-Resource-Policy": {
            "severity": "LOW",
            "description": "Missing CORP - resources can be loaded cross-origin",
            "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin"
        },
    }
    
    dangerous_headers = {
        "Server": {"severity": "INFO", "description": "Server version disclosed"},
        "X-Powered-By": {"severity": "INFO", "description": "Technology stack disclosed"},
        "X-AspNet-Version": {"severity": "INFO", "description": "ASP.NET version disclosed"},
        "X-AspNetMvc-Version": {"severity": "INFO", "description": "ASP.NET MVC version disclosed"},
        "X-Generator": {"severity": "INFO", "description": "Generator disclosed"},
        "X-Drupal-Cache": {"severity": "INFO", "description": "Drupal CMS detected"},
        "X-Varnish": {"severity": "INFO", "description": "Varnish cache detected"},
        "X-Cache": {"severity": "INFO", "description": "Cache server disclosed"},
        "Via": {"severity": "INFO", "description": "Proxy information disclosed"},
        "X-Backend-Server": {"severity": "MEDIUM", "description": "Backend server disclosed"},
        "X-Debug-Token": {"severity": "HIGH", "description": "Debug token exposed"},
        "X-Debug-Token-Link": {"severity": "HIGH", "description": "Debug link exposed"},
    }
    
    deprecated_headers = {
        "X-XSS-Protection": {
            "severity": "INFO",
            "description": "X-XSS-Protection is deprecated (can cause vulnerabilities)",
            "recommendation": "Remove and rely on CSP instead"
        },
        "Public-Key-Pins": {
            "severity": "INFO", 
            "description": "HPKP is deprecated and removed from browsers",
            "recommendation": "Remove Public-Key-Pins header"
        },
        "Expect-CT": {
            "severity": "INFO",
            "description": "Expect-CT is deprecated (CT now mandatory)",
            "recommendation": "Can be removed as CT is enforced by default"
        },
    }
    
    csp_dangerous_values = {
        "unsafe-inline": ("HIGH", "Allows inline scripts - XSS risk"),
        "unsafe-eval": ("HIGH", "Allows eval() - code injection risk"),
        "unsafe-hashes": ("MEDIUM", "Allows specific inline event handlers"),
        "*": ("HIGH", "Wildcard allows any source"),
        "data:": ("MEDIUM", "data: URIs can bypass CSP"),
        "blob:": ("LOW", "blob: URIs may be exploitable"),
        "'self' *": ("HIGH", "Self with wildcard negates protection"),
        "http:": ("MEDIUM", "HTTP sources on HTTPS page - mixed content"),
    }
    
    csp_missing_directives = {
        "default-src": ("MEDIUM", "No default-src fallback"),
        "script-src": ("HIGH", "No script-src - scripts unrestricted"),
        "object-src": ("HIGH", "No object-src - plugins unrestricted (Flash XSS)"),
        "base-uri": ("MEDIUM", "No base-uri - base tag injection possible"),
        "form-action": ("MEDIUM", "No form-action - forms can submit anywhere"),
        "frame-ancestors": ("MEDIUM", "No frame-ancestors - clickjacking possible"),
    }
    
    permissions_policy_features = [
        "accelerometer", "ambient-light-sensor", "autoplay", "battery", "camera",
        "display-capture", "document-domain", "encrypted-media", "fullscreen",
        "geolocation", "gyroscope", "magnetometer", "microphone", "midi",
        "payment", "picture-in-picture", "publickey-credentials-get", "sync-xhr",
        "usb", "xr-spatial-tracking"
    ]
    
    async def scan(self, target):
        self.findings = []
        
        resp = await self.http.get(target)
        if not resp.get("status"):
            return self.findings
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        text = resp.get("text", "")
        
        await self._check_missing_headers(target, headers)
        await self._check_dangerous_headers(target, headers)
        await self._check_deprecated_headers(target, headers)
        await self._analyze_csp(target, headers)
        await self._analyze_hsts(target, headers)
        await self._analyze_permissions_policy(target, headers)
        await self._check_cookies(target, resp)
        await self._check_cache_headers(target, headers, resp)
        await self._check_cors_headers(target, headers)
        await self._detect_frameworks(target, resp)
        await self._check_third_party_scripts(target, text)
        
        if self.aggressive:
            await self._test_report_uri_reachability(target, headers)
            await self._check_sensitive_endpoints(target)
        
        return self.findings
    
    async def _check_missing_headers(self, target, headers):
        for header, info in self.security_headers.items():
            if header.lower() not in headers:
                self.add_finding(
                    info["severity"],
                    info["description"],
                    url=target,
                    evidence=f"Missing header: {header}",
                    confidence_evidence=["header_missing"]
                )
    
    async def _check_dangerous_headers(self, target, headers):
        for header, info in self.dangerous_headers.items():
            if header.lower() in headers:
                value = headers[header.lower()]
                self.add_finding(
                    info["severity"],
                    f"{info['description']}: {value}",
                    url=target,
                    evidence=f"{header}: {value}",
                    confidence_evidence=["information_disclosure"]
                )
    
    async def _check_deprecated_headers(self, target, headers):
        for header, info in self.deprecated_headers.items():
            if header.lower() in headers:
                self.add_finding(
                    info["severity"],
                    info["description"],
                    url=target,
                    evidence=f"Deprecated: {header}"
                )
    
    async def _analyze_csp(self, target, headers):
        csp = headers.get("content-security-policy", "")
        csp_ro = headers.get("content-security-policy-report-only", "")
        
        if not csp and csp_ro:
            self.add_finding(
                "MEDIUM",
                "CSP is report-only (not enforced)",
                url=target,
                evidence="Content-Security-Policy-Report-Only without enforcing CSP"
            )
            csp = csp_ro
        
        if not csp:
            return
        
        directives = self._parse_csp(csp)
        issues = []
        
        for dangerous, (severity, desc) in self.csp_dangerous_values.items():
            if dangerous in csp:
                issues.append((severity, f"Contains '{dangerous}': {desc}"))
        
        for directive, (severity, desc) in self.csp_missing_directives.items():
            if directive not in directives and "default-src" not in directives:
                issues.append((severity, f"Missing {directive}: {desc}"))
            elif directive not in directives and directive in ["object-src", "base-uri", "form-action"]:
                issues.append((severity, f"Missing {directive} (default-src doesn't cover it): {desc}"))
        
        if "script-src" in directives:
            script_src = directives["script-src"]
            if "'strict-dynamic'" not in script_src and "'nonce-" not in script_src and "'sha" not in script_src:
                if "'unsafe-inline'" in script_src:
                    issues.append(("HIGH", "script-src has unsafe-inline without nonce/hash"))
        
        if "default-src" in directives:
            default = directives["default-src"]
            if default.strip() == "'none'" or default.strip() == "'self'":
                pass
            elif "*" in default:
                issues.append(("HIGH", "default-src contains wildcard"))
        
        if "upgrade-insecure-requests" not in csp and "block-all-mixed-content" not in csp:
            parsed = urlparse(target)
            if parsed.scheme == "https":
                issues.append(("LOW", "Missing upgrade-insecure-requests for HTTPS site"))
        
        cdn_bypasses = [
            "*.googleapis.com", "*.gstatic.com", "*.cloudflare.com",
            "*.jsdelivr.net", "*.unpkg.com", "*.cdnjs.cloudflare.com",
            "*.bootstrapcdn.com", "ajax.googleapis.com", "cdnjs.cloudflare.com"
        ]
        for cdn in cdn_bypasses:
            if cdn.replace("*.", "") in csp.lower() or cdn in csp.lower():
                issues.append(("MEDIUM", f"CDN in CSP may allow bypass via JSONP/Angular: {cdn}"))
                break
        
        if issues:
            high_issues = [i for i in issues if i[0] == "HIGH"]
            medium_issues = [i for i in issues if i[0] == "MEDIUM"]
            
            if high_issues:
                self.add_finding(
                    "HIGH",
                    "CSP has critical weaknesses",
                    url=target,
                    evidence="; ".join([i[1] for i in high_issues[:3]]),
                    confidence_evidence=["csp_weak", "xss_risk"]
                )
            elif medium_issues:
                self.add_finding(
                    "MEDIUM",
                    "CSP has moderate weaknesses",
                    url=target,
                    evidence="; ".join([i[1] for i in medium_issues[:3]]),
                    confidence_evidence=["csp_issues"]
                )
    
    def _parse_csp(self, csp):
        directives = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split(None, 1)
            if tokens:
                directive = tokens[0].lower()
                value = tokens[1] if len(tokens) > 1 else ""
                directives[directive] = value
        return directives
    
    async def _analyze_hsts(self, target, headers):
        hsts = headers.get("strict-transport-security", "")
        
        if not hsts:
            return
        
        issues = []
        
        if "max-age=0" in hsts:
            issues.append(("MEDIUM", "HSTS disabled (max-age=0)"))
        elif "max-age" in hsts:
            try:
                max_age = int(re.search(r'max-age\s*=\s*(\d+)', hsts).group(1))
                if max_age < 2592000:
                    issues.append(("MEDIUM", f"HSTS max-age too short ({max_age}s < 30 days)"))
                elif max_age < 31536000:
                    issues.append(("LOW", f"HSTS max-age less than 1 year ({max_age}s)"))
            except:
                pass
        
        if "includesubdomains" not in hsts.lower():
            issues.append(("LOW", "HSTS missing includeSubDomains"))
        
        if "preload" not in hsts.lower():
            issues.append(("INFO", "HSTS missing preload directive"))
        
        for severity, desc in issues:
            self.add_finding(
                severity,
                f"HSTS Issue: {desc}",
                url=target,
                evidence=f"HSTS: {hsts}"
            )
    
    async def _analyze_permissions_policy(self, target, headers):
        pp = headers.get("permissions-policy", "")
        fp = headers.get("feature-policy", "")
        
        if fp and not pp:
            self.add_finding(
                "INFO",
                "Using deprecated Feature-Policy (use Permissions-Policy)",
                url=target,
                evidence=f"Feature-Policy: {fp[:100]}"
            )
            pp = fp
        
        if not pp:
            return
        
        dangerous_permissions = ["camera", "microphone", "geolocation", "payment"]
        
        for perm in dangerous_permissions:
            if perm not in pp.lower():
                pass
            elif f"{perm}=*" in pp or f"{perm}=()" not in pp:
                if f"{perm}=self" not in pp and f"{perm}=(self)" not in pp:
                    self.add_finding(
                        "LOW",
                        f"Permissions-Policy: {perm} may be too permissive",
                        url=target,
                        evidence=f"Consider restricting {perm}"
                    )
    
    async def _check_cookies(self, target, resp):
        set_cookie = resp.get("headers", {}).get("Set-Cookie", "")
        
        if not set_cookie:
            return
        
        cookies = set_cookie.split(",") if "," in set_cookie else [set_cookie]
        
        for cookie in cookies:
            cookie_lower = cookie.lower()
            issues = []
            
            name_match = re.match(r'([^=]+)=', cookie)
            cookie_name = name_match.group(1).strip() if name_match else "unknown"
            
            is_session = any(s in cookie_name.lower() for s in ["session", "sess", "sid", "auth", "token", "jwt"])
            
            if "httponly" not in cookie_lower:
                issues.append("HttpOnly")
            
            parsed = urlparse(target)
            if parsed.scheme == "https" and "secure" not in cookie_lower:
                issues.append("Secure")
            
            if "samesite" not in cookie_lower:
                issues.append("SameSite")
            elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                issues.append("SameSite=None without Secure")
            
            if "__host-" in cookie_name.lower():
                if "secure" not in cookie_lower or "path=/" not in cookie_lower:
                    issues.append("__Host- prefix requirements not met")
            
            if "__secure-" in cookie_name.lower():
                if "secure" not in cookie_lower:
                    issues.append("__Secure- prefix requires Secure flag")
            
            if issues:
                severity = "HIGH" if is_session and len(issues) >= 2 else "MEDIUM" if is_session else "LOW"
                self.add_finding(
                    severity,
                    f"Cookie '{cookie_name}' missing security flags",
                    url=target,
                    evidence=f"Missing: {', '.join(issues)}",
                    confidence_evidence=["cookie_security_issue"] + (["session_cookie"] if is_session else [])
                )
    
    async def _check_cache_headers(self, target, headers, resp):
        cache_control = headers.get("cache-control", "")
        pragma = headers.get("pragma", "")
        expires = headers.get("expires", "")
        
        text = resp.get("text", "").lower()
        is_sensitive = any(s in target.lower() for s in [
            "login", "auth", "account", "profile", "admin", "dashboard",
            "password", "settings", "payment", "checkout", "order"
        ])
        
        if not is_sensitive:
            is_sensitive = any(s in text for s in [
                "password", "credit card", "ssn", "social security",
                "account number", "bank", "token", "api_key"
            ])
        
        if is_sensitive:
            issues = []
            
            if not cache_control:
                issues.append("No Cache-Control header")
            else:
                if "no-store" not in cache_control.lower():
                    issues.append("Missing no-store")
                if "no-cache" not in cache_control.lower():
                    issues.append("Missing no-cache")
                if "private" not in cache_control.lower() and "public" in cache_control.lower():
                    issues.append("Public caching enabled")
            
            if pragma.lower() != "no-cache" and not cache_control:
                issues.append("No Pragma: no-cache")
            
            if issues:
                self.add_finding(
                    "MEDIUM",
                    "Sensitive page may be cached",
                    url=target,
                    evidence=f"Issues: {', '.join(issues)}",
                    confidence_evidence=["cache_security", "sensitive_data_caching"]
                )
    
    async def _check_cors_headers(self, target, headers):
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        
        if not acao:
            return
        
        if acao == "*" and acac.lower() == "true":
            self.add_finding(
                "CRITICAL",
                "CORS: Wildcard origin with credentials",
                url=target,
                evidence="Access-Control-Allow-Origin: * with credentials=true"
            )
        elif acao == "*":
            self.add_finding(
                "LOW",
                "CORS: Wildcard origin",
                url=target,
                evidence="Access-Control-Allow-Origin: *"
            )
    
    async def _detect_frameworks(self, target, resp):
        text = resp.get("text", "") or ""
        headers = resp.get("headers", {})
        
        signatures = [
            ("WordPress", ["wp-content", "wp-includes", "/wp-json/"]),
            ("Joomla", ["Joomla!", "/administrator/", "com_content"]),
            ("Drupal", ["Drupal.settings", "/sites/default/", "drupal.js"]),
            ("Django", ["csrftoken", "__admin__", "django"]),
            ("Laravel", ["laravel_session", "XSRF-TOKEN"]),
            ("ASP.NET", ["__VIEWSTATE", "__EVENTVALIDATION", ".aspx"]),
            ("Ruby on Rails", ["_session_id", "authenticity_token"]),
            ("Spring", ["JSESSIONID", "spring", "org.springframework"]),
            ("Express.js", ["connect.sid", "express"]),
            ("Next.js", ["__NEXT_DATA__", "_next/"]),
            ("React", ["react", "__REACT", "reactroot"]),
            ("Angular", ["ng-version", "ng-app", "angular"]),
            ("Vue.js", ["vue", "__VUE__", "v-cloak"]),
        ]
        
        for name, sigs in signatures:
            for sig in sigs:
                if sig.lower() in text.lower() or sig.lower() in str(headers).lower():
                    self.add_finding(
                        "INFO",
                        f"Framework detected: {name}",
                        url=target,
                        evidence=f"Signature: {sig}"
                    )
                    return
    
    async def _check_third_party_scripts(self, target, text):
        script_re = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
        target_host = urlparse(target).netloc.lower()
        
        external = []
        risky_domains = []
        
        for match in script_re.finditer(text):
            src = match.group(1).strip()
            if not src or src.startswith("data:") or src.startswith("javascript:"):
                continue
            
            full = urljoin(target, src)
            host = urlparse(full).netloc.lower()
            
            if host and host != target_host and not host.endswith("." + target_host):
                external.append(full)
                
                risky = [
                    "pastebin", "gist.github", "raw.githubusercontent",
                    "jsbin", "codepen", "jsfiddle", "plnkr"
                ]
                if any(r in host for r in risky):
                    risky_domains.append(host)
        
        if risky_domains:
            self.add_finding(
                "HIGH",
                "Scripts loaded from risky domains",
                url=target,
                evidence=f"Risky: {', '.join(risky_domains[:3])}",
                confidence_evidence=["third_party_risk", "supply_chain_risk"]
            )
        elif len(external) > 5:
            self.add_finding(
                "LOW",
                f"Many third-party scripts ({len(external)})",
                url=target,
                evidence=f"External scripts: {', '.join([urlparse(e).netloc for e in external[:3]])}..."
            )
    
    async def _test_report_uri_reachability(self, target, headers):
        csp = headers.get("content-security-policy", "")
        
        report_uri_match = re.search(r'report-uri\s+([^\s;]+)', csp)
        report_to_match = re.search(r'report-to\s+([^\s;]+)', csp)
        
        uris_to_test = []
        
        if report_uri_match:
            uris_to_test.append(report_uri_match.group(1))
        
        nel = headers.get("nel", "")
        if nel:
            try:
                import json
                nel_data = json.loads(nel)
                if nel_data.get("report_to"):
                    pass
            except:
                pass
        
        for uri in uris_to_test:
            if uri.startswith("http"):
                resp = await self.http.post(uri, json={"test": "lantern"})
                if resp.get("status") in [200, 204]:
                    self.add_finding(
                        "INFO",
                        f"CSP report-uri endpoint reachable",
                        url=target,
                        evidence=f"Report URI: {uri}"
                    )
                elif resp.get("status") == 404:
                    self.add_finding(
                        "LOW",
                        "CSP report-uri endpoint not found",
                        url=target,
                        evidence=f"404 at {uri}"
                    )
    
    async def _check_sensitive_endpoints(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        sensitive_paths = [
            "/admin", "/login", "/dashboard", "/account",
            "/api/user", "/api/me", "/profile", "/settings"
        ]
        
        for path in sensitive_paths:
            url = urljoin(base, path)
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                
                cache_control = headers.get("cache-control", "")
                
                if "no-store" not in cache_control.lower() and "private" not in cache_control.lower():
                    self.add_finding(
                        "MEDIUM",
                        f"Sensitive endpoint may be cached: {path}",
                        url=url,
                        evidence="Missing no-store/private in Cache-Control"
                    )
                    break
