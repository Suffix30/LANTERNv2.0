import re
from modules.base import BaseModule

class FingerprintModule(BaseModule):
    name = "fingerprint"
    description = "Technology Fingerprinting"
    
    technologies = {
        "WordPress": {
            "patterns": [r"/wp-content/", r"/wp-includes/", r"wp-json", r"wordpress"],
            "headers": {"X-Powered-By": "wordpress"},
            "paths": ["/wp-login.php", "/wp-admin/", "/xmlrpc.php"],
        },
        "Drupal": {
            "patterns": [r"drupal", r"/sites/default/", r"Drupal.settings"],
            "headers": {"X-Generator": "drupal"},
            "paths": ["/user/login", "/admin/config"],
        },
        "Joomla": {
            "patterns": [r"joomla", r"/administrator/", r"/components/"],
            "headers": {},
            "paths": ["/administrator/", "/configuration.php"],
        },
        "Laravel": {
            "patterns": [r"laravel_session", r"XSRF-TOKEN"],
            "headers": {},
            "cookies": ["laravel_session", "XSRF-TOKEN"],
        },
        "Django": {
            "patterns": [r"csrfmiddlewaretoken", r"__admin__"],
            "headers": {},
            "cookies": ["csrftoken", "sessionid"],
        },
        "Flask": {
            "patterns": [r"Werkzeug"],
            "headers": {"Server": "werkzeug"},
            "cookies": ["session"],
        },
        "Express": {
            "patterns": [r"express"],
            "headers": {"X-Powered-By": "express"},
            "cookies": ["connect.sid"],
        },
        "ASP.NET": {
            "patterns": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"aspnet"],
            "headers": {"X-AspNet-Version": "", "X-Powered-By": "asp.net"},
            "cookies": ["ASP.NET_SessionId", ".ASPXAUTH"],
        },
        "PHP": {
            "patterns": [r"\.php", r"PHPSESSID"],
            "headers": {"X-Powered-By": "php"},
            "cookies": ["PHPSESSID"],
        },
        "Java/Spring": {
            "patterns": [r"JSESSIONID", r"j_spring_security"],
            "headers": {},
            "cookies": ["JSESSIONID"],
        },
        "Ruby on Rails": {
            "patterns": [r"_session_id", r"rails"],
            "headers": {"X-Powered-By": "phusion"},
            "cookies": ["_session_id"],
        },
        "Apache": {
            "patterns": [],
            "headers": {"Server": "apache"},
        },
        "Nginx": {
            "patterns": [],
            "headers": {"Server": "nginx"},
        },
        "IIS": {
            "patterns": [],
            "headers": {"Server": "microsoft-iis", "X-Powered-By": "asp.net"},
        },
        "Cloudflare": {
            "patterns": [],
            "headers": {"Server": "cloudflare", "CF-RAY": ""},
        },
        "AWS": {
            "patterns": [r"amazonaws", r"aws"],
            "headers": {"X-Amz-Cf-Id": "", "X-Amz-Request-Id": ""},
        },
        "React": {
            "patterns": [r"react", r"_reactRootContainer", r"data-reactroot"],
            "headers": {},
        },
        "Vue.js": {
            "patterns": [r"vue", r"v-if", r"v-for", r"data-v-"],
            "headers": {},
        },
        "Angular": {
            "patterns": [r"ng-", r"angular", r"ng-app", r"ng-controller"],
            "headers": {},
        },
        "jQuery": {
            "patterns": [r"jquery", r"\$\(document\)", r"\$\(function"],
            "headers": {},
        },
        "GraphQL": {
            "patterns": [r"graphql", r"__schema", r"__typename"],
            "headers": {},
            "paths": ["/graphql", "/api/graphql", "/v1/graphql"],
        },
        "Swagger/OpenAPI": {
            "patterns": [r"swagger", r"openapi"],
            "headers": {},
            "paths": ["/swagger", "/swagger-ui", "/api-docs", "/swagger.json", "/openapi.json"],
        },
    }
    
    async def scan(self, target):
        self.findings = []
        detected = []
        
        resp = await self.http.get(target)
        if not resp.get("status"):
            return self.findings
        
        headers = {k.lower(): v.lower() for k, v in resp.get("headers", {}).items()}
        text = resp["text"].lower()
        cookies = headers.get("set-cookie", "")
        
        for tech, signatures in self.technologies.items():
            confidence = 0
            
            for pattern in signatures.get("patterns", []):
                if re.search(pattern, text, re.IGNORECASE):
                    confidence += 30
            
            for header, expected in signatures.get("headers", {}).items():
                header_lower = header.lower()
                if header_lower in headers:
                    if not expected or expected.lower() in headers[header_lower]:
                        confidence += 40
            
            for cookie in signatures.get("cookies", []):
                if cookie.lower() in cookies.lower():
                    confidence += 30
            
            if confidence >= 30:
                detected.append((tech, min(confidence, 100)))
        
        for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]:
            await self._check_path(target, path, detected)
        
        if detected:
            detected.sort(key=lambda x: x[1], reverse=True)
            tech_list = ", ".join([f"{t[0]} ({t[1]}%)" for t in detected[:10]])
            
            self.add_finding(
                "INFO",
                f"Technologies detected: {tech_list}",
                url=target,
                evidence=f"Found {len(detected)} technologies"
            )
            
            for tech, conf in detected:
                if tech in ["WordPress", "Drupal", "Joomla"] and conf >= 50:
                    self.add_finding(
                        "LOW",
                        f"CMS detected: {tech} - check for known vulnerabilities",
                        url=target,
                        evidence=f"Confidence: {conf}%"
                    )
        
        await self._check_waf(target)
        
        return self.findings
    
    async def _check_path(self, target, path, detected):
        base = target.rstrip("/")
        resp = await self.http.get(f"{base}{path}")
        if resp.get("status") == 200:
            text = resp["text"].lower()
            
            for tech, sigs in self.technologies.items():
                for pattern in sigs.get("patterns", []):
                    if re.search(pattern, text, re.IGNORECASE):
                        detected.append((tech, 20))
    
    async def _check_waf(self, target):
        waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "AWS WAF": ["x-amzn-requestid", "awselb"],
            "Akamai": ["akamai", "x-akamai"],
            "Sucuri": ["sucuri", "x-sucuri"],
            "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-cdn"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "F5 BIG-IP": ["bigip", "f5"],
            "Barracuda": ["barra_counter_session"],
            "Fortinet FortiWeb": ["fortiwafsid"],
        }
        
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        headers_str = str(resp.get("headers", {})).lower()
        cookies = resp.get("headers", {}).get("Set-Cookie", "").lower()
        
        for waf, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in headers_str or sig in cookies:
                    self.add_finding(
                        "INFO",
                        f"WAF detected: {waf}",
                        url=target,
                        evidence=f"Signature: {sig}"
                    )
                    return
        
        attack_payloads = ["<script>alert(1)</script>", "' OR '1'='1", "../../etc/passwd"]
        
        for payload in attack_payloads:
            resp = await self.http.get(f"{target}?test={payload}")
            if resp.get("status") in [403, 406, 429, 503]:
                self.add_finding(
                    "INFO",
                    f"WAF likely present (blocked attack payload)",
                    url=target,
                    evidence=f"Status: {resp['status']}"
                )
                return
