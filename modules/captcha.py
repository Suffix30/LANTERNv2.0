import re
from urllib.parse import urljoin, urlparse
from modules.base import BaseModule

class CaptchaModule(BaseModule):
    name = "captcha"
    description = "CAPTCHA & Rate Limit Bypass Scanner"
    
    captcha_indicators = [
        r'captcha', r'recaptcha', r'hcaptcha', r'turnstile',
        r'g-recaptcha', r'h-captcha', r'cf-turnstile',
        r'captcha_response', r'captcha_token', r'captcha_code',
        r'security_code', r'verification_code', r'verify_human',
    ]
    
    rate_limit_headers = [
        "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
        "x-rate-limit-limit", "x-rate-limit-remaining", "retry-after",
        "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    ]
    
    sensitive_endpoints = [
        "/login", "/signin", "/register", "/signup", "/forgot-password",
        "/reset-password", "/contact", "/comment", "/feedback",
        "/api/login", "/api/register", "/api/auth", "/api/password",
        "/user/login", "/user/register", "/auth/login", "/auth/register",
        "/account/login", "/account/register", "/submit", "/send",
    ]
    
    async def scan(self, target):
        self.findings = []
        
        await self._detect_captcha(target)
        await self._test_captcha_bypass(target)
        await self._test_rate_limits(target)
        await self._test_missing_captcha(target)
        await self._test_captcha_reuse(target)
        await self._test_empty_captcha(target)
        
        return self.findings
    
    async def _detect_captcha(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        text = resp.get("text", "")
        
        captcha_types = []
        
        if "recaptcha" in text.lower() or "g-recaptcha" in text:
            captcha_types.append("Google reCAPTCHA")
            
            site_key = re.search(r'data-sitekey=["\']([^"\']+)', text)
            if site_key:
                self.add_finding(
                    "INFO",
                    f"reCAPTCHA detected",
                    url=target,
                    evidence=f"Site key: {site_key.group(1)[:20]}..."
                )
        
        if "hcaptcha" in text.lower() or "h-captcha" in text:
            captcha_types.append("hCaptcha")
        
        if "turnstile" in text.lower() or "cf-turnstile" in text:
            captcha_types.append("Cloudflare Turnstile")
        
        if re.search(r'captcha\.php|captcha\.aspx|captcha\.jsp', text, re.IGNORECASE):
            captcha_types.append("Custom CAPTCHA")
            self.add_finding(
                "MEDIUM",
                f"Custom CAPTCHA implementation",
                url=target,
                evidence="Custom CAPTCHAs are often bypassable"
            )
        
        if captcha_types:
            self.log_info(f"CAPTCHA types found: {', '.join(captcha_types)}")
    
    async def _test_captcha_bypass(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        text = resp.get("text", "")
        
        forms = re.findall(r'<form[^>]*>.*?</form>', text, re.DOTALL | re.IGNORECASE)
        
        for form in forms:
            if any(re.search(indicator, form, re.IGNORECASE) for indicator in self.captcha_indicators):
                action = re.search(r'action=["\']?([^"\'>\s]+)', form, re.IGNORECASE)
                form_action = action.group(1) if action else target
                
                if not form_action.startswith("http"):
                    form_action = urljoin(target, form_action)
                
                inputs = re.findall(r'<input[^>]+name=["\']?([^"\'>\s]+)["\']?[^>]*value=["\']?([^"\'>\s]*)', form, re.IGNORECASE)
                data = {name: value for name, value in inputs}
                
                captcha_field = None
                for indicator in self.captcha_indicators:
                    for field in data.keys():
                        if re.search(indicator, field, re.IGNORECASE):
                            captcha_field = field
                            break
                
                if captcha_field:
                    test_values = ["", "test", "1234", "aaaa", "0000", "bypass", "null"]
                    
                    for test_val in test_values:
                        test_data = data.copy()
                        test_data[captcha_field] = test_val
                        
                        resp = await self.http.post(form_action, data=test_data)
                        
                        if resp.get("status") == 200:
                            resp_text = resp.get("text", "").lower()
                            
                            if "captcha" not in resp_text and "invalid" not in resp_text:
                                self.add_finding(
                                    "CRITICAL",
                                    f"CAPTCHA bypass: {captcha_field}={test_val}",
                                    url=form_action,
                                    parameter=captcha_field,
                                    evidence="Form submitted without valid CAPTCHA"
                                )
                                return
                
                if captcha_field:
                    test_data = data.copy()
                    del test_data[captcha_field]
                    
                    resp = await self.http.post(form_action, data=test_data)
                    
                    if resp.get("status") == 200:
                        if "captcha" not in resp.get("text", "").lower():
                            self.add_finding(
                                "CRITICAL",
                                f"CAPTCHA field not required",
                                url=form_action,
                                parameter=captcha_field,
                                evidence="Form accepted without CAPTCHA field"
                            )
    
    async def _test_rate_limits(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for endpoint in self.sensitive_endpoints[:5]:
            responses = []
            
            for i in range(20):
                resp = await self.http.post(
                    f"{base}{endpoint}",
                    data={"username": f"test{i}", "password": "test123"}
                )
                responses.append(resp)
                
                if resp.get("status") == 429:
                    self.add_finding(
                        "INFO",
                        f"Rate limiting active on {endpoint}",
                        url=f"{base}{endpoint}",
                        evidence=f"429 after {i+1} requests"
                    )
                    break
            else:
                success_count = sum(1 for r in responses if r.get("status") in [200, 302, 401, 403])
                if success_count >= 15:
                    self.add_finding(
                        "HIGH",
                        f"No rate limiting on {endpoint}",
                        url=f"{base}{endpoint}",
                        evidence=f"{success_count}/20 requests succeeded (brute force possible)"
                    )
            
            headers = responses[-1].get("headers", {}) if responses else {}
            rate_headers = {k.lower(): v for k, v in headers.items() if k.lower() in self.rate_limit_headers}
            
            if rate_headers:
                remaining = rate_headers.get("x-ratelimit-remaining", rate_headers.get("ratelimit-remaining"))
                if remaining and int(remaining) > 1000:
                    self.add_finding(
                        "MEDIUM",
                        f"High rate limit on {endpoint}",
                        url=f"{base}{endpoint}",
                        evidence=f"Remaining: {remaining} requests"
                    )
    
    async def _test_missing_captcha(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        critical_endpoints = ["/login", "/register", "/forgot-password", "/contact"]
        
        for endpoint in critical_endpoints:
            resp = await self.http.get(f"{base}{endpoint}")
            
            if resp.get("status") == 200:
                text = resp.get("text", "").lower()
                
                has_form = "<form" in text
                has_captcha = any(re.search(ind, text, re.IGNORECASE) for ind in self.captcha_indicators)
                
                if has_form and not has_captcha:
                    self.add_finding(
                        "MEDIUM",
                        f"No CAPTCHA on {endpoint}",
                        url=f"{base}{endpoint}",
                        evidence="Sensitive form without bot protection"
                    )
    
    async def _test_captcha_reuse(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        text = resp.get("text", "")
        
        captcha_tokens = re.findall(r'name=["\']?(captcha[_-]?token|g-recaptcha-response)["\']?\s+value=["\']?([^"\']+)', text, re.IGNORECASE)
        
        if captcha_tokens:
            token_name, token_value = captcha_tokens[0]
            
            if token_value and len(token_value) > 10:
                forms = re.findall(r'<form[^>]*action=["\']?([^"\'>\s]+)', text, re.IGNORECASE)
                
                if forms:
                    form_action = forms[0]
                    if not form_action.startswith("http"):
                        form_action = urljoin(target, form_action)
                    
                    for _ in range(3):
                        resp = await self.http.post(
                            form_action,
                            data={token_name: token_value, "test": "value"}
                        )
                        
                        if resp.get("status") == 200:
                            if "invalid" not in resp.get("text", "").lower():
                                self.add_finding(
                                    "HIGH",
                                    f"CAPTCHA token reusable",
                                    url=form_action,
                                    parameter=token_name,
                                    evidence="Same token accepted multiple times"
                                )
                                return
    
    async def _test_empty_captcha(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        text = resp.get("text", "")
        
        forms = re.findall(r'<form[^>]*>.*?</form>', text, re.DOTALL | re.IGNORECASE)
        
        for form in forms:
            if "captcha" in form.lower():
                action = re.search(r'action=["\']?([^"\'>\s]+)', form, re.IGNORECASE)
                form_action = action.group(1) if action else target
                
                if not form_action.startswith("http"):
                    form_action = urljoin(target, form_action)
                
                inputs = re.findall(r'<input[^>]+name=["\']?([^"\'>\s]+)', form, re.IGNORECASE)
                data = {name: "" for name in inputs}
                
                resp = await self.http.post(form_action, data=data)
                
                if resp.get("status") == 200:
                    resp_text = resp.get("text", "").lower()
                    
                    if "captcha" not in resp_text and "error" not in resp_text:
                        self.add_finding(
                            "HIGH",
                            f"Empty form accepted (no CAPTCHA validation)",
                            url=form_action,
                            evidence="Form processed with empty values"
                        )
