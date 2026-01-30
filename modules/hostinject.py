import re
from urllib.parse import urljoin, urlparse
from modules.base import BaseModule

class HostinjectModule(BaseModule):
    name = "hostinject"
    description = "Host Header / Password Reset Poisoning Scanner"

    reset_paths = [
        "/forgot-password", "/forgot_password", "/forgotpassword", "/password/forgot",
        "/reset-password", "/reset_password", "/resetpassword", "/password/reset",
        "/recover", "/recovery", "/password-recovery", "/account/recover",
        "/auth/forgot", "/auth/reset", "/login/forgot", "/signin/forgot",
        "/api/forgot-password", "/api/password/reset", "/api/auth/forgot",
        "/user/forgot-password", "/users/password/new", "/password/request",
        "/send-reset", "/request-reset", "/password/forgot/send",
    ]

    poison_headers = ["Host", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Original-Host"]

    async def scan(self, target):
        self.findings = []
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        evil_host = self.config.get("callback_host") or "evil.lantern.local"
        await self._test_host_reflection(target, base_url, evil_host)
        await self._test_password_reset_poisoning(base_url, evil_host)
        await self._test_redirect_host_override(base_url, evil_host)
        return self.findings

    async def _test_host_reflection(self, target, base_url, evil_host):
        for header in self.poison_headers:
            resp = await self.http.get(target, headers={header: evil_host})
            if not resp.get("status"):
                continue
            text = (resp.get("text") or "").lower()
            headers_str = str(resp.get("headers", {})).lower()
            if evil_host.lower() in text or evil_host.lower() in headers_str:
                self.add_finding(
                    "HIGH",
                    f"Host header reflection via {header}",
                    url=target,
                    evidence=f"Reflected host: {evil_host}"
                )
                return

    async def _test_password_reset_poisoning(self, base_url, evil_host):
        for path in self.reset_paths:
            url = urljoin(base_url, path)
            resp = await self.http.get(url)
            if resp.get("status") not in [200, 302]:
                continue
            text = (resp.get("text") or "").lower()
            if not any(x in text for x in ["forgot", "reset", "password", "email", "recover"]):
                continue
            form_action = re.search(r'<form[^>]+action=["\']?([^"\'>\s]+)', resp.get("text", ""), re.I)
            post_url = urljoin(url, form_action.group(1)) if form_action else url
            email_param = self._guess_email_param(resp.get("text", ""))
            if not email_param:
                email_param = "email"
            for header in ["Host", "X-Forwarded-Host"]:
                poisoned = await self.http.post(
                    post_url,
                    data={email_param: "victim@example.com"},
                    headers={header: evil_host}
                )
                if not poisoned.get("status"):
                    continue
                body = (poisoned.get("text") or "").lower()
                if any(x in body for x in ["sent", "check your email", "reset link", "recovery"]):
                    self.add_finding(
                        "CRITICAL",
                        f"Password reset poisoning likely via {header}",
                        url=post_url,
                        evidence=f"Reset flow accepts {header}={evil_host}; links may point to attacker"
                    )
                    return
                if evil_host.lower() in body:
                    self.add_finding(
                        "CRITICAL",
                        f"Password reset link contains poisoned host ({header})",
                        url=post_url,
                        evidence=f"Response body contains {evil_host}"
                    )
                    return

    def _guess_email_param(self, html):
        for name in ["email", "username", "user", "login", "account"]:
            if re.search(rf'name=["\']?{name}["\']?', html, re.I):
                return name
        return None

    async def _test_redirect_host_override(self, base_url, evil_host):
        login_paths = ["/login", "/signin", "/auth/login", "/admin"]
        for path in login_paths:
            url = urljoin(base_url, path)
            resp = await self.http.get(url, headers={"X-Forwarded-Host": evil_host}, allow_redirects=False)
            if resp.get("status") in [301, 302, 303, 307, 308]:
                loc = resp.get("headers", {}).get("Location", "")
                if evil_host in loc:
                    self.add_finding(
                        "HIGH",
                        "Redirect uses X-Forwarded-Host in Location",
                        url=url,
                        evidence=f"Location: {loc[:80]}"
                    )
                    return
