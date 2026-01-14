import re
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from modules.base import BaseModule
from core.utils import random_string
 

class OauthModule(BaseModule):
    name = "oauth"
    description = "OAuth 2.0 Misconfiguration Scanner"
    
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
        base_url = self._get_base_url(target)
        
        oauth_urls = await self._discover_oauth_endpoints(base_url)
        
        for oauth_url in oauth_urls:
            await self._test_redirect_uri_bypass(oauth_url)
            await self._test_state_parameter(oauth_url)
            await self._test_scope_escalation(oauth_url)
            await self._test_token_leakage(oauth_url)
            await self._test_pkce_bypass(oauth_url)
        
        await self._test_token_exposure(target)
        
        return self.findings
    
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
