import re
import json
import asyncio
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class AuthCredentials:
    auth_type: str
    cookies: Dict[str, str] = None
    bearer_token: str = None
    basic_auth: Tuple[str, str] = None
    api_key: str = None
    api_key_header: str = None
    custom_headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.cookies is None:
            self.cookies = {}
        if self.custom_headers is None:
            self.custom_headers = {}


class AuthHandler:
    def __init__(self, http_client):
        self.http = http_client
        self.credentials: Optional[AuthCredentials] = None
        self.session_cookies: Dict[str, str] = {}
        self.auth_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
        self.login_url: Optional[str] = None
        self.login_data: Optional[Dict] = None
    
    def set_cookie_auth(self, cookies: Dict[str, str]):
        self.credentials = AuthCredentials(
            auth_type="cookie",
            cookies=cookies
        )
        self.session_cookies = cookies.copy()
    
    def set_cookie_string(self, cookie_string: str):
        cookies = {}
        for item in cookie_string.split(";"):
            item = item.strip()
            if "=" in item:
                key, value = item.split("=", 1)
                cookies[key.strip()] = value.strip()
        
        self.set_cookie_auth(cookies)
    
    def set_bearer_token(self, token: str, expiry_seconds: int = None):
        self.credentials = AuthCredentials(
            auth_type="bearer",
            bearer_token=token
        )
        self.auth_token = token
        
        if expiry_seconds:
            self.token_expiry = datetime.now() + timedelta(seconds=expiry_seconds)
    
    def set_basic_auth(self, username: str, password: str):
        import base64
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        self.credentials = AuthCredentials(
            auth_type="basic",
            basic_auth=(username, password),
            custom_headers={"Authorization": f"Basic {encoded}"}
        )
    
    def set_api_key(self, api_key: str, header_name: str = "X-API-Key"):
        self.credentials = AuthCredentials(
            auth_type="api_key",
            api_key=api_key,
            api_key_header=header_name,
            custom_headers={header_name: api_key}
        )
    
    def set_custom_headers(self, headers: Dict[str, str]):
        if self.credentials:
            self.credentials.custom_headers.update(headers)
        else:
            self.credentials = AuthCredentials(
                auth_type="custom",
                custom_headers=headers
            )
    
    async def login(self, login_url: str, username: str, password: str, 
                   username_field: str = None, password_field: str = None) -> bool:
        self.login_url = login_url
        
        if not username_field or not password_field:
            username_field, password_field = await self._detect_login_fields(login_url)
        
        if not username_field or not password_field:
            username_field = "username"
            password_field = "password"
        
        self.login_data = {
            username_field: username,
            password_field: password
        }
        
        resp = await self.http.post(login_url, data=self.login_data, allow_redirects=True)
        
        if resp.get("status") in [200, 302]:
            cookies = resp.get("cookies", {})
            
            if cookies:
                self.session_cookies.update(cookies)
                self.credentials = AuthCredentials(
                    auth_type="session",
                    cookies=self.session_cookies
                )
                return True
            
            set_cookie = resp.get("headers", {}).get("set-cookie", "")
            if set_cookie:
                self._parse_set_cookie(set_cookie)
                self.credentials = AuthCredentials(
                    auth_type="session",
                    cookies=self.session_cookies
                )
                return True
        
        return False
    
    async def _detect_login_fields(self, login_url: str) -> Tuple[Optional[str], Optional[str]]:
        resp = await self.http.get(login_url)
        
        if not resp.get("status"):
            return None, None
        
        html = resp.get("text", "")
        
        username_patterns = [
            r'<input[^>]*name=["\']([^"\']*(?:user|login|email|account)[^"\']*)["\']',
            r'<input[^>]*id=["\']([^"\']*(?:user|login|email|account)[^"\']*)["\']',
        ]
        
        password_patterns = [
            r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']+)["\']',
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']password["\']',
        ]
        
        username_field = None
        password_field = None
        
        for pattern in username_patterns:
            match = re.search(pattern, html, re.I)
            if match:
                username_field = match.group(1)
                break
        
        for pattern in password_patterns:
            match = re.search(pattern, html, re.I)
            if match:
                password_field = match.group(1)
                break
        
        return username_field, password_field
    
    def _parse_set_cookie(self, set_cookie_header: str):
        for cookie_str in set_cookie_header.split(","):
            parts = cookie_str.split(";")[0].strip()
            if "=" in parts:
                key, value = parts.split("=", 1)
                self.session_cookies[key.strip()] = value.strip()
    
    def get_auth_headers(self) -> Dict[str, str]:
        headers = {}
        
        if not self.credentials:
            return headers
        
        if self.credentials.auth_type == "bearer":
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"
        
        elif self.credentials.auth_type == "cookie":
            cookie_str = "; ".join([f"{k}={v}" for k, v in self.session_cookies.items()])
            if cookie_str:
                headers["Cookie"] = cookie_str
        
        elif self.credentials.auth_type == "session":
            cookie_str = "; ".join([f"{k}={v}" for k, v in self.session_cookies.items()])
            if cookie_str:
                headers["Cookie"] = cookie_str
        
        if self.credentials.custom_headers:
            headers.update(self.credentials.custom_headers)
        
        return headers
    
    def get_cookies(self) -> Dict[str, str]:
        return self.session_cookies.copy()
    
    async def refresh_session(self) -> bool:
        if self.token_expiry and datetime.now() > self.token_expiry:
            return False
        
        if self.login_url and self.login_data:
            return await self.login(
                self.login_url,
                self.login_data.get("username", ""),
                self.login_data.get("password", "")
            )
        
        return True
    
    async def verify_auth(self, test_url: str) -> bool:
        headers = self.get_auth_headers()
        
        resp = await self.http.get(test_url, headers=headers)
        
        if resp.get("status") in [200, 201, 204]:
            return True
        
        if resp.get("status") in [401, 403]:
            return False
        
        return True
    
    def is_authenticated(self) -> bool:
        return self.credentials is not None and (
            bool(self.session_cookies) or 
            bool(self.auth_token) or 
            bool(self.credentials.custom_headers)
        )
    
    def get_auth_type(self) -> Optional[str]:
        if self.credentials:
            return self.credentials.auth_type
        return None
    
    def clear_auth(self):
        self.credentials = None
        self.session_cookies = {}
        self.auth_token = None
        self.token_expiry = None
        self.login_url = None
        self.login_data = None
    
    def export_session(self) -> str:
        session_data = {
            "auth_type": self.credentials.auth_type if self.credentials else None,
            "cookies": self.session_cookies,
            "token": self.auth_token,
            "expiry": self.token_expiry.isoformat() if self.token_expiry else None,
        }
        return json.dumps(session_data)
    
    def import_session(self, session_json: str):
        data = json.loads(session_json)
        if data.get("cookies"):
            self.set_cookie_auth(data["cookies"])
        if data.get("token"):
            self.set_bearer_token(data["token"])
    
    async def test_multiple_endpoints(self, endpoints: List[str]) -> Dict[str, bool]:
        results = {}
        
        async def check_endpoint(url: str) -> Tuple[str, bool]:
            is_authed = await self.verify_auth(url)
            return (url, is_authed)
        
        tasks = [check_endpoint(ep) for ep in endpoints]
        completed = await asyncio.gather(*tasks)
        
        for url, is_authed in completed:
            results[url] = is_authed
        
        return results
    
    def get_full_url(self, base: str, path: str) -> str:
        return urljoin(base, path)
    
    def extract_domain(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc


_global_auth: Optional[AuthHandler] = None


def get_auth_handler(http_client=None) -> AuthHandler:
    global _global_auth
    if _global_auth is None and http_client:
        _global_auth = AuthHandler(http_client)
    return _global_auth


def set_auth_handler(auth: AuthHandler):
    global _global_auth
    _global_auth = auth
