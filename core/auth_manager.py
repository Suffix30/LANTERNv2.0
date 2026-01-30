import re
import time
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import json


@dataclass
class Credentials:
    username: str
    password: str
    role: str = "user"
    extra_fields: Dict[str, str] = field(default_factory=dict)


@dataclass
class SessionInfo:
    role: str
    cookies: Dict[str, str]
    headers: Dict[str, str]
    logged_in: bool
    login_time: float
    expires: Optional[float] = None
    csrf_token: Optional[str] = None
    
    def is_expired(self) -> bool:
        if self.expires is None:
            return False
        return time.time() > self.expires
    
    def to_dict(self) -> dict:
        return {
            "role": self.role,
            "logged_in": self.logged_in,
            "login_time": self.login_time,
            "expires": self.expires,
            "has_csrf": self.csrf_token is not None,
        }


@dataclass
class AccessIssue:
    issue_type: str
    lower_role: str
    higher_role: str
    url: str
    method: str
    evidence: str
    severity: str = "HIGH"
    
    def to_dict(self) -> dict:
        return {
            "type": self.issue_type,
            "lower_role": self.lower_role,
            "higher_role": self.higher_role,
            "url": self.url,
            "method": self.method,
            "evidence": self.evidence,
            "severity": self.severity,
        }


@dataclass
class RoleComparison:
    url: str
    method: str
    responses: Dict[str, dict]
    access_issues: List[AccessIssue]
    
    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "responses": {k: {"status": v.get("status"), "length": len(v.get("text", ""))} for k, v in self.responses.items()},
            "access_issues": [i.to_dict() for i in self.access_issues],
        }


@dataclass
class AuthConfig:
    auth_type: str = "form"
    login_url: str = "/login"
    logout_url: str = "/logout"
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: Optional[str] = None
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    session_cookie: str = "session"
    auth_header: Optional[str] = None
    token_field: Optional[str] = None
    refresh_threshold: int = 300
    
    @classmethod
    def from_dict(cls, data: dict) -> "AuthConfig":
        return cls(
            auth_type=data.get("type", "form"),
            login_url=data.get("login_url", "/login"),
            logout_url=data.get("logout_url", "/logout"),
            username_field=data.get("form", {}).get("username_field", "username"),
            password_field=data.get("form", {}).get("password_field", "password"),
            csrf_field=data.get("form", {}).get("csrf_field"),
            success_indicators=data.get("success_indicators", []),
            failure_indicators=data.get("failure_indicators", []),
            session_cookie=data.get("session", {}).get("cookie_name", "session"),
            auth_header=data.get("session", {}).get("header_name"),
            token_field=data.get("token_field"),
            refresh_threshold=data.get("session", {}).get("refresh_threshold", 300),
        )


class AuthManager:
    CSRF_PATTERNS = [
        r'name=["\']?csrf[_-]?token["\']?\s+value=["\']?([^"\'>\s]+)',
        r'name=["\']?_token["\']?\s+value=["\']?([^"\'>\s]+)',
        r'name=["\']?authenticity_token["\']?\s+value=["\']?([^"\'>\s]+)',
        r'name=["\']?__RequestVerificationToken["\']?\s+value=["\']?([^"\'>\s]+)',
        r'csrf[_-]?token["\s:=]+["\']?([a-zA-Z0-9_-]{16,})',
        r'"csrfToken"\s*:\s*"([^"]+)"',
        r"'csrfToken'\s*:\s*'([^']+)'",
    ]
    
    DEFAULT_SUCCESS_INDICATORS = [
        "dashboard", "welcome", "logout", "profile", "account",
        "successfully logged", "login successful",
    ]
    
    DEFAULT_FAILURE_INDICATORS = [
        "invalid", "incorrect", "failed", "error", "wrong",
        "denied", "unauthorized", "try again",
    ]
    
    def __init__(self, http_client, config: AuthConfig = None):
        self.http = http_client
        self.config = config or AuthConfig()
        self.sessions: Dict[str, SessionInfo] = {}
        self.credentials: Dict[str, Credentials] = {}
        self.base_url = ""
        self._role_hierarchy = ["guest", "user", "editor", "admin", "superadmin"]
    
    def set_base_url(self, url: str):
        parsed = urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    def add_credentials(self, role: str, username: str, password: str, extra: Dict = None):
        self.credentials[role] = Credentials(
            username=username,
            password=password,
            role=role,
            extra_fields=extra or {},
        )
    
    def add_credentials_from_dict(self, roles_config: Dict):
        for role, creds in roles_config.items():
            if creds.get("authenticated", True):
                self.add_credentials(
                    role=role,
                    username=creds.get("username", ""),
                    password=creds.get("password", ""),
                    extra=creds.get("extra", {}),
                )
            else:
                self.sessions[role] = SessionInfo(
                    role=role,
                    cookies={},
                    headers={},
                    logged_in=False,
                    login_time=time.time(),
                )
    
    async def login(self, role: str) -> bool:
        if role not in self.credentials:
            self.sessions[role] = SessionInfo(
                role=role,
                cookies={},
                headers={},
                logged_in=False,
                login_time=time.time(),
            )
            return True
        
        creds = self.credentials[role]
        
        if self.config.auth_type == "form":
            return await self._form_login(role, creds)
        elif self.config.auth_type == "basic":
            return await self._basic_auth_login(role, creds)
        elif self.config.auth_type == "bearer":
            return await self._bearer_login(role, creds)
        elif self.config.auth_type == "api_key":
            return await self._api_key_login(role, creds)
        
        return False
    
    async def _form_login(self, role: str, creds: Credentials) -> bool:
        login_url = urljoin(self.base_url, self.config.login_url)
        
        login_page = await self.http.get(login_url)
        csrf_token = self._extract_csrf(login_page.get("text", ""))
        
        login_data = {
            self.config.username_field: creds.username,
            self.config.password_field: creds.password,
        }
        
        if csrf_token and self.config.csrf_field:
            login_data[self.config.csrf_field] = csrf_token
        
        login_data.update(creds.extra_fields)
        
        response = await self.http.post(login_url, data=login_data, allow_redirects=True)
        
        success = self._check_login_success(response)
        
        if success:
            cookies = self._extract_cookies(response)
            self.sessions[role] = SessionInfo(
                role=role,
                cookies=cookies,
                headers={},
                logged_in=True,
                login_time=time.time(),
                expires=time.time() + 3600,
                csrf_token=csrf_token,
            )
            return True
        
        return False
    
    async def _basic_auth_login(self, role: str, creds: Credentials) -> bool:
        import base64
        auth_string = f"{creds.username}:{creds.password}"
        encoded = base64.b64encode(auth_string.encode()).decode()
        
        self.sessions[role] = SessionInfo(
            role=role,
            cookies={},
            headers={"Authorization": f"Basic {encoded}"},
            logged_in=True,
            login_time=time.time(),
        )
        return True
    
    async def _bearer_login(self, role: str, creds: Credentials) -> bool:
        token = creds.extra_fields.get("token") or creds.password
        
        self.sessions[role] = SessionInfo(
            role=role,
            cookies={},
            headers={"Authorization": f"Bearer {token}"},
            logged_in=True,
            login_time=time.time(),
        )
        return True
    
    async def _api_key_login(self, role: str, creds: Credentials) -> bool:
        api_key = creds.extra_fields.get("api_key") or creds.password
        header_name = creds.extra_fields.get("header_name", "X-API-Key")
        
        self.sessions[role] = SessionInfo(
            role=role,
            cookies={},
            headers={header_name: api_key},
            logged_in=True,
            login_time=time.time(),
        )
        return True
    
    async def logout(self, role: str):
        if role in self.sessions:
            logout_url = urljoin(self.base_url, self.config.logout_url)
            session = self.sessions[role]
            
            headers = session.headers.copy()
            if session.cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
            
            await self.http.get(logout_url, headers=headers)
            
            del self.sessions[role]
    
    async def get_session(self, role: str) -> SessionInfo:
        if role not in self.sessions or self.sessions[role].is_expired():
            await self.login(role)
        return self.sessions.get(role)
    
    async def request_as(self, role: str, method: str, url: str, **kwargs) -> dict:
        session = await self.get_session(role)
        
        if not session:
            return {"error": f"No session for role {role}", "status": 0}
        
        headers = kwargs.pop("headers", {})
        headers.update(session.headers)
        
        if session.cookies:
            cookie_header = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
            headers["Cookie"] = cookie_header
        
        if not url.startswith(("http://", "https://")):
            url = urljoin(self.base_url, url)
        
        method = method.upper()
        
        if method == "GET":
            return await self.http.get(url, headers=headers, **kwargs)
        elif method == "POST":
            return await self.http.post(url, headers=headers, **kwargs)
        elif method == "PUT":
            return await self.http.put(url, headers=headers, **kwargs)
        elif method == "DELETE":
            return await self.http.delete(url, headers=headers)
        elif method == "PATCH":
            return await self.http.patch(url, headers=headers, **kwargs)
        else:
            return await self.http.request(method, url, headers=headers, **kwargs)
    
    async def compare_roles(self, method: str, url: str, roles: List[str] = None) -> RoleComparison:
        if roles is None:
            roles = list(self.sessions.keys()) + list(self.credentials.keys())
            roles = list(set(roles))
        
        if not roles:
            roles = ["guest"]
        
        responses = {}
        for role in roles:
            resp = await self.request_as(role, method, url)
            responses[role] = resp
        
        issues = self._detect_access_issues(url, method, responses)
        
        return RoleComparison(
            url=url,
            method=method,
            responses=responses,
            access_issues=issues,
        )
    
    async def test_horizontal_access(self, url_template: str, user_ids: List[str], role: str = "user") -> List[AccessIssue]:
        issues = []
        
        for user_id in user_ids:
            url = url_template.replace("{id}", str(user_id))
            resp = await self.request_as(role, "GET", url)
            
            if resp.get("status") == 200:
                issues.append(AccessIssue(
                    issue_type="horizontal_idor",
                    lower_role=role,
                    higher_role=role,
                    url=url,
                    method="GET",
                    evidence=f"Accessed resource for user {user_id}",
                    severity="HIGH",
                ))
        
        return issues
    
    async def test_privilege_escalation(self, admin_endpoints: List[str], roles: List[str] = None) -> List[AccessIssue]:
        if roles is None:
            roles = ["guest", "user"]
        
        issues = []
        
        for endpoint in admin_endpoints:
            for role in roles:
                for method in ["GET", "POST"]:
                    resp = await self.request_as(role, method, endpoint)
                    
                    if resp.get("status") in [200, 201, 202]:
                        issues.append(AccessIssue(
                            issue_type="privilege_escalation",
                            lower_role=role,
                            higher_role="admin",
                            url=endpoint,
                            method=method,
                            evidence=f"Status {resp.get('status')} returned for {role}",
                            severity="CRITICAL",
                        ))
        
        return issues
    
    def _extract_csrf(self, html: str) -> Optional[str]:
        for pattern in self.CSRF_PATTERNS:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def _extract_cookies(self, response: dict) -> Dict[str, str]:
        cookies = {}
        headers = response.get("headers", {})
        
        set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie")
        if set_cookie:
            if isinstance(set_cookie, str):
                set_cookie = [set_cookie]
            
            for cookie in set_cookie:
                parts = cookie.split(";")[0]
                if "=" in parts:
                    name, value = parts.split("=", 1)
                    cookies[name.strip()] = value.strip()
        
        return cookies
    
    def _check_login_success(self, response: dict) -> bool:
        status = response.get("status", 0)
        text = response.get("text", "").lower()
        url = response.get("url", "").lower()
        
        if status in [401, 403]:
            return False
        
        indicators = self.config.failure_indicators or self.DEFAULT_FAILURE_INDICATORS
        for indicator in indicators:
            if indicator.lower() in text:
                return False
        
        indicators = self.config.success_indicators or self.DEFAULT_SUCCESS_INDICATORS
        for indicator in indicators:
            if indicator.lower() in text or indicator.lower() in url:
                return True
        
        if status in [200, 302, 303] and "login" not in url:
            return True
        
        return False
    
    def _detect_access_issues(self, url: str, method: str, responses: Dict[str, dict]) -> List[AccessIssue]:
        issues = []
        
        sorted_roles = sorted(responses.keys(), key=lambda r: self._role_hierarchy.index(r) if r in self._role_hierarchy else 0)
        
        admin_roles = ["admin", "superadmin", "administrator"]
        admin_response = None
        for role in admin_roles:
            if role in responses and responses[role].get("status") == 200:
                admin_response = responses[role]
                break
        
        for i, role in enumerate(sorted_roles):
            resp = responses[role]
            status = resp.get("status", 0)
            text = resp.get("text", "")
            
            if status in [200, 201] and role in ["guest", "user"]:
                for higher_role in sorted_roles[i+1:]:
                    higher_resp = responses.get(higher_role)
                    if higher_resp and higher_resp.get("status") == status:
                        higher_text = higher_resp.get("text", "")
                        
                        if len(text) > 100 and abs(len(text) - len(higher_text)) < len(text) * 0.1:
                            issues.append(AccessIssue(
                                issue_type="unauthorized_access",
                                lower_role=role,
                                higher_role=higher_role,
                                url=url,
                                method=method,
                                evidence=f"{role} got similar response to {higher_role}",
                                severity="HIGH",
                            ))
        
        return issues
    
    def get_active_sessions(self) -> Dict[str, dict]:
        return {role: session.to_dict() for role, session in self.sessions.items()}


def create_auth_manager(http_client, config: Dict = None) -> AuthManager:
    auth_config = AuthConfig.from_dict(config) if config else AuthConfig()
    return AuthManager(http_client, auth_config)
