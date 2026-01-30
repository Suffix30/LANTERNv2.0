import re
from urllib.parse import urlparse, urljoin
from modules.base import BaseModule
from core.utils import random_string

class CacheModule(BaseModule):
    name = "cache"
    description = "Web Cache Poisoning and Deception Scanner"
    
    unkeyed_headers = [
        "X-Forwarded-Host",
        "X-Forwarded-Scheme",
        "X-Forwarded-Proto",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Host",
        "X-Forwarded-Server",
        "X-HTTP-Host-Override",
        "Forwarded",
        "X-Custom-IP-Authorization",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Client-IP",
        "X-Real-IP",
        "True-Client-IP",
        "Cluster-Client-IP",
        "X-ProxyUser-Ip",
        "Via",
        "X-Forwarded-Port",
    ]
    
    cache_headers = [
        "X-Cache",
        "X-Cache-Hit",
        "X-Cache-Status",
        "CF-Cache-Status",
        "Age",
        "X-Varnish",
        "X-Drupal-Cache",
        "X-Proxy-Cache",
        "Surrogate-Control",
        "CDN-Cache-Control",
        "X-Fastly-Request-ID",
        "X-Served-By",
        "X-Timer",
    ]
    
    async def scan(self, target):
        self.findings = []
        
        has_cache = await self._detect_cache(target)
        
        if has_cache:
            self.add_finding(
                "INFO",
                f"Caching detected",
                url=target,
                evidence="Cache headers present"
            )
            await self._check_cache_behavior(target)
            await self._test_cache_poisoning(target)
            await self._test_cache_deception(target)
            await self._test_parameter_cloaking(target)
        
        return self.findings
    
    async def _check_cache_behavior(self, target):
        base = await self.http.get(target)
        if not base.get("status"):
            return
        base_len = len(base.get("text", ""))
        bust_url = target + (f"&cb={random_string(8)}" if "?" in target else f"?cb={random_string(8)}")
        bust = await self.http.get(bust_url, headers={"Cache-Control": "no-cache"})
        if not bust.get("status"):
            return
        bust_len = len(bust.get("text", ""))
        if base_len != bust_len:
            self.add_finding(
                "INFO",
                "Cache keyed by query or Cache-Control",
                url=target,
                evidence=f"Response size differs with cache-bust (baseline {base_len} vs {bust_len} bytes)"
            )
    
    async def _detect_cache(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return False
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        
        for cache_header in self.cache_headers:
            if cache_header.lower() in headers:
                return True
        
        if "cache-control" in headers:
            cc = headers["cache-control"].lower()
            if "public" in cc or "max-age" in cc or "s-maxage" in cc:
                return True
        
        if "vary" in headers:
            return True
        
        return False
    
    async def _test_cache_poisoning(self, target):
        cache_buster = f"?cb={random_string(8)}"
        test_url = target + cache_buster
        
        for header in self.unkeyed_headers[:10]:
            poison_value = f"evil-{random_string(6)}.com"
            
            resp1 = await self.http.get(test_url, headers={header: poison_value})
            
            if resp1.get("status"):
                text1 = resp1.get("text", "")
                
                if poison_value in text1:
                    resp2 = await self.http.get(test_url)
                    
                    if resp2.get("status"):
                        text2 = resp2.get("text", "")
                        
                        if poison_value in text2:
                            self.add_finding(
                                "CRITICAL",
                                f"Cache Poisoning via {header}",
                                url=target,
                                evidence=f"Poisoned value cached and served to other users"
                            )
                            return
                        else:
                            self.add_finding(
                                "HIGH",
                                f"Unkeyed header reflected: {header}",
                                url=target,
                                evidence=f"Header value reflected but not cached (test manually)"
                            )
    
    async def _test_cache_deception(self, target):
        parsed = urlparse(target)
        
        deception_paths = [
            "/nonexistent.css",
            "/nonexistent.js",
            "/nonexistent.jpg",
            "/nonexistent.png",
            "/nonexistent.gif",
            "/..%2fprofile",
            "/..;/admin",
            "/.css",
            "/;.css",
        ]
        
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        resp_original = await self.http.get(target)
        if not resp_original.get("status"):
            return
        
        original_len = len(resp_original.get("text", ""))
        
        for deception_path in deception_paths[:5]:
            test_url = urljoin(base, parsed.path.rstrip("/") + deception_path)
            
            resp = await self.http.get(test_url)
            
            if resp.get("status") == 200:
                resp_len = len(resp.get("text", ""))
                
                if abs(resp_len - original_len) < 100:
                    cache_status = None
                    for ch in self.cache_headers:
                        if ch.lower() in {k.lower() for k in resp.get("headers", {}).keys()}:
                            cache_status = resp.get("headers", {}).get(ch)
                            break
                    
                    if cache_status and ("hit" in str(cache_status).lower() or "cached" in str(cache_status).lower()):
                        self.add_finding(
                            "HIGH",
                            f"Cache Deception possible",
                            url=test_url,
                            evidence=f"Static extension serves dynamic content and is cached"
                        )
                        return
                    else:
                        self.add_finding(
                            "MEDIUM",
                            f"Path normalization issue",
                            url=test_url,
                            evidence=f"Static extension serves original page content"
                        )
    
    async def _test_parameter_cloaking(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        cloaking_tests = [
            ("utm_content", "test;callback=evil"),
            ("_", "__proto__[test]=1"),
            ("cb", "1;admin=1"),
        ]
        
        for param, value in cloaking_tests:
            test_url = f"{base}?{param}={value}"
            
            resp = await self.http.get(test_url)
            
            if resp.get("status"):
                headers = resp.get("headers", {})
                
                cache_hit = False
                for ch in self.cache_headers:
                    h_val = headers.get(ch, "")
                    if "hit" in str(h_val).lower():
                        cache_hit = True
                        break
                
                if cache_hit and ("evil" in resp.get("text", "") or "admin" in resp.get("text", "")):
                    self.add_finding(
                        "HIGH",
                        f"Parameter cloaking detected",
                        url=test_url,
                        evidence=f"Payload hidden in cache-ignored parameter"
                    )
                    return
    
    def _detect_cache_headers(self, headers):
        cache_patterns = [
            re.compile(r'max-age=(\d+)', re.IGNORECASE),
            re.compile(r's-maxage=(\d+)', re.IGNORECASE),
            re.compile(r'(public|private)', re.IGNORECASE),
        ]
        results = {}
        for key, value in headers.items():
            for pattern in cache_patterns:
                match = pattern.search(str(value))
                if match:
                    results[key] = match.group(0)
        return results
    
    def _parse_vary_header(self, vary_value):
        return re.split(r'\s*,\s*', vary_value)
