import aiohttp
import asyncio
import random
import ssl
import time
import json as json_lib
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from pathlib import Path
from core.utils import TokenBucketLimiter, ScanMetrics

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


class HttpClient:
    def __init__(self, config):
        self.config = config
        self.timeout = aiohttp.ClientTimeout(total=config.get("timeout", 10))
        self.headers = config.get("headers", {})
        self.proxy = config.get("proxy")
        self.stealth = config.get("stealth", False)
        self.aggressive = config.get("aggressive", False)
        self.session = None
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.request_count = 0
        self.rate_limit_hits = 0
        self.adaptive_delay = 0
        rate = config.get("rate_limit", 100)
        burst = config.get("rate_burst", rate * 2)
        self.rate_limiter = TokenBucketLimiter(rate=rate, burst=burst, name="http")
        self.metrics = ScanMetrics(window_size=60)
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=self.config.get("threads", 50),
            limit_per_host=self.config.get("threads_per_host", 10),
            ssl=self.ssl_context,
            force_close=False,
            enable_cleanup_closed=True,
            ttl_dns_cache=300,
        )
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers=self._get_headers()
        )
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    def _get_headers(self):
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        headers.update(self.headers)
        return headers
    
    async def _adaptive_delay(self):
        await self.rate_limiter.acquire()
        if self.stealth:
            await asyncio.sleep(random.uniform(0.3, 1.5))
    
    def _handle_rate_limit(self, status):
        self.rate_limiter.record_response(status)
        self.metrics.record_request()
        if status == 429:
            self.rate_limit_hits += 1
        elif status >= 500:
            self.metrics.record_error()
    
    async def get(self, url, params=None, headers=None, allow_redirects=True):
        await self._adaptive_delay()
        self.request_count += 1
        try:
            merged_headers = self._get_headers()
            if headers:
                merged_headers.update(headers)
            async with self.session.get(
                url, 
                params=params, 
                headers=merged_headers,
                proxy=self.proxy,
                allow_redirects=allow_redirects
            ) as resp:
                result = await self._build_response(resp)
                self._handle_rate_limit(resp.status)
                return result
        except Exception as e:
            return {"error": str(e), "status": 0, "text": "", "headers": {}}
    
    async def post(self, url, data=None, json=None, headers=None, allow_redirects=True):
        await self._adaptive_delay()
        self.request_count += 1
        start = time.time()
        try:
            merged_headers = self._get_headers()
            if headers:
                merged_headers.update(headers)
            async with self.session.post(
                url,
                data=data,
                json=json,
                headers=merged_headers,
                proxy=self.proxy,
                allow_redirects=allow_redirects
            ) as resp:
                result = await self._build_response(resp)
                result["elapsed"] = time.time() - start
                self._handle_rate_limit(resp.status)
                return result
        except Exception as e:
            return {"error": str(e), "status": 0, "text": "", "headers": {}, "elapsed": time.time() - start}
    
    async def put(self, url, data=None, json=None, headers=None):
        await self._adaptive_delay()
        self.request_count += 1
        try:
            merged_headers = self._get_headers()
            if headers:
                merged_headers.update(headers)
            async with self.session.put(
                url,
                data=data,
                json=json,
                headers=merged_headers,
                proxy=self.proxy
            ) as resp:
                result = await self._build_response(resp)
                self._handle_rate_limit(resp.status)
                return result
        except Exception as e:
            return {"error": str(e), "status": 0, "text": "", "headers": {}}
    
    async def patch(self, url, data=None, json=None, headers=None):
        await self._adaptive_delay()
        self.request_count += 1
        try:
            merged_headers = self._get_headers()
            if headers:
                merged_headers.update(headers)
            async with self.session.patch(
                url,
                data=data,
                json=json,
                headers=merged_headers,
                proxy=self.proxy
            ) as resp:
                result = await self._build_response(resp)
                self._handle_rate_limit(resp.status)
                return result
        except Exception as e:
            return {"error": str(e), "status": 0, "text": "", "headers": {}}
    
    async def delete(self, url, headers=None):
        await self._adaptive_delay()
        self.request_count += 1
        try:
            merged_headers = self._get_headers()
            if headers:
                merged_headers.update(headers)
            async with self.session.delete(
                url,
                headers=merged_headers,
                proxy=self.proxy
            ) as resp:
                result = await self._build_response(resp)
                self._handle_rate_limit(resp.status)
                return result
        except Exception as e:
            return {"error": str(e), "status": 0, "text": "", "headers": {}}
    
    async def options(self, url, headers=None):
        await self._adaptive_delay()
        self.request_count += 1
        try:
            merged_headers = self._get_headers()
            if headers:
                merged_headers.update(headers)
            async with self.session.options(
                url,
                headers=merged_headers,
                proxy=self.proxy
            ) as resp:
                result = await self._build_response(resp)
                return result
        except Exception as e:
            return {"error": str(e), "status": 0, "text": "", "headers": {}}
    
    async def request(self, method, url, **kwargs):
        await self._adaptive_delay()
        self.request_count += 1
        try:
            merged_headers = self._get_headers()
            if "headers" in kwargs:
                merged_headers.update(kwargs.pop("headers"))
            async with self.session.request(
                method,
                url,
                headers=merged_headers,
                proxy=self.proxy,
                **kwargs
            ) as resp:
                result = await self._build_response(resp)
                self._handle_rate_limit(resp.status)
                return result
        except Exception as e:
            return {"error": str(e), "status": 0, "text": "", "headers": {}}
    
    async def _build_response(self, resp):
        text = ""
        try:
            text = await resp.text()
        except:
            try:
                text = (await resp.read()).decode("utf-8", errors="ignore")
            except:
                pass
        return {
            "status": resp.status,
            "text": text,
            "headers": dict(resp.headers),
            "url": str(resp.url),
            "elapsed": 0,
        }
    
    async def timed_get(self, url, params=None, headers=None):
        await self._adaptive_delay()
        self.request_count += 1
        start = time.time()
        try:
            merged_headers = self._get_headers()
            if headers:
                merged_headers.update(headers)
            async with self.session.get(
                url,
                params=params,
                headers=merged_headers,
                proxy=self.proxy
            ) as resp:
                result = await self._build_response(resp)
                result["elapsed"] = time.time() - start
                self._handle_rate_limit(resp.status)
                return result
        except Exception as e:
            return {"error": str(e), "status": 0, "text": "", "headers": {}, "elapsed": time.time() - start}
    
    def get_stats(self):
        return {
            "requests": self.request_count,
            "rate_limit_hits": self.rate_limit_hits,
            "rate_limiter": self.rate_limiter.stats(),
            "metrics": self.metrics.stats(),
        }


class ScanCheckpoint:
    def __init__(self, checkpoint_file="lantern_checkpoint.json"):
        self.checkpoint_file = Path(checkpoint_file)
        self.data = {
            "targets_completed": [],
            "modules_completed": {},
            "findings": [],
            "timestamp": None,
        }
    
    def load(self):
        if self.checkpoint_file.exists():
            try:
                with open(self.checkpoint_file, "r") as f:
                    self.data = json_lib.load(f)
                return True
            except:
                pass
        return False
    
    def save(self):
        self.data["timestamp"] = time.time()
        with open(self.checkpoint_file, "w") as f:
            json_lib.dump(self.data, f, indent=2)
    
    def mark_target_complete(self, target, module):
        key = f"{target}:{module}"
        if key not in self.data["targets_completed"]:
            self.data["targets_completed"].append(key)
        self.save()
    
    def is_completed(self, target, module):
        key = f"{target}:{module}"
        return key in self.data["targets_completed"]
    
    def add_finding(self, finding):
        self.data["findings"].append(finding)
        self.save()
    
    def get_findings(self):
        return self.data.get("findings", [])
    
    def clear(self):
        self.data = {
            "targets_completed": [],
            "modules_completed": {},
            "findings": [],
            "timestamp": None,
        }
        if self.checkpoint_file.exists():
            self.checkpoint_file.unlink()


class Http2Client:
    def __init__(self, config):
        self.config = config
        self.headers = config.get("headers", {})
        self.proxy = config.get("proxy")
        self.stealth = config.get("stealth", False)
        self.client = None
        self.request_count = 0
        self.rate_limit_hits = 0
        self.adaptive_delay = 0
    
    async def __aenter__(self):
        try:
            import httpx
            self.client = httpx.AsyncClient(
                http2=True,
                timeout=httpx.Timeout(self.config.get("timeout", 10)),
                limits=httpx.Limits(
                    max_connections=self.config.get("threads", 50),
                    max_keepalive_connections=20
                ),
                verify=False,
                follow_redirects=True,
                headers=self._get_headers(),
            )
        except ImportError:
            self.client = None
        return self
    
    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()
    
    def _get_headers(self):
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        headers.update(self.headers)
        return headers
    
    async def _adaptive_delay(self):
        if self.stealth:
            await asyncio.sleep(random.uniform(0.5, 2.0) + self.adaptive_delay)
        elif self.adaptive_delay > 0:
            await asyncio.sleep(self.adaptive_delay)
    
    def _handle_rate_limit(self, status):
        if status == 429:
            self.rate_limit_hits += 1
            self.adaptive_delay = min(self.adaptive_delay + 0.5, 5.0)
        elif status == 200 and self.adaptive_delay > 0:
            self.adaptive_delay = max(self.adaptive_delay - 0.1, 0)
    
    async def get(self, url, params=None, headers=None):
        if not self.client:
            return {"error": "httpx not installed", "status": 0, "text": "", "headers": {}}
        
        await self._adaptive_delay()
        self.request_count += 1
        start = time.time()
        
        try:
            merged_headers = self._get_headers()
            if headers:
                merged_headers.update(headers)
            
            resp = await self.client.get(url, params=params, headers=merged_headers)
            self._handle_rate_limit(resp.status_code)
            
            return {
                "status": resp.status_code,
                "text": resp.text,
                "headers": dict(resp.headers),
                "url": str(resp.url),
                "elapsed": time.time() - start,
                "http_version": resp.http_version,
            }
        except Exception as e:
            return {"error": str(e), "status": 0, "text": "", "headers": {}, "elapsed": time.time() - start}
    
    async def post(self, url, data=None, json=None, headers=None):
        if not self.client:
            return {"error": "httpx not installed", "status": 0, "text": "", "headers": {}}
        
        await self._adaptive_delay()
        self.request_count += 1
        start = time.time()
        
        try:
            merged_headers = self._get_headers()
            if headers:
                merged_headers.update(headers)
            
            resp = await self.client.post(url, data=data, json=json, headers=merged_headers)
            self._handle_rate_limit(resp.status_code)
            
            return {
                "status": resp.status_code,
                "text": resp.text,
                "headers": dict(resp.headers),
                "url": str(resp.url),
                "elapsed": time.time() - start,
                "http_version": resp.http_version,
            }
        except Exception as e:
            return {"error": str(e), "status": 0, "text": "", "headers": {}, "elapsed": time.time() - start}
    
    def get_stats(self):
        return {
            "requests": self.request_count,
            "rate_limit_hits": self.rate_limit_hits,
            "http2_enabled": self.client is not None,
        }


def inject_param(url, param_name, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def get_params(url):
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def get_base_url(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def build_url(base, path, params=None):
    if params:
        return f"{base}{path}?{urlencode(params)}"
    return f"{base}{path}"
