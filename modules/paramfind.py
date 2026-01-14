import re
import asyncio
import json
from typing import Dict, List, Set, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from modules.base import BaseModule
from core.utils import random_string


class ParamfindModule(BaseModule):
    name = "paramfind"
    description = "Hidden Parameter Discovery"
    
    common_params = [
        "id", "page", "p", "q", "query", "search", "s", "keyword", "keywords",
        "name", "user", "username", "email", "login", "password", "pass", "passwd",
        "token", "key", "api_key", "apikey", "api", "secret", "auth", "session",
        "file", "path", "dir", "folder", "url", "link", "redirect", "next", "return",
        "callback", "cb", "jsonp", "format", "type", "action", "do", "cmd", "command",
        "exec", "execute", "run", "func", "function", "method", "mode", "op", "operation",
        "data", "input", "output", "result", "response", "content", "body", "text",
        "sort", "order", "orderby", "sortby", "asc", "desc", "limit", "offset", "start",
        "count", "num", "number", "size", "length", "max", "min", "from", "to",
        "date", "time", "year", "month", "day", "hour", "minute", "second",
        "category", "cat", "tag", "tags", "label", "group", "class", "filter",
        "lang", "language", "locale", "country", "region", "timezone", "tz",
        "debug", "test", "dev", "admin", "root", "config", "setting", "settings",
        "view", "show", "display", "render", "template", "tpl", "layout", "theme",
        "include", "require", "load", "import", "module", "plugin", "component",
        "version", "v", "ver", "rev", "revision", "build", "release",
        "ref", "reference", "src", "source", "origin", "target", "dest", "destination",
        "host", "domain", "site", "server", "port", "protocol", "scheme",
        "width", "height", "w", "h", "x", "y", "z", "lat", "lng", "latitude", "longitude",
        "color", "colour", "bg", "background", "fg", "foreground", "font", "style",
        "ajax", "async", "xhr", "fetch", "cors", "jsonp", "xml", "json", "csv", "html",
        "upload", "download", "attach", "attachment", "image", "img", "photo", "pic",
        "video", "audio", "media", "document", "doc", "pdf", "zip", "archive",
        "message", "msg", "comment", "note", "description", "title", "subject", "topic",
        "status", "state", "flag", "enabled", "disabled", "active", "inactive", "hidden",
        "public", "private", "visible", "published", "draft", "pending", "approved",
        "role", "permission", "access", "level", "privilege", "scope", "grant",
        "oauth", "oauth2", "openid", "saml", "sso", "jwt", "bearer",
        "client_id", "client_secret", "code", "state", "nonce", "redirect_uri",
        "grant_type", "response_type", "scope", "audience", "resource",
        "account", "profile", "avatar", "bio", "about", "info", "details",
        "address", "phone", "mobile", "fax", "zip", "postal", "city", "street",
        "company", "organization", "org", "department", "dept", "team", "project",
        "item", "product", "sku", "upc", "ean", "isbn", "price", "cost", "amount",
        "quantity", "qty", "stock", "inventory", "cart", "checkout", "order", "invoice",
        "payment", "transaction", "txn", "receipt", "refund", "discount", "coupon", "promo",
        "subscribe", "unsubscribe", "newsletter", "notification", "alert", "notify",
        "share", "like", "favorite", "bookmark", "follow", "unfollow", "block", "report",
        "rate", "rating", "score", "vote", "poll", "survey", "feedback", "review",
    ]
    
    json_params = [
        "data", "json", "body", "payload", "request", "params", "args", "options",
        "config", "settings", "query", "filter", "where", "select", "fields",
        "include", "exclude", "expand", "embed", "populate", "relations",
    ]
    
    header_params = [
        "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "X-Original-URL",
        "X-Rewrite-URL", "X-Custom-IP-Authorization", "X-Api-Key", "X-Auth-Token",
        "X-Access-Token", "X-Request-Id", "X-Correlation-Id", "X-Trace-Id",
        "X-Debug", "X-Test", "X-Admin", "X-Internal", "X-Bypass",
        "Authorization", "Cookie", "Referer", "Origin", "Host",
    ]
    
    async def scan(self, target):
        self.findings = []
        self.discovered_params: Dict[str, List[str]] = {
            "get": [],
            "post": [],
            "json": [],
            "header": [],
        }
        
        await self._discover_get_params(target)
        await self._discover_post_params(target)
        await self._discover_json_params(target)
        await self._discover_header_params(target)
        await self._extract_params_from_js(target)
        await self._extract_params_from_html(target)
        
        total = sum(len(v) for v in self.discovered_params.values())
        
        if total > 0:
            self.add_finding(
                "INFO",
                f"Discovered {total} Hidden Parameters",
                url=target,
                evidence=f"GET: {len(self.discovered_params['get'])}, POST: {len(self.discovered_params['post'])}, JSON: {len(self.discovered_params['json'])}, Header: {len(self.discovered_params['header'])}"
            )
        
        return self.findings
    
    async def _discover_get_params(self, target: str):
        parsed = urlparse(target)
        existing_params: Set[str] = set(parse_qs(parsed.query).keys())
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self.baseline_response: Optional[Dict] = None
        
        baseline = await self.http.get(target)
        if not baseline.get("status"):
            return
        
        self.baseline_response = baseline
        baseline_len = len(baseline.get("text", ""))
        baseline_hash = hash(baseline.get("text", "")[:1000])
        
        sem = asyncio.Semaphore(30)
        
        async def test_param(param):
            if param in existing_params:
                return None
            
            async with sem:
                canary = random_string(8)
                test_url = f"{base_url}?{param}={canary}"
                
                if existing_params:
                    test_url = f"{target}&{param}={canary}"
                
                resp = await self.http.get(test_url)
                
                if not resp.get("status"):
                    return None
                
                resp_len = len(resp.get("text", ""))
                resp_hash = hash(resp.get("text", "")[:1000])
                
                if resp_hash != baseline_hash:
                    if abs(resp_len - baseline_len) > 10:
                        return param
                
                if canary in resp.get("text", ""):
                    return param
                
                return None
        
        tasks = [test_param(p) for p in self.common_params]
        results = await asyncio.gather(*tasks)
        
        for param in results:
            if param:
                self.discovered_params["get"].append(param)
    
    async def _discover_post_params(self, target: str):
        baseline = await self.http.post(target, data={})
        if not baseline.get("status"):
            return
        
        baseline_len = len(baseline.get("text", ""))
        
        sem = asyncio.Semaphore(20)
        
        async def test_param(param):
            async with sem:
                canary = random_string(8)
                
                resp = await self.http.post(target, data={param: canary})
                
                if not resp.get("status"):
                    return None
                
                resp_len = len(resp.get("text", ""))
                
                if abs(resp_len - baseline_len) > 20:
                    return param
                
                if canary in resp.get("text", ""):
                    return param
                
                return None
        
        tasks = [test_param(p) for p in self.common_params[:50]]
        results = await asyncio.gather(*tasks)
        
        for param in results:
            if param:
                self.discovered_params["post"].append(param)
    
    async def _discover_json_params(self, target: str):
        baseline = await self.http.post(target, json={}, headers={"Content-Type": "application/json"})
        if not baseline.get("status"):
            return
        
        baseline_len = len(baseline.get("text", ""))
        found_json_params: Set[str] = set()
        
        for param in self.json_params:
            canary = random_string(8)
            
            payload = json.dumps({param: canary})
            resp = await self.http.post(target, data=payload, headers={"Content-Type": "application/json"})
            
            if not resp.get("status"):
                continue
            
            resp_len = len(resp.get("text", ""))
            
            if abs(resp_len - baseline_len) > 20 or canary in resp.get("text", ""):
                found_json_params.add(param)
                self.discovered_params["json"].append(param)
    
    async def _discover_header_params(self, target: str):
        baseline = await self.http.get(target)
        if not baseline.get("status"):
            return
        
        baseline_status = baseline.get("status")
        baseline_len = len(baseline.get("text", ""))
        
        for header in self.header_params:
            canary = random_string(8)
            
            resp = await self.http.get(target, headers={header: canary})
            
            if not resp.get("status"):
                continue
            
            resp_status = resp.get("status")
            resp_len = len(resp.get("text", ""))
            
            if resp_status != baseline_status:
                self.discovered_params["header"].append(header)
                continue
            
            if abs(resp_len - baseline_len) > 50:
                self.discovered_params["header"].append(header)
                continue
            
            if canary in resp.get("text", ""):
                self.discovered_params["header"].append(header)
    
    async def _extract_params_from_js(self, target: str):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        html = resp.get("text", "")
        
        js_files = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I)
        
        all_js = html
        
        base = self.get_base(target)
        for js_file in js_files[:10]:
            js_url = urljoin(base, js_file)
            
            try:
                js_resp = await self.http.get(js_url)
                if js_resp.get("status") == 200:
                    all_js += js_resp.get("text", "")
            except:
                pass
        
        param_patterns = [
            r'[?&](\w+)=',
            r'\.get\(["\'](\w+)["\']',
            r'\.post\(["\'](\w+)["\']',
            r'params\[["\'](\w+)["\']',
            r'params\.(\w+)',
            r'query\[["\'](\w+)["\']',
            r'query\.(\w+)',
            r'data\[["\'](\w+)["\']',
            r'data\.(\w+)',
            r'["\'](\w+)["\']:\s*["\']',
            r'name=["\'](\w+)["\']',
        ]
        
        found_params = set()
        for pattern in param_patterns:
            matches = re.findall(pattern, all_js)
            for match in matches:
                if len(match) > 2 and len(match) < 30 and match.isalnum():
                    found_params.add(match)
        
        for param in found_params:
            if param not in self.discovered_params["get"]:
                if param.lower() in [p.lower() for p in self.common_params]:
                    continue
                
                self.discovered_params["get"].append(f"js:{param}")
    
    async def _extract_params_from_html(self, target: str):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        html = resp.get("text", "")
        
        input_names = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', html, re.I)
        select_names = re.findall(r'<select[^>]*name=["\']([^"\']+)["\']', html, re.I)
        textarea_names = re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', html, re.I)
        
        form_params = set(input_names + select_names + textarea_names)
        
        for param in form_params:
            if param not in self.discovered_params["post"]:
                self.discovered_params["post"].append(f"form:{param}")
        
        data_attrs = re.findall(r'data-(\w+)=', html, re.I)
        for attr in set(data_attrs):
            if len(attr) > 2 and attr not in self.discovered_params["get"]:
                self.discovered_params["get"].append(f"data:{attr}")
    
    def get_discovered_params(self) -> Dict[str, List[str]]:
        return self.discovered_params
    
    def build_test_url(self, base_url: str, params: Dict[str, str]) -> str:
        query_string = urlencode(params)
        return f"{base_url}?{query_string}" if query_string else base_url