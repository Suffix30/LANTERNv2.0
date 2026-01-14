import re
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from collections import deque
from core.utils import TargetWordlist

class Crawler:
    def __init__(self, http, config):
        self.http = http
        self.config = config
        self.max_depth = config.get("crawl_depth", 3)
        self.max_urls = config.get("max_urls", 500)
        self.visited = set()
        self.discovered_urls = set()
        self.discovered_forms = []
        self.discovered_params = {}
        self.discovered_js = set()
        self.discovered_endpoints = set()
        self.wordlist = TargetWordlist()
        
    async def crawl(self, start_url):
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        queue = deque([(start_url, 0)])
        
        while queue and len(self.visited) < self.max_urls:
            batch = []
            for _ in range(min(20, len(queue))):
                if queue:
                    batch.append(queue.popleft())
            
            tasks = [self._process_url(url, depth) for url, depth in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    for new_url, new_depth in result:
                        if new_url not in self.visited and new_depth <= self.max_depth:
                            queue.append((new_url, new_depth))
        
        return {
            "urls": list(self.discovered_urls),
            "forms": self.discovered_forms,
            "params": self.discovered_params,
            "js_files": list(self.discovered_js),
            "endpoints": list(self.discovered_endpoints),
            "wordlist": self.wordlist,
        }
    
    async def _process_url(self, url, depth):
        if url in self.visited:
            return []
        
        self.visited.add(url)
        new_urls = []
        
        resp = await self.http.get(url)
        if not resp.get("status") or resp["status"] >= 400:
            return []
        
        content_type = resp.get("headers", {}).get("Content-Type", "")
        if "text/html" not in content_type.lower() and "application/json" not in content_type.lower():
            return []
        
        self.discovered_urls.add(url)
        
        self.wordlist.add_url(url)
        self.wordlist.add_response(resp.get("text", ""), content_type)
        for header_name, header_val in resp.get("headers", {}).items():
            self.wordlist.add_header(header_name, header_val)
        
        soup = BeautifulSoup(resp["text"], "lxml")
        
        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = self._normalize_url(href, url)
            if full_url and self._is_in_scope(full_url):
                new_urls.append((full_url, depth + 1))
                self._extract_params(full_url)
        
        for form in soup.find_all("form"):
            form_data = self._extract_form(form, url)
            if form_data:
                self.discovered_forms.append(form_data)
        
        for script in soup.find_all("script", src=True):
            js_url = self._normalize_url(script["src"], url)
            if js_url:
                self.discovered_js.add(js_url)
        
        self._extract_inline_endpoints(resp["text"])
        
        for script in soup.find_all("script"):
            if script.string:
                self._extract_js_endpoints(script.string)
        
        for tag in soup.find_all(["img", "iframe", "embed", "object", "source", "video", "audio"]):
            for attr in ["src", "data", "href"]:
                if tag.get(attr):
                    attr_url = self._normalize_url(tag[attr], url)
                    if attr_url and self._is_in_scope(attr_url):
                        new_urls.append((attr_url, depth + 1))
        
        return new_urls
    
    def _normalize_url(self, href, base):
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            return None
        
        try:
            full_url = urljoin(base, href)
            parsed = urlparse(full_url)
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            return normalized
        except:
            return None
    
    def _is_in_scope(self, url):
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain or parsed.netloc.endswith(f".{self.base_domain}")
        except:
            return False
    
    def _extract_params(self, url):
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base not in self.discovered_params:
                self.discovered_params[base] = set()
            for param in params.keys():
                self.discovered_params[base].add(param)
        except:
            pass
    
    def _build_test_url(self, base, params):
        return f"{base}?{urlencode(params)}"
    
    def _extract_form(self, form, base_url):
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        action_url = self._normalize_url(action, base_url) or base_url
        
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                input_type = inp.get("type", "text")
                value = inp.get("value", "")
                inputs.append({
                    "name": name,
                    "type": input_type,
                    "value": value,
                })
        
        if inputs:
            return {
                "action": action_url,
                "method": method,
                "inputs": inputs,
            }
        return None
    
    def _extract_inline_endpoints(self, html):
        patterns = [
            r'["\'](/api/[^"\'>\s]+)["\']',
            r'["\'](/v\d+/[^"\'>\s]+)["\']',
            r'["\']([^"\'>\s]*/graphql)["\']',
            r'["\'](https?://[^"\'>\s]+/api/[^"\'>\s]+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            r'href\s*=\s*["\']([^"\']+\.(?:php|asp|aspx|jsp|json|xml))["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                endpoint = self._normalize_url(match, self.base_url)
                if endpoint:
                    self.discovered_endpoints.add(endpoint)
    
    def _extract_js_endpoints(self, js_content):
        patterns = [
            r'["\'](/[a-zA-Z0-9_/\-]+)["\']',
            r'["\']([a-zA-Z0-9_\-]+\.(?:php|asp|aspx|jsp|json|xml|action))["\']',
            r'path\s*:\s*["\']([^"\']+)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'endpoint\s*:\s*["\']([^"\']+)["\']',
            r'api[_]?(?:url|endpoint|path)\s*[=:]\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 2 and not match.endswith(('.js', '.css', '.png', '.jpg', '.gif', '.svg')):
                    endpoint = self._normalize_url(match, self.base_url)
                    if endpoint:
                        self.discovered_endpoints.add(endpoint)


class JSAnalyzer:
    def __init__(self, http):
        self.http = http
        self.secrets = []
        self.endpoints = []
        self.sensitive_data = []
    
    async def analyze(self, js_urls):
        tasks = [self._analyze_js(url) for url in js_urls]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            "secrets": self.secrets,
            "endpoints": self.endpoints,
            "sensitive_data": self.sensitive_data,
        }
    
    async def _analyze_js(self, url):
        resp = await self.http.get(url)
        if not resp.get("status") or resp["status"] != 200:
            return
        
        content = resp["text"]
        
        secret_patterns = [
            (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key"),
            (r'["\']?api[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Secret"),
            (r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', "Auth Token"),
            (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{6,})["\']', "Password"),
            (r'["\']?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "Secret"),
            (r'["\']?private[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', "Private Key"),
            (r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']?(AKIA[A-Z0-9]{16})', "AWS Access Key"),
            (r'["\']?bearer\s+([a-zA-Z0-9_\-\.]+)["\']', "Bearer Token"),
            (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "JWT Token"),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub Token"),
            (r'sk-[a-zA-Z0-9]{48}', "OpenAI Key"),
            (r'xox[baprs]-[a-zA-Z0-9\-]+', "Slack Token"),
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 5 and match not in ["undefined", "null", "true", "false"]:
                    self.secrets.append({
                        "type": secret_type,
                        "value": match[:50] + "..." if len(match) > 50 else match,
                        "source": url,
                    })
        
        endpoint_patterns = [
            r'["\']((?:https?:)?//[^"\'>\s]+)["\']',
            r'["\'](/api/[^"\'>\s]+)["\']',
            r'["\'](/v[0-9]+/[^"\'>\s]+)["\']',
            r'["\']([^"\'>\s]+\.(?:php|asp|aspx|jsp|action|do))["\']',
        ]
        
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if not match.endswith(('.js', '.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf')):
                    self.endpoints.append({"endpoint": match, "source": url})
        
        sensitive_patterns = [
            (r'["\']?(?:admin|root|superuser)["\']?\s*[:=]', "Admin Reference"),
            (r'["\']?debug["\']?\s*[:=]\s*true', "Debug Enabled"),
            (r'(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d+', "Internal Address"),
            (r'(?:mysql|postgres|mongodb|redis)://[^\s"\']+', "Database URL"),
            (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', "Private Key"),
        ]
        
        for pattern, data_type in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.sensitive_data.append({"type": data_type, "source": url})
