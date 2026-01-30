import re
from urllib.parse import urlparse, urljoin
from modules.base import BaseModule
from core.utils import extract_params

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


class DomModule(BaseModule):
    name = "dom"
    description = "DOM-based Vulnerability Scanner"
    exploitable = True
    
    dangerous_sinks = [
        (r"document\.write\s*\(", "document.write", "HIGH"),
        (r"document\.writeln\s*\(", "document.writeln", "HIGH"),
        (r"\.innerHTML\s*=", "innerHTML", "HIGH"),
        (r"\.outerHTML\s*=", "outerHTML", "HIGH"),
        (r"eval\s*\(", "eval", "CRITICAL"),
        (r"new\s+Function\s*\(", "Function constructor", "CRITICAL"),
        (r"setTimeout\s*\(\s*['\"]", "setTimeout string", "HIGH"),
        (r"setInterval\s*\(\s*['\"]", "setInterval string", "HIGH"),
        (r"\.src\s*=", "src assignment", "MEDIUM"),
        (r"\.href\s*=", "href assignment", "MEDIUM"),
        (r"location\s*=", "location assignment", "HIGH"),
        (r"location\.href\s*=", "location.href", "HIGH"),
        (r"location\.replace\s*\(", "location.replace", "HIGH"),
        (r"location\.assign\s*\(", "location.assign", "HIGH"),
        (r"window\.open\s*\(", "window.open", "MEDIUM"),
        (r"document\.location\s*=", "document.location", "HIGH"),
        (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML", "HIGH"),
        (r"\.append\s*\(", "append", "MEDIUM"),
        (r"\.prepend\s*\(", "prepend", "MEDIUM"),
        (r"\.after\s*\(", "after", "MEDIUM"),
        (r"\.before\s*\(", "before", "MEDIUM"),
        (r"\.html\s*\(", "jQuery .html()", "HIGH"),
        (r"\$\s*\(\s*['\"]<", "jQuery HTML creation", "HIGH"),
        (r"jQuery\s*\(\s*['\"]<", "jQuery HTML creation", "HIGH"),
        (r"\.parseHTML\s*\(", "$.parseHTML", "HIGH"),
        (r"\.globalEval\s*\(", "$.globalEval", "CRITICAL"),
        (r"Range\.createContextualFragment\s*\(", "createContextualFragment", "HIGH"),
        (r"document\.implementation\.createHTMLDocument", "createHTMLDocument", "MEDIUM"),
    ]
    
    dangerous_sources = [
        (r"location\.hash", "location.hash"),
        (r"location\.search", "location.search"),
        (r"location\.href", "location.href"),
        (r"location\.pathname", "location.pathname"),
        (r"document\.URL", "document.URL"),
        (r"document\.documentURI", "document.documentURI"),
        (r"document\.referrer", "document.referrer"),
        (r"document\.baseURI", "document.baseURI"),
        (r"document\.cookie", "document.cookie"),
        (r"window\.name", "window.name"),
        (r"localStorage\.", "localStorage"),
        (r"sessionStorage\.", "sessionStorage"),
        (r"\.getItem\s*\(", "storage.getItem"),
        (r"history\.pushState", "history.pushState"),
        (r"history\.replaceState", "history.replaceState"),
        (r"window\.postMessage", "postMessage"),
        (r"addEventListener\s*\(\s*['\"]message", "message event"),
        (r"IndexedDB", "IndexedDB"),
        (r"WebSocket\s*\(", "WebSocket"),
        (r"XMLHttpRequest", "XMLHttpRequest"),
        (r"fetch\s*\(", "fetch API"),
    ]
    
    prototype_pollution = [
        r"__proto__",
        r"constructor\s*\[\s*['\"]prototype",
        r"Object\.assign\s*\(",
        r"Object\.defineProperty\s*\(",
        r"\.merge\s*\(",
        r"\.extend\s*\(",
        r"\.defaults\s*\(",
        r"JSON\.parse\s*\(",
        r"_.merge\s*\(",
        r"_.defaultsDeep\s*\(",
        r"jQuery\.extend\s*\(",
        r"\$\.extend\s*\(",
    ]
    
    async def scan(self, target):
        self.findings = []
        self.tainted_flows = []
        self.confirmed_xss = []
        params = extract_params(target)
        resp = await self.http.get(target)
        if not resp.get("status"):
            return self.findings
        html = resp.get("text", "")
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        if self.aggressive:
            await self._deep_js_analysis(target)
        
        script_urls = [urljoin(base_url, m.group(1).strip()) for m in SCRIPT_SRC_RE.finditer(html)]
        for script_url in script_urls[:10]:
            sresp = await self.http.get(script_url)
            if sresp.get("status") == 200 and sresp.get("text"):
                await self._analyze_script_sinks(target, script_url, sresp["text"])
        
        await self._analyze_dom_sinks(target, html)
        await self._analyze_data_flow(target, html)
        await self._check_prototype_pollution(target, html, params)
        await self._test_dom_xss(target, params)
        await self._check_postmessage(target, html)
        
        if self.aggressive:
            await self._test_dom_clobbering(target, html)
            await self._test_client_side_template_injection(target, params)
        
        return self.findings
    
    async def _deep_js_analysis(self, target):
        try:
            from core.js_analyzer import create_analyzer
            analyzer = create_analyzer()
            result = await analyzer.analyze_url(self.http, target)
            
            if result.dom_sinks:
                for sink in result.dom_sinks:
                    if sink.tainted:
                        self.tainted_flows.append(sink)
                        self.add_finding(
                            "CRITICAL" if sink.sink_type in ["eval", "Function"] else "HIGH",
                            f"DOM XSS: Tainted flow to {sink.sink_type}",
                            url=sink.file or target,
                            evidence=f"Source: {sink.source} → Sink: {sink.sink_type} (line {sink.line})",
                            confidence_evidence=["tainted_data_flow", "js_analyzer_confirmed"],
                            request_data={"url": target, "sink": sink.sink_type, "source": sink.source}
                        )
            
            if result.secrets:
                for secret in result.secrets[:5]:
                    self.add_finding(
                        "HIGH",
                        f"Hardcoded secret in JS: {secret.type}",
                        url=secret.file or target,
                        evidence=f"Value: {secret.value[:20]}... (line {secret.line})",
                        confidence_evidence=["secret_exposed", "client_side_leak"]
                    )
        except Exception:
            pass
    
    async def _test_dom_clobbering(self, target, html):
        clobberable_patterns = [
            r'document\.getElementById\(["\'](\w+)["\']\)\.(\w+)',
            r'document\.forms\[["\']?(\w+)["\']?\]',
            r'window\.(\w+)',
            r'document\.(\w+)',
        ]
        
        vulnerable_ids = []
        for pattern in clobberable_patterns:
            matches = re.findall(pattern, html)
            if matches:
                for m in matches[:3]:
                    id_name = m[0] if isinstance(m, tuple) else m
                    if id_name not in ["body", "head", "html", "documentElement"]:
                        vulnerable_ids.append(id_name)
        
        if vulnerable_ids:
            for vid in vulnerable_ids[:3]:
                payload = f'<form id="{vid}"><input name="innerHTML" value="clobbered"></form>'
                if f'id="{vid}"' not in html:
                    self.add_finding(
                        "MEDIUM",
                        f"DOM clobbering possible: {vid}",
                        url=target,
                        evidence=f"Global '{vid}' can be overwritten via DOM",
                        confidence_evidence=["dom_clobbering_vector"]
                    )
                    break
    
    async def _test_client_side_template_injection(self, target, params):
        template_payloads = [
            ("{{7*7}}", "49", "Angular/Vue"),
            ("${7*7}", "49", "ES6 template"),
            ("[[$root]]", "root", "Vue"),
            ("{{constructor.constructor('return 1')()}}", "1", "Angular sandbox bypass"),
        ]
        
        for param in list(params.keys())[:3] if params else ["q", "search", "input"]:
            for payload, expected, framework in template_payloads:
                test_url = f"{target.split('?')[0]}?{param}={payload}"
                resp = await self.http.get(test_url)
                
                if resp.get("status") == 200:
                    text = resp.get("text", "")
                    if expected in text and payload not in text:
                        self.add_finding(
                            "CRITICAL",
                            f"Client-side template injection ({framework})",
                            url=test_url,
                            parameter=param,
                            evidence=f"Payload {payload} evaluated to {expected}",
                            confidence_evidence=["template_injection_confirmed", "code_execution"],
                            request_data={"method": "GET", "url": test_url, "param": param, "payload": payload}
                        )
                        self.confirmed_xss.append({"type": "CSTI", "param": param, "framework": framework})
                        return
    
    async def _analyze_script_sinks(self, target, script_url, code):
        lines = code.splitlines()
        found_sinks = []
        found_sources = []
        for pattern, name, severity in self.dangerous_sinks:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    snippet = line.strip()[:120]
                    found_sinks.append((name, severity, i, snippet))
                    break
        for pattern, name in self.dangerous_sources:
            if re.search(pattern, code, re.IGNORECASE):
                found_sources.append(name)
        if not found_sinks or not found_sources:
            return
        critical_sinks = [s for s in found_sinks if s[1] == "CRITICAL"]
        high_sinks = [s for s in found_sinks if s[1] == "HIGH"]
        sev = "CRITICAL" if critical_sinks else "HIGH" if high_sinks else "MEDIUM"
        line_no = found_sinks[0][2]
        snippet = found_sinks[0][3]
        self.add_finding(
            sev,
            "DOM XSS: dangerous sink with user input in external script",
            url=script_url,
            evidence=f"Sinks: {found_sinks[0][0]}, line {line_no}: {snippet}; Sources: {', '.join(found_sources[:3])}"
        )

    async def _analyze_dom_sinks(self, target, html):
        found_sinks = []
        found_sources = []
        
        for pattern, name, severity in self.dangerous_sinks:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                found_sinks.append((name, severity, len(matches)))
        
        for pattern, name in self.dangerous_sources:
            if re.search(pattern, html, re.IGNORECASE):
                found_sources.append(name)
        
        if found_sinks and found_sources:
            critical_sinks = [s for s in found_sinks if s[1] == "CRITICAL"]
            high_sinks = [s for s in found_sinks if s[1] == "HIGH"]
            
            if critical_sinks:
                self.add_finding(
                    "CRITICAL",
                    f"DOM XSS: Critical sink with user input",
                    url=target,
                    evidence=f"Sinks: {', '.join([s[0] for s in critical_sinks])}, Sources: {', '.join(found_sources[:3])}"
                )
            elif high_sinks:
                self.add_finding(
                    "HIGH",
                    f"DOM XSS: Dangerous sink with user input",
                    url=target,
                    evidence=f"Sinks: {', '.join([s[0] for s in high_sinks[:3]])}, Sources: {', '.join(found_sources[:3])}"
                )
            else:
                self.add_finding(
                    "MEDIUM",
                    f"Potential DOM XSS",
                    url=target,
                    evidence=f"Sinks: {len(found_sinks)}, Sources: {len(found_sources)}"
                )
    
    async def _analyze_data_flow(self, target, html):
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        
        for script in scripts:
            for source_pattern, source_name in self.dangerous_sources[:8]:
                if re.search(source_pattern, script, re.IGNORECASE):
                    for sink_pattern, sink_name, severity in self.dangerous_sinks[:10]:
                        if re.search(sink_pattern, script, re.IGNORECASE):
                            flow_pattern = f"{source_pattern}.*?{sink_pattern}"
                            if re.search(flow_pattern, script, re.IGNORECASE | re.DOTALL):
                                self.add_finding(
                                    severity,
                                    f"DOM data flow: {source_name} → {sink_name}",
                                    url=target,
                                    evidence="Direct flow from source to sink detected"
                                )
                                return
    
    async def _check_prototype_pollution(self, target, html, params):
        for pattern in self.prototype_pollution:
            if re.search(pattern, html, re.IGNORECASE):
                self.add_finding(
                    "MEDIUM",
                    f"Prototype pollution vector detected",
                    url=target,
                    evidence=f"Pattern: {pattern[:30]}"
                )
                break
        
        if params:
            test_payloads = [
                "__proto__[test]=polluted",
                "constructor[prototype][test]=polluted",
                "__proto__.test=polluted",
            ]
            
            for payload in test_payloads:
                test_url = f"{target.split('?')[0]}?{payload}"
                resp = await self.http.get(test_url)
                
                if resp.get("status") == 200:
                    if "polluted" in resp.get("text", ""):
                        self.add_finding(
                            "HIGH",
                            f"Prototype pollution exploitable",
                            url=test_url,
                            evidence="Payload reflected in response"
                        )
                        return
    
    async def _test_dom_xss(self, target, params):
        if not params:
            return
        
        dom_payloads = [
            "#<img src=x onerror=alert(1)>",
            "#javascript:alert(1)",
            "#'-alert(1)-'",
        ]
        
        for payload in dom_payloads:
            test_url = target + payload
            resp = await self.http.get(test_url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                if payload.replace("#", "") in text:
                    self.add_finding(
                        "HIGH",
                        f"DOM XSS via fragment",
                        url=test_url,
                        evidence="Fragment payload reflected in page"
                    )
                    return
    
    async def _check_postmessage(self, target, html):
        if "postMessage" in html or "addEventListener" in html and "message" in html:
            origin_check = re.search(r'(event|e)\.origin\s*[!=]==?\s*[\'"]', html)
            
            if not origin_check:
                self.add_finding(
                    "HIGH",
                    "postMessage without origin validation",
                    url=target,
                    evidence="Message handler may accept messages from any origin"
                )
            
            if re.search(r'eval\s*\(\s*(event|e)\.(data|message)', html, re.IGNORECASE):
                self.add_finding(
                    "CRITICAL",
                    "postMessage data passed to eval",
                    url=target,
                    evidence="XSS via postMessage"
                )
