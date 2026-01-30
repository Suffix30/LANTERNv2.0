import re
import json
import base64
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin


@dataclass
class Endpoint:
    url: str
    method: str
    parameters: List[str]
    source_file: str
    line_number: int
    context: str
    confidence: float = 0.8
    
    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": self.parameters,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "context": self.context,
            "confidence": self.confidence,
        }


@dataclass
class Secret:
    secret_type: str
    value: str
    source_file: str
    line_number: int
    context: str
    severity: str = "HIGH"
    
    def to_dict(self) -> dict:
        return {
            "type": self.secret_type,
            "value": self.value[:50] + "..." if len(self.value) > 50 else self.value,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "context": self.context,
            "severity": self.severity,
        }


@dataclass
class DOMSink:
    sink_type: str
    source_file: str
    line_number: int
    context: str
    tainted: bool
    source: Optional[str]
    severity: str = "MEDIUM"
    
    def to_dict(self) -> dict:
        return {
            "sink_type": self.sink_type,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "context": self.context,
            "tainted": self.tainted,
            "source": self.source,
            "severity": self.severity,
        }


@dataclass
class JSAnalysisResult:
    scripts_analyzed: int
    endpoints: List[Endpoint]
    secrets: List[Secret]
    dom_sinks: List[DOMSink]
    source_maps: List[str]
    frameworks_detected: List[str]
    interesting_strings: List[str]
    
    def to_dict(self) -> dict:
        return {
            "scripts_analyzed": self.scripts_analyzed,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "secrets": [s.to_dict() for s in self.secrets],
            "dom_sinks": [d.to_dict() for d in self.dom_sinks],
            "source_maps": self.source_maps,
            "frameworks_detected": self.frameworks_detected,
            "interesting_strings": self.interesting_strings[:50],
        }


ENDPOINT_PATTERNS = [
    (r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', "GET", "fetch"),
    (r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]\s*,\s*\{[^}]*method\s*:\s*[\'"`](GET|POST|PUT|DELETE|PATCH)[\'"`]', None, "fetch"),
    (r'axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', None, "axios"),
    (r'axios\s*\(\s*\{[^}]*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]', "GET", "axios"),
    (r'\$\s*\.\s*(ajax|get|post)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', None, "jquery"),
    (r'\$\s*\.\s*ajax\s*\(\s*\{[^}]*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]', "GET", "jquery"),
    (r'\.open\s*\(\s*[\'"`](GET|POST|PUT|DELETE)[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]', None, "xhr"),
    (r'new\s+XMLHttpRequest[^;]*\.open\s*\([\'"`](\w+)[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]', None, "xhr"),
    (r'new\s+WebSocket\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', "WS", "websocket"),
    (r'new\s+EventSource\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', "SSE", "eventsource"),
    (r'[\'"`](/api/[^\'"`]{3,50})[\'"`]', "GET", "api_path"),
    (r'[\'"`](/v\d+/[^\'"`]{3,50})[\'"`]', "GET", "versioned_api"),
    (r'[\'"`](/graphql[^\'"`]*)[\'"`]', "POST", "graphql"),
    (r'[\'"`]([^\'"`]*\.json)[\'"`]', "GET", "json_file"),
    (r'baseURL\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]', "BASE", "base_url"),
    (r'apiUrl\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]', "BASE", "api_url"),
    (r'endpoint\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]', "GET", "endpoint"),
]

SECRET_PATTERNS = [
    (r'[\'"`](AIza[0-9A-Za-z_-]{35})[\'"`]', "Google API Key", "CRITICAL"),
    (r'[\'"`](AKIA[0-9A-Z]{16})[\'"`]', "AWS Access Key ID", "CRITICAL"),
    (r'[\'"`]([0-9a-zA-Z/+]{40})[\'"`]', "AWS Secret Key (potential)", "HIGH"),
    (r'(sk_live_[0-9a-zA-Z]{24,})', "Stripe Secret Key", "CRITICAL"),
    (r'(pk_live_[0-9a-zA-Z]{24,})', "Stripe Publishable Key", "MEDIUM"),
    (r'(sk_test_[0-9a-zA-Z]{24,})', "Stripe Test Secret Key", "HIGH"),
    (r'(ghp_[a-zA-Z0-9]{36})', "GitHub Personal Access Token", "CRITICAL"),
    (r'(gho_[a-zA-Z0-9]{36})', "GitHub OAuth Token", "CRITICAL"),
    (r'(glpat-[a-zA-Z0-9_-]{20,})', "GitLab Personal Access Token", "CRITICAL"),
    (r'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)', "Slack Token", "CRITICAL"),
    (r'(sq0atp-[0-9A-Za-z_-]{22})', "Square Access Token", "CRITICAL"),
    (r'(sq0csp-[0-9A-Za-z_-]{43})', "Square OAuth Secret", "CRITICAL"),
    (r'(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})', "SendGrid API Key", "CRITICAL"),
    (r'(key-[0-9a-zA-Z]{32})', "Mailgun API Key", "CRITICAL"),
    (r'[\'"`]([0-9a-f]{32})[\'"`]', "32-char Hex (API Key/Hash)", "MEDIUM"),
    (r'api[_-]?key[\'"`]?\s*[:=]\s*[\'"`]([^\'"`]{16,})[\'"`]', "Generic API Key", "HIGH"),
    (r'api[_-]?secret[\'"`]?\s*[:=]\s*[\'"`]([^\'"`]{16,})[\'"`]', "API Secret", "CRITICAL"),
    (r'password[\'"`]?\s*[:=]\s*[\'"`]([^\'"`]{4,})[\'"`]', "Hardcoded Password", "CRITICAL"),
    (r'secret[\'"`]?\s*[:=]\s*[\'"`]([^\'"`]{8,})[\'"`]', "Generic Secret", "HIGH"),
    (r'token[\'"`]?\s*[:=]\s*[\'"`]([a-zA-Z0-9_-]{20,})[\'"`]', "Generic Token", "HIGH"),
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key", "CRITICAL"),
    (r'-----BEGIN CERTIFICATE-----', "Certificate", "MEDIUM"),
    (r'firebase[\'"`]?\s*[:=]\s*\{[^}]*apiKey[\'"`]?\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]', "Firebase API Key", "HIGH"),
    (r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})', "JWT Token", "HIGH"),
]

DOM_SINKS = [
    (r'\.innerHTML\s*=\s*([^;]+)', "innerHTML", "HIGH"),
    (r'\.outerHTML\s*=\s*([^;]+)', "outerHTML", "HIGH"),
    (r'document\.write\s*\(([^)]+)\)', "document.write", "HIGH"),
    (r'document\.writeln\s*\(([^)]+)\)', "document.writeln", "HIGH"),
    (r'eval\s*\(([^)]+)\)', "eval", "CRITICAL"),
    (r'new\s+Function\s*\(([^)]+)\)', "Function constructor", "CRITICAL"),
    (r'setTimeout\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', "setTimeout string", "HIGH"),
    (r'setInterval\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', "setInterval string", "HIGH"),
    (r'location\s*=\s*([^;]+)', "location assignment", "MEDIUM"),
    (r'location\.href\s*=\s*([^;]+)', "location.href", "MEDIUM"),
    (r'location\.assign\s*\(([^)]+)\)', "location.assign", "MEDIUM"),
    (r'location\.replace\s*\(([^)]+)\)', "location.replace", "MEDIUM"),
    (r'window\.open\s*\(([^)]+)\)', "window.open", "MEDIUM"),
    (r'\$\s*\([^)]*\)\.html\s*\(([^)]+)\)', "jQuery .html()", "HIGH"),
    (r'\$\s*\([^)]*\)\.append\s*\(([^)]+)\)', "jQuery .append()", "MEDIUM"),
    (r'\$\s*\([^)]*\)\.prepend\s*\(([^)]+)\)', "jQuery .prepend()", "MEDIUM"),
    (r'\$\s*\([^)]*\)\.after\s*\(([^)]+)\)', "jQuery .after()", "MEDIUM"),
    (r'\$\s*\([^)]*\)\.before\s*\(([^)]+)\)', "jQuery .before()", "MEDIUM"),
    (r'\.insertAdjacentHTML\s*\([^,]+,\s*([^)]+)\)', "insertAdjacentHTML", "HIGH"),
    (r'\.src\s*=\s*([^;]+)', "src assignment", "MEDIUM"),
    (r'\.setAttribute\s*\(\s*[\'"`]on\w+[\'"`]', "event handler setAttribute", "HIGH"),
    (r'\.setAttribute\s*\(\s*[\'"`]href[\'"`]\s*,\s*([^)]+)\)', "href setAttribute", "MEDIUM"),
]

DOM_SOURCES = [
    r'location\.hash',
    r'location\.search',
    r'location\.pathname',
    r'location\.href',
    r'document\.URL',
    r'document\.documentURI',
    r'document\.referrer',
    r'document\.cookie',
    r'window\.name',
    r'localStorage\.',
    r'sessionStorage\.',
    r'\.getItem\s*\(',
    r'postMessage',
    r'\.data\b',
    r'URLSearchParams',
]


class JSAnalyzer:
    def __init__(self):
        self._scripts_cache = {}
        self._results_cache = {}
    
    async def analyze_url(self, http_client, url: str) -> JSAnalysisResult:
        all_endpoints = []
        all_secrets = []
        all_sinks = []
        source_maps = []
        frameworks = set()
        interesting = []
        scripts_count = 0
        
        response = await http_client.get(url)
        if response.get("error"):
            return JSAnalysisResult(0, [], [], [], [], [], [])
        
        html = response.get("text", "")
        base_url = url
        
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        for i, script in enumerate(inline_scripts):
            if script.strip():
                result = self.analyze_script(script, f"{url}#inline-{i}", base_url)
                all_endpoints.extend(result.endpoints)
                all_secrets.extend(result.secrets)
                all_sinks.extend(result.dom_sinks)
                frameworks.update(result.frameworks_detected)
                interesting.extend(result.interesting_strings)
                scripts_count += 1
        
        external_scripts = re.findall(r'<script[^>]*src=[\'"]([^"\']+)[\'"][^>]*>', html, re.IGNORECASE)
        for script_url in external_scripts:
            full_url = urljoin(base_url, script_url)
            
            if not self._is_same_origin(full_url, base_url):
                continue
            
            script_resp = await http_client.get(full_url)
            if script_resp.get("error") or script_resp.get("status") != 200:
                continue
            
            script_content = script_resp.get("text", "")
            
            if ".map" not in script_url:
                map_url = full_url + ".map"
                map_resp = await http_client.get(map_url)
                if map_resp.get("status") == 200:
                    source_maps.append(map_url)
            
            result = self.analyze_script(script_content, full_url, base_url)
            all_endpoints.extend(result.endpoints)
            all_secrets.extend(result.secrets)
            all_sinks.extend(result.dom_sinks)
            frameworks.update(result.frameworks_detected)
            interesting.extend(result.interesting_strings)
            scripts_count += 1
        
        unique_endpoints = self._deduplicate_endpoints(all_endpoints)
        unique_secrets = self._deduplicate_secrets(all_secrets)
        
        return JSAnalysisResult(
            scripts_analyzed=scripts_count,
            endpoints=unique_endpoints,
            secrets=unique_secrets,
            dom_sinks=all_sinks,
            source_maps=source_maps,
            frameworks_detected=list(frameworks),
            interesting_strings=list(set(interesting))[:100],
        )
    
    def analyze_script(self, content: str, source_file: str, base_url: str = "") -> JSAnalysisResult:
        endpoints = self._find_endpoints(content, source_file, base_url)
        secrets = self._find_secrets(content, source_file)
        sinks = self._find_dom_sinks(content, source_file)
        frameworks = self._detect_frameworks(content)
        interesting = self._find_interesting_strings(content)
        
        return JSAnalysisResult(
            scripts_analyzed=1,
            endpoints=endpoints,
            secrets=secrets,
            dom_sinks=sinks,
            source_maps=[],
            frameworks_detected=frameworks,
            interesting_strings=interesting,
        )
    
    def _find_endpoints(self, content: str, source_file: str, base_url: str) -> List[Endpoint]:
        endpoints = []
        lines = content.split('\n')
        
        for pattern, default_method, source_type in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                groups = match.groups()
                
                if source_type in ["fetch", "axios", "jquery", "xhr"] and len(groups) >= 2:
                    method = groups[0].upper() if groups[0] else default_method
                    url = groups[1] if len(groups) > 1 else groups[0]
                else:
                    method = default_method or "GET"
                    url = groups[0] if groups else ""
                
                if not url or url.startswith("data:") or len(url) < 2:
                    continue
                
                if not url.startswith(('http://', 'https://', '/')):
                    if not re.match(r'^[a-zA-Z]', url):
                        continue
                
                line_num = content[:match.start()].count('\n') + 1
                context_start = max(0, match.start() - 50)
                context_end = min(len(content), match.end() + 50)
                context = content[context_start:context_end].replace('\n', ' ')
                
                params = self._extract_params_from_context(content, match.start(), match.end())
                
                if base_url and url.startswith('/'):
                    parsed = urlparse(base_url)
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"
                
                endpoints.append(Endpoint(
                    url=url,
                    method=method,
                    parameters=params,
                    source_file=source_file,
                    line_number=line_num,
                    context=context[:150],
                    confidence=0.9 if source_type in ["fetch", "axios", "xhr"] else 0.7,
                ))
        
        return endpoints
    
    def _find_secrets(self, content: str, source_file: str) -> List[Secret]:
        secrets = []
        found_values = set()
        
        for pattern, secret_type, severity in SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                value = match.group(1) if match.groups() else match.group(0)
                
                if value in found_values:
                    continue
                
                if self._is_false_positive_secret(value, secret_type):
                    continue
                
                found_values.add(value)
                
                line_num = content[:match.start()].count('\n') + 1
                context_start = max(0, match.start() - 30)
                context_end = min(len(content), match.end() + 30)
                context = content[context_start:context_end].replace('\n', ' ')
                
                secrets.append(Secret(
                    secret_type=secret_type,
                    value=value,
                    source_file=source_file,
                    line_number=line_num,
                    context=context[:100],
                    severity=severity,
                ))
        
        return secrets
    
    def _find_dom_sinks(self, content: str, source_file: str) -> List[DOMSink]:
        sinks = []
        sources_pattern = '|'.join(DOM_SOURCES)
        
        for pattern, sink_type, severity in DOM_SINKS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                context_start = max(0, match.start() - 50)
                context_end = min(len(content), match.end() + 50)
                context = content[context_start:context_end].replace('\n', ' ')
                
                input_expr = match.group(1) if match.groups() else ""
                tainted = bool(re.search(sources_pattern, input_expr, re.IGNORECASE))
                source = None
                
                if tainted:
                    for src_pattern in DOM_SOURCES:
                        if re.search(src_pattern, input_expr, re.IGNORECASE):
                            source = src_pattern.replace(r'\s*\(', '').replace(r'\.', '.')
                            break
                
                sinks.append(DOMSink(
                    sink_type=sink_type,
                    source_file=source_file,
                    line_number=line_num,
                    context=context[:150],
                    tainted=tainted,
                    source=source,
                    severity="CRITICAL" if tainted else severity,
                ))
        
        return sinks
    
    def _detect_frameworks(self, content: str) -> List[str]:
        frameworks = []
        
        patterns = [
            (r'React\.createElement|ReactDOM|__REACT', "React"),
            (r'angular\.module|ng-app|__ng', "Angular"),
            (r'Vue\.component|new Vue\(|__vue__', "Vue.js"),
            (r'jQuery|\$\(document\)|\$\(function', "jQuery"),
            (r'Backbone\.Model|Backbone\.View', "Backbone.js"),
            (r'Ember\.Application|Ember\.Component', "Ember.js"),
            (r'next/router|__NEXT_DATA__', "Next.js"),
            (r'nuxt|__NUXT__', "Nuxt.js"),
            (r'svelte|__svelte', "Svelte"),
            (r'Alpine\.data|x-data', "Alpine.js"),
            (r'htmx\.org|hx-get|hx-post', "htmx"),
            (r'axios\.create|axios\.defaults', "Axios"),
            (r'lodash|_\.map|_\.filter', "Lodash"),
            (r'moment\(|moment\.', "Moment.js"),
            (r'socket\.io|io\.connect', "Socket.IO"),
            (r'firebase\.initializeApp', "Firebase"),
            (r'aws-sdk|AWS\.', "AWS SDK"),
            (r'google\.maps|new google\.maps', "Google Maps"),
            (r'Stripe\(|stripe\.', "Stripe"),
            (r'PayPal|paypal\.', "PayPal"),
        ]
        
        for pattern, name in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                frameworks.append(name)
        
        return frameworks
    
    def _find_interesting_strings(self, content: str) -> List[str]:
        interesting = []
        
        patterns = [
            r'admin|administrator',
            r'debug|test|staging|dev',
            r'internal|private|secret',
            r'backup|dump|export',
            r'\.env|config|settings',
            r'todo|fixme|hack|xxx',
            r'password|passwd|pwd|credentials',
            r'bearer|authorization',
            r'localhost|127\.0\.0\.1|0\.0\.0\.0',
            r'database|mysql|postgres|mongodb',
        ]
        
        for pattern in patterns:
            matches = re.findall(rf'\b\w*{pattern}\w*\b', content, re.IGNORECASE)
            interesting.extend(matches[:5])
        
        comments = re.findall(r'//[^\n]{10,100}|/\*[\s\S]{10,200}?\*/', content)
        for comment in comments[:20]:
            if any(kw in comment.lower() for kw in ['todo', 'fixme', 'hack', 'bug', 'secret', 'key', 'password']):
                interesting.append(comment[:100])
        
        return list(set(interesting))
    
    def _extract_params_from_context(self, content: str, start: int, end: int) -> List[str]:
        params = []
        
        context_end = min(len(content), end + 500)
        context = content[start:context_end]
        
        param_patterns = [
            r'[\?&](\w+)=',
            r'params\s*[:=]\s*\{([^}]+)\}',
            r'data\s*[:=]\s*\{([^}]+)\}',
            r'body\s*[:=]\s*\{([^}]+)\}',
            r'"(\w+)":\s*["\'\d\[\{]',
            r"'(\w+)':\s*[\"'\d\[\{]",
        ]
        
        for pattern in param_patterns:
            matches = re.findall(pattern, context)
            for match in matches:
                if isinstance(match, str):
                    if ':' in match:
                        keys = re.findall(r'["\']?(\w+)["\']?\s*:', match)
                        params.extend(keys)
                    else:
                        params.append(match)
        
        return list(set(params))[:10]
    
    def _is_false_positive_secret(self, value: str, secret_type: str) -> bool:
        if len(value) < 8:
            return True
        
        if value in ['undefined', 'null', 'true', 'false', 'function', 'object']:
            return True
        
        if re.match(r'^[a-z]+$', value) and len(value) < 20:
            return True
        
        if value.count('0') > len(value) * 0.5:
            return True
        
        placeholders = ['xxx', 'your_', 'example', 'placeholder', 'changeme', 'insert', 'replace']
        if any(p in value.lower() for p in placeholders):
            return True
        
        return False
    
    def _is_same_origin(self, url1: str, url2: str) -> bool:
        p1 = urlparse(url1)
        p2 = urlparse(url2)
        return p1.netloc == p2.netloc
    
    def _deduplicate_endpoints(self, endpoints: List[Endpoint]) -> List[Endpoint]:
        seen = set()
        unique = []
        for ep in endpoints:
            key = (ep.url, ep.method)
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return unique
    
    def _deduplicate_secrets(self, secrets: List[Secret]) -> List[Secret]:
        seen = set()
        unique = []
        for secret in secrets:
            key = (secret.secret_type, secret.value)
            if key not in seen:
                seen.add(key)
                unique.append(secret)
        return unique


def create_analyzer() -> JSAnalyzer:
    return JSAnalyzer()


async def analyze_url(http_client, url: str) -> JSAnalysisResult:
    analyzer = JSAnalyzer()
    return await analyzer.analyze_url(http_client, url)
