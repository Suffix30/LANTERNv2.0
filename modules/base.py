from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from core.utils import random_string, extract_params
from core.http import inject_param, get_params, get_base_url
from core.learned import record_successful_payload, record_successful_mutation, load_payloads_with_learned, load_payloads_with_learned as load_payloads
from core.bypass import get_regex_mutator, get_obfuscator, PayloadMutator, WAFBypass, Obfuscator
from core.differ import AdvancedResponseDiffer, create_differ
from core.confidence import ConfidenceScorer, ConfidenceLevel, create_scorer
from core.poc import PoCGenerator, create_poc_generator

 
def requires(*modules):
    def decorator(cls):
        cls._dependencies = list(modules)
        return cls
    return decorator


def priority(level):
    def decorator(cls):
        cls._priority = level
        return cls
    return decorator


def tags(*tag_list):
    def decorator(cls):
        cls._tags = set(tag_list)
        return cls
    return decorator


class ModuleDependencyResolver:
    def __init__(self):
        self.modules = {}
        self.resolved = []
        self.unresolved = set()
    
    def add(self, module_cls):
        self.modules[module_cls.name] = module_cls
    
    def resolve(self):
        self.resolved = []
        self.unresolved = set()
        
        for name, module_cls in sorted(self.modules.items(), key=lambda x: getattr(x[1], '_priority', 50)):
            self._resolve_module(name, module_cls)
        
        return self.resolved
    
    def _resolve_module(self, name, module_cls, chain=None):
        if chain is None:
            chain = set()
        
        if name in self.unresolved:
            return
        
        if name in chain:
            return
        
        chain.add(name)
        
        dependencies = getattr(module_cls, '_dependencies', [])
        for dep in dependencies:
            if dep in self.modules and dep not in self.unresolved:
                self._resolve_module(dep, self.modules[dep], chain.copy())
        
        if name not in self.unresolved:
            self.unresolved.add(name)
            self.resolved.append(module_cls)
    
    def get_order(self):
        return [m.name for m in self.resolved]


class BaseModule(ABC):
    name = "base"
    description = "Base module"
    severity = "INFO"
    _dependencies = []
    _priority = 50
    _tags = set()
    exploitable = False
    
    def __init__(self, http, config):
        self.http = http
        self.config = config
        self.aggressive = config.get("aggressive", False)
        self.exploit_mode = config.get("exploit", False)
        self.findings = []
        self.exploited_data = {}
        self.differ = create_differ()
        self.confidence_scorer = create_scorer()
        self.poc_generator = create_poc_generator()
        self._baselines: Dict[str, dict] = {}
        self._request_cache: Dict[str, dict] = {}
    
    @abstractmethod
    async def scan(self, target):
        pass
    
    async def exploit(self, target, finding):
        return None
    
    def add_exploit_data(self, key, value):
        self.exploited_data[key] = value
    
    def add_finding(self, severity, description, url=None, parameter=None, evidence=None,
                    confidence_evidence: List[str] = None, request_data: dict = None, 
                    response_data: dict = None, **kwargs):
        confidence = None
        if confidence_evidence:
            result = self.confidence_scorer.calculate(self.name, confidence_evidence)
            confidence = result.level.value
            severity = self.confidence_scorer.adjust_severity(severity, result.level)
        
        finding = {
            "module": self.name,
            "severity": severity,
            "description": description,
            "url": url,
            "parameter": parameter,
            "evidence": evidence[:500] if evidence else None,
            "confidence": confidence,
        }
        
        finding.update(kwargs)
        
        if request_data:
            self._request_cache[url or ""] = request_data
            finding["request_data"] = request_data
        
        if response_data:
            finding["response_length"] = len(response_data.get("text", ""))
            finding["response_status"] = response_data.get("status")
            finding["response_data"] = {
                "status": response_data.get("status"),
                "headers": response_data.get("headers", {}),
                "text": response_data.get("text", "")[:2000],
            }
        
        skip_poc = kwargs.get('skip_generic_poc', False) or kwargs.get('secret_type') or kwargs.get('requires_browser')
        if not skip_poc:
            poc_data = self._generate_poc_data(url, parameter, request_data, response_data, description)
            if poc_data:
                finding["poc_data"] = poc_data
        
        self.findings.append(finding)
    
    def _generate_poc_data(self, url, parameter, request_data, response_data, description):
        if not url:
            return None
        
        method = "GET"
        payload = None
        headers = {}
        post_data = None
        
        if request_data:
            method = request_data.get("method", "GET")
            payload = request_data.get("payload")
            headers = request_data.get("headers", {})
            post_data = request_data.get("data")
        
        reproduction_steps = [
            f"Navigate to: {url}",
        ]
        
        if parameter and payload:
            reproduction_steps.append(f"Locate the '{parameter}' parameter")
            reproduction_steps.append(f"Inject the payload: {payload}")
            reproduction_steps.append(f"Observe the response for {description}")
        elif payload:
            reproduction_steps.append(f"Inject the payload: {payload}")
            reproduction_steps.append(f"Observe the response for {description}")
        else:
            reproduction_steps.append(f"Check for {description}")
        
        if response_data and response_data.get("status"):
            reproduction_steps.append(f"Expected response status: {response_data.get('status')}")
        
        curl_cmd = self._build_curl_command(url, method, parameter, payload, headers, post_data)
        python_code = self._build_python_code(url, method, parameter, payload, headers, post_data)
        
        return {
            "reproduction_steps": reproduction_steps,
            "curl_command": curl_cmd,
            "python_code": python_code,
            "payload": payload,
            "method": method,
        }
    
    def _build_curl_command(self, url, method, parameter, payload, headers, post_data):
        from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
        
        if method == "GET" and parameter and payload:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[parameter] = [payload]
            new_query = urlencode(params, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))
        
        cmd_parts = ["curl"]
        
        if method != "GET":
            cmd_parts.append(f"-X {method}")
        
        for name, value in headers.items():
            cmd_parts.append(f"-H '{name}: {value}'")
        
        if post_data:
            if parameter and payload:
                post_data = post_data.copy() if isinstance(post_data, dict) else {}
                post_data[parameter] = payload
            cmd_parts.append(f"-d '{urlencode(post_data) if isinstance(post_data, dict) else post_data}'")
        
        cmd_parts.append(f"'{url}'")
        
        return " \\\n  ".join(cmd_parts)
    
    def _build_python_code(self, url, method, parameter, payload, headers, post_data):
        from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
        
        code_lines = [
            "import requests",
            "",
        ]
        
        if method == "GET" and parameter and payload:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[parameter] = [payload]
            new_query = urlencode(params, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))
        
        code_lines.append(f"url = '{url}'")
        
        if headers:
            code_lines.append(f"headers = {repr(headers)}")
        else:
            code_lines.append("headers = {}")
        
        if method == "GET":
            code_lines.append("")
            code_lines.append("response = requests.get(url, headers=headers, verify=False)")
        elif method == "POST":
            if post_data:
                if parameter and payload:
                    post_data = post_data.copy() if isinstance(post_data, dict) else {}
                    post_data[parameter] = payload
                code_lines.append(f"data = {repr(post_data)}")
            else:
                code_lines.append("data = {}")
            code_lines.append("")
            code_lines.append("response = requests.post(url, headers=headers, data=data, verify=False)")
        else:
            code_lines.append("")
            code_lines.append(f"response = requests.request('{method}', url, headers=headers, verify=False)")
        
        code_lines.extend([
            "",
            "print(f'Status: {response.status_code}')",
            "print(f'Headers: {dict(response.headers)}')",
            "print(f'Body: {response.text[:1000]}')",
        ])
        
        return "\n".join(code_lines)
    
    def log(self, message):
        if self.config.get("verbose"):
            print(f"  {message}")
    
    def log_info(self, message):
        if self.config.get("verbose"):
            print(f"  [{self.name}] {message}")
    
    def log_error(self, message):
        if self.config.get("verbose"):
            print(f"  [{self.name}] ERROR: {message}")
    
    def gen_marker(self):
        return random_string(8)
    
    def get_base(self, url):
        return get_base_url(url)
    
    def get_url_params(self, url):
        return get_params(url)
    
    async def baseline_request(self, url):
        return await self.http.get(url)
    
    async def test_param(self, url, param, payload):
        test_url = inject_param(url, param, payload)
        return await self.http.get(test_url)
    
    async def test_post_param(self, url, param, payload, data=None):
        post_data = data.copy() if data else {}
        post_data[param] = payload
        return await self.http.post(url, data=post_data)
    
    async def test_params_with_payloads(self, url, payloads, check_func):
        params = extract_params(url)
        for param in params:
            for payload in payloads:
                resp = await self.test_param(url, param, payload)
                if resp.get("status") and check_func(resp, payload):
                    return param, payload, resp
        return None, None, None
    
    def get_payloads(self, name, limit=None):
        payloads = load_payloads_with_learned(name)
        if not self.aggressive and limit:
            return payloads[:limit]
        return payloads
    
    def extract_url_params(self, url):
        return extract_params(url)
    
    def record_success(self, payload, target=None):
        record_successful_payload(self.name, payload, {"target": target, "module": self.name})
    
    def record_mutation_success(self, original, mutation, target=None):
        record_successful_mutation(self.name, original, mutation, target)
    
    def mutate_payload(self, payload: str, category: str = None, use_regex: bool = True) -> List[str]:
        mutator = PayloadMutator()
        cat = category or self.name
        return mutator.mutate(payload, cat, use_regex)
    
    def mutate_with_waf_bypass(self, payload: str, aggressive: bool = None) -> List[str]:
        bypass = WAFBypass()
        use_aggressive = aggressive if aggressive is not None else self.aggressive
        return bypass.generate_variants(payload, use_aggressive)
    
    def extract_secrets(self, text: str) -> Dict[str, List[str]]:
        regex = get_regex_mutator()
        return regex.extract_secrets(text)
    
    def extract_pattern(self, text: str, pattern_name: str) -> List[str]:
        regex = get_regex_mutator()
        return regex.extract_all(text, pattern_name)
    
    def obfuscate(self, payload: str, techniques: List[str] = None, max_variants: int = 30) -> List[str]:
        obf = get_obfuscator()
        return obf.obfuscate(payload, techniques, max_variants)
    
    def obfuscate_encoding(self, payload: str) -> List[str]:
        return self.obfuscate(payload, ["encoding"])
    
    def obfuscate_all(self, payload: str) -> List[str]:
        return self.obfuscate(payload, None, 50)
    
    def get_polyglot_xss(self) -> List[str]:
        obf = get_obfuscator()
        return obf.get_polyglot_xss()
    
    def get_polyglot_sqli(self) -> List[str]:
        obf = get_obfuscator()
        return obf.get_polyglot_sqli()
    
    async def establish_baseline(self, url: str, method: str = "GET", **kwargs) -> dict:
        if url in self._baselines:
            return self._baselines[url]
        
        if method == "GET":
            resp = await self.http.get(url, **kwargs)
        else:
            resp = await self.http.post(url, **kwargs)
        
        self.differ.set_baseline(url, resp)
        self._baselines[url] = resp
        return resp
    
    def compare_response(self, url: str, response: dict) -> Any:
        return self.differ.compare(url, response)
    
    def find_reflection(self, response: dict, payload: str) -> List[Any]:
        return self.differ.find_reflection(response, payload)
    
    def calculate_similarity(self, resp1: dict, resp2: dict) -> float:
        return self.differ.calculate_similarity(resp1, resp2)
    
    def detect_boolean_behavior(self, true_responses: List[dict], false_responses: List[dict]) -> Optional[dict]:
        return self.differ.detect_boolean_behavior(true_responses, false_responses)
    
    def detect_time_anomaly(self, responses: List[dict], baseline_time: float = None) -> Optional[dict]:
        return self.differ.detect_time_anomaly(responses, baseline_time)
    
    def generate_poc(self, finding: dict, request: dict = None, response: dict = None) -> Any:
        return self.poc_generator.generate(finding, request, response)
    
    def get_confidence_requirements(self, current_level: str) -> List[str]:
        level = ConfidenceLevel[current_level] if current_level else ConfidenceLevel.LOW
        return self.confidence_scorer.get_verification_steps(self.name, level)
    
    async def test_param_with_baseline(self, url: str, param: str, payload: str) -> tuple:
        baseline = await self.establish_baseline(url)
        resp = await self.test_param(url, param, payload)
        diff = self.compare_response(url, resp)
        return resp, diff
    
    async def smart_fuzz_param(self, url: str, param: str, payloads: List[str]) -> List[dict]:
        baseline = await self.establish_baseline(url)
        results = []
        
        for payload in payloads:
            resp = await self.test_param(url, param, payload)
            diff = self.compare_response(url, resp)
            reflections = self.find_reflection(resp, payload)
            
            if diff.is_meaningful or reflections:
                results.append({
                    "payload": payload,
                    "response": resp,
                    "diff": diff.to_dict(),
                    "reflections": [r.to_dict() for r in reflections],
                })
        
        return results