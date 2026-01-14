from abc import ABC, abstractmethod
from typing import Dict, List
from core.utils import random_string, extract_params
from core.http import inject_param, get_params, get_base_url
from core.learned import record_successful_payload, record_successful_mutation, load_payloads_with_learned, load_payloads_with_learned as load_payloads
from core.bypass import get_regex_mutator, get_obfuscator, PayloadMutator, WAFBypass, Obfuscator

 
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
    
    @abstractmethod
    async def scan(self, target):
        pass
    
    async def exploit(self, target, finding):
        return None
    
    def add_exploit_data(self, key, value):
        self.exploited_data[key] = value
    
    def add_finding(self, severity, description, url=None, parameter=None, evidence=None):
        self.findings.append({
            "module": self.name,
            "severity": severity,
            "description": description,
            "url": url,
            "parameter": parameter,
            "evidence": evidence[:500] if evidence else None
        })
    
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