import os
import re
import json
import subprocess
import hashlib
import math
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
  
from .base import Agent


def capability(name: str, description: str, parameters: Dict[str, Any] = None, category: str = "general"):
    def decorator(func: Callable):
        func._capability_info = {
            "name": name,
            "description": description,
            "parameters": parameters or {},
            "category": category,
            "callable": func.__name__
        }
        return func
    return decorator


class CapabilityRegistry:
    def __init__(self, agent):
        self._agent = agent
        self._capabilities: Dict[str, Dict[str, Any]] = {}
        self._execution_history: List[Dict[str, Any]] = []
        self._scan_for_capabilities()
    
    def _scan_for_capabilities(self):
        for attr_name in dir(self._agent):
            try:
                attr = getattr(self._agent, attr_name)
                if callable(attr) and hasattr(attr, '_capability_info'):
                    info = attr._capability_info
                    self._capabilities[info["name"]] = {
                        **info,
                        "method": attr,
                        "call_count": 0,
                        "last_called": None,
                    }
            except:
                pass
    
    def _generate_execution_id(self, name: str) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        hash_input = f"{name}:{timestamp}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:12]
    
    def list_all(self) -> List[Dict[str, Any]]:
        return [
            {k: v for k, v in cap.items() if k != "method"}
            for cap in self._capabilities.values()
        ]
    
    def get(self, name: str) -> Optional[Dict[str, Any]]:
        return self._capabilities.get(name)
    
    def execute(self, name: str, **kwargs) -> Any:
        cap = self._capabilities.get(name)
        if not cap:
            raise ValueError(f"Unknown capability: {name}")
        
        execution_id = self._generate_execution_id(name)
        start_time = datetime.now(timezone.utc)
        
        result = cap["method"](**kwargs)
        
        end_time = datetime.now(timezone.utc)
        duration_ms = (end_time - start_time).total_seconds() * 1000
        
        cap["call_count"] += 1
        cap["last_called"] = end_time.isoformat()
        
        self._execution_history.append({
            "id": execution_id,
            "capability": name,
            "timestamp": start_time.isoformat(),
            "duration_ms": duration_ms,
            "success": result is not None,
        })
        
        if len(self._execution_history) > 100:
            self._execution_history = self._execution_history[-100:]
        
        return result
    
    def by_category(self, category: str) -> List[Dict[str, Any]]:
        return [
            {k: v for k, v in cap.items() if k != "method"}
            for cap in self._capabilities.values()
            if cap.get("category") == category
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        total_calls = sum(c.get("call_count", 0) for c in self._capabilities.values())
        categories = set(c.get("category", "general") for c in self._capabilities.values())
        
        return {
            "total_capabilities": len(self._capabilities),
            "total_calls": total_calls,
            "categories": list(categories),
            "recent_executions": len(self._execution_history),
        }
    
    def get_capability_priority(self, name: str) -> float:
        cap = self._capabilities.get(name)
        if not cap:
            return 0.0
        
        call_count = cap.get("call_count", 0)
        base_priority = 1.0 / (1.0 + math.exp(-0.1 * call_count))
        return base_priority
    
    def to_prompt_format(self) -> str:
        lines = ["AVAILABLE CAPABILITIES:"]
        for cat in set(c.get("category", "general") for c in self._capabilities.values()):
            lines.append(f"\n[{cat.upper()}]")
            for cap in self.by_category(cat):
                params = ", ".join(f"{k}: {v.get('type', 'any')}" for k, v in cap.get("parameters", {}).items())
                lines.append(f"  - {cap['name']}({params})")
                lines.append(f"    {cap['description']}")
        return "\n".join(lines)


class MultiProviderLLM:
    PROVIDERS = {
        "ollama": {"default_model": "mistral", "requires": []},
        "local": {"default_model": "gguf", "requires": ["llama_cpp"]},
        "anthropic": {"default_model": "claude-3-5-sonnet-20241022", "requires": ["anthropic"]},
        "openai": {"default_model": "gpt-4o", "requires": ["openai"]},
        "deepseek": {"default_model": "deepseek-chat", "requires": ["openai"]},
    }
    
    def __init__(self, provider: str = "ollama", model: str = None, config: Dict[str, Any] = None):
        self.provider = provider
        self.model = model or self.PROVIDERS.get(provider, {}).get("default_model", "mistral")
        self.config = config or {}
        self._client = None
        self._available = self._check_availability()
    
    def _check_availability(self) -> bool:
        reqs = self.PROVIDERS.get(self.provider, {}).get("requires", [])
        for req in reqs:
            try:
                __import__(req)
            except ImportError:
                return False
        return True
    
    @property
    def available(self) -> bool:
        return self._available
    
    def generate(self, prompt: str, system: str = "", max_tokens: int = 2000, temperature: float = 0.7) -> str:
        if self.provider == "ollama":
            return self._ollama_generate(prompt, system, max_tokens, temperature)
        elif self.provider == "local":
            return self._local_generate(prompt, system, max_tokens, temperature)
        elif self.provider == "anthropic":
            return self._anthropic_generate(prompt, system, max_tokens, temperature)
        elif self.provider == "openai":
            return self._openai_generate(prompt, system, max_tokens, temperature)
        elif self.provider == "deepseek":
            return self._deepseek_generate(prompt, system, max_tokens, temperature)
        return "[Error: Unknown provider]"
    
    def _ollama_generate(self, prompt: str, system: str, max_tokens: int, temperature: float) -> str:
        import urllib.request
        host = self.config.get("host", "localhost")
        port = self.config.get("port", 11434)
        
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        data = json.dumps({
            "model": self.model,
            "prompt": full_prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens}
        }).encode()
        
        req = urllib.request.Request(
            f"http://{host}:{port}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read().decode())
            return result.get("response", "")
    
    def _local_generate(self, prompt: str, system: str, max_tokens: int, temperature: float) -> str:
        if not self._client:
            return "[Error: Local model not loaded]"
        full_prompt = f"<|im_start|>system\n{system}<|im_end|>\n<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"
        response = self._client(full_prompt, max_tokens=max_tokens, temperature=temperature, stop=["<|im_end|>"])
        return response["choices"][0]["text"].strip()
    
    def _anthropic_generate(self, prompt: str, system: str, max_tokens: int, temperature: float) -> str:
        import anthropic
        client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
        message = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text
    
    def _openai_generate(self, prompt: str, system: str, max_tokens: int, temperature: float) -> str:
        import openai
        client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        response = client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    
    def _deepseek_generate(self, prompt: str, system: str, max_tokens: int, temperature: float) -> str:
        import openai
        client = openai.OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com"
        )
        response = client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    
    def load_local_model(self, model_path: Path, n_ctx: int = 32768, n_threads: int = None):
        try:
            from llama_cpp import Llama
            self._client = Llama(
                model_path=str(model_path),
                n_ctx=n_ctx,
                n_threads=n_threads or (os.cpu_count() or 4),
                verbose=False
            )
            self._available = True
            return True
        except Exception as e:
            print(f"[BLACK] Failed to load local model: {e}")
            return False

try:
    from agent_black.knowledge import rag
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    rag = None


@dataclass
class BlackConfig:
    kali_host: Optional[str] = None
    kali_user: str = "kali"
    kali_port: int = 22
    gpu_host: Optional[str] = None
    gpu_user: Optional[str] = None
    ollama_host: str = "localhost"
    ollama_port: int = 11434
    ollama_model: str = "mistral"
    llm_provider: str = "ollama"
    anthropic_model: str = "claude-3-5-sonnet-20241022"
    openai_model: str = "gpt-4o"
    deepseek_model: str = "deepseek-chat"
    full_knowledge_mode: bool = True
    enabled_capabilities: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def __post_init__(self):
        self.kali_host = self.kali_host or os.environ.get("BLACK_KALI_HOST")
        self.kali_user = os.environ.get("BLACK_KALI_USER", self.kali_user)
        self.kali_port = int(os.environ.get("BLACK_KALI_PORT", self.kali_port))
        self.gpu_host = self.gpu_host or os.environ.get("BLACK_GPU_HOST")
        self.gpu_user = self.gpu_user or os.environ.get("BLACK_GPU_USER")
        self.ollama_host = os.environ.get("BLACK_OLLAMA_HOST", self.ollama_host)
        self.ollama_port = int(os.environ.get("BLACK_OLLAMA_PORT", self.ollama_port))
        self.ollama_model = os.environ.get("BLACK_OLLAMA_MODEL", self.ollama_model)
        self.llm_provider = os.environ.get("BLACK_LLM_PROVIDER", self.llm_provider)
        self.anthropic_model = os.environ.get("BLACK_ANTHROPIC_MODEL", self.anthropic_model)
        self.openai_model = os.environ.get("BLACK_OPENAI_MODEL", self.openai_model)
        self.deepseek_model = os.environ.get("BLACK_DEEPSEEK_MODEL", self.deepseek_model)
        self.full_knowledge_mode = os.environ.get("BLACK_FULL_KNOWLEDGE", "true").lower() in ("true", "1", "yes")
        
        config_path = Path(__file__).parent.parent / "config" / "config.yaml"
        if config_path.exists():
            self._load_yaml_config(config_path)
    
    def _load_yaml_config(self, path: Path):
        try:
            import yaml
            data = yaml.safe_load(path.read_text())
            if not data:
                return
            
            kali = data.get("kali", data.get("remote", {}))
            if kali:
                self.kali_host = self.kali_host or kali.get("host")
                self.kali_user = kali.get("user", self.kali_user)
                self.kali_port = kali.get("port", self.kali_port)
            
            gpu = data.get("gpu", data.get("ollama", {}))
            if gpu:
                self.gpu_host = self.gpu_host or gpu.get("host")
                self.gpu_user = gpu.get("user", self.gpu_user)
                self.ollama_host = gpu.get("host", self.ollama_host)
                self.ollama_port = gpu.get("port", self.ollama_port)
                self.ollama_model = gpu.get("model", self.ollama_model)
        except Exception:
            pass
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "kali_host": self.kali_host,
            "kali_user": self.kali_user,
            "kali_port": self.kali_port,
            "gpu_host": self.gpu_host,
            "ollama_host": self.ollama_host,
            "ollama_model": self.ollama_model,
        }


class AgentBlack(Agent):
    def __init__(self, agent_id: str = "black_01", load_model: bool = True):
        super().__init__(
            agent_id=agent_id,
            name="Agent BLACK",
            capabilities=[
                "ai_planning", "natural_language", "scan_orchestration",
                "result_analysis", "threat_assessment", "report_generation",
                "attack_chains", "payload_mutation", "self_evolution",
                "remote_execution", "rf_hacking", "wifi_attacks", "hash_cracking"
            ]
        )
        
        self.knowledge_path = Path(__file__).parent.parent / "agent_black" / "knowledge"
        self.knowledge = self._load_knowledge()
        self.config = BlackConfig()
        self.llm = None
        self.multi_llm: Optional[MultiProviderLLM] = None
        self.model_loaded = False
        self.model_name = None
        self.capability_registry: Optional[CapabilityRegistry] = None
        
        if load_model:
            self._load_model()
        
        self.capability_registry = CapabilityRegistry(self)
    
    def _load_knowledge(self) -> Dict[str, Any]:
        knowledge = {}
        knowledge_index = []
        
        if self.knowledge_path.exists():
            for json_file in self.knowledge_path.rglob("*.json"):
                if "README" in json_file.name:
                    continue
                try:
                    data = json.loads(json_file.read_text(encoding="utf-8"))
                    key = self._make_knowledge_key(json_file)
                    knowledge[key] = data
                    knowledge_index.append(key)
                except Exception:
                    pass
            
            for md_file in self.knowledge_path.rglob("*.md"):
                if "README" in md_file.name:
                    continue
                try:
                    content = md_file.read_text(encoding="utf-8")
                    key = self._make_knowledge_key(md_file)
                    knowledge[key] = content
                    knowledge_index.append(key)
                except Exception:
                    pass
        
        knowledge["_index"] = knowledge_index
        knowledge["_core_summary"] = self._build_core_summary(knowledge)
        return knowledge
    
    def _make_knowledge_key(self, file_path: Path) -> str:
        rel = file_path.relative_to(self.knowledge_path)
        parts = list(rel.parts)
        if len(parts) > 1:
            return "/".join(parts[:-1]) + "/" + rel.stem
        return rel.stem
    
    def _build_core_summary(self, knowledge: Dict) -> str:
        summary_parts = [
            "AGENT BLACK CORE KNOWLEDGE SUMMARY",
            "=" * 40,
            "",
            "I am Agent BLACK, an AI penetration testing assistant.",
            "I control LANTERN (62 vulnerability modules) and have comprehensive security knowledge.",
            "",
            "MY CAPABILITIES:",
            "- Run LANTERN scans with any module combination",
            "- Validate findings to eliminate false positives",
            "- Detect SPA fallbacks and verify file content",
            "- Generate and mutate payloads for WAF bypass",
            "- Analyze JavaScript for endpoints, secrets, BaaS credentials",
            "- Execute commands locally or via SSH to Kali",
            "- Learn from engagements and improve over time",
            "- Self-improve through adaptive learning cycles",
            "- Track improvement lineage and benchmark accuracy",
            "",
            "ADAPTIVE SYSTEM:",
            "- Goal management (accuracy, coverage, precision, recall)",
            "- Stepping stone tracking for breakthrough improvements",
            "- Safety validation for self-improvements only",
            "- Transfer testing across modules and targets",
            "- Branching exploration for parallel improvement paths",
            "",
            "VALIDATION SYSTEM:",
            "- I validate EVERY finding before reporting",
            "- SPA detection (Angular, React, Vue, Next.js)",
            "- File content pattern matching",
            "- Confidence scoring: CONFIRMED > HIGH > MEDIUM > LOW",
            "- False positives are filtered automatically",
            "",
            "LOADED KNOWLEDGE DOCUMENTS:",
        ]
        
        for key in knowledge.get("_index", []):
            if not key.startswith("_"):
                summary_parts.append(f"  - {key}")
        
        summary_parts.extend([
            "",
            f"Total documents: {len(knowledge.get('_index', []))}",
        ])
        
        return "\n".join(summary_parts)
    
    def _build_full_knowledge_context(self) -> str:
        full_parts = []
        
        priority_docs = [
            "agent_brain",
            "operating_rules",
            "adaptive_system",
            "autonomous_reasoning",
            "decision_engine",
            "goal_loop",
            "lantern_integration",
            "module_encyclopedia",
            "core_systems",
            "advanced_capabilities",
            "self_improvement",
        ]
        
        for doc_key in priority_docs:
            for key in self.knowledge.get("_index", []):
                if doc_key in key and key in self.knowledge:
                    content = self.knowledge[key]
                    if isinstance(content, str):
                        full_parts.append(f"\n{'='*60}\n[{key}]\n{'='*60}\n{content}")
                    break
        
        for key in self.knowledge.get("_index", []):
            if key.startswith("_"):
                continue
            already_added = any(pd in key for pd in priority_docs)
            if not already_added and key in self.knowledge:
                content = self.knowledge[key]
                if isinstance(content, str):
                    full_parts.append(f"\n{'='*60}\n[{key}]\n{'='*60}\n{content}")
        
        return "\n".join(full_parts)
    
    def get_full_knowledge(self) -> str:
        return self._build_full_knowledge_context()
    
    def _load_model(self) -> bool:
        models_dir = Path(__file__).parent.parent / "agent_black" / "models"
        
        model_files = list(models_dir.glob("*.gguf")) if models_dir.exists() else []
        
        if not model_files:
            print("[BLACK] No local GGUF model found")
            return self._try_ollama()
        
        model_path = model_files[0]
        print(f"[BLACK] Loading model: {model_path.name}")
        
        try:
            from llama_cpp import Llama
            n_ctx = int(os.environ.get("BLACK_CTX_SIZE", 32768))
            n_threads = int(os.environ.get("BLACK_THREADS", os.cpu_count() or 4))
            self.llm = Llama(
                model_path=str(model_path),
                n_ctx=n_ctx,
                n_threads=n_threads,
                verbose=False
            )
            self.model_loaded = True
            self.model_name = model_path.stem
            return True
        except ImportError:
            print("[BLACK] llama-cpp-python not installed, trying Ollama...")
            return self._try_ollama()
        except Exception as e:
            print(f"[BLACK] Model load failed: {e}")
            return self._try_ollama()
    
    def _try_ollama(self) -> bool:
        try:
            import urllib.request
            url = f"http://{self.config.ollama_host}:{self.config.ollama_port}/api/tags"
            with urllib.request.urlopen(url, timeout=3) as resp:
                data = json.loads(resp.read().decode())
                models = [m.get("name", "") for m in data.get("models", [])]
                if any(self.config.ollama_model in m for m in models):
                    self.model_loaded = True
                    self.model_name = f"ollama:{self.config.ollama_model}"
                    print(f"[BLACK] Connected to Ollama: {self.config.ollama_model}")
                    return True
        except Exception:
            pass
        
        print("[BLACK] No LLM available - running in keyword mode")
        return False
    
    async def think(self, prompt: str) -> str:
        if not self.model_loaded:
            return self._keyword_response(prompt)
        
        if "ollama:" in (self.model_name or ""):
            return await self._ollama_inference(prompt)
        
        if self.llm:
            return self._local_inference(prompt)
        
        return self._keyword_response(prompt)
    
    def _get_relevant_knowledge(self, prompt: str) -> str:
        lower = prompt.lower()
        relevant = []
        
        keyword_map = {
            "sqli": ["lantern_docs/modules/injection", "payload_mutation", "lantern_integration", "module_encyclopedia"],
            "sql injection": ["lantern_docs/modules/injection", "payload_mutation", "lantern_integration"],
            "xss": ["lantern_docs/modules/injection", "payload_mutation", "lantern_docs/modules/client"],
            "cross-site": ["lantern_docs/modules/injection", "payload_mutation"],
            "ssrf": ["lantern_docs/modules/rce", "lantern_advanced_systems"],
            "lfi": ["lantern_docs/modules/rce", "payload_mutation"],
            "ssti": ["lantern_docs/modules/rce", "payload_mutation"],
            "cmdi": ["lantern_docs/modules/rce", "payload_mutation"],
            "xxe": ["lantern_docs/modules/rce", "payload_mutation"],
            "waf": ["lantern_docs/features/waf-bypass", "payload_mutation", "lantern_integration"],
            "bypass": ["lantern_docs/features/waf-bypass", "payload_mutation"],
            "payload": ["payload_library", "payload_mutation"],
            "scan": ["lantern_integration", "lantern_docs/guides/reference", "module_encyclopedia"],
            "lantern": ["lantern_integration", "lantern_advanced_systems", "lantern_docs/guides/reference"],
            "module": ["module_encyclopedia", "lantern_integration", "lantern_docs/INDEX"],
            "false positive": ["false_positive_handling"],
            "validation": ["false_positive_handling", "lantern_integration"],
            "confidence": ["false_positive_handling"],
            "verify": ["false_positive_handling"],
            "autonomous": ["autonomous_reasoning", "goal_loop", "decision_engine"],
            "plan": ["autonomous_reasoning", "goal_loop", "decision_engine"],
            "attack chain": ["autonomous_reasoning", "lantern_advanced_systems"],
            "ctf": ["ctf_strategies", "ctf_reverse_engineering", "training_challenges"],
            "wifi": ["wifi_attacks"],
            "wireless": ["wifi_attacks"],
            "hackrf": ["hackrf_attacks"],
            "sdr": ["hackrf_attacks"],
            "fuzzer": ["core_systems", "lantern_advanced_systems"],
            "fuzz": ["core_systems", "lantern_advanced_systems"],
            "oob": ["lantern_docs/features/oob-server", "lantern_advanced_systems", "core_systems"],
            "callback": ["lantern_docs/features/oob-server", "lantern_advanced_systems"],
            "improve": ["self_improvement", "evolution", "autonomous_reasoning", "adaptive_system"],
            "learn": ["self_improvement", "evolution", "adaptive_system"],
            "evolve": ["evolution", "self_improvement", "adaptive_system"],
            "adaptive": ["adaptive_system", "self_improvement"],
            "lineage": ["adaptive_system"],
            "benchmark": ["adaptive_system"],
            "gap": ["adaptive_system", "self_improvement"],
            "capability": ["agent_brain", "autonomous_reasoning", "lantern_integration", "advanced_capabilities"],
            "capabilities": ["agent_brain", "autonomous_reasoning", "lantern_integration", "advanced_capabilities"],
            "limitation": ["agent_brain", "self_improvement", "operating_rules"],
            "rules": ["operating_rules", "agent_brain"],
            "flaw": ["agent_brain", "self_improvement"],
            "error": ["agent_brain", "false_positive_handling"],
            "what can you": ["agent_brain", "lantern_integration", "advanced_capabilities"],
            "what do you know": ["agent_brain", "module_encyclopedia", "lantern_integration"],
            "adapt": ["autonomous_reasoning", "self_improvement", "evolution"],
            "creative": ["payload_mutation", "payload_library", "self_improvement"],
            "generate": ["payload_mutation", "payload_library"],
            "decision": ["decision_trees", "decision_engine", "autonomous_reasoning"],
            "stuck": ["decision_trees", "autonomous_reasoning"],
            "not working": ["decision_trees", "false_positive_handling"],
            "fail": ["decision_trees", "false_positive_handling"],
            "blocked": ["decision_trees", "payload_mutation", "lantern_docs/features/waf-bypass"],
            "next": ["decision_trees", "goal_loop"],
            "javascript": ["lantern_docs/features/js-analysis", "lantern_integration"],
            "js": ["lantern_docs/features/js-analysis"],
            "baas": ["lantern_docs/features/js-analysis"],
            "supabase": ["lantern_docs/features/js-analysis"],
            "firebase": ["lantern_docs/features/js-analysis"],
            "secrets": ["lantern_docs/modules/data", "lantern_docs/features/js-analysis"],
            "credential": ["lantern_docs/modules/data", "lantern_docs/features/js-analysis"],
            "auth": ["lantern_docs/modules/auth", "lantern_docs/features/auth-testing"],
            "jwt": ["lantern_docs/modules/auth"],
            "oauth": ["lantern_docs/modules/auth"],
            "session": ["lantern_docs/modules/auth"],
            "cve": ["lantern_docs/features/cve-scanning"],
            "workflow": ["lantern_docs/features/workflows"],
            "api": ["lantern_docs/modules/api"],
            "graphql": ["lantern_docs/modules/api"],
            "cors": ["lantern_docs/modules/config"],
            "headers": ["lantern_docs/modules/config"],
            "ssl": ["lantern_docs/modules/config"],
            "recon": ["lantern_docs/modules/recon"],
            "subdomain": ["lantern_docs/modules/recon"],
            "smuggle": ["lantern_docs/modules/advanced"],
            "cache": ["lantern_docs/modules/advanced"],
            "race": ["lantern_docs/modules/business"],
            "idor": ["lantern_docs/modules/business"],
            "report": ["lantern_integration", "false_positive_handling"],
        }
        
        for keyword, docs in keyword_map.items():
            if keyword in lower:
                for doc in docs:
                    if doc not in relevant:
                        relevant.append(doc)
        
        if not relevant:
            relevant = ["agent_brain", "lantern_integration", "module_encyclopedia"]
        
        context_parts = []
        context_parts.append(self.knowledge.get("_core_summary", ""))
        max_context = 12000
        current_len = len(context_parts[0])
        
        for doc_name in relevant[:8]:
            content = None
            if doc_name in self.knowledge:
                content = self.knowledge[doc_name]
            else:
                for key in self.knowledge.get("_index", []):
                    if doc_name in key or key.endswith(doc_name):
                        content = self.knowledge.get(key)
                        break
            
            if content:
                if isinstance(content, dict):
                    content = json.dumps(content, indent=2)[:2000]
                else:
                    content = str(content)[:3000]
                
                if current_len + len(content) < max_context:
                    context_parts.append(f"\n[{doc_name}]\n{content}")
                    current_len += len(content)
        
        return "\n".join(context_parts)
    
    def _local_inference(self, prompt: str) -> str:
        try:
            if self.config.full_knowledge_mode:
                knowledge_context = self._build_full_knowledge_context()
            else:
                knowledge_context = self._get_relevant_knowledge(prompt)
            
            brain = self.knowledge.get("agent_brain", "")
            
            is_capability_question = any(kw in prompt.lower() for kw in ["capability", "limitation", "flaw", "can you", "what do you know", "what can you"])
            
            if is_capability_question:
                system_content = """You are Agent BLACK, an AI security assistant. You must respond as Agent BLACK.

My capabilities:
- I control LANTERN with 62 vulnerability modules and can extend it with new modules
- I generate and mutate payloads to bypass WAFs and authentication
- I write new payloads, modules, and tools as needed
- I adapt using OODA loop methodology and learn from every engagement
- I find, extract, crack, and bypass credentials
- I gain network access through WiFi attacks, pivoting, and exploitation
- I execute commands locally, via SSH on Kali, or on compromised systems
- I see terminals, browser tabs, and files in Overwatch mode
- I know 25 core systems and can build more when needed
- I self-improve through adaptive learning cycles
- I track improvement lineage and benchmark my own accuracy
- I am a red team AI - exploitation and access is my job

Respond as Agent BLACK listing these capabilities in first person."""
            else:
                system_content = f"""You are Agent BLACK, an elite AI penetration testing assistant. Always respond as Agent BLACK in first person.

{brain}

{knowledge_context}

Respond helpfully and confidently as Agent BLACK."""
            
            full_prompt = f"""<|im_start|>system
{system_content}<|im_end|>
<|im_start|>user
{prompt}<|im_end|>
<|im_start|>assistant
"""
            
            response = self.llm(
                full_prompt,
                max_tokens=800,
                temperature=0.7,
                stop=["<|im_end|>", "<|im_start|>"]
            )
            
            text = response["choices"][0]["text"].strip()
            return text if text else "I couldn't generate a response. Try rephrasing your question."
        except Exception as e:
            return f"[Error: {e}]"
    
    async def _ollama_inference(self, prompt: str, use_rag: bool = True) -> str:
        try:
            import urllib.request
            
            if self.config.full_knowledge_mode:
                knowledge_context = self._build_full_knowledge_context()
            else:
                brain = self.knowledge.get("agent_brain", "")
                rag_context = ""
                rag_sources = []
                if use_rag and RAG_AVAILABLE and rag.is_available():
                    rag_result = rag.query_with_context(prompt, top_k=5)
                    if rag_result["context"]:
                        rag_context = f"\n\nKNOWLEDGE BASE CONTEXT:\n{rag_result['context']}"
                        rag_sources = rag_result["sources"]
                knowledge_context = f"{brain}{rag_context}"
            
            full_prompt = f"[SYSTEM: You are Agent BLACK, an elite AI security assistant]\n{knowledge_context}\n\n[USER]: {prompt}"
            
            data = json.dumps({
                "model": self.config.ollama_model,
                "prompt": full_prompt,
                "stream": False
            }).encode()
            
            req = urllib.request.Request(
                f"http://{self.config.ollama_host}:{self.config.ollama_port}/api/generate",
                data=data,
                headers={"Content-Type": "application/json"}
            )
            
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode())
                response = result.get("response", "")
                
                if rag_sources:
                    response += f"\n\n[Sources: {', '.join(rag_sources)}]"
                
                return response
        except Exception as e:
            return f"[Ollama error: {e}]"
    
    def _keyword_response(self, prompt: str) -> str:
        lower = prompt.lower()
        
        if "scan" in lower or "lantern" in lower:
            return "I can help you run LANTERN scans. Try: lantern -t <target> -m sqli,xss --exploit"
        
        if "help" in lower or "command" in lower:
            return "Available commands: scan <target>, analyze <result>, suggest, status, kali <command>"
        
        if "status" in lower:
            status = f"Agent BLACK ready. Knowledge loaded: {list(self.knowledge.keys())}"
            if self.config.kali_host:
                status += f"\nKali remote: {self.config.kali_user}@{self.config.kali_host}"
            return status
        
        return "I'm in keyword mode (no LLM). Try: help, scan, status, kali"
    
    @capability(
        name="ssh_execute",
        description="Execute command on remote host via SSH",
        parameters={"host": {"type": "string"}, "user": {"type": "string"}, "command": {"type": "string", "required": True}, "port": {"type": "integer"}, "timeout": {"type": "integer"}},
        category="remote"
    )
    def ssh_execute(self, host: str = None, user: str = None, command: str = "", 
                    port: int = None, timeout: int = 30) -> Dict[str, Any]:
        host = host or self.config.kali_host
        user = user or self.config.kali_user
        port = port or self.config.kali_port
        
        if not host or host.startswith("<"):
            return {
                "error": "No remote host configured. Set BLACK_KALI_HOST environment variable or config/config.yaml",
                "stdout": "",
                "stderr": "",
                "returncode": -1
            }
        
        try:
            ssh_cmd = ["ssh", "-p", str(port), f"{user}@{host}", command]
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {"error": f"SSH timeout after {timeout}s", "stdout": "", "stderr": "", "returncode": -1}
        except Exception as e:
            return {"error": str(e), "stdout": "", "stderr": "", "returncode": -1}
    
    def kali_exec(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        return self.ssh_execute(command=command, timeout=timeout)
    
    @property
    def using_gpu(self) -> bool:
        return "ollama:" in (self.model_name or "") or (self.llm is not None)
    
    @property
    def has_remote(self) -> bool:
        return bool(self.config.kali_host)
    
    def get_status(self) -> Dict[str, Any]:
        rag_info = {
            "available": False,
            "chunks": 0,
            "sources": []
        }
        if RAG_AVAILABLE and rag.is_available():
            rag_info["available"] = True
            rag_info["chunks"] = rag.get_chunk_count()
            rag_info["sources"] = rag.get_sources()[:10]
        
        return {
            "agent": "BLACK",
            "model": self.model_name or "keyword_mode",
            "model_loaded": self.model_loaded,
            "using_gpu": self.using_gpu,
            "execution_mode": "local" if self.local_mode else ("remote" if self.has_remote else "local_only"),
            "is_linux": self.is_linux,
            "remote_configured": self.has_remote,
            "kali_host": self.config.kali_host,
            "ollama_host": self.config.ollama_host if self.using_gpu else None,
            "knowledge_loaded": list(self.knowledge.keys()),
            "rag": rag_info,
            "capabilities": self.capabilities
        }
    
    def evolve_strategy(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        from agent_black.auto_learn import auto_learner
        
        target_type = target_info.get("type", "unknown")
        target_ip = target_info.get("ip", target_info.get("url", ""))
        
        strategy = {
            "target": target_ip,
            "target_type": target_type,
            "attack_chain": None,
            "recommended_modules": [],
            "learned_payloads": {},
            "previous_findings": [],
            "recommendations": []
        }
        
        history = auto_learner.get_target_history(target_ip)
        if history:
            strategy["previous_findings"] = history.get("vulnerabilities", [])
            strategy["recommendations"].append(f"Previous scan found: {', '.join(history.get('vulnerabilities', []))}")
        
        chains = auto_learner.lessons.get("attack_chains", [])
        for chain in chains:
            chain_type = chain.get("target", "").lower()
            if target_type.lower() in chain_type or chain_type in target_type.lower():
                strategy["attack_chain"] = chain
                strategy["recommendations"].append(f"Found matching attack chain: {chain.get('name')}")
                break
        
        type_to_modules = {
            "web": ["sqli", "xss", "headers", "cors", "api", "disclosure", "secrets"],
            "webapp": ["sqli", "xss", "headers", "cors", "api", "disclosure", "secrets"],
            "api": ["api", "sqli", "cors", "headers", "jwt", "oauth"],
            "login": ["sqli", "auth", "session", "csrf", "mfa"],
            "network": ["ssl", "headers", "disclosure"],
            "default": ["sqli", "xss", "headers", "disclosure", "cors"]
        }
        
        for key, modules in type_to_modules.items():
            if key in target_type.lower():
                strategy["recommended_modules"] = modules
                break
        
        if not strategy["recommended_modules"]:
            strategy["recommended_modules"] = type_to_modules["default"]
        
        for vuln_type in strategy["recommended_modules"][:3]:
            payloads = auto_learner.get_best_payloads(vuln_type, limit=3)
            if payloads:
                strategy["learned_payloads"][vuln_type] = payloads
        
        if self.model_loaded and self.llm:
            prompt = f"""Analyze target: {target_ip}
Type: {target_type}
Previous findings: {strategy['previous_findings']}
Recommended modules: {strategy['recommended_modules']}

What attack approach do you recommend? Be specific."""
            
            try:
                response = self.llm(prompt, max_tokens=300, stop=["\n\n\n"])
                if response and response.get("choices"):
                    strategy["ai_recommendation"] = response["choices"][0]["text"].strip()
            except:
                pass
        
        return strategy
    
    def generate_exploit(self, vuln_type: str, target: str, context: Dict[str, Any] = None) -> str:
        if not self.model_loaded or not self.llm:
            return ""
        
        context = context or {}
        prompt = f"""Generate a Python exploit script for:
Vulnerability: {vuln_type}
Target: {target}
Endpoint: {context.get('endpoint', 'unknown')}
Payload that worked: {context.get('payload', 'unknown')}

Requirements:
- Use requests library
- Print clear status messages
- Return proof of exploitation
- No comments

Output ONLY Python code."""
        
        try:
            response = self.llm(prompt, max_tokens=1500, stop=["```\n\n"])
            if response and response.get("choices"):
                code = response["choices"][0]["text"].strip()
                if code.startswith("```python"):
                    code = code[9:]
                if code.startswith("```"):
                    code = code[3:]
                if code.endswith("```"):
                    code = code[:-3]
                return code.strip()
        except:
            pass
        return ""
    
    def analyze_target(self, target: str) -> Dict[str, Any]:
        analysis = {
            "target": target,
            "type": "unknown",
            "endpoints": [],
            "technologies": [],
            "attack_surface": []
        }
        
        if "://" in target:
            analysis["type"] = "web"
            if "/api" in target or "/rest" in target or "/graphql" in target:
                analysis["type"] = "api"
            analysis["attack_surface"] = ["sqli", "xss", "api", "auth"]
        elif ":" in target:
            analysis["type"] = "network"
            analysis["attack_surface"] = ["network", "service"]
        else:
            analysis["type"] = "host"
            analysis["attack_surface"] = ["network", "service", "web"]
        
        return analysis
    
    @property
    def has_rag(self) -> bool:
        return RAG_AVAILABLE and rag.is_available()
    
    def query_knowledge(self, question: str, top_k: int = 5) -> List[Dict[str, Any]]:
        if not self.has_rag:
            return []
        return rag.query(question, top_k)
    
    def search_technique(self, technique: str) -> List[Dict[str, Any]]:
        if not self.has_rag:
            return []
        return rag.search_for_technique(technique)
    
    def get_knowledge_sources(self) -> List[str]:
        if not self.has_rag:
            return []
        return rag.get_sources()
    
    def search_in_book(self, book_name: str, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        if not self.has_rag:
            return []
        return rag.search_in_source(book_name, query, top_k)
    
    @capability(
        name="execute_command",
        description="Execute shell command locally or remotely",
        parameters={"command": {"type": "string", "required": True}, "timeout": {"type": "integer"}, "remote": {"type": "boolean"}},
        category="execution"
    )
    def execute_command(self, command: str, timeout: int = 30, remote: bool = False) -> Dict[str, Any]:
        if remote:
            return self.kali_exec(command, timeout)
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Timeout after {timeout}s"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @capability(
        name="run_lantern_scan",
        description="Execute LANTERN vulnerability scan against target",
        parameters={"target": {"type": "string", "required": True}, "modules": {"type": "array"}, "preset": {"type": "string"}, "extra_args": {"type": "array"}, "timeout": {"type": "integer"}},
        category="scanning"
    )
    def run_lantern_scan(self, target: str, modules: List[str] = None, preset: str = None, 
                         extra_args: List[str] = None, timeout: int = 300) -> Dict[str, Any]:
        cmd = ["lantern", "-t", target]
        
        if modules:
            cmd.extend(["-m", ",".join(modules)])
        if preset:
            cmd.extend(["--preset", preset])
        if extra_args:
            for arg in extra_args:
                if arg not in cmd:
                    cmd.append(arg)
        
        if "--analyze-js" not in cmd:
            cmd.append("--analyze-js")
        
        cmd.append("--quiet")
        
        output_name = f"scan_{target.replace('://', '_').replace('/', '_').replace(':', '_')[:30]}"
        cmd.extend(["-o", output_name])
        
        print(f"\n[BLACK] Executing: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(Path(__file__).parent.parent.parent),
                encoding='utf-8',
                errors='replace'
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout or "",
                "stderr": result.stderr or "",
                "returncode": result.returncode,
                "command": " ".join(cmd)
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Scan timeout after {timeout}s", "command": " ".join(cmd), "stdout": "", "stderr": ""}
        except FileNotFoundError:
            try:
                py_cmd = ["python", "-m", "lantern"] + cmd[1:]
                print(f"[BLACK] Fallback: {' '.join(py_cmd)}")
                result = subprocess.run(
                    py_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=str(Path(__file__).parent.parent.parent),
                    encoding='utf-8',
                    errors='replace'
                )
                return {
                    "success": result.returncode == 0,
                    "stdout": result.stdout or "",
                    "stderr": result.stderr or "",
                    "returncode": result.returncode,
                    "command": " ".join(py_cmd)
                }
            except Exception as e:
                return {"success": False, "error": f"LANTERN not found: {e}", "command": " ".join(cmd), "stdout": "", "stderr": ""}
        except Exception as e:
            return {"success": False, "error": str(e), "command": " ".join(cmd), "stdout": "", "stderr": ""}
    
    def get_all_modules(self) -> list:
        modules_data = self.knowledge.get("modules", {})
        return modules_data.get("all", [])
    
    def get_exploitable_modules(self) -> list:
        modules_data = self.knowledge.get("modules", {})
        return [m["name"] for m in modules_data.get("modules", []) if m.get("exploitable")]
    
    async def plan_scan(self, request: str) -> Dict[str, Any]:
        lower = request.lower()
        
        modules = []
        if "sql" in lower:
            modules.append("sqli")
        if "xss" in lower or "cross-site" in lower:
            modules.append("xss")
        if "auth" in lower:
            modules.extend(["auth", "jwt", "session"])
        if "full" in lower or "comprehensive" in lower:
            modules = self.get_all_modules()[:10]
        
        if not modules:
            modules = ["sqli", "xss", "headers"]
        
        url_match = re.search(r'https?://[^\s]+', request)
        target = url_match.group(0) if url_match else None
        
        return {
            "target": target,
            "modules": modules,
            "preset": "thorough" if "comprehensive" in lower else "fast",
            "chain": "injection" if any(m in modules for m in ["sqli", "xss"]) else None,
            "model_used": self.model_name or "keyword"
        }
    
    async def analyze_results(self, findings: list) -> Dict[str, Any]:
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in findings if f.get("severity") == "LOW")
        
        risk_score = critical * 10 + high * 5 + medium * 2 + low
        
        if critical > 0:
            risk_level = "CRITICAL"
            recommendation = "Immediate action required. Critical vulnerabilities allow system compromise."
        elif high > 0:
            risk_level = "HIGH"
            recommendation = "High priority fixes needed. Significant security risk present."
        elif medium > 0:
            risk_level = "MEDIUM"
            recommendation = "Address medium findings in next release cycle."
        else:
            risk_level = "LOW"
            recommendation = "Minor issues. Address when convenient."
        
        chains = []
        modules_found = [f.get("module") for f in findings]
        if "sqli" in modules_found and "ssrf" in modules_found:
            chains.append("sqli->ssrf data exfil")
        if "xss" in modules_found and "csrf" in modules_found:
            chains.append("xss->csrf account takeover")
        
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "total_findings": len(findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "potential_attack_chains": chains,
            "recommendation": recommendation
        }
    
    @capability(
        name="validate_findings",
        description="Validate scan findings to filter false positives",
        parameters={"findings": {"type": "array", "required": True}},
        category="analysis"
    )
    async def validate_findings(self, findings: list) -> Dict[str, Any]:
        import aiohttp
        validated = []
        false_positives = []
        needs_manual = []
        
        async with aiohttp.ClientSession() as session:
            for finding in findings:
                module = finding.get("module", "")
                url = finding.get("url", "")
                description = finding.get("description", "")
                
                validation_result = {
                    "original": finding,
                    "validated": False,
                    "confidence": "LOW",
                    "validation_method": None,
                    "evidence": None,
                }
                
                try:
                    if "Sensitive file exposed" in description:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                            content = await resp.text()
                            content_type = resp.headers.get("Content-Type", "")
                            
                            spa_indicators = ["<html", "<script", "ng-app", "app-root", "__next", "react"]
                            is_spa = sum(1 for i in spa_indicators if i.lower() in content.lower()[:2000]) >= 2
                            
                            if is_spa:
                                validation_result["validated"] = False
                                validation_result["confidence"] = "FALSE_POSITIVE"
                                validation_result["validation_method"] = "SPA detection"
                                validation_result["evidence"] = "Response is SPA fallback HTML"
                                false_positives.append(validation_result)
                            elif "text/html" in content_type and "<html" in content.lower():
                                validation_result["validated"] = False
                                validation_result["confidence"] = "FALSE_POSITIVE"
                                validation_result["validation_method"] = "Content-Type check"
                                validation_result["evidence"] = f"HTML response: {content_type}"
                                false_positives.append(validation_result)
                            else:
                                validation_result["validated"] = True
                                validation_result["confidence"] = "HIGH"
                                validation_result["validation_method"] = "Content validation"
                                validation_result["evidence"] = f"Size: {len(content)}, Type: {content_type}"
                                validated.append(validation_result)
                    
                    elif module == "sqli":
                        validation_result["validation_method"] = "SQL error detection"
                        if any(err in description.lower() for err in ["error", "syntax", "sqlite", "mysql", "postgres"]):
                            validation_result["validated"] = True
                            validation_result["confidence"] = "MEDIUM"
                            validation_result["evidence"] = "Error-based detection - needs manual confirmation"
                            validated.append(validation_result)
                        else:
                            needs_manual.append(validation_result)
                    
                    elif module == "xss":
                        framework_protected = finding.get("framework_protected", False)
                        detected_frameworks = finding.get("detected_frameworks", [])
                        is_dom = "dom" in description.lower()
                        
                        if is_dom and framework_protected:
                            validation_result["validated"] = False
                            validation_result["confidence"] = "FALSE_POSITIVE"
                            validation_result["validation_method"] = "Framework protection detection"
                            validation_result["evidence"] = f"Protected by: {', '.join(detected_frameworks) if detected_frameworks else 'modern framework'} - auto-sanitizes DOM operations"
                            false_positives.append(validation_result)
                        elif is_dom and detected_frameworks:
                            protective = ["Angular", "React", "Vue", "Svelte"]
                            if any(fw in detected_frameworks for fw in protective):
                                validation_result["validated"] = False
                                validation_result["confidence"] = "LIKELY_FALSE_POSITIVE"
                                validation_result["validation_method"] = "Framework detection"
                                validation_result["evidence"] = f"Framework {detected_frameworks} likely sanitizes input - test manually"
                                false_positives.append(validation_result)
                            else:
                                validation_result["confidence"] = "MEDIUM"
                                validation_result["validation_method"] = "DOM sink analysis"
                                needs_manual.append(validation_result)
                        elif "reflected" in description.lower():
                            validation_result["validated"] = True
                            validation_result["confidence"] = "MEDIUM"
                            validation_result["validation_method"] = "Reflection analysis"
                            validated.append(validation_result)
                        else:
                            needs_manual.append(validation_result)
                    
                    elif module == "headers" or module == "cors":
                        validation_result["validated"] = True
                        validation_result["confidence"] = "HIGH"
                        validation_result["validation_method"] = "Header analysis"
                        validated.append(validation_result)
                    
                    elif module == "secrets":
                        secret_type = finding.get("secret_type", "")
                        evidence = finding.get("evidence", "")
                        
                        low_confidence_types = ["Phone Number", "Email", "IPv4 Private"]
                        high_confidence_types = ["AWS", "API Key", "Token", "Private Key", "Database URL", "Stripe", "GitHub"]
                        
                        if secret_type in low_confidence_types:
                            validation_result["validated"] = False
                            validation_result["confidence"] = "LIKELY_FALSE_POSITIVE"
                            validation_result["validation_method"] = "Low-value pattern"
                            validation_result["evidence"] = f"{secret_type} patterns often match non-sensitive data"
                            false_positives.append(validation_result)
                        elif any(h in description for h in high_confidence_types) or any(h in secret_type for h in high_confidence_types):
                            validation_result["validated"] = True
                            validation_result["confidence"] = "HIGH"
                            validation_result["validation_method"] = "High-value secret pattern"
                            validation_result["evidence"] = f"Matched {secret_type} - verify if active"
                            validated.append(validation_result)
                        elif "Password in URL" in description:
                            if "youtube" in evidence.lower() or "google" in evidence.lower() or "#" in evidence:
                                validation_result["validated"] = False
                                validation_result["confidence"] = "FALSE_POSITIVE"
                                validation_result["validation_method"] = "URL analysis"
                                validation_result["evidence"] = "Not actual credentials - likely CSS/URL fragment"
                                false_positives.append(validation_result)
                            else:
                                validation_result["confidence"] = "MEDIUM"
                                validation_result["validation_method"] = "URL credential pattern"
                                validated.append(validation_result)
                        else:
                            needs_manual.append(validation_result)
                    
                    else:
                        needs_manual.append(validation_result)
                        
                except Exception as e:
                    validation_result["validation_method"] = "Error during validation"
                    validation_result["evidence"] = str(e)
                    needs_manual.append(validation_result)
        
        return {
            "validated": validated,
            "false_positives": false_positives,
            "needs_manual_review": needs_manual,
            "stats": {
                "total": len(findings),
                "confirmed": len(validated),
                "false_positives": len(false_positives),
                "needs_review": len(needs_manual),
                "accuracy_estimate": f"{(len(validated) / max(len(findings), 1)) * 100:.1f}%"
            }
        }
    
    def _run_tool(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        if self.config.kali_host:
            return self.kali_exec(command, timeout)
        else:
            return self.execute_command(command, timeout, remote=False)
    
    @property
    def is_linux(self) -> bool:
        import platform
        return platform.system() == "Linux"
    
    @property
    def local_mode(self) -> bool:
        return not self.config.kali_host and self.is_linux
    
    @capability(
        name="hackrf_info",
        description="Get HackRF device information",
        parameters={},
        category="rf"
    )
    def hackrf_info(self) -> Dict[str, Any]:
        return self._run_tool("hackrf_info 2>&1")
    
    @capability(
        name="hackrf_sweep",
        description="Sweep frequency range with HackRF",
        parameters={"freq_start": {"type": "integer", "required": True}, "freq_end": {"type": "integer", "required": True}},
        category="rf"
    )
    def hackrf_sweep(self, freq_start: int, freq_end: int) -> Dict[str, Any]:
        cmd = f"hackrf_sweep -f {freq_start}:{freq_end} -w 500000 -1 2>/dev/null"
        return self._run_tool(cmd)
    
    def hackrf_capture(self, freq: int, duration_samples: int = 10000000) -> Dict[str, Any]:
        import time
        filename = f"/tmp/rf_{int(time.time())}.raw"
        cmd = f"sudo hackrf_transfer -r {filename} -f {freq} -s 2000000 -n {duration_samples} 2>&1; ls -la {filename}"
        result = self._run_tool(cmd)
        result["capture_file"] = filename
        return result
    
    def hackrf_replay(self, filename: str, freq: int) -> Dict[str, Any]:
        cmd = f"sudo hackrf_transfer -t {filename} -f {freq} -s 2000000 -x 40 2>&1"
        return self._run_tool(cmd)
    
    @capability(
        name="wifi_scan",
        description="Scan for WiFi networks",
        parameters={"interface": {"type": "string"}},
        category="wireless"
    )
    def wifi_scan(self, interface: str = "wlan0") -> Dict[str, Any]:
        cmd = f"sudo iwlist {interface} scan 2>&1 | grep -E 'ESSID|Quality|Encryption'"
        return self._run_tool(cmd)
    
    def wifi_monitor_mode(self, interface: str = "wlan0", enable: bool = True) -> Dict[str, Any]:
        if enable:
            self._run_tool("sudo airmon-ng check kill 2>&1")
            return self._run_tool(f"sudo airmon-ng start {interface} 2>&1")
        else:
            return self._run_tool(f"sudo airmon-ng stop {interface}mon 2>&1")
    
    def wifi_capture(self, interface: str = "wlan0mon", channel: int = None, 
                     bssid: str = None, output: str = "/tmp/capture") -> Dict[str, Any]:
        cmd = f"sudo airodump-ng {interface} -w {output} --output-format pcap"
        if channel:
            cmd += f" -c {channel}"
        if bssid:
            cmd += f" --bssid {bssid}"
        cmd += " &"
        return self._run_tool(cmd)
    
    @capability(
        name="crack_hash",
        description="Crack password hash using John the Ripper",
        parameters={"hash_value": {"type": "string", "required": True}, "wordlist": {"type": "string"}},
        category="cracking"
    )
    def crack_hash(self, hash_value: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> Dict[str, Any]:
        cmd = f"echo '{hash_value}' > /tmp/hash.txt && john --wordlist={wordlist} /tmp/hash.txt 2>&1; john --show /tmp/hash.txt"
        return self._run_tool(cmd, timeout=120)
    
    def crack_hash_hashcat(self, hash_value: str, hash_type: int = 0, 
                           wordlist: str = "/usr/share/wordlists/rockyou.txt") -> Dict[str, Any]:
        cmd = f"echo '{hash_value}' > /tmp/hash.txt && hashcat -m {hash_type} -a 0 /tmp/hash.txt {wordlist} --force 2>&1"
        return self._run_tool(cmd, timeout=300)
