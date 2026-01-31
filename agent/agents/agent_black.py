import os
import re
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
 
from .base import Agent

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
    
    def __post_init__(self):
        self.kali_host = self.kali_host or os.environ.get("BLACK_KALI_HOST")
        self.kali_user = os.environ.get("BLACK_KALI_USER", self.kali_user)
        self.kali_port = int(os.environ.get("BLACK_KALI_PORT", self.kali_port))
        self.gpu_host = self.gpu_host or os.environ.get("BLACK_GPU_HOST")
        self.gpu_user = self.gpu_user or os.environ.get("BLACK_GPU_USER")
        self.ollama_host = os.environ.get("BLACK_OLLAMA_HOST", self.ollama_host)
        self.ollama_port = int(os.environ.get("BLACK_OLLAMA_PORT", self.ollama_port))
        self.ollama_model = os.environ.get("BLACK_OLLAMA_MODEL", self.ollama_model)
        
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
        self.model_loaded = False
        self.model_name = None
        
        if load_model:
            self._load_model()
    
    def _load_knowledge(self) -> Dict[str, Any]:
        knowledge = {}
        if self.knowledge_path.exists():
            for json_file in self.knowledge_path.glob("*.json"):
                try:
                    data = json.loads(json_file.read_text(encoding="utf-8"))
                    knowledge[json_file.stem] = data
                except Exception:
                    pass
            for md_file in self.knowledge_path.glob("*.md"):
                try:
                    knowledge[md_file.stem] = md_file.read_text(encoding="utf-8")
                except Exception:
                    pass
        return knowledge
    
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
            "sqli": ["module_encyclopedia", "payload_mutation", "lantern_integration"],
            "sql injection": ["module_encyclopedia", "payload_mutation", "lantern_integration"],
            "xss": ["module_encyclopedia", "payload_mutation", "dom"],
            "cross-site": ["module_encyclopedia", "payload_mutation"],
            "ssrf": ["module_encyclopedia", "lantern_advanced_systems"],
            "lfi": ["module_encyclopedia", "payload_mutation"],
            "ssti": ["module_encyclopedia", "payload_mutation"],
            "waf": ["payload_mutation", "lantern_integration"],
            "bypass": ["payload_mutation", "lantern_integration"],
            "payload": ["payload_library", "payload_mutation"],
            "scan": ["lantern_integration", "module_encyclopedia"],
            "lantern": ["lantern_integration", "lantern_advanced_systems", "module_encyclopedia"],
            "module": ["module_encyclopedia", "lantern_integration"],
            "false positive": ["false_positive_handling"],
            "confidence": ["false_positive_handling"],
            "autonomous": ["autonomous_reasoning", "goal_loop"],
            "plan": ["autonomous_reasoning", "goal_loop", "decision_engine"],
            "attack chain": ["chains", "autonomous_reasoning"],
            "ctf": ["ctf_strategies", "ctf_reverse_engineering"],
            "wifi": ["wifi_attacks"],
            "wireless": ["wifi_attacks"],
            "hackrf": ["hackrf_attacks"],
            "sdr": ["hackrf_attacks"],
            "fuzzer": ["core_systems", "lantern_advanced_systems"],
            "oob": ["lantern_advanced_systems", "core_systems"],
            "callback": ["lantern_advanced_systems"],
            "improve": ["self_improvement", "autonomous_reasoning"],
            "learn": ["self_improvement", "lessons_learned"],
            "capability": ["agent_brain", "autonomous_reasoning", "self_improvement", "lantern_integration"],
            "capabilities": ["agent_brain", "autonomous_reasoning", "self_improvement", "lantern_integration"],
            "limitation": ["agent_brain", "self_improvement", "autonomous_reasoning"],
            "flaw": ["agent_brain", "self_improvement", "autonomous_reasoning"],
            "error": ["agent_brain", "self_improvement"],
            "what can you": ["agent_brain", "lantern_integration", "autonomous_reasoning"],
            "what do you know": ["agent_brain", "module_encyclopedia", "lantern_integration"],
            "adapt": ["autonomous_reasoning", "self_improvement", "goal_loop"],
            "creative": ["payload_mutation", "payload_library", "self_improvement"],
            "generate": ["payload_mutation", "payload_library"],
            "real-time": ["lessons_learned", "self_improvement"],
            "update": ["self_improvement", "payload_library"],
            "decision": ["decision_trees", "autonomous_reasoning"],
            "stuck": ["decision_trees", "autonomous_reasoning"],
            "not working": ["decision_trees", "false_positive_handling"],
            "fail": ["decision_trees", "lessons_learned"],
            "blocked": ["decision_trees", "payload_mutation"],
            "next": ["decision_trees", "goal_loop"],
        }
        
        for keyword, docs in keyword_map.items():
            if keyword in lower:
                for doc in docs:
                    if doc not in relevant:
                        relevant.append(doc)
        
        context_parts = []
        max_context = 4000
        current_len = 0
        
        for doc_name in relevant[:5]:
            if doc_name in self.knowledge:
                content = self.knowledge[doc_name]
                if isinstance(content, dict):
                    content = json.dumps(content, indent=2)[:1000]
                else:
                    content = str(content)[:1200]
                
                if current_len + len(content) < max_context:
                    context_parts.append(f"[{doc_name}]\n{content}")
                    current_len += len(content)
        
        return "\n\n".join(context_parts)
    
    def _local_inference(self, prompt: str) -> str:
        try:
            brain = self.knowledge.get("agent_brain", "")
            relevant_knowledge = self._get_relevant_knowledge(prompt)
            
            is_capability_question = any(kw in prompt.lower() for kw in ["capability", "limitation", "flaw", "can you", "what do you know", "what can you"])
            
            if is_capability_question:
                system_content = """You are Agent BLACK, an AI security assistant. You must respond as Agent BLACK.

My capabilities:
- I control LANTERN with 62 vulnerability modules (sqli, xss, ssrf, lfi, ssti, cmdi, xxe, jwt, oauth, idor, etc)
- I generate and mutate payloads to bypass WAFs
- I write new payloads to the payloads/ directory
- I adapt using OODA loop methodology
- I learn from each engagement via lessons_learned.json
- I improve myself by analyzing gaps and suggesting patches
- I execute commands locally and via SSH on Kali
- I see terminals, browser tabs, and files in Overwatch mode
- I know 25 core systems including fuzzer, differ, OOB callbacks
- I have 21 knowledge docs and real attack chain experience

My actual limitations:
- I need network access to scan remote targets
- I cannot access systems without credentials
- I rely on LANTERN for scanning capabilities

Respond as Agent BLACK listing these capabilities in first person."""
            else:
                system_content = f"""You are Agent BLACK, an elite AI penetration testing assistant. Always respond as Agent BLACK in first person.

{brain[:3000]}

{relevant_knowledge}

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
            brain = self.knowledge.get("agent_brain", "")[:1000]
            
            rag_context = ""
            rag_sources = []
            if use_rag and RAG_AVAILABLE and rag.is_available():
                rag_result = rag.query_with_context(prompt, top_k=5)
                if rag_result["context"]:
                    rag_context = f"\n\nKNOWLEDGE BASE CONTEXT:\n{rag_result['context'][:3000]}"
                    rag_sources = rag_result["sources"]
            
            full_prompt = f"[SYSTEM: You are Agent BLACK, an elite AI security assistant]\n{brain}{rag_context}\n\n[USER]: {prompt}"
            
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
    
    def hackrf_info(self) -> Dict[str, Any]:
        return self._run_tool("hackrf_info 2>&1")
    
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
    
    def crack_hash(self, hash_value: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> Dict[str, Any]:
        cmd = f"echo '{hash_value}' > /tmp/hash.txt && john --wordlist={wordlist} /tmp/hash.txt 2>&1; john --show /tmp/hash.txt"
        return self._run_tool(cmd, timeout=120)
    
    def crack_hash_hashcat(self, hash_value: str, hash_type: int = 0, 
                           wordlist: str = "/usr/share/wordlists/rockyou.txt") -> Dict[str, Any]:
        cmd = f"echo '{hash_value}' > /tmp/hash.txt && hashcat -m {hash_type} -a 0 /tmp/hash.txt {wordlist} --force 2>&1"
        return self._run_tool(cmd, timeout=300)
