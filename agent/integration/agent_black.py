#!/usr/bin/env python3
"""
Agent BLACK Integration Module

High-level interface combining all Agent BLACK capabilities:
- Natural language security scanning
- Learning from past scans
- Smart probing beyond Lantern's capabilities
- Self-improvement and patch generation
- CTF toolkit and utilities
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.agent_black import AgentBlack, BlackConfig

from agent_black import learning
from agent_black.learning import (
    record_scan_result,
    get_target_profile,
    get_recommended_modules,
    get_prioritized_payloads,
    get_scan_variation,
    get_learning_summary,
    should_try_new_approach,
    get_unexplored_modules,
    record_successful_payload,
)

from agent_black import improvement_applier
from agent_black.improvement_applier import (
    load_all_improvements,
    consolidate_improvements,
    generate_lantern_patch,
    save_patches,
    apply_improvements_to_lantern,
    generate_improvement_report,
    verify_patches_applied,
    print_verification_report,
)

from agent_black.smart_probe import SmartProbe, run_smart_probe, print_probe_summary

from agent_black import ctf_utils
from agent_black.ctf_utils import (
    FLAG_PATTERNS,
    search_flags,
    auto_decode,
    identify_hash,
    crack_hash_wordlist,
    quick_solve,
    analyze_binary_file,
    analyze_js_source,
    analyze_html_source,
)

try:
    from llama_cpp import Llama
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False
    Llama = None


class IntegratedAgentBlack(AgentBlack):
    def __init__(
        self,
        agent_id: str = "black_integrated",
        load_model: bool = True,
        auto_learn: bool = True,
        smart_probe: bool = False,
    ):
        super().__init__(agent_id=agent_id, load_model=load_model)
        
        self.auto_learn = auto_learn
        self.smart_probe_enabled = smart_probe
        self.session_findings: List[Dict[str, Any]] = []
        self.session_flags: List[str] = []
        self.current_target: Optional[str] = None
    
    def scan_target(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        use_learning: bool = True,
        deep_probe: bool = False,
    ) -> Dict[str, Any]:
        self.current_target = target
        
        result = {
            "target": target,
            "modules_requested": modules,
            "modules_used": [],
            "findings": [],
            "flags": [],
            "recommendations": [],
            "improvements_suggested": 0,
        }
        
        if use_learning:
            profile = get_target_profile(target)
            if profile:
                result["target_profile"] = {
                    "scan_count": profile.get("scan_count", 0),
                    "known_vulns": profile.get("vulnerable_modules", []),
                    "tech_stack": profile.get("tech_stack", []),
                    "flags_captured": len(profile.get("flags_captured", [])),
                }
                
                if modules is None:
                    modules = get_recommended_modules(target, [
                        "sqli", "xss", "lfi", "ssti", "ssrf", "cmdi"
                    ])
                    result["modules_used"] = modules[:10]
        
        if modules is None:
            modules = ["sqli", "xss", "lfi", "ssti", "ssrf"]
        
        result["modules_used"] = modules
        
        if deep_probe or self.smart_probe_enabled:
            probe = SmartProbe(target)
            probe_results = probe.probe_all()
            
            result["smart_probe"] = {
                "findings": probe_results.get("total_findings", 0),
                "flags": probe_results.get("flags_found", []),
                "improvements": len(probe_results.get("improvement_suggestions", [])),
            }
            
            result["flags"].extend(probe_results.get("flags_found", []))
            result["improvements_suggested"] = len(probe_results.get("improvement_suggestions", []))
            
            self.session_flags.extend(probe_results.get("flags_found", []))
        
        return result
    
    def record_findings(
        self,
        target: str,
        modules_used: List[str],
        findings: Dict[str, int],
        flags_found: List[str],
        successful_exploits: List[Dict[str, Any]],
        tech_detected: List[str],
    ) -> None:
        if self.auto_learn:
            record_scan_result(
                target=target,
                modules_used=modules_used,
                findings=findings,
                flags_found=flags_found,
                successful_exploits=successful_exploits,
                tech_detected=tech_detected,
            )
    
    def get_smart_modules(self, target: str) -> List[str]:
        return get_recommended_modules(target, [
            "sqli", "xss", "lfi", "ssti", "ssrf", "cmdi",
            "xxe", "graphql", "jwt", "idor", "auth"
        ])
    
    def get_variation(self, target: str, base_modules: List[str]) -> tuple:
        return get_scan_variation(target, base_modules)
    
    def should_vary_approach(self, target: str) -> bool:
        return should_try_new_approach(target)
    
    def get_unexplored(self, target: str) -> List[str]:
        all_modules = [
            "sqli", "xss", "lfi", "ssti", "ssrf", "cmdi", "xxe",
            "graphql", "jwt", "idor", "auth", "cors", "csrf",
            "deserial", "prototype", "race", "cachepois", "smuggle"
        ]
        return get_unexplored_modules(target, all_modules)
    
    def run_smart_probe(self, target: str) -> Dict[str, Any]:
        probe = SmartProbe(target)
        return probe.probe_all()
    
    def get_improvements(self) -> str:
        return generate_improvement_report()
    
    def apply_improvements(self, lantern_path: Optional[Path] = None) -> str:
        from agent_black.improvement_applier import apply_improvements_to_lantern as apply_imp
        return apply_imp(lantern_path)
    
    def verify_improvements(self, lantern_path: Optional[Path] = None) -> Dict[str, Any]:
        return verify_patches_applied(lantern_path)
    
    def ctf_decode(self, data: str) -> List[Dict[str, Any]]:
        return auto_decode(data)
    
    def ctf_search_flags(self, text: str) -> List[str]:
        return search_flags(text)
    
    def ctf_identify_hash(self, hash_str: str) -> List[str]:
        return identify_hash(hash_str)
    
    def ctf_crack_hash(self, hash_str: str, wordlist: Optional[List[str]] = None) -> Optional[str]:
        return crack_hash_wordlist(hash_str, wordlist)
    
    def ctf_quick_solve(self, data: str) -> Dict[str, Any]:
        return quick_solve(data)
    
    def ctf_analyze_binary(self, file_path: str) -> Dict[str, Any]:
        return analyze_binary_file(file_path)
    
    def ctf_analyze_js(self, code: str) -> Dict[str, Any]:
        return analyze_js_source(code)
    
    def ctf_analyze_html(self, html: str) -> Dict[str, Any]:
        return analyze_html_source(html)
    
    def get_learning_summary(self) -> str:
        return get_learning_summary()
    
    def get_session_summary(self) -> Dict[str, Any]:
        base_status = self.get_status()
        
        return {
            **base_status,
            "session": {
                "current_target": self.current_target,
                "findings_count": len(self.session_findings),
                "flags_found": list(set(self.session_flags)),
                "auto_learn": self.auto_learn,
                "smart_probe": self.smart_probe_enabled,
            }
        }
    
    def interactive_chat(self, user_input: str) -> str:
        import asyncio
        
        lower = user_input.lower().strip()
        
        if lower in ["status", "info", "?"]:
            summary = self.get_session_summary()
            lines = [
                "=== Agent BLACK Status ===",
                f"Model: {summary['model']}",
                f"Model Loaded: {summary['model_loaded']}",
                f"Execution Mode: {summary['execution_mode']}",
                f"Remote Configured: {summary['remote_configured']}",
            ]
            if summary.get("rag", {}).get("available"):
                lines.append(f"Knowledge Base: {summary['rag']['chunks']} chunks")
            lines.append(f"Session Flags: {len(summary['session']['flags_found'])}")
            return "\n".join(lines)
        
        elif lower.startswith("learn"):
            return self.get_learning_summary()
        
        elif lower.startswith("improve"):
            return self.get_improvements()
        
        elif lower.startswith("decode "):
            data = user_input[7:].strip()
            results = self.ctf_decode(data)
            if results:
                output = ["=== Decode Results ==="]
                for r in results:
                    output.append(f"Chain: {' -> '.join(s['encoding'] for s in r['chain'])}")
                    output.append(f"Result: {r['final'][:200]}")
                    if r.get("flags_found"):
                        output.append(f"FLAGS: {r['flags_found']}")
                return "\n".join(output)
            return "Could not decode data"
        
        elif lower.startswith("hash "):
            hash_str = user_input[5:].strip()
            types = self.ctf_identify_hash(hash_str)
            cracked = self.ctf_crack_hash(hash_str)
            output = [f"Hash Types: {', '.join(types) if types else 'Unknown'}"]
            if cracked:
                output.append(f"CRACKED: {cracked}")
            return "\n".join(output)
        
        elif lower.startswith("probe "):
            target = user_input[6:].strip()
            results = self.run_smart_probe(target)
            print_probe_summary(results)
            return f"Probe complete. Found {results['total_findings']} issues, {len(results['flags_found'])} flags."
        
        elif lower.startswith("scan ") or lower.startswith("test "):
            return asyncio.get_event_loop().run_until_complete(
                self.process_natural_language(user_input)
            )
        
        else:
            return asyncio.get_event_loop().run_until_complete(
                self.process_natural_language(user_input)
            )


__all__ = [
    "AgentBlack",
    "BlackConfig",
    "IntegratedAgentBlack",
    "SmartProbe",
    "run_smart_probe",
    "print_probe_summary",
    "record_scan_result",
    "get_target_profile",
    "get_recommended_modules",
    "get_learning_summary",
    "generate_improvement_report",
    "apply_improvements_to_lantern",
    "verify_patches_applied",
    "search_flags",
    "auto_decode",
    "quick_solve",
    "FLAG_PATTERNS",
]


if __name__ == "__main__":
    print("Agent BLACK Integration Module")
    print("=" * 40)
    
    agent = IntegratedAgentBlack(load_model=False)
    print(f"\nAgent Status:")
    status = agent.get_session_summary()
    for key, value in status.items():
        if key != "capabilities":
            print(f"  {key}: {value}")
    
    print(f"\nLearning Summary:")
    print(agent.get_learning_summary())
