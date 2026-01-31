"""
Auto-Learning System for Agent BLACK

Automatically records successful patterns after scans:
- Which payloads worked
- Which modules found vulnerabilities
- Target characteristics
- Attack chains that succeeded
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


class AutoLearner:
    def __init__(self):
        self.knowledge_path = Path(__file__).parent / "knowledge"
        self.lessons_file = self.knowledge_path / "lessons_learned.json"
        self.learned_payloads_file = self.knowledge_path / "learned_payloads.json"
        
        self.lessons = self._load_json(self.lessons_file) or {
            "lessons": [],
            "attack_chains": [],
            "failed_attempts": [],
            "successful_payloads": {},
            "target_profiles": {}
        }
        
        self.learned_payloads = self._load_json(self.learned_payloads_file) or {
            "sqli": [],
            "xss": [],
            "ssrf": [],
            "lfi": [],
            "ssti": [],
            "cmdi": [],
            "other": []
        }
    
    def _load_json(self, path: Path) -> Optional[Dict]:
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        except:
            pass
        return None
    
    def _save_json(self, path: Path, data: Dict):
        try:
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"[AutoLearn] Failed to save: {e}")
    
    def record_successful_payload(self, vuln_type: str, payload: str, target: str, context: str = ""):
        category = vuln_type.lower()
        if category not in self.learned_payloads:
            category = "other"
        
        entry = {
            "payload": payload,
            "target": target,
            "context": context,
            "timestamp": datetime.now().isoformat(),
            "success_count": 1
        }
        
        for existing in self.learned_payloads[category]:
            if existing["payload"] == payload:
                existing["success_count"] = existing.get("success_count", 1) + 1
                existing["last_success"] = datetime.now().isoformat()
                self._save_json(self.learned_payloads_file, self.learned_payloads)
                return
        
        self.learned_payloads[category].append(entry)
        self._save_json(self.learned_payloads_file, self.learned_payloads)
        print(f"[AutoLearn] New {category} payload recorded")
    
    def record_attack_chain(self, name: str, steps: List[str], target: str, outcome: str):
        chain = {
            "name": name,
            "steps": steps,
            "target": target,
            "outcome": outcome,
            "timestamp": datetime.now().isoformat()
        }
        
        self.lessons["attack_chains"].append(chain)
        self._save_json(self.lessons_file, self.lessons)
        print(f"[AutoLearn] Attack chain '{name}' recorded")
    
    def record_target_profile(self, target: str, tech_stack: List[str], 
                              vulnerabilities: List[str], notes: str = ""):
        profile = {
            "tech_stack": tech_stack,
            "vulnerabilities": vulnerabilities,
            "notes": notes,
            "last_scan": datetime.now().isoformat()
        }
        
        self.lessons["target_profiles"][target] = profile
        self._save_json(self.lessons_file, self.lessons)
        print(f"[AutoLearn] Target profile for '{target}' recorded")
    
    def record_failure(self, technique: str, target: str, reason: str):
        failure = {
            "technique": technique,
            "target": target,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        }
        
        self.lessons["failed_attempts"].append(failure)
        self._save_json(self.lessons_file, self.lessons)
    
    def record_lesson(self, lesson: str, target: str, techniques: List[str]):
        entry = {
            "lesson": lesson,
            "target": target,
            "techniques": techniques,
            "timestamp": datetime.now().isoformat()
        }
        
        self.lessons["lessons"].append(entry)
        self._save_json(self.lessons_file, self.lessons)
        print(f"[AutoLearn] Lesson recorded: {lesson[:50]}...")
    
    def get_best_payloads(self, vuln_type: str, limit: int = 5) -> List[str]:
        category = vuln_type.lower()
        if category not in self.learned_payloads:
            return []
        
        sorted_payloads = sorted(
            self.learned_payloads[category],
            key=lambda x: x.get("success_count", 1),
            reverse=True
        )
        
        return [p["payload"] for p in sorted_payloads[:limit]]
    
    def get_target_history(self, target: str) -> Optional[Dict]:
        return self.lessons["target_profiles"].get(target)
    
    def should_skip_technique(self, technique: str, target: str) -> bool:
        for failure in self.lessons["failed_attempts"]:
            if failure["technique"] == technique and failure["target"] == target:
                return True
        return False
    
    def process_scan_results(self, results: Dict, target: str):
        if not results:
            return
        
        findings = results.get("findings", [])
        tech_stack = []
        vulnerabilities = []
        
        for finding in findings:
            vuln_type = finding.get("type", finding.get("module", "unknown"))
            confidence = finding.get("confidence", "LOW")
            payload = finding.get("payload", "")
            
            if confidence in ["CONFIRMED", "HIGH"]:
                vulnerabilities.append(vuln_type)
                
                if payload:
                    self.record_successful_payload(
                        vuln_type=vuln_type,
                        payload=payload,
                        target=target,
                        context=finding.get("endpoint", "")
                    )
        
        if vulnerabilities:
            self.record_target_profile(
                target=target,
                tech_stack=tech_stack,
                vulnerabilities=list(set(vulnerabilities))
            )
            
            self.record_lesson(
                lesson=f"Found {len(vulnerabilities)} vulnerabilities on {target}",
                target=target,
                techniques=list(set(vulnerabilities))
            )


auto_learner = AutoLearner()
