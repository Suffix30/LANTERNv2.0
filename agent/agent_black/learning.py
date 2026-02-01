import json
import hashlib
import math
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Tuple
from urllib.parse import urlparse


LEARNING_DIR = Path(__file__).parent / "learned"
LEARNING_DIR.mkdir(exist_ok=True)

TARGET_PROFILES_FILE = LEARNING_DIR / "target_profiles.json"
SUCCESSFUL_PAYLOADS_FILE = LEARNING_DIR / "successful_payloads.json"
SCAN_HISTORY_FILE = LEARNING_DIR / "scan_history.json"
MODULE_EFFECTIVENESS_FILE = LEARNING_DIR / "module_effectiveness.json"
LINEAGE_FILE = LEARNING_DIR / "improvement_lineage.json"
IMPROVEMENT_ARCHIVE_FILE = LEARNING_DIR / "improvement_archive.json"


def get_target_signature(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def get_target_hash(url: str) -> str:
    sig = get_target_signature(url)
    return hashlib.md5(sig.encode()).hexdigest()[:12]


def load_json_file(path: Path) -> dict[str, Any]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except:
            pass
    return {}


def save_json_file(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def record_scan_result(
    target: str,
    modules_used: list[str],
    findings: dict[str, int],
    flags_found: list[str],
    successful_exploits: list[dict[str, Any]],
    tech_detected: list[str],
) -> None:
    target_hash = get_target_hash(target)
    target_sig = get_target_signature(target)
    
    profiles = load_json_file(TARGET_PROFILES_FILE)
    if target_hash not in profiles:
        profiles[target_hash] = {
            "signature": target_sig,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "scan_count": 0,
            "tech_stack": [],
            "vulnerable_modules": [],
            "working_payloads": [],
            "total_findings": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "flags_captured": [],
            "best_modules": [],
        }
    
    profile = profiles[target_hash]
    profile["scan_count"] += 1
    profile["last_scan"] = datetime.now(timezone.utc).isoformat()
    
    for tech in tech_detected:
        if tech not in profile["tech_stack"]:
            profile["tech_stack"].append(tech)
    
    for sev, count in findings.items():
        if count > profile["total_findings"].get(sev, 0):
            profile["total_findings"][sev] = count
    
    for flag in flags_found:
        if flag not in profile["flags_captured"]:
            profile["flags_captured"].append(flag)
    
    for exploit in successful_exploits:
        module = exploit.get("module")
        if module and module not in profile["vulnerable_modules"]:
            profile["vulnerable_modules"].append(module)
        payload = exploit.get("payload")
        if payload and payload not in profile["working_payloads"]:
            profile["working_payloads"].append(payload)
    
    save_json_file(TARGET_PROFILES_FILE, profiles)
    
    record_module_effectiveness(modules_used, findings, successful_exploits)
    
    history = load_json_file(SCAN_HISTORY_FILE)
    scan_id = f"{target_hash}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    history[scan_id] = {
        "target": target_sig,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "modules": modules_used,
        "findings": findings,
        "flags": flags_found,
        "exploits": len(successful_exploits),
    }
    
    if len(history) > 1000:
        sorted_keys = sorted(history.keys())
        for old_key in sorted_keys[:-1000]:
            del history[old_key]
    
    save_json_file(SCAN_HISTORY_FILE, history)


def record_module_effectiveness(
    modules_used: list[str],
    findings: dict[str, int],
    successful_exploits: list[dict[str, Any]],
) -> None:
    effectiveness = load_json_file(MODULE_EFFECTIVENESS_FILE)
    
    total_score = (
        findings.get("CRITICAL", 0) * 100 +
        findings.get("HIGH", 0) * 50 +
        findings.get("MEDIUM", 0) * 20 +
        findings.get("LOW", 0) * 5 +
        findings.get("INFO", 0) * 1
    )
    
    exploit_modules = {e.get("module") for e in successful_exploits if e.get("module")}
    
    for module in modules_used:
        if module not in effectiveness:
            effectiveness[module] = {
                "times_used": 0,
                "total_score": 0,
                "exploit_success": 0,
                "avg_score": 0,
            }
        
        effectiveness[module]["times_used"] += 1
        effectiveness[module]["total_score"] += total_score / max(len(modules_used), 1)
        
        if module in exploit_modules:
            effectiveness[module]["exploit_success"] += 1
        
        effectiveness[module]["avg_score"] = (
            effectiveness[module]["total_score"] / effectiveness[module]["times_used"]
        )
    
    save_json_file(MODULE_EFFECTIVENESS_FILE, effectiveness)


def record_successful_payload(
    module: str,
    payload: str,
    target_tech: list[str],
    vuln_type: str,
    severity: str,
) -> None:
    payloads = load_json_file(SUCCESSFUL_PAYLOADS_FILE)
    
    payload_hash = hashlib.md5(payload.encode()).hexdigest()[:16]
    
    if payload_hash not in payloads:
        payloads[payload_hash] = {
            "module": module,
            "payload": payload,
            "vuln_type": vuln_type,
            "severity": severity,
            "first_success": datetime.now(timezone.utc).isoformat(),
            "success_count": 0,
            "tech_stacks": [],
        }
    
    payloads[payload_hash]["success_count"] += 1
    payloads[payload_hash]["last_success"] = datetime.now(timezone.utc).isoformat()
    
    for tech in target_tech:
        if tech not in payloads[payload_hash]["tech_stacks"]:
            payloads[payload_hash]["tech_stacks"].append(tech)
    
    save_json_file(SUCCESSFUL_PAYLOADS_FILE, payloads)


def get_target_profile(target: str) -> dict[str, Any] | None:
    target_hash = get_target_hash(target)
    profiles = load_json_file(TARGET_PROFILES_FILE)
    return profiles.get(target_hash)


def get_recommended_modules(target: str, default_modules: list[str]) -> list[str]:
    profile = get_target_profile(target)
    effectiveness = load_json_file(MODULE_EFFECTIVENESS_FILE)
    
    if not profile and not effectiveness:
        return default_modules
    
    scored_modules: dict[str, float] = {}
    
    for module in default_modules:
        scored_modules[module] = 10.0
    
    if profile:
        for module in profile.get("vulnerable_modules", []):
            scored_modules[module] = scored_modules.get(module, 0) + 50
        
        tech_stack = profile.get("tech_stack", [])
        tech_module_map = {
            "flask": ["ssti", "lfi", "cmdi"],
            "django": ["ssti", "csrf", "idor"],
            "express": ["prototype", "xss", "ssrf"],
            "php": ["lfi", "sqli", "upload"],
            "java": ["deserial", "xxe", "sqli"],
            "asp.net": ["sqli", "xss", "upload"],
            "wordpress": ["sqli", "upload", "xss"],
            "graphql": ["graphql", "idor", "auth"],
            "jwt": ["jwt", "auth", "session"],
        }
        
        for tech in tech_stack:
            tech_lower = tech.lower()
            for tech_key, modules in tech_module_map.items():
                if tech_key in tech_lower:
                    for module in modules:
                        scored_modules[module] = scored_modules.get(module, 0) + 20
    
    if effectiveness:
        for module, stats in effectiveness.items():
            avg_score = stats.get("avg_score", 0)
            exploit_rate = (
                stats.get("exploit_success", 0) / max(stats.get("times_used", 1), 1)
            )
            
            bonus = avg_score * 0.1 + exploit_rate * 30
            scored_modules[module] = scored_modules.get(module, 0) + bonus
    
    sorted_modules = sorted(
        scored_modules.items(),
        key=lambda x: x[1],
        reverse=True,
    )
    
    return [m[0] for m in sorted_modules]


def get_prioritized_payloads(module: str, tech_stack: list[str]) -> list[str]:
    payloads = load_json_file(SUCCESSFUL_PAYLOADS_FILE)
    
    matching = []
    for payload_hash, data in payloads.items():
        if data.get("module") != module:
            continue
        
        score = data.get("success_count", 0) * 10
        
        for tech in tech_stack:
            if tech in data.get("tech_stacks", []):
                score += 20
        
        if data.get("severity") == "CRITICAL":
            score += 50
        elif data.get("severity") == "HIGH":
            score += 30
        
        matching.append((data.get("payload"), score))
    
    matching.sort(key=lambda x: x[1], reverse=True)
    return [p[0] for p in matching[:20]]


def get_scan_variation(target: str, base_modules: list[str]) -> tuple[list[str], list[str]]:
    profile = get_target_profile(target)
    scan_count = profile.get("scan_count", 0) if profile else 0
    
    all_injection = ["sqli", "xss", "cmdi", "ssti", "lfi", "xxe", "ssrf"]
    all_recon = ["dirbust", "fingerprint", "techdetect", "secrets", "disclosure"]
    all_auth = ["jwt", "auth", "session", "cookie", "cors", "csrf"]
    all_advanced = ["graphql", "prototype", "deserial", "race", "cachepois", "smuggle"]
    
    variation_sets = [
        base_modules,
        all_injection + ["cookie", "headers"],
        all_recon + all_auth,
        all_injection + all_advanced,
        all_injection + all_recon + all_auth,
    ]
    
    variation_flags = [
        [],
        ["--aggressive"],
        ["--crawl", "--crawl-depth", "3"],
        ["--deep", "--aggressive"],
        ["--exploit", "--aggressive", "--crawl"],
    ]
    
    idx = scan_count % len(variation_sets)
    return variation_sets[idx], variation_flags[idx]


def get_learning_summary() -> str:
    profiles = load_json_file(TARGET_PROFILES_FILE)
    effectiveness = load_json_file(MODULE_EFFECTIVENESS_FILE)
    payloads = load_json_file(SUCCESSFUL_PAYLOADS_FILE)
    history = load_json_file(SCAN_HISTORY_FILE)
    
    lines = [
        "=" * 60,
        "AGENT BLACK LEARNING SUMMARY",
        "=" * 60,
        f"\nTargets Profiled: {len(profiles)}",
        f"Total Scans: {len(history)}",
        f"Successful Payloads: {len(payloads)}",
        f"Modules Tracked: {len(effectiveness)}",
    ]
    
    if effectiveness:
        sorted_eff = sorted(
            effectiveness.items(),
            key=lambda x: x[1].get("avg_score", 0),
            reverse=True,
        )[:10]
        
        lines.append("\nTop Performing Modules:")
        for module, stats in sorted_eff:
            lines.append(f"  {module}: score={stats.get('avg_score', 0):.1f}, exploits={stats.get('exploit_success', 0)}")
    
    if profiles:
        lines.append("\nRecent Targets:")
        sorted_profiles = sorted(
            profiles.items(),
            key=lambda x: x[1].get("last_scan", ""),
            reverse=True,
        )[:5]
        
        for target_hash, profile in sorted_profiles:
            flags = len(profile.get("flags_captured", []))
            vulns = profile.get("vulnerable_modules", [])
            lines.append(f"  {profile.get('signature', 'unknown')}: {flags} flags, vulns in {vulns[:3]}")
    
    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def should_try_new_approach(target: str) -> bool:
    profile = get_target_profile(target)
    if not profile:
        return False
    
    scan_count = profile.get("scan_count", 0)
    flags_found = len(profile.get("flags_captured", []))
    
    return scan_count > 1 and flags_found < 5


def get_unexplored_modules(target: str, all_modules: list[str]) -> list[str]:
    history = load_json_file(SCAN_HISTORY_FILE)
    target_hash = get_target_hash(target)
    
    used_modules: set[str] = set()
    for scan_id, scan_data in history.items():
        if scan_id.startswith(target_hash):
            used_modules.update(scan_data.get("modules", []))
    
    return [m for m in all_modules if m not in used_modules]


class ImprovementLineage:
    def __init__(self):
        self.lineage_file = LINEAGE_FILE
        self.archive_file = IMPROVEMENT_ARCHIVE_FILE
        self._lineage = self._load_lineage()
        self._archive = self._load_archive()
    
    def _load_lineage(self) -> dict[str, Any]:
        if self.lineage_file.exists():
            try:
                return json.loads(self.lineage_file.read_text(encoding="utf-8"))
            except:
                pass
        return {
            "root": {
                "id": "initial",
                "parent": None,
                "created": datetime.now(timezone.utc).isoformat(),
                "accuracy_score": 0.0,
                "children_count": 0,
                "description": "Initial baseline",
                "patch_hash": None,
            },
            "nodes": {},
            "current_best": "initial",
        }
    
    def _load_archive(self) -> dict[str, Any]:
        if self.archive_file.exists():
            try:
                return json.loads(self.archive_file.read_text(encoding="utf-8"))
            except:
                pass
        return {
            "improvements": [],
            "generations": [],
            "total_accuracy_gain": 0.0,
        }
    
    def _save_lineage(self):
        self.lineage_file.write_text(json.dumps(self._lineage, indent=2), encoding="utf-8")
    
    def _save_archive(self):
        self.archive_file.write_text(json.dumps(self._archive, indent=2), encoding="utf-8")
    
    def _generate_id(self, patch_content: str) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        patch_hash = hashlib.md5(patch_content.encode()).hexdigest()[:8]
        return f"imp_{timestamp}_{patch_hash}"
    
    def add_improvement(
        self,
        parent_id: str,
        patch_content: str,
        accuracy_before: float,
        accuracy_after: float,
        description: str,
        metadata: dict[str, Any] = None,
    ) -> str:
        improvement_id = self._generate_id(patch_content)
        patch_hash = hashlib.md5(patch_content.encode()).hexdigest()
        
        node = {
            "id": improvement_id,
            "parent": parent_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "accuracy_before": accuracy_before,
            "accuracy_after": accuracy_after,
            "accuracy_score": accuracy_after,
            "accuracy_delta": accuracy_after - accuracy_before,
            "children_count": 0,
            "description": description,
            "patch_hash": patch_hash,
            "patch_content": patch_content,
            "metadata": metadata or {},
        }
        
        self._lineage["nodes"][improvement_id] = node
        
        if parent_id == "initial":
            self._lineage["root"]["children_count"] += 1
        elif parent_id in self._lineage["nodes"]:
            self._lineage["nodes"][parent_id]["children_count"] += 1
        
        if accuracy_after > self.get_best_score():
            self._lineage["current_best"] = improvement_id
        
        self._archive["improvements"].append({
            "id": improvement_id,
            "parent": parent_id,
            "accuracy_delta": accuracy_after - accuracy_before,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._archive["total_accuracy_gain"] += max(0, accuracy_after - accuracy_before)
        
        self._save_lineage()
        self._save_archive()
        
        return improvement_id
    
    def get_node(self, node_id: str) -> Optional[dict[str, Any]]:
        if node_id == "initial":
            return self._lineage["root"]
        return self._lineage["nodes"].get(node_id)
    
    def get_lineage(self, node_id: str) -> list[str]:
        lineage = []
        current = node_id
        
        while current and current != "initial":
            lineage.append(current)
            node = self.get_node(current)
            current = node.get("parent") if node else None
        
        lineage.append("initial")
        lineage.reverse()
        return lineage
    
    def get_patches_for_lineage(self, node_id: str) -> list[str]:
        lineage = self.get_lineage(node_id)
        patches = []
        for nid in lineage:
            if nid != "initial":
                node = self.get_node(nid)
                if node and node.get("patch_content"):
                    patches.append(node["patch_content"])
        return patches
    
    def get_all_nodes(self) -> list[dict[str, Any]]:
        nodes = [self._lineage["root"]]
        nodes.extend(self._lineage["nodes"].values())
        return nodes
    
    def get_best_score(self) -> float:
        best_id = self._lineage.get("current_best", "initial")
        if best_id == "initial":
            return self._lineage["root"].get("accuracy_score", 0.0)
        node = self._lineage["nodes"].get(best_id)
        return node.get("accuracy_score", 0.0) if node else 0.0
    
    def get_best_node_id(self) -> str:
        return self._lineage.get("current_best", "initial")
    
    def record_generation(self, parent_ids: list[str], child_ids: list[str], compiled_ids: list[str]):
        generation = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parents": parent_ids,
            "children": child_ids,
            "compiled": compiled_ids,
            "success_rate": len(compiled_ids) / max(len(child_ids), 1),
        }
        self._archive["generations"].append(generation)
        self._save_archive()
    
    def get_generation_count(self) -> int:
        return len(self._archive.get("generations", []))


class MeritSelector:
    def __init__(self, lineage: ImprovementLineage):
        self.lineage = lineage
    
    def _sigmoid(self, x: float, scale: float = 10.0) -> float:
        return 1.0 / (1.0 + math.exp(-scale * x))
    
    def select_parent(self, method: str = "merit_weighted") -> str:
        nodes = self.lineage.get_all_nodes()
        
        if len(nodes) <= 1:
            return "initial"
        
        if method == "merit_weighted":
            return self._merit_weighted_selection(nodes)
        elif method == "exploration_bonus":
            return self._exploration_bonus_selection(nodes)
        elif method == "best_only":
            return self.lineage.get_best_node_id()
        elif method == "random":
            return random.choice([n["id"] for n in nodes])
        
        return self._merit_weighted_selection(nodes)
    
    def _merit_weighted_selection(self, nodes: list[dict[str, Any]]) -> str:
        weights = []
        for node in nodes:
            score = node.get("accuracy_score", 0.0)
            children = node.get("children_count", 0)
            
            merit = self._sigmoid(score, scale=5.0)
            exploration = 1.0 / (1.0 + children)
            weight = merit * exploration
            
            weights.append(max(weight, 0.001))
        
        total = sum(weights)
        probabilities = [w / total for w in weights]
        
        r = random.random()
        cumulative = 0.0
        for i, prob in enumerate(probabilities):
            cumulative += prob
            if r <= cumulative:
                return nodes[i]["id"]
        
        return nodes[-1]["id"]
    
    def _exploration_bonus_selection(self, nodes: list[dict[str, Any]]) -> str:
        weights = []
        for node in nodes:
            score = node.get("accuracy_score", 0.0)
            children = node.get("children_count", 0)
            
            merit = self._sigmoid(score, scale=3.0)
            exploration = 2.0 / (1.0 + children)
            weight = merit * exploration
            
            weights.append(max(weight, 0.01))
        
        total = sum(weights)
        probabilities = [w / total for w in weights]
        
        r = random.random()
        cumulative = 0.0
        for i, prob in enumerate(probabilities):
            cumulative += prob
            if r <= cumulative:
                return nodes[i]["id"]
        
        return nodes[-1]["id"]
    
    def get_selection_probabilities(self, method: str = "merit_weighted") -> list[Tuple[str, float]]:
        nodes = self.lineage.get_all_nodes()
        
        if len(nodes) <= 1:
            return [("initial", 1.0)]
        
        weights = []
        for node in nodes:
            score = node.get("accuracy_score", 0.0)
            children = node.get("children_count", 0)
            
            if method == "merit_weighted":
                merit = self._sigmoid(score, scale=5.0)
                exploration = 1.0 / (1.0 + children)
            else:
                merit = self._sigmoid(score, scale=3.0)
                exploration = 2.0 / (1.0 + children)
            
            weight = merit * exploration
            weights.append(max(weight, 0.001))
        
        total = sum(weights)
        return [(nodes[i]["id"], w / total) for i, w in enumerate(weights)]


class GoalManager:
    GOALS = {
        "accuracy": {"description": "Maximize detection accuracy", "weight": 1.0},
        "coverage": {"description": "Maximize vulnerability type coverage", "weight": 0.8},
        "speed": {"description": "Minimize scan time while maintaining accuracy", "weight": 0.6},
        "precision": {"description": "Minimize false positives", "weight": 0.9},
        "recall": {"description": "Minimize false negatives", "weight": 0.9},
        "transfer": {"description": "Maximize cross-target generalization", "weight": 0.7},
    }
    
    def __init__(self):
        self.goal_file = LEARNING_DIR / "active_goals.json"
        self._goals = self._load_goals()
    
    def _load_goals(self) -> dict[str, Any]:
        if self.goal_file.exists():
            try:
                return json.loads(self.goal_file.read_text(encoding="utf-8"))
            except:
                pass
        return {
            "active_goal": "accuracy",
            "goal_history": [],
            "switch_count": 0,
            "last_switch": None,
        }
    
    def _save_goals(self):
        self.goal_file.write_text(json.dumps(self._goals, indent=2), encoding="utf-8")
    
    def get_active_goal(self) -> str:
        return self._goals.get("active_goal", "accuracy")
    
    def switch_goal(self, new_goal: str, reason: str = "") -> bool:
        if new_goal not in self.GOALS:
            return False
        
        old_goal = self._goals["active_goal"]
        self._goals["goal_history"].append({
            "from": old_goal,
            "to": new_goal,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._goals["active_goal"] = new_goal
        self._goals["switch_count"] += 1
        self._goals["last_switch"] = datetime.now(timezone.utc).isoformat()
        self._save_goals()
        return True
    
    def should_switch_goal(self, recent_improvements: list[dict[str, Any]]) -> Optional[str]:
        if not recent_improvements:
            return None
        
        current = self.get_active_goal()
        
        recent_deltas = [i.get("accuracy_delta", 0) for i in recent_improvements[-5:]]
        avg_delta = sum(recent_deltas) / len(recent_deltas) if recent_deltas else 0
        
        if avg_delta < 0.01 and current == "accuracy":
            return "coverage"
        
        if avg_delta < 0 and current == "coverage":
            return "precision"
        
        return None
    
    def get_goal_weight(self, goal: str = None) -> float:
        goal = goal or self.get_active_goal()
        return self.GOALS.get(goal, {}).get("weight", 1.0)


class SteppingStoneTracker:
    def __init__(self, lineage: ImprovementLineage):
        self.lineage = lineage
        self.stepping_stone_file = LEARNING_DIR / "stepping_stones.json"
        self._stones = self._load_stones()
    
    def _load_stones(self) -> dict[str, Any]:
        if self.stepping_stone_file.exists():
            try:
                return json.loads(self.stepping_stone_file.read_text(encoding="utf-8"))
            except:
                pass
        return {"marked_stones": [], "breakthrough_ancestors": []}
    
    def _save_stones(self):
        self.stepping_stone_file.write_text(json.dumps(self._stones, indent=2), encoding="utf-8")
    
    def mark_stepping_stone(self, node_id: str, reason: str):
        self._stones["marked_stones"].append({
            "node_id": node_id,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._save_stones()
    
    def identify_breakthrough_ancestors(self) -> list[str]:
        best_id = self.lineage.get_best_node_id()
        if best_id == "initial":
            return []
        
        ancestry = self.lineage.get_lineage(best_id)
        breakthrough_ancestors = []
        
        prev_score = 0.0
        for node_id in ancestry:
            node = self.lineage.get_node(node_id)
            if not node:
                continue
            
            score = node.get("accuracy_score", 0.0)
            delta = score - prev_score
            
            if delta > 0.05:
                breakthrough_ancestors.append(node_id)
                if node_id not in [s["node_id"] for s in self._stones["breakthrough_ancestors"]]:
                    self._stones["breakthrough_ancestors"].append({
                        "node_id": node_id,
                        "delta": delta,
                        "identified": datetime.now(timezone.utc).isoformat(),
                    })
            
            prev_score = score
        
        self._save_stones()
        return breakthrough_ancestors
    
    def get_exploration_candidates(self) -> list[str]:
        candidates = []
        
        for stone in self._stones["marked_stones"]:
            candidates.append(stone["node_id"])
        
        for ancestor in self._stones["breakthrough_ancestors"]:
            if ancestor["node_id"] not in candidates:
                candidates.append(ancestor["node_id"])
        
        nodes = self.lineage.get_all_nodes()
        for node in nodes:
            if node.get("children_count", 0) == 0 and node["id"] != "initial":
                if node["id"] not in candidates:
                    candidates.append(node["id"])
        
        return candidates


class SafetyValidator:
    def __init__(self):
        self.validation_file = LEARNING_DIR / "safety_validations.json"
        self._validations = self._load_validations()
    
    def _load_validations(self) -> dict[str, Any]:
        if self.validation_file.exists():
            try:
                return json.loads(self.validation_file.read_text(encoding="utf-8"))
            except:
                pass
        return {
            "hallucination_checks": [],
            "reward_hacking_checks": [],
            "flagged_improvements": [],
        }
    
    def _save_validations(self):
        self.validation_file.write_text(json.dumps(self._validations, indent=2), encoding="utf-8")
    
    def check_hallucination(self, improvement: dict[str, Any]) -> dict[str, Any]:
        result = {
            "improvement_id": improvement.get("id", "unknown"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hallucination_detected": False,
            "indicators": [],
        }
        
        patch_content = improvement.get("patch_content", "")
        
        suspicious_patterns = [
            (r"test.*passed", "Claims tests passed without evidence"),
            (r"verified.*working", "Claims verification without proof"),
            (r"100%.*success", "Unrealistic success claims"),
            (r"all.*tests.*pass", "Generic test pass claims"),
        ]
        
        import re
        for pattern, description in suspicious_patterns:
            if re.search(pattern, patch_content, re.IGNORECASE):
                result["indicators"].append(description)
        
        if len(result["indicators"]) >= 2:
            result["hallucination_detected"] = True
        
        self._validations["hallucination_checks"].append(result)
        self._save_validations()
        
        return result
    
    def check_reward_hacking(
        self,
        accuracy_before: float,
        accuracy_after: float,
        improvement: dict[str, Any],
    ) -> dict[str, Any]:
        result = {
            "improvement_id": improvement.get("id", "unknown"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reward_hacking_detected": False,
            "indicators": [],
            "accuracy_jump": accuracy_after - accuracy_before,
        }
        
        if accuracy_after - accuracy_before > 0.3:
            result["indicators"].append("Suspicious large accuracy jump (>30%)")
        
        if accuracy_after == 1.0:
            result["indicators"].append("Perfect accuracy is suspicious")
        
        patch_content = improvement.get("patch_content", "")
        hack_patterns = [
            (r"return\s+True", "Always returns True"),
            (r"confidence\s*=\s*1", "Hardcoded confidence"),
            (r"skip.*test", "Skipping tests"),
            (r"mock.*result", "Mocking results"),
        ]
        
        import re
        for pattern, description in hack_patterns:
            if re.search(pattern, patch_content, re.IGNORECASE):
                result["indicators"].append(description)
        
        if len(result["indicators"]) >= 2:
            result["reward_hacking_detected"] = True
            self._validations["flagged_improvements"].append(improvement.get("id", "unknown"))
        
        self._validations["reward_hacking_checks"].append(result)
        self._save_validations()
        
        return result
    
    def is_improvement_safe(self, improvement: dict[str, Any], accuracy_before: float, accuracy_after: float) -> bool:
        hallucination = self.check_hallucination(improvement)
        hacking = self.check_reward_hacking(accuracy_before, accuracy_after, improvement)
        
        return not hallucination["hallucination_detected"] and not hacking["reward_hacking_detected"]
    
    def get_safety_summary(self) -> dict[str, Any]:
        return {
            "total_checks": len(self._validations["hallucination_checks"]) + len(self._validations["reward_hacking_checks"]),
            "hallucinations_detected": sum(1 for c in self._validations["hallucination_checks"] if c.get("hallucination_detected")),
            "reward_hacks_detected": sum(1 for c in self._validations["reward_hacking_checks"] if c.get("reward_hacking_detected")),
            "flagged_improvements": len(self._validations["flagged_improvements"]),
        }


def get_lineage_summary() -> str:
    lineage = ImprovementLineage()
    selector = MeritSelector(lineage)
    
    nodes = lineage.get_all_nodes()
    best_id = lineage.get_best_node_id()
    best_score = lineage.get_best_score()
    generations = lineage.get_generation_count()
    
    lines = [
        "=" * 60,
        "IMPROVEMENT LINEAGE SUMMARY",
        "=" * 60,
        f"\nTotal Improvements: {len(nodes) - 1}",
        f"Generations: {generations}",
        f"Best Score: {best_score:.3f}",
        f"Best Node: {best_id}",
    ]
    
    if best_id != "initial":
        ancestry = lineage.get_lineage(best_id)
        lines.append(f"\nBest Node Ancestry ({len(ancestry)} steps):")
        for i, node_id in enumerate(ancestry):
            node = lineage.get_node(node_id)
            score = node.get("accuracy_score", 0.0) if node else 0.0
            lines.append(f"  {'└─' if i == len(ancestry)-1 else '├─'} {node_id} (score: {score:.3f})")
    
    lines.append("\nSelection Probabilities:")
    probs = selector.get_selection_probabilities()
    for node_id, prob in sorted(probs, key=lambda x: x[1], reverse=True)[:5]:
        lines.append(f"  {node_id}: {prob*100:.1f}%")
    
    lines.append("\n" + "=" * 60)
    return "\n".join(lines)
