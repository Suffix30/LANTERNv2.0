"""
Agent BLACK Learning System
Remembers successful approaches and improves over time
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


LEARNING_DIR = Path(__file__).parent / "learned"
LEARNING_DIR.mkdir(exist_ok=True)

TARGET_PROFILES_FILE = LEARNING_DIR / "target_profiles.json"
SUCCESSFUL_PAYLOADS_FILE = LEARNING_DIR / "successful_payloads.json"
SCAN_HISTORY_FILE = LEARNING_DIR / "scan_history.json"
MODULE_EFFECTIVENESS_FILE = LEARNING_DIR / "module_effectiveness.json"


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
