import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_black.knowledge_loader import load_brain
from agent_black.lantern_runner import run_lantern, get_latest_result, determine_next_actions
from agent_black.model_registry import discover_models, select_model
from agent_black.policies import (
    validate_request,
    validate_plan,
    load_scope_config,
    get_policy_summary,
)
from agent_black.learning import (
    get_recommended_modules,
    get_scan_variation,
    get_target_profile,
    get_learning_summary,
    should_try_new_approach,
    get_unexplored_modules,
)
from agent_black.smart_probe import run_smart_probe, print_probe_summary
from agent_black.improvement_applier import (
    generate_improvement_report,
    apply_improvements_to_lantern,
    show_improvement_diff,
    verify_patches_applied,
    print_verification_report,
    validate_improvements,
    print_validation_report,
    full_improvement_cycle,
)


WORKFLOWS = {
    "full": ["recon", "exploit"],
    "recon_then_exploit": ["recon", "exploit"],
    "safe": ["recon"],
    "aggressive": ["exploit"],
}

WORKFLOW_CONFIGS = {
    "recon": {
        "chain": "full_recon",
        "modules": ["techdetect", "fingerprint", "subdomain", "dirbust", "disclosure", "secrets", "dork", "paramfind"],
        "flags": ["--crawl", "--crawl-depth", "3"],
    },
    "exploit": {
        "chain": "injection",
        "modules": ["sqli", "xss", "cmdi", "ssti", "lfi", "xxe", "ssrf"],
        "flags": ["--exploit", "--aggressive", "--deep"],
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Agent BLACK - AI companion for the LANTERN CLI"
    )
    parser.add_argument(
        "prompt",
        nargs="*",
        help="User request to translate into a LANTERN scan plan",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned LANTERN command without running it",
    )
    parser.add_argument(
        "--lantern-path",
        default="lantern",
        help="Path to the LANTERN executable (default: lantern)",
    )
    parser.add_argument(
        "--provider",
        default="free",
        help="AI provider to use (default: free)",
    )
    parser.add_argument(
        "--api-key",
        default="",
        help="Optional API key for paid AI providers",
    )
    parser.add_argument(
        "--api-base",
        default="",
        help="Optional base URL for the selected AI provider",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Optional local model name (auto-detected if omitted)",
    )
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="List auto-detected local models and exit",
    )
    parser.add_argument(
        "--lantern-docs",
        default="",
        help="Path to Lantern docs directory or Commands-Expanded.md file to load into the brain",
    )
    parser.add_argument(
        "--rerun-last",
        action="store_true",
        help="Re-run the last stored Lantern plan",
    )
    parser.add_argument(
        "--show-results",
        action="store_true",
        help="Show the latest scan results summary",
    )
    parser.add_argument(
        "--show-policy",
        action="store_true",
        help="Show the current scope/policy configuration",
    )
    parser.add_argument(
        "--workflow",
        choices=list(WORKFLOWS.keys()),
        help="Run a multi-stage workflow (recon_then_exploit, full, safe, aggressive)",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip scope/policy validation (use with caution)",
    )
    parser.add_argument(
        "--show-learning",
        action="store_true",
        help="Show what Agent BLACK has learned from past scans",
    )
    parser.add_argument(
        "--adapt",
        action="store_true",
        help="Adapt approach based on past scan results (tries new things on repeat scans)",
    )
    parser.add_argument(
        "--explore",
        action="store_true",
        help="Try unexplored modules on targets that have been scanned before",
    )
    parser.add_argument(
        "--smart-probe",
        action="store_true",
        help="Run Agent BLACK's own intelligent probing after Lantern (finds things Lantern misses)",
    )
    parser.add_argument(
        "--probe-only",
        action="store_true",
        help="Skip Lantern and only run Agent BLACK's smart probe",
    )
    parser.add_argument(
        "--show-improvements",
        action="store_true",
        help="Show all improvement suggestions collected from smart probes",
    )
    parser.add_argument(
        "--apply-improvements",
        action="store_true",
        help="Apply improvement patches to Lantern modules",
    )
    parser.add_argument(
        "--diff-improvements",
        action="store_true",
        help="Show what changes would be made to Lantern",
    )
    parser.add_argument(
        "--verify-patches",
        action="store_true",
        help="Verify that patches were actually applied to Lantern",
    )
    parser.add_argument(
        "--validate-improvements",
        metavar="TARGET",
        help="Test improvements against a target to confirm they work",
    )
    parser.add_argument(
        "--improvement-cycle",
        action="store_true",
        help="Run full improvement cycle: check status, verify, and guide next steps",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    user_prompt = " ".join(args.prompt).strip()

    if args.show_results:
        return show_results()

    if args.show_policy:
        print(get_policy_summary())
        return 0

    if args.show_learning:
        print(get_learning_summary())
        return 0

    if args.show_improvements:
        print(generate_improvement_report())
        return 0

    if args.diff_improvements:
        print(show_improvement_diff())
        return 0

    if args.apply_improvements:
        print(apply_improvements_to_lantern())
        return 0

    if args.verify_patches:
        verification = verify_patches_applied()
        print(print_verification_report(verification))
        return 0

    if args.validate_improvements:
        validation = validate_improvements(args.validate_improvements)
        print(print_validation_report(validation))
        return 0

    if args.improvement_cycle:
        target = extract_target_from_prompt(user_prompt) if user_prompt else ""
        print(full_improvement_cycle(target))
        return 0

    if not user_prompt and not args.rerun_last:
        print("No prompt provided. Use: agent-black \"<request>\"")
        print("\nExamples:")
        print("  agent-black \"authorized scope scan https://demo.testfire.net for XSS\"")
        print("  agent-black \"scope find cookies on https://demo.testfire.net\"")
        print("  agent-black \"authorized run full recon on https://target.com\"")
        print("\nOptions:")
        print("  --dry-run          Show planned command without running")
        print("  --rerun-last       Re-run the last scan")
        print("  --show-results     Show latest scan results")
        print("  --show-policy      Show scope/policy settings")
        print("  --workflow <name>  Run multi-stage workflow (full, recon_then_exploit, safe, aggressive)")
        return 1

    if user_prompt and not validate_request(user_prompt):
        print("Request rejected by policy. Include 'authorized', 'scope', or target URL in your prompt.")
        return 2

    if args.provider != "free" and not args.api_key:
        print("Selected provider requires an API key. Use --api-key or switch to --provider free.")
        return 3

    extra_docs: list[Path] = []
    if args.lantern_docs:
        candidate = Path(args.lantern_docs).expanduser()
        if candidate.is_dir():
            doc_candidate = candidate / "docs" / "Commands-Expanded.md"
            if doc_candidate.exists():
                extra_docs.append(doc_candidate)
            else:
                doc_candidate = candidate / "Commands-Expanded.md"
                if doc_candidate.exists():
                    extra_docs.append(doc_candidate)
        elif candidate.is_file():
            extra_docs.append(candidate)
        if candidate and not extra_docs:
            print(f"Warning: specified --lantern-docs path {candidate} did not yield a Commands-Expanded.md file")

    brain = load_brain(extra_doc_paths=extra_docs)
    if not brain:
        print("Warning: the Agent BLACK brain is empty.")

    if args.rerun_last:
        return rerun_last_plan(args)

    models_dir = Path(__file__).parent / "models"
    models = discover_models(models_dir)
    if args.list_models:
        if not models:
            print("No local models detected. Drop a .gguf into agent_black/models.")
            return 0
        print("Detected local models:")
        for model in models:
            print(f"- {model.name} ({model.engine}) -> {model.path}")
        return 0

    selected = select_model(models, args.model if args.model else None)
    if models and not selected:
        print(f"Requested model '{args.model}' not found.")
        return 4

    if args.workflow:
        return run_workflow(args.workflow, user_prompt, brain, args)

    target = extract_target_from_prompt(user_prompt)
    
    if args.probe_only:
        if not target or target == "<target>":
            print("Smart probe requires a target URL in the prompt")
            return 8
        print(f"🧠 Running Agent BLACK Smart Probe only (skipping Lantern)")
        probe_result = run_smart_probe(target)
        print_probe_summary(probe_result)
        return 0

    planned_cmd, plan_details = build_plan(
        user_prompt,
        brain,
        args.lantern_path,
        adapt=args.adapt,
        explore=args.explore,
    )

    if not args.skip_validation:
        scope_config = load_scope_config()
        valid, reason = validate_plan(planned_cmd, scope_config)
        if not valid:
            print(f"Plan rejected by policy: {reason}")
            print("Use --skip-validation to override (use with caution)")
            return 6

    if args.dry_run:
        print("Planned command:", " ".join(planned_cmd))
        save_plan(prompt=user_prompt, command=planned_cmd, details=plan_details)
        return 0

    print("Planned command:", " ".join(planned_cmd))
    print("Running LANTERN...")
    save_plan(prompt=user_prompt, command=planned_cmd, details=plan_details)
    
    exit_code = run_autonomous_scan(planned_cmd, args.lantern_path, args.skip_validation)
    
    if args.smart_probe and target and target != "<target>":
        print("\n🧠 Lantern complete. Now running Agent BLACK's own smart probe...")
        probe_result = run_smart_probe(target)
        print_probe_summary(probe_result)
        
        if probe_result.get("improvement_suggestions"):
            print("\n💡 Agent BLACK found things Lantern missed!")
            print("   Check improvement_logs/ for detailed suggestions to enhance Lantern.")
    
    return exit_code


MAX_AUTONOMOUS_ITERATIONS = 5


def run_autonomous_scan(initial_cmd: list[str], lantern_path: str, skip_validation: bool) -> int:
    iteration = 0
    current_cmd = initial_cmd
    all_findings = 0
    all_critical = 0
    all_high = 0
    
    while iteration < MAX_AUTONOMOUS_ITERATIONS:
        iteration += 1
        
        if iteration > 1:
            print(f"\n{'=' * 60}")
            print(f"🤖 AGENT BLACK PROACTIVE ACTION (Iteration {iteration}/{MAX_AUTONOMOUS_ITERATIONS})")
            print(f"{'=' * 60}")
            print(f"Command: {' '.join(current_cmd)}")
        
        exit_code, scan_result = run_lantern(current_cmd)
        
        if not scan_result:
            return exit_code
        
        findings = scan_result.get("total_findings", 0)
        critical = scan_result.get("severity_counts", {}).get("CRITICAL", 0)
        high = scan_result.get("severity_counts", {}).get("HIGH", 0)
        
        all_findings += findings
        all_critical += critical
        all_high += high
        
        next_actions = determine_next_actions(scan_result, current_cmd, iteration)
        
        if not next_actions:
            print(f"\n✅ Agent BLACK completed scan cycle")
            print(f"   Total findings: {all_findings}")
            print(f"   Critical: {all_critical} | High: {all_high}")
            if all_critical > 0 or all_high > 0:
                print(f"   ⚠️  Review findings - exploitation data may be in scan results")
            return exit_code
        
        action = next_actions[0]
        print(f"\n🤖 Agent BLACK taking initiative: {action.get('reason', 'Follow-up scan')}")
        
        target = scan_result.get("target")
        if not target:
            return exit_code
        
        current_cmd = build_followup_cmd(lantern_path, target, action, current_cmd)
        
        if not skip_validation:
            scope_config = load_scope_config()
            valid, reason = validate_plan(current_cmd, scope_config)
            if not valid:
                print(f"   Follow-up blocked by policy: {reason}")
                return exit_code
    
    print(f"\n🏁 Agent BLACK completed {MAX_AUTONOMOUS_ITERATIONS} iterations")
    print(f"   Total findings: {all_findings}")
    print(f"   Critical: {all_critical} | High: {all_high}")
    return 0


def build_followup_cmd(lantern_path: str, target: str, action: dict[str, Any], prev_cmd: list[str]) -> list[str]:
    cmd = [lantern_path, "-t", target]
    
    modules = action.get("modules", [])
    if modules:
        cmd += ["--modules", ",".join(modules)]
    else:
        for i, arg in enumerate(prev_cmd):
            if arg == "--modules" and i + 1 < len(prev_cmd):
                cmd += ["--modules", prev_cmd[i + 1]]
                break
    
    flags = action.get("flags", [])
    for flag in flags:
        if flag not in cmd:
            cmd.append(flag)
    
    prev_flags = ["--aggressive", "--deep", "--crawl", "--smart"]
    for flag in prev_flags:
        if flag in prev_cmd and flag not in cmd:
            cmd.append(flag)
    
    return cmd


def run_workflow(workflow_name: str, prompt: str, brain: dict[str, Any], args: argparse.Namespace) -> int:
    stages = WORKFLOWS.get(workflow_name, [])
    if not stages:
        print(f"Unknown workflow: {workflow_name}")
        return 7

    target = extract_target_from_prompt(prompt)
    if not target or target == "<target>":
        print("Workflow requires a target URL in the prompt")
        return 8

    print(f"\n{'=' * 60}")
    print(f"AGENT BLACK WORKFLOW: {workflow_name.upper()}")
    print(f"Target: {target}")
    print(f"Stages: {' → '.join(stages)}")
    print(f"{'=' * 60}\n")

    for i, stage in enumerate(stages, 1):
        print(f"\n[Stage {i}/{len(stages)}] {stage.upper()}")
        print("-" * 40)

        stage_config = WORKFLOW_CONFIGS.get(stage, {})
        cmd = [args.lantern_path, "-t", target]

        modules = stage_config.get("modules", [])
        if modules:
            cmd += ["--modules", ",".join(modules)]

        chain = stage_config.get("chain")
        if chain:
            cmd += ["--chain", chain]

        flags = stage_config.get("flags", [])
        cmd.extend(flags)

        if not args.skip_validation:
            scope_config = load_scope_config()
            valid, reason = validate_plan(cmd, scope_config)
            if not valid:
                print(f"Stage {stage} rejected by policy: {reason}")
                continue

        if args.dry_run:
            print("Planned command:", " ".join(cmd))
        else:
            print("Running:", " ".join(cmd))
            exit_code, _ = run_lantern(cmd)
            if exit_code != 0:
                print(f"Stage {stage} completed with exit code {exit_code}")

    print(f"\n{'=' * 60}")
    print("WORKFLOW COMPLETE")
    print(f"{'=' * 60}")
    return 0


def show_results() -> int:
    result = get_latest_result()
    if not result:
        print("No scan results found. Run a scan first.")
        return 0

    scan_result = result.get("result", {})
    cmd = result.get("command", [])

    print("\n" + "=" * 60)
    print("LATEST SCAN RESULTS")
    print("=" * 60)

    print(f"\nCommand: {' '.join(cmd)}")
    print(f"Timestamp: {scan_result.get('timestamp', 'unknown')}")

    counts = scan_result.get("severity_counts", {})
    total = scan_result.get("total_findings", 0)

    print(f"\nTotal Findings: {total}")
    if counts:
        print("\nBy Severity:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                print(f"  {sev}: {counts[sev]}")

    recs = scan_result.get("recommendations", [])
    if recs:
        print("\nRecommendations:")
        for rec in recs:
            print(f"  → {rec}")

    print("\n" + "=" * 60)
    return 0


def build_plan(
    prompt: str,
    brain: dict[str, Any],
    lantern_path: str,
    adapt: bool = False,
    explore: bool = False,
) -> tuple[list[str], dict[str, Any]]:
    knowledge = brain or {}
    target = determine_target(prompt, knowledge)
    preset = select_preset(prompt, knowledge)
    chain_name, chain_modules = select_chain(prompt, knowledge)
    modules = determine_modules(prompt, knowledge, preset, chain_modules)
    extra_flags = determine_extra_flags(prompt, knowledge)

    if adapt and target and target != "<target>":
        profile = get_target_profile(target)
        if profile and profile.get("scan_count", 0) > 0:
            print(f"🧠 Learning: Target scanned {profile['scan_count']} time(s) before")
            
            modules = get_recommended_modules(target, modules)
            print(f"🧠 Learning: Prioritized modules based on past success")
            
            if should_try_new_approach(target):
                variation_modules, variation_flags = get_scan_variation(target, modules)
                modules = variation_modules
                extra_flags.extend(variation_flags)
                print(f"🧠 Learning: Trying variation #{profile['scan_count'] % 5 + 1} for better coverage")
            
            if profile.get("vulnerable_modules"):
                print(f"🧠 Learning: Known vulnerable modules: {', '.join(profile['vulnerable_modules'][:5])}")

    if explore and target and target != "<target>":
        all_modules = knowledge.get("modules", {}).get("all", [])
        unexplored = get_unexplored_modules(target, all_modules)
        if unexplored:
            print(f"🔍 Explore: Found {len(unexplored)} unexplored modules for this target")
            modules = unexplored[:20]
            print(f"🔍 Explore: Testing: {', '.join(modules[:10])}...")

    cmd = [lantern_path, "-t", target]
    if modules:
        cmd += ["--modules", ",".join(modules)]
    if preset:
        cmd += ["--preset", preset["name"]]
    if chain_name:
        cmd += ["--chain", chain_name]

    config = {}
    if preset:
        config.update(preset.get("config", {}))
    config_defaults = knowledge.get("config", {}).get("config_defaults", {})
    if config_defaults:
        config = {**config_defaults, **config}

    skip_flags = {"chain"} if chain_name else set()
    apply_config_flags(cmd, config, skip_keys=skip_flags)
    
    for flag in extra_flags:
        if flag not in cmd:
            cmd.append(flag)

    plan_details = {
        "prompt": prompt,
        "target": target,
        "modules": modules,
        "preset": preset["name"] if preset else None,
        "chain": chain_name,
        "config": config,
        "extra_flags": extra_flags,
        "adapted": adapt,
        "explored": explore,
    }
    return cmd, plan_details


def determine_target(prompt: str, knowledge: dict[str, Any]) -> str:
    config_target = knowledge.get("config", {}).get("config_defaults", {}).get("target")
    if config_target:
        return config_target
    extracted = extract_target_from_prompt(prompt)
    return extracted or "<target>"


def extract_target_from_prompt(prompt: str) -> str | None:
    url_match = re.search(
        r"(https?://[^\s\"'<>]+)",
        prompt,
    )
    if url_match:
        return url_match.group(1).rstrip(".,;:\"'")

    domain_match = re.search(
        r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|fr|jp|cn|app|dev|xyz|info|biz))\b",
        prompt,
    )
    if domain_match:
        candidate = domain_match.group(1)
        return "https://" + candidate

    return None


def determine_extra_flags(prompt: str, knowledge: dict[str, Any]) -> list[str]:
    flags = []
    lowered = prompt.lower()

    flag_triggers = {
        "--exploit": ["exploit", "extract", "dump", "exfil", "steal", "pwn", "hack", "attack"],
        "--aggressive": ["aggressive", "bypass", "waf", "mutation", "obfuscate", "evade"],
        "--deep": ["deep", "thorough", "comprehensive", "full"],
        "--stealth": ["stealth", "quiet", "slow", "careful", "undetected"],
        "--crawl": ["crawl", "spider", "discover", "enumerate"],
        "--smart": ["smart", "auto", "detect", "fingerprint"],
    }

    for flag, triggers in flag_triggers.items():
        if any(t in lowered for t in triggers):
            if flag not in flags:
                flags.append(flag)

    if "--crawl" in flags and "--crawl-depth" not in " ".join(flags):
        flags.extend(["--crawl-depth", "3"])

    return flags


def select_preset(prompt: str, knowledge: dict[str, Any]) -> dict[str, Any] | None:
    presets = knowledge.get("presets", {}).get("presets", [])
    lowered = prompt.lower()
    for preset in presets:
        if regex_word_match(lowered, preset["name"]):
            return preset

    synonyms = {
        "fast": ["quick", "rapid", "speed", "hotfix", "passive", "light"],
        "thorough": ["deep", "comprehensive", "full", "complete", "everything"],
        "api": ["api", "rest", "graphql", "endpoint", "json"],
        "stealth": ["stealth", "quiet", "low profile", "hidden", "undetected"],
        "exploit": ["exploit", "attack", "hack", "pwn", "payload", "rce"],
    }

    for preset in presets:
        terms = synonyms.get(preset["name"].lower(), [])
        for term in terms:
            if term in lowered:
                return preset
    return None


def select_chain(prompt: str, knowledge: dict[str, Any]) -> tuple[str | None, list[str] | None]:
    chains = knowledge.get("chains", {}).get("chains", {})
    lowered = prompt.lower()

    skip_words = {"authorized", "authorize", "authorization", "authority"}
    if any(w in lowered for w in skip_words) and not regex_word_match(lowered, "auth bypass"):
        cleaned = lowered
        for w in skip_words:
            cleaned = cleaned.replace(w, "")
        lowered = cleaned

    chain_synonyms = {
        "auth_bypass": ["auth bypass", "login bypass", "authentication bypass", "password bypass", "credential bypass"],
        "data_theft": ["data theft", "steal data", "exfil", "extract data", "dump data"],
        "rce": ["rce", "remote code", "shell", "code execution"],
        "xss_chain": ["xss chain", "xss attack", "cross-site scripting"],
        "api_attack": ["api attack", "api hack", "graphql attack"],
        "injection": ["injection chain", "sqli chain", "sql injection"],
        "enum": ["enumeration", "recon chain", "discovery chain"],
        "full_recon": ["full recon", "reconnaissance", "information gathering"],
    }

    for name, modules in chains.items():
        phrase = name.replace("_", " ")
        if phrase in lowered or name in lowered:
            return name, modules

    for chain_name, triggers in chain_synonyms.items():
        if chain_name in chains:
            for trigger in triggers:
                if trigger in lowered:
                    return chain_name, chains[chain_name]

    return None, None


def determine_modules(
    prompt: str,
    knowledge: dict[str, Any],
    preset: dict[str, Any] | None,
    chain_modules: list[str] | None,
) -> list[str]:
    modules_data = knowledge.get("modules", {})
    available = set(modules_data.get("all", []))
    lowered = prompt.lower()

    full_scan_triggers = [
        "all vulnerabilities", "all vulns", "full scan", "comprehensive scan",
        "everything", "complete scan", "thorough scan", "every vulnerability",
        "all modules", "all attacks", "maximum coverage"
    ]
    if any(trigger in lowered for trigger in full_scan_triggers):
        return sorted(available)

    selected: set[str] = set()
    if preset:
        selected.update(preset.get("modules", []))
    if chain_modules:
        selected.update(chain_modules)
    selected.update(extract_module_mentions(prompt, knowledge))

    selected = {module for module in selected if module in available}
    
    if not selected:
        default_modules = [
            "sqli", "xss", "lfi", "ssrf", "ssti", "cmdi", "xxe",
            "cookie", "cors", "headers", "disclosure", "secrets",
            "fingerprint", "techdetect", "dirbust"
        ]
        selected.update(m for m in default_modules if m in available)

    return sorted(selected)


def extract_module_mentions(prompt: str, knowledge: dict[str, Any]) -> set[str]:
    mapping = knowledge.get("smart_mapping", {}).get("module_mapping", {})
    all_modules = knowledge.get("modules", {}).get("all", [])
    lowered = prompt.lower()
    mentioned: set[str] = set()

    skip_words = ["authorized", "authorize", "authorization", "authority"]
    cleaned = lowered
    for w in skip_words:
        cleaned = cleaned.replace(w, " ")

    module_synonyms = {
        "cookie": ["cookie", "cookies"],
        "session": ["session fixation", "session hijack"],
        "auth": ["auth bypass", "authentication flaw", "login bypass", "broken auth"],
        "jwt": ["jwt", "json web token", "bearer token"],
        "sqli": ["sqli", "sql injection", "database injection"],
        "xss": ["xss", "cross-site scripting", "script injection"],
        "ssrf": ["ssrf", "server-side request forgery"],
        "lfi": ["lfi", "local file inclusion", "path traversal", "directory traversal"],
        "ssti": ["ssti", "server-side template injection", "template injection"],
        "cmdi": ["cmdi", "command injection", "os command injection", "rce"],
        "xxe": ["xxe", "xml external entity"],
        "cors": ["cors", "cross-origin"],
        "csrf": ["csrf", "cross-site request forgery"],
        "idor": ["idor", "insecure direct object"],
        "upload": ["file upload", "upload vulnerability"],
        "headers": ["security headers", "missing headers"],
        "ssl": ["ssl", "tls", "certificate"],
        "subdomain": ["subdomain", "subdomain takeover"],
        "dirbust": ["directory brute", "path brute", "dirbust"],
        "secrets": ["secrets", "api keys", "credentials exposed", "hardcoded"],
        "disclosure": ["information disclosure", "info leak"],
        "fingerprint": ["fingerprint", "tech detect", "technology detection"],
        "waf": ["waf bypass", "firewall bypass"],
    }

    for keyword, module_name in mapping.items():
        if regex_word_match(cleaned, keyword):
            mentioned.add(module_name)

    for module_name in all_modules:
        if regex_word_match(cleaned, module_name):
            mentioned.add(module_name)

    modules_all = set(all_modules)
    for module, triggers in module_synonyms.items():
        if module in modules_all:
            for trigger in triggers:
                if trigger in cleaned:
                    mentioned.add(module)
                    break

    return mentioned


def regex_word_match(text: str, term: str) -> bool:
    return re.search(rf"\b{re.escape(term)}\b", text) is not None


def apply_config_flags(
    cmd: list[str], config: dict[str, Any], skip_keys: set[str] | None = None
) -> None:
    skip_keys = skip_keys or set()
    for key, value in sorted(config.items()):
        if key in skip_keys or value is None:
            continue
        flag = f"--{key.replace('_', '-')}"
        if isinstance(value, bool):
            if value:
                cmd.append(flag)
        else:
            cmd += [flag, str(value)]


PLAN_STATE_FILE = Path(__file__).parent / "last_plan.json"


def save_plan(prompt: str, command: list[str], details: dict[str, Any]) -> None:
    try:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prompt": prompt,
            "cmd": command,
            "details": details,
        }
        PLAN_STATE_FILE.write_text(json.dumps(payload), encoding="utf-8")
    except Exception:
        pass


def load_plan_state() -> dict[str, Any] | None:
    if not PLAN_STATE_FILE.exists():
        return None
    try:
        return json.loads(PLAN_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def rerun_last_plan(args: argparse.Namespace) -> int:
    plan = load_plan_state()
    if not plan:
        print("No previous plan found. Run a prompt first.")
        return 5
    cmd = plan.get("cmd", [])
    if not cmd:
        print("Stored plan is invalid.")
        return 5
    print("Re-running saved plan:")
    print("Prompt:", plan.get("prompt", "<unknown>"))
    print("Command:", " ".join(cmd))
    if args.dry_run:
        return 0
    print("Running LANTERN...")
    exit_code, _ = run_lantern(cmd)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
