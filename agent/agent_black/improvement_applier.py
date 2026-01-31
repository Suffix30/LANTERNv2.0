"""
Agent BLACK Improvement Applier
Takes improvement logs and generates/applies patches to Lantern modules
""" 

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections import defaultdict


IMPROVEMENT_LOG_DIR = Path(__file__).parent / "improvement_logs"
LANTERN_PATH = Path("/home/kali/Shared/LANTERNv2.0-main")
PATCHES_DIR = Path(__file__).parent / "lantern_patches"
PATCHES_DIR.mkdir(exist_ok=True)


def load_all_improvements() -> list[dict[str, Any]]:
    improvements = []
    if not IMPROVEMENT_LOG_DIR.exists():
        return improvements
    
    for json_file in sorted(IMPROVEMENT_LOG_DIR.glob("improvements_*.json"), reverse=True):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            for suggestion in data.get("improvement_suggestions", []):
                suggestion["source_file"] = json_file.name
                suggestion["target"] = data.get("target", "unknown")
                improvements.append(suggestion)
        except:
            pass
    
    return improvements


def consolidate_improvements(improvements: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_type = defaultdict(list)
    
    seen_payloads = set()
    
    for imp in improvements:
        finding_type = imp.get("finding_type", "unknown")
        payload = imp.get("payload_that_worked", "")
        
        key = f"{finding_type}:{payload}"
        if key in seen_payloads:
            continue
        seen_payloads.add(key)
        
        by_type[finding_type].append(imp)
    
    return dict(by_type)


def generate_lantern_patch(finding_type: str, improvements: list[dict[str, Any]]) -> dict[str, Any]:
    patch = {
        "module": finding_type,
        "target_file": f"modules/{finding_type}.py",
        "payloads_to_add": [],
        "detection_patterns_to_add": [],
        "code_additions": [],
        "patch_content": "",
    }
    
    for imp in improvements:
        payload = imp.get("payload_that_worked", "")
        if payload and payload not in patch["payloads_to_add"]:
            patch["payloads_to_add"].append(payload)
        
        pattern = imp.get("indicator_pattern", "")
        if pattern and pattern not in patch["detection_patterns_to_add"]:
            patch["detection_patterns_to_add"].append(pattern)
    
    patch["patch_content"] = _generate_patch_code(finding_type, patch)
    
    return patch


def _generate_patch_code(finding_type: str, patch: dict[str, Any]) -> str:
    payloads = patch["payloads_to_add"]
    patterns = patch["detection_patterns_to_add"]
    
    code_lines = [
        f"# ============================================================",
        f"# Agent BLACK Suggested Improvements for {finding_type.upper()} Module",
        f"# Generated: {datetime.now(timezone.utc).isoformat()}",
        f"# ============================================================",
        f"",
    ]
    
    if finding_type == "sqli":
        code_lines.extend([
            "# Add these payloads to SQLI_PAYLOADS or create Flask-specific list:",
            "FLASK_SQLI_PAYLOADS = [",
        ])
        for p in payloads[:20]:
            escaped = p.replace('"', '\\"')
            code_lines.append(f'    "{escaped}",')
        code_lines.extend([
            "]",
            "",
            "# Add these detection patterns to error checking:",
            "FLASK_SQLITE_ERRORS = [",
        ])
        for p in patterns[:10]:
            code_lines.append(f'    r"{p}",')
        code_lines.extend([
            "]",
            "",
            "# Integration suggestion:",
            "# In the scan() method, after sending payload:",
            "#   for pattern in FLASK_SQLITE_ERRORS:",
            "#       if re.search(pattern, response.text, re.IGNORECASE):",
            "#           self.add_finding(...)",
        ])
    
    elif finding_type == "lfi":
        code_lines.extend([
            "# Add these paths to LFI_PAYLOADS:",
            "FLASK_LFI_PATHS = [",
        ])
        for p in payloads[:20]:
            escaped = p.replace('"', '\\"')
            code_lines.append(f'    "{escaped}",')
        code_lines.extend([
            "]",
            "",
            "# Detection patterns for Flask apps:",
            "FLASK_LFI_INDICATORS = [",
        ])
        for p in patterns[:10]:
            code_lines.append(f'    r"{p}",')
        code_lines.extend([
            "]",
            "",
            "# These paths are commonly vulnerable in Flask:",
            "#   ../data/config.ini  - Config files",
            "#   ../.env             - Environment files", 
            "#   ../instance/        - Flask instance folder",
        ])
    
    elif finding_type == "ssti":
        code_lines.extend([
            "# Jinja2/Flask SSTI payloads - Agent BLACK confirmed these work:",
            "JINJA2_PAYLOADS = [",
        ])
        for p in payloads[:20]:
            escaped = p.replace('"', '\\"').replace("{{", "{{").replace("}}", "}}")
            code_lines.append(f'    "{escaped}",')
        code_lines.extend([
            "]",
            "",
            "# Detection patterns:",
            "JINJA2_INDICATORS = [",
        ])
        for p in patterns[:10]:
            code_lines.append(f'    r"{p}",')
        code_lines.extend([
            "]",
            "",
            "# Key detection logic:",
            "# 1. Send {{7*7}} - if response contains '49', SSTI confirmed",
            "# 2. Send {{config}} - if response contains '<Config', Flask SSTI",
            "# 3. Send {{self.__class__}} - if response contains '__class__', Jinja2",
        ])
    
    elif finding_type == "cmdi":
        code_lines.extend([
            "# Command injection payloads that worked:",
            "ADDITIONAL_CMDI_PAYLOADS = [",
        ])
        for p in payloads[:20]:
            escaped = p.replace('"', '\\"')
            code_lines.append(f'    "{escaped}",')
        code_lines.extend([
            "]",
            "",
            "# Detection patterns:",
            "CMDI_SUCCESS_INDICATORS = [",
        ])
        for p in patterns[:10]:
            code_lines.append(f'    r"{p}",')
        code_lines.extend([
            "]",
        ])
    
    elif finding_type == "xss":
        code_lines.extend([
            "# XSS payloads that bypassed filters:",
            "ADDITIONAL_XSS_PAYLOADS = [",
        ])
        for p in payloads[:20]:
            escaped = p.replace('"', '\\"')
            code_lines.append(f'    "{escaped}",')
        code_lines.extend([
            "]",
            "",
            "# Reflection patterns:",
            "XSS_REFLECTION_PATTERNS = [",
        ])
        for p in patterns[:10]:
            code_lines.append(f'    r"{p}",')
        code_lines.extend([
            "]",
        ])
    
    elif finding_type == "ssrf":
        code_lines.extend([
            "# SSRF payloads including bypass techniques:",
            "SSRF_BYPASS_PAYLOADS = [",
        ])
        for p in payloads[:20]:
            escaped = p.replace('"', '\\"')
            code_lines.append(f'    "{escaped}",')
        code_lines.extend([
            "]",
            "",
            "# Internal service indicators:",
            "SSRF_SUCCESS_INDICATORS = [",
        ])
        for p in patterns[:10]:
            code_lines.append(f'    r"{p}",')
        code_lines.extend([
            "]",
        ])
    
    elif finding_type == "sensitive_file":
        code_lines.extend([
            "# Sensitive files/paths to check:",
            "SENSITIVE_PATHS = [",
        ])
        seen_paths = set()
        for imp in patch.get("_raw_improvements", []):
            file_path = imp.get("file_path", imp.get("payload_that_worked", ""))
            if file_path and file_path not in seen_paths:
                seen_paths.add(file_path)
                code_lines.append(f'    "{file_path}",')
        code_lines.extend([
            "]",
            "",
            "# Add to dirbust.py or disclosure.py module",
        ])
    
    else:
        code_lines.extend([
            f"# Payloads for {finding_type}:",
            f"{finding_type.upper()}_PAYLOADS = [",
        ])
        for p in payloads[:20]:
            escaped = p.replace('"', '\\"')
            code_lines.append(f'    "{escaped}",')
        code_lines.extend([
            "]",
            "",
            "# Detection patterns:",
            f"{finding_type.upper()}_PATTERNS = [",
        ])
        for p in patterns[:10]:
            code_lines.append(f'    r"{p}",')
        code_lines.extend([
            "]",
        ])
    
    return "\n".join(code_lines)


def save_patches(patches: list[dict[str, Any]]) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    patch_dir = PATCHES_DIR / f"patch_{timestamp}"
    patch_dir.mkdir(exist_ok=True)
    
    for patch in patches:
        module = patch["module"]
        patch_file = patch_dir / f"{module}_improvements.py"
        patch_file.write_text(patch["patch_content"], encoding="utf-8")
    
    summary = generate_patch_summary(patches)
    summary_file = patch_dir / "PATCH_SUMMARY.md"
    summary_file.write_text(summary, encoding="utf-8")
    
    return patch_dir


def generate_patch_summary(patches: list[dict[str, Any]]) -> str:
    lines = [
        "# Lantern Improvement Patches",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Overview",
        "",
        "Agent BLACK has analyzed scan results and generated the following improvements for Lantern.",
        "",
        "## Patches Generated",
        "",
    ]
    
    for patch in patches:
        module = patch["module"]
        payloads = len(patch["payloads_to_add"])
        patterns = len(patch["detection_patterns_to_add"])
        
        lines.extend([
            f"### {module.upper()} Module",
            "",
            f"- **Target File:** `{patch['target_file']}`",
            f"- **New Payloads:** {payloads}",
            f"- **New Detection Patterns:** {patterns}",
            f"- **Patch File:** `{module}_improvements.py`",
            "",
        ])
    
    lines.extend([
        "## How to Apply",
        "",
        "1. Review each `*_improvements.py` file in this directory",
        "2. Copy relevant sections to the corresponding Lantern module",
        "3. Test the changes against a safe target",
        "4. Commit the improvements to your Lantern fork",
        "",
        "## Automatic Application",
        "",
        "Run with `--apply` to automatically merge improvements into Lantern:",
        "```bash",
        "agent-black --apply-improvements",
        "```",
        "",
    ])
    
    return "\n".join(lines)


def apply_patches_to_lantern(patches: list[dict[str, Any]], lantern_path: Path) -> list[str]:
    results = []
    
    for patch in patches:
        module = patch["module"]
        target_file = lantern_path / patch["target_file"]
        
        if not target_file.exists():
            results.append(f"⚠️  {module}: Target file not found: {target_file}")
            continue
        
        original_content = target_file.read_text(encoding="utf-8")
        
        backup_file = target_file.with_suffix(".py.bak")
        if not backup_file.exists():
            backup_file.write_text(original_content, encoding="utf-8")
        
        integration_results = integrate_payloads_into_module(
            module, original_content, patch["payloads_to_add"], patch["detection_patterns_to_add"]
        )
        
        if integration_results["modified"]:
            target_file.write_text(integration_results["content"], encoding="utf-8")
            results.append(f"✅ {module}: INTEGRATED improvements into scan logic")
            for change in integration_results["changes"]:
                results.append(f"   → {change}")
        else:
            results.append(f"⚠️  {module}: No integration points found")
    
    return results


def integrate_payloads_into_module(module: str, content: str, payloads: list[str], patterns: list[str]) -> dict[str, Any]:
    result = {"modified": False, "content": content, "changes": []}
    
    if module == "ssti":
        result = _integrate_ssti(content, payloads, patterns)
    elif module == "lfi":
        result = _integrate_lfi(content, payloads, patterns)
    elif module == "sqli":
        result = _integrate_sqli(content, payloads, patterns)
    elif module == "xss":
        result = _integrate_xss(content, payloads, patterns)
    elif module == "ssrf":
        result = _integrate_ssrf(content, payloads, patterns)
    elif module == "cmdi":
        result = _integrate_cmdi(content, payloads, patterns)
    
    return result


def _integrate_ssti(content: str, payloads: list[str], patterns: list[str]) -> dict[str, Any]:
    result = {"modified": False, "content": content, "changes": []}
    
    jinja2_confirm_match = re.search(
        r'("jinja2":\s*\{[^}]*"confirm":\s*\[)([^\]]+)(\])',
        content, re.DOTALL
    )
    
    if jinja2_confirm_match:
        existing = jinja2_confirm_match.group(2)
        new_payloads = []
        for p in payloads:
            escaped = p.replace('"', '\\"')
            if escaped not in existing and "{{" in p:
                new_payloads.append(f'"{escaped}"')
        
        if new_payloads:
            new_confirm = existing.rstrip() + ", " + ", ".join(new_payloads)
            content = content[:jinja2_confirm_match.start(2)] + new_confirm + content[jinja2_confirm_match.end(2):]
            result["modified"] = True
            result["changes"].append(f"Added {len(new_payloads)} payloads to jinja2 confirm list")
    
    confirmations_match = re.search(
        r'("jinja2":\s*\[)([^\]]+)(\])',
        content[content.find("confirmations"):] if "confirmations" in content else ""
    )
    
    if confirmations_match and patterns:
        for pattern in patterns:
            if pattern not in content:
                result["changes"].append(f"Pattern '{pattern}' should be added to confirmations")
    
    result["content"] = content
    return result


def _integrate_lfi(content: str, payloads: list[str], patterns: list[str]) -> dict[str, Any]:
    result = {"modified": False, "content": content, "changes": []}
    
    lines = content.split('\n')
    new_lines = []
    in_traversals = False
    in_config = False
    traversals_added = False
    patterns_added = False
    
    for i, line in enumerate(lines):
        new_lines.append(line)
        
        if 'traversals = [' in line and '_test_basic_traversal' in '\n'.join(lines[max(0,i-10):i]):
            in_traversals = True
        
        if in_traversals and line.strip() == ']' and not traversals_added:
            in_traversals = False
            traversals_added = True
            new_payloads = []
            for p in payloads:
                if (".." in p or "/" in p) and p not in content:
                    new_payloads.append(f'            "{p}",')
            if new_payloads:
                new_lines.pop()
                for np in new_payloads:
                    new_lines.append(np)
                new_lines.append(line)
                result["modified"] = True
                result["changes"].append(f"Added {len(new_payloads)} paths to traversals list")
        
        if '"config": [' in line:
            in_config = True
        
        if in_config and line.strip() == '],' and not patterns_added:
            in_config = False
            patterns_added = True
            new_patterns_list = []
            for p in patterns:
                escaped = p.replace('\\', '\\\\')
                if escaped not in content:
                    new_patterns_list.append(f'            r"{escaped}",')
            if new_patterns_list:
                new_lines.pop()
                for np in new_patterns_list:
                    new_lines.append(np)
                new_lines.append(line)
                result["modified"] = True
                result["changes"].append(f"Added {len(new_patterns_list)} detection patterns")
    
    result["content"] = '\n'.join(new_lines)
    return result


def _integrate_sqli(content: str, payloads: list[str], patterns: list[str]) -> dict[str, Any]:
    result = {"modified": False, "content": content, "changes": []}
    
    payloads_match = re.search(
        r'((?:payloads|SQLI_PAYLOADS|error_payloads)\s*=\s*\[)([^\]]+)(\])',
        content, re.DOTALL
    )
    
    if payloads_match:
        existing = payloads_match.group(2)
        new_payloads = []
        for p in payloads:
            escaped = p.replace('"', '\\"').replace("'", "\\'")
            if escaped not in existing:
                new_payloads.append(f'        "{escaped}"')
        
        if new_payloads:
            new_list = existing.rstrip() + ",\n" + ",\n".join(new_payloads)
            content = content[:payloads_match.start(2)] + new_list + content[payloads_match.end(2):]
            result["modified"] = True
            result["changes"].append(f"Added {len(new_payloads)} SQLi payloads")
    
    result["content"] = content
    return result


def _integrate_xss(content: str, payloads: list[str], patterns: list[str]) -> dict[str, Any]:
    result = {"modified": False, "content": content, "changes": []}
    
    payloads_match = re.search(
        r'((?:payloads|XSS_PAYLOADS|test_payloads)\s*=\s*\[)([^\]]+)(\])',
        content, re.DOTALL
    )
    
    if payloads_match:
        existing = payloads_match.group(2)
        new_payloads = []
        for p in payloads:
            escaped = p.replace('"', '\\"').replace("'", "\\'")
            if escaped not in existing:
                new_payloads.append(f'        "{escaped}"')
        
        if new_payloads:
            new_list = existing.rstrip() + ",\n" + ",\n".join(new_payloads)
            content = content[:payloads_match.start(2)] + new_list + content[payloads_match.end(2):]
            result["modified"] = True
            result["changes"].append(f"Added {len(new_payloads)} XSS payloads")
    
    result["content"] = content
    return result


def _integrate_ssrf(content: str, payloads: list[str], patterns: list[str]) -> dict[str, Any]:
    result = {"modified": False, "content": content, "changes": []}
    
    payloads_match = re.search(
        r'((?:internal_urls|ssrf_payloads|test_urls)\s*=\s*\[)([^\]]+)(\])',
        content, re.DOTALL
    )
    
    if payloads_match:
        existing = payloads_match.group(2)
        new_payloads = []
        for p in payloads:
            escaped = p.replace('"', '\\"')
            if escaped not in existing:
                new_payloads.append(f'        "{escaped}"')
        
        if new_payloads:
            new_list = existing.rstrip() + ",\n" + ",\n".join(new_payloads)
            content = content[:payloads_match.start(2)] + new_list + content[payloads_match.end(2):]
            result["modified"] = True
            result["changes"].append(f"Added {len(new_payloads)} SSRF payloads")
    
    result["content"] = content
    return result


def _integrate_cmdi(content: str, payloads: list[str], patterns: list[str]) -> dict[str, Any]:
    result = {"modified": False, "content": content, "changes": []}
    
    payloads_match = re.search(
        r'((?:payloads|CMDI_PAYLOADS|cmd_payloads)\s*=\s*\[)([^\]]+)(\])',
        content, re.DOTALL
    )
    
    if payloads_match:
        existing = payloads_match.group(2)
        new_payloads = []
        for p in payloads:
            escaped = p.replace('"', '\\"')
            if escaped not in existing:
                new_payloads.append(f'        "{escaped}"')
        
        if new_payloads:
            new_list = existing.rstrip() + ",\n" + ",\n".join(new_payloads)
            content = content[:payloads_match.start(2)] + new_list + content[payloads_match.end(2):]
            result["modified"] = True
            result["changes"].append(f"Added {len(new_payloads)} CMDI payloads")
    
    result["content"] = content
    return result


def generate_improvement_report() -> str:
    improvements = load_all_improvements()
    
    if not improvements:
        return "No improvement suggestions found. Run scans with --smart-probe first."
    
    consolidated = consolidate_improvements(improvements)
    
    patches = []
    for finding_type, type_improvements in consolidated.items():
        patch = generate_lantern_patch(finding_type, type_improvements)
        patch["_raw_improvements"] = type_improvements
        patches.append(patch)
    
    patch_dir = save_patches(patches)
    
    lines = [
        "",
        "=" * 60,
        "AGENT BLACK IMPROVEMENT REPORT",
        "=" * 60,
        "",
        f"Total Unique Improvements: {sum(len(p['payloads_to_add']) for p in patches)}",
        f"Modules Affected: {len(patches)}",
        "",
        "Modules with improvements:",
    ]
    
    for patch in patches:
        lines.append(f"  → {patch['module'].upper()}: {len(patch['payloads_to_add'])} payloads, {len(patch['detection_patterns_to_add'])} patterns")
    
    lines.extend([
        "",
        f"📁 Patches saved to: {patch_dir}",
        "",
        "To apply improvements to Lantern:",
        f"  1. Review patches in {patch_dir}",
        f"  2. Run: agent-black --apply-improvements",
        "",
        "=" * 60,
    ])
    
    return "\n".join(lines)


def apply_improvements_to_lantern(lantern_path: Path | None = None, reinstall: bool = True) -> str:
    import subprocess
    
    lantern_path = lantern_path or LANTERN_PATH
    
    if not lantern_path.exists():
        return f"Error: Lantern path not found: {lantern_path}"
    
    improvements = load_all_improvements()
    
    if not improvements:
        return "No improvements to apply. Run scans with --smart-probe first."
    
    consolidated = consolidate_improvements(improvements)
    
    patches = []
    for finding_type, type_improvements in consolidated.items():
        patch = generate_lantern_patch(finding_type, type_improvements)
        patch["_raw_improvements"] = type_improvements
        patches.append(patch)
    
    lines = [
        "",
        "=" * 60,
        "APPLYING IMPROVEMENTS TO LANTERN",
        "=" * 60,
        "",
    ]
    
    results = apply_patches_to_lantern(patches, lantern_path)
    lines.extend(results)
    
    if reinstall:
        lines.append("")
        lines.append("🔄 Reinstalling Lantern via pipx to apply changes...")
        try:
            result = subprocess.run(
                ["pipx", "install", str(lantern_path), "--force"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                lines.append("✅ Lantern reinstalled successfully!")
                lines.append("   Changes are now active in the installed version.")
            else:
                lines.append(f"⚠️  pipx reinstall failed: {result.stderr[:200]}")
                lines.append("   Run manually: pipx install /path/to/lantern --force")
        except Exception as e:
            lines.append(f"⚠️  Could not reinstall: {e}")
            lines.append("   Run manually: pipx install /path/to/lantern --force")
    
    lines.extend([
        "",
        "=" * 60,
        "COMPLETE",
        "=" * 60,
        "",
        "Verification steps:",
        "  1. agent-black --verify-patches     (confirm code changes)",
        "  2. agent-black --validate-improvements http://target  (test it works)",
        "",
    ])
    
    return "\n".join(lines)


def show_improvement_diff(lantern_path: Path | None = None) -> str:
    lantern_path = lantern_path or LANTERN_PATH
    
    improvements = load_all_improvements()
    consolidated = consolidate_improvements(improvements)
    
    lines = [
        "",
        "=" * 60,
        "PROPOSED CHANGES TO LANTERN",
        "=" * 60,
        "",
    ]
    
    for finding_type, type_improvements in consolidated.items():
        patch = generate_lantern_patch(finding_type, type_improvements)
        target_file = lantern_path / patch["target_file"]
        
        lines.extend([
            f"### {finding_type.upper()} ({target_file})",
            "",
            "```python",
            patch["patch_content"],
            "```",
            "",
        ])
    
    return "\n".join(lines)


def verify_patches_applied(lantern_path: Path | None = None) -> dict[str, Any]:
    lantern_path = lantern_path or LANTERN_PATH
    
    result = {
        "verified": [],
        "not_found": [],
        "errors": [],
        "summary": "",
    }
    
    if not lantern_path.exists():
        result["errors"].append(f"Lantern path not found: {lantern_path}")
        return result
    
    improvements = load_all_improvements()
    consolidated = consolidate_improvements(improvements)
    
    for finding_type, type_improvements in consolidated.items():
        target_file = lantern_path / "modules" / f"{finding_type}.py"
        
        if not target_file.exists():
            alt_files = {
                "sensitive_file": "disclosure.py",
                "ssrf": "ssrf.py",
            }
            alt_name = alt_files.get(finding_type)
            if alt_name:
                target_file = lantern_path / "modules" / alt_name
        
        if not target_file.exists():
            result["not_found"].append({
                "module": finding_type,
                "expected_file": str(target_file),
            })
            continue
        
        try:
            content = target_file.read_text(encoding="utf-8")
            
            has_agent_black_marker = "AGENT BLACK IMPROVEMENTS" in content
            
            patch = generate_lantern_patch(finding_type, type_improvements)
            payloads_found = []
            payloads_missing = []
            
            for payload in patch["payloads_to_add"]:
                escaped_payload = re.escape(payload)
                if re.search(escaped_payload, content):
                    payloads_found.append(payload)
                else:
                    payloads_missing.append(payload)
            
            result["verified"].append({
                "module": finding_type,
                "file": str(target_file),
                "has_marker": has_agent_black_marker,
                "payloads_found": len(payloads_found),
                "payloads_missing": len(payloads_missing),
                "total_payloads": len(patch["payloads_to_add"]),
                "fully_applied": has_agent_black_marker and len(payloads_missing) == 0,
                "details": {
                    "found": payloads_found[:5],
                    "missing": payloads_missing[:5],
                }
            })
            
        except Exception as e:
            result["errors"].append({
                "module": finding_type,
                "error": str(e),
            })
    
    applied_count = sum(1 for v in result["verified"] if v["fully_applied"])
    total_count = len(result["verified"])
    
    result["summary"] = f"{applied_count}/{total_count} modules fully patched"
    
    return result


def print_verification_report(verification: dict[str, Any]) -> str:
    lines = [
        "",
        "=" * 60,
        "PATCH VERIFICATION REPORT",
        "=" * 60,
        "",
        f"Summary: {verification['summary']}",
        "",
    ]
    
    if verification["verified"]:
        lines.append("Verified Modules:")
        for v in verification["verified"]:
            status = "✅ APPLIED" if v["fully_applied"] else "⚠️  PARTIAL" if v["has_marker"] else "❌ NOT APPLIED"
            lines.append(f"  {v['module'].upper()}: {status}")
            lines.append(f"    File: {v['file']}")
            lines.append(f"    Payloads: {v['payloads_found']}/{v['total_payloads']} present")
            if v["details"]["missing"]:
                lines.append(f"    Missing: {v['details']['missing'][:3]}...")
            lines.append("")
    
    if verification["not_found"]:
        lines.append("Modules Not Found:")
        for nf in verification["not_found"]:
            lines.append(f"  ⚠️  {nf['module']}: {nf['expected_file']}")
        lines.append("")
    
    if verification["errors"]:
        lines.append("Errors:")
        for err in verification["errors"]:
            lines.append(f"  ❌ {err}")
        lines.append("")
    
    lines.append("=" * 60)
    
    return "\n".join(lines)


def validate_improvements(target: str, lantern_path: Path | None = None) -> dict[str, Any]:
    import subprocess
    try:
        import requests
    except ImportError:
        print("[!] requests not installed. Run: pip install requests")
        return {"error": "requests not installed"}
    
    lantern_path = lantern_path or LANTERN_PATH
    
    result = {
        "target": target,
        "tests_run": 0,
        "tests_passed": 0,
        "tests_failed": 0,
        "validation_results": [],
        "before_after": [],
    }
    
    improvements = load_all_improvements()
    consolidated = consolidate_improvements(improvements)
    
    print(f"\n🧪 VALIDATING IMPROVEMENTS against {target}")
    print("=" * 60)
    
    for finding_type, type_improvements in consolidated.items():
        patch = generate_lantern_patch(finding_type, type_improvements)
        
        for payload in patch["payloads_to_add"][:3]:
            result["tests_run"] += 1
            
            test_result = {
                "module": finding_type,
                "payload": payload,
                "lantern_detected": False,
                "manual_works": False,
                "improvement_needed": False,
            }
            
            print(f"\n  Testing {finding_type.upper()}: {payload[:40]}...")
            
            try:
                test_url = f"{target}/search?q={requests.utils.quote(payload)}"
                resp = requests.get(test_url, timeout=5)
                
                for pattern in patch["detection_patterns_to_add"]:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        test_result["manual_works"] = True
                        break
            except:
                pass
            
            try:
                lantern_cmd = [
                    "lantern", "-t", target,
                    "--modules", finding_type,
                    "--format", "json",
                    "-o", "/tmp/validation_test"
                ]
                
                proc = subprocess.run(
                    lantern_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                
                if Path("/tmp/validation_test.json").exists():
                    report = json.loads(Path("/tmp/validation_test.json").read_text())
                    findings = report.get("findings", [])
                    
                    for finding in findings:
                        if payload in str(finding.get("evidence", "")):
                            test_result["lantern_detected"] = True
                            break
            except:
                pass
            
            if test_result["manual_works"] and not test_result["lantern_detected"]:
                test_result["improvement_needed"] = True
                result["tests_failed"] += 1
                print(f"    ❌ Payload works but Lantern doesn't detect it")
            elif test_result["lantern_detected"]:
                result["tests_passed"] += 1
                print(f"    ✅ Lantern now detects this!")
            else:
                print(f"    ⚪ Not applicable to this target")
            
            result["validation_results"].append(test_result)
    
    return result


def print_validation_report(validation: dict[str, Any]) -> str:
    lines = [
        "",
        "=" * 60,
        "IMPROVEMENT VALIDATION REPORT",
        "=" * 60,
        "",
        f"Target: {validation['target']}",
        f"Tests Run: {validation['tests_run']}",
        f"Tests Passed: {validation['tests_passed']}",
        f"Tests Failed: {validation['tests_failed']}",
        "",
    ]
    
    if validation["validation_results"]:
        lines.append("Results by Module:")
        
        by_module = {}
        for vr in validation["validation_results"]:
            module = vr["module"]
            if module not in by_module:
                by_module[module] = {"passed": 0, "failed": 0, "na": 0}
            
            if vr["lantern_detected"]:
                by_module[module]["passed"] += 1
            elif vr["improvement_needed"]:
                by_module[module]["failed"] += 1
            else:
                by_module[module]["na"] += 1
        
        for module, counts in by_module.items():
            status = "✅" if counts["failed"] == 0 and counts["passed"] > 0 else "⚠️" if counts["passed"] > 0 else "❌"
            lines.append(f"  {status} {module.upper()}: {counts['passed']} passed, {counts['failed']} need improvement, {counts['na']} N/A")
    
    lines.extend([
        "",
        "=" * 60,
    ])
    
    return "\n".join(lines)


def full_improvement_cycle(target: str, lantern_path: Path | None = None) -> str:
    lantern_path = lantern_path or LANTERN_PATH
    
    lines = [
        "",
        "=" * 70,
        "AGENT BLACK FULL IMPROVEMENT CYCLE",
        "=" * 70,
        "",
    ]
    
    lines.append("📊 STEP 1: Checking existing improvements...")
    improvements = load_all_improvements()
    lines.append(f"   Found {len(improvements)} improvement suggestions")
    lines.append("")
    
    lines.append("🔍 STEP 2: Verifying current patch status...")
    verification = verify_patches_applied(lantern_path)
    applied = sum(1 for v in verification["verified"] if v["fully_applied"])
    total = len(verification["verified"])
    lines.append(f"   Patches applied: {applied}/{total} modules")
    lines.append("")
    
    if applied < total:
        lines.append("📝 STEP 3: Generating patches...")
        consolidated = consolidate_improvements(improvements)
        patches = []
        for finding_type, type_improvements in consolidated.items():
            patch = generate_lantern_patch(finding_type, type_improvements)
            patches.append(patch)
        patch_dir = save_patches(patches)
        lines.append(f"   Patches saved to: {patch_dir}")
        lines.append("")
        
        lines.append("   ⚠️  Patches not yet applied. Run:")
        lines.append("      agent-black --apply-improvements")
        lines.append("")
    
    lines.append("🧪 STEP 4: Validation status...")
    if target:
        lines.append(f"   Target available: {target}")
        lines.append("   Run validation with: agent-black --validate-improvements <target>")
    else:
        lines.append("   No target specified for validation")
    lines.append("")
    
    lines.append("📋 SUMMARY:")
    lines.append(f"   • Improvements collected: {len(improvements)}")
    lines.append(f"   • Modules with patches: {total}")
    lines.append(f"   • Patches applied: {applied}")
    lines.append(f"   • Patches pending: {total - applied}")
    lines.append("")
    
    if applied < total:
        lines.append("🔄 NEXT STEPS:")
        lines.append("   1. Review: agent-black --diff-improvements")
        lines.append("   2. Apply:  agent-black --apply-improvements")
        lines.append("   3. Verify: agent-black --verify-patches")
        lines.append("   4. Test:   agent-black --validate-improvements http://target")
    else:
        lines.append("✅ All patches applied!")
        lines.append("   Run: agent-black --validate-improvements http://target")
        lines.append("   to test the improvements")
    
    lines.extend([
        "",
        "=" * 70,
    ])
    
    return "\n".join(lines)


if __name__ == "__main__":
    print(generate_improvement_report())
