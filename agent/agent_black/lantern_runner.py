import json
import subprocess
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_black.learning import record_scan_result


RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

LANTERN_REPORTS_DIR = RESULTS_DIR / "lantern_reports"
LANTERN_REPORTS_DIR.mkdir(exist_ok=True)


def run_lantern(cmd: list[str], capture_output: bool = True) -> tuple[int, dict[str, Any]]:
    scan_result: dict[str, Any] = {}
    
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_base = LANTERN_REPORTS_DIR / f"report_{timestamp}"
    
    enhanced_cmd = cmd.copy()
    if "-o" not in enhanced_cmd and "--output" not in enhanced_cmd:
        enhanced_cmd.extend(["-o", str(report_base)])
    if "--format" not in enhanced_cmd:
        enhanced_cmd.extend(["--format", "json"])
    
    try:
        if capture_output:
            result = subprocess.run(
                enhanced_cmd,
                check=False,
                capture_output=True,
                text=True,
            )
            print(result.stdout)
            if result.stderr:
                print(result.stderr)
            
            scan_result = parse_lantern_output(result.stdout, result.stderr, cmd)
            
            json_report = Path(str(report_base) + ".json")
            if json_report.exists():
                detailed_findings = parse_lantern_json_report(json_report)
                scan_result["detailed_findings"] = detailed_findings.get("findings", [])
                scan_result["exploited_data"] = detailed_findings.get("exploited_data", [])
                scan_result["flags_found"] = detailed_findings.get("flags", [])
                scan_result["secrets_found"] = detailed_findings.get("secrets", [])
                
                if scan_result["flags_found"]:
                    print(f"\n🚩 FLAGS CAPTURED: {len(scan_result['flags_found'])}")
                    for flag in scan_result["flags_found"]:
                        print(f"   → {flag}")
                
                if scan_result["secrets_found"]:
                    print(f"\n🔑 SECRETS EXTRACTED: {len(scan_result['secrets_found'])}")
                    for secret in scan_result["secrets_found"][:5]:
                        print(f"   → {secret[:80]}...")
            
            save_scan_result(cmd, scan_result)
            print_summary(scan_result)
            
            return result.returncode, scan_result
        else:
            result = subprocess.run(enhanced_cmd, check=False)
            return result.returncode, scan_result
    except FileNotFoundError:
        print("LANTERN executable not found. Ensure it is installed and in PATH.")
        return 127, scan_result
    except Exception as exc:
        print(f"Failed to run LANTERN: {exc}")
        return 1, scan_result


def parse_lantern_json_report(report_path: Path) -> dict[str, Any]:
    result = {
        "findings": [],
        "exploited_data": [],
        "flags": [],
        "secrets": [],
    }
    
    try:
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        
        findings = report_data.get("findings", report_data.get("vulnerabilities", []))
        result["findings"] = findings
        
        for finding in findings:
            evidence = finding.get("evidence", "") or finding.get("proof", "") or ""
            extracted = finding.get("extracted_data", "") or finding.get("exploit_data", "") or ""
            response = finding.get("response", "") or ""
            
            all_text = f"{evidence} {extracted} {response}"
            
            flags = re.findall(r"(?:BLACKFLAG|FLAG|flag|CTF)\{[^}]+\}", all_text, re.IGNORECASE)
            result["flags"].extend(flags)
            
            secrets = []
            secret_patterns = [
                r"(?:password|passwd|pwd)[:\s=]+['\"]?([^\s'\"<>]{4,50})",
                r"(?:api[_-]?key|apikey)[:\s=]+['\"]?([^\s'\"<>]{10,100})",
                r"(?:secret|token)[:\s=]+['\"]?([^\s'\"<>]{10,100})",
                r"(?:AWS|aws)[_-]?(?:ACCESS|SECRET)[_-]?(?:KEY|ID)[:\s=]+['\"]?([A-Z0-9]{16,40})",
                r"-----BEGIN[^-]+-----[^-]+-----END[^-]+-----",
            ]
            for pattern in secret_patterns:
                matches = re.findall(pattern, all_text, re.IGNORECASE)
                if matches:
                    if isinstance(matches[0], str):
                        secrets.extend(matches)
                    else:
                        secrets.extend([m[0] if isinstance(m, tuple) else m for m in matches])
            
            result["secrets"].extend(secrets)
            
            if finding.get("exploited") or finding.get("exploit_success"):
                result["exploited_data"].append({
                    "type": finding.get("type", finding.get("vulnerability_type", "unknown")),
                    "url": finding.get("url", ""),
                    "data": extracted[:500] if extracted else evidence[:500],
                })
        
        result["flags"] = list(set(result["flags"]))
        result["secrets"] = list(set(result["secrets"]))
        
    except Exception as e:
        pass
    
    return result


def parse_lantern_output(stdout: str, stderr: str, cmd: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "command": cmd,
        "raw_stdout": stdout,
        "raw_stderr": stderr,
        "findings": [],
        "severity_counts": {},
        "total_findings": 0,
        "targets_scanned": 0,
        "modules_run": [],
        "critical_high_count": 0,
        "next_actions": [],
    }
    
    target = None
    for i, arg in enumerate(cmd):
        if arg in ("-t", "--target") and i + 1 < len(cmd):
            target = cmd[i + 1]
            break
    result["target"] = target
    
    severity_match = re.search(r"CRITICAL\s*│\s*(\d+)", stdout)
    if severity_match:
        result["severity_counts"]["CRITICAL"] = int(severity_match.group(1))
    
    severity_match = re.search(r"HIGH\s*│\s*(\d+)", stdout)
    if severity_match:
        result["severity_counts"]["HIGH"] = int(severity_match.group(1))
    
    severity_match = re.search(r"MEDIUM\s*│\s*(\d+)", stdout)
    if severity_match:
        result["severity_counts"]["MEDIUM"] = int(severity_match.group(1))
    
    severity_match = re.search(r"LOW\s*│\s*(\d+)", stdout)
    if severity_match:
        result["severity_counts"]["LOW"] = int(severity_match.group(1))
    
    severity_match = re.search(r"INFO\s*│\s*(\d+)", stdout)
    if severity_match:
        result["severity_counts"]["INFO"] = int(severity_match.group(1))
    
    total_match = re.search(r"Found\s+(\d+)\s+potential\s+vulnerabilit", stdout)
    if total_match:
        result["total_findings"] = int(total_match.group(1))
    
    targets_match = re.search(r"Target\(s\):\s*(\d+)", stdout)
    if targets_match:
        result["targets_scanned"] = int(targets_match.group(1))
    
    modules_match = re.search(r"Modules:\s*\d+\s*\(([^)]+)\)", stdout)
    if modules_match:
        modules_str = modules_match.group(1).replace("...", "").strip()
        result["modules_run"] = [m.strip() for m in modules_str.split(",") if m.strip()]
    
    critical = result["severity_counts"].get("CRITICAL", 0)
    high = result["severity_counts"].get("HIGH", 0)
    result["critical_high_count"] = critical + high
    
    return result


def determine_next_actions(scan_result: dict[str, Any], cmd: list[str], iteration: int = 1) -> list[dict[str, Any]]:
    actions = []
    counts = scan_result.get("severity_counts", {})
    modules_run = scan_result.get("modules_run", [])
    total = scan_result.get("total_findings", 0)
    target = scan_result.get("target")
    
    cmd_str = " ".join(cmd)
    has_exploit = "--exploit" in cmd_str
    has_aggressive = "--aggressive" in cmd_str
    has_deep = "--deep" in cmd_str
    has_crawl = "--crawl" in cmd_str
    
    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    medium = counts.get("MEDIUM", 0)
    low = counts.get("LOW", 0)
    info = counts.get("INFO", 0)
    
    real_vulns = critical + high + medium + low
    
    injection_modules = ["sqli", "xss", "cmdi", "ssti", "lfi", "xxe", "ssrf"]
    recon_modules = ["fingerprint", "techdetect", "dirbust", "secrets", "disclosure"]
    cookie_modules = ["cookie", "cors", "headers", "jwt", "session"]
    advanced_modules = ["graphql", "prototype", "deserial", "race", "jwt", "websocket"]
    
    ran_injection = any(m in modules_run for m in injection_modules)
    ran_recon = any(m in modules_run for m in recon_modules)
    ran_advanced = any(m in modules_run for m in advanced_modules)
    
    if critical > 0:
        if not has_exploit:
            actions.append({
                "action": "exploit_critical",
                "reason": f"🔴 {critical} CRITICAL vulns found - EXPLOITING to extract data",
                "flags": ["--exploit", "--aggressive"],
                "priority": 1,
            })
        elif iteration == 1:
            actions.append({
                "action": "deep_exploit",
                "reason": f"🔴 {critical} CRITICAL vulns - running DEEP exploitation for maximum extraction",
                "flags": ["--exploit", "--deep", "--aggressive"],
                "priority": 1,
            })
    
    if high > 0 and not has_exploit:
        actions.append({
            "action": "exploit_high", 
            "reason": f"🟠 {high} HIGH severity vulns - attempting exploitation",
            "flags": ["--exploit"],
            "priority": 2,
        })
    
    if critical > 0 and has_exploit and not has_crawl and iteration < 3:
        actions.append({
            "action": "crawl_for_more",
            "reason": "🔍 Crawling to find MORE vulnerable endpoints to exploit",
            "flags": ["--exploit", "--crawl", "--crawl-depth", "3", "--aggressive"],
            "priority": 3,
        })
    
    if real_vulns > 0 and not ran_advanced and iteration < 4:
        missing_advanced = [m for m in advanced_modules if m not in modules_run]
        if missing_advanced:
            actions.append({
                "action": "try_advanced",
                "reason": f"🧪 Trying advanced attack modules: {', '.join(missing_advanced[:4])}",
                "modules": missing_advanced[:4],
                "flags": ["--exploit", "--aggressive"],
                "priority": 4,
            })
    
    if real_vulns == 0 and not ran_injection:
        missing_injection = [m for m in injection_modules if m not in modules_run]
        if missing_injection:
            actions.append({
                "action": "try_injection",
                "reason": f"No vulns yet - trying injection modules: {', '.join(missing_injection)}",
                "modules": missing_injection,
                "flags": ["--aggressive", "--deep"],
                "priority": 5,
            })
    
    if real_vulns == 0 and ran_injection and not has_crawl:
        actions.append({
            "action": "crawl_discover",
            "reason": "No vulns found - crawling to discover more endpoints",
            "flags": ["--crawl", "--crawl-depth", "3", "--aggressive"],
            "priority": 6,
        })
    
    if total == 0 and not has_deep and not has_aggressive:
        actions.append({
            "action": "deep_scan",
            "reason": "Nothing found - running deep aggressive scan",
            "flags": ["--deep", "--aggressive", "--crawl"],
            "priority": 7,
        })
    
    if info > 0 and real_vulns == 0 and not ran_recon:
        missing_recon = [m for m in recon_modules if m not in modules_run]
        if missing_recon:
            actions.append({
                "action": "expand_recon",
                "reason": f"Only INFO findings - expanding recon: {', '.join(missing_recon)}",
                "modules": missing_recon,
                "priority": 8,
            })
    
    if real_vulns == 0 and not any(m in modules_run for m in cookie_modules):
        missing_cookie = [m for m in cookie_modules if m not in modules_run]
        if missing_cookie:
            actions.append({
                "action": "check_cookies_auth",
                "reason": f"Checking cookie/auth weaknesses: {', '.join(missing_cookie)}",
                "modules": missing_cookie,
                "priority": 7,
            })
    
    if total > 0 and "sqli" in modules_run and not has_exploit:
        actions.append({
            "action": "exploit_sqli",
            "reason": "SQL injection tested - attempting data extraction",
            "flags": ["--exploit"],
            "modules": ["sqli"],
            "priority": 8,
        })
    
    if medium > 0 and not has_exploit:
        actions.append({
            "action": "exploit_medium",
            "reason": "MEDIUM severity issues found - attempting exploitation for validation",
            "flags": ["--exploit"],
            "priority": 9,
        })
    
    actions.sort(key=lambda x: x.get("priority", 99))
    return actions[:3]


def save_scan_result(cmd: list[str], scan_result: dict[str, Any]) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    result_file = RESULTS_DIR / f"scan_{timestamp}.json"
    
    payload = {
        "command": cmd,
        "result": scan_result,
    }
    
    result_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    
    try:
        target = scan_result.get("target", "")
        modules_run = scan_result.get("modules_run", [])
        findings = scan_result.get("severity_counts", {})
        
        flags_found = extract_flags_from_output(scan_result.get("raw_stdout", ""))
        successful_exploits = extract_exploits_from_output(scan_result.get("raw_stdout", ""))
        tech_detected = extract_tech_from_output(scan_result.get("raw_stdout", ""))
        
        if target:
            record_scan_result(
                target=target,
                modules_used=modules_run,
                findings=findings,
                flags_found=flags_found,
                successful_exploits=successful_exploits,
                tech_detected=tech_detected,
            )
    except Exception:
        pass
    
    return result_file


def extract_flags_from_output(stdout: str) -> list[str]:
    flags = re.findall(r"BLACKFLAG\{[^}]+\}", stdout)
    flags += re.findall(r"FLAG\{[^}]+\}", stdout)
    flags += re.findall(r"flag\{[^}]+\}", stdout, re.IGNORECASE)
    return list(set(flags))


def extract_exploits_from_output(stdout: str) -> list[dict[str, Any]]:
    exploits = []
    
    exploit_patterns = [
        (r"\[EXPLOIT\]\s*(\w+).*?payload[:\s]+([^\n]+)", "exploit"),
        (r"\[SQLi\].*?extracted[:\s]+([^\n]+)", "sqli"),
        (r"\[XSS\].*?confirmed[:\s]+([^\n]+)", "xss"),
        (r"\[RCE\].*?command[:\s]+([^\n]+)", "cmdi"),
        (r"\[LFI\].*?file[:\s]+([^\n]+)", "lfi"),
        (r"\[SSRF\].*?url[:\s]+([^\n]+)", "ssrf"),
    ]
    
    for pattern, module in exploit_patterns:
        matches = re.findall(pattern, stdout, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                exploits.append({"module": module, "payload": match[-1]})
            else:
                exploits.append({"module": module, "payload": match})
    
    return exploits


def extract_tech_from_output(stdout: str) -> list[str]:
    tech = []
    
    tech_pattern = r"(?:Technology|Framework|Server|CMS)[:\s]+([^\n,]+)"
    matches = re.findall(tech_pattern, stdout, re.IGNORECASE)
    tech.extend(m.strip() for m in matches if m.strip())
    
    common_tech = [
        "Flask", "Django", "Express", "Node.js", "PHP", "Apache",
        "Nginx", "WordPress", "Joomla", "Drupal", "React", "Angular",
        "Vue", "jQuery", "Bootstrap", "ASP.NET", "Spring", "Laravel",
        "Ruby on Rails", "Tomcat", "IIS", "GraphQL", "REST API",
    ]
    
    for t in common_tech:
        if t.lower() in stdout.lower():
            tech.append(t)
    
    return list(set(tech))


def print_summary(scan_result: dict[str, Any]) -> None:
    print("\n" + "=" * 60)
    print("AGENT BLACK SCAN SUMMARY")
    print("=" * 60)
    
    counts = scan_result.get("severity_counts", {})
    total = scan_result.get("total_findings", 0)
    
    print(f"\nTotal Findings: {total}")
    if counts:
        print("\nBy Severity:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                print(f"  {sev}: {counts[sev]}")
    
    critical_high = scan_result.get("critical_high_count", 0)
    if critical_high > 0:
        print(f"\n⚠️  {critical_high} CRITICAL/HIGH findings require immediate attention!")
    
    flags = scan_result.get("flags_found", [])
    if flags:
        print(f"\n🚩 FLAGS CAPTURED ({len(flags)}):")
        for flag in flags:
            print(f"   🏴 {flag}")
    
    secrets = scan_result.get("secrets_found", [])
    if secrets:
        print(f"\n🔑 SECRETS EXTRACTED ({len(secrets)}):")
        for secret in secrets[:10]:
            display = secret[:60] + "..." if len(secret) > 60 else secret
            print(f"   → {display}")
    
    exploited = scan_result.get("exploited_data", [])
    if exploited:
        print(f"\n💀 EXPLOITED ({len(exploited)}):")
        for exp in exploited[:5]:
            print(f"   → {exp.get('type', 'unknown')}: {exp.get('url', '')[:50]}")
    
    print("\n" + "=" * 60)


def get_latest_result() -> dict[str, Any] | None:
    if not RESULTS_DIR.exists():
        return None
    
    result_files = sorted(RESULTS_DIR.glob("scan_*.json"), reverse=True)
    if not result_files:
        return None
    
    try:
        return json.loads(result_files[0].read_text(encoding="utf-8"))
    except Exception:
        return None


def get_all_results(limit: int = 10) -> list[dict[str, Any]]:
    if not RESULTS_DIR.exists():
        return []
    
    result_files = sorted(RESULTS_DIR.glob("scan_*.json"), reverse=True)[:limit]
    results = []
    
    for f in result_files:
        try:
            results.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    
    return results
