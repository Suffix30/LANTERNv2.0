#!/usr/bin/env python3
"""
Agent BLACK - Overwatch Mode

Situational awareness system that monitors:
- All terminals
- Browser tabs (via extension)
- Open files
- Tool outputs
- Scan reports

Then synthesizes everything to understand your current problem
and provide contextual assistance.

Usage:
    python black_overwatch.py              # Start monitoring
    python black_overwatch.py --snapshot   # One-time analysis
"""

import sys
import os
import json
import time
import glob
import subprocess
import platform
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.agent_black import AgentBlack


def safe_print(text: str):
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode('ascii', 'replace').decode('ascii'))


def sanitize_text(text: str) -> str:
    return text.encode('ascii', 'replace').decode('ascii')


class OverwatchSystem:
    def __init__(self, load_model=False):
        print("[*] Initializing Agent BLACK Overwatch Mode...")
        self.agent = None
        self.llm_available = False
        
        if load_model:
            try:
                self.agent = AgentBlack(load_model=True)
                self.llm_available = self.agent.model_loaded
                if self.llm_available:
                    print("[+] LLM loaded - full analysis available")
                else:
                    print("[!] LLM not loaded - using fallback analysis")
            except Exception as e:
                print(f"[!] Could not load LLM: {e}")
                print("[*] Continuing with fallback analysis...")
        else:
            print("[*] Running in fast mode (no LLM)")
        
        self.context = {
            "terminals": [],
            "browser_tabs": [],
            "open_files": [],
            "recent_reports": [],
            "running_tools": [],
            "clipboard": None,
            "timestamp": None,
        }
        
    def gather_terminal_context(self) -> List[Dict]:
        terminals = []
        
        terminals.extend(self._read_ide_terminals())
        terminals.extend(self._read_shell_history())
        terminals.extend(self._read_custom_logs())
        
        return terminals
    
    def _read_ide_terminals(self) -> List[Dict]:
        terminals = []
        
        ide_paths = [
            Path.home() / ".cursor" / "projects",
            Path.home() / ".vscode-server" / "data" / "logs",
        ]
        
        for ide_base in ide_paths:
            if not ide_base.exists():
                continue
            
            for project_dir in ide_base.iterdir():
                term_dir = project_dir / "terminals"
                if not term_dir.exists():
                    continue
                
                for term_file in term_dir.glob("*.txt"):
                    try:
                        content = term_file.read_text(encoding="utf-8", errors="ignore")
                        lines = content.split("\n")
                        
                        cwd = "unknown"
                        last_cmd = "unknown"
                        exit_code = "unknown"
                        for line in lines[:30]:
                            if line.startswith("cwd:"):
                                cwd = line.split(":", 1)[1].strip().strip('"')
                            elif line.startswith("last_command:"):
                                last_cmd = line.split(":", 1)[1].strip().strip('"')
                            elif line.startswith("last_exit_code:"):
                                exit_code = line.split(":", 1)[1].strip()
                        
                        recent_output = "\n".join(lines[-100:])
                        
                        terminals.append({
                            "id": term_file.stem,
                            "source": "ide",
                            "cwd": cwd,
                            "last_command": last_cmd,
                            "exit_code": exit_code,
                            "recent_output": recent_output,
                            "full_content": content[-5000:],
                        })
                    except:
                        pass
        
        return terminals
    
    def _read_shell_history(self) -> List[Dict]:
        terminals = []
        
        history_files = [
            (Path.home() / ".bash_history", "bash"),
            (Path.home() / ".zsh_history", "zsh"),
            (Path.home() / ".local" / "share" / "fish" / "fish_history", "fish"),
            (Path.home() / ".histfile", "zsh"),
        ]
        
        if os.name == "nt":
            ps_history = Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
            history_files.append((ps_history, "powershell"))
        
        for hist_path, shell_name in history_files:
            if not hist_path.exists():
                continue
            
            try:
                content = hist_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.strip().split("\n")
                
                recent_commands = []
                for line in lines[-50:]:
                    line = line.strip()
                    if line.startswith(": ") and ";" in line:
                        line = line.split(";", 1)[1]
                    if line and not line.startswith("#"):
                        recent_commands.append(line)
                
                if recent_commands:
                    terminals.append({
                        "id": f"{shell_name}_history",
                        "source": "shell_history",
                        "cwd": str(Path.cwd()),
                        "last_command": recent_commands[-1] if recent_commands else "unknown",
                        "exit_code": "unknown",
                        "recent_output": "\n".join(recent_commands[-30:]),
                        "full_content": "\n".join(recent_commands[-100:]),
                    })
            except:
                pass
        
        return terminals
    
    def _read_custom_logs(self) -> List[Dict]:
        terminals = []
        
        custom_log_paths = [
            Path.home() / ".agent_black" / "terminal_logs",
            Path.home() / ".config" / "agent_black" / "logs",
            Path("/tmp") / "agent_black_logs",
        ]
        
        env_log_dir = os.environ.get("BLACK_TERMINAL_LOGS")
        if env_log_dir:
            custom_log_paths.insert(0, Path(env_log_dir))
        
        for log_dir in custom_log_paths:
            if not log_dir.exists():
                continue
            
            for log_file in sorted(log_dir.glob("*.log"), key=lambda x: x.stat().st_mtime, reverse=True)[:5]:
                try:
                    content = log_file.read_text(encoding="utf-8", errors="ignore")
                    lines = content.split("\n")
                    
                    terminals.append({
                        "id": log_file.stem,
                        "source": "custom_log",
                        "cwd": str(log_dir),
                        "last_command": "unknown",
                        "exit_code": "unknown",
                        "recent_output": "\n".join(lines[-100:]),
                        "full_content": content[-5000:],
                    })
                except:
                    pass
        
        return terminals
    
    def gather_browser_context(self) -> List[Dict]:
        tabs = []
        
        browser_state = Path.home() / ".agent_black" / "browser_state.json"
        if browser_state.exists():
            try:
                data = json.loads(browser_state.read_text())
                tabs = data.get("tabs", [])
            except:
                pass
        
        return tabs
    
    def gather_file_context(self) -> List[Dict]:
        files = []
        
        recent_patterns = [
            "**/*_report*.json",
            "**/*_report*.html",
            "**/*_report*.md",
            "**/scan_*.json",
            "**/results*.json",
            "**/output*.txt",
            "**/findings*.json",
        ]
        
        search_dirs = [
            Path.cwd(),
            Path.home() / "Downloads",
            Path.home() / "Documents",
        ]
        
        for search_dir in search_dirs:
            if not search_dir.exists():
                continue
            for pattern in recent_patterns:
                for f in search_dir.glob(pattern):
                    try:
                        stat = f.stat()
                        if time.time() - stat.st_mtime < 3600:
                            files.append({
                                "path": str(f),
                                "name": f.name,
                                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                "size": stat.st_size,
                                "preview": f.read_text(errors="ignore")[:2000] if stat.st_size < 100000 else "[large file]",
                            })
                    except:
                        pass
        
        return files[:20]
    
    def gather_running_tools(self) -> List[Dict]:
        tools = []
        known_tools = [
            "nmap", "nikto", "dirb", "gobuster", "ffuf", "sqlmap", "burp",
            "hydra", "john", "hashcat", "metasploit", "msfconsole",
            "wireshark", "tcpdump", "responder", "bloodhound",
            "nuclei", "httpx", "subfinder", "amass", "lantern",
        ]
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["tasklist"], capture_output=True, text=True)
                processes = result.stdout.lower()
            else:
                result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
                processes = result.stdout.lower()
            
            for tool in known_tools:
                if tool in processes:
                    tools.append({"name": tool, "running": True})
        except:
            pass
        
        return tools
    
    def get_clipboard(self) -> Optional[str]:
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["powershell", "-command", "Get-Clipboard"], 
                                       capture_output=True, text=True)
                return result.stdout.strip()[:1000]
        except:
            pass
        return None
    
    def gather_all_context(self) -> Dict:
        print("[*] Gathering context from all sources...")
        
        print("  - Scanning terminals...")
        self.context["terminals"] = self.gather_terminal_context()
        print(f"    Found {len(self.context['terminals'])} terminals")
        
        print("  - Checking browser state...")
        self.context["browser_tabs"] = self.gather_browser_context()
        print(f"    Found {len(self.context['browser_tabs'])} tabs")
        
        print("  - Finding recent files...")
        self.context["recent_reports"] = self.gather_file_context()
        print(f"    Found {len(self.context['recent_reports'])} recent files")
        
        print("  - Checking running tools...")
        self.context["running_tools"] = self.gather_running_tools()
        print(f"    Found {len(self.context['running_tools'])} security tools")
        
        print("  - Reading clipboard...")
        self.context["clipboard"] = self.get_clipboard()
        
        self.context["timestamp"] = datetime.now().isoformat()
        
        return self.context
    
    def build_situation_summary(self) -> str:
        summary_parts = []
        
        summary_parts.append("=" * 60)
        summary_parts.append("  AGENT BLACK - OVERWATCH REPORT")
        summary_parts.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary_parts.append("=" * 60)
        summary_parts.append("")
        
        summary_parts.append(f"Terminals scanned: {len(self.context['terminals'])}")
        summary_parts.append(f"Browser tabs: {len(self.context['browser_tabs'])}")
        summary_parts.append(f"Recent files: {len(self.context['recent_reports'])}")
        summary_parts.append(f"Active tools: {len(self.context['running_tools'])}")
        summary_parts.append("")
        
        if self.context["terminals"]:
            summary_parts.append("-" * 60)
            summary_parts.append("TERMINAL ACTIVITY")
            summary_parts.append("-" * 60)
            
            for term in self.context["terminals"][:12]:
                cwd = term.get('cwd', 'unknown')
                if '\\' in cwd:
                    cwd_short = cwd.split('\\')[-1]
                elif '/' in cwd:
                    cwd_short = cwd.split('/')[-1]
                else:
                    cwd_short = cwd
                
                if not cwd_short or cwd_short == "unknown":
                    cwd_short = f"Terminal-{term.get('id', '?')}"
                
                last_cmd = term.get('last_command', '')
                exit_code = term.get('exit_code', '')
                output = term.get('recent_output', '')
                
                summary_parts.append("")
                summary_parts.append(f"[{sanitize_text(cwd_short)}]")
                summary_parts.append(f"  Dir: {sanitize_text(cwd)}")
                if last_cmd and last_cmd != "unknown":
                    summary_parts.append(f"  Cmd: {sanitize_text(last_cmd)[:80]}")
                if exit_code and exit_code != "unknown":
                    summary_parts.append(f"  Exit: {exit_code}")
                
                output_lines = self._extract_useful_output(output)
                if output_lines:
                    summary_parts.append("  Output:")
                    for line in output_lines[:8]:
                        summary_parts.append(f"    {line}")
        
        if self.context["running_tools"]:
            summary_parts.append("")
            summary_parts.append("-" * 60)
            summary_parts.append("ACTIVE SECURITY TOOLS")
            summary_parts.append("-" * 60)
            for tool in self.context["running_tools"]:
                summary_parts.append(f"  - {tool['name']}")
        
        if self.context["browser_tabs"]:
            summary_parts.append("")
            summary_parts.append("-" * 60)
            summary_parts.append("BROWSER TABS")
            summary_parts.append("-" * 60)
            for tab in self.context["browser_tabs"][:10]:
                title = tab.get('title', 'Unknown')[:40]
                url = tab.get('url', 'Unknown')
                summary_parts.append(f"  {title}")
                summary_parts.append(f"    {url}")
        
        if self.context["recent_reports"]:
            summary_parts.append("")
            summary_parts.append("-" * 60)
            summary_parts.append("RECENT FILES")
            summary_parts.append("-" * 60)
            for f in self.context["recent_reports"][:5]:
                summary_parts.append(f"  - {f['name']} ({f['modified'][:10]})")
        
        if self.context["clipboard"]:
            clip = sanitize_text(self.context["clipboard"])
            if len(clip) > 100:
                clip = clip[:100] + "..."
            summary_parts.append("")
            summary_parts.append("-" * 60)
            summary_parts.append("CLIPBOARD")
            summary_parts.append("-" * 60)
            summary_parts.append(f"  {clip}")
        
        summary_parts.append("")
        summary_parts.append("=" * 60)
        
        return "\n".join(summary_parts)
    
    def _extract_useful_output(self, output: str) -> List[str]:
        if not output:
            return []
        
        skip_exact = ["---", ""]
        skip_starts = ["pid:", "started_at:", "running_for_seconds:", "elapsed_ms:", "ended_at:"]
        
        lines = output.split("\n")
        useful = []
        
        for line in lines:
            line_stripped = line.strip()
            
            if not line_stripped or line_stripped in skip_exact:
                continue
            
            line_lower = line_stripped.lower()
            if any(line_lower.startswith(p) for p in skip_starts):
                continue
            
            cleaned = sanitize_text(line_stripped)
            if cleaned and len(cleaned) > 2:
                if len(cleaned) > 120:
                    cleaned = cleaned[:120] + "..."
                useful.append(cleaned)
        
        return useful[-15:]
    
    def analyze_situation(self) -> str:
        self.gather_all_context()
        situation = self.build_situation_summary()
        
        if not self.llm_available or not self.agent:
            return self._fallback_analysis(situation)
        
        prompt = f"""You are Agent BLACK in Overwatch Mode. You have full situational awareness of the operator's current work environment.

CURRENT SITUATION:
{situation}

Based on everything you can see:
1. What is the operator currently working on? (CTF, bug bounty, pentest, etc.)
2. What is their current target/objective?
3. What have they tried so far?
4. Where do they appear to be stuck or what's their next step?
5. What specific actionable advice can you give RIGHT NOW?

Be specific and reference what you see in their terminals, files, and tools.
If you see error messages, address them directly.
If you see scan results, analyze them.
If you see incomplete work, suggest next steps.

ANALYSIS AND RECOMMENDATIONS:"""
        
        try:
            if self.agent.model_loaded and self.agent.llm:
                response = self.agent.llm(prompt, max_tokens=1500)
                return response["choices"][0]["text"].strip()
        except Exception as e:
            print(f"[!] LLM error: {e}")
        
        return self._fallback_analysis(situation)
    
    def _fallback_analysis(self, situation: str = "") -> str:
        analysis = []
        
        findings = {
            "flags": [],
            "vulns": [],
            "errors": [],
            "tools": [],
            "info": []
        }
        
        seen_errors = set()
        
        for term in self.context["terminals"]:
            output = term["recent_output"].lower()
            cwd = term.get("cwd", "").lower()
            last_cmd = term.get("last_command", "").lower()
            
            if "flag{" in output or "ctf{" in output or "htb{" in output or "picoctf{" in output:
                findings["flags"].append(f"FLAG in Terminal {term['id']}!")
            
            if "sqlmap" in output:
                if "injectable" in output and "not injectable" not in output:
                    findings["vulns"].append("SQLi confirmed - consider --dump for extraction")
                elif "not injectable" in output:
                    findings["info"].append("SQLi test negative - try tamper scripts or different params")
            
            if "nmap" in output and "/tcp" in output and "open" in output:
                findings["tools"].append(f"Nmap scan completed (Terminal {term['id']})")
            
            if "gobuster" in output or "ffuf" in output or "dirb" in output:
                if "status: 200" in output or "=> 200" in output or "[200]" in output:
                    findings["vulns"].append("Directory scan found accessible paths")
            
            if "burpsuite" in output or "127.0.0.1:8080" in output or "localhost:8080" in output:
                if "intercept" in output or "proxy" in last_cmd:
                    findings["tools"].append("Burp Suite proxy active")
            
            if "hydra" in output:
                if "login:" in output or "password:" in output:
                    findings["vulns"].append("Hydra found valid credentials!")
                elif "0 valid" in output:
                    findings["info"].append("Hydra brute force completed - no hits")
            
            if "metasploit" in output or "msfconsole" in output:
                if "session" in output and "opened" in output:
                    findings["vulns"].append("Metasploit session opened!")
            
            specific_errors = [
                ("permission denied", "Permission denied - try sudo"),
                ("connection refused", "Connection refused - service may be down"),
                ("connection timed out", "Connection timeout - check network/firewall"),
                ("no route to host", "No route to host - check target IP"),
                ("name or service not known", "DNS resolution failed"),
                ("authentication failed", "Auth failed - check credentials"),
            ]
            
            for pattern, msg in specific_errors:
                if pattern in output and msg not in seen_errors:
                    findings["errors"].append(msg)
                    seen_errors.add(msg)
        
        if findings["flags"]:
            for f in findings["flags"]:
                analysis.append(f"[!!!] {f}")
        
        if findings["vulns"]:
            for v in set(findings["vulns"]):
                analysis.append(f"[+] {v}")
        
        if findings["tools"]:
            for t in set(findings["tools"]):
                analysis.append(f"[*] {t}")
        
        if findings["errors"]:
            analysis.append("\n[!] Issues detected:")
            for e in set(findings["errors"]):
                analysis.append(f"    - {e}")
        
        if findings["info"]:
            analysis.append("\n[i] Notes:")
            for i in set(findings["info"]):
                analysis.append(f"    - {i}")
        
        if self.context["running_tools"]:
            analysis.append("\n[*] Active security tools: " + ", ".join([t["name"] for t in self.context["running_tools"]]))
        
        if self.context["clipboard"]:
            clip = self.context["clipboard"]
            if any(x in clip.lower() for x in ["password", "token", "key", "secret", "flag{"]):
                analysis.append(f"\n[!] Sensitive data in clipboard detected")
        
        has_findings = any(findings[k] for k in findings)
        
        if analysis or has_findings:
            insights = ["-" * 60, "INSIGHTS", "-" * 60, ""]
            insights.extend(analysis)
            if not has_findings:
                insights.append("[*] No significant patterns detected")
            insights.append("")
            return "\n".join(insights) + "\n" + situation
        else:
            return situation + "\n\n[*] No significant patterns detected. Run with --llm for AI analysis."
    
    def interactive_mode(self):
        print("\n" + "=" * 60)
        print("  AGENT BLACK - OVERWATCH MODE")
        print("=" * 60)
        print("\nI'm watching your environment. Commands:")
        print("  status    - Analyze current situation")
        print("  refresh   - Re-gather all context")
        print("  help      - Ask me anything about what you're working on")
        print("  quit      - Exit overwatch mode")
        print("=" * 60)
        
        self.gather_all_context()
        
        while True:
            try:
                cmd = input("\n[OVERWATCH] > ").strip().lower()
                
                if not cmd:
                    continue
                
                if cmd in ["quit", "exit", "q"]:
                    print("[*] Exiting Overwatch Mode...")
                    break
                
                elif cmd in ["status", "sitrep", "analyze"]:
                    print("\n[*] Analyzing situation...")
                    analysis = self.analyze_situation()
                    print("\n" + "=" * 60)
                    print("SITUATION ANALYSIS")
                    print("=" * 60)
                    print(analysis)
                    print("=" * 60)
                
                elif cmd in ["refresh", "update", "rescan"]:
                    self.gather_all_context()
                    print("[+] Context updated")
                
                elif cmd.startswith("help ") or cmd.startswith("how ") or cmd.startswith("what "):
                    if not self.llm_available or not self.agent:
                        print("[!] LLM not loaded. Run with --llm flag to enable AI answers.")
                        print("[*] Or use 'status' to see pattern-based analysis.")
                        continue
                    
                    situation = self.build_situation_summary()
                    question = cmd
                    
                    prompt = f"""You are Agent BLACK in Overwatch Mode with full situational awareness.

CURRENT SITUATION:
{situation}

OPERATOR'S QUESTION: {question}

Answer based on what you can see in their environment. Be specific and actionable."""
                    
                    try:
                        response = self.agent.llm(prompt, max_tokens=1000)
                        print(f"\n[BLACK] {response['choices'][0]['text'].strip()}")
                    except Exception as e:
                        print(f"[!] LLM error: {e}")
                
                else:
                    print(f"[?] Unknown command. Try: status, refresh, help <question>, quit")
                    
            except KeyboardInterrupt:
                print("\n[!] Interrupted")
            except Exception as e:
                print(f"[!] Error: {e}")
    
    def watch_mode(self, interval: int = 10):
        import time
        import hashlib
        
        print("\n" + "=" * 60)
        print("  AGENT BLACK - WATCH MODE")
        print("=" * 60)
        print(f"\nMonitoring your environment every {interval} seconds...")
        print("I'll alert you when I detect issues or opportunities.")
        print("Press Ctrl+C to stop watching.")
        print("=" * 60)
        
        seen_alerts = set()
        last_terminal_state = {}
        check_count = 0
        
        alert_patterns = [
            ("flag{", "FLAG FOUND", "critical"),
            ("ctf{", "FLAG FOUND", "critical"),
            ("htb{", "FLAG FOUND", "critical"),
            ("picoctf{", "FLAG FOUND", "critical"),
            ("permission denied", "Permission denied - need elevated privs?", "warning"),
            ("connection refused", "Connection refused - service down or wrong port", "warning"),
            ("connection timed out", "Connection timeout - firewall or host down", "warning"),
            ("authentication failed", "Auth failed - check creds or try bypass", "warning"),
            ("login failed", "Login failed - check creds", "warning"),
            ("syntax error", "Syntax error in command", "error"),
            ("segmentation fault", "Crash detected - possible exploit vector", "info"),
            ("buffer overflow", "Buffer overflow detected", "info"),
            ("sql syntax", "SQL error - possible injection point", "info"),
            ("injectable", "SQLMap found injectable param!", "critical"),
            ("session opened", "Shell/session obtained!", "critical"),
            ("password:", "Credentials found", "critical"),
            ("root@", "Root shell obtained!", "critical"),
            ("nt authority\\system", "SYSTEM shell obtained!", "critical"),
            ("access denied", "Access denied - need different approach", "warning"),
            ("not found", "Resource not found", "info"),
            ("500 internal server error", "Server error - investigate", "info"),
            ("stack trace", "Stack trace exposed - info disclosure", "info"),
        ]
        
        try:
            while True:
                check_count += 1
                self.gather_all_context()
                
                new_alerts = []
                
                for term in self.context["terminals"]:
                    term_id = term["id"]
                    output = term.get("recent_output", "").lower()
                    output_hash = hashlib.md5(output.encode()).hexdigest()[:8]
                    
                    if term_id in last_terminal_state:
                        if last_terminal_state[term_id] == output_hash:
                            continue
                    
                    last_terminal_state[term_id] = output_hash
                    
                    for pattern, message, severity in alert_patterns:
                        if pattern in output:
                            alert_key = f"{term_id}:{pattern}"
                            if alert_key not in seen_alerts:
                                seen_alerts.add(alert_key)
                                cwd = term.get("cwd", "unknown")
                                folder = cwd.split("\\")[-1] if "\\" in cwd else cwd.split("/")[-1]
                                new_alerts.append((severity, message, folder, term_id))
                
                if new_alerts:
                    print("\n" + "!" * 60)
                    print("  ALERT - Agent BLACK detected something")
                    print("!" * 60)
                    
                    for severity, message, folder, term_id in new_alerts:
                        if severity == "critical":
                            icon = "[!!!]"
                        elif severity == "warning":
                            icon = "[!]"
                        elif severity == "error":
                            icon = "[X]"
                        else:
                            icon = "[*]"
                        
                        print(f"{icon} {message}")
                        print(f"    Location: [{folder}] (Terminal {term_id})")
                    
                    print("!" * 60)
                    
                    try:
                        print("\a", end="", flush=True)
                    except:
                        pass
                    
                    if self.llm_available and self.agent:
                        print("\n[BLACK] Let me analyze this...")
                        try:
                            situation = self.build_situation_summary()
                            alert_context = "\n".join([f"{s}: {m} in {f}" for s, m, f, _ in new_alerts])
                            
                            prompt = f"""You are Agent BLACK. You just detected these issues:

{alert_context}

CURRENT SITUATION:
{situation[:3000]}

Give 2-3 SPECIFIC, ACTIONABLE suggestions for what the operator should try next. Be concise."""
                            
                            response = self.agent.llm(prompt, max_tokens=500)
                            suggestion = response["choices"][0]["text"].strip()
                            print(f"\n[BLACK] {suggestion}")
                        except Exception as e:
                            pass
                
                if check_count % 6 == 0:
                    print(f"[*] Still watching... ({check_count} checks, {len(seen_alerts)} alerts so far)")
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n[*] Watch mode stopped.")
            print(f"[*] Total checks: {check_count}")
            print(f"[*] Alerts triggered: {len(seen_alerts)}")


def get_default_export_path() -> Path:
    reports_dir = Path(__file__).parent.parent / "agent_black" / "overwatch_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return reports_dir / f"overwatch_{timestamp}.txt"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Agent BLACK Overwatch Mode")
    parser.add_argument("--snapshot", action="store_true", help="One-time analysis, then exit")
    parser.add_argument("--watch", action="store_true", help="Continuous monitoring with proactive alerts")
    parser.add_argument("--interval", type=int, default=10, help="Watch mode check interval in seconds (default: 10)")
    parser.add_argument("--llm", action="store_true", help="Load LLM for AI-powered analysis (slower)")
    parser.add_argument("--export", type=str, nargs="?", const="auto", help="Export analysis (default: auto-named in overwatch_reports/)")
    parser.add_argument("--obsidian", action="store_true", help="Also export to Obsidian vault")
    parser.add_argument("--no-save", action="store_true", help="Don't auto-save snapshot analysis")
    args = parser.parse_args()
    
    overwatch = OverwatchSystem(load_model=args.llm)
    
    if args.watch:
        overwatch.watch_mode(interval=args.interval)
    elif args.snapshot:
        analysis = overwatch.analyze_situation()
        
        safe_print("\n" + "=" * 60)
        safe_print("SITUATION ANALYSIS")
        safe_print("=" * 60)
        safe_print(analysis)
        safe_print("=" * 60)
        
        if not args.no_save:
            if args.export and args.export != "auto":
                export_path = Path(args.export)
            else:
                export_path = get_default_export_path()
            
            try:
                export_path.write_text(analysis, encoding="utf-8")
                safe_print(f"\n[+] Analysis saved to: {export_path}")
            except Exception as e:
                safe_print(f"\n[!] Save failed: {e}")
        
        if args.obsidian:
            try:
                from integration.obsidian import ObsidianIntegration
                obsidian = ObsidianIntegration()
                if obsidian.vault_path:
                    obs_path = obsidian.export_overwatch_session(analysis, overwatch.context)
                    safe_print(f"[+] Exported to Obsidian: {obs_path}")
                else:
                    safe_print("[!] No Obsidian vault configured. Run: black obsidian init <path>")
            except ImportError:
                safe_print("[!] Obsidian integration not available")
    else:
        overwatch.interactive_mode()


if __name__ == "__main__":
    main()
