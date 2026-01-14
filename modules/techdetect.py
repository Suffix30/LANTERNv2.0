from urllib.parse import urlparse, urljoin
from modules.base import BaseModule
from core.tech_detect import TechDetector, TechFingerprinter


class TechdetectModule(BaseModule):
    name = "techdetect"
    description = "Technology Stack Detection and Module Recommendation"
    
    additional_paths = [
        "/",
        "/robots.txt",
        "/sitemap.xml",
        "/favicon.ico",
        "/wp-login.php",
        "/wp-admin/",
        "/administrator/",
        "/admin/",
        "/user/login",
        "/api/",
        "/api/v1/",
        "/graphql",
        "/swagger.json",
        "/openapi.json",
        "/.well-known/",
        "/actuator/health",
        "/info",
        "/status",
        "/health",
        "/version",
        "/.git/config",
        "/.env",
        "/package.json",
        "/composer.json",
    ]
    
    async def scan(self, target):
        self.findings = []
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        fingerprinter = TechFingerprinter(self.http)
        detector = TechDetector()
        all_techs = {}
        
        initial_result = await fingerprinter.fingerprint(target)
        for tech in initial_result.get("technologies", []):
            all_techs[tech["name"]] = type("Tech", (), tech)()
        
        for path in self.additional_paths:
            check_url = urljoin(base_url, path)
            
            try:
                resp = await self.http.get(check_url)
                
                if resp and resp.get("status"):
                    resp["url"] = check_url
                    techs = detector.detect(resp)
                    
                    for tech in techs:
                        if tech.name not in all_techs or tech.confidence > all_techs[tech.name].confidence:
                            all_techs[tech.name] = tech
                    
                    if resp["status"] == 200 and path in ["/.git/config", "/.env", "/package.json", "/composer.json"]:
                        self.add_finding(
                            "HIGH" if path in ["/.git/config", "/.env"] else "MEDIUM",
                            f"Sensitive file exposed: {path}",
                            url=check_url,
                            evidence=resp.get("text", "")[:200]
                        )
            except:
                pass
        
        technologies = sorted(all_techs.values(), key=lambda t: (-t.confidence, t.name))
        
        if technologies:
            tech_list = []
            for tech in technologies:
                version_str = f" {tech.version}" if tech.version else ""
                tech_list.append(f"{tech.name}{version_str} ({tech.category})")
            
            self.add_finding(
                "INFO",
                f"Detected {len(technologies)} technologies",
                url=target,
                evidence="; ".join(tech_list[:20])
            )
            
            cms_techs = [t for t in technologies if t.category == "cms"]
            for cms in cms_techs:
                if cms.name == "WordPress":
                    await self._check_wordpress(base_url)
                elif cms.name == "Drupal":
                    await self._check_drupal(base_url)
                elif cms.name == "Joomla":
                    await self._check_joomla(base_url)
            
            framework_techs = [t for t in technologies if t.category in ["framework", "backend"]]
            for fw in framework_techs:
                if fw.name in ["Spring", "Spring Boot"]:
                    await self._check_spring_actuator(base_url)
                elif fw.name in ["Django", "Flask"]:
                    await self._check_python_debug(base_url)
            
            all_modules = set()
            for tech in technologies:
                all_modules.update(tech.relevant_modules)
            
            if all_modules:
                self.add_finding(
                    "INFO",
                    f"Recommended scan modules based on detected tech",
                    url=target,
                    evidence=", ".join(sorted(all_modules))
                )
        
        return self.findings
    
    async def _check_wordpress(self, base_url):
        paths = [
            "/wp-json/wp/v2/users",
            "/wp-json/",
            "/?rest_route=/wp/v2/users",
            "/xmlrpc.php",
            "/wp-content/debug.log",
            "/wp-config.php.bak",
            "/wp-config.php~",
            "/wp-config.old",
        ]
        
        for path in paths:
            url = urljoin(base_url, path)
            try:
                resp = await self.http.get(url)
                
                if resp and resp.get("status") == 200:
                    text = resp.get("text", "")
                    
                    if path == "/wp-json/wp/v2/users" and '"id":' in text and '"slug":' in text:
                        self.add_finding(
                            "MEDIUM",
                            "WordPress user enumeration via REST API",
                            url=url,
                            evidence=text[:300]
                        )
                    
                    elif path == "/xmlrpc.php" and "<methodResponse>" in text or "XML-RPC server" in text:
                        self.add_finding(
                            "MEDIUM",
                            "WordPress XML-RPC enabled",
                            url=url,
                            evidence="XML-RPC can be used for brute force and DDoS amplification"
                        )
                    
                    elif "debug.log" in path and ("PHP" in text or "error" in text.lower()):
                        self.add_finding(
                            "HIGH",
                            "WordPress debug log exposed",
                            url=url,
                            evidence=text[:200]
                        )
                    
                    elif "wp-config" in path and ("DB_NAME" in text or "DB_PASSWORD" in text):
                        self.add_finding(
                            "CRITICAL",
                            "WordPress config backup exposed",
                            url=url,
                            evidence="Database credentials may be exposed"
                        )
            except:
                pass
    
    async def _check_drupal(self, base_url):
        paths = [
            "/CHANGELOG.txt",
            "/core/CHANGELOG.txt",
            "/user/register",
            "/admin/config/development/maintenance",
        ]
        
        for path in paths:
            url = urljoin(base_url, path)
            try:
                resp = await self.http.get(url)
                
                if resp and resp.get("status") == 200:
                    text = resp.get("text", "")
                    
                    if "CHANGELOG" in path and "Drupal" in text:
                        import re
                        version_match = re.search(r"Drupal\s+([\d.]+)", text)
                        if version_match:
                            self.add_finding(
                                "LOW",
                                f"Drupal version disclosure: {version_match.group(1)}",
                                url=url,
                                evidence=text[:200]
                            )
            except:
                pass
    
    async def _check_joomla(self, base_url):
        paths = [
            "/administrator/manifests/files/joomla.xml",
            "/language/en-GB/en-GB.xml",
            "/plugins/system/cache/cache.xml",
        ]
        
        for path in paths:
            url = urljoin(base_url, path)
            try:
                resp = await self.http.get(url)
                
                if resp and resp.get("status") == 200:
                    text = resp.get("text", "")
                    
                    if "<version>" in text:
                        import re
                        version_match = re.search(r"<version>([\d.]+)</version>", text)
                        if version_match:
                            self.add_finding(
                                "LOW",
                                f"Joomla version disclosure: {version_match.group(1)}",
                                url=url,
                                evidence=text[:200]
                            )
            except:
                pass
    
    async def _check_spring_actuator(self, base_url):
        actuator_paths = [
            "/actuator",
            "/actuator/env",
            "/actuator/heapdump",
            "/actuator/mappings",
            "/actuator/configprops",
            "/actuator/beans",
            "/actuator/threaddump",
            "/actuator/logfile",
            "/manage",
            "/manage/env",
            "/env",
            "/heapdump",
            "/mappings",
            "/trace",
            "/jolokia",
            "/jolokia/list",
        ]
        
        for path in actuator_paths:
            url = urljoin(base_url, path)
            try:
                resp = await self.http.get(url)
                
                if resp and resp.get("status") == 200:
                    text = resp.get("text", "")
                    
                    if path == "/actuator/env" and ("spring" in text.lower() or "java" in text.lower()):
                        self.add_finding(
                            "CRITICAL",
                            "Spring Boot Actuator /env exposed",
                            url=url,
                            evidence="Environment variables and secrets may be exposed"
                        )
                    
                    elif path == "/actuator/heapdump":
                        self.add_finding(
                            "CRITICAL",
                            "Spring Boot Actuator /heapdump exposed",
                            url=url,
                            evidence="Memory dump can reveal secrets, credentials, and session data"
                        )
                    
                    elif "actuator" in path and ("_links" in text or "beans" in text or "mappings" in text):
                        self.add_finding(
                            "HIGH",
                            f"Spring Boot Actuator endpoint exposed: {path}",
                            url=url,
                            evidence=text[:200]
                        )
                    
                    elif path in ["/jolokia", "/jolokia/list"] and "java" in text.lower():
                        self.add_finding(
                            "CRITICAL",
                            "Jolokia JMX endpoint exposed",
                            url=url,
                            evidence="Remote code execution may be possible"
                        )
            except:
                pass
    
    async def _check_python_debug(self, base_url):
        debug_paths = [
            "/?__debugger__=yes",
            "/console",
            "/__debug__/",
        ]
        
        for path in debug_paths:
            url = urljoin(base_url, path)
            try:
                resp = await self.http.get(url)
                
                if resp and resp.get("status") == 200:
                    text = resp.get("text", "")
                    
                    if "Werkzeug" in text or "debugger" in text.lower():
                        self.add_finding(
                            "CRITICAL",
                            "Werkzeug debugger exposed",
                            url=url,
                            evidence="Python debugger console allows remote code execution"
                        )
                    
                    elif "Django" in text and "debug" in text.lower():
                        self.add_finding(
                            "HIGH",
                            "Django debug mode enabled",
                            url=url,
                            evidence="Debug information and settings exposed"
                        )
            except:
                pass
