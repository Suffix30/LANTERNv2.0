import re
from modules.base import BaseModule
from urllib.parse import urlparse, urljoin

class CveModule(BaseModule):
    name = "cve"
    description = "Known CVE and CMS Vulnerability Scanner"
    
    wordpress_checks = [
        {
            "path": "/wp-json/wp/v2/users",
            "vuln": "WordPress User Enumeration",
            "severity": "MEDIUM",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "id" in r.get("text", ""),
        },
        {
            "path": "/wp-config.php.bak",
            "vuln": "WordPress Config Backup Exposed",
            "severity": "CRITICAL",
            "cve": "Configuration Exposure",
            "check": lambda r: r.get("status") == 200 and "DB_" in r.get("text", ""),
        },
        {
            "path": "/wp-content/debug.log",
            "vuln": "WordPress Debug Log Exposed",
            "severity": "HIGH",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and ("PHP" in r.get("text", "") or "error" in r.get("text", "").lower()),
        },
        {
            "path": "/?author=1",
            "vuln": "WordPress Author Enumeration",
            "severity": "LOW",
            "cve": "User Enumeration",
            "check": lambda r: r.get("status") in [200, 301, 302] and "author" in r.get("url", ""),
        },
        {
            "path": "/wp-includes/wlwmanifest.xml",
            "vuln": "WordPress XML-RPC Enabled",
            "severity": "LOW",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200,
        },
        {
            "path": "/xmlrpc.php",
            "vuln": "WordPress XML-RPC Enabled (Brute Force Vector)",
            "severity": "MEDIUM",
            "cve": "CVE-2015-5623",
            "check": lambda r: r.get("status") == 405 or "XML-RPC server accepts POST requests only" in r.get("text", ""),
        },
        {
            "path": "/wp-json/oembed/1.0/embed?url=",
            "vuln": "WordPress oEmbed SSRF",
            "severity": "MEDIUM",
            "cve": "SSRF Vector",
            "check": lambda r: r.get("status") == 200 or r.get("status") == 400,
        },
        {
            "path": "/readme.html",
            "vuln": "WordPress Version Disclosure",
            "severity": "LOW",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "wordpress" in r.get("text", "").lower(),
        },
    ]
    
    joomla_checks = [
        {
            "path": "/administrator/manifests/files/joomla.xml",
            "vuln": "Joomla Version Disclosure",
            "severity": "LOW",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "version" in r.get("text", "").lower(),
        },
        {
            "path": "/configuration.php.bak",
            "vuln": "Joomla Config Backup Exposed",
            "severity": "CRITICAL",
            "cve": "Configuration Exposure",
            "check": lambda r: r.get("status") == 200 and "$" in r.get("text", ""),
        },
        {
            "path": "/administrator/",
            "vuln": "Joomla Admin Panel Exposed",
            "severity": "LOW",
            "cve": "Admin Panel Access",
            "check": lambda r: r.get("status") == 200 and "joomla" in r.get("text", "").lower(),
        },
    ]
    
    drupal_checks = [
        {
            "path": "/CHANGELOG.txt",
            "vuln": "Drupal Version Disclosure",
            "severity": "LOW",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "drupal" in r.get("text", "").lower(),
        },
        {
            "path": "/core/CHANGELOG.txt",
            "vuln": "Drupal 8+ Version Disclosure",
            "severity": "LOW",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "drupal" in r.get("text", "").lower(),
        },
        {
            "path": "/user/register",
            "vuln": "Drupal User Registration Open",
            "severity": "MEDIUM",
            "cve": "Misconfiguration",
            "check": lambda r: r.get("status") == 200 and "create new account" in r.get("text", "").lower(),
        },
    ]
    
    common_cves = [
        {
            "path": "/.git/config",
            "vuln": "Git Repository Exposed",
            "severity": "CRITICAL",
            "cve": "Source Code Exposure",
            "check": lambda r: r.get("status") == 200 and "[core]" in r.get("text", ""),
        },
        {
            "path": "/.svn/entries",
            "vuln": "SVN Repository Exposed",
            "severity": "CRITICAL",
            "cve": "Source Code Exposure",
            "check": lambda r: r.get("status") == 200,
        },
        {
            "path": "/.env",
            "vuln": "Environment File Exposed",
            "severity": "CRITICAL",
            "cve": "Configuration Exposure",
            "check": lambda r: r.get("status") == 200 and "=" in r.get("text", ""),
        },
        {
            "path": "/server-status",
            "vuln": "Apache Server Status Exposed",
            "severity": "MEDIUM",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "apache" in r.get("text", "").lower(),
        },
        {
            "path": "/server-info",
            "vuln": "Apache Server Info Exposed",
            "severity": "MEDIUM",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "apache" in r.get("text", "").lower(),
        },
        {
            "path": "/elmah.axd",
            "vuln": "ELMAH Error Log Exposed",
            "severity": "HIGH",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "error" in r.get("text", "").lower(),
        },
        {
            "path": "/trace.axd",
            "vuln": "ASP.NET Trace Exposed",
            "severity": "HIGH",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "trace" in r.get("text", "").lower(),
        },
        {
            "path": "/phpinfo.php",
            "vuln": "PHPInfo Exposed",
            "severity": "MEDIUM",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "php version" in r.get("text", "").lower(),
        },
        {
            "path": "/info.php",
            "vuln": "PHP Info File Exposed",
            "severity": "MEDIUM",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "php" in r.get("text", "").lower(),
        },
        {
            "path": "/actuator/env",
            "vuln": "Spring Actuator Env Exposed",
            "severity": "CRITICAL",
            "cve": "CVE-2020-5421",
            "check": lambda r: r.get("status") == 200 and "{" in r.get("text", ""),
        },
        {
            "path": "/actuator/health",
            "vuln": "Spring Actuator Health Exposed",
            "severity": "LOW",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "status" in r.get("text", "").lower(),
        },
        {
            "path": "/actuator/mappings",
            "vuln": "Spring Actuator Mappings Exposed",
            "severity": "MEDIUM",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and "handler" in r.get("text", "").lower(),
        },
        {
            "path": "/api/swagger-ui.html",
            "vuln": "Swagger UI Exposed",
            "severity": "LOW",
            "cve": "API Documentation Exposed",
            "check": lambda r: r.get("status") == 200 and "swagger" in r.get("text", "").lower(),
        },
        {
            "path": "/swagger.json",
            "vuln": "Swagger JSON Exposed",
            "severity": "LOW",
            "cve": "API Documentation Exposed",
            "check": lambda r: r.get("status") == 200 and "swagger" in r.get("text", "").lower(),
        },
        {
            "path": "/.DS_Store",
            "vuln": "MacOS DS_Store Exposed",
            "severity": "LOW",
            "cve": "Information Disclosure",
            "check": lambda r: r.get("status") == 200 and len(r.get("text", "")) > 0,
        },
        {
            "path": "/crossdomain.xml",
            "vuln": "Flash Crossdomain Policy",
            "severity": "LOW",
            "cve": "Cross-Domain Policy",
            "check": lambda r: r.get("status") == 200 and "*" in r.get("text", ""),
        },
        {
            "path": "/WEB-INF/web.xml",
            "vuln": "Java Web Config Exposed",
            "severity": "CRITICAL",
            "cve": "Configuration Exposure",
            "check": lambda r: r.get("status") == 200 and "servlet" in r.get("text", "").lower(),
        },
        {
            "path": "/console",
            "vuln": "Debug Console Exposed",
            "severity": "CRITICAL",
            "cve": "RCE Vector",
            "check": lambda r: r.get("status") == 200 and ("console" in r.get("text", "").lower() or "debug" in r.get("text", "").lower()),
        },
    ]
    
    async def scan(self, target):
        self.findings = []
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        cms = await self._detect_cms(target)
        
        if cms == "wordpress":
            await self._run_checks(base_url, self.wordpress_checks, "WordPress")
        elif cms == "joomla":
            await self._run_checks(base_url, self.joomla_checks, "Joomla")
        elif cms == "drupal":
            await self._run_checks(base_url, self.drupal_checks, "Drupal")
        
        await self._run_checks(base_url, self.common_cves, "Common")
        
        return self.findings
    
    async def _detect_cms(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return None
        
        text = resp.get("text", "").lower()
        headers = resp.get("headers", {})
        
        if "wp-content" in text or "wordpress" in text:
            return "wordpress"
        elif "joomla" in text or "/components/com_" in text:
            return "joomla"
        elif "drupal" in text or "sites/default" in text:
            return "drupal"
        
        generator = re.search(r'<meta[^>]+generator[^>]+content=["\']([^"\']+)', text, re.IGNORECASE)
        if generator:
            gen_val = generator.group(1).lower()
            if "wordpress" in gen_val:
                return "wordpress"
            elif "joomla" in gen_val:
                return "joomla"
            elif "drupal" in gen_val:
                return "drupal"
        
        return None
    
    async def _run_checks(self, base_url, checks, cms_name):
        for check in checks:
            url = urljoin(base_url, check["path"])
            resp = await self.http.get(url)
            
            if check["check"](resp):
                self.add_finding(
                    check["severity"],
                    f"{check['vuln']}",
                    url=url,
                    evidence=f"CVE/Type: {check['cve']}"
                )
