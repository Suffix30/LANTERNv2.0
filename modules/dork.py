from pathlib import Path
from urllib.parse import urlparse
from modules.base import BaseModule

class DorkModule(BaseModule):
    name = "dork"
    description = "Google Dork Generator for Target Recon"
    
    dork_categories = {
        "sensitive_files": "Sensitive Files (configs, passwords, API keys)",
        "admin_login": "Login and Admin Pages",
        "backups": "Exposed Backups",
        "error_pages": "Error Pages (info disclosure)",
        "database_files": "Database Files",
        "cms_vulns": "CMS Vulnerabilities",
    }
    
    async def scan(self, target):
        self.findings = []
        
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
        domain = domain.replace("www.", "")
        
        dorks = self._generate_dorks(domain)
        
        self.add_finding(
            "INFO",
            f"Generated {len(dorks)} Google dorks for {domain}",
            url=target,
            evidence=f"Categories: {', '.join(self.dork_categories.keys())}"
        )
        
        high_value_dorks = self._get_high_value_dorks(domain)
        for dork_info in high_value_dorks[:10]:
            self.add_finding(
                "INFO",
                f"Dork: {dork_info['category']}",
                url=target,
                evidence=dork_info['dork']
            )
        
        output_file = self._save_dorks(domain, dorks)
        if output_file:
            self.add_finding(
                "INFO",
                f"Dorks saved to file",
                url=target,
                evidence=output_file
            )
        
        return self.findings
    
    def _generate_dorks(self, domain):
        dorks = []
        payloads_dir = Path(__file__).parent.parent / "payloads" / "dorks"
        
        for category in self.dork_categories.keys():
            dork_file = payloads_dir / f"{category}.txt"
            if dork_file.exists():
                with open(dork_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            site_dork = f"site:{domain} {line}"
                            dorks.append({
                                "category": category,
                                "dork": site_dork,
                                "original": line
                            })
        
        dorks.extend(self._generate_custom_dorks(domain))
        
        return dorks
    
    def _generate_custom_dorks(self, domain):
        custom = []
        
        sensitive_paths = [
            f'site:{domain} inurl:".env"',
            f'site:{domain} inurl:".git"',
            f'site:{domain} inurl:".svn"',
            f'site:{domain} inurl:".htaccess"',
            f'site:{domain} inurl:".htpasswd"',
            f'site:{domain} inurl:"wp-config.php"',
            f'site:{domain} inurl:"config.php"',
            f'site:{domain} inurl:"database.yml"',
            f'site:{domain} inurl:"settings.py"',
            f'site:{domain} inurl:"application.properties"',
            f'site:{domain} inurl:"/api/" inurl:"swagger"',
            f'site:{domain} inurl:"/graphql"',
            f'site:{domain} inurl:"/actuator"',
            f'site:{domain} inurl:"phpinfo.php"',
            f'site:{domain} inurl:"info.php"',
            f'site:{domain} inurl:"test.php"',
            f'site:{domain} inurl:"debug"',
            f'site:{domain} inurl:"trace"',
            f'site:{domain} inurl:"/server-status"',
            f'site:{domain} inurl:"/server-info"',
        ]
        
        for dork in sensitive_paths:
            custom.append({
                "category": "custom",
                "dork": dork,
                "original": dork
            })
        
        extensions = [
            f'site:{domain} filetype:sql',
            f'site:{domain} filetype:env',
            f'site:{domain} filetype:log',
            f'site:{domain} filetype:bak',
            f'site:{domain} filetype:old',
            f'site:{domain} filetype:backup',
            f'site:{domain} filetype:conf',
            f'site:{domain} filetype:config',
            f'site:{domain} filetype:ini',
            f'site:{domain} filetype:xml',
            f'site:{domain} filetype:json',
            f'site:{domain} filetype:yml',
            f'site:{domain} filetype:yaml',
            f'site:{domain} filetype:properties',
            f'site:{domain} filetype:pem',
            f'site:{domain} filetype:key',
            f'site:{domain} filetype:csv',
            f'site:{domain} filetype:xls',
            f'site:{domain} filetype:xlsx',
            f'site:{domain} filetype:doc',
            f'site:{domain} filetype:docx',
            f'site:{domain} filetype:pdf',
            f'site:{domain} filetype:txt',
            f'site:{domain} filetype:zip',
            f'site:{domain} filetype:tar',
            f'site:{domain} filetype:gz',
            f'site:{domain} filetype:7z',
            f'site:{domain} filetype:rar',
        ]
        
        for dork in extensions:
            custom.append({
                "category": "filetypes",
                "dork": dork,
                "original": dork
            })
        
        info_disclosure = [
            f'site:{domain} "index of /"',
            f'site:{domain} intitle:"index of"',
            f'site:{domain} "parent directory"',
            f'site:{domain} "directory listing"',
            f'site:{domain} intext:"sql syntax near"',
            f'site:{domain} intext:"warning" intext:"mysql"',
            f'site:{domain} intext:"fatal error"',
            f'site:{domain} intext:"stack trace"',
            f'site:{domain} intext:"debug"',
            f'site:{domain} "powered by"',
            f'site:{domain} "running on"',
            f'site:{domain} "server at"',
            f'site:{domain} intext:"password"',
            f'site:{domain} intext:"username"',
            f'site:{domain} intext:"api_key"',
            f'site:{domain} intext:"secret"',
            f'site:{domain} intext:"token"',
            f'site:{domain} intext:"credentials"',
        ]
        
        for dork in info_disclosure:
            custom.append({
                "category": "info_disclosure",
                "dork": dork,
                "original": dork
            })
        
        subdomains = [
            f'site:*.{domain}',
            f'site:*.{domain} -www',
            f'site:dev.{domain}',
            f'site:staging.{domain}',
            f'site:test.{domain}',
            f'site:api.{domain}',
            f'site:admin.{domain}',
            f'site:mail.{domain}',
            f'site:beta.{domain}',
            f'site:internal.{domain}',
        ]
        
        for dork in subdomains:
            custom.append({
                "category": "subdomains",
                "dork": dork,
                "original": dork
            })
        
        return custom
    
    def _get_high_value_dorks(self, domain):
        high_value = [
            {"category": "Sensitive Config", "dork": f'site:{domain} filetype:env'},
            {"category": "SQL Dumps", "dork": f'site:{domain} filetype:sql'},
            {"category": "Backups", "dork": f'site:{domain} filetype:bak OR filetype:backup'},
            {"category": "Git Exposure", "dork": f'site:{domain} inurl:".git"'},
            {"category": "Admin Panel", "dork": f'site:{domain} inurl:admin'},
            {"category": "Login Pages", "dork": f'site:{domain} inurl:login'},
            {"category": "API Docs", "dork": f'site:{domain} inurl:swagger OR inurl:api-docs'},
            {"category": "Debug/Logs", "dork": f'site:{domain} filetype:log'},
            {"category": "Directory Listing", "dork": f'site:{domain} intitle:"index of"'},
            {"category": "Subdomains", "dork": f'site:*.{domain} -www'},
        ]
        return high_value
    
    def _save_dorks(self, domain, dorks):
        try:
            reports_dir = Path.cwd() / "reports"
            reports_dir.mkdir(exist_ok=True)
            
            output_file = reports_dir / f"dorks_{domain.replace('.', '_')}.txt"
            
            with open(output_file, "w") as f:
                f.write(f"# Google Dorks for {domain}\n")
                f.write(f"# Generated by Lantern\n")
                f.write(f"# Total: {len(dorks)} dorks\n\n")
                
                current_category = None
                for dork in dorks:
                    if dork["category"] != current_category:
                        current_category = dork["category"]
                        f.write(f"\n# === {current_category.upper()} ===\n")
                    f.write(f"{dork['dork']}\n")
            
            return str(output_file)
        except Exception as e:
            return None
