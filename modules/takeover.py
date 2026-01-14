import re
import asyncio
import socket
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse
from modules.base import BaseModule


class TakeoverModule(BaseModule):
    name = "takeover"
    description = "Subdomain Takeover Scanner"
    exploitable = True
    
    fingerprints = {
        "aws_s3": {
            "cnames": ["s3.amazonaws.com", "s3-website", ".s3."],
            "patterns": ["NoSuchBucket", "The specified bucket does not exist"],
            "severity": "CRITICAL",
        },
        "aws_cloudfront": {
            "cnames": ["cloudfront.net"],
            "patterns": ["Bad request", "ERROR: The request could not be satisfied"],
            "severity": "HIGH",
        },
        "aws_elastic_beanstalk": {
            "cnames": ["elasticbeanstalk.com"],
            "patterns": [],
            "nxdomain": True,
            "severity": "CRITICAL",
        },
        "azure_websites": {
            "cnames": ["azurewebsites.net", "azure-mobile.net"],
            "patterns": ["404 Web Site not found", "Azure Web Apps"],
            "severity": "CRITICAL",
        },
        "azure_blob": {
            "cnames": ["blob.core.windows.net"],
            "patterns": ["BlobNotFound", "The specified container does not exist"],
            "severity": "HIGH",
        },
        "azure_cloudapp": {
            "cnames": ["cloudapp.net", "cloudapp.azure.com"],
            "patterns": [],
            "nxdomain": True,
            "severity": "CRITICAL",
        },
        "azure_trafficmanager": {
            "cnames": ["trafficmanager.net"],
            "patterns": [],
            "nxdomain": True,
            "severity": "CRITICAL",
        },
        "github_pages": {
            "cnames": ["github.io", "githubusercontent.com"],
            "patterns": ["There isn't a GitHub Pages site here", "404 - File not found"],
            "severity": "CRITICAL",
        },
        "heroku": {
            "cnames": ["herokuapp.com", "herokussl.com", "herokudns.com"],
            "patterns": ["No such app", "herokucdn.com/error-pages/no-such-app"],
            "severity": "CRITICAL",
        },
        "shopify": {
            "cnames": ["myshopify.com"],
            "patterns": ["Sorry, this shop is currently unavailable", "Only one step left"],
            "severity": "HIGH",
        },
        "tumblr": {
            "cnames": ["tumblr.com", "domains.tumblr.com"],
            "patterns": ["There's nothing here", "Whatever you were looking for"],
            "severity": "HIGH",
        },
        "wordpress": {
            "cnames": ["wordpress.com"],
            "patterns": ["Do you want to register"],
            "severity": "HIGH",
        },
        "ghost": {
            "cnames": ["ghost.io"],
            "patterns": ["The thing you were looking for is no longer here"],
            "severity": "HIGH",
        },
        "pantheon": {
            "cnames": ["pantheonsite.io", "gotpantheon.com"],
            "patterns": ["404 error unknown site", "The gods are wise"],
            "severity": "CRITICAL",
        },
        "fastly": {
            "cnames": ["fastly.net", "fastlylb.net"],
            "patterns": ["Fastly error: unknown domain"],
            "severity": "CRITICAL",
        },
        "netlify": {
            "cnames": ["netlify.app", "netlify.com"],
            "patterns": ["Not Found - Request ID"],
            "severity": "CRITICAL",
        },
        "vercel": {
            "cnames": ["vercel.app", "now.sh", "zeit.co"],
            "patterns": ["The deployment could not be found"],
            "severity": "CRITICAL",
        },
        "surge": {
            "cnames": ["surge.sh"],
            "patterns": ["project not found"],
            "severity": "HIGH",
        },
        "firebase": {
            "cnames": ["firebaseapp.com", "web.app"],
            "patterns": ["Site Not Found"],
            "severity": "HIGH",
        },
        "zendesk": {
            "cnames": ["zendesk.com"],
            "patterns": ["Help Center Closed", "this help center no longer exists"],
            "severity": "MEDIUM",
        },
        "desk": {
            "cnames": ["desk.com"],
            "patterns": ["Sorry, We Couldn't Find That Page", "Please try again"],
            "severity": "MEDIUM",
        },
        "freshdesk": {
            "cnames": ["freshdesk.com"],
            "patterns": ["There is no helpdesk here", "May be this is still fresh"],
            "severity": "MEDIUM",
        },
        "statuspage": {
            "cnames": ["statuspage.io"],
            "patterns": ["You are being redirected", "Status page pushed a DNS"],
            "severity": "MEDIUM",
        },
        "hubspot": {
            "cnames": ["hubspot.com", "hs-sites.com"],
            "patterns": ["Domain not found"],
            "severity": "MEDIUM",
        },
        "unbounce": {
            "cnames": ["unbouncepages.com"],
            "patterns": ["The requested URL was not found"],
            "severity": "MEDIUM",
        },
        "launchrock": {
            "cnames": ["launchrock.com"],
            "patterns": ["It looks like you may have taken a wrong turn"],
            "severity": "MEDIUM",
        },
        "uservoice": {
            "cnames": ["uservoice.com"],
            "patterns": ["This UserVoice subdomain is currently available"],
            "severity": "MEDIUM",
        },
        "helpjuice": {
            "cnames": ["helpjuice.com"],
            "patterns": ["We could not find what you're looking for"],
            "severity": "MEDIUM",
        },
        "helpscout": {
            "cnames": ["helpscoutdocs.com"],
            "patterns": ["No settings were found for this company"],
            "severity": "MEDIUM",
        },
        "cargo": {
            "cnames": ["cargocollective.com"],
            "patterns": ["404 Not Found"],
            "severity": "MEDIUM",
        },
        "strikingly": {
            "cnames": ["strikinglydns.com", "strikingly.com"],
            "patterns": ["page not found"],
            "severity": "MEDIUM",
        },
        "smartling": {
            "cnames": ["smartling.com"],
            "patterns": ["Domain is not configured"],
            "severity": "MEDIUM",
        },
        "tilda": {
            "cnames": ["tilda.ws"],
            "patterns": ["Please renew your subscription"],
            "severity": "MEDIUM",
        },
        "readme": {
            "cnames": ["readme.io"],
            "patterns": ["Project doesnt exist"],
            "severity": "MEDIUM",
        },
        "bitbucket": {
            "cnames": ["bitbucket.io"],
            "patterns": ["Repository not found"],
            "severity": "HIGH",
        },
        "intercom": {
            "cnames": ["intercom.io", "intercom.help"],
            "patterns": ["Uh oh. That page doesn't exist"],
            "severity": "MEDIUM",
        },
        "webflow": {
            "cnames": ["webflow.io", "proxy.webflow.com"],
            "patterns": ["The page you are looking for doesn't exist"],
            "severity": "HIGH",
        },
        "kajabi": {
            "cnames": ["kajabi.com", "mykajabi.com"],
            "patterns": ["The page you were looking for doesn't exist"],
            "severity": "MEDIUM",
        },
        "thinkific": {
            "cnames": ["thinkific.com"],
            "patterns": ["You may have mistyped the address"],
            "severity": "MEDIUM",
        },
        "teachable": {
            "cnames": ["teachable.com", "teachablecdn.com"],
            "patterns": ["Uh oh. You've requested a page that doesn't exist"],
            "severity": "MEDIUM",
        },
        "aftership": {
            "cnames": ["aftership.com"],
            "patterns": ["Oops.<br>The page you're looking for doesn't exist"],
            "severity": "MEDIUM",
        },
        "aha": {
            "cnames": ["aha.io"],
            "patterns": ["There is no portal here"],
            "severity": "MEDIUM",
        },
        "brightcove": {
            "cnames": ["bcvp0rtal.com", "brightcovegallery.com"],
            "patterns": ["Error - unass"],
            "severity": "MEDIUM",
        },
        "campaignmonitor": {
            "cnames": ["createsend.com", "cmail"],
            "patterns": ["Trying to access your account"],
            "severity": "MEDIUM",
        },
        "acquia": {
            "cnames": ["acquia-test.co"],
            "patterns": ["Web Site Not Found"],
            "severity": "MEDIUM",
        },
        "simplebooklet": {
            "cnames": ["simplebooklet.com"],
            "patterns": ["We can't find this SimpleBoo"],
            "severity": "LOW",
        },
        "getresponse": {
            "cnames": ["gr8.com"],
            "patterns": ["With GetResponse Landing Pages"],
            "severity": "MEDIUM",
        },
        "vend": {
            "cnames": ["vendecommerce.com"],
            "patterns": ["Looks like you've traveled too far"],
            "severity": "MEDIUM",
        },
        "feedpress": {
            "cnames": ["redirect.feedpress.me"],
            "patterns": ["The feed has not been found"],
            "severity": "LOW",
        },
        "ngrok": {
            "cnames": ["ngrok.io"],
            "patterns": ["ngrok.io not found", "Tunnel not found"],
            "severity": "HIGH",
        },
        "kinsta": {
            "cnames": ["kinsta.cloud"],
            "patterns": ["No Site For Domain"],
            "severity": "HIGH",
        },
        "pingdom": {
            "cnames": ["pingdom.com"],
            "patterns": ["Sorry, couldn't find the status page"],
            "severity": "MEDIUM",
        },
        "smartjobboard": {
            "cnames": ["smartjobboard.com"],
            "patterns": ["This job board website is either expired"],
            "severity": "LOW",
        },
        "smugmug": {
            "cnames": ["smugmug.com"],
            "patterns": ["Page Not Found"],
            "severity": "MEDIUM",
        },
        "tave": {
            "cnames": ["tave.com"],
            "patterns": ["Error 404"],
            "severity": "LOW",
        },
    }
    
    async def scan(self, target):
        self.findings = []
        self.vulnerable_subs: List[Dict] = []
        
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
        domain = domain.split(":")[0]
        
        await self._check_domain(domain, target)
        
        subdomains = await self._get_subdomains(domain)
        
        sem = asyncio.Semaphore(20)
        tasks = [self._check_subdomain(sub, sem) for sub in subdomains]
        await asyncio.gather(*tasks)
        
        return self.findings
    
    async def _get_subdomains(self, domain: str) -> List[str]:
        subs: Set[str] = set()
        
        common_subs = [
            "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
            "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
            "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs",
            "ww42", "mx", "email", "cloud", "1", "mail1", "2", "forum",
            "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api",
            "exchange", "app", "gov", "2tty", "vps", "govyty", "news",
            "1rer", "lert", "stg", "stage", "staging", "uat", "qa",
        ]
        
        for sub in common_subs:
            subs.add(f"{sub}.{domain}")
        
        return list(subs)
    
    async def _check_domain(self, domain: str, target: str):
        cname = await self._get_cname(domain)
        
        if cname:
            await self._check_cname_vulnerable(domain, cname, target)
    
    async def _check_subdomain(self, subdomain: str, sem: asyncio.Semaphore):
        async with sem:
            cname = await self._get_cname(subdomain)
            
            if cname:
                await self._check_cname_vulnerable(subdomain, cname, f"https://{subdomain}")
    
    async def _get_cname(self, domain: str) -> Optional[str]:
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            try:
                answers = resolver.resolve(domain, 'CNAME')
                for rdata in answers:
                    return str(rdata.target).rstrip('.')
            except:
                pass
        except ImportError:
            pass
        
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, socket.gethostbyname, domain)
            return None
        except socket.gaierror as e:
            if "NXDOMAIN" in str(e) or "Name or service not known" in str(e):
                return "NXDOMAIN"
            return None
        except:
            return None
    
    async def _check_cname_vulnerable(self, subdomain: str, cname: str, target: str):
        cname_lower = cname.lower()
        
        for service, fingerprint in self.fingerprints.items():
            for cname_pattern in fingerprint.get("cnames", []):
                if cname_pattern.lower() in cname_lower:
                    if await self._verify_takeover(subdomain, target, fingerprint, service):
                        self.vulnerable_subs.append({
                            "subdomain": subdomain,
                            "cname": cname,
                            "service": service,
                        })
                        
                        self.add_finding(
                            fingerprint.get("severity", "HIGH"),
                            f"Subdomain Takeover: {service}",
                            url=target,
                            evidence=f"{subdomain} → {cname}"
                        )
                        
                        self.record_success(f"{subdomain}:{service}", target)
                    return
        
        if cname == "NXDOMAIN":
            for service, fingerprint in self.fingerprints.items():
                if fingerprint.get("nxdomain"):
                    self.add_finding(
                        "MEDIUM",
                        f"Potential Subdomain Takeover (NXDOMAIN)",
                        url=target,
                        evidence=f"{subdomain} has no DNS record - may be claimable"
                    )
                    return
    
    async def _verify_takeover(self, subdomain: str, target: str, fingerprint: Dict, service: str) -> bool:
        patterns = fingerprint.get("patterns", [])
        
        if not patterns:
            return fingerprint.get("nxdomain", False)
        
        try:
            resp = await self.http.get(f"https://{subdomain}", timeout=5)
            body = resp.get("text", "")
            
            for pattern in patterns:
                if re.search(re.escape(pattern), body, re.IGNORECASE):
                    return True
            
            resp = await self.http.get(f"http://{subdomain}", timeout=5)
            body = resp.get("text", "")
            
            for pattern in patterns:
                if re.search(re.escape(pattern), body, re.IGNORECASE):
                    return True
        except:
            pass
        
        return False
    
    async def exploit(self, target, finding):
        results = {
            "vulnerable_subdomains": self.vulnerable_subs,
            "takeover_instructions": [],
        }
        
        for vuln in self.vulnerable_subs:
            service = vuln["service"]
            subdomain = vuln["subdomain"]
            
            instructions = self._get_takeover_instructions(service, subdomain)
            results["takeover_instructions"].append({
                "subdomain": subdomain,
                "service": service,
                "steps": instructions,
            })
        
        if results["takeover_instructions"]:
            self.add_exploit_data("takeover_instructions", results)
            return results
        
        return None
    
    def _get_takeover_instructions(self, service: str, subdomain: str) -> List[str]:
        instructions = {
            "aws_s3": [
                f"1. Create S3 bucket with name matching subdomain: {subdomain}",
                "2. Enable static website hosting",
                "3. Upload index.html with PoC content",
                "4. Verify takeover by visiting subdomain",
            ],
            "github_pages": [
                "1. Create new GitHub repository",
                f"2. Add CNAME file with content: {subdomain}",
                "3. Enable GitHub Pages in repository settings",
                "4. Push index.html with PoC content",
            ],
            "heroku": [
                "1. Create new Heroku app",
                f"2. Add custom domain: {subdomain}",
                "3. Deploy simple web app",
                "4. Verify takeover",
            ],
            "azure_websites": [
                "1. Create Azure Web App",
                f"2. Add custom domain: {subdomain}",
                "3. Verify domain ownership (may require DNS TXT)",
                "4. Deploy content",
            ],
            "netlify": [
                "1. Create Netlify site",
                f"2. Add custom domain: {subdomain}",
                "3. Deploy content",
            ],
            "vercel": [
                "1. Create Vercel project",
                f"2. Add domain: {subdomain}",
                "3. Deploy content",
            ],
        }
        
        return instructions.get(service, [
            f"1. Create account on {service}",
            f"2. Claim subdomain: {subdomain}",
            "3. Verify takeover with PoC content",
        ])
