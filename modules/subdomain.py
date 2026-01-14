import asyncio
from urllib.parse import urlparse
from modules.base import BaseModule
from core.dns_brute import DNSBruteForcer, SubdomainWordlist


class SubdomainModule(BaseModule):
    name = "subdomain"
    description = "High-Speed Subdomain Enumeration and Takeover Detection"
    
    takeover_fingerprints = {
        "github": ["There isn't a GitHub Pages site here", "For root URLs"],
        "heroku": ["No such app", "herokucdn.com"],
        "shopify": ["Sorry, this shop is currently unavailable"],
        "tumblr": ["There's nothing here", "tumblr.com"],
        "wordpress": ["Do you want to register"],
        "teamwork": ["Oops - We didn't find your site"],
        "helpjuice": ["We could not find what you're looking for"],
        "helpscout": ["No settings were found for this company"],
        "cargo": ["If you're moving your domain away"],
        "statuspage": ["You are being redirected", "statuspage.io"],
        "uservoice": ["This UserVoice subdomain is currently available"],
        "surge": ["project not found"],
        "intercom": ["This page is reserved for artistic dogs"],
        "webflow": ["The page you are looking for doesn't exist"],
        "kajabi": ["The page you were looking for doesn't exist"],
        "thinkific": ["You may have mistyped the address"],
        "tave": ["<h1>Error 404: Page Not Found</h1>"],
        "wishpond": ["https://www.wishpond.com/404"],
        "aftership": ["Oops.</h2><p class=\"text-muted text-tight\">"],
        "aha": ["There is no portal here"],
        "brightcove": ["<p class=\"bc-gallery-error-code\">Error Code: 404</p>"],
        "bigcartel": ["<h1>Oops! We couldn&#8217;t find that page.</h1>"],
        "acquia": ["The site you are looking for could not be found"],
        "fastly": ["Fastly error: unknown domain"],
        "pantheon": ["The gods are wise"],
        "zendesk": ["Help Center Closed"],
        "bitbucket": ["Repository not found"],
        "smartling": ["Domain is not configured"],
        "pingdom": ["Sorry, couldn't find the status page"],
        "tilda": ["Please renew your subscription"],
        "campaignmonitor": ["Trying to access your account?"],
        "azure": ["404 Web Site not found"],
        "cloudfront": ["The request could not be satisfied", "Bad request", "ERROR: The request could not be satisfied"],
        "s3": ["The specified bucket does not exist", "NoSuchBucket", "AccessDenied"],
        "elasticbeanstalk": ["404 Not Found"],
        "netlify": ["Not Found - Request ID"],
        "vercel": ["The deployment could not be found", "404: NOT_FOUND"],
        "fly": ["404 Not Found"],
        "render": ["Not Found"],
        "firebase": ["404. That's an error", "Firebase Hosting Setup Complete"],
        "ghost": ["The thing you were looking for is no longer here"],
        "readme": ["Project doesnt exist"],
        "gitbook": ["If you need specifics"],
        "ngrok": ["Tunnel not found", "ngrok.io not found"],
        "canny": ["Company Not Found"],
        "tictail": ["Building a new Tictail store"],
        "launchrock": ["It looks like you may have taken a wrong turn"],
        "unbounce": ["The requested URL was not found"],
        "desk": ["Please try again or try Desk.com free"],
        "feedpress": ["The feed has not been found"],
        "freshdesk": ["There is no helpdesk here"],
        "kinsta": ["No site configured at this address"],
        "readme_io": ["Project doesnt exist... yet!"],
        "strikingly": ["page not found"],
        "uptimerobot": ["page not found"],
        "wufoo": ["Hmmm....something is not right"],
        "smugmug": ["Not Found"],
    }
    
    async def scan(self, target):
        self.findings = []
        
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
        domain = domain.replace("www.", "")
        
        if ":" in domain:
            domain = domain.split(":")[0]
        
        parts = domain.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = domain
        
        wordlist = SubdomainWordlist.BUILTIN
        if self.aggressive:
            wordlist = SubdomainWordlist.generate_mutations(wordlist, depth=2)
        
        bruter = DNSBruteForcer(
            concurrency=self.config.get("dns_concurrency", 500),
            timeout=self.config.get("dns_timeout", 2.0),
            retries=self.config.get("dns_retries", 2),
        )
        
        found_subdomains = []
        
        async def on_found(subdomain, ips):
            found_subdomains.append((subdomain, ips))
        
        await bruter.brute(base_domain, wordlist, callback=on_found)
        
        stats = bruter.get_stats()
        
        if found_subdomains:
            self.add_finding(
                "INFO",
                f"DNS brute force completed: {stats['found']} subdomains found ({stats['rate_per_second']:.0f} req/s)",
                url=target,
                evidence=", ".join(s[0] for s in found_subdomains[:15])
            )
        
        takeover_tasks = [self._check_takeover(sub, ips) for sub, ips in found_subdomains[:50]]
        await asyncio.gather(*takeover_tasks, return_exceptions=True)
        
        await self._check_dangling_cnames(base_domain, [s[0] for s in found_subdomains[:30]])
        
        return self.findings
    
    async def _check_takeover(self, subdomain, ips):
        protocols = ["https", "http"]
        
        for protocol in protocols:
            url = f"{protocol}://{subdomain}"
            
            try:
                resp = await self.http.get(url, allow_redirects=True)
                
                if resp.get("status"):
                    text = resp.get("text", "")
                    
                    for service, fingerprints in self.takeover_fingerprints.items():
                        for fingerprint in fingerprints:
                            if fingerprint.lower() in text.lower():
                                self.add_finding(
                                    "CRITICAL",
                                    f"Subdomain takeover: {service}",
                                    url=url,
                                    evidence=f"Fingerprint matched: {fingerprint[:50]}"
                                )
                                return
                    
                    if resp["status"] == 404:
                        headers = resp.get("headers", {})
                        server = headers.get("server", "").lower()
                        
                        vulnerable_servers = ["amazons3", "cloudfront", "heroku", "github", "netlify", "vercel"]
                        for vs in vulnerable_servers:
                            if vs in server or vs in text.lower():
                                self.add_finding(
                                    "HIGH",
                                    f"Potential subdomain takeover: {vs}",
                                    url=url,
                                    evidence=f"404 on {vs} infrastructure"
                                )
                                return
                    
                    elif resp["status"] in [502, 503, 521, 522, 523]:
                        self.add_finding(
                            "MEDIUM",
                            f"Subdomain returning error status",
                            url=url,
                            evidence=f"HTTP {resp['status']} - possible abandoned service"
                        )
                    
                    return
            except:
                pass
    
    async def _check_dangling_cnames(self, domain, subdomains):
        from core.dns_brute import AsyncDNSResolver, DNSPacket
        
        resolver = AsyncDNSResolver(timeout=2.0, retries=1)
        
        for subdomain in subdomains:
            try:
                result = await resolver.resolve(subdomain, qtype=DNSPacket.QTYPE_CNAME)
                
                if result and result.get("has_answer"):
                    for answer in result.get("answers", []):
                        if answer.get("type") == "CNAME":
                            cname_result = await resolver.resolve(subdomain)
                            
                            if cname_result and cname_result.get("is_nxdomain"):
                                self.add_finding(
                                    "HIGH",
                                    f"Dangling CNAME detected",
                                    url=f"https://{subdomain}",
                                    evidence=f"CNAME target does not resolve"
                                )
            except:
                pass
        
        await resolver.close()
