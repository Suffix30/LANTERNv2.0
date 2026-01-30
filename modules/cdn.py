import re
from urllib.parse import urlparse
from modules.base import BaseModule


class CdnModule(BaseModule):
    name = "cdn"
    description = "CDN Detection"

    cdn_signatures = {
        "Cloudflare": ["cloudflare", "cf-ray", "cf-cache-status", "__cfduid"],
        "Akamai": ["akamai", "akamaiedge", "x-akamai", "akamai-origin"],
        "Fastly": ["fastly", "x-served-by", "x-cache"],
        "Amazon CloudFront": ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"],
        "Azure CDN": ["azureedge", "azurecdn", "x-ec-debug"],
        "StackPath": ["stackpath", "netdna", "maxcdn"],
        "Imperva": ["incapsula", "imperva", "incap_ses", "visid_incap"],
        "CacheFly": ["cachefly"],
        "KeyCDN": ["keycdn"],
        "BunnyCDN": ["bunnycdn"],
        "CDN77": ["cdn77"],
    }

    async def scan(self, target):
        self.findings = []
        resp = await self.http.get(target)
        if not resp.get("status"):
            return self.findings
        headers = resp.get("headers", {})
        headers_str = " ".join(f"{k.lower()}:{str(v).lower()}" for k, v in headers.items())
        for cdn_name, sigs in self.cdn_signatures.items():
            for sig in sigs:
                if sig.lower() in headers_str:
                    self.add_finding(
                        "INFO",
                        f"CDN detected: {cdn_name}",
                        url=target,
                        evidence=f"Header/signature: {sig}"
                    )
                    return self.findings
        server = (headers.get("Server") or headers.get("server") or "").lower()
        via = (headers.get("Via") or headers.get("via") or "").lower()
        if "cdn" in server or "cdn" in via or "edge" in server:
            self.add_finding(
                "INFO",
                "CDN or edge server indicated",
                url=target,
                evidence=f"Server: {server or '-'}, Via: {via or '-'}"
            )
        return self.findings
