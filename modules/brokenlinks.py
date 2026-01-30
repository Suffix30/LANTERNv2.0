import re
from urllib.parse import urlparse, urljoin
from modules.base import BaseModule


class BrokenlinksModule(BaseModule):
    name = "brokenlinks"
    description = "Broken Links Checker"

    max_links = 25

    async def scan(self, target):
        self.findings = []
        resp = await self.http.get(target)
        if not resp.get("status") or resp.get("status") != 200:
            return self.findings
        html = resp.get("text", "") or ""
        parsed = urlparse(target)
        base_netloc = parsed.netloc.lower()
        base_scheme = parsed.scheme or "https"
        base_url = f"{base_scheme}://{base_netloc}"
        links = set()
        for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.I):
            href = m.group(1).strip()
            if not href or href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            full = urljoin(target, href)
            full = full.split("#")[0]
            try:
                p = urlparse(full)
                if p.scheme not in ("http", "https"):
                    continue
                if p.netloc.lower() != base_netloc and not p.netloc.lower().endswith("." + base_netloc):
                    continue
                links.add(full)
            except Exception:
                continue
        links = list(links)[:self.max_links]
        broken = []
        for url in links:
            try:
                r = await self.http.get(url, timeout=5)
                status = r.get("status")
                if not status or status >= 400:
                    broken.append((url, status or "ERR"))
            except Exception:
                broken.append((url, "ERR"))
        if broken:
            self.add_finding(
                "LOW",
                f"Broken links on page ({len(broken)} of {len(links)} checked)",
                url=target,
                evidence=f"Broken: {broken[0][0][:60]} ({broken[0][1]})"
            )
        return self.findings
