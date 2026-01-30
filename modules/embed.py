import re
from urllib.parse import urlparse, urljoin
from modules.base import BaseModule


class EmbedModule(BaseModule):
    name = "embed"
    description = "Embedded Objects Scanner"

    embed_patterns = [
        (r'<iframe[^>]+src=["\']([^"\']+)["\']', "iframe"),
        (r'<embed[^>]+src=["\']([^"\']+)["\']', "embed"),
        (r'<object[^>]+data=["\']([^"\']+)["\']', "object"),
        (r'<object[^>]*>.*?<param[^>]+value=["\']([^"\']+)["\']', "object param"),
    ]
    suspicious_ext = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".swf", ".zip", ".sql", ".bak", ".log"}

    async def scan(self, target):
        self.findings = []
        resp = await self.http.get(target)
        if not resp.get("status") or resp.get("status") != 200:
            return self.findings
        html = resp.get("text", "") or ""
        parsed = urlparse(target)
        base_netloc = parsed.netloc.lower()
        external = []
        suspicious = []
        for pattern, tag in self.embed_patterns:
            for m in re.finditer(pattern, html, re.I | re.DOTALL):
                src = (m.group(1) or "").strip()
                if not src or src.startswith("data:") or src.startswith("javascript:"):
                    continue
                full = urljoin(target, src)
                path = urlparse(full).path
                ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path.split("?")[0] else ""
                try:
                    host = urlparse(full).netloc.lower()
                    if host and host != base_netloc and not host.endswith("." + base_netloc):
                        external.append((full, tag))
                    if ext in self.suspicious_ext:
                        suspicious.append((full, ext, tag))
                except Exception:
                    continue
        if external:
            self.add_finding(
                "INFO",
                f"External embedded content ({len(external)} iframe/embed/object)",
                url=target,
                evidence=f"External: {external[0][0][:60]} ({external[0][1]})"
            )
        if suspicious and not external:
            self.add_finding(
                "INFO",
                f"Suspicious embedded file types ({len(suspicious)} found)",
                url=target,
                evidence=f"Suspicious: {suspicious[0][1]} in {suspicious[0][2]}"
            )
        return self.findings
