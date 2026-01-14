import re
from modules.base import BaseModule
from core.utils import extract_params

class IdorModule(BaseModule):
    name = "idor"
    description = "Insecure Direct Object Reference Scanner"
    
    async def scan(self, target):
        self.findings = []
        params = extract_params(target)
        
        id_params = self._find_id_params(params)
        
        if id_params:
            await self._test_numeric_idor(target, id_params)
            await self._test_uuid_idor(target, id_params)
            await self._test_sequential_idor(target, id_params)
        
        return self.findings
    
    def _find_id_params(self, params):
        id_keywords = ["id", "uid", "user", "userid", "user_id", "account", 
                      "accountid", "account_id", "profile", "profileid",
                      "doc", "docid", "document", "documentid", "file",
                      "fileid", "file_id", "order", "orderid", "order_id",
                      "invoice", "invoiceid", "item", "itemid", "product",
                      "productid", "ref", "reference", "num", "number"]
        
        found = []
        for param in params:
            if any(kw in param.lower() for kw in id_keywords):
                found.append(param)
            elif re.match(r'^\d+$', str(params.get(param, [''])[0])):
                found.append(param)
        
        return found if found else params
    
    async def _test_numeric_idor(self, target, params):
        for param in params:
            baseline = await self.http.get(target)
            if not baseline.get("status"):
                continue
            
            original_value = self._extract_param_value(target, param)
            if not original_value or not original_value.isdigit():
                continue
            
            test_values = [
                str(int(original_value) + 1),
                str(int(original_value) - 1),
                str(int(original_value) + 100),
                "1",
                "0",
                "-1",
            ]
            
            for test_val in test_values:
                resp = await self.test_param(target, param, test_val)
                if resp.get("status") == 200:
                    if self._check_different_content(baseline, resp, original_value, test_val):
                        self.add_finding(
                            "HIGH",
                            f"Potential IDOR: Different content for ID {test_val}",
                            url=target,
                            parameter=param,
                            evidence=f"Original: {original_value}, Test: {test_val}"
                        )
                        return
    
    async def _test_uuid_idor(self, target, params):
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        
        for param in params:
            original_value = self._extract_param_value(target, param)
            if not original_value:
                continue
            
            if re.match(uuid_pattern, original_value, re.IGNORECASE):
                test_uuids = [
                    "00000000-0000-0000-0000-000000000000",
                    "11111111-1111-1111-1111-111111111111",
                    original_value[:-1] + ("0" if original_value[-1] != "0" else "1"),
                ]
                
                baseline = await self.http.get(target)
                
                for test_uuid in test_uuids:
                    resp = await self.test_param(target, param, test_uuid)
                    if resp.get("status") == 200:
                        if len(resp["text"]) > 100 and resp["text"] != baseline.get("text", ""):
                            self.add_finding(
                                "HIGH",
                                f"Potential UUID-based IDOR",
                                url=target,
                                parameter=param,
                                evidence=f"Test UUID: {test_uuid}"
                            )
                            return
    
    async def _test_sequential_idor(self, target, params):
        for param in params:
            original_value = self._extract_param_value(target, param)
            if not original_value or not original_value.isdigit():
                continue
            
            base_id = int(original_value)
            accessible_count = 0
            
            for offset in range(1, 6):
                test_id = str(base_id + offset)
                resp = await self.test_param(target, param, test_id)
                if resp.get("status") == 200 and len(resp["text"]) > 50:
                    accessible_count += 1
            
            if accessible_count >= 3:
                self.add_finding(
                    "MEDIUM",
                    f"Sequential ID access: {accessible_count}/5 IDs accessible",
                    url=target,
                    parameter=param,
                    evidence=f"Starting from ID: {original_value}"
                )
    
    def _extract_param_value(self, url, param):
        match = re.search(rf'{param}=([^&]+)', url)
        return match.group(1) if match else None
    
    def _check_different_content(self, baseline, test_resp, orig_val, test_val):
        if baseline["text"] == test_resp["text"]:
            return False
        
        baseline_without_ids = re.sub(r'\b' + orig_val + r'\b', '', baseline["text"])
        test_without_ids = re.sub(r'\b' + test_val + r'\b', '', test_resp["text"])
        
        if baseline_without_ids == test_without_ids:
            return False
        
        if abs(len(baseline["text"]) - len(test_resp["text"])) < 50:
            return False
        
        return True
