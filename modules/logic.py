import re
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from modules.base import BaseModule


class LogicModule(BaseModule):
    name = "logic"
    description = "Business Logic / Parameter Tampering Scanner"
    exploitable = True

    tamper_params = [
        ("price", ["0", "0.01", "-1", "1", "999999"], "Price manipulation"),
        ("amount", ["0", "0.01", "-1", "1"], "Amount manipulation"),
        ("quantity", ["0", "-1", "1", "99999", "999999999"], "Quantity manipulation"),
        ("total", ["0", "0.01", "1"], "Total override"),
        ("step", ["0", "1", "999", "skip", "final"], "Step/jump manipulation"),
        ("stage", ["0", "1", "99", "final", "complete"], "Stage override"),
        ("role", ["admin", "administrator", "superuser", "root"], "Role escalation"),
        ("is_admin", ["true", "1", "yes"], "Admin flag"),
        ("discount", ["100", "99", "50", "999"], "Discount abuse"),
        ("coupon", ["FREE", "100OFF", "ADMIN", "test"], "Coupon abuse"),
        ("id", ["1", "0", "-1", "admin"], "ID manipulation"),
        ("user_id", ["1", "0", "admin"], "User ID override"),
        ("order_id", ["1", "0"], "Order ID manipulation"),
        ("payment_status", ["paid", "completed", "success"], "Payment status override"),
        ("verified", ["true", "1", "yes"], "Verified flag"),
        ("trial", ["true", "1", "999"], "Trial abuse"),
    ]

    async def scan(self, target):
        self.findings = []
        self.exploited_flows = []
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        await self._test_query_tampering(target)
        await self._test_checkout_flows(base_url)
        await self._test_multi_step_flows(base_url)
        await self._test_role_parameters(target)
        
        if self.aggressive:
            await self._test_workflow_attacks(base_url)
            await self._test_payment_bypass(base_url)
            await self._test_coupon_stacking(base_url)
        
        return self.findings
    
    async def _test_workflow_attacks(self, base_url):
        workflow_config = self.config.get("workflow")
        if not workflow_config:
            return
        
        try:
            from core.workflow import WorkflowEngine
            engine = WorkflowEngine(self.http)
            
            if isinstance(workflow_config, str):
                engine.load_workflow(workflow_config)
            else:
                engine.workflow = workflow_config
            
            results = await engine.run()
            
            for attack_name, attack_result in results.get("attacks", {}).items():
                if attack_result.get("success"):
                    self.add_finding(
                        "CRITICAL",
                        f"Business logic attack succeeded: {attack_name}",
                        url=base_url,
                        evidence=f"Attack type: {attack_result.get('type', 'unknown')}",
                        confidence_evidence=["workflow_attack_confirmed", "business_logic_bypass"],
                        request_data=attack_result.get("request_data")
                    )
                    self.exploited_flows.append(attack_result)
        except Exception:
            pass
    
    async def _test_payment_bypass(self, base_url):
        payment_endpoints = [
            "/api/checkout/complete", "/checkout/confirm", "/payment/process",
            "/order/finalize", "/cart/checkout", "/api/order/create",
        ]
        
        for endpoint in payment_endpoints:
            url = urljoin(base_url, endpoint)
            
            bypass_payloads = [
                {"payment_status": "completed", "amount": "0"},
                {"paid": "true", "total": "0.01"},
                {"status": "success", "verified": "1"},
                {"skip_payment": "true"},
                {"payment_method": "free"},
            ]
            
            for payload in bypass_payloads:
                resp = await self.http.post(url, json=payload)
                
                if resp.get("status") in [200, 201, 302]:
                    text = (resp.get("text") or "").lower()
                    if any(s in text for s in ["success", "complete", "confirmed", "order", "thank"]):
                        if "error" not in text and "invalid" not in text:
                            self.add_finding(
                                "CRITICAL",
                                f"Payment bypass: {endpoint}",
                                url=url,
                                evidence=f"Payload accepted: {list(payload.keys())}",
                                confidence_evidence=["payment_bypass_confirmed", "success_response"],
                                request_data={"method": "POST", "url": url, "payload": payload}
                            )
                            self.exploited_flows.append({"type": "payment_bypass", "endpoint": endpoint, "payload": payload})
                            return
    
    async def _test_coupon_stacking(self, base_url):
        coupon_endpoints = ["/api/coupon", "/cart/coupon", "/apply-coupon", "/discount/apply"]
        
        for endpoint in coupon_endpoints:
            url = urljoin(base_url, endpoint)
            
            coupons = ["TEST", "SAVE10", "FREE", "100OFF", "DISCOUNT", "PROMO"]
            applied = 0
            
            for coupon in coupons:
                resp = await self.http.post(url, json={"code": coupon})
                if resp.get("status") == 200:
                    text = (resp.get("text") or "").lower()
                    if "applied" in text or "success" in text or "discount" in text:
                        applied += 1
            
            if applied >= 2:
                self.add_finding(
                    "HIGH",
                    f"Coupon stacking possible: {applied} coupons applied",
                    url=url,
                    evidence=f"Multiple coupons accepted simultaneously",
                    confidence_evidence=["coupon_stacking", "multiple_discounts"]
                )
                return

    async def _test_query_tampering(self, target):
        params = parse_qs(parsed.query) if (parsed := urlparse(target)).query else {}
        if not params:
            for param, values, desc in self.tamper_params[:8]:
                test_url = self._inject_param(target, param, values[0])
                resp = await self.http.get(test_url)
                if self._success_indicator(resp, param, values[0]):
                    self.add_finding(
                        "HIGH",
                        f"Parameter tampering: {desc}",
                        url=test_url,
                        parameter=param,
                        evidence=f"{param}={values[0]} accepted with success indicator"
                    )
                    return
        else:
            for existing in list(params.keys())[:5]:
                for param, values, desc in self.tamper_params:
                    if param.lower() == existing.lower():
                        for v in values[:2]:
                            test_url = self._set_param(target, existing, v)
                            resp = await self.http.get(test_url)
                            if self._success_indicator(resp, param, v):
                                self.add_finding(
                                    "HIGH",
                                    f"Parameter tampering: {desc}",
                                    url=test_url,
                                    parameter=param,
                                    evidence=f"{param}={v} accepted"
                                )
                                return

    def _inject_param(self, url, param, value):
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[param] = [value]
        new_query = urlencode(q, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _set_param(self, url, param, value):
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[param] = [value]
        new_query = urlencode(q, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _success_indicator(self, resp, param, value):
        if not resp.get("status"):
            return False
        text = (resp.get("text") or "").lower()
        if resp.get("status") in [200, 201, 302]:
            if param in ["price", "amount", "total", "discount"] and "error" not in text and "invalid" not in text:
                return True
            if param in ["role", "is_admin"] and ("admin" in text or "dashboard" in text or "welcome" in text):
                return True
            if param in ["step", "stage"] and ("success" in text or "complete" in text or "next" in text):
                return True
        return False

    async def _test_checkout_flows(self, base_url):
        checkout_paths = ["/cart", "/checkout", "/basket", "/payment", "/order", "/api/cart", "/api/checkout"]
        for path in checkout_paths:
            url = urljoin(base_url, path)
            resp = await self.http.get(url)
            if resp.get("status") != 200:
                continue
            for param, values, desc in [("price", ["0", "0.01"], "Price"), ("quantity", ["0", "-1"], "Quantity"), ("discount", ["100"], "Discount")]:
                for v in values:
                    r = await self.http.post(url, data={param: v, "item_id": "1"})
                    if r.get("status") in [200, 302] and "error" not in (r.get("text") or "").lower():
                        self.add_finding(
                            "MEDIUM",
                            f"Checkout parameter tampering: {desc}={v}",
                            url=url,
                            parameter=param,
                            evidence=f"POST {param}={v} not rejected"
                        )
                        return

    async def _test_multi_step_flows(self, base_url):
        step_paths = ["/wizard", "/onboarding", "/signup", "/register", "/survey", "/application"]
        for path in step_paths:
            url = urljoin(base_url, path)
            resp = await self.http.get(url)
            if resp.get("status") != 200:
                continue
            for param in ["step", "stage", "page", "phase"]:
                for v in ["999", "final", "complete", "end", "1", "0"]:
                    r = await self.http.get(f"{url}?{param}={v}")
                    if r.get("status") == 200:
                        text = (r.get("text") or "").lower()
                        if "success" in text or "complete" in text or "thank" in text or "congratulation" in text:
                            self.add_finding(
                                "MEDIUM",
                                f"Multi-step bypass via {param}={v}",
                                url=url,
                                parameter=param,
                                evidence=f"Step jump to completion"
                            )
                            return

    async def _test_role_parameters(self, target):
        for param, values, desc in [("role", ["admin", "administrator"], "Role"), ("is_admin", ["true", "1"], "Admin flag"), ("type", ["admin", "superuser"], "Type")]:
            for v in values:
                test_url = self._inject_param(target, param, v)
                resp = await self.http.get(test_url)
                if resp.get("status") == 200:
                    text = (resp.get("text") or "").lower()
                    if any(x in text for x in ["admin", "dashboard", "panel", "manage", "settings"]):
                        self.add_finding(
                            "HIGH",
                            f"Role escalation: {desc} via {param}={v}",
                            url=test_url,
                            parameter=param,
                            evidence=f"Admin-like content with {param}={v}"
                        )
                        return
