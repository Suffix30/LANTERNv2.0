import re
import json
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from modules.base import BaseModule
from core.utils import extract_params

class PaymentModule(BaseModule):
    name = "payment"
    description = "E-commerce & Payment Security Scanner"
    
    cart_indicators = [
        r'add.?to.?cart', r'shopping.?cart', r'basket', r'checkout',
        r'buy.?now', r'purchase', r'order', r'payment', r'price',
        r'quantity', r'qty', r'amount', r'total', r'subtotal',
        r'cart_id', r'product_id', r'item_id', r'sku',
    ]
    
    payment_paths = [
        "/cart", "/basket", "/checkout", "/payment", "/order",
        "/shop/cart", "/store/cart", "/shopping-cart",
        "/api/cart", "/api/checkout", "/api/order", "/api/payment",
        "/cart/add", "/cart/update", "/cart/remove",
        "/checkout/payment", "/checkout/confirm", "/checkout/process",
        "/order/create", "/order/submit", "/order/confirm",
        "/payment/process", "/payment/confirm", "/payment/submit",
        "/stripe/webhook", "/paypal/ipn", "/webhook/payment",
    ]
    
    price_params = [
        "price", "amount", "total", "subtotal", "cost", "value",
        "unit_price", "item_price", "product_price", "sale_price",
        "discount", "discount_amount", "coupon_value", "tax",
        "shipping", "shipping_cost", "fee", "charge",
    ]
    
    quantity_params = [
        "quantity", "qty", "amount", "count", "num", "number",
        "units", "items", "stock", "available",
    ]
    
    async def scan(self, target):
        self.findings = []
        
        await self._detect_ecommerce(target)
        await self._test_price_manipulation(target)
        await self._test_quantity_manipulation(target)
        await self._test_coupon_abuse(target)
        await self._test_race_conditions(target)
        await self._test_negative_values(target)
        await self._test_currency_manipulation(target)
        await self._check_payment_endpoints(target)
        await self._test_order_manipulation(target)
        
        return self.findings
    
    async def _detect_ecommerce(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        text = resp.get("text", "").lower()
        
        indicators_found = []
        for pattern in self.cart_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                indicators_found.append(pattern.replace('.?', ' '))
        
        if indicators_found:
            self.add_finding(
                "INFO",
                f"E-commerce functionality detected",
                url=target,
                evidence=f"Indicators: {', '.join(indicators_found[:5])}"
            )
    
    async def _test_price_manipulation(self, target):
        params = extract_params(target)
        
        for param in params:
            param_lower = param.lower()
            if any(p in param_lower for p in self.price_params):
                original = params[param]
                
                test_values = ["0", "0.01", "-100", "0.001", "1", "NaN", "null"]
                
                for test_val in test_values:
                    test_url = self._replace_param(target, param, test_val)
                    resp = await self.http.get(test_url)
                    
                    if resp.get("status") == 200:
                        text = resp.get("text", "").lower()
                        
                        if test_val in text or any(x in text for x in ["success", "added", "updated", "confirmed"]):
                            severity = "CRITICAL" if test_val in ["0", "-100", "0.01"] else "HIGH"
                            self.add_finding(
                                severity,
                                f"Price manipulation accepted: {param}={test_val}",
                                url=test_url,
                                parameter=param,
                                evidence=f"Server accepted modified price value"
                            )
                            break
        
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in ["/cart/add", "/api/cart/add", "/shop/cart/add"]:
            for price_param in self.price_params[:5]:
                test_data = {
                    "product_id": "1",
                    price_param: "0.01",
                    "quantity": "1"
                }
                
                resp = await self.http.post(f"{base}{path}", data=test_data)
                
                if resp.get("status") in [200, 201, 302]:
                    text = resp.get("text", "").lower()
                    if "error" not in text and "invalid" not in text:
                        self.add_finding(
                            "CRITICAL",
                            f"Cart accepts custom price parameter",
                            url=f"{base}{path}",
                            parameter=price_param,
                            evidence=f"Price parameter {price_param}=0.01 accepted"
                        )
                        return
    
    async def _test_quantity_manipulation(self, target):
        params = extract_params(target)
        
        for param in params:
            param_lower = param.lower()
            if any(q in param_lower for q in self.quantity_params):
                test_values = ["-1", "-100", "0", "99999999", "1e10", "0.5"]
                
                for test_val in test_values:
                    test_url = self._replace_param(target, param, test_val)
                    resp = await self.http.get(test_url)
                    
                    if resp.get("status") == 200:
                        text = resp.get("text", "").lower()
                        
                        if "error" not in text and "invalid" not in text:
                            if test_val.startswith("-"):
                                self.add_finding(
                                    "CRITICAL",
                                    f"Negative quantity accepted: {param}={test_val}",
                                    url=test_url,
                                    parameter=param,
                                    evidence="Negative quantity may result in credit/refund"
                                )
                            elif test_val == "99999999":
                                self.add_finding(
                                    "HIGH",
                                    f"Excessive quantity accepted: {param}={test_val}",
                                    url=test_url,
                                    parameter=param,
                                    evidence="No upper limit validation"
                                )
                            break
    
    async def _test_coupon_abuse(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        coupon_endpoints = [
            "/cart/coupon", "/api/coupon", "/apply-coupon", "/discount",
            "/checkout/coupon", "/promo", "/voucher", "/code",
        ]
        
        for endpoint in coupon_endpoints:
            resp = await self.http.post(
                f"{base}{endpoint}",
                data={"coupon": "TEST100", "code": "DISCOUNT50"}
            )
            
            if resp.get("status") == 200:
                text = resp.get("text", "").lower()
                
                if "invalid" in text or "expired" in text or "not found" in text:
                    for _ in range(3):
                        await self.http.post(f"{base}{endpoint}", data={"coupon": "TEST100"})
                    
                    self.add_finding(
                        "MEDIUM",
                        f"Coupon endpoint found: {endpoint}",
                        url=f"{base}{endpoint}",
                        evidence="Test for coupon brute-forcing manually"
                    )
                elif "success" in text or "applied" in text:
                    self.add_finding(
                        "HIGH",
                        f"Coupon accepted without validation",
                        url=f"{base}{endpoint}",
                        evidence="Random coupon code accepted"
                    )
        
        resp = await self.http.get(target)
        if resp.get("status"):
            text = resp.get("text", "")
            coupon_patterns = [
                r'coupon[_-]?code["\']?\s*[:=]\s*["\']([A-Z0-9]+)',
                r'promo[_-]?code["\']?\s*[:=]\s*["\']([A-Z0-9]+)',
                r'discount[_-]?code["\']?\s*[:=]\s*["\']([A-Z0-9]+)',
            ]
            
            for pattern in coupon_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    self.add_finding(
                        "MEDIUM",
                        f"Coupon code exposed in source",
                        url=target,
                        evidence=f"Found: {matches[0]}"
                    )
    
    async def _test_race_conditions(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        race_endpoints = [
            "/api/coupon/apply", "/cart/checkout", "/order/create",
            "/payment/process", "/redeem", "/claim",
        ]
        
        for endpoint in race_endpoints[:3]:
            async def race_request():
                return await self.http.post(
                    f"{base}{endpoint}",
                    data={"coupon": "TEST", "action": "apply"}
                )
            
            tasks = [race_request() for _ in range(5)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            success_count = sum(1 for r in results if isinstance(r, dict) and r.get("status") == 200)
            
            if success_count > 1:
                self.add_finding(
                    "MEDIUM",
                    f"Potential race condition: {endpoint}",
                    url=f"{base}{endpoint}",
                    evidence=f"{success_count}/5 concurrent requests succeeded"
                )
    
    async def _test_negative_values(self, target):
        params = extract_params(target)
        
        numeric_params = []
        for param, value in params.items():
            try:
                float(value)
                numeric_params.append(param)
            except:
                pass
        
        for param in numeric_params:
            test_url = self._replace_param(target, param, "-1")
            resp = await self.http.get(test_url)
            
            if resp.get("status") == 200:
                text = resp.get("text", "").lower()
                if "error" not in text and "-1" not in text:
                    self.add_finding(
                        "HIGH",
                        f"Negative value accepted: {param}=-1",
                        url=test_url,
                        parameter=param,
                        evidence="May cause calculation errors or credits"
                    )
    
    async def _test_currency_manipulation(self, target):
        params = extract_params(target)
        
        currency_params = ["currency", "cur", "cc", "money_type", "payment_currency"]
        
        for param in params:
            if param.lower() in currency_params:
                weak_currencies = ["VND", "IDR", "KRW", "IRR", "JPY", "XXX", "TEST"]
                
                for currency in weak_currencies:
                    test_url = self._replace_param(target, param, currency)
                    resp = await self.http.get(test_url)
                    
                    if resp.get("status") == 200:
                        text = resp.get("text", "").lower()
                        if currency.lower() in text:
                            self.add_finding(
                                "HIGH",
                                f"Currency manipulation: {param}={currency}",
                                url=test_url,
                                parameter=param,
                                evidence="Weak/test currency accepted"
                            )
                            break
    
    async def _check_payment_endpoints(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for endpoint in self.payment_paths[:5]:
            full_url = urljoin(base, endpoint)
            resp = await self.http.get(full_url)
            if resp.get("status") == 200:
                self.discovered_payments.append(full_url)
        
        self.discovered_payments = getattr(self, 'discovered_payments', [])
        
        sensitive_endpoints = [
            "/stripe/webhook", "/paypal/ipn", "/payment/webhook",
            "/api/payment/callback", "/checkout/callback",
            "/payment/success", "/payment/failure",
            "/.well-known/apple-developer-merchantid-domain-association",
        ]
        
        for endpoint in sensitive_endpoints:
            resp = await self.http.get(f"{base}{endpoint}")
            
            if resp.get("status") == 200:
                self.add_finding(
                    "MEDIUM",
                    f"Payment endpoint accessible: {endpoint}",
                    url=f"{base}{endpoint}",
                    evidence="Test for webhook manipulation"
                )
            
            resp = await self.http.post(
                f"{base}{endpoint}",
                data={"type": "checkout.session.completed", "data": {"id": "test"}}
            )
            
            if resp.get("status") == 200:
                text = resp.get("text", "").lower()
                if "error" not in text and "invalid" not in text:
                    self.add_finding(
                        "CRITICAL",
                        f"Payment webhook accepts fake events",
                        url=f"{base}{endpoint}",
                        evidence="No signature validation on webhook"
                    )
    
    async def _test_order_manipulation(self, target):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for i in range(1, 10):
            resp = await self.http.get(f"{base}/order/{i}")
            
            if resp.get("status") == 200:
                text = resp.get("text", "").lower()
                if any(x in text for x in ["order", "total", "items", "address", "email"]):
                    self.add_finding(
                        "HIGH",
                        f"Order IDOR: accessible order #{i}",
                        url=f"{base}/order/{i}",
                        evidence="Order details exposed without auth"
                    )
                    break
        
        order_endpoints = ["/api/order", "/order/details", "/checkout/order"]
        
        for endpoint in order_endpoints:
            resp = await self.http.post(
                f"{base}{endpoint}",
                json={"order_id": "1", "status": "completed", "paid": True}
            )
            
            if resp.get("status") == 200:
                self.add_finding(
                    "CRITICAL",
                    f"Order status manipulation possible",
                    url=f"{base}{endpoint}",
                    evidence="Order modification accepted"
                )
    
    def _replace_param(self, url, param, value):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _parse_json_response(self, resp):
        try:
            text = resp.get("text", "")
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    
    def _build_payment_payload(self, product_id, quantity, price):
        return json.dumps({
            "product_id": product_id,
            "quantity": quantity,
            "price": price,
            "currency": "USD"
        })
    
    def _build_checkout_url(self, base, cart_id):
        return urljoin(base, f"/checkout/{cart_id}")