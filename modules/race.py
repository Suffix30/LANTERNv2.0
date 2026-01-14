import asyncio
import time
import hashlib
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from modules.base import BaseModule
from core.utils import extract_params, random_string


class RaceModule(BaseModule):
    name = "race"
    description = "Race Condition Scanner"
    exploitable = True
    
    limit_indicators = [
        ("rate", "Rate limit"),
        ("limit", "Limit"),
        ("quota", "Quota"),
        ("exceed", "Exceeded"),
        ("too many", "Too many requests"),
        ("throttle", "Throttled"),
        ("slow down", "Slow down"),
        ("try again", "Try again"),
        ("maximum", "Maximum reached"),
    ]
    
    async def scan(self, target: str):
        self.findings = []
        self.vulnerable_endpoints: List[Dict] = []
        self.timing_data: List[Tuple[str, float]] = []
        self.baseline_response: Optional[Dict] = None
        
        params = extract_params(target)
        parsed = urlparse(target)
        
        baseline = await self.http.get(target)
        if baseline.get("status"):
            self.baseline_response = baseline
        
        start_time = time.time()
        
        await self._warm_connections(target)
        await self._detect_race_conditions(target, params)
        await self._test_single_packet_attack(target)
        await self._test_last_byte_sync(target)
        await self._test_limit_overrun(target)
        await self._test_toctou(target, params)
        await self._test_double_spend(target)
        await self._test_state_confusion(target)
        
        elapsed = time.time() - start_time
        self.log_info(f"Race condition scan completed in {elapsed:.2f}s")
        
        return self.findings
    
    async def _warm_connections(self, target: str, count: int = 5):
        tasks = [self.http.get(target) for _ in range(count)]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _detect_race_conditions(self, target: str, params: List[str]):
        concurrent_requests = 30
        
        responses = await self._send_concurrent_requests(target, concurrent_requests, method="GET")
        
        if not responses:
            return
        
        status_codes = [r.get("status") for r in responses if r.get("status")]
        unique_statuses: Set[int] = set(status_codes)
        
        if len(unique_statuses) > 2:
            self.add_finding(
                "MEDIUM",
                f"Race condition indicator: inconsistent responses",
                url=target,
                evidence=f"Status codes: {unique_statuses}"
            )
            
            self.vulnerable_endpoints.append({
                "url": target,
                "type": "inconsistent_response",
                "statuses": list(unique_statuses),
            })
        
        lengths = [len(r.get("text", "")) for r in responses if r.get("text")]
        if lengths:
            length_variance = max(lengths) - min(lengths)
            if length_variance > 100:
                self.add_finding(
                    "LOW",
                    f"Race condition indicator: response length variance",
                    url=target,
                    evidence=f"Length variance: {length_variance} bytes"
                )
        
        content_hashes: Set[str] = set()
        for r in responses:
            if r.get("text"):
                h = hashlib.md5(r["text"].encode()).hexdigest()[:8]
                content_hashes.add(h)
        
        if len(content_hashes) > 3:
            self.add_finding(
                "HIGH",
                "Race condition: multiple unique responses",
                url=target,
                evidence=f"{len(content_hashes)} unique response bodies"
            )
        
        errors = sum(1 for r in responses if r.get("status", 0) >= 500)
        if errors >= 3:
            self.add_finding(
                "MEDIUM",
                f"Race condition indicator: server errors under load",
                url=target,
                evidence=f"{errors}/{concurrent_requests} requests returned 5xx"
            )
    
    async def _test_single_packet_attack(self, target: str):
        parsed = urlparse(target)
        base_url = urljoin(target, "/")
        
        request_count = 20
        
        async def timed_request():
            start = time.time()
            resp = await self.http.get(target)
            elapsed = time.time() - start
            return (elapsed, resp)
        
        tasks = [timed_request() for _ in range(request_count)]
        
        trigger_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_time = time.time() - trigger_time
        
        valid_results = [(t, r) for t, r in results if isinstance(r, tuple) and not isinstance(r[1], Exception)]
        
        if len(valid_results) >= request_count // 2:
            timings = [t for t, _ in valid_results]
            avg_time = sum(timings) / len(timings)
            
            if total_time < avg_time * 2:
                self.add_finding(
                    "HIGH",
                    "Single-packet attack possible",
                    url=target,
                    evidence=f"{request_count} requests completed in {total_time:.3f}s (avg {avg_time:.3f}s each)"
                )
                
                self.timing_data.append(("single_packet", total_time))
                self.record_success("single_packet", target)
    
    async def _test_last_byte_sync(self, target: str):
        payload = random_string(100)
        
        async def delayed_request(delay: float):
            await asyncio.sleep(delay)
            return await self.http.post(target, data={"data": payload})
        
        delays = [0.0, 0.001, 0.002, 0.003, 0.004]
        tasks = [delayed_request(d) for d in delays * 4]
        
        start = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start
        
        valid = [r for r in results if isinstance(r, dict) and r.get("status")]
        
        if len(valid) >= len(tasks) // 2:
            statuses = set(r.get("status") for r in valid)
            if len(statuses) > 1 or any(r.get("status") >= 500 for r in valid):
                self.add_finding(
                    "MEDIUM",
                    "Last-byte sync may be effective",
                    url=target,
                    evidence=f"Varied responses with {elapsed:.3f}s total time"
                )
    
    async def _test_limit_overrun(self, target: str):
        burst_size = 100
        
        responses = await self._send_concurrent_requests(target, burst_size, method="GET")
        
        if not responses:
            return
        
        limited_count = 0
        success_count = 0
        
        for resp in responses:
            status = resp.get("status", 0)
            text = resp.get("text", "").lower()
            
            if status == 429:
                limited_count += 1
            elif status == 200:
                is_limited = any(ind in text for ind, _ in self.limit_indicators)
                if is_limited:
                    limited_count += 1
                else:
                    success_count += 1
            elif 200 <= status < 300:
                success_count += 1
        
        if limited_count > 0 and success_count > limited_count:
            self.add_finding(
                "CRITICAL",
                "Rate limit bypass via race condition",
                url=target,
                evidence=f"Bypassed: {success_count}/{burst_size} succeeded despite limits"
            )
            
            self.vulnerable_endpoints.append({
                "url": target,
                "type": "limit_bypass",
                "success_rate": success_count / burst_size,
            })
            
            self.record_success(f"limit_bypass:{burst_size}", target)
        
        elif limited_count == 0 and success_count >= burst_size * 0.9:
            self.add_finding(
                "MEDIUM",
                "No rate limiting detected",
                url=target,
                evidence=f"{success_count}/{burst_size} requests all succeeded"
            )
    
    async def _test_toctou(self, target: str, params: List[str]):
        if not params:
            return
        
        for param in params[:3]:
            value1 = random_string(8)
            value2 = random_string(8)
            
            async def check_then_use():
                check = await self.test_param(target, param, value1)
                use = await self.test_param(target, param, value2)
                return (check, use)
            
            tasks = [check_then_use() for _ in range(10)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for r in results:
                if isinstance(r, tuple) and len(r) == 2:
                    check, use = r
                    if check.get("status") and use.get("status"):
                        if check.get("text") != use.get("text"):
                            check_hash = hashlib.md5(check.get("text", "").encode()).hexdigest()[:8]
                            use_hash = hashlib.md5(use.get("text", "").encode()).hexdigest()[:8]
                            
                            if check_hash != use_hash:
                                self.add_finding(
                                    "HIGH",
                                    "TOCTOU vulnerability detected",
                                    url=target,
                                    parameter=param,
                                    evidence="Check and use returned different results"
                                )
                                return
    
    async def _test_double_spend(self, target: str):
        parsed = urlparse(target)
        query = parse_qs(parsed.query)
        
        if not any(k in str(query).lower() for k in ["amount", "quantity", "count", "transfer", "send", "pay"]):
            return
        
        async def spend_request():
            return await self.http.post(target, data=query)
        
        tasks = [spend_request() for _ in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid = [r for r in results if isinstance(r, dict) and r.get("status")]
        success = [r for r in valid if 200 <= r.get("status", 0) < 300]
        
        if len(success) > 1:
            self.add_finding(
                "CRITICAL",
                "Potential double-spend vulnerability",
                url=target,
                evidence=f"{len(success)} concurrent transactions succeeded"
            )
            
            self.vulnerable_endpoints.append({
                "url": target,
                "type": "double_spend",
                "successful_transactions": len(success),
            })
    
    async def _test_state_confusion(self, target: str):
        state_values = ["pending", "approved", "completed", "cancelled", "active", "inactive"]
        
        for state in state_values:
            parsed = urlparse(target)
            new_query = urlencode({"status": state})
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            
            tasks = [self.http.post(test_url, data={"status": s}) for s in state_values]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            valid = [r for r in results if isinstance(r, dict) and r.get("status")]
            
            if len(set(r.get("status") for r in valid)) > 2:
                self.add_finding(
                    "MEDIUM",
                    "State confusion under concurrent requests",
                    url=target,
                    evidence="Multiple state values accepted simultaneously"
                )
                break
    
    async def _send_concurrent_requests(self, target: str, count: int, method: str = "GET") -> List[Dict]:
        async def make_request():
            if method == "GET":
                return await self.http.get(target)
            else:
                return await self.http.post(target, data={})
        
        tasks = [make_request() for _ in range(count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_responses = []
        for r in results:
            if isinstance(r, dict) and not isinstance(r, Exception):
                valid_responses.append(r)
        
        return valid_responses
    
    async def exploit(self, target: str, finding: Dict):
        results = {
            "vulnerable_endpoints": self.vulnerable_endpoints,
            "timing_data": self.timing_data,
            "exploit_attempts": [],
        }
        
        for vuln in self.vulnerable_endpoints:
            if vuln["type"] == "limit_bypass":
                results["exploit_attempts"].append({
                    "type": "limit_bypass",
                    "method": "Send 100+ concurrent requests",
                    "expected_bypass_rate": vuln.get("success_rate", 0),
                })
            
            elif vuln["type"] == "double_spend":
                results["exploit_attempts"].append({
                    "type": "double_spend",
                    "method": "Send concurrent transaction requests",
                    "success_count": vuln.get("successful_transactions", 0),
                })
        
        if results["exploit_attempts"]:
            self.add_exploit_data("race_exploits", results)
        
        return results
    
    def get_vulnerable_endpoints(self) -> List[Dict]:
        return self.vulnerable_endpoints
